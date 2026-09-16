#!/usr/bin/env python3
"""Evaluate the locked E3 threshold once on held-out test paired traces.

The lock-validation report is verified before this script opens the held-out
CSV.  The script never sweeps thresholds and refuses to overwrite outputs.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
E3_ROOT = SCRIPT_DIR.parent
TEST_NAME = "held_out_test.csv.gz"
BOOTSTRAP_REPLICATES = 5000
METRICS = ("attack_alert_rate", "benign_trigger_rate", "FNR", "balanced_precision", "J")
REQUIRED_COLUMNS = {
    "source_e2_split", "e3_split", "profile", "condition", "role", "level", "pair_id",
    "arrival_schedule_sha256", "query_schedule_sha256", "query_idx", "samples", "entropy",
    "unique_ratio", "block_volume", "block_combined",
}
TRACE_FIELDS = (
    "source_e2_split", "profile", "level", "pair_id",
    "arrival_schedule_sha256", "query_schedule_sha256",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def csv_bool(value: str) -> bool:
    if value not in {"0", "1"}:
        raise ValueError(f"Expected detector flag 0 or 1, got {value!r}")
    return value == "1"


def new_b5_block(row: dict[str, str], candidate: dict[str, Any]) -> bool:
    return (
        int(row["samples"]) >= int(candidate["min_samples"])
        and float(row["entropy"]) >= float(candidate["entropy_threshold"])
        and float(row["unique_ratio"]) >= float(candidate["unique_ratio_threshold"])
    )


def block_rate(rows: list[dict[str, str]], variant: str, candidate: dict[str, Any]) -> float:
    if not rows:
        raise ValueError("Cannot calculate rate for empty condition-run")
    if variant == "new_B5":
        return fmean(new_b5_block(row, candidate) for row in rows)
    if variant == "B2":
        return fmean(csv_bool(row["block_volume"]) for row in rows)
    if variant == "old_B5":
        return fmean(csv_bool(row["block_combined"]) for row in rows)
    raise ValueError(f"Unknown variant: {variant}")


def trace_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[field] for field in TRACE_FIELDS)


def pair_metrics(attack_rows: list[dict[str, str]], benign_rows: list[dict[str, str]],
                 variant: str, candidate: dict[str, Any]) -> dict[str, float]:
    attack = block_rate(attack_rows, variant, candidate)
    benign = block_rate(benign_rows, variant, candidate)
    return {
        "attack_alert_rate": attack,
        "benign_trigger_rate": benign,
        "FNR": 1.0 - attack,
        "balanced_precision": (attack + (1.0 - benign)) / 2.0,
        "J": attack - benign,
    }


def stable_seed(*parts: object) -> int:
    material = "|".join(map(str, parts)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def percentile(sorted_values: list[float], quantile: float) -> float:
    if not sorted_values:
        raise ValueError("Cannot calculate percentile of no values")
    index = (len(sorted_values) - 1) * quantile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return sorted_values[lower]
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (index - lower)


def bootstrap_mean(values: list[float], seed_parts: tuple[object, ...]) -> dict[str, Any]:
    if not values:
        raise ValueError("Cannot bootstrap no paired-trace values")
    rng = random.Random(stable_seed(*seed_parts))
    count = len(values)
    samples = [fmean(values[rng.randrange(count)] for _ in range(count)) for _ in range(BOOTSTRAP_REPLICATES)]
    samples.sort()
    return {
        "mean": fmean(values),
        "ci95": [percentile(samples, 0.025), percentile(samples, 0.975)],
        "n_pairs": count,
    }


def bootstrap_macro(cell_values: list[list[float]], seed_parts: tuple[object, ...]) -> dict[str, Any]:
    if not cell_values or any(not values for values in cell_values):
        raise ValueError("Every macro cell needs at least one paired trace")
    rng = random.Random(stable_seed(*seed_parts))
    observed = fmean(fmean(values) for values in cell_values)
    samples: list[float] = []
    for _ in range(BOOTSTRAP_REPLICATES):
        cell_means = []
        for values in cell_values:
            count = len(values)
            cell_means.append(fmean(values[rng.randrange(count)] for _ in range(count)))
        samples.append(fmean(cell_means))
    samples.sort()
    return {
        "mean": observed,
        "ci95": [percentile(samples, 0.025), percentile(samples, 0.975)],
        "n_cells": len(cell_values),
        "n_pairs_by_cell": [len(values) for values in cell_values],
        "bootstrap": "stratified paired-trace bootstrap; resample paired traces within each equally weighted cell",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument("--lock", type=Path, default=E3_ROOT / "e3_locked_threshold.json")
    parser.add_argument("--lock-validation", type=Path, default=E3_ROOT / "e3_lock_validation.json")
    parser.add_argument("--test", type=Path, default=E3_ROOT / "datasets" / "splits_60_20_20" / TEST_NAME)
    parser.add_argument("--json-output", type=Path, default=E3_ROOT / "e3_test_results.json")
    parser.add_argument("--csv-output", type=Path, default=E3_ROOT / "e3_test_results.csv")
    parser.add_argument("--summary-output", type=Path, default=E3_ROOT / "e3_summary.csv")
    return parser.parse_args()


def require_lock_validation(protocol_path: Path, lock_path: Path, report_path: Path) -> dict[str, Any]:
    report = load_json(report_path)
    if report.get("status") != "PASS" or report.get("critical_failures"):
        raise ValueError("Lock validation is not PASS")
    hashes = report.get("artifact_hashes", {})
    if hashes.get("protocol", {}).get("sha256") != sha256_file(protocol_path):
        raise ValueError("Protocol changed after lock validation")
    if hashes.get("lock", {}).get("sha256") != sha256_file(lock_path):
        raise ValueError("Locked threshold changed after lock validation")
    if report.get("data_access_policy", {}).get("held_out_test_csv_opened") is not False:
        raise ValueError("Lock validator provenance does not show held-out test unopened")
    return report


def collect_traces(test_path: Path) -> tuple[dict[tuple[str, ...], dict[str, list[dict[str, str]]]], int]:
    traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    rows_read = 0
    with gzip.open(test_path, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Held-out CSV missing required columns: {', '.join(sorted(missing))}")
        for row in reader:
            rows_read += 1
            if row["e3_split"] != "held_out_test":
                raise ValueError(f"Held-out input contains e3_split={row['e3_split']!r}")
            traces[trace_key(row)][row["condition"]].append(row)
    return traces, rows_read


def evaluate_cell(
    traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]],
    attack_condition: str,
    benign_condition: str,
    level: int,
    candidate: dict[str, Any],
    scope: str,
) -> tuple[dict[str, Any], dict[str, dict[str, list[float]]]]:
    values = {variant: {metric: [] for metric in METRICS} for variant in ("new_B5", "B2", "old_B5")}
    for key, conditions in sorted(traces.items()):
        if int(key[2]) != level or attack_condition not in conditions:
            continue
        if benign_condition not in conditions:
            raise ValueError(f"Missing paired benign trace {benign_condition} for {key}")
        attack_rows, benign_rows = conditions[attack_condition], conditions[benign_condition]
        if len(attack_rows) != len(benign_rows):
            raise ValueError(f"Paired decision count mismatch for {key}")
        for variant in values:
            metrics = pair_metrics(attack_rows, benign_rows, variant, candidate)
            for metric, value in metrics.items():
                values[variant][metric].append(value)
    if not values["new_B5"]["J"]:
        raise ValueError(f"No pairs found for {attack_condition}, level {level}")

    summaries = {
        variant: {
            metric: bootstrap_mean(metric_values, ("E3", "test", scope, attack_condition, level, variant, metric))
            for metric, metric_values in metrics.items()
        }
        for variant, metrics in values.items()
    }
    comparisons = {}
    for baseline in ("B2", "old_B5"):
        delta = [left - right for left, right in zip(values["new_B5"]["J"], values[baseline]["J"])]
        comparisons[f"Delta_J_new_B5_minus_{baseline}"] = bootstrap_mean(
            delta, ("E3", "test", scope, attack_condition, level, "new_B5", baseline, "Delta_J")
        )
    return {
        "scope": scope,
        "attack_condition": attack_condition,
        "benign_condition": benign_condition,
        "level": level,
        "n_pairs": len(values["new_B5"]["J"]),
        "variants": summaries,
        "comparisons": comparisons,
    }, values


def macro_result(cells: list[dict[str, Any]], cell_values: list[dict[str, dict[str, list[float]]]]) -> dict[str, Any]:
    variants = {}
    for variant in ("new_B5", "B2", "old_B5"):
        variants[variant] = {
            metric: bootstrap_macro(
                [values[variant][metric] for values in cell_values],
                ("E3", "test", "primary_macro", variant, metric),
            )
            for metric in METRICS
        }
    comparisons = {}
    for baseline in ("B2", "old_B5"):
        per_cell_delta = [
            [left - right for left, right in zip(values["new_B5"]["J"], values[baseline]["J"])]
            for values in cell_values
        ]
        comparisons[f"Delta_J_new_B5_minus_{baseline}"] = bootstrap_macro(
            per_cell_delta, ("E3", "test", "primary_macro", "new_B5", baseline, "Delta_J")
        )
    return {
        "scope": "primary_macro",
        "aggregation": "equal-weight macro-average across 2 primary attack conditions x 4 levels",
        "source_cells": [{"attack_condition": cell["attack_condition"], "level": cell["level"]} for cell in cells],
        "variants": variants,
        "comparisons": comparisons,
    }


def write_cell_csv(path: Path, primary_cells: list[dict[str, Any]], macro: dict[str, Any], secondary: dict[str, list[dict[str, Any]]]) -> None:
    fields = [
        "scope", "attack_condition", "benign_condition", "level", "variant_or_comparison", "metric",
        "mean", "ci95_low", "ci95_high", "n_pairs", "n_cells",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()

        def write_result(scope: str, attack: str, benign: str, level: str, result: dict[str, Any]) -> None:
            for variant, metrics in result["variants"].items():
                for metric, value in metrics.items():
                    writer.writerow({
                        "scope": scope, "attack_condition": attack, "benign_condition": benign, "level": level,
                        "variant_or_comparison": variant, "metric": metric, "mean": value["mean"],
                        "ci95_low": value["ci95"][0], "ci95_high": value["ci95"][1],
                        "n_pairs": value.get("n_pairs", ""), "n_cells": value.get("n_cells", ""),
                    })
            for comparison, value in result["comparisons"].items():
                writer.writerow({
                    "scope": scope, "attack_condition": attack, "benign_condition": benign, "level": level,
                    "variant_or_comparison": comparison, "metric": "Delta_J", "mean": value["mean"],
                    "ci95_low": value["ci95"][0], "ci95_high": value["ci95"][1],
                    "n_pairs": value.get("n_pairs", ""), "n_cells": value.get("n_cells", ""),
                })

        for cell in primary_cells:
            write_result("primary_cell", cell["attack_condition"], cell["benign_condition"], str(cell["level"]), cell)
        write_result("primary_macro", "all_primary", "matched_benign", "all_levels", macro)
        for group, cells in secondary.items():
            for cell in cells:
                write_result(group, cell["attack_condition"], cell["benign_condition"], str(cell["level"]), cell)


def write_summary_csv(path: Path, macro: dict[str, Any]) -> None:
    fields = ["row_type", "variant_or_comparison", "metric", "mean", "ci95_low", "ci95_high", "n_cells", "n_pairs_by_cell"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for variant, metrics in macro["variants"].items():
            for metric, value in metrics.items():
                writer.writerow({
                    "row_type": "primary_macro", "variant_or_comparison": variant, "metric": metric,
                    "mean": value["mean"], "ci95_low": value["ci95"][0], "ci95_high": value["ci95"][1],
                    "n_cells": value["n_cells"], "n_pairs_by_cell": json.dumps(value["n_pairs_by_cell"]),
                })
        for comparison, value in macro["comparisons"].items():
            writer.writerow({
                "row_type": "primary_macro", "variant_or_comparison": comparison, "metric": "Delta_J",
                "mean": value["mean"], "ci95_low": value["ci95"][0], "ci95_high": value["ci95"][1],
                "n_cells": value["n_cells"], "n_pairs_by_cell": json.dumps(value["n_pairs_by_cell"]),
            })


def main() -> int:
    args = parse_args()
    if args.test.name != TEST_NAME:
        raise SystemExit("Held-out evaluator only accepts a file named held_out_test.csv.gz")
    if any(path.exists() for path in (args.json_output, args.csv_output, args.summary_output)):
        raise SystemExit("Refusing to overwrite held-out outputs; evaluation is permitted exactly once")
    if not args.test.is_file():
        raise SystemExit(f"Held-out test dataset not found: {args.test}")

    # This verification occurs before collect_traces opens the held-out CSV.
    lock_validation = require_lock_validation(args.protocol, args.lock, args.lock_validation)
    protocol = load_json(args.protocol)
    lock = load_json(args.lock)
    if lock.get("status") != "locked-before-test":
        raise SystemExit("Threshold is not locked-before-test")
    candidate = lock.get("selected_candidate")
    if not isinstance(candidate, dict):
        raise SystemExit("Lock has no selected candidate")

    traces, rows_read = collect_traces(args.test)
    expected_test = protocol.get("partition", {}).get("partitions", {}).get("held_out_test", {})
    if rows_read != expected_test.get("decisions"):
        raise SystemExit(f"Held-out row count {rows_read} does not match protocol {expected_test.get('decisions')}")

    selection = protocol["selection"]
    primary_cells: list[dict[str, Any]] = []
    primary_values: list[dict[str, dict[str, list[float]]]] = []
    for attack, benign in selection["matching_benign_conditions"].items():
        for level in selection["levels"]:
            cell, values = evaluate_cell(traces, attack, benign, level, candidate, "primary")
            primary_cells.append(cell)
            primary_values.append(values)
    primary_macro = macro_result(primary_cells, primary_values)

    secondary: dict[str, list[dict[str, Any]]] = {"negative_control": [], "failure_probes": []}
    for level in selection["levels"]:
        cell, _ = evaluate_cell(traces, "attack_random_continuous", "benign_continuous", level, candidate, "negative_control")
        secondary["negative_control"].append(cell)
    for attack in selection["failure_probe_treatment"]["conditions"]:
        for level in selection["levels"]:
            cell, _ = evaluate_cell(traces, attack, "benign_continuous", level, candidate, "failure_probe")
            secondary["failure_probes"].append(cell)

    result = {
        "schema_version": 1,
        "status": "held_out_evaluation_complete_once",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "held_out_evaluation": {
            "evaluation_count": 1,
            "candidate": candidate,
            "threshold_source": str(args.lock),
            "threshold_lock_sha256": sha256_file(args.lock),
            "lock_validation": {"path": str(args.lock_validation), "status": lock_validation["status"], "sha256": sha256_file(args.lock_validation)},
            "test_input": {"path": str(args.test), "sha256": sha256_file(args.test), "rows_read": rows_read},
            "note": "The locked threshold was evaluated once. No sweep or threshold selection was performed during held-out evaluation."
        },
        "bootstrap": {
            "replicates": BOOTSTRAP_REPLICATES,
            "unit": "paired_trace",
            "confidence_interval": "95% percentile bootstrap CI",
            "macro_method": "stratified resampling of paired traces within each equally weighted primary cell"
        },
        "primary": {"cells": primary_cells, "macro": primary_macro},
        "secondary_reports": secondary,
        "asr": {
            "status": "not_measured_not_supported_by_E2_decision_level_data",
            "note": "Synthetic attack-alert is not ASR or poisoning-prevention evidence."
        }
    }
    args.json_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_cell_csv(args.csv_output, primary_cells, primary_macro, secondary)
    write_summary_csv(args.summary_output, primary_macro)
    print("Held-out evaluation complete once; no threshold selection performed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
