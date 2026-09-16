#!/usr/bin/env python3
"""Independent integrity audit for the completed E3 threshold experiment.

This validator replays the already-completed held-out evaluation exclusively to
audit derived results.  It never sweeps candidates, selects a threshold, or
modifies protocol/lock/test artifacts.
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
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
E3_ROOT = SCRIPT_DIR.parent
BOOTSTRAP_REPLICATES = 5000
METRICS = ("attack_alert_rate", "benign_trigger_rate", "FNR", "balanced_precision", "J")
TRACE_FIELDS = (
    "source_e2_split", "profile", "level", "pair_id",
    "arrival_schedule_sha256", "query_schedule_sha256",
)
REQUIRED_COLUMNS = {
    "source_e2_split", "e3_split", "profile", "condition", "role", "level", "pair_id",
    "arrival_schedule_sha256", "query_schedule_sha256", "query_idx", "samples", "entropy",
    "unique_ratio", "block_volume", "block_combined",
}
EXPECTED_CRITERION = "maximize macro delta_J_new_vs_B2"
EXPECTED_TIE_BREAK = [
    "higher macro delta_J_new_vs_B2",
    "lower macro benign_trigger_rate on primary cells",
    "higher macro attack_alert_rate on primary cells",
    "ascending tuple (min_samples, entropy_threshold, unique_ratio_threshold)",
]


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


def add_check(checks: list[dict[str, Any]], name: str, passed: bool, details: Any) -> None:
    checks.append({"name": name, "critical": True, "status": "PASS" if passed else "FAIL", "details": details})


def close(left: float, right: float, tolerance: float = 1e-12) -> bool:
    return math.isclose(float(left), float(right), abs_tol=tolerance, rel_tol=tolerance)


def csv_bool(value: str) -> bool:
    if value not in {"0", "1"}:
        raise ValueError(f"Expected detector flag 0 or 1, got {value!r}")
    return value == "1"


def trace_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[field] for field in TRACE_FIELDS)


def new_b5_block(row: dict[str, str], candidate: dict[str, Any]) -> bool:
    return (
        int(row["samples"]) >= int(candidate["min_samples"])
        and float(row["entropy"]) >= float(candidate["entropy_threshold"])
        and float(row["unique_ratio"]) >= float(candidate["unique_ratio_threshold"])
    )


def rate(rows: list[dict[str, str]], variant: str, candidate: dict[str, Any]) -> float:
    if variant == "new_B5":
        return fmean(new_b5_block(row, candidate) for row in rows)
    if variant == "B2":
        return fmean(csv_bool(row["block_volume"]) for row in rows)
    if variant == "old_B5":
        return fmean(csv_bool(row["block_combined"]) for row in rows)
    raise ValueError(variant)


def stable_seed(*parts: object) -> int:
    return int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest()[:8], "big")


def percentile(values: list[float], quantile: float) -> float:
    index = (len(values) - 1) * quantile
    low, high = math.floor(index), math.ceil(index)
    return values[low] if low == high else values[low] + (values[high] - values[low]) * (index - low)


def bootstrap_mean(values: list[float], seed_parts: tuple[object, ...]) -> dict[str, Any]:
    rng = random.Random(stable_seed(*seed_parts))
    count = len(values)
    resamples = [fmean(values[rng.randrange(count)] for _ in range(count)) for _ in range(BOOTSTRAP_REPLICATES)]
    resamples.sort()
    return {"mean": fmean(values), "ci95": [percentile(resamples, .025), percentile(resamples, .975)], "n_pairs": count}


def bootstrap_macro(cell_values: list[list[float]], seed_parts: tuple[object, ...]) -> dict[str, Any]:
    rng = random.Random(stable_seed(*seed_parts))
    resamples: list[float] = []
    for _ in range(BOOTSTRAP_REPLICATES):
        means = []
        for values in cell_values:
            count = len(values)
            means.append(fmean(values[rng.randrange(count)] for _ in range(count)))
        resamples.append(fmean(means))
    resamples.sort()
    return {
        "mean": fmean(fmean(values) for values in cell_values),
        "ci95": [percentile(resamples, .025), percentile(resamples, .975)],
        "n_cells": len(cell_values),
        "n_pairs_by_cell": [len(values) for values in cell_values],
    }


def rank_key(entry: dict[str, Any]) -> tuple[float, float, float, int, float, float]:
    macro = entry["primary"]["macro"]
    candidate = entry["candidate"]
    return (-float(macro["delta_J_new_vs_B2"]), float(macro["benign_trigger_rate"]),
            -float(macro["attack_alert_rate"]), int(candidate["min_samples"]),
            float(candidate["entropy_threshold"]), float(candidate["unique_ratio_threshold"]))


def calculate_cell(traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]], attack: str,
                   benign: str, level: int, candidate: dict[str, Any], scope: str) -> tuple[dict[str, Any], dict[str, dict[str, list[float]]]]:
    values = {variant: {metric: [] for metric in METRICS} for variant in ("new_B5", "B2", "old_B5")}
    for key, conditions in sorted(traces.items()):
        if int(key[2]) != level or attack not in conditions:
            continue
        if benign not in conditions:
            raise ValueError(f"Missing paired benign trace for {attack}: {key}")
        attack_rows, benign_rows = conditions[attack], conditions[benign]
        if len(attack_rows) != len(benign_rows):
            raise ValueError(f"Pair count mismatch: {key}")
        for variant in values:
            attack_rate, benign_rate = rate(attack_rows, variant, candidate), rate(benign_rows, variant, candidate)
            values[variant]["attack_alert_rate"].append(attack_rate)
            values[variant]["benign_trigger_rate"].append(benign_rate)
            values[variant]["FNR"].append(1 - attack_rate)
            values[variant]["balanced_precision"].append((attack_rate + 1 - benign_rate) / 2)
            values[variant]["J"].append(attack_rate - benign_rate)
    if not values["new_B5"]["J"]:
        raise ValueError(f"No pairs: {attack}/{level}")
    variants = {
        variant: {metric: bootstrap_mean(series, ("E3", "test", scope, attack, level, variant, metric))
                  for metric, series in metrics.items()}
        for variant, metrics in values.items()
    }
    comparisons = {}
    for baseline in ("B2", "old_B5"):
        delta = [a - b for a, b in zip(values["new_B5"]["J"], values[baseline]["J"])]
        comparisons[f"Delta_J_new_B5_minus_{baseline}"] = bootstrap_mean(
            delta, ("E3", "test", scope, attack, level, "new_B5", baseline, "Delta_J")
        )
    return {"variants": variants, "comparisons": comparisons, "n_pairs": len(values["new_B5"]["J"])}, values


def compare_summary(observed: dict[str, Any], expected: dict[str, Any]) -> bool:
    if observed.get("n_pairs") != expected.get("n_pairs"):
        return False
    for variant in ("new_B5", "B2", "old_B5"):
        for metric in METRICS:
            left, right = observed["variants"][variant][metric], expected["variants"][variant][metric]
            if left.get("n_pairs") != right.get("n_pairs") or not close(left["mean"], right["mean"]) or any(not close(a, b) for a, b in zip(left["ci95"], right["ci95"])):
                return False
    for comparison in ("Delta_J_new_B5_minus_B2", "Delta_J_new_B5_minus_old_B5"):
        left, right = observed["comparisons"][comparison], expected["comparisons"][comparison]
        if left.get("n_pairs") != right.get("n_pairs") or not close(left["mean"], right["mean"]) or any(not close(a, b) for a, b in zip(left["ci95"], right["ci95"])):
            return False
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument("--manifest", type=Path, default=E3_ROOT / "datasets" / "splits_60_20_20" / "split_manifest.json")
    parser.add_argument("--grid", type=Path, default=E3_ROOT / "e3_validation_grid.json")
    parser.add_argument("--lock", type=Path, default=E3_ROOT / "e3_locked_threshold.json")
    parser.add_argument("--lock-validation", type=Path, default=E3_ROOT / "e3_lock_validation.json")
    parser.add_argument("--test", type=Path, default=E3_ROOT / "datasets" / "splits_60_20_20" / "held_out_test.csv.gz")
    parser.add_argument("--test-results", type=Path, default=E3_ROOT / "e3_test_results.json")
    parser.add_argument("--test-csv", type=Path, default=E3_ROOT / "e3_test_results.csv")
    parser.add_argument("--summary-csv", type=Path, default=E3_ROOT / "e3_summary.csv")
    parser.add_argument("--output", type=Path, default=E3_ROOT / "e3_validation.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {"schema_version": 1, "experiment": "E3 independent artifact audit",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "checks": checks,
        "audit_scope": "Post-test integrity replay only; no selection or threshold modification."}
    try:
        protocol, manifest, grid = load_json(args.protocol), load_json(args.manifest), load_json(args.grid)
        lock, lock_validation, test_result = load_json(args.lock), load_json(args.lock_validation), load_json(args.test_results)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add_check(checks, "required_artifacts_are_readable", False, str(exc))
        report["status"] = "FAIL"
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    hashes = {name: {"path": str(path), "sha256": sha256_file(path)} for name, path in {
        "protocol": args.protocol, "split_manifest": args.manifest, "validation_grid": args.grid,
        "lock": args.lock, "lock_validation": args.lock_validation, "held_out_test": args.test,
        "test_results": args.test_results, "test_csv": args.test_csv, "summary_csv": args.summary_csv,
    }.items()}
    report["artifact_hashes"] = hashes
    add_check(checks, "input_and_split_provenance_hashes", 
        protocol.get("input_dataset", {}).get("sha256") == manifest.get("input", {}).get("sha256")
        and protocol.get("partition", {}).get("manifest_sha256") == hashes["split_manifest"]["sha256"]
        and protocol.get("partition", {}).get("partitions", {}).get("held_out_test", {}).get("sha256") == hashes["held_out_test"]["sha256"],
        {"protocol_input": protocol.get("input_dataset", {}).get("sha256"), "manifest_input": manifest.get("input", {}).get("sha256")})

    selection = protocol.get("selection", {})
    add_check(checks, "registered_selection_rule_is_unchanged", selection.get("primary_criterion") == EXPECTED_CRITERION
              and selection.get("tie_breaking_in_order") == EXPECTED_TIE_BREAK and selection.get("hard_constraints") == "none",
              {"criterion": selection.get("primary_criterion"), "tie_break": selection.get("tie_breaking_in_order")})
    add_check(checks, "grid_and_lock_provenance_hashes", grid.get("protocol", {}).get("sha256") == hashes["protocol"]["sha256"]
              and lock.get("protocol", {}).get("sha256") == hashes["protocol"]["sha256"]
              and lock.get("validation_grid", {}).get("sha256") == hashes["validation_grid"]["sha256"],
              {"grid_protocol": grid.get("protocol", {}).get("sha256"), "lock_grid": lock.get("validation_grid", {}).get("sha256")})
    add_check(checks, "lock_validation_and_test_provenance", lock_validation.get("status") == "PASS"
              and not lock_validation.get("critical_failures")
              and test_result.get("held_out_evaluation", {}).get("threshold_lock_sha256") == hashes["lock"]["sha256"]
              and test_result.get("held_out_evaluation", {}).get("lock_validation", {}).get("sha256") == hashes["lock_validation"]["sha256"],
              {"lock_validation_status": lock_validation.get("status"), "test_lock_hash": test_result.get("held_out_evaluation", {}).get("threshold_lock_sha256")})

    candidates = grid.get("candidates", [])
    candidate_keys = {(c["candidate"]["min_samples"], c["candidate"]["entropy_threshold"], c["candidate"]["unique_ratio_threshold"]) for c in candidates}
    ranked = sorted(candidates, key=rank_key) if candidates else []
    add_check(checks, "validation_grid_has_60_candidates_and_reproducible_winner", len(candidates) == 60 and len(candidate_keys) == 60
              and all(len(c.get("primary", {}).get("cells", [])) == 8 for c in candidates)
              and bool(ranked) and lock.get("selected_candidate") == ranked[0]["candidate"],
              {"candidate_count": len(candidates), "locked": lock.get("selected_candidate"), "recomputed_winner": ranked[0]["candidate"] if ranked else None})
    add_check(checks, "held_out_test_was_evaluated_once_with_locked_candidate", test_result.get("status") == "held_out_evaluation_complete_once"
              and test_result.get("held_out_evaluation", {}).get("evaluation_count") == 1
              and test_result.get("held_out_evaluation", {}).get("candidate") == lock.get("selected_candidate"),
              {"test_status": test_result.get("status"), "count": test_result.get("held_out_evaluation", {}).get("evaluation_count")})
    add_check(checks, "asr_is_explicitly_not_measured", test_result.get("asr", {}).get("status") == "not_measured_not_supported_by_E2_decision_level_data",
              test_result.get("asr"))

    candidate = lock.get("selected_candidate", {})
    traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    rows = 0
    b2_mismatch = old_mismatch = 0
    try:
        with gzip.open(args.test, "rt", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            missing = REQUIRED_COLUMNS.difference(reader.fieldnames or [])
            if missing:
                raise ValueError(f"held-out schema missing: {sorted(missing)}")
            for row in reader:
                rows += 1
                if row["e3_split"] != "held_out_test":
                    raise ValueError(f"unexpected E3 split {row['e3_split']}")
                traces[trace_key(row)][row["condition"]].append(row)
                if (int(row["samples"]) >= 24) != csv_bool(row["block_volume"]):
                    b2_mismatch += 1
                old = (int(row["samples"]) >= 24 and float(row["entropy"]) >= 4.0 and float(row["unique_ratio"]) >= .70)
                if old != csv_bool(row["block_combined"]):
                    old_mismatch += 1
    except (OSError, ValueError, csv.Error) as exc:
        add_check(checks, "held_out_replay_input_schema_and_split", False, str(exc))
        report["status"] = "FAIL"
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    expected_rows = protocol.get("partition", {}).get("partitions", {}).get("held_out_test", {}).get("decisions")
    add_check(checks, "held_out_replay_input_schema_and_split", rows == expected_rows,
              {"rows": rows, "expected_rows": expected_rows, "paired_traces": len(traces)})
    add_check(checks, "recomputed_B2_and_old_B5_match_E2_flags", b2_mismatch == 0 and old_mismatch == 0,
              {"B2_mismatches": b2_mismatch, "old_B5_mismatches": old_mismatch})

    try:
        primary_cells, primary_values = [], []
        for attack, benign in selection["matching_benign_conditions"].items():
            for level in selection["levels"]:
                cell, values = calculate_cell(traces, attack, benign, level, candidate, "primary")
                primary_cells.append(cell)
                primary_values.append(values)
        observed_cells = {(c["attack_condition"], c["level"]): c for c in test_result["primary"]["cells"]}
        cell_pass = len(observed_cells) == 8
        for attack, benign in selection["matching_benign_conditions"].items():
            for level in selection["levels"]:
                expected_cell, _ = calculate_cell(traces, attack, benign, level, candidate, "primary")
                observed = observed_cells.get((attack, level))
                if observed is None or not compare_summary(observed, expected_cell):
                    cell_pass = False
        add_check(checks, "held_out_primary_cells_recompute_exactly", cell_pass, {"expected_cell_count": 8, "observed_cell_count": len(observed_cells)})

        macro_variants = {}
        for variant in ("new_B5", "B2", "old_B5"):
            macro_variants[variant] = {metric: bootstrap_macro([v[variant][metric] for v in primary_values], ("E3", "test", "primary_macro", variant, metric)) for metric in METRICS}
        macro_comparisons = {}
        for baseline in ("B2", "old_B5"):
            deltas = [[a - b for a, b in zip(v["new_B5"]["J"], v[baseline]["J"])] for v in primary_values]
            macro_comparisons[f"Delta_J_new_B5_minus_{baseline}"] = bootstrap_macro(deltas, ("E3", "test", "primary_macro", "new_B5", baseline, "Delta_J"))
        observed_macro = test_result["primary"]["macro"]
        macro_pass = True
        for variant in macro_variants:
            for metric in METRICS:
                left, right = observed_macro["variants"][variant][metric], macro_variants[variant][metric]
                macro_pass &= close(left["mean"], right["mean"]) and all(close(a, b) for a, b in zip(left["ci95"], right["ci95"])) and left["n_pairs_by_cell"] == right["n_pairs_by_cell"]
        for comparison in macro_comparisons:
            left, right = observed_macro["comparisons"][comparison], macro_comparisons[comparison]
            macro_pass &= close(left["mean"], right["mean"]) and all(close(a, b) for a, b in zip(left["ci95"], right["ci95"])) and left["n_pairs_by_cell"] == right["n_pairs_by_cell"]
        add_check(checks, "held_out_primary_macro_J_delta_J_and_5000_bootstrap_CI_recompute_exactly", macro_pass,
                  {"replicates": BOOTSTRAP_REPLICATES, "unit": "paired_trace", "cells": 8})
    except (KeyError, ValueError, TypeError) as exc:
        add_check(checks, "held_out_primary_cells_recompute_exactly", False, str(exc))
        add_check(checks, "held_out_primary_macro_J_delta_J_and_5000_bootstrap_CI_recompute_exactly", False, str(exc))

    try:
        with args.test_csv.open("r", encoding="utf-8", newline="") as handle:
            test_csv_rows = list(csv.DictReader(handle))
        with args.summary_csv.open("r", encoding="utf-8", newline="") as handle:
            summary_rows = list(csv.DictReader(handle))
        expected_summary_rows = 17  # 3 variants x 5 metrics + 2 Delta-J comparisons.
        add_check(checks, "test_csv_and_summary_csv_are_present_and_consistent_with_json", len(test_csv_rows) == 357 and len(summary_rows) == expected_summary_rows,
                  {"test_csv_rows": len(test_csv_rows), "summary_csv_rows": len(summary_rows), "expected_summary_rows": expected_summary_rows})
    except (OSError, csv.Error) as exc:
        add_check(checks, "test_csv_and_summary_csv_are_present_and_consistent_with_json", False, str(exc))

    failures = [check["name"] for check in checks if check["status"] == "FAIL"]
    report["status"] = "PASS" if not failures else "FAIL"
    report["critical_failures"] = failures
    report["summary"] = {"bootstrap_recomputed": BOOTSTRAP_REPLICATES, "test_rows_replayed": rows,
                           "selection_or_sweep_performed": False, "threshold_modified": False}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"E3 independent validation: {report['status']} ({len(checks)} checks)")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
