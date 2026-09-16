"""Integrity and protocol validation for an isolated E1 artifact directory."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
import time
from collections import defaultdict
from pathlib import Path


VARIANTS = ("legacy", "combined", "volume", "entropy", "unique")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_event_raw(artifact_dir: Path, rows: list[dict], expected_phase: str,
                       operating_point: dict) -> tuple[list[str], int, set[str]]:
    """Cross-check every retained decision record against its per-run summary."""
    errors: list[str] = []
    total_records = 0
    seen_paths: set[str] = set()
    for row in rows:
        run_label = (f"{expected_phase}/{row['behavior']}/"
                     f"{row['level_samples_per_window']}/run-{row['run_idx']}")
        relative = row.get("raw_decisions_file", "")
        if not relative or relative in seen_paths:
            errors.append(f"{run_label}: missing/duplicate raw path")
            continue
        seen_paths.add(relative)
        raw_path = (artifact_dir / relative).resolve()
        try:
            raw_path.relative_to(artifact_dir)
        except ValueError:
            errors.append(f"{run_label}: raw path escapes artifact")
            continue
        if not raw_path.is_file():
            errors.append(f"{run_label}: missing {relative}")
            continue
        if sha256_file(raw_path) != row.get("raw_decisions_sha256"):
            errors.append(f"{run_label}: sha256 mismatch")

        expected_decisions = int(row["decisions"])
        expected_static = {
            "phase": expected_phase,
            "behavior": row["behavior"],
            "level_samples_per_window": int(row["level_samples_per_window"]),
            "run_idx": int(row["run_idx"]),
            "seed": int(row["seed"]),
        }
        count = 0
        blocks = {variant: 0 for variant in VARIANTS}
        entropy_sum = 0.0
        samples_sum = 0.0
        unique_ratio_sum = 0.0
        previous_timestamp = -math.inf
        previous_elapsed = -math.inf
        with raw_path.open(encoding="utf-8") as handle:
            for count, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    errors.append(f"{run_label}: invalid JSON at decision {count}")
                    continue
                if not isinstance(record, dict):
                    errors.append(f"{run_label}: record is not an object at {count}")
                    continue
                if record.get("schema_version") != 1:
                    errors.append(f"{run_label}: schema_version mismatch at {count}")
                try:
                    decision_idx = int(record["decision_idx"])
                except (KeyError, TypeError, ValueError):
                    decision_idx = -1
                if decision_idx != count:
                    errors.append(f"{run_label}: non-sequential decision_idx at {count}")
                if any(record.get(key) != value for key, value in expected_static.items()):
                    errors.append(f"{run_label}: static identity mismatch at {count}")
                try:
                    entropy = float(record["entropy"])
                    samples = int(record["samples"])
                    unique_ipids = int(record["unique_ipids"])
                    unique_ratio = float(record["unique_ratio"])
                    timestamp = float(record["virtual_timestamp_seconds"])
                    elapsed = float(record["measurement_elapsed_seconds"])
                except (KeyError, TypeError, ValueError):
                    errors.append(f"{run_label}: invalid metrics at {count}")
                    continue
                if not all(math.isfinite(value) for value in (
                    entropy, unique_ratio, timestamp, elapsed
                )):
                    errors.append(f"{run_label}: non-finite metrics at {count}")
                if not (samples >= unique_ipids >= 1 and 0.0 <= unique_ratio <= 1.0):
                    errors.append(f"{run_label}: impossible occupancy at {count}")
                elif abs(unique_ratio - unique_ipids / samples) > 1e-12:
                    errors.append(f"{run_label}: unique ratio mismatch at {count}")
                if timestamp <= previous_timestamp or elapsed <= previous_elapsed:
                    errors.append(f"{run_label}: non-monotonic time at {count}")
                previous_timestamp = timestamp
                previous_elapsed = elapsed
                entropy_sum += entropy
                samples_sum += samples
                unique_ratio_sum += unique_ratio
                expected_blocks = {
                    "legacy": True,
                    "volume": samples >= int(operating_point["min_samples"]),
                    "entropy": entropy >= float(operating_point["entropy_threshold"]),
                    "unique": unique_ratio >= float(
                        operating_point["unique_ratio_threshold"]
                    ),
                }
                expected_blocks["combined"] = (
                    expected_blocks["volume"] and expected_blocks["entropy"]
                    and expected_blocks["unique"]
                )
                for variant in VARIANTS:
                    value = record.get(f"block_{variant}")
                    if not isinstance(value, bool):
                        errors.append(f"{run_label}: non-boolean block_{variant} at {count}")
                    elif value != expected_blocks[variant]:
                        errors.append(f"{run_label}: block_{variant} rule mismatch at {count}")
                    blocks[variant] += int(value is True)

        total_records += count
        if count != expected_decisions:
            errors.append(f"{run_label}: records={count} expected={expected_decisions}")
            continue
        for variant in VARIANTS:
            if blocks[variant] != int(row[f"blocks_{variant}"]):
                errors.append(f"{run_label}: block_{variant} mismatch")
        if abs(entropy_sum / count - float(row["entropy_mean"])) > 0.000051:
            errors.append(f"{run_label}: entropy mean mismatch")
        if abs(samples_sum / count - float(row["samples_mean"])) > 0.000501:
            errors.append(f"{run_label}: samples mean mismatch")
        if abs(unique_ratio_sum / count - float(row["unique_ratio_mean"])) > 0.000051:
            errors.append(f"{run_label}: unique mean mismatch")
    return errors, total_records, seen_paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an E1 artifact package")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()
    artifact_dir = args.artifact_dir.resolve()

    checks: list[dict] = []

    def check(name: str, condition: bool, detail: str) -> None:
        checks.append({"name": name, "status": "PASS" if condition else "FAIL",
                       "detail": detail})
        print(f"[{'PASS' if condition else 'FAIL'}] {name}: {detail}")

    required = ["e1_protocol.json", "e1_runs.csv", "e1_levels.csv", "e1_results.json"]
    missing = [name for name in required if not (artifact_dir / name).is_file()]
    check("required_files", not missing, "missing=" + repr(missing))
    if missing:
        return 1

    protocol = json.loads((artifact_dir / "e1_protocol.json").read_text(encoding="utf-8"))
    results = json.loads((artifact_dir / "e1_results.json").read_text(encoding="utf-8"))
    meta = results["meta"]

    check("registered_before_collection",
          protocol.get("status") == "registered-before-data-collection",
          str(protocol.get("status")))
    check("run_id_match", protocol.get("run_id") == meta.get("run_id"),
          f"protocol={protocol.get('run_id')} results={meta.get('run_id')}")
    check("independent_unit", meta.get("independent_unit") == "run",
          str(meta.get("independent_unit")))

    with (artifact_dir / "e1_runs.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    levels = [int(value) for value in meta["levels_samples_per_window"]]
    behaviors = list(meta["behaviors"])
    runs_per_cell = int(meta["runs_per_cell"])
    decisions_per_run = int(meta["decisions_per_run"])
    expected_rows = len(levels) * len(behaviors) * runs_per_cell
    check("main_row_count", len(rows) == expected_rows,
          f"observed={len(rows)} expected={expected_rows}")
    seeds = [int(row["seed"]) for row in rows]
    check("unique_main_seeds", len(set(seeds)) == len(seeds),
          f"unique={len(set(seeds))} rows={len(seeds)}")
    check("complete_runs",
          all(int(row["decisions"]) == decisions_per_run for row in rows),
          f"decisions/run={decisions_per_run}")
    main_raw_errors, main_raw_records, main_raw_paths = validate_event_raw(
        artifact_dir, rows, "main", protocol["operating_point"]
    )
    expected_main_records = expected_rows * decisions_per_run
    check("main_event_level_raw",
          not main_raw_errors and main_raw_records == expected_main_records,
          f"records={main_raw_records} expected={expected_main_records}"
          if not main_raw_errors else repr(main_raw_errors[:12]))

    by_cell: dict[tuple[int, str], list[dict]] = defaultdict(list)
    finite = True
    rates_positive = True
    for row in rows:
        key = (int(row["level_samples_per_window"]), row["behavior"])
        by_cell[key].append(row)
        numeric_fields = ("samples_mean", "actual_fragments_per_second",
                          "entropy_mean", "unique_ratio_mean")
        finite &= all(math.isfinite(float(row[field])) for field in numeric_fields)
        rates_positive &= float(row["actual_fragments_per_second"]) > 0
    check("finite_metrics", finite, "samples/rate/entropy/unique are finite")
    check("positive_actual_rates", rates_positive, "all measured rates > 0")
    cell_sizes = sorted({len(value) for value in by_cell.values()})
    check("balanced_cells", cell_sizes == [runs_per_cell], f"cell_sizes={cell_sizes}")

    occupancy_failures = []
    for (level, behavior), cell_rows in sorted(by_cell.items()):
        observed = sum(float(row["samples_mean"]) for row in cell_rows) / len(cell_rows)
        tolerance = max(0.75, level * 0.05)
        if abs(observed - level) > tolerance:
            occupancy_failures.append(
                {"level": level, "behavior": behavior, "observed": observed,
                 "tolerance": tolerance}
            )
    check("target_occupancy", not occupancy_failures,
          "all cell means within max(0.75, 5%) of target" if not occupancy_failures
          else repr(occupancy_failures))

    result_cells = {(int(entry["level"]), entry["behavior"]): entry
                    for entry in results["levels"]}
    aggregate_errors = []
    for key, cell_rows in by_cell.items():
        entry = result_cells.get(key)
        if entry is None:
            aggregate_errors.append(f"missing result cell {key}")
            continue
        for variant in VARIANTS:
            blocks = sum(int(row[f"blocks_{variant}"]) for row in cell_rows)
            decisions = sum(int(row["decisions"]) for row in cell_rows)
            run_mean = sum(float(row[f"fpr_{variant}"]) for row in cell_rows) / len(cell_rows)
            aggregate = entry["variants"][variant]
            if blocks != int(aggregate["blocks_total"]):
                aggregate_errors.append(f"{key}/{variant}: blocks")
            if decisions != int(aggregate["decisions_total"]):
                aggregate_errors.append(f"{key}/{variant}: decisions")
            if abs(run_mean - float(aggregate["fpr_run_mean"])) > 5e-7:
                aggregate_errors.append(f"{key}/{variant}: fpr mean")
            lo, hi = aggregate["fpr_cluster_bootstrap_ci95"]
            point = float(aggregate["fpr_pooled"])
            if not (float(lo) - 1e-12 <= point <= float(hi) + 1e-12):
                aggregate_errors.append(f"{key}/{variant}: cluster CI excludes point")
    check("raw_to_json_aggregation", not aggregate_errors,
          "all aggregates match raw" if not aggregate_errors else repr(aggregate_errors[:12]))

    high_levels = protocol.get("high_load_levels_exploratory", [])
    high_path = artifact_dir / "e1_high_load_runs.csv"
    if high_levels:
        with high_path.open(newline="", encoding="utf-8") as handle:
            high_rows = list(csv.DictReader(handle))
        expected_high = len(high_levels) * runs_per_cell
        check("high_load_raw", len(high_rows) == expected_high,
              f"observed={len(high_rows)} expected={expected_high}")
        high_seeds = [int(row["seed"]) for row in high_rows]
        check("unique_high_load_seeds", len(set(high_seeds)) == len(high_seeds),
              f"unique={len(set(high_seeds))} rows={len(high_seeds)}")
        high_raw_errors, high_raw_records, high_raw_paths = validate_event_raw(
            artifact_dir, high_rows, "high_load", protocol["operating_point"]
        )
        expected_high_records = expected_high * decisions_per_run
        check("high_load_event_level_raw",
              not high_raw_errors and high_raw_records == expected_high_records,
              f"records={high_raw_records} expected={expected_high_records}"
              if not high_raw_errors else repr(high_raw_errors[:12]))
        referenced_raw_paths = main_raw_paths | high_raw_paths
    else:
        check("high_load_skipped", not high_path.exists(), "registered as skipped")
        high_dir = artifact_dir / "raw_decisions" / "high_load"
        check("high_load_event_raw_skipped", not high_dir.exists(),
              "no unregistered high-load event raw")
        referenced_raw_paths = main_raw_paths

    on_disk_raw_paths = {
        path.relative_to(artifact_dir).as_posix()
        for path in (artifact_dir / "raw_decisions").rglob("*.jsonl")
    }
    raw_inventory_errors = sorted(on_disk_raw_paths ^ referenced_raw_paths)
    check("event_raw_inventory", not raw_inventory_errors,
          f"referenced={len(referenced_raw_paths)} on_disk={len(on_disk_raw_paths)}"
          if not raw_inventory_errors else repr(raw_inventory_errors[:12]))

    hash_errors = []
    for name, item in protocol.get("source_manifest", {}).items():
        snapshot = Path(item["snapshot"])
        if not snapshot.is_file() or sha256_file(snapshot) != item["sha256"]:
            hash_errors.append(name)
    check("source_snapshot_hashes", not hash_errors,
          "all exact source snapshots match" if not hash_errors else repr(hash_errors))

    failures = [item for item in checks if item["status"] == "FAIL"]
    validation = {
        "schema_version": 1,
        "artifact_dir": str(artifact_dir),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "warnings": [
            "This campaign is controlled emulation, not real IP fragmentation.",
            "Simulation scores after inserting the current FRAG2; Docker emits paired FRAG2 asynchronously after FRAG1.",
            "Event-level Clopper-Pearson intervals are descriptive only because windows overlap.",
            "Detector latency/throughput/CPU/memory are not measured by virtual-time simulation.",
        ],
    }
    if not args.no_write:
        (artifact_dir / "validation.json").write_text(
            json.dumps(validation, indent=2), encoding="utf-8"
        )
    print(f"E1 VALIDATION: {validation['status']} ({len(checks) - len(failures)}/{len(checks)})")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
