#!/usr/bin/env python3
"""Validate E3 inputs and scoring semantics before validation is opened.

This program intentionally reads only the E3 train/exploration CSV plus JSON
protocol/manifest/provenance metadata.  It must never open validation.csv.gz or
held_out_test.csv.gz: validation is reserved for threshold selection and test
is reserved for the locked final evaluation.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import itertools
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
E3_ROOT = SCRIPT_DIR.parent
CANONICAL_E2_ROOT = (
    E3_ROOT.parent / "E2" / "runs" / "E2_confirmatory_20260814_complete_b0_ablation"
)
TRAIN_PARTITION = "train_exploration"
EXPECTED_QUERIES_PER_RUN = 150
REQUIRED_COLUMNS = {
    "source_e2_split",
    "e3_split",
    "profile",
    "condition",
    "role",
    "level",
    "pair_id",
    "arrival_schedule_sha256",
    "query_schedule_sha256",
    "query_idx",
    "samples",
    "entropy",
    "unique_ratio",
    "block_combined",
    "block_volume",
}
TRACE_FIELDS = (
    "source_e2_split",
    "profile",
    "level",
    "pair_id",
    "arrival_schedule_sha256",
    "query_schedule_sha256",
)
CONDITION_RUN_FIELDS = (
    "source_e2_split",
    "profile",
    "condition",
    "role",
    "level",
    "pair_id",
    "arrival_schedule_sha256",
    "query_schedule_sha256",
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
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def bool_from_csv(value: str) -> bool:
    if value not in {"0", "1"}:
        raise ValueError(f"Expected detector flag 0 or 1, got {value!r}")
    return value == "1"


def new_b5_block(samples: int, entropy: float, unique_ratio: float,
                 min_samples: int, entropy_threshold: float,
                 unique_ratio_threshold: float) -> bool:
    """Registered B5 rule; every threshold comparison is inclusive."""
    return (
        samples >= min_samples
        and entropy >= entropy_threshold
        and unique_ratio >= unique_ratio_threshold
    )


def mean_block(values: Iterable[bool]) -> float:
    observations = list(values)
    if not observations:
        raise ValueError("A paired trace has no decision windows")
    return sum(observations) / len(observations)


def youden_j(attack_alert_rate: float, benign_trigger_rate: float) -> float:
    return attack_alert_rate - benign_trigger_rate


def delta_j(new_b5_j: float, b2_j: float) -> float:
    return new_b5_j - b2_j


def add_check(checks: list[dict[str, Any]], name: str, critical: bool,
              passed: bool, details: Any) -> None:
    checks.append({
        "name": name,
        "critical": critical,
        "status": "PASS" if passed else "FAIL",
        "details": details,
    })


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=E3_ROOT / "datasets" / "splits_60_20_20" / "split_manifest.json",
    )
    parser.add_argument(
        "--train",
        type=Path,
        default=E3_ROOT / "datasets" / "splits_60_20_20" / "train_exploration.csv.gz",
    )
    parser.add_argument(
        "--e2-protocol",
        type=Path,
        default=CANONICAL_E2_ROOT / "e2_protocol.json",
    )
    parser.add_argument(
        "--e2-validation",
        type=Path,
        default=CANONICAL_E2_ROOT / "validation.json",
    )
    parser.add_argument("--output", type=Path, default=E3_ROOT / "e3_preflight.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks: list[dict[str, Any]] = []
    output: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "E3 preflight",
        "data_access_policy": {
            "opened_decision_dataset": str(args.train),
            "validation_csv_opened": False,
            "held_out_test_csv_opened": False,
            "note": "Only train_exploration.csv.gz is opened. E2 protocol/validation JSON are provenance metadata."
        },
        "checks": checks,
    }

    # Fail safely if a caller tries to substitute a protected partition.
    forbidden_names = {"validation.csv.gz", "held_out_test.csv.gz"}
    train_name_allowed = args.train.name not in forbidden_names and args.train.name == "train_exploration.csv.gz"
    add_check(checks, "train_path_is_the_only_permitted_decision_dataset", True,
              train_name_allowed, {"path": str(args.train)})

    try:
        protocol = load_json(args.protocol)
        manifest = load_json(args.manifest)
        e2_protocol = load_json(args.e2_protocol)
        e2_validation = load_json(args.e2_validation)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add_check(checks, "required_protocol_and_provenance_metadata_readable", True, False, str(exc))
        output["status"] = "FAIL"
        args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    add_check(
        checks,
        "e2_canonical_validation_passes",
        True,
        e2_validation.get("status") == "PASS" and len(e2_validation.get("checks", [])) == 18,
        {"status": e2_validation.get("status"), "check_count": len(e2_validation.get("checks", []))},
    )
    add_check(
        checks,
        "e2_protocol_semantics",
        True,
        e2_protocol.get("raw_schema_version") == 2
        and e2_protocol.get("queries_per_run") == EXPECTED_QUERIES_PER_RUN
        and e2_protocol.get("operating_point", {}).get("window_seconds") == 2.0
        and e2_protocol.get("levels_samples_per_window") == [24, 60, 120, 200],
        {
            "raw_schema_version": e2_protocol.get("raw_schema_version"),
            "queries_per_run": e2_protocol.get("queries_per_run"),
            "window_seconds": e2_protocol.get("operating_point", {}).get("window_seconds"),
            "levels": e2_protocol.get("levels_samples_per_window"),
        },
    )

    expected_manifest_hash = protocol.get("partition", {}).get("manifest_sha256")
    manifest_hash = sha256_file(args.manifest)
    add_check(
        checks,
        "split_manifest_hash_matches_protocol",
        True,
        manifest_hash == expected_manifest_hash,
        {"expected": expected_manifest_hash, "observed": manifest_hash},
    )
    add_check(
        checks,
        "manifest_input_hash_matches_protocol_input_hash",
        True,
        manifest.get("input", {}).get("sha256") == protocol.get("input_dataset", {}).get("sha256"),
        {
            "manifest_input_sha256": manifest.get("input", {}).get("sha256"),
            "protocol_input_sha256": protocol.get("input_dataset", {}).get("sha256"),
        },
    )

    expected_train = protocol.get("partition", {}).get("partitions", {}).get(TRAIN_PARTITION, {})
    train_hash = sha256_file(args.train) if args.train.is_file() else None
    add_check(
        checks,
        "train_hash_matches_protocol",
        True,
        train_hash == expected_train.get("sha256"),
        {"expected": expected_train.get("sha256"), "observed": train_hash},
    )

    rows = 0
    condition_run_counts: Counter[tuple[str, ...]] = Counter()
    condition_run_query_indices: dict[tuple[str, ...], set[int]] = defaultdict(set)
    trace_conditions: dict[tuple[str, ...], set[str]] = defaultdict(set)
    trace_schedule_values: dict[tuple[str, str, str, str], set[tuple[str, str]]] = defaultdict(set)
    b2_mismatches = 0
    old_b5_mismatches = 0
    mismatch_examples: dict[str, list[dict[str, Any]]] = {"B2": [], "old_B5": []}
    header: list[str] | None = None

    if train_name_allowed and args.train.is_file():
        try:
            with gzip.open(args.train, "rt", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                header = reader.fieldnames
                missing_columns = REQUIRED_COLUMNS.difference(header or [])
                add_check(checks, "train_schema_contains_required_columns", True, not missing_columns,
                          {"missing": sorted(missing_columns), "header": header})
                if missing_columns:
                    raise ValueError("Cannot continue without required train columns")

                for row in reader:
                    rows += 1
                    if row["e3_split"] != TRAIN_PARTITION:
                        raise ValueError(f"Row {rows} has e3_split={row['e3_split']!r}")
                    condition_key = tuple(row[field] for field in CONDITION_RUN_FIELDS)
                    trace_key = tuple(row[field] for field in TRACE_FIELDS)
                    schedule_identity = (
                        row["source_e2_split"], row["profile"], row["level"], row["pair_id"]
                    )
                    condition_run_counts[condition_key] += 1
                    condition_run_query_indices[condition_key].add(int(row["query_idx"]))
                    trace_conditions[trace_key].add(row["condition"])
                    trace_schedule_values[schedule_identity].add(
                        (row["arrival_schedule_sha256"], row["query_schedule_sha256"])
                    )

                    samples = int(row["samples"])
                    entropy = float(row["entropy"])
                    unique_ratio = float(row["unique_ratio"])
                    expected_b2 = samples >= 24
                    expected_old_b5 = new_b5_block(samples, entropy, unique_ratio, 24, 4.0, 0.70)
                    observed_b2 = bool_from_csv(row["block_volume"])
                    observed_old_b5 = bool_from_csv(row["block_combined"])
                    if expected_b2 != observed_b2:
                        b2_mismatches += 1
                        if len(mismatch_examples["B2"]) < 5:
                            mismatch_examples["B2"].append({"query_idx": row["query_idx"], "samples": samples})
                    if expected_old_b5 != observed_old_b5:
                        old_b5_mismatches += 1
                        if len(mismatch_examples["old_B5"]) < 5:
                            mismatch_examples["old_B5"].append({
                                "query_idx": row["query_idx"], "samples": samples,
                                "entropy": entropy, "unique_ratio": unique_ratio,
                            })
        except (OSError, ValueError, csv.Error) as exc:
            add_check(checks, "train_csv_read_and_row_semantics", True, False, str(exc))
    else:
        add_check(checks, "train_csv_read_and_row_semantics", True, False,
                  "Protected partition path or missing train file")

    expected_decisions = expected_train.get("decisions")
    add_check(checks, "train_decision_count_matches_protocol", True, rows == expected_decisions,
              {"expected": expected_decisions, "observed": rows})
    add_check(
        checks,
        "each_condition_run_has_exactly_150_decisions",
        True,
        bool(condition_run_counts)
        and all(count == EXPECTED_QUERIES_PER_RUN for count in condition_run_counts.values())
        and all(indices == set(range(1, EXPECTED_QUERIES_PER_RUN + 1))
                for indices in condition_run_query_indices.values()),
        {
            "condition_runs": len(condition_run_counts),
            "invalid_count_runs": sum(count != EXPECTED_QUERIES_PER_RUN for count in condition_run_counts.values()),
            "invalid_query_index_runs": sum(
                indices != set(range(1, EXPECTED_QUERIES_PER_RUN + 1))
                for indices in condition_run_query_indices.values()
            ),
        },
    )
    add_check(
        checks,
        "paired_trace_count_matches_protocol",
        True,
        len(trace_conditions) == expected_train.get("paired_traces"),
        {"expected": expected_train.get("paired_traces"), "observed": len(trace_conditions)},
    )
    add_check(
        checks,
        "one_schedule_identity_per_source_split_profile_level_pair",
        True,
        all(len(hashes) == 1 for hashes in trace_schedule_values.values()),
        {"identities": len(trace_schedule_values), "violations": sum(len(hashes) != 1 for hashes in trace_schedule_values.values())},
    )

    primary_to_benign = protocol.get("selection", {}).get("matching_benign_conditions", {})
    pairing_violations: list[dict[str, Any]] = []
    for trace_key, conditions in trace_conditions.items():
        for attack_condition, benign_condition in primary_to_benign.items():
            if attack_condition in conditions and benign_condition not in conditions:
                pairing_violations.append({"trace": trace_key, "attack": attack_condition, "missing_benign": benign_condition})
    add_check(
        checks,
        "primary_attack_traces_have_matching_benign_trace",
        True,
        not pairing_violations,
        {"violations": pairing_violations[:5], "violation_count": len(pairing_violations)},
    )
    add_check(checks, "recomputed_B2_matches_block_volume", True, b2_mismatches == 0,
              {"mismatch_count": b2_mismatches, "examples": mismatch_examples["B2"]})
    add_check(checks, "recomputed_old_B5_matches_block_combined", True, old_b5_mismatches == 0,
              {"mismatch_count": old_b5_mismatches, "examples": mismatch_examples["old_B5"]})

    grid = list(itertools.product(
        protocol.get("candidate_grid", {}).get("min_samples", []),
        protocol.get("candidate_grid", {}).get("entropy_threshold", []),
        protocol.get("candidate_grid", {}).get("unique_ratio_threshold", []),
    ))
    old_b5 = protocol.get("decision_rule", {}).get("old_B5_operating_point", {})
    old_b5_tuple = (old_b5.get("min_samples"), old_b5.get("entropy_threshold"), old_b5.get("unique_ratio_threshold"))
    add_check(
        checks,
        "registered_grid_has_60_unique_candidates_and_contains_old_B5",
        True,
        len(grid) == 60 and len(set(grid)) == 60 and old_b5_tuple in grid,
        {"candidate_count": len(grid), "unique_candidate_count": len(set(grid)), "old_B5": old_b5_tuple, "old_B5_in_grid": old_b5_tuple in grid},
    )
    boundary_cases = {
        "all_equal_thresholds_blocks": new_b5_block(24, 4.0, 0.70, 24, 4.0, 0.70),
        "samples_below_threshold_allows": not new_b5_block(23, 4.0, 0.70, 24, 4.0, 0.70),
        "entropy_below_threshold_allows": not new_b5_block(24, 3.999999, 0.70, 24, 4.0, 0.70),
        "unique_ratio_below_threshold_allows": not new_b5_block(24, 4.0, 0.699999, 24, 4.0, 0.70),
    }
    add_check(checks, "new_B5_boundary_semantics_are_inclusive_greater_than_or_equal", True,
              all(boundary_cases.values()), boundary_cases)

    synthetic_new_j = youden_j(mean_block([True, True, False, True]), mean_block([True, False, False, False]))
    synthetic_b2_j = youden_j(mean_block([True, True, False, False]), mean_block([True, False, False, False]))
    synthetic_delta = delta_j(synthetic_new_j, synthetic_b2_j)
    add_check(
        checks,
        "paired_trace_J_and_delta_J_unit_test",
        True,
        abs(synthetic_new_j - 0.5) < 1e-12
        and abs(synthetic_b2_j - 0.25) < 1e-12
        and abs(synthetic_delta - 0.25) < 1e-12,
        {"new_B5_J": synthetic_new_j, "B2_J": synthetic_b2_j, "delta_J_new_vs_B2": synthetic_delta},
    )

    critical_failures = [check["name"] for check in checks if check["critical"] and check["status"] == "FAIL"]
    output["status"] = "PASS" if not critical_failures else "FAIL"
    output["critical_failures"] = critical_failures
    output["summary"] = {
        "train_decisions_read": rows,
        "train_condition_runs": len(condition_run_counts),
        "train_paired_traces": len(trace_conditions),
        "bootstrap_run": False,
        "candidate_ranking_run": False,
        "candidate_selected": False,
    }
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"E3 preflight: {output['status']} ({len(checks)} checks)")
    return 0 if output["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
