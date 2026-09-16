#!/usr/bin/env python3
"""Validate that E3 threshold locking is reproducible before held-out test.

Only protocol, validation-grid, and lock JSON artifacts are opened.  No
decision CSV is read, including held_out_test.csv.gz.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
E3_ROOT = SCRIPT_DIR.parent
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


def rank_key(entry: dict[str, Any]) -> tuple[float, float, float, int, float, float]:
    macro = entry["primary"]["macro"]
    candidate = entry["candidate"]
    return (
        -float(macro["delta_J_new_vs_B2"]),
        float(macro["benign_trigger_rate"]),
        -float(macro["attack_alert_rate"]),
        int(candidate["min_samples"]),
        float(candidate["entropy_threshold"]),
        float(candidate["unique_ratio_threshold"]),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument("--grid", type=Path, default=E3_ROOT / "e3_validation_grid.json")
    parser.add_argument("--lock", type=Path, default=E3_ROOT / "e3_locked_threshold.json")
    parser.add_argument("--output", type=Path, default=E3_ROOT / "e3_lock_validation.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "E3 lock validation",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data_access_policy": {
            "decision_csv_opened": False,
            "held_out_test_csv_opened": False,
            "opened_artifacts": [str(args.protocol), str(args.grid), str(args.lock)],
        },
        "checks": checks,
    }
    try:
        protocol = load_json(args.protocol)
        grid = load_json(args.grid)
        lock = load_json(args.lock)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add_check(checks, "lock_artifacts_readable", False, str(exc))
        report["status"] = "FAIL"
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    protocol_hash = sha256_file(args.protocol)
    grid_hash = sha256_file(args.grid)
    lock_hash = sha256_file(args.lock)
    report["artifact_hashes"] = {
        "protocol": {"path": str(args.protocol), "sha256": protocol_hash},
        "validation_grid": {"path": str(args.grid), "sha256": grid_hash},
        "lock": {"path": str(args.lock), "sha256": lock_hash},
    }

    selection = protocol.get("selection", {})
    add_check(
        checks,
        "registered_selection_criterion_and_tie_break_are_supported",
        selection.get("primary_criterion") == EXPECTED_CRITERION
        and selection.get("tie_breaking_in_order") == EXPECTED_TIE_BREAK
        and selection.get("hard_constraints") == "none",
        {
            "criterion": selection.get("primary_criterion"),
            "tie_break": selection.get("tie_breaking_in_order"),
            "hard_constraints": selection.get("hard_constraints"),
        },
    )
    add_check(
        checks,
        "validation_grid_provenance_matches_protocol",
        grid.get("protocol", {}).get("sha256") == protocol_hash,
        {"grid_protocol_hash": grid.get("protocol", {}).get("sha256"), "actual_protocol_hash": protocol_hash},
    )
    add_check(
        checks,
        "lock_provenance_matches_protocol_and_validation_grid",
        lock.get("protocol", {}).get("sha256") == protocol_hash
        and lock.get("validation_grid", {}).get("sha256") == grid_hash,
        {
            "lock_protocol_hash": lock.get("protocol", {}).get("sha256"),
            "actual_protocol_hash": protocol_hash,
            "lock_grid_hash": lock.get("validation_grid", {}).get("sha256"),
            "actual_grid_hash": grid_hash,
        },
    )
    add_check(
        checks,
        "lock_status_and_held_out_guard",
        lock.get("status") == "locked-before-test"
        and lock.get("held_out_test_read_status") == "not_read"
        and grid.get("data_access_policy", {}).get("held_out_test_csv_opened") is False,
        {
            "lock_status": lock.get("status"),
            "lock_held_out_status": lock.get("held_out_test_read_status"),
            "grid_held_out_opened": grid.get("data_access_policy", {}).get("held_out_test_csv_opened"),
        },
    )

    candidates = grid.get("candidates", [])
    unique_candidates = {
        (entry["candidate"]["min_samples"], entry["candidate"]["entropy_threshold"], entry["candidate"]["unique_ratio_threshold"])
        for entry in candidates
    }
    add_check(
        checks,
        "validation_grid_has_60_unique_complete_primary_candidates",
        len(candidates) == 60 and len(unique_candidates) == 60
        and all(len(entry.get("primary", {}).get("cells", [])) == 8 for entry in candidates),
        {"candidate_count": len(candidates), "unique_count": len(unique_candidates)},
    )

    if candidates:
        ranked = sorted(candidates, key=rank_key)
        recomputed_selected = ranked[0]["candidate"]
        locked_selected = lock.get("selected_candidate")
        add_check(
            checks,
            "locked_candidate_is_recomputed_rank_1",
            locked_selected == recomputed_selected,
            {"locked_candidate": locked_selected, "recomputed_rank_1": recomputed_selected},
        )
        lock_ranking = lock.get("ranking", [])
        expected_ranking = [entry["candidate"] for entry in ranked]
        observed_ranking = [entry.get("candidate") for entry in lock_ranking]
        add_check(
            checks,
            "lock_ranking_matches_recomputed_criterion_and_tie_break",
            observed_ranking == expected_ranking,
            {"lock_ranking_count": len(observed_ranking), "expected_ranking_count": len(expected_ranking)},
        )
    else:
        add_check(checks, "locked_candidate_is_recomputed_rank_1", False, "No grid candidates")
        add_check(checks, "lock_ranking_matches_recomputed_criterion_and_tie_break", False, "No grid candidates")

    add_check(
        checks,
        "locked_candidate_appears_unchanged_in_registered_grid",
        tuple(lock.get("selected_candidate", {}).get(field) for field in (
            "min_samples", "entropy_threshold", "unique_ratio_threshold"
        )) in unique_candidates,
        {"locked_candidate": lock.get("selected_candidate")},
    )
    add_check(
        checks,
        "lock_records_no_test_data_use",
        lock.get("selection_data") == "validation-grid artifact only; no held-out decision data opened",
        {"selection_data": lock.get("selection_data")},
    )

    failures = [check["name"] for check in checks if check["status"] == "FAIL"]
    report["status"] = "PASS" if not failures else "FAIL"
    report["critical_failures"] = failures
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"E3 lock validation: {report['status']} ({len(checks)} checks)")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
