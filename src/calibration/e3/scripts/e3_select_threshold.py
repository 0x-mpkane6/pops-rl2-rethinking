#!/usr/bin/env python3
"""Apply the registered E3 validation criterion and lock one threshold.

This script reads only e3_protocol.json and the validation-sweep JSON.  It
never opens any decision CSV, especially not held_out_test.csv.gz.
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument("--grid", type=Path, default=E3_ROOT / "e3_validation_grid.json")
    parser.add_argument("--output", type=Path, default=E3_ROOT / "e3_locked_threshold.json")
    return parser.parse_args()


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


def main() -> int:
    args = parse_args()
    if args.output.exists():
        raise SystemExit(f"Refusing to overwrite existing lock file: {args.output}")
    protocol = load_json(args.protocol)
    grid = load_json(args.grid)

    selection = protocol.get("selection", {})
    if selection.get("primary_criterion") != EXPECTED_CRITERION:
        raise SystemExit("Protocol primary criterion does not match the registered E3 criterion")
    if selection.get("tie_breaking_in_order") != EXPECTED_TIE_BREAK:
        raise SystemExit("Protocol tie-break rule does not match the registered E3 tie-break")
    if selection.get("hard_constraints") != "none":
        raise SystemExit("This selector implements the registered no-hard-constraint protocol only")
    if grid.get("status") != "validation_sweep_complete_no_selection":
        raise SystemExit("Grid is not a completed no-selection validation sweep")
    if grid.get("data_access_policy", {}).get("held_out_test_csv_opened") is not False:
        raise SystemExit("Grid provenance does not prove that held-out test remained unopened")
    if grid.get("protocol", {}).get("sha256") != sha256_file(args.protocol):
        raise SystemExit("Validation grid was produced with a different protocol file")

    candidates = grid.get("candidates", [])
    candidate_keys = {
        (
            entry["candidate"]["min_samples"],
            entry["candidate"]["entropy_threshold"],
            entry["candidate"]["unique_ratio_threshold"],
        )
        for entry in candidates
    }
    if len(candidates) != 60 or len(candidate_keys) != 60:
        raise SystemExit("Validation grid must contain exactly 60 unique candidates")
    if any(len(entry.get("primary", {}).get("cells", [])) != 8 for entry in candidates):
        raise SystemExit("Every candidate must include the 8 registered primary condition/level cells")

    ranked = sorted(candidates, key=rank_key)
    selected = ranked[0]
    selected_candidate = selected["candidate"]
    ranking = []
    for rank, entry in enumerate(ranked, start=1):
        macro = entry["primary"]["macro"]
        ranking.append({
            "rank": rank,
            "candidate": entry["candidate"],
            "macro_delta_J_new_vs_B2": macro["delta_J_new_vs_B2"],
            "macro_benign_trigger_rate": macro["benign_trigger_rate"],
            "macro_attack_alert_rate": macro["attack_alert_rate"],
        })

    lock = {
        "schema_version": 1,
        "status": "locked-before-test",
        "locked_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "selection_data": "validation-grid artifact only; no held-out decision data opened",
        "selected_candidate": selected_candidate,
        "selected_candidate_primary_macro": selected["primary"]["macro"],
        "criterion": selection["primary_criterion"],
        "aggregation": selection["aggregation"],
        "hard_constraints": selection["hard_constraints"],
        "tie_breaking_in_order": selection["tie_breaking_in_order"],
        "ranking": ranking,
        "protocol": {"path": str(args.protocol), "sha256": sha256_file(args.protocol)},
        "validation_grid": {
            "path": str(args.grid),
            "sha256": sha256_file(args.grid),
            "validation_input": grid.get("validation_input"),
        },
        "partition_manifest": {
            "path": protocol.get("partition", {}).get("manifest_path"),
            "sha256": protocol.get("partition", {}).get("manifest_sha256"),
        },
        "held_out_test_read_status": "not_read",
        "next_permitted_step": "Run a lock validator, then evaluate this unchanged candidate on held_out_test exactly once."
    }
    args.output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Threshold locked before test:", json.dumps(selected_candidate, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
