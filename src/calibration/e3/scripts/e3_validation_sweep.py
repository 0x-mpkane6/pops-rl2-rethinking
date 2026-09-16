#!/usr/bin/env python3
"""Score the registered E3 grid on validation only; never select a threshold.

The only decision-level input opened by this script is validation.csv.gz.
Held-out test data is deliberately neither accepted nor referenced as input.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import itertools
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
E3_ROOT = SCRIPT_DIR.parent
VALIDATION_NAME = "validation.csv.gz"
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


def new_b5_block(row: dict[str, str], candidate: tuple[int, float, float]) -> bool:
    min_samples, entropy_threshold, unique_ratio_threshold = candidate
    return (
        int(row["samples"]) >= min_samples
        and float(row["entropy"]) >= entropy_threshold
        and float(row["unique_ratio"]) >= unique_ratio_threshold
    )


def block_rate(rows: list[dict[str, str]], candidate: tuple[int, float, float] | None) -> float:
    if not rows:
        raise ValueError("Cannot calculate a rate for an empty condition-run")
    if candidate is None:
        return fmean(csv_bool(row["block_volume"]) for row in rows)
    return fmean(new_b5_block(row, candidate) for row in rows)


def trace_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[field] for field in TRACE_FIELDS)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument(
        "--validation", type=Path,
        default=E3_ROOT / "datasets" / "splits_60_20_20" / VALIDATION_NAME,
    )
    parser.add_argument("--csv-output", type=Path, default=E3_ROOT / "e3_validation_grid.csv")
    parser.add_argument("--json-output", type=Path, default=E3_ROOT / "e3_validation_grid.json")
    return parser.parse_args()


def pair_cell(
    traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]],
    attack_condition: str,
    benign_condition: str,
    level: int,
    candidate: tuple[int, float, float],
) -> dict[str, Any]:
    pair_values: list[dict[str, float]] = []
    for key, conditions in sorted(traces.items()):
        if int(key[2]) != level or attack_condition not in conditions:
            continue
        if benign_condition not in conditions:
            raise ValueError(f"Missing {benign_condition} for paired trace {key} and {attack_condition}")
        attack_rows = conditions[attack_condition]
        benign_rows = conditions[benign_condition]
        if len(attack_rows) != len(benign_rows):
            raise ValueError(f"Paired decision count mismatch for trace {key}")
        new_attack = block_rate(attack_rows, candidate)
        new_benign = block_rate(benign_rows, candidate)
        b2_attack = block_rate(attack_rows, None)
        b2_benign = block_rate(benign_rows, None)
        new_j = new_attack - new_benign
        b2_j = b2_attack - b2_benign
        pair_values.append({
            "attack_alert_rate": new_attack,
            "benign_trigger_rate": new_benign,
            "J": new_j,
            "B2_J": b2_j,
            "delta_J_new_vs_B2": new_j - b2_j,
        })
    if not pair_values:
        raise ValueError(f"No paired traces for {attack_condition} level {level}")
    return {
        "attack_condition": attack_condition,
        "benign_condition": benign_condition,
        "level": level,
        "n_pairs": len(pair_values),
        "attack_alert_rate": fmean(item["attack_alert_rate"] for item in pair_values),
        "benign_trigger_rate": fmean(item["benign_trigger_rate"] for item in pair_values),
        "J": fmean(item["J"] for item in pair_values),
        "B2_J": fmean(item["B2_J"] for item in pair_values),
        "delta_J_new_vs_B2": fmean(item["delta_J_new_vs_B2"] for item in pair_values),
    }


def macro(cells: list[dict[str, Any]]) -> dict[str, float]:
    return {
        "attack_alert_rate": fmean(cell["attack_alert_rate"] for cell in cells),
        "benign_trigger_rate": fmean(cell["benign_trigger_rate"] for cell in cells),
        "J": fmean(cell["J"] for cell in cells),
        "B2_J": fmean(cell["B2_J"] for cell in cells),
        "delta_J_new_vs_B2": fmean(cell["delta_J_new_vs_B2"] for cell in cells),
    }


def main() -> int:
    args = parse_args()
    if args.validation.name != VALIDATION_NAME:
        raise SystemExit("Validation sweep only accepts a file named validation.csv.gz")
    if not args.validation.is_file():
        raise SystemExit(f"Validation dataset not found: {args.validation}")
    protocol = load_json(args.protocol)
    if protocol.get("selection", {}).get("selection_split") != "validation":
        raise SystemExit("Protocol does not register validation as the selection split")
    if protocol.get("selection_execution_status") != "not_started":
        raise SystemExit("Selection has already started or completed; refusing to re-run the sweep")
    if protocol.get("held_out_test_read_status") != "not_read":
        raise SystemExit("Protocol no longer records an unread held-out test; refusing to sweep")

    traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    rows_read = 0
    with gzip.open(args.validation, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"Validation CSV is missing required columns: {', '.join(sorted(missing))}")
        for row in reader:
            rows_read += 1
            if row["e3_split"] != "validation":
                raise SystemExit(f"Validation input contains e3_split={row['e3_split']!r}")
            traces[trace_key(row)][row["condition"]].append(row)

    grid_config = protocol["candidate_grid"]
    grid = list(itertools.product(
        grid_config["min_samples"],
        grid_config["entropy_threshold"],
        grid_config["unique_ratio_threshold"],
    ))
    if len(grid) != 60 or len(set(grid)) != 60:
        raise SystemExit("Registered candidate grid is not exactly 60 unique operating points")

    selection = protocol["selection"]
    primary_mapping = selection["matching_benign_conditions"]
    levels = selection["levels"]
    secondary_mapping = {
        "attack_random_continuous": "benign_continuous",
        "attack_fixed_continuous": "benign_continuous",
        "attack_dup_sweep_continuous": "benign_continuous",
    }
    candidates: list[dict[str, Any]] = []
    for candidate in grid:
        primary_cells = [
            pair_cell(traces, attack, benign, level, candidate)
            for attack, benign in primary_mapping.items()
            for level in levels
        ]
        secondary = {
            "negative_control": [
                pair_cell(traces, "attack_random_continuous", "benign_continuous", level, candidate)
                for level in levels
            ],
            "failure_probes": {
                attack: [pair_cell(traces, attack, benign, level, candidate) for level in levels]
                for attack, benign in secondary_mapping.items()
                if attack != "attack_random_continuous"
            },
        }
        candidates.append({
            "candidate": {
                "min_samples": candidate[0],
                "entropy_threshold": candidate[1],
                "unique_ratio_threshold": candidate[2],
            },
            "primary": {"macro": macro(primary_cells), "cells": primary_cells},
            "secondary_reports": secondary,
        })

    protocol_hash = sha256_file(args.protocol)
    validation_hash = sha256_file(args.validation)
    result = {
        "schema_version": 1,
        "status": "validation_sweep_complete_no_selection",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data_access_policy": {
            "opened_decision_dataset": str(args.validation),
            "held_out_test_csv_opened": False,
            "note": "This sweep reads validation.csv.gz only; no held-out test data is opened or aggregated."
        },
        "protocol": {"path": str(args.protocol), "sha256": protocol_hash},
        "validation_input": {"path": str(args.validation), "sha256": validation_hash, "rows_read": rows_read},
        "grid": {"candidate_count": len(candidates), "selection_performed": False},
        "selection_rule_reference": {
            "primary_criterion": selection["primary_criterion"],
            "aggregation": selection["aggregation"],
            "tie_breaking_in_order": selection["tie_breaking_in_order"],
            "note": "Recorded for provenance only; this script does not rank or select candidates."
        },
        "candidates": candidates,
    }
    args.json_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with args.csv_output.open("w", encoding="utf-8", newline="") as handle:
        fields = [
            "min_samples", "entropy_threshold", "unique_ratio_threshold", "primary_cell_count",
            "macro_attack_alert_rate", "macro_benign_trigger_rate", "macro_J", "macro_B2_J",
            "macro_delta_J_new_vs_B2",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for entry in candidates:
            candidate = entry["candidate"]
            values = entry["primary"]["macro"]
            writer.writerow({
                **candidate,
                "primary_cell_count": len(entry["primary"]["cells"]),
                "macro_attack_alert_rate": values["attack_alert_rate"],
                "macro_benign_trigger_rate": values["benign_trigger_rate"],
                "macro_J": values["J"],
                "macro_B2_J": values["B2_J"],
                "macro_delta_J_new_vs_B2": values["delta_J_new_vs_B2"],
            })
    print(f"Validation sweep complete: {len(candidates)} candidates; no threshold selected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
