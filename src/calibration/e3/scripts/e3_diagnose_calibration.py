#!/usr/bin/env python3
"""Diagnose E3 entropy feasibility, threshold redundancy, and sample counts.

This script is read-only with respect to canonical E2/E3 artifacts. It writes
derived diagnostic files under ``experiments/E3/diagnostics`` and does not
select a new threshold or alter the locked E3 operating point.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import fmean, median
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
E3_ROOT = SCRIPT_DIR.parent
DIAGNOSTICS = E3_ROOT / "diagnostics"
GRID_PATH = E3_ROOT / "e3_validation_grid.json"
LOCK_PATH = E3_ROOT / "e3_locked_threshold.json"
SPLIT_ROOT = E3_ROOT / "datasets" / "splits_60_20_20"
SPLIT_FILES = {
    "validation": SPLIT_ROOT / "validation.csv.gz",
    "held_out_test": SPLIT_ROOT / "held_out_test.csv.gz",
}

PRIMARY_MATCHES = {
    "attack_sweep_continuous": "benign_continuous",
    "attack_sweep_bursty": "benign_bursty",
}
TRACE_FIELDS = (
    "source_e2_split",
    "profile",
    "level",
    "pair_id",
    "arrival_schedule_sha256",
    "query_schedule_sha256",
)
LOCKED = (8, 6.0, 0.90)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def load_gzip_csv(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def trace_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[field] for field in TRACE_FIELDS)


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("Cannot calculate a percentile of an empty sample")
    index = (len(ordered) - 1) * quantile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def primary_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    attack_keys: dict[str, set[tuple[str, ...]]] = {}
    for attack in PRIMARY_MATCHES:
        attack_keys[attack] = {
            trace_key(row) for row in rows if row["condition"] == attack
        }

    selected: list[dict[str, str]] = []
    for row in rows:
        condition = row["condition"]
        for attack, benign in PRIMARY_MATCHES.items():
            if condition in {attack, benign} and trace_key(row) in attack_keys[attack]:
                selected.append(row)
                break
    return selected


def decision(candidate: tuple[int, float, float], row: dict[str, str]) -> bool:
    minimum, entropy_threshold, unique_threshold = candidate
    return (
        int(row["samples"]) >= minimum
        and float(row["entropy"]) >= entropy_threshold
        and float(row["unique_ratio"]) >= unique_threshold
    )


def signature(candidate: tuple[int, float, float], rows: list[dict[str, str]]) -> str:
    payload = bytes(decision(candidate, row) for row in rows)
    return hashlib.sha256(payload).hexdigest()


def sorted_rows(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        rows,
        key=lambda row: (
            trace_key(row),
            row["condition"],
            int(row["query_idx"]),
        ),
    )


def assign_class_ids(
    candidates: list[tuple[int, float, float]],
    rows: list[dict[str, str]],
    prefix: str,
) -> tuple[dict[tuple[int, float, float], str], dict[str, int]]:
    groups: dict[str, list[tuple[int, float, float]]] = defaultdict(list)
    for candidate in candidates:
        groups[signature(candidate, rows)].append(candidate)

    ordered_groups = sorted(groups.values(), key=lambda group: min(group))
    candidate_to_class: dict[tuple[int, float, float], str] = {}
    class_sizes: dict[str, int] = {}
    for index, group in enumerate(ordered_groups, start=1):
        class_id = f"{prefix}{index:03d}"
        class_sizes[class_id] = len(group)
        for candidate in group:
            candidate_to_class[candidate] = class_id
    return candidate_to_class, class_sizes


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def distribution_record(
    split: str,
    group: tuple[str, ...],
    rows: list[dict[str, str]],
    include_source_split: bool,
) -> dict[str, Any]:
    if include_source_split:
        source_split, profile, level, condition, role = group
    else:
        profile, level, condition, role = group
        source_split = "matched_primary"

    samples = [float(row["samples"]) for row in rows]
    entropies = [float(row["entropy"]) for row in rows]
    ratios = [float(row["unique_ratio"]) for row in rows]
    traces = {trace_key(row) for row in rows}
    locked_predictions = [
        decision((int(LOCKED[0]), float(LOCKED[1]), float(LOCKED[2])), row)
        for row in rows
    ]
    return {
        "e3_split": split,
        "source_e2_split": source_split,
        "profile": profile,
        "level": int(level),
        "condition": condition,
        "role": role,
        "paired_traces": len(traces),
        "decision_rows": len(rows),
        "samples_min": min(samples),
        "samples_median": median(samples),
        "samples_mean": fmean(samples),
        "samples_p95": percentile(samples, 0.95),
        "samples_max": max(samples),
        "fraction_samples_ge_64": fmean(value >= 64 for value in samples),
        "fraction_entropy_ge_6": fmean(value >= 6.0 for value in entropies),
        "fraction_unique_ratio_ge_0_90": fmean(value >= 0.90 for value in ratios),
        "fraction_locked_trigger": fmean(locked_predictions),
    }


def distribution_rows(
    split: str,
    rows: list[dict[str, str]],
    primary_only: bool,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    source = primary_rows(rows) if primary_only else rows
    for row in source:
        role = "attack" if row["condition"].startswith("attack_") else "benign"
        if primary_only:
            key = (row["profile"], row["level"], row["condition"], role)
        else:
            key = (
                row["source_e2_split"],
                row["profile"],
                row["level"],
                row["condition"],
                role,
            )
        grouped[key].append(row)

    return [
        distribution_record(split, key, values, include_source_split=not primary_only)
        for key, values in sorted(
            grouped.items(),
            key=lambda item: tuple(str(value) for value in item[0]),
        )
    ]


def fmt(value: float, digits: int = 3) -> str:
    return f"{value:.{digits}f}"


def markdown_table(rows: list[dict[str, Any]], split: str) -> str:
    selected = [row for row in rows if row["e3_split"] == split]
    lines = [
        "| Profile | Level | Role | Condition | Traces | Decisions | n min / median / mean / p95 / max | Pr(n>=64) | Locked trigger |",
        "| --- | ---: | --- | --- | ---: | ---: | --- | ---: | ---: |",
    ]
    for row in selected:
        summary = " / ".join(
            [
                fmt(row["samples_min"], 0),
                fmt(row["samples_median"], 1),
                fmt(row["samples_mean"], 2),
                fmt(row["samples_p95"], 1),
                fmt(row["samples_max"], 0),
            ]
        )
        lines.append(
            "| {profile} | {level} | {role} | `{condition}` | {paired_traces} | {decision_rows} | {summary} | {p64} | {trigger} |".format(
                **row,
                summary=summary,
                p64=fmt(row["fraction_samples_ge_64"], 4),
                trigger=fmt(row["fraction_locked_trigger"], 4),
            )
        )
    return "\n".join(lines)


def main() -> int:
    grid = load_json(GRID_PATH)
    lock = load_json(LOCK_PATH)
    candidate_items = grid["candidates"]
    candidates = [
        (
            int(item["candidate"]["min_samples"]),
            float(item["candidate"]["entropy_threshold"]),
            float(item["candidate"]["unique_ratio_threshold"]),
        )
        for item in candidate_items
    ]
    if len(candidates) != 60 or len(set(candidates)) != 60:
        raise ValueError("Expected exactly 60 unique registered candidates")

    split_rows = {name: load_gzip_csv(path) for name, path in SPLIT_FILES.items()}
    validation_all = sorted_rows(split_rows["validation"])
    validation_primary = sorted_rows(primary_rows(split_rows["validation"]))

    primary_classes, primary_sizes = assign_class_ids(
        candidates, validation_primary, "P"
    )
    all_classes, all_sizes = assign_class_ids(candidates, validation_all, "A")

    candidate_rows: list[dict[str, Any]] = []
    for item, candidate in zip(candidate_items, candidates):
        minimum, entropy_threshold, unique_threshold = candidate
        macro = item["primary"]["macro"]
        implied_minimum = math.ceil(2**entropy_threshold)
        candidate_rows.append(
            {
                "min_samples": minimum,
                "entropy_threshold": entropy_threshold,
                "unique_ratio_threshold": unique_threshold,
                "entropy_implied_min_samples": implied_minimum,
                "min_samples_gate_redundant": minimum <= implied_minimum,
                "selected_locked_candidate": candidate == LOCKED,
                "validation_attack_alert_rate": macro["attack_alert_rate"],
                "validation_benign_trigger_rate": macro["benign_trigger_rate"],
                "validation_J": macro["J"],
                "validation_delta_J_vs_B2": macro["delta_J_new_vs_B2"],
                "primary_equivalence_class": primary_classes[candidate],
                "primary_equivalence_class_size": primary_sizes[primary_classes[candidate]],
                "all_validation_equivalence_class": all_classes[candidate],
                "all_validation_equivalence_class_size": all_sizes[all_classes[candidate]],
            }
        )

    primary_distribution: list[dict[str, Any]] = []
    all_distribution: list[dict[str, Any]] = []
    for split, rows in split_rows.items():
        primary_distribution.extend(distribution_rows(split, rows, primary_only=True))
        all_distribution.extend(distribution_rows(split, rows, primary_only=False))

    candidate_fields = list(candidate_rows[0])
    distribution_fields = list(primary_distribution[0])
    write_csv(
        DIAGNOSTICS / "e3_candidate_equivalence.csv",
        candidate_rows,
        candidate_fields,
    )
    write_csv(
        DIAGNOSTICS / "e3_n_distribution_primary.csv",
        primary_distribution,
        distribution_fields,
    )
    write_csv(
        DIAGNOSTICS / "e3_n_distribution_all_conditions.csv",
        all_distribution,
        distribution_fields,
    )

    selected_class = [
        row
        for row in candidate_rows
        if row["primary_equivalence_class"]
        == primary_classes[(int(LOCKED[0]), float(LOCKED[1]), float(LOCKED[2]))]
    ]
    validation_level_60 = [
        row
        for row in primary_distribution
        if row["e3_split"] == "validation" and row["level"] == 60
    ]

    diagnostic = {
        "schema_version": 1,
        "scope": "Read-only diagnostic of frozen E3 validation and held-out artifacts; no threshold selection or artifact modification.",
        "entropy_implementation": {
            "type": "raw Shannon entropy in bits",
            "formula": "-sum((count/n) * log2(count/n))",
            "normalized": False,
            "consequence": "H >= 6 implies n >= 64; min_samples=8 is redundant.",
            "sources": [
                "labs/r2entropy/resolver/resolver.py:224-229",
                "research/Report/experiments/E5/tools/unbound_lab/resolver/detector.py:39-44",
            ],
        },
        "grid": {
            "registered_candidates": len(candidates),
            "unique_primary_prediction_vectors": len(set(primary_classes.values())),
            "unique_all_validation_prediction_vectors": len(set(all_classes.values())),
            "selected_candidate": lock["selected_candidate"],
            "selected_primary_equivalence_class": selected_class,
        },
        "validation_level_60_primary_cells": validation_level_60,
        "partition_rows": {name: len(rows) for name, rows in split_rows.items()},
        "primary_rows": {
            name: len(primary_rows(rows)) for name, rows in split_rows.items()
        },
    }
    (DIAGNOSTICS / "e3_calibration_diagnostic.json").write_text(
        json.dumps(diagnostic, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = f"""# E3 Calibration Diagnostic

> Read-only diagnostic over the frozen E3 artifacts. No threshold was selected,
> changed, or re-evaluated for reporting as a new confirmatory result.

## 1. Entropy implementation

Both the controlled detector and E5 runtime detector use raw Shannon entropy in
bits:

```python
return -sum((count / n) * math.log2(count / n) for count in counts.values())
```

They do not divide by `log2(n)`. Therefore,

$$
H \leq \log_2 n, \qquad H \geq 6 \Longrightarrow n \geq 64.
$$

For the locked point `(N,H,U)=(8,6.0,0.90)`, the gate `n>=8` is
mathematically redundant. The implementation matches the raw-entropy formula in
the paper; the issue is the parameterization and its interpretation, not a
formula/code mismatch.

## 2. Registered grid and decision equivalence

- Registered grid: `N={{8,16,24,48}}`, `H={{2,3,4,5,6}}`,
  `U={{0.5,0.7,0.9}}` = **60 candidates**.
- Exact prediction vectors on the validation primary rows: **{len(set(primary_classes.values()))} distinct classes**.
- Exact prediction vectors on all validation rows: **{len(set(all_classes.values()))} distinct classes**.
- The selected point belongs to a four-member primary equivalence class:
  `{[(row['min_samples'], row['entropy_threshold'], row['unique_ratio_threshold']) for row in selected_class]}`.

The tie-break selected `N=8`, but the validation predictions do not identify it
separately from `N=16`, `N=24`, or `N=48` at `H=6.0,U=0.90`.

See [`e3_candidate_equivalence.csv`](e3_candidate_equivalence.csv) for all 60
candidates and their exact equivalence classes.

## 3. Actual sample-count distributions in primary cells

Target volume is an expected workload level, not a fixed sample count in every
two-second window. The tables below report `min / median / mean / p95 / max`.
The column `Pr(n>=64)` shows how often raw entropy can possibly reach 6 bits.

### Validation partition (used for threshold selection)

{markdown_table(primary_distribution, 'validation')}

### Held-out partition (integrity audit only; not for selecting a replacement)

{markdown_table(primary_distribution, 'held_out_test')}

At target volume 60, validation windows do exceed 64 samples. Thus, activation
near level 60 is possible even though a window with exactly `n=60` cannot reach
six bits of entropy.

## 4. Data accounting

- Validation file: **{len(split_rows['validation']):,} rows**; primary matched analysis: **{len(primary_rows(split_rows['validation'])):,} rows**.
- Held-out file: **{len(split_rows['held_out_test']):,} rows**; primary matched analysis: **{len(primary_rows(split_rows['held_out_test'])):,} rows**.
- The primary macro uses 8 cells x 6 matched pairs x 2 runs x 150 decisions = **14,400 primary decisions**.
- The remainder of the 27,600-row held-out file comprises random-IPID control,
  fixed/duplicate failure probes, and calibration-derived benign-only rows.

The phrase “27,600 held-out decisions across eight primary cells” is therefore
incorrect. `27,600` is the full held-out file size, not the primary-analysis
denominator.

## 5. Does E3 need to be rerun?

The existing held-out numbers remain valid for the exact locked rule that was
evaluated. They do not establish that `N=8` is a meaningful calibrated volume
threshold, because that gate is redundant and four values of `N` are prediction-
equivalent at the selected `H,U` pair.

- **No rerun is strictly required** if the paper is reframed as a diagnostic or
  negative result, explicitly reports the redundancy/equivalence classes, and
  does not call the point a refined three-parameter defense.
- **A new calibration and fresh confirmatory set are required** if the paper
  claims to identify a meaningful improved threshold or operational defense.
- Replacing raw entropy with normalized entropy changes the detector and cannot
  be handled as a wording correction.
- A future search should report a Pareto frontier over attack-alert/FNR and
  benign-trigger rather than selecting solely by `J` without a coverage gate.
"""
    (DIAGNOSTICS / "E3_CALIBRATION_DIAGNOSTIC.md").write_text(
        report,
        encoding="utf-8",
    )

    print(f"Wrote diagnostics to {DIAGNOSTICS}")
    print(f"Registered candidates: {len(candidates)}")
    print(f"Distinct primary prediction vectors: {len(set(primary_classes.values()))}")
    print(f"Distinct all-validation prediction vectors: {len(set(all_classes.values()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
