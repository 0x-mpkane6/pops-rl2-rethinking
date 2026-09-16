#!/usr/bin/env python3
"""Create the E3 60/20/20 dataset partitions from E2 decision records.

The unit of assignment is a complete paired trace, not an individual decision
window.  Consequently, every condition which shares a schedule trace and all
150 of its decision windows remain in the same E3 partition.

The output keeps E2's original split as ``source_e2_split`` and writes the new
partition as ``e3_split``.  This distinction is intentional: these files are a
new E3 partition and must not overwrite or be mistaken for E2's canonical
calibration/validation/test split.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import random
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PARTITIONS = ("train_exploration", "validation", "held_out_test")
REQUIRED_COLUMNS = {
    "split",
    "profile",
    "level",
    "pair_id",
    "arrival_schedule_sha256",
    "query_schedule_sha256",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def group_key(row: dict[str, str]) -> tuple[str, str, str, str, str, str]:
    """Return a trace identity shared by all paired E2 conditions."""
    return (
        row["split"],
        row["profile"],
        row["level"],
        row["pair_id"],
        row["arrival_schedule_sha256"],
        row["query_schedule_sha256"],
    )


def stratum(key: tuple[str, str, str, str, str, str]) -> tuple[str, str, str]:
    """Keep source split/profile/level balance in every E3 partition."""
    return key[0], key[1], key[2]


def assign_partitions(
    group_keys: list[tuple[str, str, str, str, str, str]], seed: int
) -> dict[tuple[str, str, str, str, str, str], str]:
    """Allocate paired traces 60% / 20% / 20%, stratified deterministically."""
    by_stratum: dict[tuple[str, str, str], list[tuple[str, str, str, str, str, str]]] = defaultdict(list)
    for key in group_keys:
        by_stratum[stratum(key)].append(key)

    assignment: dict[tuple[str, str, str, str, str, str], str] = {}
    for bucket, keys in sorted(by_stratum.items()):
        # Hash-derived per-stratum seeds make assignments stable even if CSV row
        # order changes or a new stratum is later added.
        material = f"{seed}|{'|'.join(bucket)}".encode("utf-8")
        bucket_seed = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
        ordered = sorted(keys)
        random.Random(bucket_seed).shuffle(ordered)

        n_total = len(ordered)
        n_train = n_total * 3 // 5
        n_validation = n_total // 5
        boundaries = (n_train, n_train + n_validation)
        for index, key in enumerate(ordered):
            assignment[key] = (
                "train_exploration"
                if index < boundaries[0]
                else "validation"
                if index < boundaries[1]
                else "held_out_test"
            )
    return assignment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "datasets" / "e2_decisions.csv.gz",
        help="Canonical E2 decision CSV copied into E3/datasets.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "datasets" / "splits_60_20_20",
        help="Directory for the three E3 partition files and manifest.",
    )
    parser.add_argument("--seed", type=int, default=20260820, help="Deterministic split seed.")
    parser.add_argument("--force", action="store_true", help="Replace an existing output directory.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.is_file():
        raise SystemExit(f"Input dataset not found: {args.input}")
    if args.output_dir.exists():
        if not args.force:
            raise SystemExit(f"Output directory already exists: {args.output_dir} (use --force to replace it)")
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True)

    with gzip.open(args.input, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SystemExit("Input CSV has no header")
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames)
        if missing:
            raise SystemExit(f"Input CSV is missing required columns: {', '.join(sorted(missing))}")
        rows = list(reader)
        source_columns = reader.fieldnames

    groups: dict[tuple[str, str, str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[group_key(row)].append(row)
    assignments = assign_partitions(list(groups), args.seed)

    output_columns = ["source_e2_split", "e3_split", *[c for c in source_columns if c != "split"]]
    output_paths = {partition: args.output_dir / f"{partition}.csv.gz" for partition in PARTITIONS}
    handles: dict[str, Any] = {}
    writers: dict[str, csv.DictWriter] = {}
    try:
        for partition, path in output_paths.items():
            handles[partition] = gzip.open(path, "wt", encoding="utf-8", newline="")
            writers[partition] = csv.DictWriter(handles[partition], fieldnames=output_columns)
            writers[partition].writeheader()
        for key in sorted(groups):
            partition = assignments[key]
            for row in groups[key]:
                output_row = {"source_e2_split": row["split"], "e3_split": partition}
                output_row.update({column: row[column] for column in source_columns if column != "split"})
                writers[partition].writerow(output_row)
    finally:
        for handle in handles.values():
            handle.close()

    decision_counts = Counter()
    trace_counts = Counter(assignments.values())
    stratum_counts: dict[str, dict[str, int]] = {}
    for key, partition in assignments.items():
        decision_counts[partition] += len(groups[key])
        label = "/".join(stratum(key))
        stratum_counts[label] = stratum_counts.get(label, {name: 0 for name in PARTITIONS})
        stratum_counts[label][partition] += 1

    manifest = {
        "schema_version": 1,
        "purpose": "E3 60/20/20 split by paired trace; never split decision windows within a trace.",
        "warning": (
            "source_e2_split is preserved for provenance. Because this re-partitions E2 records, "
            "it is not E2's canonical held-out-test split."
        ),
        "input": {"path": str(args.input), "sha256": sha256_file(args.input)},
        "seed": args.seed,
        "group_key": [
            "source_e2_split",
            "profile",
            "level",
            "pair_id",
            "arrival_schedule_sha256",
            "query_schedule_sha256",
        ],
        "stratification": ["source_e2_split", "profile", "level"],
        "partitions": {
            name: {
                "file": output_paths[name].name,
                "paired_traces": trace_counts[name],
                "decisions": decision_counts[name],
                "sha256": sha256_file(output_paths[name]),
            }
            for name in PARTITIONS
        },
        "paired_traces_by_source_stratum": stratum_counts,
    }
    (args.output_dir / "split_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest["partitions"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
