"""Independent integrity validator for an isolated E2 confirmatory artifact."""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Iterable

import numpy as np
from sklearn.metrics import average_precision_score


VARIANTS = ("no_defense", "legacy", "combined", "volume", "entropy", "unique")
BASELINE_VARIANTS = ("legacy", "volume", "entropy", "unique")
FEATURES = ("volume", "entropy", "unique_ratio")
LEVELS = (24, 60, 120, 200)
CONDITIONS = {
    "benign_continuous": {"profile": "continuous", "role": "benign"},
    "attack_sweep_continuous": {"profile": "continuous", "role": "attack"},
    "attack_random_continuous": {"profile": "continuous", "role": "attack"},
    "attack_fixed_continuous": {"profile": "continuous", "role": "attack"},
    "attack_dup_sweep_continuous": {"profile": "continuous", "role": "attack"},
    "benign_bursty": {"profile": "bursty", "role": "benign"},
    "attack_sweep_bursty": {"profile": "bursty", "role": "attack"},
}
PROFILE_CONDITIONS = {
    "continuous": (
        "benign_continuous", "attack_sweep_continuous", "attack_random_continuous",
        "attack_fixed_continuous", "attack_dup_sweep_continuous",
    ),
    "bursty": ("benign_bursty", "attack_sweep_bursty"),
}
PROFILE_BENIGN = {"continuous": "benign_continuous", "bursty": "benign_bursty"}
ATTACK_CONDITIONS = tuple(name for name, cfg in CONDITIONS.items() if cfg["role"] == "attack")
BOOTSTRAP_REPLICATES = 5000
TARGET_ALERT_RATE = 0.95
EQUIVALENCE_MARGIN = 0.05


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def derive_seed(experiment_seed: int, *parts: object) -> int:
    material = "|".join([str(experiment_seed), *(str(part) for part in parts)])
    return int.from_bytes(hashlib.sha256(material.encode("utf-8")).digest()[:8], "big")


def shannon_entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    total = len(values)
    counts = Counter(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def expected_flags(samples: int, entropy: float, unique_ratio: float, operating: dict[str, Any]
                   ) -> dict[str, bool]:
    volume = samples >= int(operating["min_samples"])
    entropy_flag = entropy >= float(operating["entropy_threshold"])
    unique = unique_ratio >= float(operating["unique_ratio_threshold"])
    return {
        "no_defense": False,
        "legacy": True,
        "volume": volume,
        "entropy": entropy_flag,
        "unique": unique,
        "combined": volume and entropy_flag and unique,
    }


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    # Avoid importing scipy in the validator only for a non-primary detail.  The
    # run-any interval is checked by shape/count below; result bootstrap is exact.
    if n <= 0:
        return (0.0, 1.0)
    # Conservative Wilson-like fallback is not used to compare a persisted value.
    return (0.0, 1.0) if k == 0 else (0.0, 1.0)


def bootstrap_mean(values: list[float], seed: int) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, array.size, size=(BOOTSTRAP_REPLICATES, array.size))
    draws = array[indices].mean(axis=1)
    return {
        "mean": float(array.mean()),
        "ci95": [float(np.percentile(draws, 2.5)), float(np.percentile(draws, 97.5))],
        "ci90": [float(np.percentile(draws, 5.0)), float(np.percentile(draws, 95.0))],
        "n_pairs": int(array.size),
    }


def close(left: float, right: float, tolerance: float = 1e-10) -> bool:
    return math.isfinite(left) and math.isfinite(right) and abs(left - right) <= tolerance


def balanced_precision(attack_alert_rate: float, benign_trigger_rate: float) -> float:
    denominator = attack_alert_rate + benign_trigger_rate
    return attack_alert_rate / denominator if denominator > 0.0 else 0.0


def paired_feature_ap(benign: dict[str, Any], attack: dict[str, Any], feature: str) -> float:
    """PR-AUC of one volume-matched benign/attack run pair."""
    scores = np.concatenate([feature_values(benign, feature), feature_values(attack, feature)])
    labels = np.concatenate([
        np.zeros(len(benign["samples"]), dtype=int),
        np.ones(len(attack["samples"]), dtype=int),
    ])
    return float(average_precision_score(labels, scores))


def run_key(row: dict[str, str]) -> tuple[str, str, int, int]:
    return (row["split"], row["condition"], int(row["level"]), int(row["pair_id"]))


class Validator:
    def __init__(self, artifact_dir: Path, no_write: bool) -> None:
        self.artifact_dir = artifact_dir.resolve()
        self.no_write = no_write
        self.checks: list[dict[str, Any]] = []
        self.errors: list[str] = []

    def check(self, name: str, condition: bool, detail: str) -> None:
        self.checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})
        print(f"[{'PASS' if condition else 'FAIL'}] {name}: {detail}")
        if not condition:
            self.errors.append(f"{name}: {detail}")

    def fail(self, message: str) -> None:
        self.errors.append(message)


def validate_raw_run(artifact_dir: Path, row: dict[str, str], operating: dict[str, Any],
                     expected_queries: int) -> tuple[list[str], dict[str, Any] | None]:
    """Replay one raw gzip stream and recompute every stored window / detector flag."""
    errors: list[str] = []
    relative = row.get("raw_file", "")
    label = "/".join(map(str, run_key(row)))
    if not relative:
        return [f"{label}: missing raw_file"], None
    raw_path = (artifact_dir / relative).resolve()
    try:
        raw_path.relative_to(artifact_dir)
    except ValueError:
        return [f"{label}: raw file escapes artifact"], None
    if not raw_path.is_file():
        return [f"{label}: raw file missing: {relative}"], None
    if sha256_file(raw_path) != row.get("raw_sha256"):
        errors.append(f"{label}: raw SHA-256 mismatch")

    expected_static = {
        "split": row["split"],
        "profile": row["profile"],
        "condition": row["condition"],
        "role": row["role"],
        "level_samples_per_window": int(row["level"]),
        "pair_id": int(row["pair_id"]),
        "schedule_seed": int(row["schedule_seed"]),
        "query_seed": int(row["query_seed"]),
        "payload_seed": int(row["payload_seed"]),
        "arrival_schedule_sha256": row["arrival_schedule_sha256"],
        "query_schedule_sha256": row["query_schedule_sha256"],
    }
    history: Deque[tuple[float, int, str]] = deque()
    previous_time = -math.inf
    previous_query_time = -math.inf
    event_count = 0
    decision_count = 0
    blocks = {variant: 0 for variant in VARIANTS}
    samples: list[int] = []
    entropies: list[float] = []
    unique_ratios: list[float] = []
    b2_flags: list[bool] = []
    meta: dict[str, Any] | None = None
    seen_meta = False

    with gzip.open(raw_path, "rt", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"{label}: invalid JSON at raw line {line_no}")
                continue
            if not isinstance(record, dict):
                errors.append(f"{label}: non-object record at raw line {line_no}")
                continue
            if record.get("schema_version") != 2:
                errors.append(f"{label}: schema version at raw line {line_no}")
            record_type = record.get("record_type")
            if record_type == "run_meta":
                if seen_meta or line_no != 1:
                    errors.append(f"{label}: run_meta must be unique and first")
                seen_meta = True
                meta = record
                for key, expected in expected_static.items():
                    if record.get(key) != expected:
                        errors.append(f"{label}: meta mismatch {key}")
                continue
            if not seen_meta:
                errors.append(f"{label}: data before run_meta")
                continue
            if record_type == "frag2":
                try:
                    event_idx = int(record["event_idx"])
                    timestamp = float(record["timestamp_seconds"])
                    ipid = int(record["ipid"])
                    origin = str(record["origin"])
                except (KeyError, TypeError, ValueError):
                    errors.append(f"{label}: bad frag2 at raw line {line_no}")
                    continue
                if event_idx != event_count + 1:
                    errors.append(f"{label}: nonsequential event_idx at {event_idx}")
                if not math.isfinite(timestamp) or timestamp < previous_time:
                    errors.append(f"{label}: nonmonotonic frag2 timestamp")
                if not (0 <= ipid < 2048) or origin not in ("benign", "attack"):
                    errors.append(f"{label}: invalid frag2 payload")
                previous_time = timestamp
                event_count += 1
                history.append((timestamp, ipid, origin))
                continue
            if record_type != "decision":
                errors.append(f"{label}: unknown record type at raw line {line_no}")
                continue
            try:
                query_idx = int(record["query_idx"])
                timestamp = float(record["timestamp_seconds"])
                window_start = float(record["window_start_seconds"])
                frag1_ipid = int(record["frag1_ipid"])
                stored_samples = int(record["samples"])
                stored_unique = int(record["unique_ipids"])
                stored_entropy = float(record["entropy"])
                stored_ratio = float(record["unique_ratio"])
                stored_benign = int(record["benign_events_in_window"])
                stored_attack = int(record["attack_events_in_window"])
            except (KeyError, TypeError, ValueError):
                errors.append(f"{label}: bad decision at raw line {line_no}")
                continue
            if query_idx != decision_count + 1:
                errors.append(f"{label}: nonsequential query_idx={query_idx}")
            if (not math.isfinite(timestamp) or timestamp < previous_time
                    or timestamp <= previous_query_time):
                errors.append(f"{label}: nonmonotonic decision timestamp")
            if not close(window_start, timestamp - float(operating["window_seconds"])):
                errors.append(f"{label}: incorrect window_start at query {query_idx}")
            if not 0 <= frag1_ipid < 2048:
                errors.append(f"{label}: invalid FRAG1 IPID at query {query_idx}")
            previous_time = timestamp
            previous_query_time = timestamp
            while history and history[0][0] < window_start:
                history.popleft()
            ipids = [event[1] for event in history]
            total = len(ipids)
            unique = len(set(ipids))
            entropy = shannon_entropy(ipids)
            ratio = unique / total if total else 0.0
            benign = sum(event[2] == "benign" for event in history)
            attack = total - benign
            if (stored_samples, stored_unique, stored_benign, stored_attack) != (
                    total, unique, benign, attack):
                errors.append(f"{label}: replay counts mismatch at query {query_idx}")
            if not close(stored_entropy, entropy) or not close(stored_ratio, ratio):
                errors.append(f"{label}: replay features mismatch at query {query_idx}")
            flags = expected_flags(total, entropy, ratio, operating)
            for variant in VARIANTS:
                actual = record.get(f"block_{variant}")
                if not isinstance(actual, bool) or actual != flags[variant]:
                    errors.append(f"{label}: rule mismatch {variant} at query {query_idx}")
                blocks[variant] += int(actual is True)
            decision_count += 1
            samples.append(total)
            entropies.append(entropy)
            unique_ratios.append(ratio)
            b2_flags.append(flags["volume"])

    if meta is None:
        errors.append(f"{label}: missing run_meta")
        return errors, None
    if event_count != int(meta.get("scheduled_frag2_events", -1)):
        errors.append(f"{label}: events={event_count} scheduled={meta.get('scheduled_frag2_events')}")
    if decision_count != expected_queries or decision_count != int(meta.get("scheduled_queries", -1)):
        errors.append(f"{label}: decisions={decision_count} expected={expected_queries}")
    # Raw -> run summary checks.
    numeric_pairs = {
        "samples_mean": float(np.mean(samples)) if samples else 0.0,
        "samples_p95": float(np.percentile(samples, 95)) if samples else 0.0,
        "entropy_mean": float(np.mean(entropies)) if entropies else 0.0,
        "unique_ratio_mean": float(np.mean(unique_ratios)) if unique_ratios else 0.0,
    }
    for name, calculated in numeric_pairs.items():
        try:
            stored = float(row[name])
        except (KeyError, TypeError, ValueError):
            errors.append(f"{label}: invalid run summary field {name}")
            continue
        if not close(stored, calculated, 1e-9):
            errors.append(f"{label}: {name} raw/run mismatch")
    for variant in VARIANTS:
        if int(row[f"blocks_{variant}"]) != blocks[variant]:
            errors.append(f"{label}: blocks_{variant} raw/run mismatch")
        expected_rate = blocks[variant] / decision_count if decision_count else 0.0
        if not close(float(row[f"rate_{variant}"]), expected_rate, 1e-12):
            errors.append(f"{label}: rate_{variant} raw/run mismatch")
    if int(row["decisions"]) != decision_count:
        errors.append(f"{label}: decisions raw/run mismatch")
    if int(row["fragments_total"]) != event_count:
        errors.append(f"{label}: fragments_total raw/run mismatch")
    return errors, {
        "key": run_key(row),
        "profile": row["profile"],
        "condition": row["condition"],
        "role": row["role"],
        "level": int(row["level"]),
        "pair_id": int(row["pair_id"]),
        "arrival_schedule_sha256": row["arrival_schedule_sha256"],
        "query_schedule_sha256": row["query_schedule_sha256"],
        "samples": samples,
        "entropies": entropies,
        "unique_ratios": unique_ratios,
        "b2_flags": b2_flags,
        "rates": {variant: blocks[variant] / decision_count for variant in VARIANTS},
    }


def validate_decision_csv(path: Path, raw_summaries: dict[tuple[str, str, int, int], dict[str, Any]],
                          expected_queries: int) -> list[str]:
    errors: list[str] = []
    accum: dict[tuple[str, str, int, int], dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "samples_sum": 0.0, "entropy_sum": 0.0, "unique_sum": 0.0,
                 "blocks": {variant: 0 for variant in VARIANTS}}
    )
    with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"split", "condition", "level", "pair_id", "query_idx", "samples", "entropy",
                    "unique_ratio", *[f"block_{variant}" for variant in VARIANTS]}
        if not required.issubset(set(reader.fieldnames or [])):
            return ["e2_decisions.csv.gz missing required columns"]
        for row_no, row in enumerate(reader, 2):
            try:
                key = (row["split"], row["condition"], int(row["level"]), int(row["pair_id"]))
                query_idx = int(row["query_idx"])
                accumulator = accum[key]
                if query_idx != accumulator["count"] + 1:
                    errors.append(f"decision CSV nonsequential query idx for {key} at row {row_no}")
                accumulator["count"] += 1
                accumulator["samples_sum"] += int(row["samples"])
                accumulator["entropy_sum"] += float(row["entropy"])
                accumulator["unique_sum"] += float(row["unique_ratio"])
                for variant in VARIANTS:
                    accumulator["blocks"][variant] += int(row[f"block_{variant}"])
            except (KeyError, TypeError, ValueError):
                errors.append(f"invalid decision CSV row {row_no}")
    if set(accum) != set(raw_summaries):
        errors.append(f"decision CSV run inventory mismatch csv={len(accum)} raw={len(raw_summaries)}")
    for key, raw in raw_summaries.items():
        row = accum.get(key)
        if row is None:
            continue
        if row["count"] != expected_queries:
            errors.append(f"decision CSV count mismatch for {key}")
            continue
        if not close(row["samples_sum"] / row["count"], float(np.mean(raw["samples"])), 1e-9):
            errors.append(f"decision CSV samples mismatch for {key}")
        if not close(row["entropy_sum"] / row["count"], float(np.mean(raw["entropies"])), 1e-9):
            errors.append(f"decision CSV entropy mismatch for {key}")
        if not close(row["unique_sum"] / row["count"], float(np.mean(raw["unique_ratios"])), 1e-9):
            errors.append(f"decision CSV unique ratio mismatch for {key}")
        for variant in VARIANTS:
            expected = int(round(raw["rates"][variant] * expected_queries))
            if row["blocks"][variant] != expected:
                errors.append(f"decision CSV blocks mismatch {variant} for {key}")
    return errors


def feature_values(raw: dict[str, Any], feature: str) -> np.ndarray:
    if feature == "volume":
        return np.asarray(raw["samples"], dtype=float)
    if feature == "entropy":
        return np.asarray(raw["entropies"], dtype=float)
    if feature == "unique_ratio":
        return np.asarray(raw["unique_ratios"], dtype=float)
    raise KeyError(feature)


def validate_thresholds(thresholds: dict[str, Any], raw: dict[tuple[str, str, int, int], dict[str, Any]],
                        experiment_seed: int, validation_k: int) -> list[str]:
    errors: list[str] = []
    if thresholds.get("status") != "locked-before-test" or thresholds.get("split_used") != "validation":
        errors.append("threshold file is not a validation-locked file")
    if len(thresholds.get("entries", [])) != len(ATTACK_CONDITIONS) * len(LEVELS) * len(FEATURES):
        errors.append("threshold entry count mismatch")
        return errors
    seen = set()
    for entry in thresholds["entries"]:
        try:
            attack = str(entry["attack_condition"])
            level = int(entry["level"])
            feature = str(entry["feature"])
            threshold = float(entry["threshold"])
        except (KeyError, TypeError, ValueError):
            errors.append("invalid threshold entry")
            continue
        key = (attack, level, feature)
        if key in seen:
            errors.append(f"duplicate threshold {key}")
        seen.add(key)
        profile = CONDITIONS.get(attack, {}).get("profile")
        benign = PROFILE_BENIGN.get(profile or "")
        if entry.get("benign_condition") != benign or entry.get("direction") != "higher_is_suspicious":
            errors.append(f"threshold identity mismatch {key}")
            continue
        try:
            attack_scores = np.concatenate([
                feature_values(raw[("validation", attack, level, pair_id)], feature)
                for pair_id in range(validation_k)
            ])
            benign_scores = np.concatenate([
                feature_values(raw[("validation", benign, level, pair_id)], feature)
                for pair_id in range(validation_k)
            ])
        except KeyError:
            errors.append(f"missing validation raw for threshold {key}")
            continue
        index = min(len(attack_scores) - 1, max(0, int(math.floor(
            (1.0 - TARGET_ALERT_RATE) * len(attack_scores)
        ))))
        expected = float(np.sort(attack_scores)[index])
        if not close(threshold, expected):
            errors.append(f"threshold mismatch {key}")
        if not close(float(entry["validation_attack_alert_rate"]),
                     float(np.mean(attack_scores >= threshold))):
            errors.append(f"validation attack rate mismatch {key}")
        if not close(float(entry["validation_benign_trigger_rate"]),
                     float(np.mean(benign_scores >= threshold))):
            errors.append(f"validation benign rate mismatch {key}")
    return errors


def validate_pairing(raw: dict[tuple[str, str, int, int], dict[str, Any]],
                     split: str, k: int) -> list[str]:
    errors: list[str] = []
    for profile, conditions in PROFILE_CONDITIONS.items():
        benign_condition = PROFILE_BENIGN[profile]
        for level in LEVELS:
            for pair_id in range(k):
                try:
                    benign = raw[(split, benign_condition, level, pair_id)]
                except KeyError:
                    errors.append(f"missing paired benign run {split}/{profile}/{level}/{pair_id}")
                    continue
                for condition in conditions:
                    try:
                        candidate = raw[(split, condition, level, pair_id)]
                    except KeyError:
                        errors.append(f"missing paired run {split}/{condition}/{level}/{pair_id}")
                        continue
                    if (candidate["arrival_schedule_sha256"] != benign["arrival_schedule_sha256"]
                            or candidate["query_schedule_sha256"] != benign["query_schedule_sha256"]):
                        errors.append(f"schedule hash mismatch {split}/{condition}/{level}/{pair_id}")
                    if candidate["samples"] != benign["samples"]:
                        errors.append(f"sample sequence mismatch {split}/{condition}/{level}/{pair_id}")
                    if candidate["b2_flags"] != benign["b2_flags"]:
                        errors.append(f"B2 flag mismatch {split}/{condition}/{level}/{pair_id}")
    return errors


def compare_stats(stored: dict[str, Any], expected: dict[str, Any], label: str,
                  errors: list[str]) -> None:
    for key in ("mean",):
        if not close(float(stored[key]), float(expected[key]), 1e-12):
            errors.append(f"{label}: {key} mismatch")
    for key in ("ci95", "ci90"):
        if len(stored.get(key, [])) != 2:
            errors.append(f"{label}: missing {key}")
            continue
        for idx in range(2):
            if not close(float(stored[key][idx]), float(expected[key][idx]), 1e-12):
                errors.append(f"{label}: {key}[{idx}] mismatch")
    if int(stored.get("n_pairs", -1)) != int(expected["n_pairs"]):
        errors.append(f"{label}: n_pairs mismatch")


def validate_results(results: dict[str, Any], raw: dict[tuple[str, str, int, int], dict[str, Any]],
                     thresholds: dict[str, Any], experiment_seed: int, test_k: int) -> list[str]:
    errors: list[str] = []
    analysis = results.get("analysis", {})
    cells = analysis.get("test_cells", [])
    if len(cells) != len(ATTACK_CONDITIONS) * len(LEVELS):
        return [f"results test cell count={len(cells)}"]
    by_cell = {(cell.get("attack_condition"), int(cell.get("level", -1))): cell for cell in cells}
    threshold_index = {
        (entry["attack_condition"], int(entry["level"]), entry["feature"]): entry
        for entry in thresholds.get("entries", [])
    }
    deltas: dict[tuple[str, int], dict[str, dict[int, float]]] = {}
    for attack in ATTACK_CONDITIONS:
        profile = CONDITIONS[attack]["profile"]
        benign_condition = PROFILE_BENIGN[profile]
        for level in LEVELS:
            cell = by_cell.get((attack, level))
            if cell is None:
                errors.append(f"missing result cell {attack}/{level}")
                continue
            if int(cell.get("n_pairs", -1)) != test_k:
                errors.append(f"n_pairs mismatch {attack}/{level}")
            if not cell.get("paired_schedule_hashes_match") or int(
                    cell.get("max_abs_paired_samples_difference", -1)) != 0:
                errors.append(f"pairing assertion failed {attack}/{level}")
            per_variant = {
                variant: {
                    "benign_trigger": [],
                    "attack_alert": [],
                    "youden_j": [],
                    "synthetic_tpr": [],
                    "synthetic_fnr": [],
                    "synthetic_fpr": [],
                    "balanced_precision": [],
                }
                for variant in VARIANTS
            }
            cell_deltas = {baseline: {} for baseline in BASELINE_VARIANTS}
            feature_aps = {feature: [] for feature in FEATURES}
            threshold_values = {
                feature: {"benign_trigger": [], "attack_alert": [], "balanced_precision": []}
                for feature in FEATURES
            }
            for pair_id in range(test_k):
                try:
                    benign = raw[("test", benign_condition, level, pair_id)]
                    attack_run = raw[("test", attack, level, pair_id)]
                except KeyError:
                    errors.append(f"missing test raw pair {attack}/{level}/{pair_id}")
                    continue
                for variant in VARIANTS:
                    benign_rate = benign["rates"][variant]
                    attack_rate = attack_run["rates"][variant]
                    per_variant[variant]["benign_trigger"].append(benign_rate)
                    per_variant[variant]["attack_alert"].append(attack_rate)
                    per_variant[variant]["youden_j"].append(attack_rate - benign_rate)
                    per_variant[variant]["synthetic_tpr"].append(attack_rate)
                    per_variant[variant]["synthetic_fnr"].append(1.0 - attack_rate)
                    per_variant[variant]["synthetic_fpr"].append(benign_rate)
                    per_variant[variant]["balanced_precision"].append(
                        balanced_precision(attack_rate, benign_rate)
                    )
                for baseline in BASELINE_VARIANTS:
                    cell_deltas[baseline][pair_id] = (
                        per_variant["combined"]["youden_j"][-1]
                        - per_variant[baseline]["youden_j"][-1]
                    )
                for feature in FEATURES:
                    feature_aps[feature].append(paired_feature_ap(benign, attack_run, feature))
                    try:
                        threshold = float(threshold_index[(attack, level, feature)]["threshold"])
                    except KeyError:
                        errors.append(f"missing threshold for result diagnostic {attack}/{level}/{feature}")
                        continue
                    benign_rate = float(np.mean(feature_values(benign, feature) >= threshold))
                    attack_rate = float(np.mean(feature_values(attack_run, feature) >= threshold))
                    threshold_values[feature]["benign_trigger"].append(benign_rate)
                    threshold_values[feature]["attack_alert"].append(attack_rate)
                    threshold_values[feature]["balanced_precision"].append(
                        balanced_precision(attack_rate, benign_rate)
                    )
            for variant, metrics in per_variant.items():
                for metric, values in metrics.items():
                    expected = bootstrap_mean(values, derive_seed(experiment_seed, "bootstrap", attack,
                                                                  level, variant, metric))
                    try:
                        compare_stats(cell["variants"][variant][metric], expected,
                                      f"{attack}/{level}/{variant}/{metric}", errors)
                    except KeyError:
                        errors.append(f"missing result metric {attack}/{level}/{variant}/{metric}")
            for baseline in BASELINE_VARIANTS:
                expected_delta = bootstrap_mean(
                    [cell_deltas[baseline][pair_id] for pair_id in range(test_k)],
                    derive_seed(experiment_seed, "bootstrap", attack, level,
                                f"delta_j_combined_minus_{baseline}"),
                )
                try:
                    compare_stats(cell["paired_delta_j_combined_minus"][baseline], expected_delta,
                                  f"{attack}/{level}/delta_{baseline}", errors)
                except KeyError:
                    errors.append(f"missing paired result delta {attack}/{level}/{baseline}")
                if baseline == "volume":
                    try:
                        compare_stats(cell["delta_j_combined_minus_volume"], expected_delta,
                                      f"{attack}/{level}/delta_volume_alias", errors)
                    except KeyError:
                        errors.append(f"missing result delta alias {attack}/{level}")
            for feature in FEATURES:
                expected_ap = bootstrap_mean(
                    feature_aps[feature],
                    derive_seed(experiment_seed, "bootstrap", attack, level, feature, "auprc"),
                )
                try:
                    compare_stats(cell["feature_auprc_high_is_suspicious"][feature], expected_ap,
                                  f"{attack}/{level}/{feature}/auprc", errors)
                except KeyError:
                    errors.append(f"missing feature PR-AUC {attack}/{level}/{feature}")
                for metric, seed_suffix in (
                    ("test_benign_trigger_rate", "threshold_benign"),
                    ("test_attack_alert_rate", "threshold_attack"),
                    ("test_balanced_precision", "threshold_precision"),
                ):
                    source_metric = {
                        "test_benign_trigger_rate": "benign_trigger",
                        "test_attack_alert_rate": "attack_alert",
                        "test_balanced_precision": "balanced_precision",
                    }[metric]
                    expected = bootstrap_mean(
                        threshold_values[feature][source_metric],
                        derive_seed(experiment_seed, "bootstrap", attack, level, feature, seed_suffix),
                    )
                    try:
                        diagnostic = cell["frozen_threshold_diagnostics"][feature]
                        compare_stats(diagnostic[metric], expected,
                                      f"{attack}/{level}/{feature}/{metric}", errors)
                    except KeyError:
                        errors.append(f"missing frozen threshold diagnostic {attack}/{level}/{feature}/{metric}")
            deltas[(attack, level)] = cell_deltas
    # Registered macro effects, reusing pair IDs jointly across the four levels.
    macro_by_attack = {entry.get("attack_condition"): entry for entry in analysis.get("macro_effects", [])}
    for attack in ("attack_sweep_continuous", "attack_sweep_bursty"):
        entry = macro_by_attack.get(attack)
        if entry is None:
            errors.append(f"missing macro effect {attack}")
            continue
        if entry.get("baseline_variant") != "volume":
            errors.append(f"primary macro baseline mismatch {attack}")
        values = [float(np.mean([deltas[(attack, level)]["volume"][pair_id] for level in LEVELS]))
                  for pair_id in range(test_k)]
        expected = bootstrap_mean(values, derive_seed(experiment_seed, "bootstrap", attack,
                                                      "macro_delta_j"))
        try:
            compare_stats(entry["result"], expected, f"macro/{attack}", errors)
        except KeyError:
            errors.append(f"missing macro result {attack}")
            continue
        lo95, hi95 = expected["ci95"]
        lo90, hi90 = expected["ci90"]
        expected_verdict = (
            "meaningful_added_discrimination" if lo95 > EQUIVALENCE_MARGIN
            else "practical_equivalence_within_registered_margin"
            if lo90 >= -EQUIVALENCE_MARGIN and hi90 <= EQUIVALENCE_MARGIN
            else "meaningful_degradation" if hi95 < -EQUIVALENCE_MARGIN
            else "inconclusive"
        )
        if entry.get("verdict") != expected_verdict:
            errors.append(f"macro verdict mismatch {attack}")
    ablation_entries = analysis.get("paired_ablation_macro_effects", [])
    ablation_by_key = {
        (entry.get("attack_condition"), entry.get("baseline_variant")): entry
        for entry in ablation_entries
    }
    if len(ablation_entries) != 2 * len(BASELINE_VARIANTS):
        errors.append(f"paired ablation macro count={len(ablation_entries)}")
    for attack in ("attack_sweep_continuous", "attack_sweep_bursty"):
        for baseline in BASELINE_VARIANTS:
            entry = ablation_by_key.get((attack, baseline))
            if entry is None:
                errors.append(f"missing paired ablation macro {attack}/{baseline}")
                continue
            values = [float(np.mean([
                deltas[(attack, level)][baseline][pair_id] for level in LEVELS
            ])) for pair_id in range(test_k)]
            seed_parts: tuple[object, ...] = (
                (attack, "macro_delta_j")
                if baseline == "volume"
                else (attack, baseline, "macro_delta_j")
            )
            expected = bootstrap_mean(values, derive_seed(experiment_seed, "bootstrap", *seed_parts))
            try:
                compare_stats(entry["result"], expected, f"paired_macro/{attack}/{baseline}", errors)
            except KeyError:
                errors.append(f"missing paired ablation macro result {attack}/{baseline}")
                continue
            lo95, hi95 = expected["ci95"]
            lo90, hi90 = expected["ci90"]
            expected_verdict = (
                "meaningful_added_discrimination" if lo95 > EQUIVALENCE_MARGIN
                else "practical_equivalence_within_registered_margin"
                if lo90 >= -EQUIVALENCE_MARGIN and hi90 <= EQUIVALENCE_MARGIN
                else "meaningful_degradation" if hi95 < -EQUIVALENCE_MARGIN
                else "inconclusive"
            )
            if entry.get("verdict") != expected_verdict:
                errors.append(f"paired ablation macro verdict mismatch {attack}/{baseline}")
    return errors


def validate_manifest(artifact_dir: Path) -> list[str]:
    path = artifact_dir / "artifact_manifest.json"
    if not path.is_file():
        return ["missing artifact_manifest.json"]
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ["invalid artifact_manifest.json"]
    errors = []
    for entry in manifest.get("files", []):
        candidate = artifact_dir / entry.get("path", "")
        if not candidate.is_file() or sha256_file(candidate) != entry.get("sha256"):
            errors.append(f"manifest hash mismatch {entry.get('path')}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an E2 confirmatory artifact")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()
    validator = Validator(args.artifact_dir, args.no_write)
    root = validator.artifact_dir
    required = [
        "e2_protocol.json", "e2_preflight.json", "e2_thresholds.json", "e2_runs.csv",
        "e2_decisions.csv.gz", "e2_results.json", "e2_summary.csv", "notes.txt",
        "artifact_manifest.json", "source_snapshot",
    ]
    missing = [name for name in required if not (root / name).exists()]
    validator.check("required_files", not missing, f"missing={missing}")
    if missing:
        return 1
    try:
        protocol = json.loads((root / "e2_protocol.json").read_text(encoding="utf-8"))
        preflight = json.loads((root / "e2_preflight.json").read_text(encoding="utf-8"))
        thresholds = json.loads((root / "e2_thresholds.json").read_text(encoding="utf-8"))
        results = json.loads((root / "e2_results.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        validator.check("json_parse", False, str(exc))
        return 1
    meta = results.get("meta", {})
    validator.check("registered_before_collection", protocol.get("status") == "registered-before-data-collection",
                    str(protocol.get("status")))
    validator.check("run_id_match", protocol.get("run_id") == meta.get("run_id"),
                    f"protocol={protocol.get('run_id')} results={meta.get('run_id')}")
    validator.check("independent_unit", protocol.get("independent_unit") == "pair_id (shared timestamp trace across matched conditions)",
                    str(protocol.get("independent_unit")))
    timing_ok = True
    timing_error = ""
    try:
        ordered = [
            protocol["registered_utc"], meta["calibration_started_utc"], meta["calibration_completed_utc"],
            meta["validation_started_utc"], meta["validation_completed_utc"],
            thresholds["locked_utc"], meta["test_started_utc"], meta["test_completed_utc"],
        ]
        parsed = [parse_utc(value) for value in ordered]
        timing_ok = all(left <= right for left, right in zip(parsed, parsed[1:]))
        timing_error = " -> ".join(ordered)
    except (KeyError, TypeError, ValueError) as exc:
        timing_ok = False
        timing_error = str(exc)
    validator.check("protocol_split_timing", timing_ok, timing_error)

    # Source snapshots pin the exact inputs even when the current worktree is dirty.
    source_errors = []
    for name, item in protocol.get("source_manifest", {}).items():
        snapshot = root / item.get("snapshot", "")
        if not snapshot.is_file() or sha256_file(snapshot) != item.get("sha256"):
            source_errors.append(name)
    validator.check("source_snapshot_hashes", not source_errors,
                    "all snapshots match" if not source_errors else repr(source_errors))

    with (root / "e2_runs.csv").open(newline="", encoding="utf-8") as handle:
        run_rows = list(csv.DictReader(handle))
    split_specs = protocol.get("splits", {})
    try:
        expected_queries = int(protocol["queries_per_run"])
        calibration_k = int(split_specs["calibration"]["runs_per_cell"])
        validation_k = int(split_specs["validation"]["runs_per_cell"])
        test_k = int(split_specs["test"]["runs_per_cell"])
    except (KeyError, TypeError, ValueError) as exc:
        validator.check("protocol_matrix", False, str(exc))
        return 1
    expected_count = 2 * len(LEVELS) * calibration_k + len(CONDITIONS) * len(LEVELS) * (validation_k + test_k)
    validator.check("run_row_count", len(run_rows) == expected_count,
                    f"observed={len(run_rows)} expected={expected_count}")
    keys = [run_key(row) for row in run_rows]
    validator.check("unique_run_keys", len(set(keys)) == len(keys), f"unique={len(set(keys))} rows={len(keys)}")
    validator.check("complete_decisions", all(int(row["decisions"]) == expected_queries for row in run_rows),
                    f"queries/run={expected_queries}")
    seeds_by_split: dict[str, set[int]] = defaultdict(set)
    for row in run_rows:
        seeds_by_split[row["split"]].add(int(row["schedule_seed"]))
        seeds_by_split[row["split"]].add(int(row["query_seed"]))
    disjoint = all(not (seeds_by_split[left] & seeds_by_split[right])
                   for left, right in (("calibration", "validation"), ("calibration", "test"),
                                       ("validation", "test")))
    validator.check("disjoint_split_seed_namespaces", disjoint,
                    ", ".join(f"{split}={len(values)}" for split, values in sorted(seeds_by_split.items())))

    raw_summaries: dict[tuple[str, str, int, int], dict[str, Any]] = {}
    raw_errors: list[str] = []
    for row in run_rows:
        errors, summary = validate_raw_run(root, row, protocol["operating_point"], expected_queries)
        raw_errors.extend(errors)
        if summary is not None:
            raw_summaries[summary["key"]] = summary
    validator.check("event_level_raw_replay", not raw_errors and len(raw_summaries) == len(run_rows),
                    f"runs_replayed={len(raw_summaries)}/{len(run_rows)}"
                    if not raw_errors else repr(raw_errors[:12]))
    referenced = {row["raw_file"] for row in run_rows}
    on_disk = {path.relative_to(root).as_posix() for path in (root / "raw_runs").rglob("*.jsonl.gz")}
    validator.check("raw_inventory", referenced == on_disk,
                    f"referenced={len(referenced)} disk={len(on_disk)}" if referenced == on_disk
                    else repr(sorted(referenced ^ on_disk)[:12]))

    csv_errors = validate_decision_csv(root / "e2_decisions.csv.gz", raw_summaries, expected_queries)
    validator.check("raw_to_decision_csv", not csv_errors,
                    "all decision CSV aggregates match raw" if not csv_errors else repr(csv_errors[:12]))
    # Pairing is relevant only for full profile matrices; calibration has benign controls only.
    pairing_errors = validate_pairing(raw_summaries, "validation", validation_k)
    pairing_errors += validate_pairing(raw_summaries, "test", test_k)
    validator.check("exact_paired_occupancy", not pairing_errors,
                    "shared timestamps/samples/B2 match per paired query" if not pairing_errors
                    else repr(pairing_errors[:12]))

    preflight_errors = []
    if preflight.get("status") != "PASS":
        preflight_errors.append("preflight status")
    for cell in preflight.get("checks", []):
        if not cell.get("pass"):
            preflight_errors.append(f"preflight cell {cell.get('profile')}/{cell.get('level')}")
    validator.check("calibration_preflight", not preflight_errors,
                    "all generator QA cells passed" if not preflight_errors else repr(preflight_errors))
    try:
        experiment_seed = int(protocol["experiment_seed"])
    except (KeyError, TypeError, ValueError):
        validator.check("registered_experiment_seed", False, "protocol missing experiment_seed")
        return 1
    threshold_errors = validate_thresholds(thresholds, raw_summaries, experiment_seed, validation_k)
    validator.check("validation_threshold_lock", not threshold_errors,
                    "thresholds recompute from validation only" if not threshold_errors
                    else repr(threshold_errors[:12]))
    result_errors = validate_results(results, raw_summaries, thresholds, experiment_seed, test_k)
    validator.check("test_aggregation_and_bootstrap", not result_errors,
                    "test metrics and bootstrap recompute" if not result_errors
                    else repr(result_errors[:12]))
    manifest_errors = validate_manifest(root)
    validator.check("artifact_manifest_hashes", not manifest_errors,
                    "listed hashes match" if not manifest_errors else repr(manifest_errors[:12]))

    failures = [check for check in validator.checks if check["status"] == "FAIL"]
    validation = {
        "schema_version": 2,
        "artifact_dir": str(root),
        "generated_utc": utc_now(),
        "status": "PASS" if not failures else "FAIL",
        "checks": validator.checks,
        "warnings": [
            "This validates controlled synthetic emulation, not real IP fragmentation.",
            "Detector alert rates are not poisoning, ASR, BFrag coverage, latency, CPU, or deployment metrics.",
            "The independent unit is a paired trace/run; overlapping query decisions are never resampled as IID.",
        ],
    }
    if not args.no_write:
        with (root / "validation.json").open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(validation, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
        # Update manifest after writing validation so the final artifact is self-describing.
        from e2_confirmatory import refresh_artifact_manifest
        refresh_artifact_manifest(root, generated_utc=utc_now())
    print(f"E2 VALIDATION: {validation['status']} ({len(validator.checks) - len(failures)}/{len(validator.checks)})")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
