"""E2 confirmatory — query-timed, paired controlled emulation.

This program deliberately does not overwrite the older E2 exploratory snapshot.
It evaluates the real ``shannon_entropy`` and ``r2_should_block`` primitives from
``resolver.py`` on a deterministic virtual event stream that mirrors the resolver
ordering: FRAG2 observations enter the bucket first; a later query/FRAG1 event
reads and scores that bucket.  It is still a *controlled synthetic emulation*, not
real IP fragmentation, resolver performance, poisoning, or ASR measurement.

The registered primary comparison is B5 (combined) versus B2 (volume-only).
The same paired data also report the B0–B5 baselines/ablations and B5's paired effect
against each B1–B4 baseline. Benign and synthetic attack conditions in each
pair share the exact same FRAG2 and query timestamps, so occupancy is matched
at every decision rather than fitted on the reported data.

Usage:
    python -B e2_confirmatory.py --out <empty-artifact-dir> \
      --run-id E2_confirmatory_YYYYMMDD_HHMMSS
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Iterable, Sequence

import numpy as np
from scipy import stats
from sklearn.metrics import average_precision_score


for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 0. Exact detector import and registered configuration.                       #
# --------------------------------------------------------------------------- #
HERE = Path(__file__).resolve().parent
CODE_ROOT = HERE.parents[2]
LAB_DIR = CODE_ROOT / "src" / "detector" / "r2entropy"
RESOLVER_DIR = LAB_DIR / "resolver"
SHIM_DIR = LAB_DIR / "localtest" / "shim"

OPERATING_POINT = {
    "R2_MIN_SAMPLES": "24",
    "R2_ENTROPY_THRESHOLD": "4.0",
    "R2_UNIQUE_RATIO_THRESHOLD": "0.70",
    "R2_VARIANT": "combined",
    "FRAG2_WINDOW_SECONDS": "2.0",
}
# resolver.py reads these variables at import time.  Assignment (not setdefault)
# prevents an ambient shell setting from silently changing a registered campaign.
for _key, _value in OPERATING_POINT.items():
    os.environ[_key] = _value
sys.path.insert(0, str(SHIM_DIR))
sys.path.insert(0, str(RESOLVER_DIR))
import resolver as R  # noqa: E402

WINDOW_SECONDS = float(OPERATING_POINT["FRAG2_WINDOW_SECONDS"])
MIN_SAMPLES = int(OPERATING_POINT["R2_MIN_SAMPLES"])
ENTROPY_THRESHOLD = float(OPERATING_POINT["R2_ENTROPY_THRESHOLD"])
UNIQUE_RATIO_THRESHOLD = float(OPERATING_POINT["R2_UNIQUE_RATIO_THRESHOLD"])
if (R.R2_MIN_SAMPLES, R.R2_ENTROPY_THRESHOLD, R.R2_UNIQUE_RATIO_THRESHOLD,
        R.FRAG2_WINDOW_SECONDS) != (
            MIN_SAMPLES, ENTROPY_THRESHOLD, UNIQUE_RATIO_THRESHOLD, WINDOW_SECONDS
        ):
    raise RuntimeError("resolver.py did not load the registered operating point")


# --------------------------------------------------------------------------- #
# 1. Frozen E2 design.                                                         #
# --------------------------------------------------------------------------- #
LEVELS = (24, 60, 120, 200)
VARIANTS = ("no_defense", "legacy", "combined", "volume", "entropy", "unique")
# B0 is reported as the no-defense reference; E2's registered paired B5 effects
# are specifically versus B1–B4.
BASELINE_VARIANTS = ("legacy", "volume", "entropy", "unique")
FEATURES = ("volume", "entropy", "unique_ratio")
FEATURE_LABELS = {
    "volume": "samples/window",
    "entropy": "Shannon entropy",
    "unique_ratio": "unique ratio",
}

WARMUP_SECONDS = 6.0
QUERY_HZ = 4.0
QUERY_INTERVAL_SECONDS = 1.0 / QUERY_HZ
DEFAULT_QUERIES_PER_RUN = 150
DEFAULT_PREFLIGHT_RUNS = 10
DEFAULT_VALIDATION_RUNS = 10
DEFAULT_TEST_RUNS = 20
DEFAULT_EXPERIMENT_SEED = 20260813
DEFAULT_BENIGN_FRACTION = 0.10
IPID_SPACE = 2048
FIXED_IPID = 777
BURST_HIGH = 1.75
BURST_LOW = 0.25
BURST_HALF_PERIOD_SECONDS = 1.5
BOOTSTRAP_REPLICATES = 5000
TARGET_ALERT_RATE = 0.95
EQUIVALENCE_MARGIN = 0.05

PROFILES = {
    "continuous": {
        "description": "Homogeneous Poisson FRAG2 background.",
        "arrival_model": "poisson",
    },
    "bursty": {
        "description": "Exact thinned square-wave NHPP FRAG2 background.",
        "arrival_model": "thinned_square_wave_nhpp",
    },
}

# These names are deliberately synthetic-regime names.  They do not assert that
# each regime is a complete implementation of an attacker in the original paper.
CONDITIONS: dict[str, dict[str, str]] = {
    "benign_continuous": {
        "profile": "continuous", "role": "benign", "ipid_model": "random",
        "label": "Benign synthetic control, continuous background",
    },
    "attack_sweep_continuous": {
        "profile": "continuous", "role": "attack", "ipid_model": "sweep",
        "label": "Synthetic sweep-IPID stress regime, continuous background",
    },
    "attack_random_continuous": {
        "profile": "continuous", "role": "attack", "ipid_model": "random",
        "label": "Synthetic random-IPID negative control, continuous background",
    },
    "attack_fixed_continuous": {
        "profile": "continuous", "role": "attack", "ipid_model": "fixed",
        "label": "Synthetic fixed-IPID failure probe, continuous background",
    },
    "attack_dup_sweep_continuous": {
        "profile": "continuous", "role": "attack", "ipid_model": "dup_sweep",
        "label": "Synthetic duplicate-sweep failure probe, continuous background",
    },
    "benign_bursty": {
        "profile": "bursty", "role": "benign", "ipid_model": "random",
        "label": "Benign synthetic control, bursty background",
    },
    "attack_sweep_bursty": {
        "profile": "bursty", "role": "attack", "ipid_model": "sweep",
        "label": "Synthetic sweep-IPID stress regime, bursty background",
    },
}
PROFILE_CONDITIONS: dict[str, tuple[str, ...]] = {
    profile: tuple(condition for condition, cfg in CONDITIONS.items()
                   if cfg["profile"] == profile)
    for profile in PROFILES
}
PROFILE_BENIGN: dict[str, str] = {
    profile: next(condition for condition in conditions
                  if CONDITIONS[condition]["role"] == "benign")
    for profile, conditions in PROFILE_CONDITIONS.items()
}
ATTACK_CONDITIONS = tuple(
    condition for condition, cfg in CONDITIONS.items() if cfg["role"] == "attack"
)


# --------------------------------------------------------------------------- #
# 2. Small utility helpers.                                                    #
# --------------------------------------------------------------------------- #
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any, *, exclusive: bool = False) -> None:
    mode = "x" if exclusive else "w"
    with path.open(mode, encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def derive_seed(experiment_seed: int, *parts: object) -> int:
    """Stable, disjoint seed derivation independent of execution order."""
    material = "|".join([str(experiment_seed), *(str(part) for part in parts)])
    return int.from_bytes(hashlib.sha256(material.encode("utf-8")).digest()[:8], "big")


def float_close(left: float, right: float, tolerance: float = 1e-12) -> bool:
    return abs(left - right) <= tolerance


def finite(value: float) -> float:
    if not math.isfinite(value):
        raise ValueError(f"non-finite value: {value!r}")
    return value


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact interval over independent *runs*, never overlapping queries."""
    if n <= 0:
        return (0.0, 1.0)
    lower = 0.0 if k == 0 else float(stats.beta.ppf(alpha / 2.0, k, n - k + 1))
    upper = 1.0 if k == n else float(stats.beta.ppf(1.0 - alpha / 2.0, k + 1, n - k))
    return (lower, upper)


def bootstrap_mean(values: Sequence[float], seed: int,
                   n_boot: int = BOOTSTRAP_REPLICATES) -> dict[str, Any]:
    """Percentile cluster bootstrap where each input is one independent pair."""
    array = np.asarray(values, dtype=float)
    if array.size == 0 or not np.all(np.isfinite(array)):
        raise ValueError("bootstrap input must be non-empty and finite")
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, array.size, size=(n_boot, array.size))
    draws = array[indices].mean(axis=1)
    return {
        "mean": float(array.mean()),
        "ci95": [float(np.percentile(draws, 2.5)), float(np.percentile(draws, 97.5))],
        "ci90": [float(np.percentile(draws, 5.0)), float(np.percentile(draws, 95.0))],
        "n_pairs": int(array.size),
        "min": float(array.min()),
        "max": float(array.max()),
        "run_any_nonzero": {
            "count": int(np.count_nonzero(array)),
            "n": int(array.size),
            "clopper_pearson_ci95": list(clopper_pearson(int(np.count_nonzero(array)), int(array.size))),
        },
    }


def feature_value(run: "RunData", feature: str) -> np.ndarray:
    if feature == "volume":
        return np.asarray(run.samples, dtype=float)
    if feature == "entropy":
        return np.asarray(run.entropies, dtype=float)
    if feature == "unique_ratio":
        return np.asarray(run.unique_ratios, dtype=float)
    raise KeyError(feature)


# --------------------------------------------------------------------------- #
# 3. Shared schedule generation.                                               #
# --------------------------------------------------------------------------- #
@dataclass
class SharedSchedule:
    split: str
    profile: str
    level: int
    pair_id: int
    schedule_seed: int
    query_seed: int
    burst_phase_offset_seconds: float
    arrivals: list[float]
    query_times: list[float]
    frag1_ipids: list[int]
    arrival_schedule_sha256: str
    query_schedule_sha256: str


def make_arrival_times(profile: str, level: int, seed: int, end_time: float
                       ) -> tuple[list[float], float]:
    """Generate a continuous or exact-thinned bursty FRAG2 timestamp trace."""
    rng = random.Random(seed)
    lam = level / WINDOW_SECONDS
    arrivals: list[float] = []
    timestamp = 0.0
    if profile == "continuous":
        while True:
            timestamp += rng.expovariate(lam)
            if timestamp > end_time:
                break
            arrivals.append(timestamp)
        return arrivals, 0.0
    if profile != "bursty":
        raise ValueError(profile)

    # Thinning gives an exact realization of a piecewise-constant NHPP.  Unlike
    # the old code, no exponential wait sampled in one phase crosses a boundary
    # under the wrong hazard.
    maximum_rate = lam * BURST_HIGH
    phase_offset = rng.random() * (2.0 * BURST_HALF_PERIOD_SECONDS)
    while True:
        timestamp += rng.expovariate(maximum_rate)
        if timestamp > end_time:
            break
        phase = int((timestamp + phase_offset) / BURST_HALF_PERIOD_SECONDS) % 2
        multiplier = BURST_HIGH if phase == 0 else BURST_LOW
        if rng.random() <= multiplier / BURST_HIGH:
            arrivals.append(timestamp)
    return arrivals, phase_offset


def build_shared_schedule(experiment_seed: int, split: str, profile: str,
                          level: int, pair_id: int, queries_per_run: int) -> SharedSchedule:
    schedule_seed = derive_seed(experiment_seed, split, profile, level, pair_id, "arrival")
    query_seed = derive_seed(experiment_seed, split, profile, level, pair_id, "query")
    phase_rng = random.Random(query_seed)
    query_phase = phase_rng.random() * QUERY_INTERVAL_SECONDS
    query_times = [WARMUP_SECONDS + query_phase + query_idx * QUERY_INTERVAL_SECONDS
                   for query_idx in range(queries_per_run)]
    frag1_rng = random.Random(derive_seed(experiment_seed, split, profile, level, pair_id,
                                           "frag1_ipid"))
    frag1_ipids = [frag1_rng.randrange(IPID_SPACE) for _ in range(queries_per_run)]
    arrivals, burst_phase_offset = make_arrival_times(profile, level, schedule_seed,
                                                        query_times[-1])
    arrival_hash = sha256_bytes(canonical_json({
        "split": split, "profile": profile, "level": level, "pair_id": pair_id,
        "arrival_timestamps": arrivals,
    }))
    query_hash = sha256_bytes(canonical_json({
        "split": split, "profile": profile, "level": level, "pair_id": pair_id,
        "query_timestamps": query_times, "frag1_ipids": frag1_ipids,
    }))
    return SharedSchedule(
        split=split, profile=profile, level=level, pair_id=pair_id,
        schedule_seed=schedule_seed, query_seed=query_seed,
        burst_phase_offset_seconds=burst_phase_offset, arrivals=arrivals,
        query_times=query_times, frag1_ipids=frag1_ipids,
        arrival_schedule_sha256=arrival_hash, query_schedule_sha256=query_hash,
    )


def payload_for_condition(experiment_seed: int, schedule: SharedSchedule,
                          condition: str, benign_fraction: float
                          ) -> tuple[int, list[tuple[str, int]]]:
    """Keep timestamps fixed; vary only event origin and IPID assignment."""
    config = CONDITIONS[condition]
    payload_seed = derive_seed(experiment_seed, schedule.split, schedule.profile,
                               schedule.level, schedule.pair_id, condition, "payload")
    benign_rng = random.Random(derive_seed(payload_seed, "benign_ipid"))
    mixture_rng = random.Random(derive_seed(payload_seed, "mixture"))
    attacker_rng = random.Random(derive_seed(payload_seed, "attacker_ipid"))
    sweep_value = attacker_rng.randrange(IPID_SPACE)
    duplicate_value = attacker_rng.randrange(IPID_SPACE)
    duplicate_repeat = 0

    payload: list[tuple[str, int]] = []
    for _ in schedule.arrivals:
        if config["role"] == "benign":
            payload.append(("benign", benign_rng.randrange(IPID_SPACE)))
            continue
        is_attack = mixture_rng.random() >= benign_fraction
        if not is_attack:
            payload.append(("benign", benign_rng.randrange(IPID_SPACE)))
            continue
        model = config["ipid_model"]
        if model == "random":
            ipid = attacker_rng.randrange(IPID_SPACE)
        elif model == "fixed":
            ipid = FIXED_IPID
        elif model == "sweep":
            ipid = sweep_value % IPID_SPACE
            sweep_value += 1
        elif model == "dup_sweep":
            ipid = duplicate_value % IPID_SPACE
            duplicate_repeat += 1
            if duplicate_repeat == 2:
                duplicate_repeat = 0
                duplicate_value += 1
        else:
            raise ValueError(f"unknown IPID model: {model}")
        payload.append(("attack", ipid))
    return payload_seed, payload


# --------------------------------------------------------------------------- #
# 4. Query-timed virtual resolver adapter and retained raw records.            #
# --------------------------------------------------------------------------- #
@dataclass
class RunData:
    split: str
    profile: str
    condition: str
    role: str
    level: int
    pair_id: int
    schedule_seed: int
    query_seed: int
    payload_seed: int
    arrival_schedule_sha256: str
    query_schedule_sha256: str
    decisions: int
    fragments_total: int
    benign_fragments_total: int
    attack_fragments_total: int
    measurement_start_seconds: float
    measurement_end_seconds: float
    samples: list[int]
    entropies: list[float]
    unique_ratios: list[float]
    benign_events_in_window: list[int]
    attack_events_in_window: list[int]
    blocks: dict[str, list[bool]]
    raw_file: str
    raw_sha256: str

    @property
    def rates(self) -> dict[str, float]:
        return {variant: sum(self.blocks[variant]) / self.decisions for variant in VARIANTS}

    @property
    def samples_mean(self) -> float:
        return float(np.mean(self.samples))

    @property
    def samples_p95(self) -> float:
        return float(np.percentile(self.samples, 95))

    @property
    def entropy_mean(self) -> float:
        return float(np.mean(self.entropies))

    @property
    def unique_ratio_mean(self) -> float:
        return float(np.mean(self.unique_ratios))


DECISION_COLUMNS = [
    "split", "profile", "condition", "role", "level", "pair_id", "schedule_seed",
    "query_seed", "payload_seed", "arrival_schedule_sha256", "query_schedule_sha256",
    "query_idx", "query_timestamp_seconds", "window_start_seconds", "frag1_ipid",
    "samples", "unique_ipids", "entropy", "unique_ratio",
    "benign_events_in_window", "attack_events_in_window",
    *[f"block_{variant}" for variant in VARIANTS],
]


def raw_relative_path(split: str, condition: str, level: int, pair_id: int) -> Path:
    return (Path("raw_runs") / split / condition / f"level_{level}" /
            f"pair_{pair_id:02d}.jsonl.gz")


def write_raw_record(handle: Any, record: dict[str, Any]) -> None:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":"),
                            allow_nan=False) + "\n")


def simulate_condition_run(out_dir: Path, experiment_seed: int, schedule: SharedSchedule,
                           condition: str, benign_fraction: float,
                           decision_writer: csv.writer) -> RunData:
    """Replay one payload assignment against a shared query/arrival schedule.

    The order exactly follows the relevant resolver behavior: FRAG2 events are
    observed; on each query timestamp, old events are pruned with ``< cutoff`` and
    the history is scored.  The current query's FRAG1 IPID is logged but never
    inserted into the FRAG2 history.
    """
    config = CONDITIONS[condition]
    if config["profile"] != schedule.profile:
        raise ValueError("condition/profile does not match shared schedule")
    payload_seed, payload = payload_for_condition(experiment_seed, schedule, condition,
                                                   benign_fraction)
    if len(payload) != len(schedule.arrivals):
        raise RuntimeError("payload/schedule length mismatch")
    rel_path = raw_relative_path(schedule.split, condition, schedule.level, schedule.pair_id)
    raw_path = out_dir / rel_path
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    if raw_path.exists():
        raise FileExistsError(f"refusing to overwrite raw file: {raw_path}")

    samples: list[int] = []
    entropies: list[float] = []
    unique_ratios: list[float] = []
    benign_window_counts: list[int] = []
    attack_window_counts: list[int] = []
    blocks = {variant: [] for variant in VARIANTS}
    history: Deque[tuple[float, int, str]] = deque()
    next_arrival = 0

    with gzip.open(raw_path, "xt", encoding="utf-8", newline="\n") as raw_handle:
        write_raw_record(raw_handle, {
            "schema_version": 2,
            "record_type": "run_meta",
            "split": schedule.split,
            "profile": schedule.profile,
            "condition": condition,
            "role": config["role"],
            "level_samples_per_window": schedule.level,
            "pair_id": schedule.pair_id,
            "schedule_seed": schedule.schedule_seed,
            "query_seed": schedule.query_seed,
            "payload_seed": payload_seed,
            "arrival_schedule_sha256": schedule.arrival_schedule_sha256,
            "query_schedule_sha256": schedule.query_schedule_sha256,
            "burst_phase_offset_seconds": schedule.burst_phase_offset_seconds,
            "scheduled_frag2_events": len(schedule.arrivals),
            "scheduled_queries": len(schedule.query_times),
            "window_seconds": WINDOW_SECONDS,
            "query_timing": "score after FRAG2 timestamps <= query timestamp; current FRAG1 not inserted",
        })
        for query_idx, (query_time, frag1_ipid) in enumerate(
                zip(schedule.query_times, schedule.frag1_ipids), 1):
            while next_arrival < len(schedule.arrivals) and (
                    schedule.arrivals[next_arrival] <= query_time):
                timestamp = schedule.arrivals[next_arrival]
                origin, ipid = payload[next_arrival]
                history.append((timestamp, ipid, origin))
                write_raw_record(raw_handle, {
                    "schema_version": 2,
                    "record_type": "frag2",
                    "event_idx": next_arrival + 1,
                    "timestamp_seconds": timestamp,
                    "origin": origin,
                    "ipid": ipid,
                })
                next_arrival += 1

            window_start = query_time - WINDOW_SECONDS
            # Exact resolver.py R2EntropyTable._prune semantics: discard only ts < cutoff.
            while history and history[0][0] < window_start:
                history.popleft()
            ipids = [event[1] for event in history]
            total = len(ipids)
            unique = len(set(ipids))
            entropy = finite(float(R.shannon_entropy(ipids)))
            unique_ratio = finite((unique / total) if total else 0.0)
            benign_count = sum(1 for event in history if event[2] == "benign")
            attack_count = total - benign_count
            decisions = {
                variant: False if variant == "no_defense"
                else bool(R.r2_should_block(variant, True, total, entropy, unique_ratio))
                for variant in VARIANTS
            }
            samples.append(total)
            entropies.append(entropy)
            unique_ratios.append(unique_ratio)
            benign_window_counts.append(benign_count)
            attack_window_counts.append(attack_count)
            for variant in VARIANTS:
                blocks[variant].append(decisions[variant])
            write_raw_record(raw_handle, {
                "schema_version": 2,
                "record_type": "decision",
                "query_idx": query_idx,
                "timestamp_seconds": query_time,
                "window_start_seconds": window_start,
                "frag1_ipid": frag1_ipid,
                "samples": total,
                "unique_ipids": unique,
                "entropy": entropy,
                "unique_ratio": unique_ratio,
                "benign_events_in_window": benign_count,
                "attack_events_in_window": attack_count,
                **{f"block_{variant}": decisions[variant] for variant in VARIANTS},
            })
            decision_writer.writerow([
                schedule.split, schedule.profile, condition, config["role"], schedule.level,
                schedule.pair_id, schedule.schedule_seed, schedule.query_seed, payload_seed,
                schedule.arrival_schedule_sha256, schedule.query_schedule_sha256,
                query_idx, query_time, window_start, frag1_ipid, total, unique, entropy,
                unique_ratio, benign_count, attack_count,
                *[int(decisions[variant]) for variant in VARIANTS],
            ])

    if len(samples) != len(schedule.query_times):
        raise RuntimeError(f"incomplete run {condition}: {len(samples)}/{len(schedule.query_times)}")
    origin_counts = {"benign": sum(origin == "benign" for origin, _ in payload),
                     "attack": sum(origin == "attack" for origin, _ in payload)}
    return RunData(
        split=schedule.split, profile=schedule.profile, condition=condition,
        role=config["role"], level=schedule.level, pair_id=schedule.pair_id,
        schedule_seed=schedule.schedule_seed, query_seed=schedule.query_seed,
        payload_seed=payload_seed,
        arrival_schedule_sha256=schedule.arrival_schedule_sha256,
        query_schedule_sha256=schedule.query_schedule_sha256,
        decisions=len(samples), fragments_total=len(schedule.arrivals),
        benign_fragments_total=origin_counts["benign"], attack_fragments_total=origin_counts["attack"],
        measurement_start_seconds=schedule.query_times[0],
        measurement_end_seconds=schedule.query_times[-1], samples=samples, entropies=entropies,
        unique_ratios=unique_ratios, benign_events_in_window=benign_window_counts,
        attack_events_in_window=attack_window_counts, blocks=blocks,
        raw_file=rel_path.as_posix(), raw_sha256=sha256_file(raw_path),
    )


# --------------------------------------------------------------------------- #
# 5. Provenance and output writers.                                            #
# --------------------------------------------------------------------------- #
def git_provenance(path: Path) -> dict[str, Any]:
    def invoke(*args: str) -> str:
        try:
            result = subprocess.run(["git", "-C", str(path), *args], capture_output=True,
                                    text=True, timeout=10)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    status = invoke("status", "--porcelain=v1")
    return {
        "commit_full": invoke("rev-parse", "HEAD"),
        "commit_short": invoke("rev-parse", "--short", "HEAD"),
        "branch": invoke("branch", "--show-current"),
        "dirty": bool(status not in ("", "unknown")),
        "status_porcelain_v1": status,
    }


def dependency_versions() -> dict[str, str]:
    values = {"python": platform.python_version()}
    for package in ("numpy", "scipy", "scikit-learn", "matplotlib", "psutil"):
        try:
            values[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            values[package] = "not-installed"
    return values


def hardware_info() -> dict[str, Any]:
    value: dict[str, Any] = {
        "platform": platform.platform(),
        "processor": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unknown"),
        "logical_cpus": os.cpu_count(),
    }
    try:
        import psutil  # type: ignore
        value["memory_bytes"] = int(psutil.virtual_memory().total)
    except Exception:
        value["memory_bytes"] = None
    return value


def snapshot_sources(out_dir: Path) -> dict[str, dict[str, str]]:
    candidates = {
        "e2_confirmatory.py": Path(__file__).resolve(),
        "e2_validate.py": HERE / "e2_validate.py",
        "e2_plot_confirmatory.py": HERE / "e2_plot_confirmatory.py",
        "e2_report.py": HERE / "e2_report.py",
        "resolver.py": RESOLVER_DIR / "resolver.py",
        "auth_server.py": LAB_DIR / "auth" / "auth_server.py",
        "spoof_r2entropy.py": LAB_DIR / "attacker" / "scripts" / "spoof_r2entropy.py",
        "dnslib.py": SHIM_DIR / "dnslib.py",
    }
    snapshot_dir = out_dir / "source_snapshot"
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, dict[str, str]] = {}
    for name, source in candidates.items():
        if not source.is_file():
            raise FileNotFoundError(f"required source snapshot missing: {source}")
        destination = snapshot_dir / name
        shutil.copy2(source, destination)
        manifest[name] = {
            "source": str(source.resolve()),
            "snapshot": destination.relative_to(out_dir).as_posix(),
            "sha256": sha256_file(destination),
        }
    return manifest


RUN_COLUMNS = [
    "split", "profile", "condition", "role", "level", "pair_id", "schedule_seed",
    "query_seed", "payload_seed", "arrival_schedule_sha256", "query_schedule_sha256",
    "decisions", "fragments_total", "benign_fragments_total", "attack_fragments_total",
    "measurement_start_seconds", "measurement_end_seconds", "samples_mean", "samples_p95",
    "entropy_mean", "unique_ratio_mean", *[f"blocks_{variant}" for variant in VARIANTS],
    *[f"rate_{variant}" for variant in VARIANTS], "raw_file", "raw_sha256",
]


def write_runs_csv(path: Path, runs: Iterable[RunData]) -> None:
    split_order = {"calibration": 0, "validation": 1, "test": 2}
    ordered = sorted(runs, key=lambda run: (
        split_order[run.split], run.profile, run.condition, run.level, run.pair_id
    ))
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(RUN_COLUMNS)
        for run in ordered:
            writer.writerow([
                run.split, run.profile, run.condition, run.role, run.level, run.pair_id,
                run.schedule_seed, run.query_seed, run.payload_seed,
                run.arrival_schedule_sha256, run.query_schedule_sha256, run.decisions,
                run.fragments_total, run.benign_fragments_total, run.attack_fragments_total,
                run.measurement_start_seconds, run.measurement_end_seconds, run.samples_mean,
                run.samples_p95, run.entropy_mean, run.unique_ratio_mean,
                *[sum(run.blocks[variant]) for variant in VARIANTS],
                *[run.rates[variant] for variant in VARIANTS], run.raw_file, run.raw_sha256,
            ])


def refresh_artifact_manifest(out_dir: Path, *, generated_utc: str | None = None) -> None:
    manifest_path = out_dir / "artifact_manifest.json"
    entries = []
    for path in sorted(out_dir.rglob("*")):
        if not path.is_file() or path == manifest_path:
            continue
        entries.append({
            "path": path.relative_to(out_dir).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    write_json(manifest_path, {
        "schema_version": 1,
        "generated_utc": generated_utc or utc_now(),
        "file_count": len(entries),
        "files": entries,
    })


# --------------------------------------------------------------------------- #
# 6. Split execution, validation lock, and test aggregation.                  #
# --------------------------------------------------------------------------- #
def conditions_for_split(split: str) -> tuple[str, ...]:
    if split == "calibration":
        return tuple(PROFILE_BENIGN[profile] for profile in PROFILES)
    if split in ("validation", "test"):
        return tuple(CONDITIONS)
    raise ValueError(split)


def run_split(out_dir: Path, split: str, pair_runs: int, queries_per_run: int,
              experiment_seed: int, benign_fraction: float, decision_writer: csv.writer
              ) -> list[RunData]:
    selected_conditions = set(conditions_for_split(split))
    jobs = [(profile, level, pair_id) for profile in PROFILES for level in LEVELS
            for pair_id in range(pair_runs)]
    random.Random(derive_seed(experiment_seed, split, "job-order")).shuffle(jobs)
    output: list[RunData] = []
    started = time.monotonic()
    for job_idx, (profile, level, pair_id) in enumerate(jobs, 1):
        schedule = build_shared_schedule(experiment_seed, split, profile, level, pair_id,
                                         queries_per_run)
        condition_order = [condition for condition in PROFILE_CONDITIONS[profile]
                           if condition in selected_conditions]
        random.Random(derive_seed(experiment_seed, split, profile, level, pair_id,
                                  "condition-order")).shuffle(condition_order)
        for condition in condition_order:
            output.append(simulate_condition_run(out_dir, experiment_seed, schedule, condition,
                                                 benign_fraction, decision_writer))
        if job_idx % 20 == 0 or job_idx == len(jobs):
            print(f"[{split}] pair jobs {job_idx}/{len(jobs)}; "
                  f"condition-runs={len(output)}; elapsed={time.monotonic() - started:.1f}s")
    return output


def calibration_preflight(runs: Sequence[RunData]) -> list[dict[str, Any]]:
    expected_conditions = set(PROFILE_BENIGN.values())
    output: list[dict[str, Any]] = []
    grouped: dict[tuple[str, int], list[RunData]] = defaultdict(list)
    for run in runs:
        if run.condition not in expected_conditions:
            raise ValueError("calibration contains non-control condition")
        grouped[(run.profile, run.level)].append(run)
    for (profile, level), cell in sorted(grouped.items()):
        observed = float(np.mean([run.samples_mean for run in cell]))
        tolerance = max(0.75, level * 0.05)
        output.append({
            "profile": profile,
            "level": level,
            "runs": len(cell),
            "samples_mean": observed,
            "target_samples_per_window": level,
            "tolerance": tolerance,
            "pass": abs(observed - level) <= tolerance,
        })
    return output


def index_runs(runs: Sequence[RunData]) -> dict[tuple[str, str, int, int], RunData]:
    indexed: dict[tuple[str, str, int, int], RunData] = {}
    for run in runs:
        key = (run.split, run.condition, run.level, run.pair_id)
        if key in indexed:
            raise ValueError(f"duplicate run key: {key}")
        indexed[key] = run
    return indexed


def select_validation_thresholds(validation_runs: Sequence[RunData], experiment_seed: int
                                 ) -> dict[str, Any]:
    """Freeze optional high-is-suspicious feature thresholds before test starts."""
    indexed = index_runs(validation_runs)
    entries: list[dict[str, Any]] = []
    for attack in ATTACK_CONDITIONS:
        profile = CONDITIONS[attack]["profile"]
        benign = PROFILE_BENIGN[profile]
        for level in LEVELS:
            pairs = sorted(run.pair_id for run in validation_runs
                           if run.condition == attack and run.level == level)
            for feature in FEATURES:
                attack_scores = np.concatenate([
                    feature_value(indexed[("validation", attack, level, pair_id)], feature)
                    for pair_id in pairs
                ])
                benign_scores = np.concatenate([
                    feature_value(indexed[("validation", benign, level, pair_id)], feature)
                    for pair_id in pairs
                ])
                sorted_scores = np.sort(attack_scores)
                threshold_index = min(len(sorted_scores) - 1,
                                      max(0, int(math.floor((1.0 - TARGET_ALERT_RATE)
                                                             * len(sorted_scores)))))
                threshold = float(sorted_scores[threshold_index])
                attack_rate = float(np.mean(attack_scores >= threshold))
                benign_rate = float(np.mean(benign_scores >= threshold))
                entries.append({
                    "attack_condition": attack,
                    "benign_condition": benign,
                    "profile": profile,
                    "level": level,
                    "feature": feature,
                    "direction": "higher_is_suspicious",
                    "target_validation_attack_alert_rate": TARGET_ALERT_RATE,
                    "threshold": threshold,
                    "validation_attack_alert_rate": attack_rate,
                    "validation_benign_trigger_rate": benign_rate,
                    "selection": "largest empirical threshold with attack alert rate >= target",
                })
    return {
        "schema_version": 1,
        "status": "locked-before-test",
        "locked_utc": utc_now(),
        "split_used": "validation",
        "scope": ("diagnostic scalar-feature thresholds only; the registered B5/B2 primary "
                  "comparison uses fixed rule thresholds and is not tuned here"),
        "entries": entries,
        "selection_seed_namespace": derive_seed(experiment_seed, "validation-thresholds"),
    }


def paired_feature_ap(benign: RunData, attack: RunData, feature: str) -> float:
    scores = np.concatenate([feature_value(benign, feature), feature_value(attack, feature)])
    labels = np.concatenate([np.zeros(benign.decisions, dtype=int),
                             np.ones(attack.decisions, dtype=int)])
    return finite(float(average_precision_score(labels, scores)))


def balanced_precision(attack_alert_rate: float, benign_trigger_rate: float) -> float:
    """Precision under E2's deliberately balanced benign/attack pairing.

    E2 has equal decision counts in the paired benign and synthetic-attack runs,
    so this is the precision under a 50:50 class mix.  It is not a deployment
    prevalence estimate.  A no-alert rule receives 0.0 rather than an undefined
    precision so the metric stays serializable and is interpreted with its TPR.
    """
    denominator = attack_alert_rate + benign_trigger_rate
    return attack_alert_rate / denominator if denominator > 0.0 else 0.0


def metric_summary(values: Sequence[float], experiment_seed: int, *seed_parts: object) -> dict[str, Any]:
    return bootstrap_mean(values, derive_seed(experiment_seed, "bootstrap", *seed_parts))


def aggregate_test_results(test_runs: Sequence[RunData], thresholds: dict[str, Any],
                           experiment_seed: int) -> dict[str, Any]:
    indexed = index_runs(test_runs)
    threshold_index = {
        (entry["attack_condition"], int(entry["level"]), entry["feature"]): entry
        for entry in thresholds["entries"]
    }
    cells: list[dict[str, Any]] = []
    delta_by_attack_level: dict[tuple[str, int], dict[str, dict[int, float]]] = {}
    for attack in ATTACK_CONDITIONS:
        profile = CONDITIONS[attack]["profile"]
        benign_condition = PROFILE_BENIGN[profile]
        for level in LEVELS:
            pair_ids = sorted(run.pair_id for run in test_runs
                              if run.condition == attack and run.level == level)
            if not pair_ids:
                raise ValueError(f"no test runs for {attack}/{level}")
            per_variant: dict[str, dict[str, list[float]]] = {
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
            feature_aps = {feature: [] for feature in FEATURES}
            threshold_values: dict[str, dict[str, list[float]]] = {
                feature: {"benign_trigger": [], "attack_alert": [], "balanced_precision": []}
                for feature in FEATURES
            }
            paired_sample_diffs: list[int] = []
            paired_deltas = {baseline: {} for baseline in BASELINE_VARIANTS}
            schedule_match = True
            for pair_id in pair_ids:
                benign = indexed[("test", benign_condition, level, pair_id)]
                attack_run = indexed[("test", attack, level, pair_id)]
                schedule_match &= (
                    benign.arrival_schedule_sha256 == attack_run.arrival_schedule_sha256
                    and benign.query_schedule_sha256 == attack_run.query_schedule_sha256
                )
                if benign.decisions != attack_run.decisions:
                    raise ValueError("paired decision count mismatch")
                paired_sample_diffs.extend(
                    abs(left - right) for left, right in zip(benign.samples, attack_run.samples)
                )
                for variant in VARIANTS:
                    benign_rate = benign.rates[variant]
                    attack_rate = attack_run.rates[variant]
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
                    paired_deltas[baseline][pair_id] = (
                        per_variant["combined"]["youden_j"][-1]
                        - per_variant[baseline]["youden_j"][-1]
                    )
                for feature in FEATURES:
                    feature_aps[feature].append(paired_feature_ap(benign, attack_run, feature))
                    threshold_entry = threshold_index[(attack, level, feature)]
                    threshold = float(threshold_entry["threshold"])
                    benign_threshold_rate = float(np.mean(feature_value(benign, feature) >= threshold))
                    attack_threshold_rate = float(np.mean(
                        feature_value(attack_run, feature) >= threshold
                    ))
                    threshold_values[feature]["benign_trigger"].append(benign_threshold_rate)
                    threshold_values[feature]["attack_alert"].append(attack_threshold_rate)
                    threshold_values[feature]["balanced_precision"].append(
                        balanced_precision(attack_threshold_rate, benign_threshold_rate)
                    )

            variant_results = {
                variant: {
                    metric: metric_summary(values, experiment_seed, attack, level, variant, metric)
                    for metric, values in values_by_metric.items()
                }
                for variant, values_by_metric in per_variant.items()
            }
            paired_delta_results = {
                baseline: metric_summary(
                    [paired_deltas[baseline][pair_id] for pair_id in pair_ids],
                    experiment_seed,
                    attack,
                    level,
                    f"delta_j_combined_minus_{baseline}",
                )
                for baseline in BASELINE_VARIANTS
            }
            ap_results = {
                feature: metric_summary(values, experiment_seed, attack, level, feature, "auprc")
                for feature, values in feature_aps.items()
            }
            frozen_threshold_results = {
                feature: {
                    "threshold": float(threshold_index[(attack, level, feature)]["threshold"]),
                    "direction": "higher_is_suspicious",
                    "test_benign_trigger_rate": metric_summary(values["benign_trigger"], experiment_seed,
                                                                 attack, level, feature, "threshold_benign"),
                    "test_attack_alert_rate": metric_summary(values["attack_alert"], experiment_seed,
                                                               attack, level, feature, "threshold_attack"),
                    "test_balanced_precision": metric_summary(values["balanced_precision"], experiment_seed,
                                                                 attack, level, feature, "threshold_precision"),
                }
                for feature, values in threshold_values.items()
            }
            cells.append({
                "profile": profile,
                "attack_condition": attack,
                "benign_condition": benign_condition,
                "level": level,
                "n_pairs": len(pair_ids),
                "paired_schedule_hashes_match": schedule_match,
                "max_abs_paired_samples_difference": int(max(paired_sample_diffs, default=0)),
                "variants": variant_results,
                "paired_delta_j_combined_minus": paired_delta_results,
                # Kept as an explicit compatibility alias for the registered primary comparison.
                "delta_j_combined_minus_volume": paired_delta_results["volume"],
                "feature_auprc_high_is_suspicious": ap_results,
                "frozen_threshold_diagnostics": frozen_threshold_results,
            })
            delta_by_attack_level[(attack, level)] = paired_deltas

    macro_effects: list[dict[str, Any]] = []
    paired_ablation_macro_effects: list[dict[str, Any]] = []
    for attack in ("attack_sweep_continuous", "attack_sweep_bursty"):
        if attack not in ATTACK_CONDITIONS:
            continue
        for baseline in BASELINE_VARIANTS:
            common_pair_ids = sorted(set.intersection(*[
                set(delta_by_attack_level[(attack, level)][baseline]) for level in LEVELS
            ]))
            macro_values = [float(np.mean([
                delta_by_attack_level[(attack, level)][baseline][pair_id] for level in LEVELS
            ])) for pair_id in common_pair_ids]
            effect_seed_parts: tuple[object, ...] = (
                (attack, "macro_delta_j")
                if baseline == "volume"
                else (attack, baseline, "macro_delta_j")
            )
            effect = metric_summary(macro_values, experiment_seed, *effect_seed_parts)
            lo95, hi95 = effect["ci95"]
            lo90, hi90 = effect["ci90"]
            if lo95 > EQUIVALENCE_MARGIN:
                verdict = "meaningful_added_discrimination"
            elif lo90 >= -EQUIVALENCE_MARGIN and hi90 <= EQUIVALENCE_MARGIN:
                verdict = "practical_equivalence_within_registered_margin"
            elif hi95 < -EQUIVALENCE_MARGIN:
                verdict = "meaningful_degradation"
            else:
                verdict = "inconclusive"
            entry = {
                "attack_condition": attack,
                "baseline_variant": baseline,
                "levels": list(LEVELS),
                "metric": f"macro_average_delta_j_combined_minus_{baseline}",
                "registered_meaningful_margin": EQUIVALENCE_MARGIN,
                "result": effect,
                "verdict": verdict,
            }
            paired_ablation_macro_effects.append(entry)
            if baseline == "volume":
                # Preserve the registered B5-versus-B2 primary result for existing
                # consumers; every B1–B4 comparison is carried separately below.
                macro_effects.append(entry)
    return {
        "test_cells": cells,
        "macro_effects": macro_effects,
        "paired_ablation_macro_effects": paired_ablation_macro_effects,
        "analysis_scope": (
            "Query-timed controlled synthetic emulation. Attack alert rates are detector "
            "decisions under registered synthetic conditions, not poisoning/ASR/coverage outcomes."
        ),
    }


def write_summary_csv(path: Path, result: dict[str, Any]) -> None:
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "scope", "profile", "attack_condition", "benign_condition", "level", "metric",
            "variant_or_feature", "mean", "ci95_lo", "ci95_hi", "ci90_lo", "ci90_hi", "n_pairs",
        ])
        for cell in result["test_cells"]:
            common = ["test", cell["profile"], cell["attack_condition"],
                      cell["benign_condition"], cell["level"]]
            for variant, metrics in cell["variants"].items():
                for metric, values in metrics.items():
                    writer.writerow([
                        *common, metric, variant, values["mean"], *values["ci95"],
                        *values["ci90"], values["n_pairs"],
                    ])
            for baseline, values in cell["paired_delta_j_combined_minus"].items():
                writer.writerow([
                    *common, f"delta_j_combined_minus_{baseline}", f"combined-minus-{baseline}",
                    values["mean"], *values["ci95"], *values["ci90"], values["n_pairs"],
                ])
            for feature, values in cell["feature_auprc_high_is_suspicious"].items():
                writer.writerow([
                    *common, "auprc_high_is_suspicious", feature, values["mean"],
                    *values["ci95"], *values["ci90"], values["n_pairs"],
                ])
            for feature, values in cell["frozen_threshold_diagnostics"].items():
                for metric in (
                    "test_attack_alert_rate",
                    "test_benign_trigger_rate",
                    "test_balanced_precision",
                ):
                    summary = values[metric]
                    writer.writerow([
                        *common, f"validation_locked_{metric}", feature, summary["mean"],
                        *summary["ci95"], *summary["ci90"], summary["n_pairs"],
                    ])
        for macro in result["macro_effects"]:
            values = macro["result"]
            writer.writerow([
                "test", "macro", macro["attack_condition"], "matched-benign", "all-levels",
                macro["metric"], macro["verdict"], values["mean"], *values["ci95"],
                *values["ci90"], values["n_pairs"],
            ])


def write_notes(path: Path, results: dict[str, Any]) -> None:
    lines = [
        "E2 CONFIRMATORY — query-timed paired controlled emulation",
        "=" * 66,
        "Primary comparison: B5 combined versus B2 volume-only.",
        "Only test split is inferential; calibration is generator QA and validation locks diagnostics.",
        "Scope: detector decision behavior in synthetic traces; not real IP fragments, ASR, poisoning, latency, CPU, or deployment performance.",
        "",
        "Macro effects (registered):",
    ]
    for effect in results["analysis"]["macro_effects"]:
        value = effect["result"]
        lines.append(
            f"  {effect['attack_condition']}: ΔJ={value['mean']:+.4f}, "
            f"95% CI [{value['ci95'][0]:+.4f}, {value['ci95'][1]:+.4f}], "
            f"verdict={effect['verdict']}"
        )
    lines.append("")
    lines.append("See e2_results.json, e2_summary.csv, e2_runs.csv, raw_runs/, and validation.json.")
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
# 7. CLI orchestration.                                                        #
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run confirmatory E2 into an empty artifact directory")
    parser.add_argument("--out", type=Path, required=True,
                        help="new empty output artifact directory")
    parser.add_argument("--run-id", type=str, default=None)
    parser.add_argument("--experiment-seed", type=int, default=DEFAULT_EXPERIMENT_SEED)
    parser.add_argument("--queries", type=int, default=DEFAULT_QUERIES_PER_RUN)
    parser.add_argument("--preflight-runs", type=int, default=DEFAULT_PREFLIGHT_RUNS)
    parser.add_argument("--validation-runs", type=int, default=DEFAULT_VALIDATION_RUNS)
    parser.add_argument("--test-runs", type=int, default=DEFAULT_TEST_RUNS)
    parser.add_argument("--benign-fraction", type=float, default=DEFAULT_BENIGN_FRACTION)
    parser.add_argument("--refresh-manifest", action="store_true",
                        help="only refresh artifact_manifest.json for an existing artifact")
    args = parser.parse_args()
    if args.refresh_manifest:
        return args
    if args.queries <= 0:
        parser.error("--queries must be positive")
    if args.preflight_runs < 2 or args.validation_runs < 2:
        parser.error("preflight and validation need at least 2 independent pairs")
    if args.test_runs < 20:
        parser.error("--test-runs must be >=20 for the registered confirmatory protocol")
    if not (0.0 <= args.benign_fraction < 1.0):
        parser.error("--benign-fraction must be in [0,1)")
    return args


def main() -> int:
    args = parse_args()
    out_dir = args.out.resolve()
    if args.refresh_manifest:
        if not out_dir.is_dir():
            raise FileNotFoundError(out_dir)
        refresh_artifact_manifest(out_dir)
        print(f"[+] refreshed {out_dir / 'artifact_manifest.json'}")
        return 0
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty E2 artifact: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    run_id = args.run_id or f"E2_confirmatory_{time.strftime('%Y%m%d_%H%M%S')}_seed{args.experiment_seed}"
    source_manifest = snapshot_sources(out_dir)
    registered_utc = utc_now()
    command = [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]
    protocol = {
        "schema_version": 3,
        "status": "registered-before-data-collection",
        "experiment": "E2 confirmatory — query-timed paired controlled emulation",
        "run_id": run_id,
        "registered_utc": registered_utc,
        "experiment_seed": args.experiment_seed,
        "scope": (
            "controlled synthetic emulation of detector decisions; no real IP fragmentation, "
            "poisoning/ASR, latency, CPU, or deployment claim"
        ),
        "command": command,
        "working_directory": str(Path.cwd()),
        "git_provenance": git_provenance(CODE_ROOT),
        "dependencies": dependency_versions(),
        "hardware": hardware_info(),
        "source_manifest": source_manifest,
        "operating_point": {
            "min_samples": MIN_SAMPLES,
            "entropy_threshold": ENTROPY_THRESHOLD,
            "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
            "window_seconds": WINDOW_SECONDS,
        },
        "levels_samples_per_window": list(LEVELS),
        "profiles": PROFILES,
        "conditions": CONDITIONS,
        "benign_fraction_in_attack_conditions": args.benign_fraction,
        "queries_per_run": args.queries,
        "warmup_seconds": WARMUP_SECONDS,
        "query_hz": QUERY_HZ,
        "query_schedule": "fixed 4 Hz after seeded phase; query/FRAG1 timestamps shared within pair",
        "arrival_schedule": {
            "continuous": "Poisson lambda=level/window",
            "bursty": "exact thinned square-wave NHPP: 1.75lambda/0.25lambda, half period 1.5s",
        },
        "splits": {
            "calibration": {
                "purpose": "generator/preflight QA only; does not fit rate or detector threshold",
                "runs_per_cell": args.preflight_runs,
                "conditions": list(conditions_for_split("calibration")),
            },
            "validation": {
                "purpose": "lock optional scalar diagnostic thresholds before test",
                "runs_per_cell": args.validation_runs,
                "conditions": list(conditions_for_split("validation")),
            },
            "test": {
                "purpose": "sole confirmatory evidence",
                "runs_per_cell": args.test_runs,
                "conditions": list(conditions_for_split("test")),
            },
        },
        "seed_derivation": "SHA-256(experiment_seed | split | profile | level | pair_id | stream-name)",
        "independent_unit": "pair_id (shared timestamp trace across matched conditions)",
        "volume_matching": "identical FRAG2 and query timestamps per profile/level/pair; assert sample difference 0 per query",
        "primary_metric": "delta J = (attack-alert - benign-trigger)_B5 - (attack-alert - benign-trigger)_B2",
        "primary_inference": "5000 whole-pair bootstrap resamples; test split only",
        "claim_gate": {
            "meaningful_added_discrimination": "95% CI lower bound > +0.05",
            "practical_equivalence": "90% CI wholly within [-0.05,+0.05]",
            "meaningful_degradation": "95% CI upper bound < -0.05",
        },
        "raw_schema_version": 2,
        "raw_layout": "one gzip JSONL per condition-run under raw_runs/{split}/{condition}/level_{level}/",
        "raw_fields": {
            "frag2": ["timestamp_seconds", "origin", "ipid"],
            "decision": ["timestamp_seconds", "window_start_seconds", "frag1_ipid", "samples",
                         "unique_ipids", "entropy", "unique_ratio", "benign_events_in_window",
                         "attack_events_in_window", *[f"block_{v}" for v in VARIANTS]],
        },
    }
    write_json(out_dir / "e2_protocol.json", protocol, exclusive=True)
    print("=" * 80)
    print("E2 CONFIRMATORY — query-timed paired controlled emulation")
    print(f"run_id={run_id}; output={out_dir}")
    print(f"K: calibration={args.preflight_runs}, validation={args.validation_runs}, test={args.test_runs}; "
          f"queries/run={args.queries}")
    print("=" * 80)

    all_runs: list[RunData] = []
    decisions_path = out_dir / "e2_decisions.csv.gz"
    with gzip.open(decisions_path, "wt", encoding="utf-8", newline="") as decision_handle:
        decision_writer = csv.writer(decision_handle)
        decision_writer.writerow(DECISION_COLUMNS)
        calibration_started_utc = utc_now()
        calibration_runs = run_split(out_dir, "calibration", args.preflight_runs, args.queries,
                                     args.experiment_seed, args.benign_fraction, decision_writer)
        calibration_completed_utc = utc_now()
        all_runs.extend(calibration_runs)
        preflight = calibration_preflight(calibration_runs)
        write_json(out_dir / "e2_preflight.json", {
            "schema_version": 1,
            "started_utc": calibration_started_utc,
            "completed_utc": calibration_completed_utc,
            "status": "PASS" if all(cell["pass"] for cell in preflight) else "FAIL",
            "checks": preflight,
            "note": "No rate/threshold is fitted from this split.",
        }, exclusive=True)
        if not all(cell["pass"] for cell in preflight):
            raise RuntimeError("E2 preflight failed; stop before validation/test and re-register after fix")

        validation_started_utc = utc_now()
        validation_runs = run_split(out_dir, "validation", args.validation_runs, args.queries,
                                    args.experiment_seed, args.benign_fraction, decision_writer)
        validation_completed_utc = utc_now()
        all_runs.extend(validation_runs)
        thresholds = select_validation_thresholds(validation_runs, args.experiment_seed)
        thresholds["validation_started_utc"] = validation_started_utc
        thresholds["validation_completed_utc"] = validation_completed_utc
        write_json(out_dir / "e2_thresholds.json", thresholds, exclusive=True)
        print(f"[+] validation thresholds locked at {thresholds['locked_utc']}")

        test_started_utc = utc_now()
        test_runs = run_split(out_dir, "test", args.test_runs, args.queries,
                              args.experiment_seed, args.benign_fraction, decision_writer)
        test_completed_utc = utc_now()
        all_runs.extend(test_runs)

    write_runs_csv(out_dir / "e2_runs.csv", all_runs)
    analysis = aggregate_test_results(test_runs, thresholds, args.experiment_seed)
    results = {
        "schema_version": 3,
        "meta": {
            "run_id": run_id,
            "registered_utc": registered_utc,
            "calibration_started_utc": calibration_started_utc,
            "calibration_completed_utc": calibration_completed_utc,
            "validation_started_utc": validation_started_utc,
            "validation_completed_utc": validation_completed_utc,
            "thresholds_locked_utc": thresholds["locked_utc"],
            "test_started_utc": test_started_utc,
            "test_completed_utc": test_completed_utc,
            "generated_utc": utc_now(),
            "scope": protocol["scope"],
            "independent_unit": protocol["independent_unit"],
            "operating_point": protocol["operating_point"],
            "levels_samples_per_window": list(LEVELS),
            "queries_per_run": args.queries,
            "split_runs": {
                "calibration": args.preflight_runs,
                "validation": args.validation_runs,
                "test": args.test_runs,
            },
            "source_manifest": source_manifest,
        },
        "preflight": preflight,
        "thresholds_file": "e2_thresholds.json",
        "analysis": analysis,
    }
    write_json(out_dir / "e2_results.json", results, exclusive=True)
    write_summary_csv(out_dir / "e2_summary.csv", analysis)
    write_notes(out_dir / "notes.txt", results)
    refresh_artifact_manifest(out_dir)
    print(f"[+] wrote campaign artifacts in {out_dir}")
    for effect in analysis["macro_effects"]:
        value = effect["result"]
        print(f"  {effect['attack_condition']} vs {effect['baseline_variant']}: "
              f"ΔJ={value['mean']:+.4f} "
              f"95%CI=[{value['ci95'][0]:+.4f},{value['ci95'][1]:+.4f}] "
              f"=> {effect['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
