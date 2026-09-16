"""E1 -- FPR theo tốc độ fragment hợp lệ (operating boundary of Rℓ₂).

Thí nghiệm E1 trong outline "POPS-Rℓ₂": chạy detector trên *chỉ* lưu lượng
fragment HỢP LỆ (không bật attacker) ở nhiều mức tải khác nhau và đo False
Positive Rate (FPR). Vì không có attacker, mọi quyết định ``tc_block`` đều là
báo động nhầm (false positive) -> FPR = blocks / decisions.

Tính trung thực (fidelity)
--------------------------
Script KHÔNG cài lại thuật toán detector. Nó import trực tiếp hai hàm chấm điểm
gốc từ ``labs/r2entropy/resolver/resolver.py``:

* ``shannon_entropy(values)``  -- entropy Shannon (log2) của tập IPID.
* ``r2_should_block(variant, defense_on, samples, entropy, unique_ratio)``
  -- luật B1..B5 tại operating point 24 / 4.0 / 0.70.

Cửa sổ trượt (sliding window) được mô phỏng đúng như ``R2EntropyTable._prune``:
cutoff = now - FRAG2_WINDOW_SECONDS, loại mọi sự kiện cũ hơn cutoff. Mô hình IPID
hợp lệ lấy đúng từ ``auth/auth_server.py`` (mỗi truy vấn frag phát một FRAG2 với
IPID = randint(0, IPID_SPACE-1)).

Vì sao là testbed mô phỏng chứ không phải Docker
------------------------------------------------
Testbed Docker hiện tại tuần tự hoá mỗi truy vấn bằng AUTH_DELAY=0.25s và client
cũng phát truy vấn tuần tự, nên chỉ đạt khoảng 5--6 mẫu/cửa sổ, không thể đạt các mức
{24, 36, 60, 120, 300} mà E1 yêu cầu. Đây đúng là điều README framework đã ghi:
"throughput cần được bổ sung trước khi chạy ma trận E1-E4 chính". Do đó E1 được
chạy trên testbed mô phỏng đã kiểm chứng (cùng mã detector), và mọi kết luận chỉ
áp dụng trong controlled emulation (đúng với Phạm vi kết luận của outline).

Đầu ra
------
* raw_decisions/ -- một JSONL / run, giữ toàn bộ decision-level records.
* e1_runs.csv    -- một dòng tóm tắt / run (K x levels x behaviors x variants).
* e1_levels.csv  -- tổng hợp / (level, behavior, variant) kèm 95% CI.
* e1_results.json -- toàn bộ kết quả + config + provenance (P0 logging).
* notes.txt      -- mô tả và tóm tắt kết quả.

Usage: python e1_experiment.py [--runs 20] [--decisions 300] [--out .]
"""
from __future__ import annotations

import argparse
import csv
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
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from scipy import stats

# Windows consoles default to cp1252; force UTF-8 so Vietnamese/Rℓ₂ prints.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# 0. Import the REAL detector primitives from resolver.py (via dnslib shim).   #
# --------------------------------------------------------------------------- #
HERE = Path(__file__).resolve().parent
# HERE = Code/research/Report/experiments/E1 -> parents[3] = Code
LAB_DIR = HERE.parents[3] / "labs" / "r2entropy"          # Code/labs/r2entropy
RESOLVER_DIR = LAB_DIR / "resolver"
SHIM_DIR = LAB_DIR / "localtest" / "shim"

# Operating point 4.0 / 24 / 0.70 (paper's proposed B5 thresholds) -- resolver.py
# reads these at import time from the environment, so set them BEFORE importing.
OPERATING_POINT = {
    "R2_MIN_SAMPLES": "24",
    "R2_ENTROPY_THRESHOLD": "4.0",
    "R2_UNIQUE_RATIO_THRESHOLD": "0.70",
    "R2_VARIANT": "combined",
    "FRAG2_WINDOW_SECONDS": "2.0",
}
for _k, _v in OPERATING_POINT.items():
    os.environ.setdefault(_k, _v)

sys.path.insert(0, str(SHIM_DIR))       # dependency-free dnslib stand-in
sys.path.insert(0, str(RESOLVER_DIR))   # resolver.py
import resolver as R  # noqa: E402  (import after sys.path / env setup, by design)

# --------------------------------------------------------------------------- #
# 1. Experiment configuration (E1 spec).                                       #
# --------------------------------------------------------------------------- #
WINDOW_SECONDS = float(OPERATING_POINT["FRAG2_WINDOW_SECONDS"])
MIN_SAMPLES = R.R2_MIN_SAMPLES
ENTROPY_THRESHOLD = R.R2_ENTROPY_THRESHOLD
UNIQUE_RATIO_THRESHOLD = R.R2_UNIQUE_RATIO_THRESHOLD

# E1: target samples/window.
SAMPLES_PER_WINDOW_LEVELS = [5, 12, 18, 24, 36, 60, 120, 300]

# Extra levels beyond the outline's grid. They are required because the improved rule
# turns out to be BAND-pass, not high-pass: once the window holds enough fragments that
# IPID collisions become unavoidable (the space is only IPID_SPACE values), unique_ratio
# falls back under its threshold and the AND gate re-opens. The real testbed attack runs
# at ~2000 samples/window, i.e. inside this region, so it must be measured, not assumed.
HIGH_LOAD_LEVELS = [600, 1200, 1400, 1600, 1800, 2000, 3000, 6000]

# Detector variants scored per decision event. "combined" (B5) is the primary
# operating point under test; the others (B2/B3/B4) are reference lines that
# explain *why* B5 behaves as it does at high rate.
# Các biến thể của luật Rℓ2:
#   legacy   = Rℓ2 GỐC của paper POPS (Algorithm 3): chặn MỌI fragment.
#   combined = Rℓ2 CẢI TIẾN của nhóm (entropy 3 tham số) -- detector under test.
#   volume/entropy/unique = ablation từng tín hiệu.
VARIANTS = ["legacy", "combined", "volume", "entropy", "unique"]
PRIMARY_VARIANT = "combined"

# E1: "tối thiểu ba kiểu IPID/source behavior". Each models a legitimate way a
# real host/middlebox assigns the 16-bit IP identification field.
IPID_BEHAVIORS = {
    # Exactly auth_server.py: uniform random over IPID_SPACE=2048. High diversity.
    "random2048": {"kind": "uniform", "space": 2048,
                   "label": "Random IPID (uniform 0..2047) -- auth_server model"},
    # Classic monotonic global counter (older Linux/Windows stacks). All-distinct.
    "sequential": {"kind": "sequential", "space": 2048,
                   "label": "Sequential IPID (global +1 counter)"},
    # Constrained device / NAT / middlebox reusing a tiny IPID pool. Low diversity.
    "smallpool16": {"kind": "uniform", "space": 16,
                    "label": "Small IPID pool (uniform 0..15) -- NAT / constrained host"},
}

DEFAULT_EXPERIMENT_SEED = 20260805
WARMUP_MULT = 3.0           # discard first WARMUP_MULT * window seconds (ramp-up)


# --------------------------------------------------------------------------- #
# 2. IPID source model (faithful to auth_server.py benign FRAG2).             #
# --------------------------------------------------------------------------- #
def make_ipid_sampler(behavior: str, rng: random.Random):
    """Return a zero-arg callable producing one benign FRAG2 IPID."""
    cfg = IPID_BEHAVIORS[behavior]
    space = cfg["space"]
    if cfg["kind"] == "uniform":
        # auth_server.py: random.randint(0, IPID_SPACE - 1)
        return lambda: rng.randint(0, space - 1)
    if cfg["kind"] == "sequential":
        start = rng.randint(0, space - 1)
        counter = {"v": start}

        def _seq() -> int:
            val = counter["v"] % space
            counter["v"] += 1
            return val
        return _seq
    raise ValueError(f"unknown behavior kind: {cfg['kind']}")


# --------------------------------------------------------------------------- #
# 3. One run: steady-state benign traffic at a target samples/window.          #
# --------------------------------------------------------------------------- #
@dataclass
class RunResult:
    level: int
    behavior: str
    run_idx: int
    seed: int
    decisions: int
    # blocks per variant (numerator of FPR); decisions is the shared denominator
    blocks: Dict[str, int]
    fpr: Dict[str, float]
    entropy_mean: float
    entropy_p95: float
    samples_mean: float
    unique_ratio_mean: float
    offered_fragments_per_second: float
    measurement_seconds: float
    actual_queries_per_second: float
    actual_fragments_per_second: float
    raw_decisions_file: str
    raw_decisions_sha256: str


def simulate_run(level: int, behavior: str, run_idx: int, seed: int,
                 n_decisions: int, phase: str, raw_path: Path,
                 raw_relative_path: str) -> RunResult:
    """Simulate one independent run of benign-only traffic.

    Arrivals follow a Poisson process with rate lambda = (level - 1) / WINDOW.
    Because scoring includes the current arrival, expected decision-time occupancy
    is lambda * WINDOW + 1 = ``level``. Each
    arrival is (a) a benign FRAG2 observed by the detector and (b) a scoring
    decision. This is a registered occupancy-stress model; Docker auth_server.py
    instead emits the paired FRAG2 asynchronously after FRAG1.
    The window is pruned with resolver.py's rule (cutoff = t - WINDOW) and scored
    with the real shannon_entropy + r2_should_block.
    """
    rng = random.Random(seed)
    next_ipid = make_ipid_sampler(behavior, rng)
    # Decisions are taken immediately after the current FRAG2 is inserted.  Under
    # Palm conditioning the expected occupancy at a decision is lambda*W + 1, so
    # lambda=(target-1)/W makes ``level`` the actual target samples/decision-window.
    lam = (level - 1) / WINDOW_SECONDS    # offered arrivals per second
    warmup_until = WARMUP_MULT * WINDOW_SECONDS

    window: List[Tuple[float, int]] = []  # (timestamp, ipid), mirrors the deque
    t = 0.0
    blocks = {v: 0 for v in VARIANTS}
    decisions = 0
    entropies: List[float] = []
    samples_seen: List[int] = []
    unique_ratios: List[float] = []
    raw_path.parent.mkdir(parents=True, exist_ok=True)

    # Cap total arrivals so a pathological rate can't loop forever.
    max_arrivals = int(warmup_until * lam) + n_decisions * 3 + 1000
    with raw_path.open("x", encoding="utf-8", newline="\n") as raw_handle:
        for _ in range(max_arrivals):
            if decisions >= n_decisions:
                break
            # Poisson process -> exponential inter-arrival gaps.
            gap = rng.expovariate(lam) if lam > 0 else 1.0
            t += gap
            current_ipid = next_ipid()
            window.append((t, current_ipid))
            # resolver.py R2EntropyTable._prune: drop events older than the window.
            cutoff = t - WINDOW_SECONDS
            while window and window[0][0] < cutoff:
                window.pop(0)

            if t < warmup_until:
                continue  # ramp-up: window not yet representative of steady state

            ipids = [ipid for _, ipid in window]
            total = len(ipids)
            unique = len(set(ipids))
            entropy = R.shannon_entropy(ipids)             # REAL detector math
            unique_ratio = (unique / total) if total else 0.0

            decisions += 1
            entropies.append(entropy)
            samples_seen.append(total)
            unique_ratios.append(unique_ratio)
            blocked: Dict[str, bool] = {}
            for variant in VARIANTS:
                blocked[variant] = bool(
                    R.r2_should_block(variant, True, total, entropy, unique_ratio)
                )
                if blocked[variant]:
                    blocks[variant] += 1                   # benign block == FP

            raw_handle.write(json.dumps({
                "schema_version": 1,
                "phase": phase,
                "level_samples_per_window": level,
                "behavior": behavior,
                "run_idx": run_idx,
                "seed": seed,
                "decision_idx": decisions,
                "virtual_timestamp_seconds": t,
                "measurement_elapsed_seconds": t - warmup_until,
                "current_ipid": current_ipid,
                "samples": total,
                "unique_ipids": unique,
                "entropy": entropy,
                "unique_ratio": unique_ratio,
                **{f"block_{variant}": blocked[variant] for variant in VARIANTS},
            }, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")

    if decisions != n_decisions:
        raise RuntimeError(
            f"incomplete run level={level} behavior={behavior} run={run_idx}: "
            f"{decisions}/{n_decisions} decisions"
        )

    measurement_seconds = max(0.0, t - warmup_until)
    actual_rate = (decisions / measurement_seconds) if measurement_seconds else 0.0
    fpr = {v: (blocks[v] / decisions if decisions else 0.0) for v in VARIANTS}
    return RunResult(
        level=level, behavior=behavior, run_idx=run_idx, seed=seed,
        decisions=decisions, blocks=blocks, fpr=fpr,
        entropy_mean=float(np.mean(entropies)) if entropies else 0.0,
        entropy_p95=float(np.percentile(entropies, 95)) if entropies else 0.0,
        samples_mean=float(np.mean(samples_seen)) if samples_seen else 0.0,
        unique_ratio_mean=float(np.mean(unique_ratios)) if unique_ratios else 0.0,
        offered_fragments_per_second=lam,
        measurement_seconds=measurement_seconds,
        actual_queries_per_second=actual_rate,
        actual_fragments_per_second=actual_rate,
        raw_decisions_file=raw_relative_path,
        raw_decisions_sha256=sha256_file(raw_path),
    )


# --------------------------------------------------------------------------- #
# 4. Statistics: exact-binomial (Clopper-Pearson) + run-level cluster bootstrap.
# --------------------------------------------------------------------------- #
def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Exact binomial (Clopper-Pearson) 95% CI. Handles k=0 and k=n cleanly.

    This is the interval the outline demands for FPR=0: 0/n is reported as
    [0, upper] -- never as 'FPR is exactly 0'.
    """
    if n == 0:
        return (0.0, 1.0)
    lower = 0.0 if k == 0 else stats.beta.ppf(alpha / 2, k, n - k + 1)
    upper = 1.0 if k == n else stats.beta.ppf(1 - alpha / 2, k + 1, n - k)
    return (float(lower), float(upper))


def cluster_bootstrap_fpr(per_run_blocks: List[int], per_run_dec: List[int],
                          n_boot: int = 5000, seed: int = 12345
                          ) -> Tuple[float, float, float]:
    """Hierarchical/cluster bootstrap over RUNS (the independent unit).

    Windows inside a run are dependent, so we resample whole runs with
    replacement and recompute the pooled FPR. Returns (point, lo95, hi95).
    """
    blocks = np.asarray(per_run_blocks, dtype=float)
    dec = np.asarray(per_run_dec, dtype=float)
    point = blocks.sum() / dec.sum() if dec.sum() else 0.0
    if len(blocks) == 0 or dec.sum() == 0:
        return (point, 0.0, 0.0)
    rng = np.random.default_rng(seed)
    n = len(blocks)
    stats_boot = np.empty(n_boot)
    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        d = dec[idx].sum()
        stats_boot[b] = blocks[idx].sum() / d if d else 0.0
    lo, hi = np.percentile(stats_boot, [2.5, 97.5])
    return (float(point), float(lo), float(hi))


def mean_ci_t(values: List[float]) -> Tuple[float, float, float]:
    """Mean and 95% t-interval across runs (run-level independence)."""
    arr = np.asarray(values, dtype=float)
    n = len(arr)
    m = float(arr.mean()) if n else 0.0
    if n < 2:
        return (m, m, m)
    se = float(arr.std(ddof=1) / math.sqrt(n))
    h = stats.t.ppf(0.975, n - 1) * se
    return (m, m - h, m + h)


# --------------------------------------------------------------------------- #
# 5. Orchestration.                                                            #
# --------------------------------------------------------------------------- #
def git_commit(path: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def git_provenance(path: Path) -> dict:
    """Return an auditable Git snapshot without requiring a commit."""
    def _git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(path), *args], capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"

    return {
        "commit_full": _git("rev-parse", "HEAD"),
        "commit_short": _git("rev-parse", "--short", "HEAD"),
        "branch": _git("branch", "--show-current"),
        "dirty": bool(_git("status", "--porcelain") not in ("", "unknown")),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dependency_versions() -> dict:
    versions = {}
    for package in ("numpy", "scipy", "matplotlib"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "not-installed"
    return versions


def hardware_info() -> dict:
    info = {
        "processor": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unknown"),
        "logical_cpus": os.cpu_count(),
    }
    try:
        import psutil  # type: ignore
        info["memory_bytes"] = int(psutil.virtual_memory().total)
    except Exception:
        info["memory_bytes"] = None
    return info


def snapshot_sources(out_dir: Path) -> dict:
    """Copy exact source inputs into the artifact so a dirty tree is still pinned."""
    candidates = {
        "e1_experiment.py": Path(__file__).resolve(),
        "e1_plot.py": HERE / "e1_plot.py",
        "e1_validate.py": HERE / "e1_validate.py",
        "e1_report.py": HERE / "e1_report.py",
        "resolver.py": RESOLVER_DIR / "resolver.py",
        "auth_server.py": LAB_DIR / "auth" / "auth_server.py",
    }
    snapshot_dir = out_dir / "source_snapshot"
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    manifest = {}
    for name, source in candidates.items():
        if not source.exists():
            continue
        destination = snapshot_dir / name
        shutil.copy2(source, destination)
        manifest[name] = {
            "source": str(source),
            "snapshot": str(destination),
            "sha256": sha256_file(destination),
        }
    return manifest


def cell_seed(level: int, behavior: str, run_idx: int, experiment_seed: int) -> int:
    """Deterministic per-cell seed so results are independent of run order."""
    beh_idx = list(IPID_BEHAVIORS).index(behavior)
    return experiment_seed + level * 100003 + beh_idx * 10007 + run_idx


def raw_decision_relpath(phase: str, level: int, behavior: str,
                         run_idx: int, seed: int) -> Path:
    """Portable artifact-relative path for one run's event-level JSONL."""
    return (Path("raw_decisions") / phase / behavior / f"level_{level}" /
            f"run_{run_idx:02d}_seed_{seed}.jsonl")


def write_runs_csv(path: Path, runs: List[RunResult]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["level_samples_per_window", "behavior", "run_idx", "seed",
                    "decisions", "offered_fragments_per_second", "measurement_seconds",
                    "actual_queries_per_second", "actual_fragments_per_second",
                    "blocks_legacy", "blocks_combined", "blocks_volume",
                    "blocks_entropy", "blocks_unique",
                    "fpr_legacy", "fpr_combined", "fpr_volume", "fpr_entropy", "fpr_unique",
                    "entropy_mean", "entropy_p95", "samples_mean", "unique_ratio_mean",
                    "raw_decisions_file", "raw_decisions_sha256"])
        for x in sorted(runs, key=lambda z: (z.level, z.behavior, z.run_idx)):
            w.writerow([x.level, x.behavior, x.run_idx, x.seed, x.decisions,
                        f"{x.offered_fragments_per_second:.6f}",
                        f"{x.measurement_seconds:.6f}",
                        f"{x.actual_queries_per_second:.6f}",
                        f"{x.actual_fragments_per_second:.6f}",
                        x.blocks["legacy"], x.blocks["combined"], x.blocks["volume"],
                        x.blocks["entropy"], x.blocks["unique"],
                        f"{x.fpr['legacy']:.6f}", f"{x.fpr['combined']:.6f}",
                        f"{x.fpr['volume']:.6f}", f"{x.fpr['entropy']:.6f}",
                        f"{x.fpr['unique']:.6f}", f"{x.entropy_mean:.4f}",
                        f"{x.entropy_p95:.4f}", f"{x.samples_mean:.3f}",
                        f"{x.unique_ratio_mean:.4f}", x.raw_decisions_file,
                        x.raw_decisions_sha256])


def main() -> None:
    ap = argparse.ArgumentParser(description="E1 -- FPR vs benign fragment rate")
    ap.add_argument("--runs", type=int, default=20, help="K independent runs / cell")
    ap.add_argument("--decisions", type=int, default=300, help="decision events / run")
    ap.add_argument("--out", type=str, default=str(HERE), help="output directory")
    ap.add_argument("--experiment-seed", type=int, default=DEFAULT_EXPERIMENT_SEED,
                    help="pre-registered seed for run order and independent run seeds")
    ap.add_argument("--run-id", type=str, default=None,
                    help="stable campaign ID (default: current timestamp)")
    ap.add_argument("--skip-high-load", action="store_true",
                    help="skip the explicitly exploratory high-load extension")
    args = ap.parse_args()

    if args.runs < 2:
        ap.error("--runs must be >= 2 for run-level uncertainty")
    if args.decisions < 1:
        ap.error("--decisions must be >= 1")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    protected_outputs = ["e1_protocol.json", "e1_runs.csv", "e1_levels.csv",
                         "e1_results.json", "notes.txt", "raw_decisions"]
    if any((out_dir / name).exists() for name in protected_outputs):
        raise FileExistsError(f"refusing to overwrite an existing E1 artifact: {out_dir}")

    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    source_manifest = snapshot_sources(out_dir)
    repo = HERE.parents[3]
    provenance = git_provenance(repo)
    protocol = {
        "schema_version": 3,
        "status": "registered-before-data-collection",
        "experiment": "E1 -- FPR vs benign fragment rate",
        "run_id": run_id,
        "registered_utc": started_utc,
        "scope": "controlled-emulation / synthetic benign proxy",
        "runs_per_cell": args.runs,
        "decisions_per_run": args.decisions,
        "experiment_seed": args.experiment_seed,
        "main_levels_samples_per_window": SAMPLES_PER_WINDOW_LEVELS,
        "high_load_levels_exploratory": [] if args.skip_high_load else HIGH_LOAD_LEVELS,
        "behaviors": IPID_BEHAVIORS,
        "operating_point": {
            "min_samples": MIN_SAMPLES,
            "entropy_threshold": ENTROPY_THRESHOLD,
            "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
            "window_seconds": WINDOW_SECONDS,
        },
        "randomization": "seeded shuffle of all main cells and separate seeded shuffle of exploratory high-load cells",
        "independent_unit": "run",
        "primary_ci": "cluster bootstrap over runs; run-level t interval shown as sensitivity",
        "zero_event_rule": (
            "report 0 observed; exact binomial interval applies to independent run-any-FP "
            "probability, not dependent decision windows"
        ),
        "load_definition": (
            "lambda=(target_samples_per_window-1)/window because scoring includes the current FRAG2"
        ),
        "event_level_raw": {
            "retained": True,
            "layout": "one JSONL file per independent run under raw_decisions/{phase}/{behavior}/level_{level}/",
            "schema_version": 1,
            "unit": "one scored post-warmup decision",
            "fields": [
                "phase", "level_samples_per_window", "behavior", "run_idx", "seed",
                "decision_idx", "virtual_timestamp_seconds",
                "measurement_elapsed_seconds", "current_ipid", "samples",
                "unique_ipids", "entropy", "unique_ratio",
                *[f"block_{variant}" for variant in VARIANTS],
            ],
            "raw_scope": (
                "one record for every scored decision after warmup; overlapping window "
                "contents are represented by samples/unique/entropy, not duplicated IPID arrays"
            ),
            "full_window_ipids_retained": False,
            "warmup_arrival_trace_retained": False,
            "expected_main_records": (
                len(SAMPLES_PER_WINDOW_LEVELS) * len(IPID_BEHAVIORS)
                * args.runs * args.decisions
            ),
            "expected_high_load_records": (
                0 if args.skip_high_load else len(HIGH_LOAD_LEVELS) * args.runs
                * args.decisions
            ),
        },
        "command": [sys.executable, *sys.argv],
        "working_directory": str(Path.cwd()),
        "git": provenance,
        "source_manifest": source_manifest,
        "dependencies": dependency_versions(),
        "hardware": hardware_info(),
    }
    with (out_dir / "e1_protocol.json").open("w", encoding="utf-8") as f:
        json.dump(protocol, f, indent=2)

    print("=" * 78)
    print("E1 -- FPR theo tốc độ fragment hợp lệ (operating boundary của Rℓ₂)")
    print("Ý nghĩa: chạy detector trên lưu lượng CHỈ hợp lệ (no attacker). Mọi lần")
    print("'tc_block' là một false positive. Ta quét samples/window và đo FPR để tìm")
    print("vùng an toàn và điểm detector bắt đầu chặn nhầm người dùng thật.")
    print(f"Operating point B5: samples>={MIN_SAMPLES}, entropy>={ENTROPY_THRESHOLD}, "
          f"unique_ratio>={UNIQUE_RATIO_THRESHOLD}; window={WINDOW_SECONDS}s")
    print(f"K={args.runs} runs/cell, {args.decisions} decisions/run, "
          f"levels={SAMPLES_PER_WINDOW_LEVELS}, behaviors={list(IPID_BEHAVIORS)}")
    print("=" * 78)

    # Build all cells, then randomize execution order (E1: randomize load order).
    cells = [(lvl, beh, r)
             for lvl in SAMPLES_PER_WINDOW_LEVELS
             for beh in IPID_BEHAVIORS
             for r in range(args.runs)]
    order_rng = random.Random(args.experiment_seed)
    order_rng.shuffle(cells)

    runs: List[RunResult] = []
    t0 = time.time()
    for i, (lvl, beh, r) in enumerate(cells, 1):
        seed = cell_seed(lvl, beh, r, args.experiment_seed)
        raw_rel = raw_decision_relpath("main", lvl, beh, r, seed)
        runs.append(simulate_run(
            lvl, beh, r, seed, args.decisions, "main", out_dir / raw_rel,
            raw_rel.as_posix()
        ))
        if i % 60 == 0 or i == len(cells):
            print(f"  [{i}/{len(cells)}] cells done ({time.time() - t0:.1f}s)")

    # ---- Per-run CSV (raw, with numerator/denominator per E1/P0) ---------- #
    runs_csv = out_dir / "e1_runs.csv"
    write_runs_csv(runs_csv, runs)
    print(f"[+] wrote {runs_csv}")

    # ---- Aggregate per (level, behavior) --------------------------------- #
    levels_rows = []
    results = {
        "meta": {
            "experiment": "E1 -- FPR vs benign fragment rate (operating boundary)",
            "run_id": run_id,
            "started_utc": started_utc,
            "code_git_commit": provenance["commit_short"],
            "git": provenance,
            "source_manifest": source_manifest,
            "command": protocol["command"],
            "dependencies": protocol["dependencies"],
            "hardware": protocol["hardware"],
            "python": platform.python_version(),
            "platform": platform.platform(),
            "detector_source": str((RESOLVER_DIR / "resolver.py").as_posix()),
            "fidelity_note": ("Imports the real shannon_entropy + r2_should_block from "
                              "resolver.py; sliding window mirrors R2EntropyTable._prune; "
                              "IPID model from auth_server.py. Controlled-emulation testbed "
                              "(no Docker / real IP fragmentation)."),
            "operating_point": {
                "min_samples": MIN_SAMPLES,
                "entropy_threshold": ENTROPY_THRESHOLD,
                "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
                "window_seconds": WINDOW_SECONDS,
            },
            "detectors": {
                "legacy": "Rℓ2 gốc (paper POPS, Algorithm 3): chặn mọi fragment",
                "combined": "Rℓ2 cải tiến của nhóm: samples>=24 AND entropy>=4.0 AND unique_ratio>=0.70",
            },
            "levels_samples_per_window": SAMPLES_PER_WINDOW_LEVELS,
            "behaviors": {k: v["label"] for k, v in IPID_BEHAVIORS.items()},
            "variants": VARIANTS,
            "primary_variant": PRIMARY_VARIANT,
            "runs_per_cell": args.runs,
            "decisions_per_run": args.decisions,
            "experiment_seed": args.experiment_seed,
            "fpr_definition": "false positives = benign tc_block; FPR = blocks / decisions",
            "independent_unit": "run",
            "primary_ci": "cluster bootstrap over runs",
            "system_metrics_scope": (
                "Detector latency/throughput/CPU/memory are not estimable from this virtual-time "
                "simulation; Docker low-load fidelity is reported separately."
            ),
            "event_level_raw": protocol["event_level_raw"],
        },
        "levels": [],
    }

    for beh in IPID_BEHAVIORS:
        for lvl in SAMPLES_PER_WINDOW_LEVELS:
            cell_runs = [x for x in runs if x.level == lvl and x.behavior == beh]
            dec = [x.decisions for x in cell_runs]
            total_dec = int(sum(dec))
            entry: Dict[str, object] = {
                "behavior": beh, "level": lvl,
                "n_runs": len(cell_runs), "total_decisions": total_dec,
                "samples_mean": float(np.mean([x.samples_mean for x in cell_runs])),
                "offered_fragments_per_second": float(np.mean(
                    [x.offered_fragments_per_second for x in cell_runs]
                )),
                "variants": {},
            }
            sam_m, sam_lo, sam_hi = mean_ci_t([x.samples_mean for x in cell_runs])
            rate_m, rate_lo, rate_hi = mean_ci_t(
                [x.actual_fragments_per_second for x in cell_runs]
            )
            entry["samples_ci95"] = [sam_lo, sam_hi]
            entry["actual_queries_per_second_mean"] = rate_m
            entry["actual_queries_per_second_ci95"] = [rate_lo, rate_hi]
            entry["actual_fragments_per_second_mean"] = rate_m
            entry["actual_fragments_per_second_ci95"] = [rate_lo, rate_hi]
            ent_m, ent_lo, ent_hi = mean_ci_t([x.entropy_mean for x in cell_runs])
            uni_m, uni_lo, uni_hi = mean_ci_t([x.unique_ratio_mean for x in cell_runs])
            entry["entropy_mean"] = ent_m
            entry["entropy_ci95"] = [ent_lo, ent_hi]
            entry["unique_ratio_mean"] = uni_m
            entry["unique_ratio_ci95"] = [uni_lo, uni_hi]

            for variant in VARIANTS:
                blk = [x.blocks[variant] for x in cell_runs]
                total_blk = int(sum(blk))
                # Run-level mean FPR + t-interval (primary; respects independence)
                run_fprs = [x.fpr[variant] for x in cell_runs]
                m, lo, hi = mean_ci_t(run_fprs)
                # Cluster bootstrap over runs (pooled point + CI)
                bp, blo, bhi = cluster_bootstrap_fpr(blk, dec)
                # Exact binomial on pooled counts (for the FPR=0 upper-bound claim)
                cp_lo, cp_hi = clopper_pearson(total_blk, total_dec)
                runs_with_any_fp = int(sum(b > 0 for b in blk))
                run_cp_lo, run_cp_hi = clopper_pearson(runs_with_any_fp, len(blk))
                entry["variants"][variant] = {
                    "blocks_total": total_blk,
                    "decisions_total": total_dec,
                    "fpr_pooled": (total_blk / total_dec) if total_dec else 0.0,
                    "fpr_run_mean": m,
                    "fpr_run_ci95_t": [lo, hi],
                    "fpr_cluster_bootstrap_ci95": [blo, bhi],
                    "event_level_clopper_pearson_ci95_descriptive": [cp_lo, cp_hi],
                    "event_level_cp_warning": (
                        "decision windows overlap; this interval assumes iid events and is not inferential"
                    ),
                    "runs_with_any_fp": runs_with_any_fp,
                    "run_any_fp_probability": runs_with_any_fp / len(blk) if blk else 0.0,
                    "run_any_fp_clopper_pearson_ci95": [run_cp_lo, run_cp_hi],
                }
                levels_rows.append([
                    beh, lvl, entry["samples_mean"], rate_m, variant, len(cell_runs),
                    total_blk, total_dec, runs_with_any_fp,
                    f"{(total_blk / total_dec) if total_dec else 0.0:.6f}",
                    f"{m:.6f}", f"{lo:.6f}", f"{hi:.6f}",
                    f"{blo:.6f}", f"{bhi:.6f}",
                    f"{run_cp_lo:.6f}", f"{run_cp_hi:.6f}",
                ])
            results["levels"].append(entry)

    levels_csv = out_dir / "e1_levels.csv"
    with open(levels_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["behavior", "level_samples_per_window", "actual_samples_mean",
                    "actual_fragments_per_second_mean", "variant", "n_runs",
                    "blocks_total", "decisions_total", "runs_with_any_fp", "fpr_pooled",
                    "fpr_run_mean", "fpr_run_ci_lo", "fpr_run_ci_hi",
                    "fpr_cluster_ci_lo", "fpr_cluster_ci_hi",
                    "run_any_fp_cp_ci_lo", "run_any_fp_cp_ci_hi"])
        w.writerows(levels_rows)
    print(f"[+] wrote {levels_csv}")

    # ---- High-load extension: locate the upper edge of the blocking band ---- #
    print("\n[high-load] FPR ngoài lưới chuẩn (kiểm tra vùng mù ở tải rất cao):")
    results["high_load"] = []
    high_load_runs: List[RunResult] = []
    if not args.skip_high_load:
        high_load_cells = [(lvl, r) for lvl in HIGH_LOAD_LEVELS for r in range(args.runs)]
        random.Random(args.experiment_seed ^ 0xE1E1).shuffle(high_load_cells)
        for lvl, r in high_load_cells:
            seed = cell_seed(lvl, "random2048", r, args.experiment_seed)
            raw_rel = raw_decision_relpath("high_load", lvl, "random2048", r, seed)
            high_load_runs.append(simulate_run(
                lvl, "random2048", r, seed, args.decisions, "high_load",
                out_dir / raw_rel, raw_rel.as_posix()
            ))
    for lvl in ([] if args.skip_high_load else HIGH_LOAD_LEVELS):
        cell = [x for x in high_load_runs if x.level == lvl]
        row = {"level": lvl,
               "samples_mean": float(np.mean([x.samples_mean for x in cell])),
               "actual_fragments_per_second_mean": float(np.mean(
                   [x.actual_fragments_per_second for x in cell]
               )),
               "entropy_mean": float(np.mean([x.entropy_mean for x in cell])),
               "unique_ratio_mean": float(np.mean([x.unique_ratio_mean for x in cell]))}
        for v in VARIANTS:
            m, lo, hi = mean_ci_t([x.fpr[v] for x in cell])
            row[v] = {"fpr_run_mean": m, "ci95": [lo, hi]}
        results["high_load"].append(row)
        print(f"  s/win={lvl:>5}: FPR combined={row['combined']['fpr_run_mean']:.3f} "
              f"volume={row['volume']['fpr_run_mean']:.3f} "
              f"| entropy={row['entropy_mean']:.2f} uniq={row['unique_ratio_mean']:.3f}")

    if high_load_runs:
        high_load_csv = out_dir / "e1_high_load_runs.csv"
        write_runs_csv(high_load_csv, high_load_runs)
        print(f"[+] wrote {high_load_csv}")

    results["meta"]["completed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    results["meta"]["elapsed_seconds"] = time.time() - t0

    results_json = out_dir / "e1_results.json"
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] wrote {results_json}")

    # ---- Console summary: the failure boundary (primary variant) ---------- #
    print("\n" + "=" * 78)
    print("KẾT QUẢ E1 -- FPR của detector B5 (combined) trên benign, theo samples/window")
    print("Nhắc lại: đây là báo động NHẦM. FPR càng cao = càng chặn nhầm người dùng thật.")
    print("=" * 78)
    for beh in IPID_BEHAVIORS:
        print(f"\n[{beh}] {IPID_BEHAVIORS[beh]['label']}")
        print(f"  {'s/win':>6} {'FPR(run-mean)':>14} {'95% CI':>20} "
              f"{'entropy':>9} {'uniq':>6}")
        for entry in results["levels"]:
            if entry["behavior"] != beh:
                continue
            cv = entry["variants"][PRIMARY_VARIANT]
            lo, hi = cv["fpr_cluster_bootstrap_ci95"]
            ci = f"[{lo:.3f}, {hi:.3f}]"
            print(f"  {entry['level']:>6} {cv['fpr_run_mean']:>14.3f} {ci:>20} "
                  f"{entry['entropy_mean']:>9.3f} {entry['unique_ratio_mean']:>6.3f}")

        # failure boundary = first level whose FPR run-CI lower bound > 0
        boundary = None
        for entry in results["levels"]:
            if entry["behavior"] != beh:
                continue
            lo, _ = entry["variants"][PRIMARY_VARIANT]["fpr_cluster_bootstrap_ci95"]
            if lo > 0:
                boundary = entry["level"]
                break
        if boundary is not None:
            print(f"  -> failure boundary (FPR CI lower bound > 0) tại "
                  f"samples/window = {boundary}")
        else:
            print("  -> không quan sát false positive ở mọi mức đã thử; không suy diễn FPR thật bằng 0.")

    print("\n[✓] E1 hoàn tất. Xem e1_levels.csv / e1_results.json và figures/.")
    _write_notes(out_dir, results, args)


def _write_notes(out_dir: Path, results: dict, args) -> None:
    lines = []
    lines.append("E1 -- FPR theo tốc độ fragment hợp lệ (operating boundary của Rℓ₂)")
    lines.append("=" * 70)
    lines.append("")
    lines.append("MỤC TIÊU (outline E1): xác định operating boundary của detector trên")
    lines.append("benign traffic và đo FPR ở/ngoài vùng samples < MIN_SAMPLES.")
    lines.append("")
    lines.append("THIẾT LẬP:")
    m = results["meta"]
    lines.append(f"  - detector: {m['detector_source']} (import trực tiếp, không cài lại)")
    lines.append(f"  - operating point B5: {m['operating_point']}")
    lines.append(f"  - levels samples/window: {m['levels_samples_per_window']}")
    lines.append(f"  - behaviors: {list(m['behaviors'])}")
    lines.append(f"  - K = {m['runs_per_cell']} runs/cell, {m['decisions_per_run']} decisions/run")
    lines.append(f"  - FPR = {m['fpr_definition']}")
    lines.append("")
    lines.append("KẾT QUẢ CHÍNH (variant combined = B5):")
    for beh in results["meta"]["behaviors"]:
        lines.append(f"  [{beh}]")
        for entry in results["levels"]:
            if entry["behavior"] != beh:
                continue
            cv = entry["variants"]["combined"]
            lo, hi = cv["fpr_cluster_bootstrap_ci95"]
            lines.append(f"    s/win={entry['level']:>3}: FPR={cv['fpr_run_mean']:.3f} "
                         f"cluster-CI=[{lo:.3f},{hi:.3f}] "
                         f"actual={entry['samples_mean']:.2f} samples/window, "
                         f"{entry['actual_fragments_per_second_mean']:.2f} frag/s "
                         f"entropy={entry['entropy_mean']:.3f} "
                         f"uniq={entry['unique_ratio_mean']:.3f}")
    lines.append("")
    lines.append("DIỄN GIẢI: xem E1_report.md.")
    (out_dir / "notes.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] wrote {out_dir / 'notes.txt'}")


if __name__ == "__main__":
    main()
