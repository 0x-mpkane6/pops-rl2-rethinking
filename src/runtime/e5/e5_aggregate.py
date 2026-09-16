"""Run-level estimands and block-bootstrap helpers for E5."""

from __future__ import annotations

import math
import random
from statistics import fmean
from typing import Mapping


def exact_binomial_ci(successes: int, total: int, alpha: float = 0.05) -> tuple[float, float]:
    """Two-sided exact Clopper--Pearson interval for a binomial proportion."""

    if total < 0 or successes < 0 or successes > total:
        raise ValueError("successes and total must satisfy 0 <= successes <= total")
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between zero and one")
    if total == 0:
        return 0.0, 1.0
    try:
        from scipy.stats import beta  # type: ignore
    except ImportError as exc:  # pragma: no cover - CI includes scipy
        raise RuntimeError("SciPy is required for exact Clopper-Pearson intervals") from exc
    lower = 0.0 if successes == 0 else float(beta.ppf(alpha / 2.0, successes, total - successes + 1))
    upper = 1.0 if successes == total else float(beta.ppf(1.0 - alpha / 2.0, successes + 1, total - successes))
    return lower, upper


def _percentile(values: list[float], probability: float) -> float:
    if not values:
        raise ValueError("at least one bootstrap value is required")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    fraction = position - low
    return ordered[low] + (ordered[high] - ordered[low]) * fraction


def paired_bootstrap_mean(
    differences_by_block: Mapping[int, float],
    *,
    replicates: int = 5000,
    seed: int = 20260902,
) -> dict[str, float | int]:
    """Bootstrap complete blocks, never individual trials or observations."""

    if replicates <= 0:
        raise ValueError("replicates must be positive")
    values = [float(value) for _, value in sorted(differences_by_block.items())]
    if not values:
        raise ValueError("at least one block is required")
    estimate = fmean(values)
    rng = random.Random(seed)
    boot = [fmean(rng.choice(values) for _ in values) for _ in range(replicates)]
    return {
        "estimate": estimate,
        "ci_low": _percentile(boot, 0.025),
        "ci_high": _percentile(boot, 0.975),
        "replicates": replicates,
        "blocks": len(values),
    }


def paired_differences(
    rows: list[dict],
    *,
    target_policy: str,
    baseline_policy: str,
    workload: str,
    metric: str,
) -> dict[int, float]:
    """Collect target-minus-baseline run metrics paired by rep and workload."""

    target = {int(row["rep"]): row for row in rows if row.get("policy") == target_policy and row.get("workload") == workload}
    baseline = {int(row["rep"]): row for row in rows if row.get("policy") == baseline_policy and row.get("workload") == workload}
    reps = set(target) & set(baseline)
    return {rep: float(target[rep][metric]) - float(baseline[rep][metric]) for rep in reps}


def paired_factorial_differences(
    rows: list[dict],
    *,
    policy: str,
    first_workload: str,
    second_workload: str,
    metric: str,
) -> dict[int, float]:
    """Collect first-minus-second differences within each complete block."""

    first = {
        int(row["rep"]): row
        for row in rows
        if row.get("policy") == policy and row.get("workload") == first_workload
    }
    second = {
        int(row["rep"]): row
        for row in rows
        if row.get("policy") == policy and row.get("workload") == second_workload
    }
    reps = set(first) & set(second)
    return {rep: float(first[rep][metric]) - float(second[rep][metric]) for rep in reps}
