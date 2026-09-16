"""Pure decision and schedule primitives for the E5 routed campaign."""

from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from typing import Sequence


class Policy(str, Enum):
    """Resolver/IPS policies used by E5."""

    B0_OFF = "B0_OFF"
    B1_RL2_TC = "B1_RL2_TC"
    B2_VOLUME_TC = "B2_VOLUME_TC"
    B5_LOCKED_TC = "B5_LOCKED_TC"
    RFC_DROP_NATIVE = "RFC_DROP_NATIVE"
    PREARM_TAIL_DROP = "PREARM_TAIL_DROP"


CONFIRMATORY_POLICIES = (
    Policy.B0_OFF,
    Policy.B1_RL2_TC,
    Policy.B5_LOCKED_TC,
    Policy.RFC_DROP_NATIVE,
)

WORKLOADS = (
    "BENIGN_LOW",
    "BENIGN_BOUNDARY",
    "ATTACK_FIXED_MATCHED",
    "ATTACK_SWEEP_FLOOD",
)


@dataclass(frozen=True)
class BlockCell:
    policy: str
    workload: str


@dataclass(frozen=True)
class PolicyDecision:
    verdict: str
    reason: str


def raw_shannon_entropy(values: Sequence[int]) -> float:
    """Return unnormalised Shannon entropy in bits."""

    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def ratio_meets_threshold(numerator: int, denominator: int, threshold: float) -> bool:
    """Compare a ratio using the decimal threshold registered by the protocol."""

    if denominator <= 0:
        return False
    fraction = Fraction(str(threshold))
    return numerator * fraction.denominator >= denominator * fraction.numerator


def entropy_implied_min_samples(entropy_threshold: float) -> int:
    """Return the smallest integer n for which log2(n) can reach the threshold."""

    threshold = float(entropy_threshold)
    if not math.isfinite(threshold) or threshold < 0:
        raise ValueError("entropy_threshold must be a finite non-negative number")
    return math.ceil(2**threshold)


def build_trial_qname(run_id: str, rep: int, trial: int, nonce: int) -> str:
    """Build a unique, deterministic qname for one cache-isolated trial."""

    if rep < 0 or trial < 0 or nonce < 0:
        raise ValueError("rep, trial, and nonce must be non-negative")
    safe_run = "".join(char.lower() if char.isalnum() else "-" for char in run_id).strip("-")
    if not safe_run:
        raise ValueError("run_id must contain at least one alphanumeric character")
    # Keep the wire-format name independent of the campaign identifier.  The
    # latter belongs in the event envelope; using it as a label makes the
    # qname parser and the registered protocol needlessly coupled to a run ID.
    label = f"r{rep:02d}-t{trial:03d}-{nonce:08x}"
    qname = f"{label}.bank.com."
    if len(qname.rstrip(".")) > 253:
        raise ValueError("generated qname exceeds the DNS name length limit")
    return qname


def make_complete_block(
    rep: int,
    seed: int,
    *,
    policies: Sequence[str] | None = None,
    workloads: Sequence[str] | None = None,
) -> list[BlockCell]:
    """Return one seeded randomized complete block.

    The optional lists make registered protocols authoritative while retaining
    the historical four-by-four defaults for the original campaign.
    """

    policy_values = [item.value for item in CONFIRMATORY_POLICIES] if policies is None else [str(item) for item in policies]
    workload_values = list(WORKLOADS) if workloads is None else [str(item) for item in workloads]
    cells = [
        BlockCell(policy=policy, workload=workload)
        for policy in policy_values
        for workload in workload_values
    ]
    random.Random(f"{seed}:{rep}").shuffle(cells)
    return cells


def policy_decision(
    policy: Policy,
    *,
    is_dns_fragment: bool,
    offset: int,
    b5_active: bool,
    b2_active: bool = False,
) -> PolicyDecision:
    """Map one packet observation to a policy-level forwarding action.

    ``offset == 0`` denotes the first fragment; a positive offset denotes a
    non-initial fragment. Non-DNS occupancy fragments are observed for scoring
    but are not subject to DNS mitigation actions.
    """

    if offset < 0:
        raise ValueError("fragment offset must be non-negative")
    if not is_dns_fragment:
        return PolicyDecision("forward", "non_dns_occupancy")
    first = offset == 0
    if policy is Policy.B0_OFF:
        return PolicyDecision("forward", "defense_off")
    if policy is Policy.B1_RL2_TC:
        return PolicyDecision("inject_tc_drop" if first else "drop_tail", "rl2_immediate")
    if policy is Policy.B2_VOLUME_TC:
        if not b2_active:
            return PolicyDecision("forward", "b2_inactive")
        return PolicyDecision("inject_tc_drop" if first else "drop_tail", "b2_active")
    if policy is Policy.B5_LOCKED_TC:
        if not b5_active:
            return PolicyDecision("forward", "b5_inactive")
        return PolicyDecision("inject_tc_drop" if first else "drop_tail", "b5_active")
    if policy is Policy.RFC_DROP_NATIVE:
        return PolicyDecision("drop_fragment", "static_fragment_drop")
    if policy is Policy.PREARM_TAIL_DROP:
        return PolicyDecision("forward" if first else "drop_tail", "prearmed_tail_drop")
    raise ValueError(f"unsupported policy: {policy}")


def classify_outcome(
    *,
    poisoned: bool,
    trigger_before: bool,
    drop_observed: bool,
    tcp_retry: bool,
    legitimate: bool,
    attack: bool = False,
) -> str:
    """Classify the causal outcome of one trial."""

    if poisoned and not trigger_before:
        return "detector_miss"
    if poisoned and trigger_before and not drop_observed:
        return "enforcement_miss"
    if poisoned and trigger_before and drop_observed:
        return "transport_failure"
    if legitimate and drop_observed and tcp_retry:
        return "mitigated"
    if attack and drop_observed and not legitimate:
        return "transport_failure"
    if not legitimate:
        return "availability_failure"
    return "allowed"
