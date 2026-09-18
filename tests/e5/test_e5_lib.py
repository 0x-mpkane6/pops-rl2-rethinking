from __future__ import annotations

import sys
from pathlib import Path

import pytest

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT))

from e5_lib import (  # noqa: E402
    CONFIRMATORY_POLICIES,
    Policy,
    build_trial_qname,
    classify_outcome,
    entropy_implied_min_samples,
    make_complete_block,
    policy_decision,
    ratio_meets_threshold,
    raw_shannon_entropy,
)


def test_raw_shannon_entropy_is_not_normalized() -> None:
    assert raw_shannon_entropy([]) == 0.0
    assert raw_shannon_entropy([0, 1, 2, 3]) == pytest.approx(2.0)
    assert raw_shannon_entropy(list(range(64))) == pytest.approx(6.0)
    assert raw_shannon_entropy([7] * 64) == pytest.approx(0.0)


def test_entropy_threshold_implies_sample_lower_bound() -> None:
    assert entropy_implied_min_samples(6.0) == 64
    assert entropy_implied_min_samples(4.0) == 16
    assert entropy_implied_min_samples(0.0) == 1
    with pytest.raises(ValueError):
        entropy_implied_min_samples(-0.1)


def test_ratio_threshold_uses_registered_decimal_boundary() -> None:
    assert ratio_meets_threshold(9, 10, 0.90)
    assert not ratio_meets_threshold(899, 1000, 0.90)
    assert not ratio_meets_threshold(0, 0, 0.90)


def test_trial_qnames_are_unique_and_dns_safe() -> None:
    names = {
        build_trial_qname("E5-routed-s20260902-r001", rep=2, trial=17, nonce=i)
        for i in range(20)
    }
    assert len(names) == 20
    assert all(name.endswith(".bank.com.") for name in names)
    assert all(name.startswith("r02-t017-") for name in names)
    assert all(len(name.rstrip(".")) <= 253 for name in names)


def test_complete_block_contains_each_policy_workload_once() -> None:
    first = make_complete_block(rep=1, seed=20260902)
    second = make_complete_block(rep=1, seed=20260902)
    assert first == second
    assert len(first) == 16
    assert len({(row.policy, row.workload) for row in first}) == 16
    assert {row.policy for row in first} == {item.value for item in CONFIRMATORY_POLICIES}


def test_policy_decisions_isolate_detector_and_enforcement() -> None:
    assert policy_decision(Policy.B0_OFF, is_dns_fragment=True, offset=0, b5_active=False).verdict == "forward"
    assert policy_decision(Policy.B1_RL2_TC, is_dns_fragment=True, offset=0, b5_active=False).verdict == "inject_tc_drop"
    assert policy_decision(Policy.B1_RL2_TC, is_dns_fragment=True, offset=40, b5_active=False).verdict == "drop_tail"
    assert policy_decision(Policy.B5_LOCKED_TC, is_dns_fragment=True, offset=0, b5_active=False).verdict == "forward"
    assert policy_decision(Policy.B5_LOCKED_TC, is_dns_fragment=True, offset=0, b5_active=True).verdict == "inject_tc_drop"
    assert policy_decision(Policy.B5_LOCKED_TC, is_dns_fragment=True, offset=40, b5_active=True).verdict == "drop_tail"
    assert policy_decision(Policy.RFC_DROP_NATIVE, is_dns_fragment=True, offset=0, b5_active=False).verdict == "drop_fragment"
    assert policy_decision(Policy.RFC_DROP_NATIVE, is_dns_fragment=True, offset=40, b5_active=False).verdict == "drop_fragment"
    assert policy_decision(Policy.PREARM_TAIL_DROP, is_dns_fragment=True, offset=0, b5_active=False).verdict == "forward"
    assert policy_decision(Policy.PREARM_TAIL_DROP, is_dns_fragment=True, offset=40, b5_active=False).verdict == "drop_tail"
    assert policy_decision(Policy.B2_VOLUME_TC, is_dns_fragment=True, offset=0, b5_active=True, b2_active=False).verdict == "forward"
    assert policy_decision(Policy.B2_VOLUME_TC, is_dns_fragment=True, offset=0, b5_active=False, b2_active=True).verdict == "inject_tc_drop"
    assert policy_decision(Policy.B2_VOLUME_TC, is_dns_fragment=True, offset=40, b5_active=False, b2_active=True).verdict == "drop_tail"


def test_complete_block_defaults_exclude_b2_addon() -> None:
    assert Policy.B2_VOLUME_TC.value not in {item.value for item in CONFIRMATORY_POLICIES}


def test_non_dns_occupancy_is_observed_but_not_mitigated_by_dns_policy() -> None:
    for policy in Policy:
        result = policy_decision(policy, is_dns_fragment=False, offset=40, b5_active=True)
        assert result.verdict == "forward"


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"poisoned": True, "trigger_before": False, "drop_observed": False, "tcp_retry": False, "legitimate": False}, "detector_miss"),
        ({"poisoned": True, "trigger_before": True, "drop_observed": False, "tcp_retry": False, "legitimate": False}, "enforcement_miss"),
        ({"poisoned": True, "trigger_before": True, "drop_observed": True, "tcp_retry": False, "legitimate": False}, "transport_failure"),
        ({"poisoned": False, "trigger_before": False, "drop_observed": True, "tcp_retry": False, "legitimate": False, "attack": True}, "transport_failure"),
        ({"poisoned": False, "trigger_before": True, "drop_observed": True, "tcp_retry": True, "legitimate": True}, "mitigated"),
        ({"poisoned": False, "trigger_before": False, "drop_observed": False, "tcp_retry": False, "legitimate": False}, "availability_failure"),
    ],
)
def test_outcome_classification(kwargs: dict[str, bool], expected: str) -> None:
    assert classify_outcome(**kwargs) == expected
