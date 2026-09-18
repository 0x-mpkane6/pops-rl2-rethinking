from __future__ import annotations

import json
import sys
from pathlib import Path

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT))

from e5_validate import pmtud_kernel_fragment_gate, pilot_gate, validate_cache_probe, validate_replay_coverage, validate_trial_records  # noqa: E402


def trial(qname: str, cache_hit: bool = False) -> dict:
    return {
        "event": "trial",
        "run_id": "E5-routed-s20260902-r001",
        "rep": 1,
        "policy": "B0_OFF",
        "workload": "BENIGN_LOW",
        "trial_id": "r01-t000-abcdef01",
        "qname": qname,
        "trial": 0,
        "cache_before": {"cache_hit": cache_hit},
        "cache_after": {"cache_hit": False, "answers": []},
        "status": "no_answer",
        "query_start_mono_ns": 100,
        "client_answer_end_mono_ns": 200,
    }


def test_trial_validator_accepts_unique_cache_miss() -> None:
    result = validate_trial_records([trial("r01-t000-abcdef01.bank.com.")], expected_trials=1)
    assert result["status"] == "PASS"


def test_trial_validator_rejects_cache_hit_before_trial() -> None:
    result = validate_trial_records([trial("r01-t000-abcdef01.bank.com.", cache_hit=True)], expected_trials=1)
    assert result["status"] == "FAIL"
    assert any("cache-before" in error for error in result["errors"])


def test_cache_probe_validator_distinguishes_error_from_miss() -> None:
    assert validate_cache_probe({"probe_status": "miss", "probe_valid": True, "cache_hit": False, "answers": []})["status"] == "PASS"
    assert validate_cache_probe({"probe_status": "error", "probe_valid": False, "cache_hit": None, "answers": []})["status"] == "PASS"
    assert validate_cache_probe({"probe_status": "error", "probe_valid": True, "cache_hit": None, "answers": []})["status"] == "FAIL"


def test_trial_validator_requires_probe_status_for_factorial_campaign() -> None:
    result = validate_trial_records(
        [trial("r01-t000-abcdef01.bank.com.")],
        expected_trials=1,
        require_probe_status=True,
    )
    assert result["status"] == "FAIL"
    assert any("missing probe status" in error for error in result["errors"])


def test_trial_validator_preserves_well_formed_probe_error_as_unknown() -> None:
    row = trial("r01-t000-abcdef01.bank.com.")
    row["cache_before"] = {
        "qname": row["qname"],
        "probe_status": "error",
        "probe_valid": False,
        "cache_hit": None,
        "answers": [],
    }
    row["cache_after"] = {
        "qname": row["qname"],
        "probe_status": "error",
        "probe_valid": False,
        "cache_hit": None,
        "answers": [],
    }
    result = validate_trial_records([row], expected_trials=1, require_probe_status=True)
    assert result["status"] == "PASS"


def test_replay_coverage_uses_predefragmentation_occupancy_observations() -> None:
    schedule = {
        "rate_pps": 10.0,
        "duration_s": 10.0,
        "replay_coverage_required": {"rate_tolerance": 0.10, "occupancy_observed_fraction": 0.99},
        "occupancy": [{}] * 10,
    }
    attacker = [
        {"event": "replay_started", "mono_ns": 100, "replay_started_mono_ns": 100, "scheduled_occupancy": 10},
        {"event": "replay_finished", "mono_ns": 1_000_000_100, "replay_finished_mono_ns": 1_000_000_100, "scheduled_occupancy": 10, "observed_occupancy": 10},
    ]
    ips = [
        {"event": "fragment_observed", "mono_ns": 1000 + i, "capture_source": "af_packet", "src": "10.82.0.200", "offset": 40}
        for i in range(10)
    ]
    result = validate_replay_coverage(attacker, schedule, ips_rows=ips, measurement_end_mono_ns=1_000_000_000)
    assert result["status"] == "PASS"
    assert result["observed_fraction"] == 1.0


def test_factorial_pilot_gate_requires_b0_attack_path_but_not_b5_detection() -> None:
    base = {
        "forged_tail_ingress_trials": 1,
        "malicious_answer_trials": 1,
        "trigger_trials": 0,
        "forged_tail_drop_trials": 0,
    }
    assert pilot_gate(base, policy="B0_OFF", workload="ATTACK_DIVERSE_MODERATE")["status"] == "PASS"
    assert pilot_gate(base, policy="B5_LOCKED_TC", workload="ATTACK_DIVERSE_MODERATE")["status"] == "PASS"
    assert pilot_gate({**base, "forged_tail_ingress_trials": 0}, policy="B0_OFF", workload="ATTACK_DIVERSE_MODERATE")["status"] == "FAIL"


def test_factorial_b1_pilot_gate_checks_tc_only_for_attack_cells() -> None:
    base = {"tc_injection_trials": 0, "tcp_retry_trials": 0, "legitimate_trials": 1}
    assert pilot_gate(base, policy="B1_RL2_TC", workload="BENIGN_DIVERSE_MODERATE")["status"] == "PASS"
    assert pilot_gate(base, policy="B1_RL2_TC", workload="ATTACK_DIVERSE_MODERATE")["status"] == "FAIL"


def test_b2_pilot_gate_requires_volume_activation_and_drop() -> None:
    base = {
        "volume_active_at_query_trials": 1,
        "forged_tail_drop_trials": 1,
        "legitimate_trials": 1,
    }
    assert pilot_gate(base, policy="B2_VOLUME_TC", workload="ATTACK_FIXED_MATCHED")["status"] == "PASS"
    assert pilot_gate({**base, "volume_active_at_query_trials": 0}, policy="B2_VOLUME_TC", workload="ATTACK_FIXED_MATCHED")["status"] == "FAIL"
    assert pilot_gate(base, policy="B2_VOLUME_TC", workload="BENIGN_BOUNDARY")["status"] == "PASS"


def test_pmtud_gate_requires_icmp_and_auth_tails() -> None:
    ips = [{"event": "fragment_observed", "src": "10.82.0.100", "offset": 40}]
    attacker = [{"event": "icmp_needfrag_send"}]
    assert pmtud_kernel_fragment_gate(ips, attacker)["status"] == "PASS"
    assert pmtud_kernel_fragment_gate([], attacker)["status"] == "FAIL"
    assert pmtud_kernel_fragment_gate(ips, [])["status"] == "FAIL"


def test_pmtud_pilot_gate_does_not_require_b0_poison() -> None:
    # A 576-byte PMTU first fragment already contains the A-RR, so tail
    # replacement is not an engineering requirement. Kernel fragments are
    # gated separately by pmtud_kernel_fragment_gate.
    assert (
        pilot_gate(
            {"any_poison": False},
            policy="B0_OFF",
            workload="ATTACK_FIXED_MATCHED",
            fragmentation_mode="pmtud",
        )["status"]
        == "PASS"
    )
    assert (
        pilot_gate(
            {"any_poison": False},
            policy="B0_OFF",
            workload="ATTACK_FIXED_MATCHED",
        )["status"]
        == "FAIL"
    )
    flood = {"trigger_trials": 5, "forged_tail_drop_trials": 0}
    assert (
        pilot_gate(
            flood,
            policy="B5_LOCKED_TC",
            workload="ATTACK_SWEEP_FLOOD",
            fragmentation_mode="pmtud",
        )["status"]
        == "PASS"
    )
    assert (
        pilot_gate(flood, policy="B5_LOCKED_TC", workload="ATTACK_SWEEP_FLOOD")["status"]
        == "FAIL"
    )

