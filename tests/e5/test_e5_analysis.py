from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT))

from e5_aggregate import exact_binomial_ci, paired_bootstrap_mean, paired_factorial_differences  # noqa: E402
from e5_analysis import b5_active_at, compare_trigger_times, compute_run_metrics, reconstruct_b5_windows, reconstruct_volume_windows, volume_active_at  # noqa: E402


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def test_exact_cp_zero_of_twenty_matches_two_sided_95_percent_bound() -> None:
    low, high = exact_binomial_ci(0, 20)
    assert low == pytest.approx(0.0)
    assert high == pytest.approx(0.168433, abs=1e-5)


def test_complete_block_bootstrap_is_deterministic() -> None:
    result = paired_bootstrap_mean({1: 0.1, 2: 0.2, 3: 0.3}, replicates=500, seed=20260902)
    assert result["estimate"] == pytest.approx(0.2)
    assert result == paired_bootstrap_mean({1: 0.1, 2: 0.2, 3: 0.3}, replicates=500, seed=20260902)
    assert result["ci_low"] <= result["estimate"] <= result["ci_high"]


def test_factorial_effects_pair_runs_by_replicate() -> None:
    rows = [
        {"rep": 1, "policy": "B5_LOCKED_TC", "workload": "ATTACK_DIVERSE_MODERATE", "malicious_answer_rate": 0.4},
        {"rep": 1, "policy": "B5_LOCKED_TC", "workload": "BENIGN_DIVERSE_MODERATE", "malicious_answer_rate": 0.1},
        {"rep": 2, "policy": "B5_LOCKED_TC", "workload": "ATTACK_DIVERSE_MODERATE", "malicious_answer_rate": 0.5},
        {"rep": 2, "policy": "B5_LOCKED_TC", "workload": "BENIGN_DIVERSE_MODERATE", "malicious_answer_rate": 0.2},
    ]
    assert paired_factorial_differences(
        rows,
        policy="B5_LOCKED_TC",
        first_workload="ATTACK_DIVERSE_MODERATE",
        second_workload="BENIGN_DIVERSE_MODERATE",
        metric="malicious_answer_rate",
    ) == {1: pytest.approx(0.3), 2: pytest.approx(0.3)}


def test_b5_window_reconstruction_uses_raw_fragment_events() -> None:
    rows = [
        {"event": "fragment_observed", "mono_ns": index * 1_000_000, "ipid": index}
        for index in range(64)
    ]
    states = reconstruct_b5_windows(rows)
    assert states[-1]["samples"] == 64
    assert states[-1]["entropy"] == pytest.approx(6.0)
    assert states[-1]["unique_ratio"] == pytest.approx(1.0)
    assert any(row["triggered"] for row in states)


def test_b5_window_reconstruction_tracks_state_transitions_after_expiry() -> None:
    rows = [
        {"event": "fragment_observed", "mono_ns": index * 1_000_000, "ipid": index}
        for index in range(64)
    ]
    rows.extend(
        {"event": "fragment_observed", "mono_ns": 2_100_000_000 + index * 1_000_000, "ipid": 10_000 + index}
        for index in range(64)
    )
    states = reconstruct_b5_windows(rows)
    assert sum(row["triggered"] for row in states) == 2


def test_b5_activity_expires_when_query_is_after_two_second_idle_window() -> None:
    rows = [
        {"event": "fragment_observed", "mono_ns": index * 1_000_000, "ipid": index}
        for index in range(64)
    ]
    assert b5_active_at(rows, 63_000_000) is True
    assert b5_active_at(rows, 2_100_000_000) is False


def test_volume_window_activates_before_locked_b5() -> None:
    rows = [
        {"event": "fragment_observed", "mono_ns": index * 1_000_000, "ipid": index}
        for index in range(8)
    ]
    volume = reconstruct_volume_windows(rows)
    b5 = reconstruct_b5_windows(rows)
    assert volume[-1]["b2_active"] is True
    assert b5[-1]["b5_active"] is False
    assert volume_active_at(rows, 7_000_000) is True
    assert b5_active_at(rows, 7_000_000) is False


def test_trigger_time_comparison_tolerates_logging_boundary_but_reports_count() -> None:
    result = compare_trigger_times([1_000_000_000], [1_050_000_000, 1_060_000_000])
    assert result["mismatch"] is False
    assert result["count_difference"] == 1
    assert result["runtime_unmatched_count"] == 0
    assert result["reconstructed_unmatched_count"] == 0


def test_trigger_time_comparison_rejects_unmatched_transition() -> None:
    result = compare_trigger_times([1_000_000_000], [1_500_000_000])
    assert result["mismatch"] is True
    assert result["runtime_unmatched_count"] == 1


def test_run_metrics_reconstructs_attack_mechanism(tmp_path: Path) -> None:
    qname = "r01-t000-abcdef01.bank.com."
    base = {
        "run_id": "E5-routed-s20260902-r001",
        "rep": 1,
        "policy": "B1_RL2_TC",
        "workload": "ATTACK_FIXED_MATCHED",
    }
    trial = {
        **base,
        "event": "trial",
        "trial_id": "r01-t000-abcdef01",
        "qname": qname,
        "trial": 0,
        "query_start_mono_ns": 200,
        "answer_ip": "203.0.113.80",
        "status": "legitimate_answer",
        "client_latency_ms": 10.0,
        "cache_before": {"cache_hit": False},
        "cache_after": {"cache_hit": True, "answers": ["203.0.113.80"]},
    }
    write_jsonl(tmp_path / "trials.jsonl", [trial])
    write_jsonl(
        tmp_path / "ips_events.jsonl",
        [
            {**base, "event": "detector_trigger", "mono_ns": 100, "qname": None},
            {**base, "event": "packet_ingress", "mono_ns": 300, "qname": qname, "ipid": 777, "offset": 40},
            {**base, "event": "packet_verdict", "mono_ns": 301, "qname": qname, "ipid": 777, "offset": 40, "verdict": "drop"},
            {**base, "event": "tc_injected", "mono_ns": 302, "qname": qname, "ipid": 777},
        ],
    )
    write_jsonl(tmp_path / "attacker_events.jsonl", [{**base, "event": "forged_tail_send", "mono_ns": 250, "qname": qname, "ipid": 777}])
    write_jsonl(tmp_path / "auth_events.jsonl", [{**base, "event": "tcp_receive", "mono_ns": 400, "qname": qname}])
    write_jsonl(tmp_path / "cache_events.jsonl", [])
    metrics = compute_run_metrics(tmp_path, expected_trials=1)
    assert metrics["any_poison"] is False
    assert metrics["tc_injection_trials"] == 1
    assert metrics["tcp_retry_trials"] == 1
    assert metrics["forged_tail_drop_trials"] == 1
    assert metrics["cache_insertion_rate"] is None
    assert metrics["root_cause_counts"]["mitigated"] == 1


def test_benign_fragmented_legitimate_answer_is_not_forged_tail(tmp_path: Path) -> None:
    qname = "r01-t000-abcdef01.bank.com."
    base = {
        "run_id": "E5-factorial-s20260911-r001",
        "rep": 1,
        "policy": "B5_LOCKED_TC",
        "workload": "BENIGN_DIVERSE_MODERATE",
    }
    trial = {
        **base,
        "event": "trial",
        "trial_id": "r01-t000-abcdef01",
        "qname": qname,
        "trial": 0,
        "query_start_mono_ns": 200,
        "answer_ip": "203.0.113.80",
        "status": "legitimate_answer",
        "cache_before": {"cache_hit": False},
        "cache_after": {"cache_hit": False, "answers": []},
    }
    write_jsonl(tmp_path / "trials.jsonl", [trial])
    write_jsonl(
        tmp_path / "ips_events.jsonl",
        [
            {**base, "event": "packet_ingress", "mono_ns": 300, "qname": qname, "ipid": 10, "offset": 40},
            {**base, "event": "packet_verdict", "mono_ns": 301, "qname": qname, "ipid": 10, "offset": 40, "verdict": "drop"},
        ],
    )
    write_jsonl(tmp_path / "attacker_events.jsonl", [])
    write_jsonl(tmp_path / "auth_events.jsonl", [])
    write_jsonl(tmp_path / "cache_events.jsonl", [])
    metrics = compute_run_metrics(tmp_path, expected_trials=1)
    assert metrics["forged_tail_ingress_trials"] == 0
    assert metrics["forged_tail_drop_trials"] == 0
