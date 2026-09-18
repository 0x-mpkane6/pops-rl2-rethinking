from __future__ import annotations

import sys
from pathlib import Path

import pytest

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT))

from e5_schedule import (  # noqa: E402
    WORKLOAD_SPECS,
    build_replay_schedule,
    schedule_digest,
)


def test_schedule_is_deterministic_and_policy_independent() -> None:
    first = build_replay_schedule(
        run_id="E5-routed-s20260902-r001",
        rep=3,
        workload="ATTACK_FIXED_MATCHED",
        seed=20260902,
        trials=5,
        duration_s=2.0,
    )
    second = build_replay_schedule(
        run_id="E5-routed-s20260902-r001",
        rep=3,
        workload="ATTACK_FIXED_MATCHED",
        seed=20260902,
        trials=5,
        duration_s=2.0,
    )
    assert first == second
    assert schedule_digest(first) == schedule_digest(second)
    assert first["workload"] == "ATTACK_FIXED_MATCHED"
    assert len(first["trials"]) == 5
    assert len({row["qname"] for row in first["trials"]}) == 5
    assert first["trials"][0]["auth_ipid"] == 777


def test_schedule_replay_has_expected_workload_rates() -> None:
    for workload, spec in WORKLOAD_SPECS.items():
        schedule = build_replay_schedule(
            run_id="E5-routed-s20260902-r001",
            rep=1,
            workload=workload,
            seed=9,
            trials=2,
            duration_s=1.0,
        )
        assert schedule["rate_pps"] == pytest.approx(spec["rate_pps"])
        assert schedule["occupancy"]
        assert schedule["occupancy"][0]["at_s"] >= 0
        assert all(0 <= row["ipid"] <= 65535 for row in schedule["occupancy"])


def test_sweep_is_monotone_and_fixed_is_constant() -> None:
    fixed = build_replay_schedule(
        run_id="E5-routed-s20260902-r001",
        rep=1,
        workload="ATTACK_FIXED_MATCHED",
        seed=9,
        trials=1,
        duration_s=1.0,
    )
    sweep = build_replay_schedule(
        run_id="E5-routed-s20260902-r001",
        rep=1,
        workload="ATTACK_SWEEP_FLOOD",
        seed=9,
        trials=1,
        duration_s=1.0,
    )
    assert {row["ipid"] for row in fixed["occupancy"]} == {777}
    assert [row["ipid"] for row in sweep["occupancy"][:100]] == list(range(100))


def test_factorial_kind_pair_shares_qnames_ipids_and_sweep_start() -> None:
    benign = build_replay_schedule(
        run_id="E5-factorial-s20260911-r001", rep=2, workload="BENIGN_DIVERSE_MODERATE", seed=20260911, trials=5, duration_s=1.0
    )
    attack = build_replay_schedule(
        run_id="E5-factorial-s20260911-r001", rep=2, workload="ATTACK_DIVERSE_MODERATE", seed=20260911, trials=5, duration_s=1.0
    )
    assert [row["qname"] for row in benign["trials"]] == [row["qname"] for row in attack["trials"]]
    assert [row["auth_ipid"] for row in benign["trials"]] == [row["auth_ipid"] for row in attack["trials"]]
    assert benign["occupancy"] == attack["occupancy"]
    assert benign["matching_component_sha256"] == attack["matching_component_sha256"]
    assert schedule_digest(benign) != schedule_digest(attack)
    assert benign["attack_tail"] is False and attack["attack_tail"] is True
    assert benign["occupancy"][0]["ipid"] != 0
    assert benign["trials"][0]["query_at_s"] >= 3.0
    assert all(0 <= row["ipid"] <= 65535 for row in benign["occupancy"])
