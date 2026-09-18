from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT))

from run_e5 import aggregate_confirmatory, build_stage_jobs, load_protocol, source_guard, validate_b2_protocol, validate_factorial_protocol, validate_pmtud_protocol, write_compose_override, write_runtime_env, _stage_duration  # noqa: E402


def protocol() -> dict:
    return {
        "experiment_seed": 20260902,
        "k_runs_per_cell": 20,
        "trials_per_run": 50,
        "policies": ["B0_OFF", "B1_RL2_TC", "B5_LOCKED_TC", "RFC_DROP_NATIVE"],
        "workloads": ["BENIGN_LOW", "BENIGN_BOUNDARY", "ATTACK_FIXED_MATCHED", "ATTACK_SWEEP_FLOOD"],
        "pilot": [
            ["B0_OFF", "ATTACK_FIXED_MATCHED"],
            ["PREARM_TAIL_DROP", "ATTACK_FIXED_MATCHED"],
        ],
    }


def test_confirmatory_jobs_are_randomized_complete_blocks() -> None:
    jobs = build_stage_jobs("confirmatory", protocol())
    assert len(jobs) == 320
    assert (jobs[0]["policy"], jobs[0]["workload"]) != ("B0_OFF", "BENIGN_LOW") or jobs[1]["policy"] != "B0_OFF"
    for rep in range(1, 21):
        block = [row for row in jobs if row["rep"] == rep]
        assert len(block) == 16
        assert len({(row["policy"], row["workload"]) for row in block}) == 16


def test_sanity_has_one_complete_block_and_pilot_excludes_confirmatory_only() -> None:
    sanity = build_stage_jobs("sanity", protocol())
    assert len(sanity) == 16
    assert {row["rep"] for row in sanity} == {0}
    pilot = build_stage_jobs("pilot", protocol())
    assert len(pilot) == 2
    assert all(row["rep"] == 0 and row["policy"] in {"B0_OFF", "PREARM_TAIL_DROP"} for row in pilot)


def test_source_guard_rejects_resolver_local_poisoner(tmp_path: Path) -> None:
    (tmp_path / "resolver").mkdir()
    (tmp_path / "resolver" / "poisoner.py").write_text("", encoding="utf-8")
    result = source_guard(tmp_path)
    assert result["status"] == "FAIL"
    assert result["errors"]


def test_protocol_drives_factorial_matrix_and_full_pilot() -> None:
    factorial = {
        "experiment_seed": 20260911,
        "k_runs_per_cell": 20,
        "trials_per_run": 50,
        "policies": ["B0_OFF", "B1_RL2_TC", "B5_LOCKED_TC", "RFC_DROP_NATIVE"],
        "workloads": ["BENIGN_DIVERSE_MODERATE", "BENIGN_DIVERSE_HIGH", "ATTACK_DIVERSE_MODERATE", "ATTACK_DIVERSE_HIGH"],
        "stages": {"pilot": {"cells": "all_4_policies_x_all_4_workloads"}},
    }
    assert len(build_stage_jobs("pilot", factorial)) == 16
    jobs = build_stage_jobs("confirmatory", factorial)
    assert len(jobs) == 320
    assert all(len([j for j in jobs if j["rep"] == rep]) == 16 for rep in range(1, 21))


def test_legacy_protocol_matrix_remains_unchanged() -> None:
    jobs = build_stage_jobs("confirmatory", protocol())
    assert {row["workload"] for row in jobs} == {"BENIGN_LOW", "BENIGN_BOUNDARY", "ATTACK_FIXED_MATCHED", "ATTACK_SWEEP_FLOOD"}


def test_registered_legacy_protocol_keeps_legacy_sweep_and_pilot_duration() -> None:
    legacy_path = E5_ROOT / "e5_protocol.json"
    legacy = load_protocol("legacy-audit", legacy_path)
    assert _stage_duration("pilot", legacy) == 20.0
    assert len(build_stage_jobs("confirmatory", legacy)) == 320


def test_aggregate_rejects_missing_or_duplicate_cells() -> None:
    small = {"policies": ["B0_OFF"], "workloads": ["BENIGN_LOW"], "k_runs_per_cell": 1}
    row = {
        "rep": 1, "policy": "B0_OFF", "workload": "BENIGN_LOW",
        "any_poison": False, "first_trial_poison": False,
        "legitimate_answer_rate": 1.0, "noanswer_rate": 0.0, "trigger_rate": 0.0,
        "forged_tail_drop_rate": 0.0, "tc_injection_rate": 0.0, "tcp_retry_rate": 0.0,
        "cache_insertion_rate": 0.0, "cache_probe_valid_rate": 1.0,
    }
    aggregate_confirmatory([row], small)
    with pytest.raises(ValueError):
        aggregate_confirmatory([], small)
    with pytest.raises(ValueError):
        aggregate_confirmatory([row, row], small)


def test_factorial_compose_override_mounts_shared_replay_control(tmp_path: Path) -> None:
    override = tmp_path / "compose.override.yaml"
    logs = {service: tmp_path / service for service in ("ips", "resolver", "auth", "attacker", "client")}
    for directory in logs.values():
        directory.mkdir()
    write_compose_override(
        override,
        log_dirs=logs,
        pcap_dir=tmp_path / "pcap",
        schedule_path=tmp_path / "schedule.json",
        control_path=tmp_path / "control",
    )
    text = override.read_text(encoding="utf-8")
    assert text.count("target: /app/control") == 2


def test_registered_factorial_protocol_rejects_extra_pilot_policy() -> None:
    factorial = json.loads((E5_ROOT / "e5_factorial_protocol.json").read_text(encoding="utf-8"))
    factorial["policies"].append("PREARM_TAIL_DROP")
    with pytest.raises(ValueError):
        validate_factorial_protocol(factorial)


def test_b2_protocol_registers_eighty_confirmatory_jobs() -> None:
    protocol = json.loads((E5_ROOT / "e5_b2_protocol.json").read_text(encoding="utf-8"))
    validate_b2_protocol(protocol)
    jobs = build_stage_jobs("confirmatory", protocol)
    assert len(jobs) == 80
    assert {row["policy"] for row in jobs} == {"B2_VOLUME_TC"}
    assert {row["workload"] for row in jobs} == {"BENIGN_LOW", "BENIGN_BOUNDARY", "ATTACK_FIXED_MATCHED", "ATTACK_SWEEP_FLOOD"}
    assert len(build_stage_jobs("pilot", protocol)) == 4
    assert len(build_stage_jobs("sanity", protocol)) == 4


def test_pmtud_protocol_registers_eighty_confirmatory_jobs() -> None:
    protocol = json.loads((E5_ROOT / "e5_pmtud_protocol.json").read_text(encoding="utf-8"))
    validate_pmtud_protocol(protocol)
    jobs = build_stage_jobs("confirmatory", protocol)
    assert len(jobs) == 80
    assert {row["policy"] for row in jobs} == {"B0_OFF", "B5_LOCKED_TC"}
    assert {row["workload"] for row in jobs} == {"ATTACK_FIXED_MATCHED", "ATTACK_SWEEP_FLOOD"}


def test_runtime_env_can_pass_pmtud_mode(tmp_path: Path) -> None:
    env = tmp_path / "runtime.env"
    write_runtime_env(env, run_id="E5-pmtud-s20260915-r001", rep=1, policy="B0_OFF", workload="ATTACK_FIXED_MATCHED", extra={"AUTH_FRAGMENT_MODE": "pmtud"})
    text = env.read_text(encoding="utf-8")
    assert "AUTH_FRAGMENT_MODE=pmtud" in text
