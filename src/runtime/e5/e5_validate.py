"""Integrity and engineering gates for E5 raw artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from e5_analysis import read_jsonl


IDENTITY_FIELDS = ("run_id", "rep", "policy", "workload", "mono_ns", "wall_ns")
REQUIRED_LOGS = (
    "trials.jsonl",
    "client_events.jsonl",
    "auth_events.jsonl",
    "attacker_events.jsonl",
    "ips_events.jsonl",
    "unbound_events.jsonl",
    "cache_events.jsonl",
    "unbound_version.txt",
    "firewall_before.rules",
    "firewall_after.rules",
    "ips_inside.pcapng",
    "ips_outside.pcapng",
    "metrics.json",
    "resource_samples.jsonl",
)


def validate_trial_records(
    rows: list[dict[str, Any]],
    *,
    expected_trials: int,
    expected_qnames: Iterable[str] | None = None,
    require_probe_status: bool = False,
) -> dict[str, Any]:
    errors: list[str] = []
    if len(rows) != expected_trials:
        errors.append(f"expected {expected_trials} trial rows, found {len(rows)}")
    qnames = [row.get("qname") for row in rows]
    if any(not isinstance(qname, str) for qname in qnames):
        errors.append("every trial is missing qname")
    if len(set(qnames)) != len(qnames):
        errors.append("duplicate qname in trial records")
    trial_ids = [row.get("trial_id") for row in rows]
    if len(set(trial_ids)) != len(trial_ids):
        errors.append("duplicate trial_id in trial records")
    expected = list(expected_qnames or [])
    if expected and set(qnames) != set(expected):
        errors.append("trial qnames do not match the registered replay schedule")
    for index, row in enumerate(rows):
        if not row.get("trial_id"):
            errors.append(f"trial {index} is missing trial_id")
        before = row.get("cache_before")
        after = row.get("cache_after")
        if not isinstance(before, dict) or "cache_hit" not in before:
            errors.append(f"trial {index} is missing cache-before result")
        elif before.get("probe_status") == "error":
            if before.get("probe_valid") is not False or before.get("cache_hit") is not None:
                errors.append(f"trial {index} has malformed cache-before error probe")
        elif before.get("probe_valid") is False:
            errors.append(f"trial {index} has invalid cache-before probe")
        elif before.get("probe_status") not in (None, "miss"):
            errors.append(f"trial {index} cache-before probe is not a miss")
        elif bool(before.get("cache_hit")):
            errors.append(f"trial {index} has cache-before hit")
        if isinstance(before, dict) and before.get("qname") and before.get("qname").rstrip(".").lower() != str(row.get("qname", "")).rstrip(".").lower():
            errors.append(f"trial {index} cache-before probe qname mismatch")
        if not isinstance(after, dict) or "cache_hit" not in after:
            errors.append(f"trial {index} is missing cache-after result")
        elif after.get("probe_status") == "error":
            if after.get("probe_valid") is not False or after.get("cache_hit") is not None:
                errors.append(f"trial {index} has malformed cache-after error probe")
        elif after.get("probe_valid") is False:
            errors.append(f"trial {index} has invalid cache-after probe")
        if isinstance(after, dict) and after.get("qname") and after.get("qname").rstrip(".").lower() != str(row.get("qname", "")).rstrip(".").lower():
            errors.append(f"trial {index} cache-after probe qname mismatch")
        if "query_start_mono_ns" not in row or "client_answer_end_mono_ns" not in row:
            errors.append(f"trial {index} is missing client event timestamps")
        for phase in ("before", "after"):
            probe = row.get(f"cache_{phase}")
            if require_probe_status and (not isinstance(probe, dict) or "probe_status" not in probe):
                errors.append(f"trial {index} cache-{phase}: missing probe status")
            if isinstance(probe, dict) and "probe_status" in probe:
                probe_check = validate_cache_probe(probe, expected_qname=str(row.get("qname", "")))
                errors.extend(f"trial {index} cache-{phase}: {error}" for error in probe_check["errors"])
    return {"status": "PASS" if not errors else "FAIL", "errors": errors, "n_trials": len(rows)}


def validate_cache_probe(result: dict[str, Any], *, expected_qname: str | None = None) -> dict[str, Any]:
    """Validate one cache snapshot without collapsing probe errors into miss."""

    errors: list[str] = []
    status = result.get("probe_status")
    if expected_qname:
        if not result.get("qname"):
            errors.append("cache probe is missing qname")
        elif result.get("qname").rstrip(".").lower() != expected_qname.rstrip(".").lower():
            errors.append("cache probe qname does not match trial qname")
    if status not in {"hit", "miss", "error"}:
        errors.append("cache probe has no hit/miss/error status")
    if status == "error":
        if result.get("probe_valid") is not False:
            errors.append("cache probe error is not marked invalid")
        if result.get("cache_hit") is not None:
            errors.append("cache probe error must leave cache_hit unknown")
    elif result.get("probe_valid") is not True:
        errors.append("cache hit/miss is missing valid probe marker")
    if status == "miss" and result.get("answers"):
        errors.append("cache miss contains answers")
    if status == "miss" and result.get("cache_hit") is not False:
        errors.append("cache miss must set cache_hit=false")
    if status == "hit" and not result.get("answers"):
        errors.append("cache hit has no answers")
    if status == "hit" and result.get("cache_hit") is not True:
        errors.append("cache hit must set cache_hit=true")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def validate_replay_coverage(
    attacker_rows: list[dict[str, Any]],
    schedule: dict[str, Any],
    *,
    ips_rows: list[dict[str, Any]] | None = None,
    measurement_end_mono_ns: int | None = None,
) -> dict[str, Any]:
    """Check registered warmup, duration, rate and occupancy observation."""

    errors: list[str] = []
    starts = [row for row in attacker_rows if row.get("event") == "replay_started"]
    if len(starts) != 1:
        errors.append("expected exactly one replay_started event")
    if not starts:
        return {"status": "FAIL", "errors": errors, "observed_fraction": 0.0}
    start = starts[0]
    finishes = [row for row in attacker_rows if row.get("event") == "replay_finished"]
    finish = finishes[-1] if finishes else None
    scheduled_rows = schedule.get("occupancy", [])
    start_ns = int(start.get("replay_started_mono_ns", start.get("mono_ns", 0)))
    finish_ns = int(measurement_end_mono_ns if measurement_end_mono_ns is not None else (finish or {}).get("replay_finished_mono_ns", start_ns))
    window_s = max(0.0, (finish_ns - start_ns) / 1_000_000_000.0)
    if measurement_end_mono_ns is not None:
        scheduled = sum(
            1 for row in scheduled_rows
            if "at_s" not in row or float(row.get("at_s", 0.0)) <= window_s + 1e-9
        )
    else:
        scheduled = int((finish or start).get("scheduled_occupancy", len(scheduled_rows)))
    # Count occupancy datagrams that reached the pre-defragmentation observer
    # when IPS events are available.  Older artifacts fall back to sender
    # telemetry so they remain readable during migration.
    if ips_rows is not None:
        observed = sum(
            1
            for row in ips_rows
            if row.get("event") == "fragment_observed"
            and row.get("capture_source") == "af_packet"
            and row.get("src") == "10.82.0.200"
            and int(row.get("offset", 0)) > 0
            and (measurement_end_mono_ns is None or int(row.get("mono_ns", 0)) <= measurement_end_mono_ns)
        )
    else:
        observed = int((finish or {}).get("observed_occupancy", 0))
    fraction = observed / scheduled if scheduled else 0.0
    required = float(schedule.get("replay_coverage_required", {}).get("occupancy_observed_fraction", 0.99))
    if fraction < required:
        errors.append(f"occupancy observation fraction {fraction:.6f} below {required:.6f}")
    target_rate = float(schedule.get("rate_pps", 0.0))
    target_duration = float(schedule.get("duration_s", 0.0))
    elapsed_s = window_s
    observed_rate = observed / elapsed_s if elapsed_s else 0.0
    tolerance = float(schedule.get("replay_coverage_required", {}).get("rate_tolerance", 0.10))
    if target_rate and abs(observed_rate - target_rate) / target_rate > tolerance:
        errors.append(f"observed replay rate {observed_rate:.6f} outside target ±{tolerance:.0%}")
    # A running replay need only cover the measurement interval.  Its finite
    # completion event is optional because the runner may tear down early.
    if measurement_end_mono_ns is not None:
        replay_end = start_ns + int(target_duration * 1_000_000_000)
        if replay_end < measurement_end_mono_ns:
            errors.append("replay duration does not cover measurement window")
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "replay_started_mono_ns": start.get("replay_started_mono_ns"),
        "replay_finished_mono_ns": finish.get("replay_finished_mono_ns") if finish else None,
        "observed_occupancy": observed,
        "scheduled_occupancy": scheduled,
        "observed_fraction": fraction,
        "observed_rate_pps": observed_rate,
        "elapsed_s": elapsed_s,
    }


def _event_identity_errors(rows: list[dict[str, Any]], expected: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for index, row in enumerate(rows):
        for field in IDENTITY_FIELDS:
            if field not in row:
                errors.append(f"event row {index} missing {field}")
        for field in ("run_id", "policy", "workload"):
            if field in row and row[field] != expected[field]:
                errors.append(f"event row {index} has inconsistent {field}")
        if "rep" in row and int(row["rep"]) != int(expected["rep"]):
            errors.append(f"event row {index} has inconsistent rep")
    return errors


def _has_nonzero_nfqueue_counter(text: str) -> bool:
    return any(int(packet_count) > 0 for packet_count in re.findall(r"\[(\d+):\d+\]", text))


def _pcapng(path: Path) -> bool:
    try:
        payload = path.read_bytes()
        # Section + interface headers alone are not evidence of a capture;
        # require room for at least one packet block as well.
        return payload[:4] == b"\x0a\x0d\x0d\x0a" and len(payload) > 128
    except OSError:
        return False


def validate_run(
    run_dir: Path,
    *,
    expected: dict[str, Any],
    expected_qnames: Iterable[str] | None = None,
    expected_trials: int,
    require_pcap: bool = True,
    require_probe_status: bool = False,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    missing = [name for name in REQUIRED_LOGS if not (run_dir / name).exists()]
    errors.extend(f"missing artifact: {name}" for name in missing)
    if not missing:
        trial_rows = read_jsonl(run_dir / "trials.jsonl")
        trial_check = validate_trial_records(
            trial_rows,
            expected_trials=expected_trials,
            expected_qnames=expected_qnames,
            require_probe_status=require_probe_status,
        )
        errors.extend(trial_check["errors"])
        log_rows = {
            name: read_jsonl(run_dir / name)
            for name in ("client_events.jsonl", "auth_events.jsonl", "attacker_events.jsonl", "ips_events.jsonl", "unbound_events.jsonl", "cache_events.jsonl")
        }
        for name, rows in log_rows.items():
            errors.extend(f"{name}: {error}" for error in _event_identity_errors(rows, expected))
        if not any(row.get("event") == "fragment_observed" for row in log_rows["ips_events.jsonl"]):
            errors.append("IPS raw fragment observation log is empty")
        if not any(row.get("event") == "raw_observer_ready" for row in log_rows["ips_events.jsonl"]):
            errors.append("IPS AF_PACKET raw observer did not report readiness")
        trial_ids = {row.get("trial_id") for row in trial_rows}
        for trial_id in trial_ids:
            if not trial_id:
                continue
            for name in ("auth_events.jsonl", "ips_events.jsonl", "cache_events.jsonl"):
                if not any(row.get("trial_id") == trial_id for row in log_rows[name]):
                    errors.append(f"{trial_id}: missing {name} event mapping")
            for phase in ("before", "after"):
                if not any(row.get("event") == f"cache_{phase}" and row.get("trial_id") == trial_id for row in log_rows["cache_events.jsonl"]):
                    errors.append(f"{trial_id}: missing cache_{phase} event")
            if not any(row.get("event") == "client_query_send" and row.get("trial_id") == trial_id for row in log_rows["client_events.jsonl"]):
                errors.append(f"{trial_id}: missing client query event")
            if not any(row.get("event") == "client_answer_receive" and row.get("trial_id") == trial_id for row in log_rows["client_events.jsonl"]):
                errors.append(f"{trial_id}: missing client answer event")
            if not any(row.get("event") == "udp_receive" and row.get("trial_id") == trial_id for row in log_rows["auth_events.jsonl"]):
                errors.append(f"{trial_id}: missing auth UDP receive")
            if not any(row.get("event") == "packet_ingress" and row.get("trial_id") == trial_id for row in log_rows["ips_events.jsonl"]):
                errors.append(f"{trial_id}: missing IPS packet ingress")
        if expected["workload"].startswith("ATTACK_"):
            if not any(row.get("event") == "forged_tail_send" for row in log_rows["attacker_events.jsonl"]):
                errors.append("attack workload has no external forged-tail send evidence")
        elif any(row.get("event") == "forged_tail_send" for row in log_rows["attacker_events.jsonl"]):
            errors.append("benign workload contains an unexpected forged-tail send")

        ready_path = run_dir / "ips_ready.json"
        if ready_path.exists():
            ready = json.loads(ready_path.read_text(encoding="utf-8"))
            if ready.get("queue_num") != 5:
                errors.append("IPS ready record does not use NFQUEUE 5")
            for key, value in (("min_samples", 8), ("entropy_threshold", 6.0), ("unique_ratio_threshold", 0.90), ("window_seconds", 2.0)):
                if ready.get(key) != value:
                    errors.append(f"IPS ready record has unlocked/mismatched {key}")
            if ready.get("raw_observer") != "AF_PACKET":
                errors.append("IPS ready record lacks the AF_PACKET pre-defragmentation observer")
            if ready.get("raw_observer_duplicate_window_seconds") != 0.5:
                errors.append("IPS ready record has mismatched raw-observer duplicate window")
        else:
            errors.append("missing IPS ready record")
        for firewall_name in ("firewall_before.rules", "firewall_after.rules"):
            firewall = (run_dir / firewall_name).read_text(encoding="utf-8", errors="replace") if (run_dir / firewall_name).exists() else ""
            if "NFQUEUE" not in firewall or "--queue-num 5" not in firewall:
                errors.append(f"{firewall_name} does not prove NFQUEUE queue 5")
            if "queue-bypass" in firewall:
                errors.append(f"{firewall_name} contains forbidden NFQUEUE fallback")
            if firewall_name.endswith("after.rules") and not _has_nonzero_nfqueue_counter(firewall):
                errors.append("NFQUEUE/firewall counters did not increase")
        version_text = (run_dir / "unbound_version.txt").read_text(encoding="utf-8", errors="replace")
        if "1.26.1" not in version_text:
            errors.append("resolver is not the registered Unbound 1.26.1 build")
        try:
            metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
            if metrics.get("b5_trigger_mismatch"):
                errors.append("independent B5 window reconstruction disagrees with detector trigger log")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"metrics.json cannot be read: {exc}")
    if require_pcap:
        for pcap in (run_dir / "ips_inside.pcapng", run_dir / "ips_outside.pcapng"):
            if pcap.exists() and not _pcapng(pcap):
                errors.append(f"{pcap.name} is not a PCAPNG artifact")
    if (run_dir / "resource_samples.jsonl").exists() and not (run_dir / "resource_samples.jsonl").read_text(encoding="utf-8", errors="replace").strip():
        errors.append("runtime CPU/memory sample artifact is empty")
    if not (run_dir / "resolver_local_poisoner.present").exists():
        pass
    else:
        errors.append("resolver-local poisoner marker is present")
    return {
        "schema_version": 1,
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "warnings": warnings,
        "run_dir": str(run_dir),
        "expected": expected,
    }


AUTH_IP = "10.82.0.100"


def pmtud_kernel_fragment_gate(
    ips_rows: list[dict[str, Any]],
    attacker_rows: list[dict[str, Any]],
    *,
    auth_ip: str = AUTH_IP,
) -> dict[str, Any]:
    """Abort confirmatory PMTUD if the kernel never emitted AUTH fragments."""

    icmp = sum(1 for row in attacker_rows if row.get("event") == "icmp_needfrag_send")
    auth_tails = [
        row
        for row in ips_rows
        if row.get("event") == "fragment_observed"
        and row.get("src") == auth_ip
        and int(row.get("offset") or 0) > 0
    ]
    errors: list[str] = []
    if icmp == 0:
        errors.append("no ICMP NeedFrag sent")
    if not auth_tails:
        errors.append("AF_PACKET saw no non-initial fragments from AUTH after the PMTUD path")
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "icmp_needfrag_send": icmp,
        "auth_noninitial_fragments": len(auth_tails),
    }


def pilot_gate(
    metrics: dict[str, Any],
    *,
    policy: str,
    workload: str,
    fragmentation_mode: str = "crafted",
) -> dict[str, Any]:
    """Engineering/root-cause acceptance checks; never used as an inference gate."""

    errors: list[str] = []
    if (
        policy == "B0_OFF"
        and workload == "ATTACK_FIXED_MATCHED"
        and not metrics.get("any_poison")
        and fragmentation_mode != "pmtud"
    ):
        errors.append("B0 positive-control attack did not poison")
    if policy == "B0_OFF" and workload in {"ATTACK_DIVERSE_MODERATE", "ATTACK_DIVERSE_HIGH"}:
        if not metrics.get("forged_tail_ingress_trials"):
            errors.append("B0 factorial attack saw no forged-tail ingress")
        if not metrics.get("malicious_answer_trials"):
            errors.append("B0 factorial attack produced no malicious answer")
    if policy == "PREARM_TAIL_DROP" and workload == "ATTACK_FIXED_MATCHED":
        if not metrics.get("forged_tail_ingress_trials"):
            errors.append("PREARM saw no forged-tail ingress")
        if not metrics.get("forged_tail_drop_trials"):
            errors.append("PREARM dropped no forged tail")
        if metrics.get("any_poison"):
            errors.append("PREARM forged tail reached a poisoned cache")
    if policy == "B1_RL2_TC" and workload.startswith("ATTACK_"):
        if not metrics.get("tc_injection_trials"):
            errors.append("B1 produced no TC injection")
        if not metrics.get("tcp_retry_trials"):
            errors.append("B1 produced no TCP retry")
    if policy == "B1_RL2_TC" and workload == "BENIGN_BOUNDARY" and not metrics.get("legitimate_trials"):
        errors.append("B1 benign pilot produced no legitimate answer")
    if policy == "B2_VOLUME_TC" and workload == "ATTACK_FIXED_MATCHED":
        if not metrics.get("volume_active_at_query_trials"):
            errors.append("B2 fixed-IPID pilot produced no volume activation")
        if not metrics.get("forged_tail_drop_trials"):
            errors.append("B2 fixed-IPID pilot produced no enforced drop")
    if policy == "B2_VOLUME_TC" and workload == "ATTACK_SWEEP_FLOOD":
        if not metrics.get("volume_active_at_query_trials"):
            errors.append("B2 flood pilot produced no volume activation")
        if not metrics.get("forged_tail_drop_trials"):
            errors.append("B2 flood pilot produced no enforced drop")
    if policy == "B2_VOLUME_TC" and workload == "BENIGN_BOUNDARY":
        if not metrics.get("volume_active_at_query_trials"):
            errors.append("B2 boundary pilot produced no volume activation")
        if not metrics.get("legitimate_trials"):
            errors.append("B2 boundary pilot produced no legitimate answer")
    if policy == "B5_LOCKED_TC" and workload == "ATTACK_SWEEP_FLOOD":
        if not metrics.get("trigger_trials"):
            errors.append("B5 flood pilot produced no detector trigger")
        if fragmentation_mode != "pmtud" and not metrics.get("forged_tail_drop_trials"):
            errors.append("B5 flood pilot produced no enforced drop")
    if policy == "RFC_DROP_NATIVE":
        if not metrics.get("forged_tail_drop_trials") and workload.startswith("ATTACK_"):
            errors.append("RFC attack pilot dropped no fragmented response")
        if metrics.get("tc_injection_trials"):
            errors.append("RFC pilot unexpectedly injected TC")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors, "policy": policy, "workload": workload}
