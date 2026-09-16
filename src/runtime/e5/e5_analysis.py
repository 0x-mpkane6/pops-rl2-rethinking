"""Deterministic reconstruction of E5 metrics from raw artifacts."""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter, deque
from pathlib import Path
from typing import Any

from e5_lib import classify_outcome, ratio_meets_threshold, raw_shannon_entropy


POISON_IP = "6.6.6.6"
LEGITIMATE_IP = "203.0.113.80"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"non-object JSONL row at {path}:{line_number}")
        rows.append(value)
    return rows


def _quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    fraction = position - low
    return ordered[low] + (ordered[high] - ordered[low]) * fraction


def _stats_percentages(rows: list[dict[str, Any]], field: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(field)
        if isinstance(value, str):
            value = value.strip().rstrip("%")
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(parsed):
            values.append(parsed)
    return values


def _trial_events(rows: list[dict[str, Any]], trial: dict[str, Any]) -> list[dict[str, Any]]:
    qname = trial.get("qname")
    trial_id = trial.get("trial_id")
    return [
        row
        for row in rows
        if (qname and row.get("qname") == qname) or (trial_id and row.get("trial_id") == trial_id)
    ]


def _has_event(rows: list[dict[str, Any]], event: str) -> bool:
    return any(row.get("event") == event for row in rows)


def _has_drop(rows: list[dict[str, Any]], *, noninitial_only: bool = False) -> bool:
    return any(
        row.get("event") == "packet_verdict"
        and row.get("verdict") == "drop"
        and (not noninitial_only or int(row.get("offset", 0)) > 0)
        for row in rows
    )


def reconstruct_b5_windows(
    ips_rows: list[dict[str, Any]],
    *,
    window_seconds: float = 2.0,
    min_samples: int = 8,
    entropy_threshold: float = 6.0,
    unique_ratio_threshold: float = 0.90,
) -> list[dict[str, Any]]:
    """Rebuild B5 state from raw non-initial-fragment observations only."""

    if window_seconds <= 0 or min_samples < 0:
        raise ValueError("window_seconds must be positive and min_samples non-negative")
    observations = sorted(
        (row for row in ips_rows if row.get("event") == "fragment_observed" and row.get("ipid") is not None),
        key=lambda row: int(row["mono_ns"]),
    )
    states: list[dict[str, Any]] = []
    state: deque[tuple[int, int]] = deque()
    window_ns = int(window_seconds * 1_000_000_000)
    previous_active = False
    for row in observations:
        timestamp = int(row["mono_ns"])
        cutoff = timestamp - window_ns
        while state and state[0][0] < cutoff:
            state.popleft()
        state.append((timestamp, int(row["ipid"])))
        ipids = [ipid for _, ipid in state]
        n = len(ipids)
        entropy = raw_shannon_entropy(ipids)
        unique_count = len(set(ipids))
        unique_ratio = unique_count / n if n else 0.0
        active = n >= min_samples and entropy >= entropy_threshold and ratio_meets_threshold(
            unique_count,
            n,
            unique_ratio_threshold,
        )
        states.append(
            {
                "mono_ns": timestamp,
                "b5_active": active,
                "triggered": active and not previous_active,
                "samples": n,
                "entropy": entropy,
                "unique_ratio": unique_ratio,
            }
        )
        # The runtime detector carries the last Boolean state between packet
        # callbacks.  Reusing that state here mirrors the live transition
        # semantics, including a window expiry that occurs between two
        # observations; recomputing a separate "pre-append" predicate can
        # disagree at an exact U=0.90 boundary.
        previous_active = active
    return states


def reconstruct_volume_windows(
    ips_rows: list[dict[str, Any]],
    *,
    window_seconds: float = 2.0,
    min_samples: int = 8,
) -> list[dict[str, Any]]:
    """Rebuild volume-only B2 state from raw non-initial-fragment observations."""

    if window_seconds <= 0 or min_samples < 0:
        raise ValueError("window_seconds must be positive and min_samples non-negative")
    observations = sorted(
        (row for row in ips_rows if row.get("event") == "fragment_observed" and row.get("ipid") is not None),
        key=lambda row: int(row["mono_ns"]),
    )
    states: list[dict[str, Any]] = []
    state: deque[tuple[int, int]] = deque()
    window_ns = int(window_seconds * 1_000_000_000)
    previous_active = False
    for row in observations:
        timestamp = int(row["mono_ns"])
        cutoff = timestamp - window_ns
        while state and state[0][0] < cutoff:
            state.popleft()
        state.append((timestamp, int(row["ipid"])))
        n = len(state)
        active = n >= min_samples
        states.append(
            {
                "mono_ns": timestamp,
                "b2_active": active,
                "triggered": active and not previous_active,
                "samples": n,
            }
        )
        previous_active = active
    return states


def b5_active_at(
    ips_rows: list[dict[str, Any]],
    timestamp_ns: int,
    *,
    window_seconds: float = 2.0,
    min_samples: int = 8,
    entropy_threshold: float = 6.0,
    unique_ratio_threshold: float = 0.90,
) -> bool:
    """Recompute detector activity at an arbitrary event timestamp.

    A previous trigger is not evidence that the detector remains active.  The
    current window is rebuilt from raw observations so an idle period beyond
    the two-second window correctly expires the state before a query.
    """

    cutoff_ns = int(timestamp_ns) - int(window_seconds * 1_000_000_000)
    ipids = [
        int(row["ipid"])
        for row in ips_rows
        if row.get("event") == "fragment_observed"
        and row.get("ipid") is not None
        and cutoff_ns <= int(row.get("mono_ns", 0)) <= int(timestamp_ns)
    ]
    n = len(ipids)
    if n < min_samples:
        return False
    unique_count = len(set(ipids))
    return raw_shannon_entropy(ipids) >= entropy_threshold and ratio_meets_threshold(
        unique_count,
        n,
        unique_ratio_threshold,
    )


def volume_active_at(
    ips_rows: list[dict[str, Any]],
    timestamp_ns: int,
    *,
    window_seconds: float = 2.0,
    min_samples: int = 8,
) -> bool:
    """Recompute volume-only activity at an arbitrary event timestamp."""

    cutoff_ns = int(timestamp_ns) - int(window_seconds * 1_000_000_000)
    n = sum(
        1
        for row in ips_rows
        if row.get("event") == "fragment_observed"
        and row.get("ipid") is not None
        and cutoff_ns <= int(row.get("mono_ns", 0)) <= int(timestamp_ns)
    )
    return n >= min_samples


def compare_trigger_times(
    reconstructed: list[int],
    runtime: list[int],
    *,
    tolerance_ns: int = 100_000_000,
) -> dict[str, Any]:
    """Check temporal agreement between raw reconstruction and live logs.

    The live detector can emit a transition from either the packet callback
    or the periodic tick thread.  Their event-write times need not be
    identical to the raw-observer row even when they describe the same
    transition.  A bounded temporal match keeps that logging boundary from
    becoming a false integrity failure while retaining both counts and any
    genuinely unmatched transitions in the metrics.
    """

    if tolerance_ns < 0:
        raise ValueError("tolerance_ns must be non-negative")

    def nearest_distances(source: list[int], target: list[int]) -> list[int]:
        if not target:
            return [tolerance_ns + 1 for _ in source]
        return [min(abs(value - candidate) for candidate in target) for value in source]

    runtime_distances = nearest_distances(runtime, reconstructed)
    reconstructed_distances = nearest_distances(reconstructed, runtime)
    all_distances = runtime_distances + reconstructed_distances
    return {
        "mismatch": any(distance > tolerance_ns for distance in all_distances),
        "tolerance_ns": tolerance_ns,
        "runtime_unmatched_count": sum(distance > tolerance_ns for distance in runtime_distances),
        "reconstructed_unmatched_count": sum(distance > tolerance_ns for distance in reconstructed_distances),
        "max_nearest_error_ns": max(all_distances) if all_distances else None,
        "count_difference": len(runtime) - len(reconstructed),
    }


def compute_run_metrics(run_dir: Path, *, expected_trials: int | None = None) -> dict[str, Any]:
    """Reconstruct one run without treating its 50 trials as independent runs."""

    trials = read_jsonl(run_dir / "trials.jsonl")
    ips = read_jsonl(run_dir / "ips_events.jsonl")
    auth = read_jsonl(run_dir / "auth_events.jsonl")
    attacker = read_jsonl(run_dir / "attacker_events.jsonl")
    cache = read_jsonl(run_dir / "cache_events.jsonl")
    resource_rows = read_jsonl(run_dir / "resource_samples.jsonl")
    if expected_trials is not None and len(trials) != expected_trials:
        raise ValueError(f"expected {expected_trials} trial rows, found {len(trials)}")
    if not trials:
        raise ValueError(f"no trial rows in {run_dir}")

    first = trials[0]
    workload = str(first.get("workload", "unknown"))
    policy = str(first.get("policy", "unknown"))
    attack = workload.startswith("ATTACK_")
    reconstructed_states = reconstruct_b5_windows(ips)
    reconstructed_triggers = [row["mono_ns"] for row in reconstructed_states if row.get("triggered")]
    runtime_triggers = [int(row.get("mono_ns", 0)) for row in ips if row.get("event") == "detector_trigger"]
    trigger_alignment = compare_trigger_times(reconstructed_triggers, runtime_triggers)
    trigger_times = reconstructed_triggers or runtime_triggers
    volume_states = reconstruct_volume_windows(ips)
    volume_reconstructed_triggers = [row["mono_ns"] for row in volume_states if row.get("triggered")]
    volume_runtime_triggers = [int(row.get("mono_ns", 0)) for row in ips if row.get("event") == "volume_trigger"]
    volume_alignment = compare_trigger_times(volume_reconstructed_triggers, volume_runtime_triggers)
    trigger_trials = 0
    forged_ingress_trials = 0
    forged_drop_trials = 0
    tc_trials = 0
    tcp_trials = 0
    poison_trials = 0
    legit_trials = 0
    noanswer_trials = 0
    cache_insertion_trials = 0
    cache_before_probe_valid_trials = 0
    cache_before_probe_error_trials = 0
    cache_probe_error_trials = 0
    cache_probe_valid_trials = 0
    detector_active_query_trials = 0
    detector_active_enforcement_trials = 0
    volume_active_query_trials = 0
    volume_active_enforcement_trials = 0
    latencies: list[float] = []
    query_latencies: list[float] = []
    per_trial: list[dict[str, Any]] = []
    root_causes: Counter[str] = Counter()

    for trial in sorted(trials, key=lambda row: int(row.get("trial", 0))):
        qname = trial.get("qname")
        events = _trial_events(ips, trial)
        auth_events = _trial_events(auth, trial)
        attacker_events = _trial_events(attacker, trial)
        query_start = int(trial.get("client_query_start_mono_ns", trial.get("mono_ns", 0)))
        trigger_seen_before = any(int(timestamp) <= query_start for timestamp in trigger_times)
        detector_active_at_query = b5_active_at(ips, query_start)
        volume_active_at_query = volume_active_at(ips, query_start)
        policy_trigger_before = volume_active_at_query if policy == "B2_VOLUME_TC" else detector_active_at_query
        forged_sends = [row for row in attacker_events if row.get("event") == "forged_tail_send"]
        candidate_ipids = {int(row["ipid"]) for row in forged_sends if row.get("ipid") is not None}
        forged_hashes = {
            packet_hash
            for row in forged_sends
            for packet_hash in row.get("packet_sha256", [])
            if isinstance(packet_hash, str)
        }
        forged_body_hashes = {
            row["dns_body_sha256"]
            for row in forged_sends
            if isinstance(row.get("dns_body_sha256"), str)
        }
        raw_fragment_events = [row for row in ips if row.get("event") == "fragment_observed"]
        packet_events = [row for row in events if row.get("event") in {"packet_ingress", "packet_verdict"}]
        if policy == "B2_VOLUME_TC":
            enforcement_states = [
                bool(row.get("b2_active"))
                for row in events
                if row.get("event") in {"packet_decision", "enforcement_action"} and "b2_active" in row
            ]
        else:
            enforcement_states = [
                bool(row.get("b5_active"))
                for row in events
                if row.get("event") in {"packet_decision", "enforcement_action"} and "b5_active" in row
            ]
        detector_active_at_enforcement = any(enforcement_states)
        volume_active_at_enforcement = any(
            bool(row.get("b2_active"))
            for row in events
            if row.get("event") in {"packet_decision", "enforcement_action"} and "b2_active" in row
        )
        if forged_hashes or forged_body_hashes:
            forged_ingress = any(
                row.get("payload_sha256") in forged_hashes
                for row in raw_fragment_events
            ) or any(
                row.get("event") == "packet_ingress"
                and (row.get("payload_sha256") in forged_hashes or row.get("dns_body_sha256") in forged_body_hashes)
                for row in packet_events
            )
            forged_drop = any(
                row.get("event") == "packet_verdict"
                and row.get("verdict") == "drop"
                and (row.get("payload_sha256") in forged_hashes or row.get("dns_body_sha256") in forged_body_hashes)
                and (int(row.get("offset", 0)) > 0 or bool(row.get("reassembled")))
                for row in packet_events
            )
        elif candidate_ipids:
            forged_ingress = any(
                int(row.get("ipid", -1)) in candidate_ipids
                for row in raw_fragment_events
            ) or any(
                row.get("event") == "packet_ingress"
                and int(row.get("ipid", -1)) in candidate_ipids
                for row in packet_events
            )
            forged_drop = any(
                row.get("event") == "packet_verdict"
                and row.get("verdict") == "drop"
                and int(row.get("ipid", -1)) in candidate_ipids
                and (int(row.get("offset", 0)) > 0 or bool(row.get("reassembled")))
                for row in packet_events
            )
        else:
            # A benign fragmented authoritative answer is not a forged tail.
            # Only use the generic packet fallback when this is an attack
            # workload whose sender evidence is unavailable.
            forged_ingress = attack and _has_event(events, "packet_ingress") and any(int(row.get("offset", 0)) > 0 for row in packet_events)
            forged_drop = attack and _has_drop(events, noninitial_only=True)
        tc_injected = _has_event(events, "tc_injected")
        tcp_retry = any(row.get("event") in {"tcp_receive", "tcp_query"} for row in auth_events)
        answer_ip = trial.get("answer_ip")
        # Keep the transport outcome separate from the independent cache
        # snapshot.  A cache hit after the query is evidence of insertion,
        # not evidence that this client received a malicious answer.
        cache_before = trial.get("cache_before", {})
        before_status = cache_before.get("probe_status")
        if before_status in {"hit", "miss"} and cache_before.get("probe_valid") is True:
            cache_before_probe_valid_trials += 1
        elif before_status == "error" or cache_before.get("probe_valid") is False:
            cache_before_probe_error_trials += 1
        cache_after = trial.get("cache_after", {})
        cache_status = cache_after.get("probe_status")
        cache_valid = cache_after.get("probe_valid") is True or (cache_status in {"hit", "miss"} and "probe_valid" not in cache_after)
        if cache_valid:
            cache_probe_valid_trials += 1
        elif cache_status == "error" or cache_after.get("probe_valid") is False:
            cache_probe_error_trials += 1
        cache_inserted = cache_valid and cache_status == "hit" and POISON_IP in cache_after.get("answers", [])
        poisoned = answer_ip == POISON_IP
        legitimate = answer_ip == LEGITIMATE_IP
        noanswer = answer_ip is None
        if trigger_seen_before:
            trigger_trials += 1
        if detector_active_at_query:
            detector_active_query_trials += 1
        if detector_active_at_enforcement:
            detector_active_enforcement_trials += 1
        if volume_active_at_query:
            volume_active_query_trials += 1
        if volume_active_at_enforcement:
            volume_active_enforcement_trials += 1
        if forged_ingress:
            forged_ingress_trials += 1
        if forged_drop:
            forged_drop_trials += 1
        if tc_injected:
            tc_trials += 1
        if tcp_retry:
            tcp_trials += 1
        if poisoned:
            poison_trials += 1
        if cache_inserted:
            cache_insertion_trials += 1
        if legitimate:
            legit_trials += 1
        if noanswer:
            noanswer_trials += 1
        latency = trial.get("client_latency_ms", trial.get("latency_ms"))
        if latency is not None and math.isfinite(float(latency)):
            latencies.append(float(latency))
        query_latency = trial.get("latency_ms")
        if query_latency is not None and math.isfinite(float(query_latency)):
            query_latencies.append(float(query_latency))
        cause = classify_outcome(
            poisoned=poisoned,
            trigger_before=policy_trigger_before,
            drop_observed=forged_drop or _has_drop(events),
            tcp_retry=tcp_retry,
            legitimate=legitimate,
            attack=attack,
        )
        if attack:
            root_causes[cause] += 1
        per_trial.append(
            {
                "trial_id": trial.get("trial_id"),
                "qname": qname,
                "answer_ip": answer_ip,
                "status": trial.get("status"),
                "poisoned": poisoned,
                "cache_inserted": cache_inserted,
                "legitimate": legitimate,
                "trigger_seen_before": trigger_seen_before,
                "detector_active_at_query": detector_active_at_query,
                "detector_active_at_enforcement": detector_active_at_enforcement,
                "volume_active_at_query": volume_active_at_query,
                "volume_active_at_enforcement": volume_active_at_enforcement,
                "forged_tail_ingress": forged_ingress,
                "forged_tail_drop": forged_drop,
                "tc_injected": tc_injected,
                "tcp_retry": tcp_retry,
                "root_cause": cause,
            }
        )

    n = len(trials)
    before_probe_status_trials = sum("probe_status" in row.get("cache_before", {}) for row in trials)
    after_probe_status_trials = sum("probe_status" in row.get("cache_after", {}) for row in trials)
    cache_before_hits = sum(bool(row.get("cache_before", {}).get("cache_hit")) for row in trials)
    cache_after_poison = sum(
        row.get("cache_after", {}).get("probe_status") == "hit"
        and POISON_IP in row.get("cache_after", {}).get("answers", [])
        for row in trials
    )
    cache_after_legit = sum(LEGITIMATE_IP in row.get("cache_after", {}).get("answers", []) for row in trials)
    occupancy_target_pps = None
    observed_fragment_rate = None
    schedule_path = run_dir / "schedule.json"
    if schedule_path.exists():
        schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
        occupancy_target_pps = schedule.get("rate_pps")
    replay_started = next((row for row in attacker if row.get("event") == "replay_started"), None)
    replay_finished = next((row for row in attacker if row.get("event") == "replay_finished"), None)
    if replay_started and replay_finished:
        start_ns = int(replay_started.get("replay_started_mono_ns") or replay_started.get("mono_ns") or 0)
        end_ns = int(replay_finished.get("replay_finished_mono_ns") or replay_finished.get("mono_ns") or 0)
        elapsed = (end_ns - start_ns) / 1_000_000_000.0
        fragments = replay_finished.get("observed_fragments")
        if elapsed > 0 and fragments is not None:
            observed_fragment_rate = float(fragments) / elapsed
    metrics: dict[str, Any] = {
        "schema_version": 1,
        "run_id": first.get("run_id"),
        "rep": first.get("rep"),
        "policy": policy,
        "workload": workload,
        "n_trials": n,
        "attack_workload": attack,
        "poison_trials": poison_trials,
        "malicious_answer_trials": poison_trials,
        "malicious_answer_rate": poison_trials / n,
        "run_asr": poison_trials / n if attack else None,
        "any_poison": bool(poison_trials),
        "first_trial_poison": bool(per_trial and per_trial[0]["poisoned"]),
        "legitimate_trials": legit_trials,
        "legitimate_answer_rate": legit_trials / n,
        "noanswer_trials": noanswer_trials,
        "noanswer_rate": noanswer_trials / n,
        "trigger_trials": trigger_trials,
        "trigger_rate": trigger_trials / n,
        "detector_active_at_query_trials": detector_active_query_trials,
        "detector_active_at_query_rate": detector_active_query_trials / n,
        "detector_active_at_enforcement_trials": detector_active_enforcement_trials,
        "detector_active_at_enforcement_rate": detector_active_enforcement_trials / n,
        "volume_active_at_query_trials": volume_active_query_trials,
        "volume_active_at_query_rate": volume_active_query_trials / n,
        "volume_active_at_enforcement_trials": volume_active_enforcement_trials,
        "volume_active_at_enforcement_rate": volume_active_enforcement_trials / n,
        "volume_reconstruction_available": bool(volume_states),
        "volume_reconstructed_trigger_count": len(volume_reconstructed_triggers),
        "volume_runtime_trigger_count": len(volume_runtime_triggers),
        "volume_trigger_mismatch": bool(volume_states) and bool(volume_runtime_triggers) and bool(volume_alignment["mismatch"]),
        "b5_reconstruction_available": bool(reconstructed_states),
        "b5_reconstructed_state_count": len(reconstructed_states),
        "b5_reconstructed_trigger_count": len(reconstructed_triggers),
        "b5_runtime_trigger_count": len(runtime_triggers),
        "b5_trigger_mismatch": bool(reconstructed_states) and bool(trigger_alignment["mismatch"]),
        "b5_trigger_count_difference": trigger_alignment["count_difference"],
        "b5_trigger_runtime_unmatched_count": trigger_alignment["runtime_unmatched_count"],
        "b5_trigger_reconstructed_unmatched_count": trigger_alignment["reconstructed_unmatched_count"],
        "b5_trigger_max_nearest_error_ms": (
            trigger_alignment["max_nearest_error_ns"] / 1_000_000.0
            if trigger_alignment["max_nearest_error_ns"] is not None
            else None
        ),
        "b5_trigger_match_tolerance_ms": trigger_alignment["tolerance_ns"] / 1_000_000.0,
        "forged_tail_ingress_trials": forged_ingress_trials,
        "forged_tail_ingress_rate": forged_ingress_trials / n,
        "forged_tail_drop_trials": forged_drop_trials,
        "forged_tail_drop_rate": forged_drop_trials / n,
        "tc_injection_trials": tc_trials,
        "tc_injection_rate": tc_trials / n,
        "tcp_retry_trials": tcp_trials,
        "tcp_retry_rate": tcp_trials / n,
        "cache_before_hits": cache_before_hits,
        "cache_after_poison_trials": cache_after_poison,
        "cache_insertion_trials": cache_insertion_trials,
        "cache_insertion_rate": cache_insertion_trials / n if after_probe_status_trials == n else None,
        "cache_probe_valid_trials": cache_probe_valid_trials,
        "cache_probe_error_trials": cache_probe_error_trials,
        "cache_probe_status_trials": after_probe_status_trials,
        "cache_probe_valid_rate": cache_probe_valid_trials / n if after_probe_status_trials == n else None,
        "cache_probe_error_rate": cache_probe_error_trials / n if after_probe_status_trials == n else None,
        "cache_before_probe_valid_trials": cache_before_probe_valid_trials,
        "cache_before_probe_error_trials": cache_before_probe_error_trials,
        "cache_before_probe_status_trials": before_probe_status_trials,
        "cache_before_probe_valid_rate": cache_before_probe_valid_trials / n if before_probe_status_trials == n else None,
        "cache_before_probe_error_rate": cache_before_probe_error_trials / n if before_probe_status_trials == n else None,
        "cache_after_probe_valid_trials": cache_probe_valid_trials,
        "cache_after_probe_error_trials": cache_probe_error_trials,
        "cache_after_probe_valid_rate": cache_probe_valid_trials / n if after_probe_status_trials == n else None,
        "cache_after_probe_error_rate": cache_probe_error_trials / n if after_probe_status_trials == n else None,
        "cache_insertion_evidence_available": after_probe_status_trials == n,
        "cache_after_legitimate_trials": cache_after_legit,
        "latency_median_ms": statistics.median(latencies) if latencies else None,
        "latency_p95_ms": _quantile(latencies, 0.95),
        "latency_p99_ms": _quantile(latencies, 0.99),
        "query_latency_median_ms": statistics.median(query_latencies) if query_latencies else None,
        "query_latency_p95_ms": _quantile(query_latencies, 0.95),
        "query_latency_p99_ms": _quantile(query_latencies, 0.99),
        "cpu_percent_median": statistics.median(cpu_values) if (cpu_values := _stats_percentages(resource_rows, "CPUPerc")) else None,
        "cpu_percent_p95": _quantile(cpu_values, 0.95) if cpu_values else None,
        "memory_percent_median": statistics.median(memory_values) if (memory_values := _stats_percentages(resource_rows, "MemPerc")) else None,
        "memory_percent_p95": _quantile(memory_values, 0.95) if memory_values else None,
        "occupancy_target_pps": occupancy_target_pps,
        "observed_fragment_rate": observed_fragment_rate,
        "status_counts": dict(Counter(str(row.get("status")) for row in trials)),
        "root_cause_counts": dict(root_causes),
        "per_trial": per_trial,
        "cache_probe_rows": len(cache),
        "ips_event_rows": len(ips),
        "auth_event_rows": len(auth),
        "attacker_event_rows": len(attacker),
    }
    return metrics
