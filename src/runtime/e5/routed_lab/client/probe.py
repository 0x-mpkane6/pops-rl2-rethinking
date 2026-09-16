#!/usr/bin/env python3
"""Unique-qname resolver probe with cache-before/cache-after evidence."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any


RESOLVER_IP = os.environ.get("RESOLVER_IP", "10.81.0.53")
CACHE_PROBE_PORT = int(os.environ.get("CACHE_PROBE_PORT", "10053"))
QUERY_DEADLINE_S = float(os.environ.get("CLIENT_QUERY_DEADLINE_S", "2.0"))
SCHEDULE_PATH = Path(os.environ.get("SCHEDULE_FILE", "/app/schedule.json"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
CONTROL_DIR = Path(os.environ.get("CONTROL_DIR", "/app/control"))
REPLAY_START_PATH = CONTROL_DIR / "replay_start.json"
REPLAY_STARTED_PATH = CONTROL_DIR / "replay_started.json"
RUN_ID = os.environ.get("RUN_ID", "unregistered")
REP = int(os.environ.get("REP", "0"))
POLICY = os.environ.get("POLICY_MODE", "unregistered")
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
POISON_IP = os.environ.get("POISON_IP", "6.6.6.6")
LEGITIMATE_IP = os.environ.get("LEGITIMATE_IP", "203.0.113.80")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
APPEND_LOCK = threading.Lock()


def append(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with APPEND_LOCK, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def envelope(event: str, **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event": event,
        "run_id": RUN_ID,
        "rep": REP,
        "policy": POLICY,
        "workload": WORKLOAD,
        "mono_ns": time.monotonic_ns(),
        "wall_ns": time.time_ns(),
        **fields,
    }


def cache_probe(phase: str, trial_id: str, qname: str) -> dict[str, Any]:
    request = json.dumps({"phase": phase, "trial_id": trial_id, "qname": qname}).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    started = time.monotonic_ns()
    try:
        sock.sendto(request, (RESOLVER_IP, CACHE_PROBE_PORT))
        raw, source = sock.recvfrom(16384)
        reply = json.loads(raw.decode("utf-8"))
        reply.update({"probe_send_mono_ns": started, "probe_reply_mono_ns": time.monotonic_ns(), "probe_source": source[0]})
        return reply
    except Exception as exc:
        return {
            "ok": False,
            "probe_status": "error",
            "probe_valid": False,
            "cache_hit": None,
            "answers": [],
            "error": repr(exc),
            "probe_send_mono_ns": started,
            "probe_reply_mono_ns": time.monotonic_ns(),
            "qname": qname,
        }
    finally:
        sock.close()


def run_dig(qname: str) -> tuple[dict[str, Any], str]:
    started = time.monotonic_ns()
    try:
        proc = subprocess.run(
            [
                "dig",
                f"@{RESOLVER_IP}",
                qname,
                "+tries=1",
                "+time=2",
                "+noall",
                "+answer",
                "+comments",
            ],
            capture_output=True,
            text=True,
            timeout=max(QUERY_DEADLINE_S + 2.0, 4.0),
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        answers = []
        for line in proc.stdout.splitlines():
            fields = line.strip().split()
            if fields and IPV4.match(fields[-1]):
                answers.append(fields[-1])
        tc_seen = bool(re.search(r"(?:flags:.*\btc\b|truncated, retrying in TCP mode)", output, re.IGNORECASE | re.DOTALL))
        if POISON_IP in answers:
            status = "poisoned_answer"
        elif LEGITIMATE_IP in answers:
            status = "legitimate_answer"
        elif answers:
            status = "other_answer"
        elif proc.returncode != 0:
            status = "timeout_or_command_error"
        else:
            status = "no_answer"
        return (
            {
                "status": status,
                "returncode": proc.returncode,
                "answers": answers,
                "answer_ip": answers[0] if answers else None,
                "tc_seen": tc_seen,
                "query_start_mono_ns": started,
                "query_end_mono_ns": time.monotonic_ns(),
                "latency_ms": (time.monotonic_ns() - started) / 1_000_000.0,
                "stdout_b64": base64.b64encode(proc.stdout.encode("utf-8")).decode("ascii"),
                "stderr_b64": base64.b64encode(proc.stderr.encode("utf-8")).decode("ascii"),
            },
            output,
        )
    except Exception as exc:
        ended = time.monotonic_ns()
        return (
            {
                "status": "timeout_or_command_error",
                "returncode": None,
                "answers": [],
                "answer_ip": None,
                "tc_seen": False,
                "query_start_mono_ns": started,
                "query_end_mono_ns": ended,
                "latency_ms": (ended - started) / 1_000_000.0,
                "error": repr(exc),
                "stdout_b64": "",
                "stderr_b64": "",
            },
            repr(exc),
        )


def run_trial(
    row: dict[str, Any],
    before: dict[str, Any],
    launch_epoch: float,
    client_events_path: Path,
    honor_schedule: bool = True,
) -> dict[str, Any]:
    """Run one trial at its registered launch time.

    Queries are launched with a deterministic 10-ms stagger and allowed to
    remain in flight independently.  This is important for the RFC native
    drop baseline: a sequential client would let Unbound mark the sole stub
    server unavailable after the first few deliberately dropped responses,
    preventing later registered qnames from reaching the authoritative
    server.  The independent unit remains the recreated stack run; RFC
    cells use the registered launch schedule, while TC cells retain
    sequential resolver-query rounds.
    """

    trial_id = str(row["trial_id"])
    qname = str(row["qname"])
    if honor_schedule:
        target = launch_epoch + float(row.get("query_at_s", int(row.get("trial", 0)) * 0.01))
        while True:
            remaining = target - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(remaining, 0.01))

    query_start = time.monotonic_ns()
    append(client_events_path, envelope("client_query_send", trial_id=trial_id, qname=qname))
    result, raw_output = run_dig(qname)
    append(
        client_events_path,
        envelope(
            "client_answer_receive",
            trial_id=trial_id,
            qname=qname,
            status=result["status"],
            answer_ip=result["answer_ip"],
            tc_seen=result["tc_seen"],
        ),
    )
    after = cache_probe("after", trial_id, qname)
    after.setdefault("qname", qname)
    append(client_events_path, envelope("cache_after_reply", trial_id=trial_id, **after))
    end_ns = time.monotonic_ns()
    return envelope(
        "trial",
        trial_id=trial_id,
        qname=qname,
        trial=int(row["trial"]),
        client_query_start_mono_ns=query_start,
        client_answer_end_mono_ns=end_ns,
        client_latency_ms=(end_ns - query_start) / 1_000_000.0,
        cache_before=before,
        cache_after=after,
        **result,
        raw_output_b64=base64.b64encode(raw_output.encode("utf-8")).decode("ascii"),
    )


def _write_replay_start_marker(qname_count: int) -> None:
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    marker = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "rep": REP,
        "policy": POLICY,
        "workload": WORKLOAD,
        "cache_before_completed_mono_ns": time.monotonic_ns(),
        "qname_count": qname_count,
    }
    temporary = REPLAY_START_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, REPLAY_START_PATH)


def _wait_for_replay_started(timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while not REPLAY_STARTED_PATH.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"timed out waiting for attacker replay start: {REPLAY_STARTED_PATH}")
        time.sleep(0.05)
    try:
        marker = json.loads(REPLAY_STARTED_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid attacker replay start marker: {exc!r}") from exc
    if (
        marker.get("run_id") != RUN_ID
        or int(marker.get("rep", -1)) != REP
        or marker.get("policy") != POLICY
        or marker.get("workload") != WORKLOAD
    ):
        raise RuntimeError("attacker replay start marker identity mismatch")
    if not marker.get("replay_started_mono_ns"):
        raise RuntimeError("attacker replay start marker has no monotonic timestamp")
    return marker


def main() -> int:
    schedule = json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))
    trials = schedule.get("trials", [])
    if len({row["qname"] for row in trials}) != len(trials):
        raise RuntimeError("schedule contains duplicate qnames")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    trials_path = LOG_DIR / "trials.jsonl"
    client_events_path = LOG_DIR / "client_events.jsonl"
    trials_path.write_text("", encoding="utf-8")
    client_events_path.write_text("", encoding="utf-8")
    append(client_events_path, envelope("client_ready", trial_count=len(trials), deadline_s=QUERY_DEADLINE_S))

    # Legacy schedules retain their historical wall-clock warm-up.  Factorial
    # schedules release occupancy only after cache-before and then wait for a
    # measured three-second interval from the attacker's replay_started event.
    warmup_s = float(schedule.get("warmup_s", 0.0))
    factorial = "replay_start_mode" in schedule
    replay_started_mono_ns: int | None = None
    if warmup_s > 0 and not factorial:
        append(client_events_path, envelope("client_wait_for_replay", warmup_s=warmup_s))
        time.sleep(warmup_s)
        append(client_events_path, envelope("client_replay_window_open"))

    before_by_trial: dict[str, dict[str, Any]] = {}
    for row in trials:
        trial_id = str(row["trial_id"])
        qname = str(row["qname"])
        before = cache_probe("before", trial_id, qname)
        before.setdefault("qname", qname)
        before_by_trial[trial_id] = before
        append(client_events_path, envelope("cache_before_reply", trial_id=trial_id, **before))

    if factorial:
        _write_replay_start_marker(len(trials))
        append(client_events_path, envelope("replay_start_requested", qname_count=len(trials)))
        replay_started = _wait_for_replay_started(timeout_s=max(30.0, warmup_s + 10.0))
        replay_started_mono_ns = int(replay_started["replay_started_mono_ns"])
        append(client_events_path, envelope("replay_started_observed", replay_started_mono_ns=replay_started_mono_ns))
        target = replay_started_mono_ns / 1_000_000_000.0 + warmup_s
        while time.monotonic() < target:
            time.sleep(min(target - time.monotonic(), 0.05))
        append(client_events_path, envelope("client_replay_window_open", warmup_s=warmup_s, replay_started_mono_ns=replay_started_mono_ns))

    records: list[dict[str, Any]] = []
    if POLICY == "RFC_DROP_NATIVE":
        # A sequential native-drop replay makes Unbound's single stub server
        # enter its upstream-failure circuit after a few timeouts.  The
        # registered RFC cells therefore launch the same qname schedule in a
        # deterministic 10-ms stagger, while each query is allowed to remain
        # in flight.  This preserves 50 fully observable trials without
        # changing B1's TC fallback timing behavior.
        # The registered query offsets are relative to replay_started.  This
        # keeps the first query exactly three seconds after occupancy begins,
        # even though the client waits for the start marker before launching.
        launch_epoch = (replay_started_mono_ns / 1_000_000_000.0) if replay_started_mono_ns is not None else time.monotonic()
        with ThreadPoolExecutor(max_workers=max(1, len(trials))) as executor:
            futures = {
                executor.submit(run_trial, row, before_by_trial[str(row["trial_id"])], launch_epoch, client_events_path): row
                for row in trials
            }
            for future in as_completed(futures):
                records.append(future.result())
    else:
        # TC-based paths are intentionally replayed as resolver query rounds:
        # Unbound's TC fallback is validated with one active round at a time.
        for row in trials:
            records.append(
                run_trial(
                    row,
                    before_by_trial[str(row["trial_id"])],
                    time.monotonic(),
                    client_events_path,
                    honor_schedule=False,
                )
            )

    for record in sorted(records, key=lambda value: int(value.get("trial", 0))):
        append(trials_path, record)
        print(f"{record['trial_id']} {record['status']} {record['answer_ip'] or '-'} {record['latency_ms']:.3f}ms", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
