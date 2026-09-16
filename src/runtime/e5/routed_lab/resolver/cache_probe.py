#!/usr/bin/env python3
"""Read-only cache probe service used for per-trial cache evidence."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path


LISTEN_IP = os.environ.get("CACHE_PROBE_IP", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("CACHE_PROBE_PORT", "10053"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
RUN_ID = os.environ.get("RUN_ID", "unregistered")
REP = int(os.environ.get("REP", "0"))
POLICY = os.environ.get("POLICY_MODE", "unregistered")
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _normalise_qname(value: str) -> str:
    return value.strip().rstrip(".").lower() + "."


def parse_cache_lookup_output(qname: str, stdout: str) -> list[str]:
    """Extract exact ``IN A`` answers from unbound-control output.

    ``unbound-control cache_lookup`` emits metadata (including ``msg``) and
    may repeat an RRset in its message cache section.  Only lines whose owner
    exactly matches *qname* and whose type is A are considered.
    """

    wanted = _normalise_qname(qname)
    answers: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("msg"):
            continue
        fields = stripped.split()
        if not fields:
            continue
        # Common forms are ``qname. IN A 203.0.113.80`` and
        # ``key: qname. IN A`` followed by ``data: 203.0.113.80``.
        ttl: int | None = None
        if fields[0].lower() == "key:" and len(fields) >= 4:
            owner = _normalise_qname(fields[1])
            if len(fields) >= 6 and fields[2].isdigit() and fields[3].upper() == "IN":
                ttl, rr_type, candidate = int(fields[2]), fields[4].upper(), fields[5]
            elif len(fields) >= 4 and fields[2].upper() == "IN":
                rr_type, candidate = fields[3].upper(), fields[4] if len(fields) >= 5 else ""
            else:
                rr_type = fields[3].upper()
                candidate = fields[4] if len(fields) >= 5 else ""
        else:
            owner = fields[0].rstrip(".").lower() + "."
            if len(fields) >= 5 and fields[1].isdigit() and fields[2].upper() == "IN":
                ttl, rr_type, candidate = int(fields[1]), fields[3].upper(), fields[4]
            elif len(fields) >= 4 and fields[1].upper() == "IN":
                rr_type, candidate = fields[2].upper(), fields[3]
            elif len(fields) >= 5 and fields[2].upper() == "IN":
                ttl = int(fields[1]) if fields[1].isdigit() else None
                rr_type, candidate = fields[3].upper(), fields[4]
            else:
                rr_type, candidate = "", ""
        if owner != wanted or rr_type != "A" or (ttl is not None and ttl <= 0) or not IPV4.match(candidate):
            continue
        if candidate not in answers:
            answers.append(candidate)
    # Support key/data records where data is on its own line.
    lines = [line.strip() for line in stdout.splitlines()]
    for index, line in enumerate(lines):
        if not line.lower().startswith("key:"):
            continue
        fields = line.split()
        if len(fields) < 4 or _normalise_qname(fields[1]) != wanted:
            continue
        rr_type = fields[3].upper() if fields[3].upper() in {"A", "AAAA"} else fields[4].upper() if len(fields) >= 5 else ""
        if rr_type != "A":
            continue
        ttl: int | None = None
        candidate: str | None = None
        for follow in lines[index + 1 : index + 8]:
            if follow.lower().startswith("key:"):
                break
            if follow.lower().startswith("data:"):
                values = follow.split(":", 1)[1].strip().split()
                candidate = values[0] if values else None
            elif follow.lower().startswith("ttl:"):
                value = follow.split(":", 1)[1].strip().split()
                if value and value[0].isdigit():
                    ttl = int(value[0])
            if candidate is not None and ttl is not None:
                break
        if candidate is not None and (ttl is None or ttl > 0) and IPV4.match(candidate) and candidate not in answers:
            answers.append(candidate)
    return answers


def cache_lookup(qname: str) -> dict:
    started = time.monotonic_ns()
    try:
        proc = subprocess.run(
            [
                "unbound-control",
                "-c",
                "/etc/unbound/unbound.conf",
                "cache_lookup",
                qname,
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        raw_stdout = proc.stdout or ""
        raw_stderr = proc.stderr or ""
        if proc.returncode != 0 or any(line.strip().lower().startswith("error ") for line in raw_stdout.splitlines()):
            return {
                "qname": qname,
                "probe_status": "error",
                "probe_valid": False,
                "cache_hit": None,
                "answers": [],
                "returncode": proc.returncode,
                "stdout": raw_stdout,
                "stderr": raw_stderr,
                "probe_duration_ns": time.monotonic_ns() - started,
            }
        answers = parse_cache_lookup_output(qname, raw_stdout)
        return {
            "qname": qname,
            "probe_status": "hit" if answers else "miss",
            "probe_valid": True,
            "cache_hit": bool(answers),
            "answers": answers,
            "returncode": proc.returncode,
            "stdout": raw_stdout,
            "stderr": raw_stderr,
            "probe_duration_ns": time.monotonic_ns() - started,
        }
    except Exception as exc:
        return {
            "qname": qname,
            "probe_status": "error",
            "probe_valid": False,
            "cache_hit": None,
            "answers": [],
            "returncode": None,
            "stdout": "",
            "stderr": repr(exc),
            "probe_duration_ns": time.monotonic_ns() - started,
            "probe_error": True,
        }


def append(row: dict) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "cache_events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def main() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "cache_events.jsonl").write_text("", encoding="utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    append(
        {
            "schema_version": 1,
            "event": "cache_probe_ready",
            "run_id": RUN_ID,
            "rep": REP,
            "policy": POLICY,
            "workload": WORKLOAD,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            "listen_port": LISTEN_PORT,
        }
    )
    while True:
        payload, source = sock.recvfrom(8192)
        received_ns = time.monotonic_ns()
        try:
            request = json.loads(payload.decode("utf-8"))
            phase = str(request["phase"])
            if phase not in {"before", "after"}:
                raise ValueError(f"unsupported cache probe phase: {phase}")
            qname = str(request["qname"])
            result = cache_lookup(qname)
            row = {
                "schema_version": 1,
                "event": f"cache_{phase}",
                "run_id": RUN_ID,
                "rep": REP,
                "policy": POLICY,
                "workload": WORKLOAD,
                "mono_ns": received_ns,
                "wall_ns": time.time_ns(),
                "trial_id": request.get("trial_id"),
                "qname": qname,
                "source_ip": source[0],
                "source_port": source[1],
                **result,
            }
            append(row)
            ack = {"ok": True, "qname": qname, "phase": phase, **result}
        except Exception as exc:
            ack = {"ok": False, "error": repr(exc)}
        sock.sendto(json.dumps(ack, sort_keys=True).encode("utf-8"), source)


if __name__ == "__main__":
    main()
