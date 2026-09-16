#!/usr/bin/env python3
"""Authoritative DNS service for E5.

UDP replies are deliberately fragmented.  TCP replies are always one
unfragmented DNS message so TC-based policies have a clean transport path.
The authoritative process never sends forged data; it only notifies the one
external attacker process after the legitimate first fragment is emitted.
"""

from __future__ import annotations

import json
import hashlib
import os
import random
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

from dnslib import DNSRecord
from scapy.all import send  # type: ignore

from wire import build_dns_answer, build_padded_dns_answer, build_tcp_frame, fragment_udp_payload


AUTH_IP = os.environ.get("AUTH_IP", "10.82.0.100")
RESOLVER_IP = os.environ.get("RESOLVER_IP", "10.81.0.53")
ATTACKER_IP = os.environ.get("ATTACKER_IP", "10.82.0.200")
NOTIFY_PORT = int(os.environ.get("NOTIFY_PORT", "9999"))
FRAGSIZE = int(os.environ.get("FRAGSIZE", "40"))
BANK_REAL_IP = os.environ.get("BANK_REAL_IP", "203.0.113.80")
ZONE_IP = os.environ.get("ZONE_IP", "198.51.100.10")
SCHEDULE_PATH = Path(os.environ.get("SCHEDULE_FILE", "/app/schedule.json"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
RUN_ID = os.environ.get("RUN_ID", "unregistered")
REP = int(os.environ.get("REP", "0"))
POLICY = os.environ.get("POLICY_MODE", "unregistered")
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
TAIL_DELAY = float(os.environ.get("AUTH_TAIL_DELAY_SECONDS", "0.25"))
FRAGMENT_MODE = os.environ.get("AUTH_FRAGMENT_MODE", "crafted").strip().lower()
PMTUD_MIN_UDP = int(os.environ.get("AUTH_PMTUD_MIN_UDP", "1200"))
PMTUD_ICMP_WAIT = float(os.environ.get("AUTH_PMTUD_ICMP_WAIT_S", "0.15"))
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DONT = getattr(socket, "IP_PMTUDISC_DONT", 0)


def normalize_qname(value: str) -> str:
    name = value.strip().lower()
    return name if name.endswith(".") else name + "."


def trial_id_from_qname(qname: str) -> str | None:
    labels = normalize_qname(qname).split(".", 1)[0]
    parts = labels.split("-")
    return labels if len(parts) == 3 and parts[0].startswith("r") and parts[1].startswith("t") else None


class EventLog:
    def __init__(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path = LOG_DIR / "auth_events.jsonl"
        self.lock = threading.Lock()
        self.path.write_text("", encoding="utf-8")

    def write(self, event: str, **fields: Any) -> None:
        qname = fields.get("qname")
        row = {
            "schema_version": 1,
            "event": event,
            "run_id": RUN_ID,
            "rep": REP,
            "policy": POLICY,
            "workload": WORKLOAD,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            "trial_id": trial_id_from_qname(qname) if isinstance(qname, str) else None,
            **fields,
        }
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def load_schedule() -> dict[str, dict[str, Any]]:
    if not SCHEDULE_PATH.exists():
        return {}
    payload = json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))
    return {normalize_qname(row["qname"]): row for row in payload.get("trials", [])}


def is_bank(qname: str) -> bool:
    name = normalize_qname(qname).rstrip(".")
    return name == "bank.com" or name.endswith(".bank.com")


class AuthoritativeServer:
    def __init__(self) -> None:
        self.log = EventLog()
        self.schedule = load_schedule()
        self.rng = random.Random(f"{RUN_ID}:{REP}:{WORKLOAD}:fallback")
        self.notify_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock: socket.socket | None = None

    def schedule_row(self, qname: str) -> dict[str, Any] | None:
        return self.schedule.get(normalize_qname(qname))

    def ipid_for(self, qname: str) -> int:
        row = self.schedule_row(qname)
        if row is not None and row.get("auth_ipid") is not None:
            return int(row["auth_ipid"]) & 0xFFFF
        return self.rng.randrange(1, 65536)

    def notify_attacker(self, *, qname: str, ipid: int, dport: int, dns_id: int, dns_len: int, phase: str | None = None) -> None:
        payload = {
            "run_id": RUN_ID,
            "rep": REP,
            "workload": WORKLOAD,
            "qname": normalize_qname(qname),
            "ipid": ipid,
            "dport": dport,
            "dns_id": dns_id,
            "dns_len": dns_len,
        }
        if phase:
            payload["phase"] = phase
        self.notify_sock.sendto(json.dumps(payload).encode("utf-8"), (ATTACKER_IP, NOTIFY_PORT))
        self.log.write("attacker_notify", qname=qname, ipid=ipid, dport=dport, dns_id=dns_id, dns_len=dns_len, phase=phase)

    def respond_udp(self, payload: bytes, source: tuple[str, int]) -> None:
        src_ip, src_port = source
        try:
            request = DNSRecord.parse(payload)
        except Exception as exc:
            self.log.write("udp_parse_error", source_ip=src_ip, source_port=src_port, error=repr(exc))
            return
        qname = normalize_qname(str(request.q.qname))
        self.log.write("udp_receive", qname=qname, source_ip=src_ip, source_port=src_port, dns_id=int(request.header.id))
        answer_ip = BANK_REAL_IP if is_bank(qname) else ZONE_IP
        if FRAGMENT_MODE == "pmtud":
            self.respond_udp_pmtud(request, qname, src_port, answer_ip)
            return
        body = build_dns_answer(request, answer_ip)
        ipid = self.ipid_for(qname)
        fragments = fragment_udp_payload(
            src=AUTH_IP,
            dst=RESOLVER_IP,
            ipid=ipid,
            dst_port=src_port,
            body=body,
            fragsize=FRAGSIZE,
        )
        if is_bank(qname) and len(fragments) < 2:
            raise RuntimeError("bank.com response did not fragment; increase DNS answer size or lower FRAGSIZE")
        send(fragments[0], verbose=0)
        self.log.write(
            "legitimate_first_fragment_send",
            qname=qname,
            ipid=ipid,
            dport=src_port,
            dns_id=int(request.header.id),
            dns_len=len(body),
            fragment_count=len(fragments),
            packet_sha256=hashlib.sha256(bytes(fragments[0])).hexdigest(),
            dns_body_sha256=hashlib.sha256(body).hexdigest(),
        )
        row = self.schedule_row(qname) or {}
        attack_tail = bool(row.get("attack_tail", False))
        if attack_tail:
            self.notify_attacker(qname=qname, ipid=ipid, dport=src_port, dns_id=int(request.header.id), dns_len=len(body))
        delay = float(row.get("tail_delay_s", TAIL_DELAY))
        if delay > 0:
            time.sleep(delay)
        for fragment in fragments[1:]:
            send(fragment, verbose=0)
        self.log.write(
            "legitimate_tail_fragment_send",
            qname=qname,
            ipid=ipid,
            dport=src_port,
            dns_id=int(request.header.id),
            fragment_count=max(0, len(fragments) - 1),
            delayed_s=delay,
            packet_sha256=[hashlib.sha256(bytes(fragment)).hexdigest() for fragment in fragments[1:]],
            dns_body_sha256=hashlib.sha256(body).hexdigest(),
        )

    def respond_udp_pmtud(self, request: DNSRecord, qname: str, src_port: int, answer_ip: str) -> None:
        if self.udp_sock is None:
            raise RuntimeError("PMTUD UDP socket is not bound")
        body = build_padded_dns_answer(request, answer_ip, min_size=PMTUD_MIN_UDP)
        dns_id = int(request.header.id)
        self.udp_sock.sendto(body, (RESOLVER_IP, src_port))
        self.log.write(
            "pmtud_probe_send",
            qname=qname,
            dport=src_port,
            dns_id=dns_id,
            dns_len=len(body),
            fragment_mode="pmtud",
        )
        self.notify_attacker(qname=qname, ipid=0, dport=src_port, dns_id=dns_id, dns_len=len(body), phase="pmtud_probe")
        if PMTUD_ICMP_WAIT > 0:
            time.sleep(PMTUD_ICMP_WAIT)
        self.udp_sock.sendto(body, (RESOLVER_IP, src_port))
        self.log.write(
            "pmtud_data_send",
            qname=qname,
            dport=src_port,
            dns_id=dns_id,
            dns_len=len(body),
            fragment_mode="pmtud",
        )
        row = self.schedule_row(qname) or {}
        if bool(row.get("attack_tail", False)):
            self.notify_attacker(qname=qname, ipid=0, dport=src_port, dns_id=dns_id, dns_len=len(body), phase="forged_tail")
        delay = float(row.get("tail_delay_s", TAIL_DELAY))
        if delay > 0:
            time.sleep(delay)
        self.log.write(
            "legitimate_tail_fragment_send",
            qname=qname,
            ipid=0,
            dport=src_port,
            dns_id=dns_id,
            fragment_count=None,
            delayed_s=delay,
            fragment_mode="pmtud",
            dns_body_sha256=hashlib.sha256(body).hexdigest(),
        )

    def respond_tcp(self, conn: socket.socket, source: tuple[str, int]) -> None:
        src_ip, src_port = source
        header = self._read_exact(conn, 2)
        if header is None:
            return
        length = struct.unpack("!H", header)[0]
        payload = self._read_exact(conn, length)
        if payload is None:
            self.log.write("tcp_incomplete", source_ip=src_ip, source_port=src_port, expected=length)
            return
        try:
            request = DNSRecord.parse(payload)
        except Exception as exc:
            self.log.write("tcp_parse_error", source_ip=src_ip, source_port=src_port, error=repr(exc))
            return
        qname = normalize_qname(str(request.q.qname))
        self.log.write("tcp_receive", qname=qname, source_ip=src_ip, source_port=src_port, dns_id=int(request.header.id))
        body = build_dns_answer(request, BANK_REAL_IP if is_bank(qname) else ZONE_IP)
        conn.sendall(build_tcp_frame(body))
        self.log.write("tcp_answer_send", qname=qname, source_ip=src_ip, source_port=src_port, dns_id=int(request.header.id), dns_len=len(body))

    @staticmethod
    def _read_exact(conn: socket.socket, size: int) -> bytes | None:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = conn.recv(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def run(self) -> None:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if FRAGMENT_MODE == "pmtud":
            udp.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
        udp.bind((AUTH_IP, 53))
        self.udp_sock = udp
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((AUTH_IP, 53))
        tcp.listen(64)
        self.log.write("auth_ready", udp_port=53, tcp_port=53, schedule_trials=len(self.schedule), fragment_mode=FRAGMENT_MODE)
        threading.Thread(target=self._udp_loop, args=(udp,), daemon=True).start()
        while True:
            conn, address = tcp.accept()
            thread = threading.Thread(target=self._tcp_worker, args=(conn, address), daemon=True)
            thread.start()

    def _udp_loop(self, sock: socket.socket) -> None:
        while True:
            payload, source = sock.recvfrom(65535)
            try:
                self.respond_udp(payload, source)
            except Exception as exc:  # keep evidence for a failed trial and continue serving later trials
                self.log.write("udp_response_error", source_ip=source[0], source_port=source[1], error=repr(exc))

    def _tcp_worker(self, conn: socket.socket, source: tuple[str, int]) -> None:
        try:
            self.respond_tcp(conn, source)
        except Exception as exc:
            self.log.write("tcp_response_error", source_ip=source[0], source_port=source[1], error=repr(exc))
        finally:
            conn.close()


if __name__ == "__main__":
    AuthoritativeServer().run()
