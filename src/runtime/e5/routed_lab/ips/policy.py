#!/usr/bin/env python3
"""NFQUEUE policy plane for the E5 routed resolver experiment."""

from __future__ import annotations

import json
import hashlib
import os
import re
import signal
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from typing import NamedTuple

from netfilterqueue import NetfilterQueue  # type: ignore
from scapy.all import IP, UDP, send, sniff  # type: ignore

from e5_lib import Policy, policy_decision, ratio_meets_threshold, raw_shannon_entropy
from ips.packet_logic import PacketMeta, build_tc_response, parse_packet


class WindowStats(NamedTuple):
    samples: int
    entropy: float
    unique_ratio: float
    b5_active: bool
    b2_active: bool


# Registered and locked for E5.  These are constants rather than
# environment overrides so a runtime invocation cannot silently retune E3's
# operating point.
WINDOW_SECONDS = 2.0
MIN_SAMPLES = 8
ENTROPY_THRESHOLD = 6.0
UNIQUE_RATIO_THRESHOLD = 0.90
QUEUE_NUM = int(os.environ.get("NFQUEUE_NUM", "5"))
AUTH_IP = os.environ.get("AUTH_IP", "10.82.0.100")
RESOLVER_IP = os.environ.get("RESOLVER_IP", "10.81.0.53")
INSIDE_IP = os.environ.get("IPS_INSIDE_IP", "10.81.0.1")
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
TRIAL_RE = re.compile(r"(?:^|\.)r(?P<rep>\d+)-t(?P<trial>\d+)-(?P<nonce>[0-9a-f]+)\.bank\.com\.?$")
RAW_OBSERVER_WAIT_SECONDS = 0.15
RAW_DUPLICATE_WINDOW_SECONDS = 0.5
WINDOW_NS = int(WINDOW_SECONDS * 1_000_000_000)


class RoutedPolicy:
    def __init__(self) -> None:
        try:
            self.policy = Policy(os.environ.get("POLICY_MODE", Policy.B0_OFF.value))
        except ValueError as exc:
            raise SystemExit(f"unsupported POLICY_MODE: {exc}") from exc
        self.run_id = os.environ.get("RUN_ID", "unregistered")
        self.rep = int(os.environ.get("REP", "0"))
        self.workload = WORKLOAD
        self.events_path = LOG_DIR / "ips_events.jsonl"
        self.state_path = LOG_DIR / "detector_state.json"
        self.ready_path = LOG_DIR / "ips_ready.json"
        self.query_map: dict[tuple[int, int], str] = {}
        self.datagram_map: dict[tuple[str, str, int], str] = {}
        self.datagram_last_seen: dict[tuple[str, str, int], float] = {}
        self.events: deque[tuple[int, int]] = deque()
        self.state_lock = threading.Lock()
        self.active_lock = threading.Lock()
        self.event_lock = threading.Lock()
        self.raw_condition = threading.Condition(self.state_lock)
        self.raw_fragment_keys: set[tuple[str, str, int]] = set()
        self.raw_fragment_content_seen: dict[str, float] = {}
        self.raw_observer_started = threading.Event()
        self.raw_observer_error = False
        self.events_handle = None
        self.event_count = 0
        self.ready = False
        self.last_b5_active = False
        self.last_b2_active = False

    def append(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, sort_keys=True, allow_nan=False) + "\n"
        with self.event_lock:
            if path == self.events_path and self.events_handle is not None:
                self.events_handle.write(encoded)
                self.event_count += 1
                if self.event_count % 64 == 0:
                    self.events_handle.flush()
            else:
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(encoded)

    def event(self, event: str, **fields: object) -> None:
        row = {
            "schema_version": 1,
            "event": event,
            "run_id": self.run_id,
            "rep": self.rep,
            "policy": self.policy.value,
            "workload": self.workload,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            **fields,
        }
        qname = fields.get("qname")
        if isinstance(qname, str):
            match = TRIAL_RE.search(qname.rstrip("."))
            row["trial_id"] = (
                f"r{match.group('rep')}-t{match.group('trial')}-{match.group('nonce')}"
                if match
                else None
            )
        else:
            row["trial_id"] = None
        self.append(self.events_path, row)

    def _cleanup_locked(self, now_ns: int) -> None:
        cutoff_ns = now_ns - WINDOW_NS
        while self.events and self.events[0][0] < cutoff_ns:
            self.events.popleft()
        cutoff_s = now_ns / 1_000_000_000.0 - WINDOW_SECONDS
        old = [key for key, seen in self.datagram_last_seen.items() if seen < cutoff_s]
        for key in old:
            self.datagram_last_seen.pop(key, None)
            self.datagram_map.pop(key, None)

    def cleanup(self, now_ns: int) -> None:
        with self.state_lock:
            self._cleanup_locked(now_ns)

    def _b5_state_locked(self, now_ns: int) -> WindowStats:
        self._cleanup_locked(now_ns)
        ipids = [ipid for _, ipid in self.events]
        n = len(ipids)
        entropy = raw_shannon_entropy(ipids)
        unique_count = len(set(ipids))
        unique_ratio = unique_count / n if n else 0.0
        b5_active = n >= MIN_SAMPLES and entropy >= ENTROPY_THRESHOLD and ratio_meets_threshold(
            unique_count,
            n,
            UNIQUE_RATIO_THRESHOLD,
        )
        return WindowStats(n, entropy, unique_ratio, b5_active, n >= MIN_SAMPLES)

    def b5_state(self, now_ns: int | None = None) -> WindowStats:
        reference_ns = time.monotonic_ns() if now_ns is None else now_ns
        with self.state_lock:
            return self._b5_state_locked(reference_ns)

    def _emit_state(
        self,
        reason: str,
        *,
        stats: WindowStats,
        state_mono_ns: int,
        previous_b5_active: bool,
        previous_b2_active: bool,
    ) -> WindowStats:
        payload = {
            "schema_version": 1,
            "run_id": self.run_id,
            "rep": self.rep,
            "policy": self.policy.value,
            "workload": self.workload,
            "reason": reason,
            "mono_ns": state_mono_ns,
            "wall_ns": time.time_ns(),
            "samples": stats.samples,
            "entropy": stats.entropy,
            "unique_ratio": stats.unique_ratio,
            "min_samples": MIN_SAMPLES,
            "entropy_threshold": ENTROPY_THRESHOLD,
            "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
            "b5_active": stats.b5_active,
            "b2_active": stats.b2_active,
        }
        self.state_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        self.event(
            "detector_state",
            reason=reason,
            samples=stats.samples,
            entropy=stats.entropy,
            unique_ratio=stats.unique_ratio,
            b5_active=stats.b5_active,
            b2_active=stats.b2_active,
            mono_ns=state_mono_ns,
        )
        if stats.b5_active and not previous_b5_active:
            self.event(
                "detector_trigger",
                reason=reason,
                samples=stats.samples,
                entropy=stats.entropy,
                unique_ratio=stats.unique_ratio,
                mono_ns=state_mono_ns,
            )
        if stats.b2_active and not previous_b2_active:
            self.event(
                "volume_trigger",
                reason=reason,
                samples=stats.samples,
                entropy=stats.entropy,
                unique_ratio=stats.unique_ratio,
                mono_ns=state_mono_ns,
            )
        return stats

    def write_state(
        self,
        reason: str,
        *,
        stats: WindowStats | None = None,
        state_mono_ns: int | None = None,
    ) -> WindowStats:
        timestamp = time.monotonic_ns() if state_mono_ns is None else state_mono_ns
        with self.active_lock:
            values = self.b5_state(now_ns=timestamp) if stats is None else stats
            previous_b5 = self.last_b5_active
            previous_b2 = self.last_b2_active
            self.last_b5_active = values.b5_active
            self.last_b2_active = values.b2_active
            return self._emit_state(
                reason,
                stats=values,
                state_mono_ns=timestamp,
                previous_b5_active=previous_b5,
                previous_b2_active=previous_b2,
            )

    def _write_state_if_changed(
        self,
        reason: str,
        *,
        stats: WindowStats,
        state_mono_ns: int,
    ) -> WindowStats:
        with self.active_lock:
            if stats.b5_active == self.last_b5_active and stats.b2_active == self.last_b2_active:
                return stats
            previous_b5 = self.last_b5_active
            previous_b2 = self.last_b2_active
            self.last_b5_active = stats.b5_active
            self.last_b2_active = stats.b2_active
            return self._emit_state(
                reason,
                stats=stats,
                state_mono_ns=state_mono_ns,
                previous_b5_active=previous_b5,
                previous_b2_active=previous_b2,
            )

    def observe_fragment(
        self,
        *,
        src: str,
        dst: str,
        ipid: int,
        offset: int,
        more_fragments: bool,
        payload_sha256: str,
        capture_source: str,
        capture_iface: str | None = None,
    ) -> WindowStats:
        observed_mono_ns = time.monotonic_ns()
        with self.active_lock:
            with self.state_lock:
                self.events.append((observed_mono_ns, ipid))
                self.raw_fragment_keys.add((src, dst, ipid))
                self.raw_condition.notify_all()
                stats = self._b5_state_locked(observed_mono_ns)
            state_changed = stats.b5_active != self.last_b5_active or stats.b2_active != self.last_b2_active
            previous_b5 = self.last_b5_active
            previous_b2 = self.last_b2_active
            if state_changed:
                self.last_b5_active = stats.b5_active
                self.last_b2_active = stats.b2_active
            self.event(
                "fragment_observed",
                mono_ns=observed_mono_ns,
                src=src,
                dst=dst,
                ipid=ipid,
                offset=offset,
                more_fragments=more_fragments,
                payload_sha256=payload_sha256,
                capture_source=capture_source,
                capture_iface=capture_iface,
            )
            # Raw evidence is retained for every fragment, but rewriting
            # detector_state.json for every packet would throttle the 200
            # fragments/s workload. Persist state only when a Boolean
            # detector state changes; the independent validator rebuilds
            # every intermediate state from fragment_observed rows.
            if not state_changed:
                return stats
            return self._emit_state(
                "noninitial_fragment",
                stats=stats,
                state_mono_ns=observed_mono_ns,
                previous_b5_active=previous_b5,
                previous_b2_active=previous_b2,
            )

    def observe_noninitial(self, meta: PacketMeta, payload_sha256: str) -> WindowStats:
        return self.observe_fragment(
            src=meta.src,
            dst=meta.dst,
            ipid=meta.ipid,
            offset=meta.offset,
            more_fragments=meta.more_fragments,
            payload_sha256=payload_sha256,
            capture_source="nfqueue",
        )

    def raw_capture_packet(self, packet) -> None:  # noqa: ANN001
        if IP not in packet:
            return
        ip = packet[IP]
        src, dst = str(ip.src), str(ip.dst)
        if src not in {AUTH_IP, os.environ.get("ATTACKER_IP", "10.82.0.200")} or dst != RESOLVER_IP:
            return
        offset = int(ip.frag) * 8
        if offset <= 0:
            return
        payload_sha256 = hashlib.sha256(bytes(ip)).hexdigest()
        content_sha256 = hashlib.sha256(bytes(ip.payload)).hexdigest()
        # Docker's two veth captures can expose the same raw fragment on both
        # interfaces, with TTL/checksum rewritten on the forwarded copy.
        # Deduplicate invariant fragment payload content for B5 while keeping
        # the full packet hash for packet-path correlation and both PCAPs.
        now = time.monotonic()
        content_key = f"{src}|{dst}|{int(ip.id)}|{offset}|{content_sha256}"
        with self.state_lock:
            previous = self.raw_fragment_content_seen.get(content_key)
            if previous is not None and now - previous < RAW_DUPLICATE_WINDOW_SECONDS:
                return
            self.raw_fragment_content_seen[content_key] = now
            stale = [
                key
                for key, seen in self.raw_fragment_content_seen.items()
                if now - seen >= max(2.0, RAW_DUPLICATE_WINDOW_SECONDS)
            ]
            for key in stale:
                self.raw_fragment_content_seen.pop(key, None)
        self.observe_fragment(
            src=src,
            dst=dst,
            ipid=int(ip.id),
            offset=offset,
            more_fragments=bool(int(ip.flags) & 0x1),
            payload_sha256=payload_sha256,
            capture_source="af_packet",
            capture_iface=str(getattr(packet, "sniffed_on", "unknown")),
        )

    def raw_capture_loop(self, interfaces: list[str]) -> None:
        try:
            self.raw_observer_started.set()
            self.event("raw_observer_ready", interfaces=interfaces)
            sniff(iface=interfaces, store=False, prn=self.raw_capture_packet, filter="ip")
        except Exception as exc:  # pragma: no cover - exercised in Docker preflight
            self.raw_observer_error = True
            self.event("raw_observer_error", error=repr(exc), interfaces=interfaces)

    def wait_for_raw_tail(self, key: tuple[str, str, int]) -> bool:
        deadline = time.monotonic() + RAW_OBSERVER_WAIT_SECONDS
        with self.raw_condition:
            while key not in self.raw_fragment_keys:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.raw_condition.wait(timeout=remaining)
            return key in self.raw_fragment_keys

    @staticmethod
    def dns_body_sha256(payload: bytes) -> str | None:
        try:
            packet = IP(payload)
            if UDP in packet and int(packet.frag) == 0:
                return hashlib.sha256(bytes(packet[UDP].payload)).hexdigest()
        except Exception:
            return None
        return None

    def inside_iface(self) -> str:
        configured = os.environ.get("INSIDE_IFACE")
        if configured:
            return configured
        output = subprocess.run(["ip", "-o", "-4", "addr", "show"], check=True, capture_output=True, text=True).stdout
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[3].split("/")[0] == INSIDE_IP:
                return fields[1]
        raise RuntimeError(f"could not find interface for {INSIDE_IP}")

    def inject_tc(self, meta: PacketMeta, qname: str | None) -> bool:
        if not qname or meta.txid is None or meta.dst_port is None:
            self.event("tc_injection_failed", reason="missing_dns_metadata", qname=qname, txid=meta.txid, dst_port=meta.dst_port)
            return False
        payload = build_tc_response(
            qname=qname,
            txid=meta.txid,
            resolver_port=meta.dst_port,
            auth_ip=AUTH_IP,
            resolver_ip=RESOLVER_IP,
            ipid=meta.ipid,
        )
        try:
            send(IP(payload), iface=self.inside_iface(), verbose=0)
        except Exception as exc:
            self.event("tc_injection_failed", reason="send_error", error=repr(exc), qname=qname, txid=meta.txid, dst_port=meta.dst_port)
            return False
        self.event("tc_injected", qname=qname, txid=meta.txid, resolver_port=meta.dst_port, packet_len=len(payload))
        return True

    def record_query(self, meta: PacketMeta) -> None:
        if meta.txid is None or meta.src_port is None or not meta.qname:
            self.event("query_unmapped", src=meta.src, dst=meta.dst, txid=meta.txid, src_port=meta.src_port)
            return
        self.query_map[(meta.src_port, meta.txid)] = meta.qname
        self.event("resolver_query", qname=meta.qname, txid=meta.txid, resolver_port=meta.src_port, auth_port=meta.dst_port)

    def handle(self, nfq_packet) -> None:  # noqa: ANN001
        raw = nfq_packet.get_payload()
        payload_sha256 = hashlib.sha256(raw).hexdigest()
        try:
            meta = parse_packet(raw, auth_ip=AUTH_IP, resolver_ip=RESOLVER_IP, query_map=self.query_map)
        except Exception as exc:
            self.event("packet_parse_error", error=repr(exc), payload_len=len(raw))
            # Fail closed on an unparseable queued packet.  Accepting here
            # would create an implicit fail-open path outside the registered
            # policy semantics.
            self.event("packet_verdict", verdict="drop", reason="parse_error", payload_sha256=payload_sha256)
            nfq_packet.drop()
            return

        if meta.is_query:
            self.record_query(meta)
            nfq_packet.accept()
            return

        key = (meta.src, meta.dst, meta.ipid)
        qname = meta.qname or self.datagram_map.get(key)
        reassembled_dns_response = meta.is_dns_response and meta.offset == 0 and not meta.more_fragments
        raw_tail_seen = self.wait_for_raw_tail(key) if reassembled_dns_response else False
        dns_body_sha256 = self.dns_body_sha256(raw)
        if meta.is_dns_response:
            self.event(
                "packet_ingress",
                qname=qname,
                src=meta.src,
                dst=meta.dst,
                ipid=meta.ipid,
                offset=meta.offset,
                more_fragments=meta.more_fragments,
                txid=meta.txid,
                dst_port=meta.dst_port,
                payload_sha256=payload_sha256,
                dns_body_sha256=dns_body_sha256,
                reassembled=reassembled_dns_response,
                raw_tail_seen=raw_tail_seen,
            )
            self.datagram_last_seen[key] = time.monotonic()
            if meta.qname:
                self.datagram_map[key] = meta.qname
                qname = meta.qname

        stats = self.b5_state()
        if meta.is_noninitial_fragment:
            stats = self.observe_noninitial(meta, payload_sha256)

        if meta.is_dns_response and (meta.is_first_fragment or meta.is_noninitial_fragment or reassembled_dns_response):
            if self.policy is Policy.PREARM_TAIL_DROP and reassembled_dns_response:
                # The kernel has already reassembled the datagram before the
                # FORWARD hook.  Drop the completed datagram once the raw
                # observer has seen its non-initial tail; this is the routed
                # equivalent of the pilot's tail-drop check.
                action = policy_decision(
                    self.policy,
                    is_dns_fragment=True,
                    offset=40 if raw_tail_seen else 0,
                    b5_active=stats.b5_active,
                    b2_active=stats.b2_active,
                )
            else:
                action = policy_decision(
                    self.policy,
                    is_dns_fragment=True,
                    offset=meta.offset,
                    b5_active=stats.b5_active,
                    b2_active=stats.b2_active,
                )
            self.event(
                "packet_decision",
                qname=qname,
                src=meta.src,
                dst=meta.dst,
                ipid=meta.ipid,
                offset=meta.offset,
                more_fragments=meta.more_fragments,
                verdict=action.verdict,
                reason=action.reason,
                b5_active=stats.b5_active,
                b2_active=stats.b2_active,
                payload_sha256=payload_sha256,
                dns_body_sha256=dns_body_sha256,
                reassembled=reassembled_dns_response,
                raw_tail_seen=raw_tail_seen,
            )
            if action.verdict == "inject_tc_drop":
                injected = self.inject_tc(meta, qname)
                self.event(
                    "enforcement_action",
                    qname=qname,
                    action="tc_inject_and_drop",
                    injection_ok=injected,
                    offset=meta.offset,
                    payload_sha256=payload_sha256,
                    dns_body_sha256=dns_body_sha256,
                    reassembled=reassembled_dns_response,
                    raw_tail_seen=raw_tail_seen,
                )
                self.event("packet_verdict", qname=qname, verdict="drop", injection_ok=injected, offset=meta.offset, payload_sha256=payload_sha256, dns_body_sha256=dns_body_sha256, reassembled=reassembled_dns_response, raw_tail_seen=raw_tail_seen)
                nfq_packet.drop()
                return
            if action.verdict in {"drop_tail", "drop_fragment"}:
                self.event(
                    "enforcement_action",
                    qname=qname,
                    action=action.verdict,
                    injection_ok=False,
                    offset=meta.offset,
                    payload_sha256=payload_sha256,
                    dns_body_sha256=dns_body_sha256,
                    reassembled=reassembled_dns_response,
                    raw_tail_seen=raw_tail_seen,
                )
                self.event("packet_verdict", qname=qname, verdict="drop", injection_ok=False, offset=meta.offset, payload_sha256=payload_sha256, dns_body_sha256=dns_body_sha256, reassembled=reassembled_dns_response, raw_tail_seen=raw_tail_seen)
                nfq_packet.drop()
                return

        if meta.is_dns_response or meta.is_noninitial_fragment:
            self.event("packet_verdict", qname=qname, src=meta.src, dst=meta.dst, ipid=meta.ipid, offset=meta.offset, verdict="forward", payload_sha256=payload_sha256, dns_body_sha256=dns_body_sha256, reassembled=reassembled_dns_response, raw_tail_seen=raw_tail_seen)
        nfq_packet.accept()

    def run(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.events_path.write_text("", encoding="utf-8")
        self.state_path.write_text("", encoding="utf-8")
        self.events_handle = self.events_path.open("a", encoding="utf-8")
        self.event("ips_start", auth_ip=AUTH_IP, resolver_ip=RESOLVER_IP, inside_ip=INSIDE_IP, queue_num=QUEUE_NUM)
        self.write_state("startup")
        queue = NetfilterQueue()
        self.queue = queue
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        queue.bind(QUEUE_NUM, self.handle)
        interfaces = [
            os.environ.get("OUTSIDE_IFACE", ""),
            os.environ.get("INSIDE_IFACE", ""),
        ]
        interfaces = [iface for iface in interfaces if iface]
        if len(interfaces) != 2:
            raise RuntimeError("raw fragment observer requires two IPS interfaces")
        threading.Thread(target=self.raw_capture_loop, args=(interfaces,), daemon=True).start()
        if not self.raw_observer_started.wait(timeout=5.0):
            raise RuntimeError("raw fragment observer did not start")
        if self.raw_observer_error:
            raise RuntimeError("raw fragment observer failed during startup")
        self.ready = True
        self.ready_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": self.run_id,
                    "rep": self.rep,
                    "policy": self.policy.value,
                    "workload": self.workload,
                    "queue_num": QUEUE_NUM,
                    "window_seconds": WINDOW_SECONDS,
                    "min_samples": MIN_SAMPLES,
                    "entropy_threshold": ENTROPY_THRESHOLD,
                    "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
                    "raw_observer": "AF_PACKET",
                    "raw_observer_duplicate_window_seconds": RAW_DUPLICATE_WINDOW_SECONDS,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.event("ips_ready", queue_num=QUEUE_NUM)

        def tick_loop() -> None:
            while self.ready:
                time.sleep(0.25)
                try:
                    self.write_state("tick")
                except Exception as exc:  # pragma: no cover
                    self.event("tick_error", error=repr(exc))

        threading.Thread(target=tick_loop, daemon=True).start()
        try:
            queue.run()
        finally:
            self.ready = False
            queue.unbind()
            if self.events_handle is not None:
                self.events_handle.flush()
            self.event("ips_stop")
            if self.events_handle is not None:
                self.events_handle.flush()

    def _handle_signal(self, signum, _frame) -> None:  # noqa: ANN001
        self.ready = False
        raise SystemExit(128 + int(signum))


if __name__ == "__main__":
    RoutedPolicy().run()
