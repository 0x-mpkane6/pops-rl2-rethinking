import json
import math
import os
import random
import re
import socket
import threading
import time
from collections import Counter, deque
from typing import Deque, Dict, List, Optional, Tuple

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, RCODE

LISTEN_IP = os.getenv("RESOLVER_LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("RESOLVER_LISTEN_PORT", "53"))
RESOLVER_BIND_IP = os.getenv("RESOLVER_BIND_IP", "10.60.0.53")

UPSTREAM_IP = os.getenv("UPSTREAM_DNS_IP", "10.60.0.100")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_DNS_PORT", "53"))
UPSTREAM_FIXED_SRC_PORT = int(os.getenv("UPSTREAM_FIXED_SRC_PORT", "33333"))
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "1.2"))

CACHE_DEFAULT_TTL = int(os.getenv("CACHE_DEFAULT_TTL", "60"))
TXID_SPACE = int(os.getenv("TXID_SPACE", "1024"))

FRAG2_KEEP_SECONDS = float(os.getenv("FRAG2_KEEP_SECONDS", "2.0"))
FRAG2_WINDOW_SECONDS = float(os.getenv("FRAG2_WINDOW_SECONDS", "2.0"))
R2_MIN_SAMPLES = int(os.getenv("R2_MIN_SAMPLES", "24"))
R2_ENTROPY_THRESHOLD = float(os.getenv("R2_ENTROPY_THRESHOLD", "4.0"))
R2_UNIQUE_RATIO_THRESHOLD = float(os.getenv("R2_UNIQUE_RATIO_THRESHOLD", "0.70"))
R2_VARIANT = os.getenv("R2_VARIANT", "combined").strip().lower()
VALID_R2_VARIANTS = {"legacy", "volume", "entropy", "unique", "combined"}
# When on, an allow decision still permits FRAG2 merge. This is actual Rℓ₂
# semantics: only a tc_block decision prevents poisoning. Default off keeps
# the older lab behavior where DEFENSE_MODE=on never merged.
R2_POISON_ON_ALLOW = os.getenv("R2_POISON_ON_ALLOW", "0").strip().lower() in {
    "1",
    "on",
    "true",
    "yes",
}

FRAGMETA_QNAME = os.getenv("FRAGMETA_QNAME", "_fragmeta.example.net.")
FRAG2_QNAME = os.getenv("FRAG2_QNAME", "_frag2.example.net.")
DEFENSE_FILE = os.getenv("DEFENSE_FILE", "/app/defense_mode")
DEFENSE_DEFAULT_MODE = os.getenv("DEFENSE_MODE", "off").strip().lower()

FRAG2_EVENTS_PATH = os.getenv("FRAG2_EVENTS_PATH", "/app/frag2_events.jsonl")
R2_DECISIONS_PATH = os.getenv("R2_DECISIONS_PATH", "/app/r2_entropy_decisions.jsonl")
R2_SUMMARY_PATH = os.getenv("R2_SUMMARY_PATH", "/app/r2_entropy_summary.json")
R2_OCCUPANCY_PATH = os.getenv("R2_OCCUPANCY_PATH", "/app/r2_occupancy.json")

IPID_RE = re.compile(r"IPID=(\d+)")
OFFSET_RE = re.compile(r"OFFSET=(\d+)")


class DNSCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, Tuple[str, float]] = {}

    def get(self, qname: str) -> Optional[str]:
        with self._lock:
            value = self._data.get(qname)
            if not value:
                return None
            ip, expires_at = value
            if time.monotonic() >= expires_at:
                del self._data[qname]
                return None
            return ip

    def set(self, name: str, ip: str, ttl: int) -> None:
        expires_at = time.monotonic() + max(1, ttl)
        with self._lock:
            self._data[name] = (ip, expires_at)


class Frag2Store:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[int, Tuple[str, str, int, float]] = {}

    def put(self, ipid: int, rrname: str, ip: str, ttl: int) -> None:
        expires_at = time.monotonic() + max(0.1, FRAG2_KEEP_SECONDS)
        with self._lock:
            self._data[ipid] = (rrname, ip, ttl, expires_at)

    def get(self, ipid: int) -> Optional[Tuple[str, str, int]]:
        now = time.monotonic()
        with self._lock:
            stale = [key for key, (_, _, _, exp) in self._data.items() if exp <= now]
            for key in stale:
                self._data.pop(key, None)
            value = self._data.get(ipid)
            if not value:
                return None
            rrname, ip, ttl, _ = value
            return rrname, ip, ttl


class R2EntropyTable:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: Dict[Tuple[str, str], Deque[Dict[str, float]]] = {}
        self._total_frag2 = 0
        self._total_blocks = 0
        self._last_decision: Dict[str, object] = {}

    def observe(self, event: Dict[str, object]) -> None:
        key = (str(event["src_ip"]), str(event["dst_ip"]))
        now_mono = float(event.get("mono_ts", time.monotonic()))
        wall_ts = float(event.get("ts", time.time()))
        occupancy = 0
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            bucket.append({"mono_ts": now_mono, "ipid": int(event["ipid"])})
            self._prune(bucket, now_mono)
            self._total_frag2 += 1
            occupancy = len(bucket)
        append_jsonl(FRAG2_EVENTS_PATH, event)
        write_json(
            R2_OCCUPANCY_PATH,
            {
                "occupancy": occupancy,
                "src_ip": key[0],
                "dst_ip": key[1],
                "ts": wall_ts,
                "mono_ts": now_mono,
            },
        )

    def occupancy(self, src_ip: str, dst_ip: str) -> int:
        now = time.monotonic()
        key = (src_ip, dst_ip)
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            self._prune(bucket, now)
            return len(bucket)

    def score(self, src_ip: str, dst_ip: str, qname: str, frag1_ipid: int, defense_on: bool) -> Dict[str, object]:
        now_mono = time.monotonic()
        wall_ts = time.time()
        key = (src_ip, dst_ip)
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            self._prune(bucket, now_mono)
            ipids = [int(item["ipid"]) for item in bucket]

        total = len(ipids)
        unique = len(set(ipids))
        entropy = shannon_entropy(ipids)
        unique_ratio = (unique / total) if total else 0.0
        gate_pass = {
            "samples": total >= R2_MIN_SAMPLES,
            "entropy": entropy >= R2_ENTROPY_THRESHOLD,
            "unique_ratio": unique_ratio >= R2_UNIQUE_RATIO_THRESHOLD,
        }
        suspicious = r2_should_block(R2_VARIANT, defense_on, total, entropy, unique_ratio)
        action = "tc_block" if suspicious else "allow"
        legacy_r2_action = "tc_block_on_any_frag1"

        decision = {
            "ts": wall_ts,
            "mono_ts": now_mono,
            "qname": qname,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "frag1_ipid": frag1_ipid,
            "samples": total,
            "unique_ipids": unique,
            "unique_ratio": round(unique_ratio, 4),
            "entropy": round(entropy, 4),
            "entropy_threshold": R2_ENTROPY_THRESHOLD,
            "unique_ratio_threshold": R2_UNIQUE_RATIO_THRESHOLD,
            "min_samples": R2_MIN_SAMPLES,
            "r2_variant": R2_VARIANT,
            "defense_on": defense_on,
            "gate_pass": gate_pass,
            "failed_gates": [name for name, passed in gate_pass.items() if not passed],
            "action": action,
            "legacy_r2_action": legacy_r2_action,
            "new_r2_action": action,
            "avoids_legacy_false_positive": action == "allow",
            "blocks_entropy_flood": action == "tc_block",
        }

        with self._lock:
            if suspicious:
                self._total_blocks += 1
            self._last_decision = decision
            summary = {
                "total_frag2_observed": self._total_frag2,
                "total_blocks": self._total_blocks,
                "last_decision": self._last_decision,
            }

        append_jsonl(R2_DECISIONS_PATH, decision)
        write_json(R2_SUMMARY_PATH, summary)
        return decision

    def _prune(self, bucket: Deque[Dict[str, float]], now_mono: float) -> None:
        cutoff = now_mono - max(0.1, FRAG2_WINDOW_SECONDS)
        while bucket:
            event_mono = float(bucket[0].get("mono_ts", bucket[0].get("ts", now_mono)))
            if event_mono >= cutoff:
                break
            bucket.popleft()


def append_jsonl(path: str, row: Dict[str, object]) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_json(path: str, row: Dict[str, object]) -> None:
    temp_path = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(row, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp_path, path)


def shannon_entropy(values: List[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def r2_should_block(
    variant: str,
    defense_on: bool,
    samples: int,
    entropy: float,
    unique_ratio: float,
) -> bool:
    """Apply one B1--B5 policy without changing the lab topology."""
    if not defense_on:
        return False
    if variant == "legacy":
        return True
    if variant == "volume":
        return samples >= R2_MIN_SAMPLES
    if variant == "entropy":
        return entropy >= R2_ENTROPY_THRESHOLD
    if variant == "unique":
        return unique_ratio >= R2_UNIQUE_RATIO_THRESHOLD
    if variant == "combined":
        return (
            samples >= R2_MIN_SAMPLES
            and entropy >= R2_ENTROPY_THRESHOLD
            and unique_ratio >= R2_UNIQUE_RATIO_THRESHOLD
        )
    raise ValueError(f"unknown R2_VARIANT={variant!r}; expected one of {sorted(VALID_R2_VARIANTS)}")


def normalize_name(name: str) -> str:
    value = name.lower().strip()
    if value.endswith("."):
        value = value[:-1]
    return value


def defense_enabled() -> bool:
    try:
        with open(DEFENSE_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip().lower() == "on"
    except FileNotFoundError:
        return False


def build_response(
    request: DNSRecord,
    answer_ip: Optional[str],
    tc_flag: bool = False,
    rcode: int = RCODE.NOERROR,
) -> DNSRecord:
    header = DNSHeader(
        id=request.header.id,
        qr=1,
        aa=0,
        ra=1,
        rd=request.header.rd,
        tc=1 if tc_flag else 0,
        rcode=rcode,
    )
    response = DNSRecord(header, q=request.q)
    if answer_ip:
        response.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=CACHE_DEFAULT_TTL,
                rdata=A(answer_ip),
            )
        )
    return response


def extract_txt_values(response: DNSRecord) -> List[str]:
    values: List[str] = []
    for section in (response.rr, response.auth, response.ar):
        for rr in section:
            if QTYPE.get(rr.rtype) != "TXT":
                continue
            values.append(str(rr.rdata).strip().strip('"'))
    return values


def parse_int_marker(txt_values: List[str], regex: re.Pattern[str]) -> Optional[int]:
    for value in txt_values:
        match = regex.search(value.upper())
        if match:
            return int(match.group(1))
    return None


def is_frag2_marker(qname: str, txt_values: List[str]) -> bool:
    if normalize_name(qname) == normalize_name(FRAG2_QNAME):
        return True
    return any("TYPE=FRAG2" in value.upper() for value in txt_values)


def is_frag1_marker(txt_values: List[str]) -> bool:
    return any("TYPE=FRAG1" in value.upper() for value in txt_values)


def extract_a_records(response: DNSRecord) -> List[Tuple[str, str, int]]:
    records: List[Tuple[str, str, int]] = []
    excluded = {normalize_name(FRAGMETA_QNAME), normalize_name(FRAG2_QNAME)}
    for section in (response.rr, response.auth, response.ar):
        for rr in section:
            if QTYPE.get(rr.rtype) != "A":
                continue
            name = normalize_name(str(rr.rname))
            if name in excluded:
                continue
            records.append((name, str(rr.rdata), int(rr.ttl)))
    return records


def handle_frag2_packet(
    response: DNSRecord,
    peer_addr: Tuple[str, int],
    frag_store: Frag2Store,
    r2_table: R2EntropyTable,
) -> bool:
    if not response.q:
        return False

    qname = str(response.q.qname)
    txt_values = extract_txt_values(response)
    if not is_frag2_marker(qname, txt_values):
        return False

    ipid = parse_int_marker(txt_values, IPID_RE)
    offset = parse_int_marker(txt_values, OFFSET_RE)
    if ipid is None or offset is None or offset <= 0:
        return False

    event = {
        "ts": time.time(),
        "mono_ts": time.monotonic(),
        "src_ip": peer_addr[0],
        "dst_ip": RESOLVER_BIND_IP,
        "src_port": peer_addr[1],
        "dst_port": UPSTREAM_FIXED_SRC_PORT,
        "ipid": ipid,
        "offset": offset,
    }
    r2_table.observe(event)

    for rrname, ip, ttl in extract_a_records(response):
        frag_store.put(ipid, rrname, ip, ttl)
        print(f"[resolver] captured frag2: src={peer_addr[0]} ipid={ipid} offset={offset} {rrname}->{ip}")
        return True

    return True


class UpstreamMux:
    """Single reader for the upstream socket so FRAG2 is observed continuously."""

    def __init__(self, sock: socket.socket, frag_store: Frag2Store, r2_table: R2EntropyTable) -> None:
        self.sock = sock
        self.frag_store = frag_store
        self.r2_table = r2_table
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)
        self.responses: Dict[int, DNSRecord] = {}
        self.alive = True

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        self.sock.settimeout(0.2)
        while self.alive:
            try:
                payload, peer_addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                response = DNSRecord.parse(payload)
            except Exception:
                continue
            if handle_frag2_packet(response, peer_addr, self.frag_store, self.r2_table):
                continue
            with self.cv:
                self.responses[int(response.header.id)] = response
                self.cv.notify_all()

    def send_and_wait(self, qname: str, timeout: float) -> Optional[DNSRecord]:
        request = DNSRecord.question(qname, "A")
        txid = random.randint(0, max(1, TXID_SPACE - 1))
        request.header.id = txid
        with self.cv:
            self.responses.pop(txid, None)
        self.sock.sendto(request.pack(), (UPSTREAM_IP, UPSTREAM_PORT))
        deadline = time.monotonic() + timeout
        with self.cv:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                response = self.responses.pop(txid, None)
                if response is not None:
                    if response.q and normalize_name(str(response.q.qname)) == normalize_name(qname):
                        return response
                self.cv.wait(remaining)

    def wait_occupancy(self, min_samples: int, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        samples = 0
        while time.monotonic() < deadline:
            samples = self.r2_table.occupancy(UPSTREAM_IP, RESOLVER_BIND_IP)
            if samples >= min_samples:
                return samples
            time.sleep(0.1)
        return self.r2_table.occupancy(UPSTREAM_IP, RESOLVER_BIND_IP)


def query_upstream(
    mux: UpstreamMux,
    qname: str,
    defense_on: bool,
    frag_store: Frag2Store,
    r2_table: R2EntropyTable,
) -> Tuple[Optional[List[Tuple[str, str, int]]], bool]:
    response = mux.send_and_wait(qname, UPSTREAM_TIMEOUT)
    if response is None:
        return None, False

    txt_values = extract_txt_values(response)
    frag1_ipid = parse_int_marker(txt_values, IPID_RE) if is_frag1_marker(txt_values) else None

    if frag1_ipid is not None:
        decision = r2_table.score(UPSTREAM_IP, RESOLVER_BIND_IP, qname, frag1_ipid, defense_on)
        if decision["action"] == "tc_block":
            print(
                f"[resolver] R2 entropy block: qname={qname} "
                f"entropy={decision['entropy']} samples={decision['samples']} "
                f"unique_ratio={decision['unique_ratio']}"
            )
            return None, True

    records = extract_a_records(response)
    permit_merge = (not defense_on) or R2_POISON_ON_ALLOW
    if permit_merge and frag1_ipid is not None:
        forged = frag_store.get(frag1_ipid)
        if forged:
            rrname, ip, ttl = forged
            records.append((normalize_name(rrname), ip, ttl))
            print(f"[resolver] merged forged frag2: qname={qname} ipid={frag1_ipid} {rrname}->{ip}")

    return records, False


def main() -> None:
    if R2_VARIANT not in VALID_R2_VARIANTS:
        raise ValueError(
            f"unknown R2_VARIANT={R2_VARIANT!r}; expected one of {sorted(VALID_R2_VARIANTS)}"
        )
    if not os.path.exists(DEFENSE_FILE):
        with open(DEFENSE_FILE, "w", encoding="utf-8") as handle:
            handle.write("on\n" if DEFENSE_DEFAULT_MODE == "on" else "off\n")

    for path in (FRAG2_EVENTS_PATH, R2_DECISIONS_PATH, R2_SUMMARY_PATH, R2_OCCUPANCY_PATH):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    cache = DNSCache()
    frag_store = Frag2Store()
    r2_table = R2EntropyTable()

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, LISTEN_PORT))

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.bind((RESOLVER_BIND_IP, UPSTREAM_FIXED_SRC_PORT))
    mux = UpstreamMux(upstream_sock, frag_store, r2_table)
    mux.start()

    print(
        f"[resolver] listening on {LISTEN_IP}:{LISTEN_PORT} | "
        f"upstream={UPSTREAM_IP}:{UPSTREAM_PORT} | r2_variant={R2_VARIANT} | "
        f"r2_entropy_threshold={R2_ENTROPY_THRESHOLD} | "
        f"r2_poison_on_allow={int(R2_POISON_ON_ALLOW)} | continuous_frag2=1"
    )

    while True:
        payload, client_addr = server.recvfrom(4096)
        try:
            request = DNSRecord.parse(payload)
            if request.q.qtype != QTYPE.A:
                server.sendto(build_response(request, None, rcode=RCODE.NXDOMAIN).pack(), client_addr)
                continue

            qname = normalize_name(str(request.q.qname))
            cached_ip = cache.get(qname)
            if cached_ip:
                server.sendto(build_response(request, cached_ip).pack(), client_addr)
                continue

            defense_on = defense_enabled()
            records, frag_detected = query_upstream(mux, qname, defense_on, frag_store, r2_table)

            if frag_detected:
                server.sendto(build_response(request, None, tc_flag=True).pack(), client_addr)
                continue

            if records is None:
                server.sendto(build_response(request, None, rcode=RCODE.SERVFAIL).pack(), client_addr)
                continue

            for rrname, ip, ttl in records:
                cache.set(rrname, ip, ttl)

            answer_ip = cache.get(qname)
            server.sendto(build_response(request, answer_ip).pack(), client_addr)

        except Exception as exc:
            print(f"[resolver] error: {exc}")
            try:
                request = DNSRecord.parse(payload)
                server.sendto(build_response(request, None, rcode=RCODE.SERVFAIL).pack(), client_addr)
            except Exception:
                continue


if __name__ == "__main__":
    main()
