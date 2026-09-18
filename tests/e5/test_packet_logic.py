from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, Raw, UDP, fragment  # type: ignore

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT / "routed_lab"))

from ips.packet_logic import build_tc_response, parse_packet  # noqa: E402
from wire import udp_payload  # noqa: E402


AUTH = "10.82.0.100"
RESOLVER = "10.81.0.53"
QNAME = "r01-t001-abcd.bank.com."


def test_parse_first_and_noninitial_response_fragments() -> None:
    packet = IP(src=AUTH, dst=RESOLVER, id=77) / UDP(sport=53, dport=33333) / DNS(
        id=1234, qr=1, aa=1, qd=DNSQR(qname=QNAME, qtype="A")
    ) / Raw(b"x" * 100)
    fragments = fragment(packet, fragsize=40)
    first = parse_packet(
        bytes(fragments[0]),
        auth_ip=AUTH,
        resolver_ip=RESOLVER,
        query_map={(33333, 1234): QNAME},
    )
    tail = parse_packet(bytes(fragments[1]), auth_ip=AUTH, resolver_ip=RESOLVER)
    assert first.is_first_fragment
    assert first.qname == QNAME
    assert first.txid == 1234
    assert first.dst_port == 33333
    assert tail.is_noninitial_fragment
    assert tail.is_dns_response
    assert tail.ipid == 77


def test_parse_query_and_response_qname_fallback() -> None:
    query = IP(src=RESOLVER, dst=AUTH, id=11) / UDP(sport=41000, dport=53) / DNS(
        id=4321, rd=1, qd=DNSQR(qname=QNAME, qtype="A")
    )
    parsed_query = parse_packet(bytes(query), auth_ip=AUTH, resolver_ip=RESOLVER)
    assert parsed_query.is_query
    assert parsed_query.qname == QNAME
    response = IP(src=AUTH, dst=RESOLVER, id=12) / UDP(sport=53, dport=41000) / Raw(
        bytes(DNS(id=4321, qr=1, qd=DNSQR(qname=QNAME, qtype="A"))) + b"x" * 80
    )
    parsed_response = parse_packet(
        bytes(response),
        auth_ip=AUTH,
        resolver_ip=RESOLVER,
        query_map={(41000, 4321): QNAME},
    )
    assert parsed_response.is_dns_response
    assert parsed_response.qname == QNAME


def test_truncated_first_fragment_keeps_raw_transaction_id_for_mapping() -> None:
    dns_body = bytes(DNS(id=9876, qr=1, qd=DNSQR(qname=QNAME, qtype="A")))
    datagram = udp_payload(33333, dns_body + (b"x" * 40))
    first = IP(src=AUTH, dst=RESOLVER, id=13, flags=1, frag=0, proto=17) / Raw(datagram[:18])
    parsed = parse_packet(bytes(first), auth_ip=AUTH, resolver_ip=RESOLVER, query_map={(33333, 9876): QNAME})
    assert parsed.txid == 9876
    assert parsed.qname == QNAME


def test_build_tc_response_preserves_dns_matching_fields() -> None:
    raw = build_tc_response(
        qname=QNAME,
        txid=5432,
        resolver_port=40000,
        auth_ip=AUTH,
        resolver_ip=RESOLVER,
        ipid=99,
    )
    packet = IP(raw)
    assert packet[IP].src == AUTH
    assert packet[IP].dst == RESOLVER
    assert packet[IP].frag == 0
    assert not (int(packet[IP].flags) & 0x1)
    assert packet[UDP].sport == 53
    assert packet[UDP].dport == 40000
    assert packet[DNS].id == 5432
    assert packet[DNS].tc == 1
    assert packet[DNS].qd.qname.decode().rstrip(".") == QNAME.rstrip(".")
