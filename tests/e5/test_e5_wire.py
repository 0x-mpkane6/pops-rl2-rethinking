from __future__ import annotations

import sys
from pathlib import Path

from dnslib import DNSRecord
from scapy.all import ICMP, IP, Raw, fragment  # type: ignore

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT / "routed_lab"))

from wire import build_dns_answer, build_icmp_needfrag, build_padded_dns_answer, fragment_udp_payload, udp_payload  # noqa: E402


def test_fragmented_authoritative_answer_has_matching_udp_and_ip_metadata() -> None:
    qname = "r01-t000-abcdef01.bank.com."
    query = DNSRecord.question(qname, "A")
    body = build_dns_answer(query, "203.0.113.80")
    packets = fragment_udp_payload(
        src="10.82.0.100",
        dst="10.81.0.53",
        ipid=777,
        dst_port=33333,
        body=body,
        fragsize=40,
    )
    assert len(packets) >= 2
    first = IP(bytes(packets[0]))
    tail = IP(bytes(packets[1]))
    assert first.id == 777
    assert first.frag == 0
    assert first.flags.MF
    assert tail.frag > 0
    assert first.proto == 17
    assert bytes(first.payload)[:2] == (53).to_bytes(2, "big")
    assert bytes(first.payload)[2:4] == (33333).to_bytes(2, "big")
    assert str(DNSRecord.parse(body).rr[0].rdata) == "203.0.113.80"


def test_udp_payload_uses_zero_checksum_for_replayed_fragments() -> None:
    raw = udp_payload(40000, b"payload")
    assert raw[:8] == (53).to_bytes(2, "big") + (40000).to_bytes(2, "big") + (15).to_bytes(2, "big") + b"\x00\x00"


def test_padded_dns_answer_is_large_enough_for_pmtud_but_under_ethernet_mtu() -> None:
    query = DNSRecord.question("r01-t000-abcdef01.bank.com.", "A")
    body = build_padded_dns_answer(query, "203.0.113.80", min_size=1200, max_size=1400)
    assert 1200 <= len(body) <= 1400


def test_icmp_needfrag_is_type_3_code_4() -> None:
    packet = build_icmp_needfrag(src="10.82.0.1", dst="10.82.0.100", quoted=b"\x45" * 28, mtu=576)
    parsed = IP(bytes(packet))
    assert parsed[ICMP].type == 3
    assert parsed[ICMP].code == 4
    assert int(parsed[ICMP].nexthopmtu) == 576


def test_occupancy_tails_differ_across_sequence_numbers() -> None:
    # Keep this formula aligned with attacker.occupancy_payload: unique bytes
    # must land in the FRAGSIZE=40 tail so AF_PACKET does not collapse 12/s
    # fixed-IPID occupancy under the veth duplicate window.
    def occupancy_payload(seq: int) -> bytes:
        return b"E5V2-OCCUPANCY-" + (b"O" * 36) + f"{seq:08d}".encode("ascii") + b"-"

    tails = []
    for seq in (0, 1):
        packets = fragment_udp_payload(
            src="10.82.0.200",
            dst="10.81.0.53",
            ipid=777,
            dst_port=9,
            src_port=9,
            body=occupancy_payload(seq),
            fragsize=40,
        )
        assert len(packets) == 2
        tails.append(bytes(IP(bytes(packets[1])).payload))
    assert tails[0] != tails[1]

