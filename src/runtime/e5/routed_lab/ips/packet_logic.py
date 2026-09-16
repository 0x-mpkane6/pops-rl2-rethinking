"""Scapy packet parsing and TC-response construction for the E5 IPS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from scapy.all import DNS, DNSQR, IP, UDP  # type: ignore


@dataclass(frozen=True)
class PacketMeta:
    src: str
    dst: str
    protocol: int
    ipid: int
    offset: int
    more_fragments: bool
    src_port: int | None
    dst_port: int | None
    txid: int | None
    qname: str | None
    is_query: bool
    is_dns_response: bool

    @property
    def is_first_fragment(self) -> bool:
        return self.offset == 0 and self.more_fragments

    @property
    def is_noninitial_fragment(self) -> bool:
        return self.offset > 0


def _qname(value: object) -> str | None:
    if value is None:
        return None
    text = value.decode("ascii", "replace") if isinstance(value, bytes) else str(value)
    return text if text.endswith(".") else text + "."


def parse_packet(
    payload: bytes,
    *,
    auth_ip: str,
    resolver_ip: str,
    query_map: Mapping[tuple[int, int], str] | None = None,
) -> PacketMeta:
    """Parse headers needed by the policy plane.

    DNS payload parsing is attempted only for offset-zero packets. If a
    response question is truncated, query_map supplies a qname fallback keyed
    by resolver UDP port and TXID.
    """

    packet = IP(payload)
    ip = packet[IP]
    src, dst = str(ip.src), str(ip.dst)
    protocol = int(ip.proto)
    ipid = int(ip.id)
    offset = int(ip.frag) * 8
    more_fragments = bool(int(ip.flags) & 0x1)
    src_port = dst_port = txid = None
    qname = None
    is_query = False
    if protocol == 17 and offset == 0 and UDP in packet:
        udp = packet[UDP]
        src_port, dst_port = int(udp.sport), int(udp.dport)
        udp_payload = bytes(udp.payload)
        if len(udp_payload) >= 2:
            txid = int.from_bytes(udp_payload[:2], "big")
        raw_txid = txid
        try:
            dns = packet[DNS]
            txid = int(dns.id)
            qname = _qname(dns.qd.qname if dns.qd else None)
            is_query = int(dns.qr) == 0
        except Exception:
            # A short first fragment can make Scapy's DNS dissector reject
            # the partial question.  The two-byte transaction ID is still
            # present immediately after the UDP header and is sufficient for
            # query_map correlation.
            txid = raw_txid
    is_dns_response = src == auth_ip and dst == resolver_ip and protocol == 17
    if is_dns_response and dst_port is not None and txid is not None and query_map:
        mapped_qname = query_map.get((dst_port, txid))
        if mapped_qname:
            # A first fragment may end in the middle of the DNS question; the
            # complete outbound query is the authoritative qname source.
            qname = mapped_qname
    return PacketMeta(
        src=src,
        dst=dst,
        protocol=protocol,
        ipid=ipid,
        offset=offset,
        more_fragments=more_fragments,
        src_port=src_port,
        dst_port=dst_port,
        txid=txid,
        qname=qname,
        is_query=is_query,
        is_dns_response=is_dns_response,
    )


def build_tc_response(
    *,
    qname: str,
    txid: int,
    resolver_port: int,
    auth_ip: str,
    resolver_ip: str,
    ipid: int = 0,
) -> bytes:
    """Build an unfragmented TC=1 UDP response matching the original query."""

    packet = (
        IP(src=auth_ip, dst=resolver_ip, id=int(ipid) & 0xFFFF, flags=0, frag=0)
        / UDP(sport=53, dport=int(resolver_port))
        / DNS(id=int(txid) & 0xFFFF, qr=1, aa=1, rd=1, tc=1, qd=DNSQR(qname=qname, qtype="A"))
    )
    return bytes(packet)
