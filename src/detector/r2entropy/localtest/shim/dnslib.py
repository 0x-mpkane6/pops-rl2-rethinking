"""Minimal, dependency-free stand-in for the *subset* of the real `dnslib`
package API that this lab's resolver.py / auth_server.py use.

Why this exists: this sandbox has no package-index access (pip/apt egress is
blocked by an allowlist proxy), so the real `dnslib==0.9.26` pinned in the
Dockerfiles cannot be installed here, and Docker itself is not available
either. To actually *execute* the real, unmodified resolver.py/auth_server.py
(instead of just reasoning about them) and produce genuinely-measured
numbers, this shim implements real RFC1035 wire encoding/decoding for the
record types the lab uses (A, TXT, SOA, NS) plus generic skip-parsing for
any other record type (e.g. EDNS0 OPT, which `dig` attaches by default), so
it interoperates with a real `dig` client and with itself across a real UDP
socket. It is NOT a general-purpose DNS library and is only used for local
verification -- it is not shipped as part of the lab / repo deliverable.
"""

import struct


class QTYPE:
    A = 1
    NS = 2
    SOA = 6
    TXT = 16
    OPT = 41
    _names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 41: "OPT"}

    @classmethod
    def get(cls, code):
        return cls._names.get(code, str(code))

    @classmethod
    def code(cls, name):
        if isinstance(name, int):
            return name
        for c, nm in cls._names.items():
            if nm == name:
                return c
        raise ValueError(f"Unknown QTYPE name: {name}")


class RCODE:
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3


def _encode_name(name: str) -> bytes:
    name = str(name).strip()
    if name in (".", ""):
        return b"\x00"
    out = bytearray()
    for label in name.strip(".").split("."):
        data = label.encode("ascii")
        if data:
            out.append(len(data))
            out.extend(data)
    out.append(0)
    return bytes(out)


def _decode_name(buf: bytes, offset: int):
    labels = []
    end_offset = None
    safety = 0
    while True:
        safety += 1
        if safety > 128:
            raise ValueError("malformed name / compression loop")
        length = buf[offset]
        if length == 0:
            offset += 1
            if end_offset is None:
                end_offset = offset
            break
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if end_offset is None:
                end_offset = offset + 2
            offset = pointer
            continue
        offset += 1
        labels.append(buf[offset:offset + length].decode("ascii"))
        offset += length
    name = ".".join(labels) + "." if labels else "."
    return name, end_offset


class DNSLabel:
    def __init__(self, name):
        name = str(name)
        self.name = name if name.endswith(".") else name + "."

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"DNSLabel({self.name!r})"

    def __eq__(self, other):
        return str(self) == str(other)


class DNSQuestion:
    def __init__(self, qname, qtype=1, qclass=1):
        self.qname = qname if isinstance(qname, DNSLabel) else DNSLabel(qname)
        self.qtype = QTYPE.code(qtype) if isinstance(qtype, str) else qtype
        self.qclass = qclass

    def pack(self):
        return _encode_name(str(self.qname)) + struct.pack("!HH", self.qtype, self.qclass)


class A:
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return self.data

    def pack(self):
        return bytes(int(part) for part in self.data.split("."))


class TXT:
    def __init__(self, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        self.data = data

    def __str__(self):
        return f'"{self.data}"'

    def pack(self):
        raw = self.data.encode("utf-8")
        out = bytearray()
        for i in range(0, len(raw), 255):
            chunk = raw[i:i + 255]
            out.append(len(chunk))
            out.extend(chunk)
        if not raw:
            out.append(0)
        return bytes(out)


class NS:
    def __init__(self, data):
        self.data = str(data)

    def __str__(self):
        return self.data

    def pack(self):
        return _encode_name(self.data)


class SOA:
    def __init__(self, mname, rname, times):
        self.mname = mname
        self.rname = rname
        self.times = tuple(times)

    def __str__(self):
        return f"{self.mname} {self.rname} " + " ".join(str(t) for t in self.times)

    def pack(self):
        return _encode_name(self.mname) + _encode_name(self.rname) + struct.pack("!IIIII", *self.times)


class RawRD:
    """Fallback rdata for record types we don't need to interpret (e.g. OPT)."""

    def __init__(self, raw: bytes):
        self.raw = raw

    def __str__(self):
        return self.raw.hex()

    def pack(self):
        return self.raw


class RR:
    def __init__(self, rname, rtype=1, rclass=1, ttl=0, rdata=None):
        self.rname = rname if isinstance(rname, DNSLabel) else DNSLabel(str(rname))
        self.rtype = QTYPE.code(rtype) if isinstance(rtype, str) else rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def pack(self):
        body = self.rdata.pack() if hasattr(self.rdata, "pack") else bytes(self.rdata or b"")
        return (
            _encode_name(str(self.rname))
            + struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, len(body))
            + body
        )


class DNSHeader:
    def __init__(self, id=0, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, rcode=0,
                 qdcount=0, ancount=0, nscount=0, arcount=0, **_ignored):
        self.id = id & 0xFFFF
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def pack(self):
        flags = (
            (self.qr & 1) << 15
            | (self.opcode & 0xF) << 11
            | (self.aa & 1) << 10
            | (self.tc & 1) << 9
            | (self.rd & 1) << 8
            | (self.ra & 1) << 7
            | (self.rcode & 0xF)
        )
        return struct.pack("!HHHHHH", self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)


class DNSRecord:
    def __init__(self, header=None, q=None):
        self.header = header if header is not None else DNSHeader()
        self.questions = [q] if q is not None else []
        self.rr = []
        self.auth = []
        self.ar = []

    @property
    def q(self):
        return self.questions[0] if self.questions else None

    def add_answer(self, *rrs):
        self.rr.extend(rrs)

    def add_auth(self, *rrs):
        self.auth.extend(rrs)

    def add_ar(self, *rrs):
        self.ar.extend(rrs)

    @classmethod
    def question(cls, qname, qtype="A"):
        return cls(DNSHeader(id=0, rd=1), q=DNSQuestion(qname, qtype))

    def pack(self):
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.rr)
        self.header.nscount = len(self.auth)
        self.header.arcount = len(self.ar)
        out = bytearray(self.header.pack())
        for q in self.questions:
            out.extend(q.pack())
        for section in (self.rr, self.auth, self.ar):
            for rr in section:
                out.extend(rr.pack())
        return bytes(out)

    @classmethod
    def parse(cls, data: bytes):
        (id_, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])
        header = DNSHeader(
            id=id_,
            qr=(flags >> 15) & 1,
            opcode=(flags >> 11) & 0xF,
            aa=(flags >> 10) & 1,
            tc=(flags >> 9) & 1,
            rd=(flags >> 8) & 1,
            ra=(flags >> 7) & 1,
            rcode=flags & 0xF,
        )
        offset = 12
        questions = []
        for _ in range(qdcount):
            name, offset = _decode_name(data, offset)
            qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            questions.append(DNSQuestion(name, qtype, qclass))

        def parse_rr_list(count, off):
            items = []
            for _ in range(count):
                name, off = _decode_name(data, off)
                rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[off:off + 10])
                off += 10
                raw = data[off:off + rdlength]
                off += rdlength
                if rtype == QTYPE.A and len(raw) == 4:
                    rdata = A(".".join(str(b) for b in raw))
                elif rtype == QTYPE.TXT:
                    parts = []
                    p = 0
                    while p < len(raw):
                        ln = raw[p]
                        parts.append(raw[p + 1:p + 1 + ln].decode("utf-8", "replace"))
                        p += 1 + ln
                    rdata = TXT("".join(parts))
                else:
                    rdata = RawRD(raw)
                items.append(RR(name, rtype, rclass, ttl, rdata))
            return items, off

        record = cls(header, q=questions[0] if questions else None)
        record.questions = questions
        record.rr, offset = parse_rr_list(ancount, offset)
        record.auth, offset = parse_rr_list(nscount, offset)
        record.ar, offset = parse_rr_list(arcount, offset)
        return record
