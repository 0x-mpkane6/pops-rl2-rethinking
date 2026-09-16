import os
import random
import socket
import threading
import time

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, SOA, TXT

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = int(os.getenv("AUTH_LISTEN_PORT", "53"))

ZONE = "example.net."
ZONE_IP = os.getenv("ZONE_IP", "198.51.100.10")
BANK_REAL_IP = os.getenv("BANK_REAL_IP", "203.0.113.80")
DELAY_SECONDS = float(os.getenv("AUTH_DELAY_SECONDS", "0.25"))
IPID_SPACE = int(os.getenv("IPID_SPACE", "2048"))
FRAGMETA_QNAME = os.getenv("FRAGMETA_QNAME", "_fragmeta.example.net.")
FRAG_TRIGGER_PREFIX = os.getenv("FRAG_TRIGGER_PREFIX", "frag").strip().lower()

# --- Benign second-fragment generator ---------------------------------------
#
# Trước đây, case "benign-on" của lab r2entropy chỉ khiến auth gắn marker
# FRAG1 (offset=0, xem should_attach_frag_marker) vào response thật, nhưng
# không có thành phần nào gửi tiếp một "fragment thứ hai" nào cả. Vì
# R2EntropyTable (resolver.py) chỉ tích lũy mẫu IPID từ các gói frag2
# (offset>0) thực sự nhận được, cửa sổ quan sát trong benign-on luôn rỗng
# (samples=0) -> shannon_entropy([]) luôn trả về 0.0 một cách máy móc, không
# phản ánh hành vi IPID thật nào. Nói cách khác, "allow 150/150, entropy
# 0.000" trước đây đúng nhưng vô nghĩa: rule chưa từng thật sự được thử với
# lưu lượng fragment hợp lệ để có cơ hội báo sai (false positive).
#
# Khối này mô phỏng đúng bản chất vật lý của IP fragmentation: khi một
# datagram gốc bị phân mảnh, MỌI fragment của nó (kể cả fragment sau,
# offset>0) luôn mang chung một giá trị IPID 16-bit và luôn xuất phát từ
# cùng một host nguồn - không cần và không có giả mạo IP như attacker. Vì
# vậy, ngay sau khi auth gắn marker FRAG1;IPID=X vào response thật cho một
# truy vấn "frag*", auth gửi thêm một gói FRAG2;IPID=X hợp lệ (không đồng
# bộ, không làm chậm response chính, không mang theo Answer/poison nào) để
# resolver có mẫu IPID thật để tính entropy/unique_ratio. Cơ chế này chỉ
# được bật khi benign_frag2_enabled() == True (case benign-on trong
# run_case.sh); baseline/attack-on giữ nguyên hành vi cũ.
FRAG2_QNAME = os.getenv("FRAG2_QNAME", "_frag2.example.net.")
FRAG2_OFFSET = int(os.getenv("FRAG2_OFFSET", "1480"))
RESOLVER_IP = os.getenv("RESOLVER_IP", "")
RESOLVER_UPSTREAM_PORT = int(os.getenv("RESOLVER_UPSTREAM_PORT", "33333"))
BENIGN_FRAG2_DELAY_MS = float(os.getenv("BENIGN_FRAG2_DELAY_MS", "3"))
BENIGN_FRAG2_FILE = os.getenv("BENIGN_FRAG2_FILE", "/app/benign_frag2_mode")
BENIGN_FRAG2_DEFAULT_MODE = os.getenv("BENIGN_FRAG2_ENABLED", "0").strip().lower()

frag2_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def benign_frag2_enabled() -> bool:
    try:
        with open(BENIGN_FRAG2_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip().lower() == "on"
    except FileNotFoundError:
        return BENIGN_FRAG2_DEFAULT_MODE in ("1", "on", "true", "yes")


def build_benign_frag2(ipid: int) -> DNSRecord:
    """Fragment thứ hai HỢP LỆ: cùng IPID với FRAG1 tương ứng, không Answer."""
    record = DNSRecord.question(FRAG2_QNAME, "TXT")
    record.header.id = ipid % 65535
    record.header.qr = 1
    record.header.aa = 1
    record.header.rd = 1
    record.add_ar(
        RR(
            FRAGMETA_QNAME,
            QTYPE.TXT,
            rclass=1,
            ttl=1,
            rdata=TXT(f"TYPE=FRAG2;IPID={ipid};OFFSET={FRAG2_OFFSET}"),
        )
    )
    return record


def send_benign_frag2(ipid: int) -> None:
    if not RESOLVER_IP:
        return
    if BENIGN_FRAG2_DELAY_MS > 0:
        time.sleep(BENIGN_FRAG2_DELAY_MS / 1000.0)
    try:
        frag2_sock.sendto(build_benign_frag2(ipid).pack(), (RESOLVER_IP, RESOLVER_UPSTREAM_PORT))
    except OSError as exc:
        print(f"[auth] benign frag2 send error: {exc}")


def normalize(name: str) -> str:
    value = name.lower().strip()
    if not value.endswith("."):
        value += "."
    return value


def should_attach_frag_marker(qname: str) -> bool:
    zone = normalize(ZONE)
    if not qname.endswith(zone):
        return False
    relative = qname[: -len(zone)].strip(".")
    return bool(relative and relative.split(".")[0].startswith(FRAG_TRIGGER_PREFIX))


def build_base_reply(request: DNSRecord) -> DNSRecord:
    header = DNSHeader(id=request.header.id, qr=1, aa=1, ra=0, rd=request.header.rd)
    return DNSRecord(header, q=request.q)


def main() -> None:
    if not os.path.exists(BENIGN_FRAG2_FILE):
        with open(BENIGN_FRAG2_FILE, "w", encoding="utf-8") as handle:
            handle.write("on\n" if BENIGN_FRAG2_DEFAULT_MODE in ("1", "on", "true", "yes") else "off\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(
        f"[auth] listening on {LISTEN_IP}:{LISTEN_PORT} | delay={DELAY_SECONDS}s | "
        f"benign_frag2_target={RESOLVER_IP or '(unset)'}:{RESOLVER_UPSTREAM_PORT}"
    )

    soa = SOA(
        mname="ns1.example.net.",
        rname="hostmaster.example.net.",
        times=(2026041001, 3600, 1200, 604800, 300),
    )

    while True:
        payload, addr = sock.recvfrom(4096)
        try:
            request = DNSRecord.parse(payload)
            qname = normalize(str(request.q.qname))
            qtype_name = QTYPE.get(request.q.qtype)

            time.sleep(DELAY_SECONDS)
            reply = build_base_reply(request)

            if qtype_name == "A" and qname.endswith(ZONE):
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=60, rdata=A(ZONE_IP)))
                if should_attach_frag_marker(qname):
                    ipid = random.randint(0, max(1, IPID_SPACE - 1))
                    reply.add_ar(
                        RR(
                            FRAGMETA_QNAME,
                            QTYPE.TXT,
                            rclass=1,
                            ttl=1,
                            rdata=TXT(f"TYPE=FRAG1;IPID={ipid}"),
                        )
                    )
                    if benign_frag2_enabled():
                        threading.Thread(target=send_benign_frag2, args=(ipid,), daemon=True).start()
            elif qtype_name == "A" and qname == "bank.com.":
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=120, rdata=A(BANK_REAL_IP)))
            else:
                reply.header.rcode = 3
                reply.add_auth(RR(ZONE, QTYPE.SOA, rclass=1, ttl=60, rdata=soa))

            sock.sendto(reply.pack(), addr)
        except Exception as exc:
            print(f"[auth] error: {exc}")


if __name__ == "__main__":
    main()
