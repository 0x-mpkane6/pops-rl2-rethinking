#!/usr/bin/env python3
"""Send one routed non-DNS fragment pair for the NFQUEUE preflight gate."""

import os
import subprocess

from scapy.all import conf, send  # type: ignore

from wire import fragment_udp_payload

subprocess.run(
    [
        "ip",
        "route",
        "replace",
        os.environ.get("RESOLVER_NET", "10.81.0.0/24"),
        "via",
        os.environ.get("UPSTREAM_GATEWAY", "10.82.0.1"),
    ],
    check=True,
)
conf.route.resync()
packets = fragment_udp_payload(
    src=os.environ.get("ATTACKER_IP", "10.82.0.200"),
    dst=os.environ.get("RESOLVER_IP", "10.81.0.53"),
    ipid=65000,
    dst_port=9,
    src_port=9,
    body=b"E5V2-PREFLIGHT" + (b"P" * 64),
    fragsize=int(os.environ.get("FRAGSIZE", "40")),
)
send(packets, verbose=0)
print(f"E5V2_NFQUEUE_SMOKE fragments={len(packets)} ipid=65000", flush=True)
