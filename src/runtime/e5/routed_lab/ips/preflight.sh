#!/usr/bin/env bash
set -euo pipefail

# This is deliberately a hard gate.  E5 has no non-NFQUEUE fallback.
if ! command -v iptables >/dev/null 2>&1; then
    echo "NFQUEUE preflight failed: iptables is unavailable" >&2
    exit 20
fi
if ! iptables -j NFQUEUE -h >/dev/null 2>&1; then
    echo "NFQUEUE preflight failed: the NFQUEUE target is unavailable" >&2
    exit 21
fi
if ! python3 /app/nfqueue_probe.py >/app/log/nfqueue_bind_probe.txt 2>&1; then
    echo "NFQUEUE preflight failed: NetfilterQueue could not bind the kernel queue" >&2
    exit 22
fi

if ! iptables -t filter -N E5V2_NFQ_PREFLIGHT 2>/dev/null; then
    iptables -t filter -F E5V2_NFQ_PREFLIGHT
fi
trap 'iptables -t filter -F E5V2_NFQ_PREFLIGHT; iptables -t filter -X E5V2_NFQ_PREFLIGHT' EXIT
iptables -t filter -A E5V2_NFQ_PREFLIGHT -j NFQUEUE --queue-num "${NFQUEUE_NUM:-5}"
iptables -t filter -C E5V2_NFQ_PREFLIGHT -j NFQUEUE --queue-num "${NFQUEUE_NUM:-5}"

ip route get "${RESOLVER_IP:-10.81.0.53}" >/app/log/preflight_route_resolver.txt
ip route get "${AUTH_IP:-10.82.0.100}" >/app/log/preflight_route_auth.txt
printf '{"schema_version":1,"nfqueue_target":true,"kernel_queue_bind":true}\n' > /app/log/nfqueue_preflight.json
