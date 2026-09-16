#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="${LOG_DIR:-/app/log}"
INSIDE_IP="${IPS_INSIDE_IP:-10.81.0.1}"
OUTSIDE_IP="${IPS_OUTSIDE_IP:-10.82.0.1}"
QUEUE_NUM="${NFQUEUE_NUM:-5}"
mkdir -p "$LOG_DIR" /app/pcap

inside_if="$(ip -o -4 addr show | awk -v wanted="$INSIDE_IP" '$4 == wanted "/24" || $4 ~ ("^" wanted "/") {print $2; exit}')"
outside_if="$(ip -o -4 addr show | awk -v wanted="$OUTSIDE_IP" '$4 == wanted "/24" || $4 ~ ("^" wanted "/") {print $2; exit}')"
if [[ -z "$inside_if" || -z "$outside_if" || "$inside_if" == "$outside_if" ]]; then
    echo "could not identify two distinct IPS interfaces" >&2
    ip -o -4 addr show >&2 || true
    exit 30
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null
if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
    echo "IPv4 forwarding could not be enabled" >&2
    exit 32
fi
/app/preflight.sh

# The only forwarding decision point is NFQUEUE.  There is intentionally no
# --queue-bypass option: a missing policy process must not silently forward.
iptables -F FORWARD
iptables -P FORWARD DROP
# Linux defragments IPv4 before the normal FORWARD hook on this kernel.  The
# policy process therefore observes raw fragments with AF_PACKET while the
# routed enforcement decision remains at the registered FORWARD NFQUEUE.
iptables -A FORWARD -j NFQUEUE --queue-num "$QUEUE_NUM"
iptables -A FORWARD -j ACCEPT

/app/snapshot.sh before
printf '{"schema_version":1,"inside_ip":"%s","outside_ip":"%s","inside_iface":"%s","outside_iface":"%s","queue_num":%s}\n' \
    "$INSIDE_IP" "$OUTSIDE_IP" "$inside_if" "$outside_if" "$QUEUE_NUM" > "$LOG_DIR/interfaces.json"

# tshark/dumpcap writes PCAPNG, which is required for the packet-level
# evidence package.  A capture failure is recorded as an error rather than
# silently being presented as a valid empty capture.
tshark -i "$inside_if" -n -q -w /app/pcap/ips_inside.pcapng \
    >/app/log/ips_inside_capture.stderr 2>&1 &
inside_cap=$!
tshark -i "$outside_if" -n -q -w /app/pcap/ips_outside.pcapng \
    >/app/log/ips_outside_capture.stderr 2>&1 &
outside_cap=$!
sleep 0.2
if ! kill -0 "$inside_cap" 2>/dev/null || ! kill -0 "$outside_cap" 2>/dev/null; then
    echo "PCAPNG capture process failed to start" >&2
    exit 31
fi

cleanup() {
    set +e
    kill "$inside_cap" "$outside_cap" 2>/dev/null || true
    wait "$inside_cap" "$outside_cap" 2>/dev/null || true
    /app/snapshot.sh after
}
trap cleanup EXIT

export INSIDE_IFACE="$inside_if"
export OUTSIDE_IFACE="$outside_if"
python3 /app/policy.py &
policy_pid=$!
on_signal() {
    set +e
    kill "$policy_pid" 2>/dev/null || true
    wait "$policy_pid" 2>/dev/null || true
    exit 143
}
trap on_signal INT TERM
wait "$policy_pid"
