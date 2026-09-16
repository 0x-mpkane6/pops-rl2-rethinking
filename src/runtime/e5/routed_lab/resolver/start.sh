#!/usr/bin/env bash
set -euo pipefail

ip route replace "${UPSTREAM_NET:-10.82.0.0/24}" via "${INSIDE_GATEWAY:-10.81.0.1}"
mkdir -p "${LOG_DIR:-/app/log}"
: > "${LOG_DIR:-/app/log}/unbound_events.jsonl"
: > "${LOG_DIR:-/app/log}/cache_events.jsonl"
unbound -V > "${LOG_DIR:-/app/log}/unbound_version.txt" 2>&1 || true
unbound-checkconf /etc/unbound/unbound.conf > "${LOG_DIR:-/app/log}/unbound_checkconf.txt"

python3 /app/cache_probe.py > "${LOG_DIR:-/app/log}/cache_probe.stdout" 2> "${LOG_DIR:-/app/log}/cache_probe.stderr" &
probe_pid=$!
unbound -d -c /etc/unbound/unbound.conf > "${LOG_DIR:-/app/log}/unbound.stdout" 2> "${LOG_DIR:-/app/log}/unbound.stderr" &
unbound_pid=$!
cleanup() {
    set +e
    kill "$unbound_pid" "$probe_pid" 2>/dev/null || true
    wait "$unbound_pid" "$probe_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ready=0
for _ in $(seq 1 100); do
    if unbound-control -c /etc/unbound/unbound.conf status >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$unbound_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ "$ready" != "1" ]]; then
    echo "Unbound remote-control readiness check failed" >&2
    exit 40
fi
printf '{"schema_version":1,"run_id":"%s","resolver_ip":"%s","cache_probe_port":%s}\n' \
    "${RUN_ID:-unregistered}" "${RESOLVER_IP:-10.81.0.53}" "${CACHE_PROBE_PORT:-10053}" > "${LOG_DIR:-/app/log}/resolver_ready.json"
wait "$unbound_pid"
