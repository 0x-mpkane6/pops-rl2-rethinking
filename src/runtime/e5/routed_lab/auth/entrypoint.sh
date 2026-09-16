#!/usr/bin/env bash
set -euo pipefail

ip route replace "${RESOLVER_NET:-10.81.0.0/24}" via "${UPSTREAM_GATEWAY:-10.82.0.1}"
mkdir -p "${LOG_DIR:-/app/log}"
exec python3 /app/auth_server.py
