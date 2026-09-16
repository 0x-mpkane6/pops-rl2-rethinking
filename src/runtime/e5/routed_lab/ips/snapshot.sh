#!/usr/bin/env bash
set -euo pipefail

label="${1:-snapshot}"
mkdir -p /app/log
iptables-save -c > "/app/log/firewall_${label}.rules"
ip -o addr show > "/app/log/interfaces_${label}.txt"
ip -o route show table all > "/app/log/routes_${label}.txt"
sysctl net.ipv4.ip_forward > "/app/log/ip_forward_${label}.txt"
