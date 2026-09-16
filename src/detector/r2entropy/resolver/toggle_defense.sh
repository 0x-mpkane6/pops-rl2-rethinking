#!/bin/bash

MODE="$1"
STATE_FILE="/app/defense_mode"

if [ "$MODE" == "on" ]; then
    echo "on" > "$STATE_FILE"
    echo "[+] R2 entropy defense is ON"
else
    echo "off" > "$STATE_FILE"
    echo "[+] R2 entropy defense is OFF"
fi
