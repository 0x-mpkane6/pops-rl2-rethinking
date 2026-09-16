#!/bin/bash

MODE="$1"
STATE_FILE="/app/benign_frag2_mode"

if [ "$MODE" == "on" ]; then
    echo "on" > "$STATE_FILE"
    echo "[+] Benign frag2 generator is ON"
else
    echo "off" > "$STATE_FILE"
    echo "[+] Benign frag2 generator is OFF"
fi
