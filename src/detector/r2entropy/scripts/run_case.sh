#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_SCRIPT_DIR="$(cd "$LAB_DIR/../base/scripts" && pwd)"

source "$BASE_SCRIPT_DIR/run_case_common.sh"

CASE_NAME="${1:-}"
ROUNDS="${2:-${ROUNDS:-150}}"
TARGET_ZONE="${TARGET_ZONE:-example.net}"
POISON_IP="${POISON_IP:-6.6.6.6}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
export RUN_ID

if [ -z "$CASE_NAME" ]; then
    echo "Usage: $0 <baseline|benign-on|attack-on> [rounds]"
    exit 1
fi

cd "$LAB_DIR"

ensure_stack_up
stop_attack_worker "python3 /app/spoof_r2entropy.py"

snapshot_case_artifacts() {
    local metrics="$1"
    local out_dir="$LAB_DIR/artifacts/$RUN_ID/$CASE_NAME"

    mkdir -p "$out_dir/app"
    printf "%s\n" "$metrics" > "$out_dir/metrics.txt"

    # Stream via `docker compose exec ... cat` instead of `docker cp`: on
    # Docker Desktop for Windows, `docker cp <cid>:<path> <out_dir>` mangles
    # MSYS-style absolute destination paths (e.g. /d/foo/bar) into invalid
    # ones (e.g. D:\d\foo\bar) and fails silently under `|| true` (see
    # measure_asr.sh / measure_latency.sh, which use the same workaround).
    docker compose exec -T client cat /app/result.txt > "$out_dir/result.txt" 2>/dev/null || true
    docker compose exec -T client cat /app/latency_ms.txt > "$out_dir/latency_ms.txt" 2>/dev/null || true

    docker compose exec -T resolver cat /app/frag2_events.jsonl > "$out_dir/app/frag2_events.jsonl" 2>/dev/null || true
    docker compose exec -T resolver cat /app/r2_entropy_decisions.jsonl > "$out_dir/app/r2_entropy_decisions.jsonl" 2>/dev/null || true
    docker compose exec -T resolver cat /app/r2_entropy_summary.json > "$out_dir/app/r2_entropy_summary.json" 2>/dev/null || true

    docker compose exec -T attacker cat /tmp/attack.log > "$out_dir/attack.log" 2>/dev/null || true

    docker compose logs resolver > "$out_dir/resolver.log" 2>&1 || true
    docker compose logs attacker > "$out_dir/attacker.log" 2>&1 || true

    echo "[+] Artifacts saved to $out_dir"
}

toggle_benign_frag2() {
    local mode="${1:-off}"
    docker compose exec -T auth bash /app/toggle_benign_frag2.sh "$mode"
}

case "$CASE_NAME" in
    baseline)
        toggle_defense on
        toggle_benign_frag2 off
        docker compose stop attacker >/dev/null 2>&1 || true
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "baseline"
        ;;
    benign-on)
        toggle_defense on
        # Only benign-on makes auth emit realistic, legitimate frag2 (offset>0)
        # traffic, so R2EntropyTable is exercised with real IPID samples instead
        # of an always-empty window (see auth_server.py for the rationale).
        toggle_benign_frag2 on
        docker compose stop attacker >/dev/null 2>&1 || true
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "benign-frag"
        ;;
    attack-on)
        toggle_defense on
        toggle_benign_frag2 off
        start_attack_worker "nohup python3 /app/spoof_r2entropy.py >/tmp/attack.log 2>&1 &"
        sleep 1
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "attack"
        ;;
    *)
        echo "Unknown case: $CASE_NAME"
        echo "Usage: $0 <baseline|benign-on|attack-on> [rounds]"
        exit 1
        ;;
esac

METRICS="$(collect_metrics "$POISON_IP")"
echo "$METRICS"
snapshot_case_artifacts "$METRICS"
