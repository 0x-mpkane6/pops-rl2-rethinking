"""Offline (no-Docker) runner for the r2entropy lab's baseline / benign-on /
attack-on cases.

Why this exists
----------------
`scripts/run_case.sh` is the *official* way to run this lab: it spins up the
real Docker Compose topology (separate containers, a real 10.60.0.0/24
bridge network, real `dnslib`). That's the setup the paper's numbers are
measured from and it's what you should use for anything that ends up in the
report.

This script is a convenience/CI fallback for environments that don't have
Docker or `pip install dnslib` available (e.g. a locked-down sandbox). It
runs the *exact same, unmodified* resolver.py / auth_server.py from this lab
as real OS subprocesses talking over real UDP sockets on 127.0.0.1 (distinct
ports instead of distinct container IPs), driven by the real `dig` binary
with the same query pattern as client/test.sh. The only substitution is
`shim/dnslib.py`, a small dependency-free stand-in for the subset of the real
`dnslib` package this lab uses (see that file's docstring) -- it is only put
on PYTHONPATH for the two subprocesses this script spawns, so it never
shadows a real `dnslib` install anywhere else.

Because it isn't the Docker topology, treat numbers from this script as a
correctness/regression check, not as a replacement for an official
`run_case.sh` run.

Usage: python3 run_local.py <baseline|benign-on|attack-on> [rounds] [tag]

Note: attack-on needs the attacker's raw-socket IP spoofing (scapy +
NET_RAW), which this script does not attempt -- it only drives resolver.py +
auth_server.py directly, so attack-on here will show ASR=0%/no attacker
traffic. Use Docker for attack-on.
"""
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB_DIR = HERE.parent
RESOLVER_PY = LAB_DIR / "resolver" / "resolver.py"
AUTH_PY = LAB_DIR / "auth" / "auth_server.py"
SHIM_DIR = HERE / "shim"

AUTH_PORT = 15300
RESOLVER_CLIENT_PORT = 15353
RESOLVER_UPSTREAM_PORT = 15333
TARGET_ZONE = "example.net"
POISON_IP = "6.6.6.6"
BANK_IP_EXPECTED = "203.0.113.80"


def start_process(script_path, env, logfile):
    full_env = dict(os.environ)
    full_env["PYTHONPATH"] = str(SHIM_DIR) + os.pathsep + full_env.get("PYTHONPATH", "")
    full_env.update(env)
    full_env["PYTHONDONTWRITEBYTECODE"] = "1"
    full_env["PYTHONUNBUFFERED"] = "1"
    log = open(logfile, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-B", str(script_path)],
        env=full_env,
        stdout=log,
        stderr=subprocess.STDOUT,
        cwd=str(script_path.parent),
    )
    return proc, log


def run_case(case_name: str, rounds: int, tag: str = None, out_root: Path = None):
    assert case_name in ("baseline", "benign-on", "attack-on")
    tag = tag or str(time.time_ns())
    out_root = out_root or (HERE / "runs")
    case_dir = out_root / f"{case_name}-{tag}"
    app_dir = case_dir / "app"
    client_dir = case_dir / "client"
    app_dir.mkdir(parents=True)
    client_dir.mkdir(parents=True)

    benign_enabled = "1" if case_name == "benign-on" else "0"

    auth_env = {
        "ZONE_IP": "198.51.100.10",
        "BANK_REAL_IP": BANK_IP_EXPECTED,
        "AUTH_DELAY_SECONDS": "0.25",
        "IPID_SPACE": "2048",
        "AUTH_LISTEN_PORT": str(AUTH_PORT),
        "RESOLVER_IP": "127.0.0.1",
        "RESOLVER_UPSTREAM_PORT": str(RESOLVER_UPSTREAM_PORT),
        "FRAG2_OFFSET": "1480",
        "BENIGN_FRAG2_DELAY_MS": "3",
        "BENIGN_FRAG2_ENABLED": benign_enabled,
        "BENIGN_FRAG2_FILE": str(app_dir / "benign_frag2_mode"),
    }
    resolver_env = {
        "RESOLVER_LISTEN_IP": "0.0.0.0",
        "RESOLVER_LISTEN_PORT": str(RESOLVER_CLIENT_PORT),
        "RESOLVER_BIND_IP": "127.0.0.1",
        "UPSTREAM_DNS_IP": "127.0.0.1",
        "UPSTREAM_DNS_PORT": str(AUTH_PORT),
        "UPSTREAM_FIXED_SRC_PORT": str(RESOLVER_UPSTREAM_PORT),
        "UPSTREAM_TIMEOUT": "1.2",
        "CACHE_DEFAULT_TTL": "60",
        "TXID_SPACE": "1024",
        "DEFENSE_MODE": "on",
        "IPID_SPACE": "2048",
        "FRAG2_WINDOW_SECONDS": "2.0",
        "FRAG2_KEEP_SECONDS": "2.0",
        "R2_MIN_SAMPLES": "24",
        "R2_ENTROPY_THRESHOLD": "4.0",
        "R2_UNIQUE_RATIO_THRESHOLD": "0.70",
        "FRAG2_EVENTS_PATH": str(app_dir / "frag2_events.jsonl"),
        "R2_DECISIONS_PATH": str(app_dir / "r2_entropy_decisions.jsonl"),
        "R2_SUMMARY_PATH": str(app_dir / "r2_entropy_summary.json"),
        "DEFENSE_FILE": str(app_dir / "defense_mode"),
    }

    auth_proc, auth_log = start_process(AUTH_PY, auth_env, case_dir / "auth.log")
    resolver_proc, resolver_log = start_process(RESOLVER_PY, resolver_env, case_dir / "resolver.log")
    time.sleep(1.0)

    result_path = client_dir / "result.txt"
    latency_path = client_dir / "latency_ms.txt"
    profile = "baseline" if case_name == "baseline" else "benign-frag"

    print(f"[+] case={case_name} rounds={rounds} profile={profile} benign_frag2_enabled={benign_enabled} dir={case_dir}")
    try:
        with open(result_path, "w") as rf, open(latency_path, "w") as lf:
            for i in range(1, rounds + 1):
                ts = time.time_ns()
                qname = f"{'safe' if profile == 'baseline' else 'frag'}{i}.{ts}.{TARGET_ZONE}"

                start = time.perf_counter()
                subprocess.run(
                    ["dig", "@127.0.0.1", "-p", str(RESOLVER_CLIENT_PORT), qname,
                     "+tries=1", "+time=1", "+short"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                end = time.perf_counter()
                latency_ms = (end - start) * 1000.0
                time.sleep(0.05)

                bank_out = subprocess.run(
                    ["dig", "@127.0.0.1", "-p", str(RESOLVER_CLIENT_PORT), "bank.com",
                     "+tries=1", "+time=1", "+short"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                )
                bank_ip = bank_out.stdout.strip().splitlines()[0].strip() if bank_out.stdout.strip() else "NOANSWER"

                rf.write(bank_ip + "\n")
                lf.write(f"{latency_ms:.3f}\n")
                if i % 25 == 0 or i == rounds or i == 1:
                    print(f"    [{i}/{rounds}] bank.com -> {bank_ip} | latency={latency_ms:.3f}ms")
    finally:
        for proc in (auth_proc, resolver_proc):
            proc.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        for proc in (auth_proc, resolver_proc):
            if proc.poll() is None:
                proc.kill()
        auth_log.close()
        resolver_log.close()

    return summarize(case_name, case_dir, result_path, latency_path, app_dir)


def summarize(case_name, case_dir, result_path, latency_path, app_dir):
    lines = [l.strip() for l in open(result_path) if l.strip()]
    total = len(lines)
    poisoned = sum(1 for l in lines if l == POISON_IP)
    asr = (poisoned * 100.0 / total) if total else 0.0

    lat = [float(l.strip()) for l in open(latency_path) if l.strip()]
    lat_sorted = sorted(lat)
    avg = sum(lat) / len(lat) if lat else 0.0
    p95 = lat_sorted[max(0, math.ceil(0.95 * len(lat_sorted)) - 1)] if lat_sorted else 0.0

    decisions_path = app_dir / "r2_entropy_decisions.jsonl"
    entropies, samples_list, unique_ratios, actions = [], [], [], []
    if decisions_path.exists():
        for line in open(decisions_path):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            entropies.append(row["entropy"])
            samples_list.append(row["samples"])
            unique_ratios.append(row["unique_ratio"])
            actions.append(row["action"])

    summary = {
        "case": case_name,
        "total": total,
        "poisoned": poisoned,
        "asr_pct": round(asr, 2),
        "latency_avg_ms": round(avg, 3),
        "latency_p95_ms": round(p95, 3),
        "decisions": len(actions),
        "allow": sum(1 for a in actions if a == "allow"),
        "block": sum(1 for a in actions if a == "tc_block"),
        "entropy_avg": round(statistics.mean(entropies), 4) if entropies else None,
        "entropy_min": round(min(entropies), 4) if entropies else None,
        "entropy_max": round(max(entropies), 4) if entropies else None,
        "samples_avg": round(statistics.mean(samples_list), 3) if samples_list else None,
        "samples_min": min(samples_list) if samples_list else None,
        "samples_max": max(samples_list) if samples_list else None,
        "unique_ratio_avg": round(statistics.mean(unique_ratios), 4) if unique_ratios else None,
    }
    with open(case_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    case = sys.argv[1] if len(sys.argv) > 1 else "benign-on"
    n_rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    tag_arg = sys.argv[3] if len(sys.argv) > 3 else None
    run_case(case, n_rounds, tag_arg)
