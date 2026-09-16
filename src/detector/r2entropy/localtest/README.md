# localtest (no-Docker runner)

`run_local.py` runs `baseline` / `benign-on` against the **real, unmodified**
`../resolver/resolver.py` and `../auth/auth_server.py` as two OS processes
talking over real UDP sockets on `127.0.0.1`, driven by the real `dig`
binary with the same query loop as `client/test.sh`. It exists for
environments without Docker or `pip install dnslib` (e.g. CI, or a locked
sandbox) — `shim/dnslib.py` is a small dependency-free stand-in for the
subset of the real `dnslib` package this lab uses, put on `PYTHONPATH` only
for the two subprocesses this script spawns.

**This is not a replacement for `scripts/run_case.sh`.** The Docker Compose
setup is the official topology (separate containers/IPs, real `dnslib`,
`attack-on` with real IP-spoofed fragments via scapy). Use this script for
a quick correctness check or when Docker isn't available; use
`run_case.sh` for anything that goes in the report.

```bash
python3 run_local.py baseline 150
python3 run_local.py benign-on 150
```

`attack-on` is not supported here (it needs the attacker's raw-socket IP
spoofing, which requires `NET_RAW`/root) — use Docker for that case.

Output goes to `runs/<case>-<tag>/`, mirroring the layout `run_case.sh`
copies into `artifacts/r2entropy/<case>/` (`app/r2_entropy_decisions.jsonl`,
`app/r2_entropy_summary.json`, `client/result.txt`, `client/latency_ms.txt`,
`summary.json`).
