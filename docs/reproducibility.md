# Reviewer quick start

Run commands from the repository root with Python 3.10 or newer.
Installation and the offline checks were verified in a fresh Python 3.10.11
virtual environment using `requirements.txt`.

```bash
python -m pip install -r requirements.txt
python scripts/smoke_test.py
python -m pytest tests -q
```

The smoke test takes a few seconds in the checked environment. It requires
no Docker, privileges, or network access. Expected result: `Offline smoke PASS`.
The suite contains 68 E5 tests and 12 offline follow-up tests.

The smoke test checks all frozen file hashes; 320 primary, 320 factorial,
80 volume-only and 80 excluded PMTUD runs; 50 trials per run; aggregate means;
the locked (8, 6, 0.90) threshold; the 27,600-row held-out partition; key
runtime ASRs; and raw-log reconstruction for two primary E5 runs.
These two selected runs illustrate detector evasion and triggered mitigation;
they are smoke fixtures, not an independent replication or the complete raw data.

## Runtime preparation

The local Unbound 1.26.1 source is bundled as
`src/runtime/e5/vendor/unbound-1.26.1.tar.gz`, with its license and checksum
beside it. Docker unpacks the archive during the resolver build. It is
third-party source, not covered by the repository's project-code license.
Build dependencies are installed by Docker.

```bash
python src/runtime/e5/run_e5.py --stage confirmatory --dry-run
python src/runtime/e5/run_e5.py --protocol src/runtime/e5/e5_factorial_protocol.json --stage confirmatory --dry-run
docker compose -f src/runtime/e5/routed_lab/compose.yaml config --quiet
```

The runner has primary, factorial, B2 and PMTUD protocol files beside it. For
live collection, use Linux with Docker Compose and the capabilities described
in the root README, then run the runner with `--stage all` and a new `--run-id`.
Use only the isolated lab. Outputs go to `src/runtime/e5/output/`.
Use `--output-root /path/to/results` to keep new runs outside the source tree.
PMTUD is a separate excluded branch and must not be pooled with primary data.
All five images were built, and the live routing/NFQUEUE, DNS and cache-probe
preflight and seven-run pilot passed on Docker Desktop's Linux engine.
The full confirmatory campaigns were not rerun during packaging.

To run the same live checks, choose a new run ID and reuse it for both commands:

```bash
python src/runtime/e5/run_e5.py --stage preflight --run-id local-check --output-root ../results
python src/runtime/e5/run_e5.py --stage pilot --run-id local-check --output-root ../results
```

## Paper coverage

| Evidence | Data directory |
| --- | --- |
| Figure 2 and Table 1: benign boundary | `data/controlled/benign-boundary` |
| Figure 3: matched discrimination | `data/controlled/volume-matched` |
| Figures 4–5: calibration, held-out, failure probes | `data/calibration/registered-grid` |
| Post-hoc threshold extension | `data/calibration/extended-grid` |
| Table 2: IPID-space sensitivity | `data/followups/ipid-space` |
| Tables 3–4: primary runtime | `data/runtime/primary` |
| Table 3: B2 volume-only rows | `data/runtime/volume-only` |
| Table 5: factorial runtime | `data/runtime/factorial` |
| Offline orphan ratio | `data/followups/orphan-ratio` |
| Validity: excluded ICMP PTB branch | `data/runtime/pmtud-excluded` |

## Evidence and provenance

`data/SHA256SUMS.txt` uses paths relative to `data/`. Historical absolute paths
inside frozen JSON files are provenance, not instructions or portable paths.
The saved registration manifests describe historical source snapshots; the
packaged runner includes later changes and path normalization and is not claimed
to be byte-identical to every historical campaign version.

`data/smoke/e5/manifest.json` identifies each selected source log and records
its uncompressed SHA-256. Gzip compression is lossless and deterministic.
The full controlled decision files remain under `data/controlled` and
`data/calibration`; complete runtime PCAPs and all raw logs are not bundled.
Historical E3/E4 and figure entry points still require path adaptation; complete
raw logs and packet captures are not included in this compact distribution.
