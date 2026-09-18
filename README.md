# Rethinking POPS Rl2

Research artifact for evaluating and refining POPS Rule 2 for
IPv4-fragmentation-based DNS cache poisoning. The work evaluates an
IPID-aware refinement that combines short-term non-initial-fragment volume,
IPID entropy, and unique-IPID ratio. It distinguishes controlled detector
evidence from routed resolver-level outcomes.

All attack traffic in this artifact is for defensive experimentation in
isolated local testbeds. Do not run the routed runtime tooling against
external, production, or third-party systems.

## Evidence Studies

- **E1: Benign boundary.** Measures initial-B5 benign trigger behavior over
  fragment loads and random, sequential, and small-pool IPID patterns.
- **E2: Controlled discrimination.** Uses volume- and schedule-matched benign
  and synthetic-attack traces to evaluate feature-level discrimination beyond
  fragment volume.
- **E3: Calibration and held-out evaluation.** Partitions paired traces,
  selects one threshold from a validation-only grid, locks it, and evaluates
  it once on held-out decisions.
- **E3 extension: High-threshold sensitivity.** A post-hoc,
  validation-only extension of the registered threshold grid; it is not used
  for selection or held-out evaluation.
- **E4: Statistical synthesis.** Aggregates run- and paired-trace evidence,
  uncertainty, and failure boundaries without treating related partitions as
  independent replications.
- **E5: Routed runtime validation.** Evaluates the locked rule in a local
  Unbound 1.26.1 resolver topology with AF_PACKET observation, NFQUEUE policy
  enforcement, actual IPv4 fragmentation, and TCP fallback.
- **Follow-ups.** Assess random-IPID-space sensitivity, an offline
  orphan-fragment-ratio baseline, a volume-only runtime branch, and a
  factorial load-by-attack campaign.

## Repository Layout

```text
src/
  controlled/       E1 and E2 controlled-emulation programs
  detector/         POPS/IPID-aware detector and controlled-lab dependencies
  calibration/      E3 partitioning, sweep, locking, and held-out evaluators
  synthesis/        E4 aggregation and uncertainty scripts
  runtime/          E5 routed IPS/Unbound topology and analysis
  followups/        IPID-space and orphan-fragment analyses
  figures/          Paper figure and table renderers

data/smoke/         Minimal controlled and E5 inputs for smoke testing

scripts/            Repository-level smoke check
```

The `data/smoke` directory contains only the small inputs needed to exercise
the packaged code. Full experiment outputs and paper tables are intentionally
kept outside this clean submission repository.

## Requirements

The controlled analyses and figure scripts were validated on Python 3.10.11:

```bash
python -m venv .venv
. .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The routed runtime testbed additionally requires Linux, Docker Compose,
`NET_ADMIN`/`NET_RAW` container capabilities, and the dependencies installed
by `src/runtime/e5/routed_lab` Dockerfiles. It is not intended for execution
on shared or production networks.

## Reproducibility Scope

From the repository root, run the smoke check:

```bash
python scripts/smoke_test.py
python scripts/smoke_test.py
```

The smoke test replays two compressed E5 logs, checks the bundled Unbound source,
and verifies the detector/runtime package without sending network traffic.
