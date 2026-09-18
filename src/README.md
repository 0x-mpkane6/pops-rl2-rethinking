# Source Layout

This directory stages the source code needed to reproduce the paper's
controlled, calibration, synthesis, runtime, follow-up, and figure workflows.
Frozen inputs and confirmatory outputs are added separately under `data/`.

- `controlled/`: E1 benign-boundary and E2 volume-matched emulation.
- `detector/r2entropy/`: detector and controlled-lab dependencies used by E1/E2.
- `calibration/e3/`: split, validation sweep, lock, and held-out evaluation.
- `synthesis/e4/`: run- and paired-trace aggregation.
- `runtime/e5/`: routed IPS/Unbound testbed and result analysis.
- `followups/`: IPID-space and orphan-fragment analyses.
- `figures/`: scripts that render paper figures and addenda from frozen data.

E5 runtime paths and E1/E2 detector imports use this repository layout.
Other historical analysis and figure scripts still retain research-layout
paths. Use `../docs/reproducibility.md` for verified reviewer entry points.
