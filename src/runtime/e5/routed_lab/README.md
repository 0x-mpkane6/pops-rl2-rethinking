# E5 routed laboratory

Reviewer commands and validation scope are in
[`docs/reproducibility.md`](../../../../docs/reproducibility.md).
Frozen confirmatory results are under `data/runtime` at repository root.

This directory is the only E5 testbed: two Docker networks and a
two-interface IPS.  The attacker process is the only forged-tail sender;
there is no resolver-local poisoner.

The lab is driven by `src/runtime/e5/run_e5.py`, which
supplies read-only replay schedules and per-cell artifact mounts.  Starting
`compose.yaml` manually without those mounts is useful only for
image/configuration debugging, not for data collection.
