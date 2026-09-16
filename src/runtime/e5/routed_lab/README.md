# E5 routed laboratory

Canonical lab-construction notes are in
[`E5_LAB.md`](../../E5_LAB.md).  Campaign execution order is in
[`E5_RUNBOOK.md`](../../E5_RUNBOOK.md).  Confirmatory numbers are in
[`E5_report.md`](../../E5_report.md).

This directory is the only E5 testbed: two Docker networks and a
two-interface IPS.  The attacker process is the only forged-tail sender;
there is no resolver-local poisoner.

The lab is driven by `research/Report/experiments/E5/run_e5.py`, which
supplies read-only replay schedules and per-cell artifact mounts.  Starting
`compose.yaml` manually without those mounts is useful only for
image/configuration debugging, not for data collection.
