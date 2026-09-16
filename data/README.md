# Frozen Data

All files in this directory are frozen experiment inputs or outputs. They are
copied without transformation from the research workspace; `SHA256SUMS.txt`
records the public-artifact bytes.

- `controlled/benign-boundary/`: run-level benign fragmentation outcomes and
  validation for the initial operating point.
- `controlled/volume-matched/`: paired controlled decisions, summaries, and
  validation used for feature discrimination and calibration input.
- `calibration/registered-grid/`: registered grid, trace partition manifest,
  frozen splits, threshold lock, and one-time held-out results.
- `calibration/extended-grid/`: explicitly post-hoc validation-only grid
  extension; it was not eligible for threshold selection or held-out testing.
- `synthesis/`: run- and paired-trace uncertainty summaries.
- `runtime/`: confirmatory routed-resolver, factorial, and volume-only
  campaign metrics, schedules, configurations, and validators.
- `followups/ipid-space/`: high-load random-IPID-space sensitivity inputs and
  summaries.
- `followups/orphan-ratio/`: offline pre-enforcement orphan-fragment analysis.
- `paper/`: provenance manifests for paper-facing figures and tables.

Raw packet captures, duplicate source snapshots, exploratory runs, and
pilot/sanity outputs are intentionally excluded. The runtime campaign metrics
are retained so reported resolver-level outcomes can be independently audited.
