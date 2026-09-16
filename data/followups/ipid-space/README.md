# Controlled benign IPID-space sensitivity

Post-hoc descriptive sensitivity on the archived benign generator, comparing
2,048 and 65,536 identifiers. Both initial and locked configurations are fixed.
The 480 source runs (320 random/sequential main-grid and 160 random high-load)
are first reproduced against 144,000 archived decisions. Arrival/decision times
and occupancy are then checked to match exactly across IPID spaces.
Each cell has 20 runs of 300 decisions; intervals use 5,000 run resamples.
This is new synthetic identifier replay, not a re-labeling of old IPIDs and not
new held-out or runtime evidence. Sequential IPIDs also use the larger modulus;
their main-grid outcome is preserved. The pool-of-16 condition is not changed.

Inspect `summary.csv`, `run_rates.csv`, `decision_records.jsonl.gz`, and
`verification.json`. The registered addendum is `protocol.json`.
This covers **benign sensitivity only**; it does not establish attack PR-AUC,
malicious-answer rates, or cache insertion for a changed controlled IPID space.
