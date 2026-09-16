#!/usr/bin/env python3
"""Create read-only E4 statistical-synthesis tables from frozen E1–E3 artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
E4_ROOT = SCRIPT_DIR.parent
REPO_ROOT = E4_ROOT.parents[3]
SUMMARY_FIELDS = [
    "source_experiment", "source_artifact", "source_hash", "scope", "attack_condition",
    "benign_condition", "level", "variant_or_comparison", "metric", "estimate", "ci95_low",
    "ci95_high", "n_independent_units", "independent_unit", "inference_method",
    "measurement_status", "notes",
]
EFFECT_FIELDS = SUMMARY_FIELDS + ["registered_meaningful_margin", "verdict"]
COVERAGE_FIELDS = ["metric", "E1_status", "E2_status", "E3_status", "scope_note"]


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_path(manifest: dict[str, Any], experiment: str, artifact: str) -> tuple[Path, str]:
    record = manifest["upstream_inputs"][experiment]["artifacts"][artifact]
    path = (REPO_ROOT / record["path"]).resolve()
    if not path.is_file() or sha256_file(path) != record["sha256"]:
        raise ValueError(f"Manifest hash mismatch: {experiment}/{artifact}")
    return path, record["sha256"]


def row(**values: Any) -> dict[str, Any]:
    result = {field: "" for field in SUMMARY_FIELDS}
    result.update(values)
    return result


def result_row(source_experiment: str, source_artifact: str, source_hash: str, scope: str,
               attack: str, benign: str, level: Any, variant: str, metric: str,
               value: dict[str, Any], unit: str, method: str, notes: str = "") -> dict[str, Any]:
    ci = value.get("ci95", ["", ""])
    n_units: Any = value.get("n_pairs", "")
    if n_units == "" and isinstance(value.get("n_pairs_by_cell"), list):
        counts = value["n_pairs_by_cell"]
        n_cells = value.get("n_cells", len(counts))
        if len(set(counts)) == 1:
            n_units = f"{counts[0]} per cell x {n_cells} cells"
        else:
            n_units = f"{counts} across {n_cells} cells"
    return row(
        source_experiment=source_experiment, source_artifact=source_artifact, source_hash=source_hash,
        scope=scope, attack_condition=attack, benign_condition=benign, level=level,
        variant_or_comparison=variant, metric=metric, estimate=value.get("mean", ""),
        ci95_low=ci[0] if len(ci) == 2 else "", ci95_high=ci[1] if len(ci) == 2 else "",
        n_independent_units=n_units, independent_unit=unit,
        inference_method=method, measurement_status="measured", notes=notes,
    )


def e1_rows(data: dict[str, Any], source_hash: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cell in data.get("levels", []):
        scope_name = "primary_benign"
        base = dict(
            source_experiment="E1", source_artifact="e1_results.json", source_hash=source_hash,
            scope=scope_name, attack_condition="", benign_condition=cell["behavior"], level=cell["level"],
            independent_unit="run", inference_method="cluster bootstrap over independent runs",
            measurement_status="measured",
        )
        combined = cell["variants"]["combined"]
        rows.append(row(**base, variant_or_comparison="combined", metric="benign_trigger_rate",
                        estimate=combined["fpr_run_mean"], ci95_low=combined["fpr_cluster_bootstrap_ci95"][0],
                        ci95_high=combined["fpr_cluster_bootstrap_ci95"][1], n_independent_units=cell["n_runs"],
                        notes="Benign-only FPR; not an attack-detection metric."))
        for metric, estimate_key, ci_key in (
            ("samples", "samples_mean", "samples_ci95"),
            ("entropy", "entropy_mean", "entropy_ci95"),
            ("unique_ratio", "unique_ratio_mean", "unique_ratio_ci95"),
        ):
            rows.append(row(**base, variant_or_comparison="traffic_feature", metric=metric,
                            estimate=cell[estimate_key], ci95_low=cell[ci_key][0], ci95_high=cell[ci_key][1],
                            n_independent_units=cell["n_runs"], notes="Benign controlled-emulation feature."))
    for cell in data.get("high_load", []):
        scope_name = "supplementary_high_load_benign"
        base = dict(
            source_experiment="E1", source_artifact="e1_results.json", source_hash=source_hash,
            scope=scope_name, attack_condition="", benign_condition="random2048", level=cell["level"],
            independent_unit="run", inference_method="cluster bootstrap over independent runs",
            measurement_status="measured",
        )
        combined = cell["combined"]
        rows.append(row(**base, variant_or_comparison="combined", metric="benign_trigger_rate",
                        estimate=combined["fpr_run_mean"], ci95_low=combined["ci95"][0],
                        ci95_high=combined["ci95"][1], n_independent_units=20,
                        notes="Supplementary high-load benign FPR; source summary fixes K=20."))
        for metric, estimate_key in (
            ("samples", "samples_mean"), ("entropy", "entropy_mean"), ("unique_ratio", "unique_ratio_mean"),
        ):
            rows.append(row(**(base | {"measurement_status": "measured_ci_not_available_in_frozen_compact_artifact"}), variant_or_comparison="traffic_feature", metric=metric,
                            estimate=cell[estimate_key], ci95_low="", ci95_high="", n_independent_units=20,
                            notes="Supplementary high-load feature; no frozen feature CI in this compact artifact."))
    return rows


def e2_rows(data: dict[str, Any], source_hash: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    effects: list[dict[str, Any]] = []
    metric_map = {
        "attack_alert": "attack_alert_rate", "benign_trigger": "benign_trigger_rate",
        "synthetic_fnr": "FNR", "balanced_precision": "balanced_precision", "youden_j": "J",
    }
    analysis = data["analysis"]
    for cell in analysis["test_cells"]:
        for variant in ("combined", "volume"):
            for source_metric, metric in metric_map.items():
                rows.append(result_row("E2", "e2_results.json", source_hash, "all_test_cells",
                                       cell["attack_condition"], cell["benign_condition"], cell["level"], variant,
                                       metric, cell["variants"][variant][source_metric], "paired_trace",
                                       "5000 whole-pair bootstrap resamples"))
        for feature, value in cell["feature_auprc_high_is_suspicious"].items():
            rows.append(result_row("E2", "e2_results.json", source_hash, "all_test_cells",
                                   cell["attack_condition"], cell["benign_condition"], cell["level"], feature,
                                   "feature_PR_AUC", value, "paired_trace",
                                   "5000 whole-pair bootstrap resamples",
                                   "Feature-level diagnostic; not the locked E3 combined-rule PR-AUC."))
        effect = result_row("E2", "e2_results.json", source_hash, "all_test_cells",
                            cell["attack_condition"], cell["benign_condition"], cell["level"],
                            "combined_minus_volume", "Delta_J", cell["delta_j_combined_minus_volume"],
                            "paired_trace", "5000 whole-pair bootstrap resamples")
        effects.append(effect | {"registered_meaningful_margin": 0.05, "verdict": "cell_level_no_registered_verdict"})
    for effect_data in analysis["paired_ablation_macro_effects"]:
        effect = result_row("E2", "e2_results.json", source_hash, "primary_macro",
                            effect_data["attack_condition"], "matching_benign", "macro_24_60_120_200",
                            f"combined_minus_{effect_data['baseline_variant']}", "Delta_J", effect_data["result"],
                            "paired_trace", "5000 whole-pair bootstrap resamples")
        effects.append(effect | {"registered_meaningful_margin": effect_data["registered_meaningful_margin"],
                                 "verdict": effect_data["verdict"]})
    return rows, effects


def e3_rows(data: dict[str, Any], source_hash: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    effects: list[dict[str, Any]] = []
    metrics = ("attack_alert_rate", "benign_trigger_rate", "FNR", "balanced_precision", "J")
    cells = list(data["primary"]["cells"])
    for group in data["secondary_reports"].values():
        cells.extend(group)
    for cell in cells:
        for variant, variant_metrics in cell["variants"].items():
            for metric in metrics:
                rows.append(result_row("E3", "e3_test_results.json", source_hash, cell["scope"],
                                       cell["attack_condition"], cell["benign_condition"], cell["level"], variant,
                                       metric, variant_metrics[metric], "paired_trace",
                                       "5000 paired-trace bootstrap resamples"))
        for comparison, value in cell["comparisons"].items():
            effects.append(result_row("E3", "e3_test_results.json", source_hash, cell["scope"],
                                      cell["attack_condition"], cell["benign_condition"], cell["level"], comparison,
                                      "Delta_J", value, "paired_trace", "5000 paired-trace bootstrap resamples")
                           | {"registered_meaningful_margin": "", "verdict": "report_only_no_E3_hard_constraint"})
    macro = data["primary"]["macro"]
    for variant, variant_metrics in macro["variants"].items():
        for metric in metrics:
            rows.append(result_row("E3", "e3_test_results.json", source_hash, "primary_macro",
                                   "primary_sweeps", "matching_benign", "macro_8_cells", variant, metric,
                                   variant_metrics[metric], "paired_trace",
                                   "5000 stratified paired-trace bootstrap resamples"))
    for comparison, value in macro["comparisons"].items():
        effects.append(result_row("E3", "e3_test_results.json", source_hash, "primary_macro",
                                  "primary_sweeps", "matching_benign", "macro_8_cells", comparison, "Delta_J",
                                  value, "paired_trace", "5000 stratified paired-trace bootstrap resamples")
                       | {"registered_meaningful_margin": "", "verdict": "positive_CI_not_a_security_claim"})
    return rows, effects


def coverage_rows() -> list[dict[str, str]]:
    return [
        {"metric": "benign_trigger_rate / synthetic_FPR", "E1_status": "measured", "E2_status": "measured", "E3_status": "measured", "scope_note": "Detector behavior only."},
        {"metric": "synthetic_attack_alert / TPR and FNR", "E1_status": "not_primary_metric", "E2_status": "measured", "E3_status": "measured", "scope_note": "Synthetic detector alert, not attack success."},
        {"metric": "entropy and unique_ratio", "E1_status": "measured", "E2_status": "measured", "E3_status": "not_primary_reported_metric", "scope_note": "E3 reuses features only to evaluate the locked binary rule."},
        {"metric": "J and paired Delta_J", "E1_status": "not_measured", "E2_status": "measured", "E3_status": "measured", "scope_note": "E2 and E3 must not be pooled."},
        {"metric": "balanced precision (50:50)", "E1_status": "not_measured", "E2_status": "measured", "E3_status": "measured", "scope_note": "Synthetic balanced class mix, not production prevalence."},
        {"metric": "feature-level PR-AUC", "E1_status": "not_measured", "E2_status": "measured", "E3_status": "not_applicable_to_locked_binary_combined_rule", "scope_note": "Do not transfer E2 feature PR-AUC to E3 B5."},
        {"metric": "ASR / poisoning success", "E1_status": "not_measured", "E2_status": "not_supported", "E3_status": "not_supported", "scope_note": "No end-to-end poisoning outcome exists."},
        {"metric": "latency / throughput / CPU / memory", "E1_status": "not_supported_for_virtual_time", "E2_status": "not_measured", "E3_status": "not_measured", "scope_note": "Requires runtime/E5 evidence."},
    ]


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E4_ROOT / "e4_protocol.json")
    parser.add_argument("--manifest", type=Path, default=E4_ROOT / "e4_input_manifest.json")
    parser.add_argument("--preflight", type=Path, default=E4_ROOT / "e4_preflight.json")
    parser.add_argument("--output-dir", type=Path, default=E4_ROOT)
    parser.add_argument("--force", action="store_true", help="Replace existing E4 aggregation outputs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    protocol, manifest, preflight = (load_json(path) for path in (args.protocol, args.manifest, args.preflight))
    if preflight.get("status") != "PASS":
        raise ValueError("E4 preflight is not PASS")
    if preflight.get("artifact_hashes", {}).get("protocol") != sha256_file(args.protocol):
        raise ValueError("Preflight does not bind the current protocol")
    if preflight.get("artifact_hashes", {}).get("manifest") != sha256_file(args.manifest):
        raise ValueError("Preflight does not bind the current manifest")
    if protocol.get("aggregation_execution_status") != "not_started":
        raise ValueError("Protocol does not permit first aggregation")
    outputs = [args.output_dir / name for name in ("e4_summary.csv", "e4_paired_effects.csv", "e4_metric_coverage.csv", "e4_summary.json")]
    if not args.force and any(path.exists() for path in outputs):
        raise FileExistsError("Refusing to overwrite E4 aggregation outputs; use --force only for a reviewed rebuild.")

    e1_path, e1_hash = manifest_path(manifest, "E1", "e1_results.json")
    e2_path, e2_hash = manifest_path(manifest, "E2", "e2_results.json")
    e3_path, e3_hash = manifest_path(manifest, "E3", "e3_test_results.json")
    summary = e1_rows(load_json(e1_path), e1_hash)
    e2_summary, e2_effects = e2_rows(load_json(e2_path), e2_hash)
    e3_summary, e3_effects = e3_rows(load_json(e3_path), e3_hash)
    summary.extend(e2_summary)
    summary.extend(e3_summary)
    effects = e2_effects + e3_effects
    coverage = coverage_rows()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(outputs[0], SUMMARY_FIELDS, summary)
    write_csv(outputs[1], EFFECT_FIELDS, effects)
    write_csv(outputs[2], COVERAGE_FIELDS, coverage)
    result = {
        "schema_version": 1,
        "experiment": "E4 read-only statistical synthesis",
        "status": "aggregation_complete_read_only",
        "generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "data_access": "Frozen E1/E2/E3 result artifacts registered in e4_input_manifest.json; no raw decision data opened.",
        "protocol": {"path": "research/Report/experiments/E4/e4_protocol.json", "sha256": sha256_file(args.protocol)},
        "input_manifest": {"path": "research/Report/experiments/E4/e4_input_manifest.json", "sha256": sha256_file(args.manifest)},
        "preflight": {"path": "research/Report/experiments/E4/e4_preflight.json", "sha256": sha256_file(args.preflight), "status": "PASS"},
        "cross_experiment_dependency": protocol["cross_experiment_rules"]["E2_E3_dependence"],
        "selection_or_threshold_modification": False,
        "statistical_pooling_of_E2_and_E3": False,
        "asr": "not_measured_not_supported_by_upstream_decision_level_data",
        "outputs": {path.name: {"sha256": sha256_file(path), "rows": count} for path, count in ((outputs[0], len(summary)), (outputs[1], len(effects)), (outputs[2], len(coverage)))},
    }
    outputs[3].write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"E4 synthesis complete: {len(summary)} summary rows, {len(effects)} paired-effect rows, {len(coverage)} coverage rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
