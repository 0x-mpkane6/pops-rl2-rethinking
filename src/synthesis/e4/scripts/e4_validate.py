#!/usr/bin/env python3
"""Independent final audit of the E4 read-only statistical synthesis."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
E4_ROOT = SCRIPT_DIR.parent
REPO_ROOT = E4_ROOT.parents[3]
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def add(checks: list[dict[str, Any]], name: str, passed: bool, details: Any) -> None:
    checks.append({"name": name, "status": "PASS" if passed else "FAIL", "details": details})


def artifact_path(record: dict[str, Any]) -> Path:
    return (REPO_ROOT / record["path"]).resolve()


def check_manifest_inputs(manifest: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    matched, counts = True, {}
    for experiment, spec in manifest["upstream_inputs"].items():
        count = 0
        for record in spec["artifacts"].values():
            path = artifact_path(record)
            matched = matched and path.is_file() and sha256(path) == record["sha256"]
            count += 1
        counts[experiment] = count
    add(checks, "manifest_registered_inputs_still_match_hashes", matched, counts)


def check_summary_hashes(root: Path, summary_meta: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    matched, details = True, {}
    for filename, record in summary_meta.get("outputs", {}).items():
        path = root / filename
        actual = sha256(path) if path.is_file() else None
        matched = matched and actual == record.get("sha256")
        details[filename] = {"expected": record.get("sha256"), "actual": actual, "rows": record.get("rows")}
    add(checks, "synthesis_output_hashes_match_summary_metadata", matched, details)


def check_eol_equivalence(manifest: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    records = manifest.get("E3_final_validator_artifact_integrity", {})
    valid, modes = True, {}
    for name, record in records.items():
        status = record.get("verification_status")
        modes[name] = status
        if status == "pass_byte_exact":
            valid = valid and record.get("filesystem_sha256") == record.get("frozen_expected_sha256")
        elif status == "pass_git_lf_checkout_equivalent" and name in {"test_csv", "summary_csv"}:
            artifact = "e3_test_results.csv" if name == "test_csv" else "e3_summary.csv"
            path = artifact_path(manifest["upstream_inputs"]["E3"]["artifacts"][artifact])
            raw = path.read_bytes()
            normalized = hashlib.sha256(raw.replace(b"\n", b"\r\n")).hexdigest() if b"\r" not in raw else None
            valid = valid and normalized == record.get("frozen_expected_sha256")
        else:
            valid = False
    add(checks, "E3_final_validator_integrity_is_exact_or_registered_EOL_equivalent", valid, modes)


def check_summary_schema(summary: list[dict[str, str]], effects: list[dict[str, str]], coverage: list[dict[str, str]], checks: list[dict[str, Any]]) -> None:
    required = {"source_experiment", "source_artifact", "source_hash", "scope", "metric", "estimate", "n_independent_units", "independent_unit", "inference_method", "measurement_status"}
    rows_ok = len(summary) == 703 and len(effects) == 70 and len(coverage) == 8
    for record in summary + effects:
        rows_ok = rows_ok and required.issubset(record) and all(record[key] != "" for key in required)
    measured_missing_ci = sum(1 for record in summary if record["measurement_status"] == "measured" and (not record["ci95_low"] or not record["ci95_high"]))
    add(checks, "summary_effect_and_coverage_schema_counts_and_CI_fields", rows_ok and measured_missing_ci == 0,
        {"summary_rows": len(summary), "effect_rows": len(effects), "coverage_rows": len(coverage), "measured_rows_missing_CI": measured_missing_ci})


def check_effect_replay(manifest: dict[str, Any], effects: list[dict[str, str]], checks: list[dict[str, Any]]) -> None:
    e2_path = artifact_path(manifest["upstream_inputs"]["E2"]["artifacts"]["e2_results.json"])
    e3_path = artifact_path(manifest["upstream_inputs"]["E3"]["artifacts"]["e3_test_results.json"])
    e2, e3 = load_json(e2_path), load_json(e3_path)
    expected_e2 = {(item["attack_condition"], f"combined_minus_{item['baseline_variant']}"): item["result"] for item in e2["analysis"]["paired_ablation_macro_effects"]}
    actual_e2 = {(row["attack_condition"], row["variant_or_comparison"]): row for row in effects if row["source_experiment"] == "E2" and row["scope"] == "primary_macro"}
    e2_ok = len(expected_e2) == len(actual_e2) == 8 and all(
        float(actual_e2[key]["estimate"]) == value["mean"] and float(actual_e2[key]["ci95_low"]) == value["ci95"][0] and float(actual_e2[key]["ci95_high"]) == value["ci95"][1]
        for key, value in expected_e2.items()
    )
    expected_e3 = e3["primary"]["macro"]["comparisons"]
    actual_e3 = {row["variant_or_comparison"]: row for row in effects if row["source_experiment"] == "E3" and row["scope"] == "primary_macro"}
    e3_ok = len(expected_e3) == len(actual_e3) == 2 and all(
        float(actual_e3[key]["estimate"]) == value["mean"] and float(actual_e3[key]["ci95_low"]) == value["ci95"][0] and float(actual_e3[key]["ci95_high"]) == value["ci95"][1]
        for key, value in expected_e3.items()
    )
    add(checks, "E2_and_E3_primary_paired_effects_replay_exactly_without_pooling", e2_ok and e3_ok,
        {"E2_macro_rows": len(actual_e2), "E3_macro_rows": len(actual_e3), "E3_Delta_J_new_minus_B2": actual_e3.get("Delta_J_new_B5_minus_B2", {}).get("estimate")})


def check_coverage(coverage: list[dict[str, str]], checks: list[dict[str, Any]]) -> None:
    asr = next((row for row in coverage if row["metric"] == "ASR / poisoning success"), None)
    runtime = next((row for row in coverage if row["metric"] == "latency / throughput / CPU / memory"), None)
    passed = asr is not None and runtime is not None and asr["E2_status"] == "not_supported" and asr["E3_status"] == "not_supported" and runtime["E3_status"] == "not_measured"
    add(checks, "ASR_and_runtime_metric_gaps_are_explicit", passed, {"ASR": asr, "runtime": runtime})


def check_figures_report(root: Path, checks: list[dict[str, Any]]) -> None:
    figures = ["e4_effect_sizes.png", "e4_failure_boundaries.png", "e4_metric_coverage.png"]
    png_ok = all((root / "figures" / name).is_file() and (root / "figures" / name).read_bytes().startswith(PNG_SIGNATURE) for name in figures)
    report = (root / "E4_report.md")
    report_ok = report.is_file()
    missing_links: list[str] = []
    if report_ok:
        contents = report.read_text(encoding="utf-8")
        report_ok = "not pool" in contents or "không pool" in contents
        report_ok = report_ok and "ASR" in contents and "E5" in contents
        for figure in figures:
            if f"figures/{figure}" not in contents:
                missing_links.append(figure)
        report_ok = report_ok and not missing_links
    add(checks, "figures_are_valid_PNG_and_report_references_scope_limitations", png_ok and report_ok,
        {"figures": figures, "missing_report_figure_links": missing_links})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E4_ROOT / "e4_protocol.json")
    parser.add_argument("--manifest", type=Path, default=E4_ROOT / "e4_input_manifest.json")
    parser.add_argument("--preflight", type=Path, default=E4_ROOT / "e4_preflight.json")
    parser.add_argument("--summary-meta", type=Path, default=E4_ROOT / "e4_summary.json")
    parser.add_argument("--summary", type=Path, default=E4_ROOT / "e4_summary.csv")
    parser.add_argument("--effects", type=Path, default=E4_ROOT / "e4_paired_effects.csv")
    parser.add_argument("--coverage", type=Path, default=E4_ROOT / "e4_metric_coverage.csv")
    parser.add_argument("--output", type=Path, default=E4_ROOT / "e4_validation.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args(); checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {"schema_version": 1, "experiment": "E4 independent final validation", "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "checks": checks,
                              "audit_scope": "Frozen E4 inputs/outputs only; no raw decision data, threshold selection, or upstream modification."}
    try:
        protocol, manifest, preflight, summary_meta = (load_json(path) for path in (args.protocol, args.manifest, args.preflight, args.summary_meta))
        summary, effects, coverage = load_csv(args.summary), load_csv(args.effects), load_csv(args.coverage)
        add(checks, "protocol_manifest_preflight_summary_provenance", protocol.get("status") == "registered-before-aggregation" and preflight.get("status") == "PASS" and summary_meta.get("status") == "aggregation_complete_read_only" and preflight.get("artifact_hashes", {}).get("protocol") == sha256(args.protocol) and preflight.get("artifact_hashes", {}).get("manifest") == sha256(args.manifest) and summary_meta.get("protocol", {}).get("sha256") == sha256(args.protocol) and summary_meta.get("input_manifest", {}).get("sha256") == sha256(args.manifest), {"preflight": preflight.get("status"), "summary": summary_meta.get("status")})
        add(checks, "E4_read_only_and_no_pooling_status", summary_meta.get("selection_or_threshold_modification") is False and summary_meta.get("statistical_pooling_of_E2_and_E3") is False and manifest.get("raw_data_access") == "none", {"raw_data_access": manifest.get("raw_data_access")})
        check_manifest_inputs(manifest, checks)
        check_summary_hashes(E4_ROOT, summary_meta, checks)
        check_eol_equivalence(manifest, checks)
        check_summary_schema(summary, effects, coverage, checks)
        check_effect_replay(manifest, effects, checks)
        check_coverage(coverage, checks)
        check_figures_report(E4_ROOT, checks)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, csv.Error) as exc:
        add(checks, "required_E4_artifacts_are_readable", False, str(exc))
    failures = [check["name"] for check in checks if check["status"] == "FAIL"]
    report["status"] = "PASS" if not failures else "FAIL"
    report["critical_failures"] = failures
    report["summary"] = {"checks_passed": len(checks) - len(failures), "checks_total": len(checks), "selection_or_threshold_modification": False, "raw_decision_data_opened": False}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"E4 final validation: {report['status']} ({report['summary']['checks_passed']}/{report['summary']['checks_total']})")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
