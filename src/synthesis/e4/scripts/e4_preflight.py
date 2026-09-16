#!/usr/bin/env python3
"""Preflight E4 frozen inputs before statistical aggregation.

This audit intentionally never opens upstream raw decision data. It accepts
only the protocol, E4 input manifest, and registered frozen artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
E4_ROOT = SCRIPT_DIR.parent
REPO_ROOT = E4_ROOT.parents[3]


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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def path_from_record(record: dict[str, Any]) -> Path:
    value = record.get("path")
    if not isinstance(value, str):
        raise ValueError("Manifest artifact record has no string path")
    path = (REPO_ROOT / value).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Manifest artifact is missing: {path}")
    return path


def add_check(checks: list[dict[str, Any]], name: str, passed: bool, details: Any) -> None:
    checks.append({"name": name, "status": "PASS" if passed else "FAIL", "details": details})


def expected_validator_checks(experiment: str, filename: str) -> int:
    expected = {
        ("E1", "validation.json"): 18,
        ("E2", "validation.json"): 18,
        ("E3", "e3_lock_validation.json"): 9,
        ("E3", "e3_validation.json"): 12,
    }
    return expected[(experiment, filename)]


def verify_manifest_artifacts(protocol: dict[str, Any], manifest: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    inputs = manifest.get("upstream_inputs")
    if not isinstance(inputs, dict):
        add_check(checks, "manifest_input_structure", False, "upstream_inputs is not an object")
        return
    expected_counts = {"E1": 4, "E2": 4, "E3": 9}
    observed_counts: dict[str, int] = {}
    inventory_details: dict[str, Any] = {}
    all_match = True
    raw_paths: list[str] = []
    for experiment in ("E1", "E2", "E3"):
        spec = inputs.get(experiment)
        if not isinstance(spec, dict):
            all_match = False
            continue
        artifacts = spec.get("artifacts")
        if not isinstance(artifacts, dict):
            all_match = False
            continue
        observed_counts[experiment] = len(artifacts)
        allowed = protocol.get("allowed_inputs", {}).get(experiment, {})
        allowed_names = set(allowed.get("required_artifacts", []))
        registered_root = (E4_ROOT / str(allowed.get("root", ""))).resolve()
        registered_root_text = registered_root.relative_to(REPO_ROOT).as_posix()
        root_matches = spec.get("root") == registered_root_text
        names_match = set(artifacts) == allowed_names
        inventory_details[experiment] = {
            "manifest_root": spec.get("root"),
            "registered_root": registered_root_text,
            "manifest_artifacts": sorted(artifacts),
            "registered_artifacts": sorted(allowed_names),
        }
        all_match = all_match and root_matches and names_match
        for name, record in artifacts.items():
            try:
                path = path_from_record(record)
                actual = sha256_file(path)
                if actual != record.get("sha256"):
                    all_match = False
                if path.suffix == ".gz" or path.name.endswith("decisions.csv"):
                    raw_paths.append(str(path))
            except (OSError, ValueError) as exc:
                all_match = False
                raw_paths.append(f"{experiment}/{name}: {exc}")
    add_check(checks, "registered_artifact_hashes_match_manifest", all_match,
              {"expected_counts": expected_counts, "observed_counts": observed_counts,
               "registered_inventory": inventory_details})
    add_check(checks, "manifest_contains_no_raw_decision_input", not raw_paths,
              {"raw_or_invalid_paths": raw_paths})


def verify_validators(manifest: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    inputs = manifest.get("upstream_inputs", {})
    all_pass = True
    details: dict[str, Any] = {}
    for experiment in ("E1", "E2", "E3"):
        validators = inputs.get(experiment, {}).get("validators", {})
        for filename, record in validators.items():
            expected_count = expected_validator_checks(experiment, filename)
            actual_status = record.get("status")
            actual_count = record.get("check_count")
            passed = actual_status == "PASS" and actual_count == expected_count
            all_pass = all_pass and passed
            details[f"{experiment}/{filename}"] = {
                "status": actual_status,
                "check_count": actual_count,
                "expected_check_count": expected_count,
            }
    add_check(checks, "upstream_validators_pass_with_expected_check_counts", all_pass, details)


def verify_e3_integrity(protocol: dict[str, Any], manifest: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    policy = protocol.get("input_hash_policy", {}).get("git_lf_checkout_compatibility", {})
    allowed_eol = set(policy.get("applies_only_to_E3_validator_artifacts", [])) if policy.get("enabled") else set()
    integrity = manifest.get("E3_final_validator_artifact_integrity")
    if not isinstance(integrity, dict):
        add_check(checks, "E3_final_validator_integrity_structure", False, "missing integrity records")
        return
    modes: dict[str, str] = {}
    valid = True
    for name, record in integrity.items():
        if not isinstance(record, dict):
            valid = False
            continue
        status = record.get("verification_status")
        modes[name] = str(status)
        if status == "pass_byte_exact":
            if record.get("filesystem_sha256") != record.get("frozen_expected_sha256"):
                valid = False
        elif status == "pass_git_lf_checkout_equivalent":
            if name not in allowed_eol:
                valid = False
                continue
            e3_artifact = manifest["upstream_inputs"]["E3"]["artifacts"].get(
                "e3_test_results.csv" if name == "test_csv" else "e3_summary.csv"
            )
            if not isinstance(e3_artifact, dict):
                valid = False
                continue
            raw = path_from_record(e3_artifact).read_bytes()
            normalized = sha256_bytes(raw.replace(b"\n", b"\r\n")) if b"\r" not in raw else None
            if normalized != record.get("frozen_expected_sha256"):
                valid = False
        else:
            valid = False
    add_check(checks, "E3_final_validator_frozen_artifacts_are_byte_exact_or_registered_EOL_equivalent", valid,
              {"verification_modes": modes, "allowed_EOL_equivalents": sorted(allowed_eol)})


def verify_units(protocol: dict[str, Any], manifest: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    inputs = manifest["upstream_inputs"]
    try:
        e1 = load_json(path_from_record(inputs["E1"]["artifacts"]["e1_protocol.json"]))
        e2 = load_json(path_from_record(inputs["E2"]["artifacts"]["e2_protocol.json"]))
        e3 = load_json(path_from_record(inputs["E3"]["artifacts"]["e3_test_results.json"]))
        e1_runs = e1.get("runs_per_cell")
        e2_runs = e2.get("splits", {}).get("test", {}).get("runs_per_cell")
        e3_pairs = sorted({cell.get("n_pairs") for cell in e3.get("primary", {}).get("cells", [])})
        audit = protocol.get("run_count_audit", {})
        passed = (
            e1_runs == audit.get("E1", {}).get("expected_independent_runs_per_primary_condition")
            and e2_runs == audit.get("E2", {}).get("expected_held_out_pairs_per_cell")
            and e3_pairs == [audit.get("E3", {}).get("expected_held_out_pairs_per_primary_cell")]
        )
        details = {"E1_runs_per_cell": e1_runs, "E2_test_runs_per_cell": e2_runs, "E3_primary_n_pairs": e3_pairs}
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
        passed, details = False, str(exc)
    add_check(checks, "registered_independent_unit_counts_match_frozen_artifacts", passed, details)


def verify_no_aggregation_outputs(protocol: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    not_yet_allowed = {"e4_summary.csv", "e4_paired_effects.csv", "e4_metric_coverage.csv", "e4_summary.json", "E4_report.md"}
    existing = sorted(item for item in not_yet_allowed if (E4_ROOT / item).exists())
    status_ok = protocol.get("aggregation_execution_status") == "not_started"
    add_check(checks, "aggregation_has_not_started", status_ok and not existing,
              {"protocol_status": protocol.get("aggregation_execution_status"), "existing_aggregation_outputs": existing})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E4_ROOT / "e4_protocol.json")
    parser.add_argument("--manifest", type=Path, default=E4_ROOT / "e4_input_manifest.json")
    parser.add_argument("--output", type=Path, default=E4_ROOT / "e4_preflight.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "E4 preflight",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data_access": "protocol, input manifest, and frozen registered artifacts only; no raw decision data opened",
        "checks": checks,
    }
    try:
        protocol = load_json(args.protocol)
        manifest = load_json(args.manifest)
        protocol_hash = sha256_file(args.protocol)
        report["artifact_hashes"] = {
            "protocol": protocol_hash,
            "manifest": sha256_file(args.manifest),
        }
        add_check(checks, "protocol_is_registered_and_manifest_binds_its_hash",
                  protocol.get("status") == "registered-before-aggregation"
                  and manifest.get("protocol", {}).get("sha256") == protocol_hash,
                  {"protocol_status": protocol.get("status"), "protocol_sha256": protocol_hash,
                   "manifest_protocol_sha256": manifest.get("protocol", {}).get("sha256")})
        add_check(checks, "manifest_scope_and_mutation_policy", 
                  manifest.get("status") == "frozen_inputs_inventory_complete"
                  and manifest.get("raw_data_access") == "none"
                  and manifest.get("selection_or_threshold_modification") is False,
                  {"manifest_status": manifest.get("status"), "raw_data_access": manifest.get("raw_data_access"),
                   "selection_or_threshold_modification": manifest.get("selection_or_threshold_modification")})
        dependency = protocol.get("cross_experiment_rules", {}).get("E2_E3_dependence")
        add_check(checks, "E2_E3_non_independence_policy_is_preserved",
                  manifest.get("cross_experiment_dependency") == dependency
                  and "must not be pooled" in str(dependency),
                  {"dependency": dependency})
        verify_manifest_artifacts(protocol, manifest, checks)
        verify_validators(manifest, checks)
        verify_e3_integrity(protocol, manifest, checks)
        verify_units(protocol, manifest, checks)
        verify_no_aggregation_outputs(protocol, checks)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        add_check(checks, "preflight_inputs_are_readable", False, str(exc))

    failures = [check["name"] for check in checks if check["status"] == "FAIL"]
    report["status"] = "PASS" if not failures else "FAIL"
    report["critical_failures"] = failures
    report["summary"] = {"checks_passed": len(checks) - len(failures), "checks_total": len(checks)}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"E4 preflight: {report['status']} ({report['summary']['checks_passed']}/{report['summary']['checks_total']})")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
