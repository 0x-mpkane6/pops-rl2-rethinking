#!/usr/bin/env python3
"""Build the frozen-input manifest for E4 statistical synthesis.

This program reads only e4_protocol.json and the protocol-registered
result/protocol/validator artifacts. It never opens E1/E2/E3 raw decisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
E4_ROOT = SCRIPT_DIR.parent
REPO_ROOT = E4_ROOT.parents[3]


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def repo_relative(path: Path) -> str:
    return path.resolve().relative_to(REPO_ROOT).as_posix()


def artifact_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Required registered artifact is missing: {path}")
    return {
        "path": repo_relative(path),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def validator_record(path: Path) -> dict[str, Any]:
    record = artifact_record(path)
    validator = load_json(path)
    record["status"] = validator.get("status")
    checks = validator.get("checks")
    if isinstance(checks, list):
        record["check_count"] = len(checks)
    return record


def require_pass_validator(path: Path) -> None:
    status = load_json(path).get("status")
    if status != "PASS":
        raise ValueError(f"Upstream validator is not PASS: {path} ({status!r})")


def verify_e3_final_validator(e3_root: Path, protocol: dict[str, Any]) -> dict[str, Any]:
    """Reject a stale PASS artifact whose recorded inputs have since changed."""
    final_validator = load_json(e3_root / "e3_validation.json")
    if final_validator.get("status") != "PASS":
        raise ValueError("E3 final validator is not PASS")
    expected = final_validator.get("artifact_hashes")
    if not isinstance(expected, dict):
        raise ValueError("E3 final validator has no artifact_hashes inventory")
    hash_policy = protocol.get("input_hash_policy", {}).get("git_lf_checkout_compatibility", {})
    compatible = set(hash_policy.get("applies_only_to_E3_validator_artifacts", []))
    if hash_policy.get("enabled") is not True:
        compatible = set()
    integrity: dict[str, Any] = {}
    mismatches: list[str] = []
    for name, record in expected.items():
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ValueError(f"Malformed E3 validator hash record: {name}")
        path = Path(record["path"])
        if not path.is_file():
            raise FileNotFoundError(f"E3 validator source artifact is missing: {path}")
        expected_hash = record.get("sha256")
        actual = sha256_file(path)
        if actual == expected_hash:
            integrity[name] = {
                "verification_status": "pass_byte_exact",
                "frozen_expected_sha256": expected_hash,
                "filesystem_sha256": actual,
            }
            continue
        raw = path.read_bytes()
        crlf_equivalent = sha256_bytes(raw.replace(b"\n", b"\r\n")) if b"\r" not in raw else None
        if name in compatible and crlf_equivalent == expected_hash:
            integrity[name] = {
                "verification_status": "pass_git_lf_checkout_equivalent",
                "frozen_expected_sha256": expected_hash,
                "filesystem_sha256": actual,
                "normalization": "LF-only checkout bytes converted to CRLF before SHA-256",
            }
            continue
        mismatches.append(f"{name}: expected {expected_hash}, got {actual} ({path})")
    if mismatches:
        raise ValueError("E3 frozen-artifact integrity mismatch:\n- " + "\n- ".join(mismatches))
    return integrity


def build_manifest(protocol_path: Path) -> dict[str, Any]:
    protocol = load_json(protocol_path)
    if protocol.get("status") != "registered-before-aggregation":
        raise ValueError("E4 protocol is not registered-before-aggregation")
    if protocol.get("aggregation_execution_status") != "not_started":
        raise ValueError("E4 aggregation has already started; refusing manifest creation")

    allowed = protocol.get("allowed_inputs")
    if not isinstance(allowed, dict):
        raise ValueError("Protocol allowed_inputs must be an object")

    inputs: dict[str, Any] = {}
    e3_integrity: dict[str, Any] | None = None
    for experiment in ("E1", "E2", "E3"):
        spec = allowed.get(experiment)
        if not isinstance(spec, dict):
            raise ValueError(f"Missing allowed-input specification for {experiment}")
        root_text = spec.get("root")
        files = spec.get("required_artifacts")
        if not isinstance(root_text, str) or not isinstance(files, list):
            raise ValueError(f"Malformed allowed-input specification for {experiment}")
        root = (E4_ROOT / root_text).resolve()
        for name in files:
            if name.endswith("validation.json"):
                require_pass_validator(root / name)
        if experiment == "E3":
            e3_integrity = verify_e3_final_validator(root, protocol)
        artifacts = {name: artifact_record(root / name) for name in files}
        validators: dict[str, Any] = {}
        for name in files:
            if name.endswith("validation.json"):
                validators[name] = validator_record(root / name)
        inputs[experiment] = {
            "root": repo_relative(root),
            "validator_requirement": spec.get("validator_requirement"),
            "artifacts": artifacts,
            "validators": validators,
        }

    return {
        "schema_version": 1,
        "experiment": "E4 input manifest",
        "status": "frozen_inputs_inventory_complete",
        "generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "generation_scope": "Hash and inventory only; no raw decision data, aggregation, CI recomputation, threshold selection, or experiment execution.",
        "protocol": artifact_record(protocol_path),
        "upstream_inputs": inputs,
        "cross_experiment_dependency": protocol["cross_experiment_rules"]["E2_E3_dependence"],
        "E3_final_validator_artifact_integrity": e3_integrity,
        "raw_data_access": "none",
        "selection_or_threshold_modification": False,
        "notes": [
            "E3 held-out decision data was not opened.",
            "Hashes are recorded before E4 aggregation and must be verified by e4_preflight.py.",
            "This manifest does not treat E2 and E3 as independent studies."
        ]
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E4_ROOT / "e4_protocol.json")
    parser.add_argument("--output", type=Path, default=E4_ROOT / "e4_input_manifest.json")
    parser.add_argument("--force", action="store_true", help="Replace an existing manifest.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output.exists() and not args.force:
        raise FileExistsError(f"Refusing to overwrite existing manifest: {args.output}. Use --force after review.")
    manifest = build_manifest(args.protocol)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote frozen-input manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
