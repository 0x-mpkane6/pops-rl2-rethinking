"""Offline reviewer checks; no sockets, Docker, training, or threshold selection."""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import tarfile
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
E5 = ROOT / "src/runtime/e5"
sys.path.insert(0, str(E5))
from e5_analysis import compute_run_metrics
from run_e5 import source_guard


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    smoke_files = list((DATA / "smoke").rglob("*"))
    check(smoke_files, "Smoke data missing")
    print(f"PASS: {len([p for p in smoke_files if p.is_file()])} smoke files")

    fixtures = DATA / "smoke/e5"
    expected = read(fixtures / "expected.json")
    manifest = read(fixtures / "manifest.json")
    for entry in manifest:
        check(hashlib.sha256(gzip.decompress((DATA / entry["path"]).read_bytes())).hexdigest() == entry["uncompressed_sha256"], "Fixture provenance")
    with tempfile.TemporaryDirectory(prefix="pops-reviewer-") as tmp:
        for folder in sorted(p for p in fixtures.iterdir() if p.is_dir()):
            target = Path(tmp) / folder.name
            target.mkdir()
            for path in folder.glob("*.gz"):
                (target / path.stem).write_bytes(gzip.decompress(path.read_bytes()))
            metrics = compute_run_metrics(target, expected_trials=50)
            saved = expected[folder.name]
            for key in ["n_trials", "poison_trials", "noanswer_trials", "run_asr", "tc_injection_rate", "tcp_retry_rate"]:
                check(math.isclose(metrics[key], saved[key], abs_tol=1e-12), f"Raw replay: {folder.name}/{key}")
            print(f"PASS: raw-log replay {folder.name}")

    check(source_guard()["status"] == "PASS", "E5 source guard")
    vendor = E5 / "vendor"
    digest, name = (vendor / "SHA256SUMS.txt").read_text().strip().split("  ", 1)
    check(hashlib.sha256((vendor / name).read_bytes()).hexdigest() == digest, "Unbound source hash")
    with tarfile.open(vendor / name, "r:gz") as archive:
        check(b"PACKAGE_VERSION='1.26.1'" in archive.extractfile("unbound/configure").read(), "Unbound source version")
        check(archive.getmember("unbound/configure").mode & 0o111, "Unbound configure executable permission")
    print("PASS: E5 source dependencies")
    print("Offline smoke PASS. This command does not run Docker/network checks.")


if __name__ == "__main__":
    main()
