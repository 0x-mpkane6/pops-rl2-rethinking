#!/usr/bin/env python3
"""Run the registered E5 routed IPS campaign.

The runner registers a source/image snapshot before data collection, recreates
the Docker stack for each cell, and writes raw evidence before deriving any
metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from statistics import fmean
from typing import Any, Iterable

from e5_aggregate import exact_binomial_ci, paired_bootstrap_mean, paired_differences, paired_factorial_differences
from e5_analysis import compute_run_metrics, read_jsonl
from e5_lib import CONFIRMATORY_POLICIES, WORKLOADS, make_complete_block
from e5_schedule import WORKLOAD_SPECS, build_replay_schedule, schedule_digest
from e5_validate import pilot_gate, pmtud_kernel_fragment_gate, validate_replay_coverage, validate_run


E5_ROOT = Path(__file__).resolve().parent
LAB_ROOT = E5_ROOT / "routed_lab"
PROTOCOL_PATH = E5_ROOT / "e5_protocol.json"
OUTPUT_ROOT = E5_ROOT / "output"
DEFAULT_RUN_ID = "E5-routed-s20260902-r001"
STAGE_NAMES = ("pilot", "sanity", "confirmatory")
SERVICE_LOG_DIRS = ("ips", "resolver", "auth", "attacker", "client", "ips_pcap")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_run_id(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ValueError("run ID must be one directory name")
    if not all(char.isalnum() or char in "-_" for char in value):
        raise ValueError("run ID may contain only letters, digits, hyphen, and underscore")
    return value


def load_protocol(run_id: str, protocol_path: Path = PROTOCOL_PATH) -> dict[str, Any]:
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    validate_protocol_workloads(protocol)
    if protocol.get("protocol_id") == "E5-factorial-s20260911-r001":
        validate_factorial_protocol(protocol)
    if protocol.get("addon") == "B2_VOLUME_TC":
        validate_b2_protocol(protocol)
    if protocol.get("fragmentation_mode") == "pmtud":
        validate_pmtud_protocol(protocol)
    protocol["run_id"] = run_id
    protocol["protocol_id"] = run_id
    protocol["protocol_path"] = str(protocol_path.resolve())
    return protocol


def source_guard(root: Path = LAB_ROOT) -> dict[str, Any]:
    """Reject any resolver-local poisoner or an equivalent stale path."""

    errors: list[str] = []
    if not root.exists():
        return {"status": "FAIL", "errors": [f"missing lab root: {root}"]}
    for path in root.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if "poisoner" in path.name.lower():
            errors.append(f"forbidden resolver-local poisoner path: {path.relative_to(root)}")
        if path.suffix.lower() in {".py", ".sh", ".yaml", ".yml", ".json", ".dockerfile"}:
            try:
                text = path.read_text(encoding="utf-8").lower()
            except UnicodeDecodeError:
                continue
            if "poisoner.py" in text or "/poisoner" in text or "\\poisoner" in text:
                errors.append(f"forbidden poisoner reference: {path.relative_to(root)}")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def source_files(protocol_path: Path = PROTOCOL_PATH) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in (
        E5_ROOT / "run_e5.py",
        E5_ROOT / "e5_lib.py",
        E5_ROOT / "e5_schedule.py",
        E5_ROOT / "e5_analysis.py",
        E5_ROOT / "e5_aggregate.py",
        E5_ROOT / "e5_validate.py",
        E5_ROOT / "vendor" / "unbound-1.26.1.tar.gz",
        E5_ROOT / "vendor" / "UNBOUND-LICENSE",
        protocol_path,
    ):
        try:
            name = path.relative_to(E5_ROOT).as_posix()
        except ValueError:
            name = f"protocol/{path.name}"
        files[name] = path
    for path in sorted(LAB_ROOT.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix.lower() not in {".pyc", ".pcap", ".pcapng"}:
            files[f"routed_lab/{path.relative_to(LAB_ROOT).as_posix()}"] = path
    return files


def source_manifest(protocol_path: Path = PROTOCOL_PATH) -> dict[str, Any]:
    return {
        "file_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in source_files(protocol_path).items()},
    }


def copy_source_snapshot(root: Path, protocol_path: Path = PROTOCOL_PATH) -> None:
    for name, path in source_files(protocol_path).items():
        destination = root / "source_snapshot" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def docker_info() -> dict[str, Any]:
    proc = subprocess.run(["docker", "info", "--format", "{{json .}}"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "Docker daemon unavailable").strip()
        raise RuntimeError(f"Docker Desktop/daemon is unavailable: {detail}")
    try:
        info = json.loads(proc.stdout)
    except json.JSONDecodeError:
        info = {"raw": proc.stdout.strip()}
    return {key: info.get(key) for key in ("NCPU", "MemTotal", "KernelVersion", "OperatingSystem", "ServerVersion")}


def project_name(run_id: str) -> str:
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:8]
    return f"e5-{run_id.lower()[:35]}-{digest}"


def compose_base(run_id: str, env_file: Path, override: Path | None = None) -> list[str]:
    command = [
        "docker",
        "compose",
        "--project-name",
        project_name(run_id),
        "--project-directory",
        str(LAB_ROOT),
        "--env-file",
        str(env_file),
        "-f",
        str(LAB_ROOT / "compose.yaml"),
    ]
    if override is not None:
        command.extend(["-f", str(override)])
    return command


def run_command(command: list[str], *, check: bool = True, capture: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    print("$ " + " ".join(command), flush=True)
    result = subprocess.run(command, capture_output=capture, text=True, check=False, timeout=timeout)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{detail[-4000:]}")
    return result


def yaml_quote(value: Path | str) -> str:
    text = str(value).replace("\\", "/").replace("'", "''")
    return f"'{text}'"


def write_runtime_env(
    path: Path,
    *,
    run_id: str,
    rep: int,
    policy: str,
    workload: str,
    extra: dict[str, str] | None = None,
) -> None:
    lines = [
        f"RUN_ID={run_id}",
        f"REP={rep}",
        f"POLICY_MODE={policy}",
        f"WORKLOAD={workload}",
        "COMPOSE_PROJECT_NAME=" + project_name(run_id),
    ]
    for key, value in sorted((extra or {}).items()):
        name = str(key)
        if not name.replace("_", "").isalnum() or not name.isupper():
            raise ValueError(f"invalid runtime env name: {name}")
        lines.append(f"{name}={value}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_compose_override(
    path: Path,
    *,
    log_dirs: dict[str, Path],
    pcap_dir: Path | None = None,
    schedule_path: Path | None = None,
    control_path: Path | None = None,
) -> None:
    lines = ["services:"]
    mounts: dict[str, list[tuple[Path, str, bool]]] = {service: [] for service in log_dirs}
    for service, source in log_dirs.items():
        mounts.setdefault(service, []).append((source, "/app/log", False))
    if pcap_dir is not None:
        mounts.setdefault("ips", []).append((pcap_dir, "/app/pcap", False))
    if schedule_path is not None:
        for service in ("resolver", "auth", "attacker", "client"):
            mounts.setdefault(service, []).append((schedule_path, "/app/schedule.json", True))
    if control_path is not None:
        # Factorial runs use a host-backed rendezvous so the client can release
        # the occupancy replay only after every cache-before probe completes.
        # Legacy schedules omit this mount and retain their historical timing.
        for service in ("attacker", "client"):
            mounts.setdefault(service, []).append((control_path, "/app/control", False))
    for service, service_mounts in mounts.items():
        if not service_mounts:
            continue
        lines.extend([f"  {service}:", "    volumes:"])
        for source, target, read_only in service_mounts:
            lines.extend(
                [
                    "      - type: bind",
                    f"        source: {yaml_quote(source.resolve())}",
                    f"        target: {target}",
                ]
            )
            if read_only:
                lines.append("        read_only: true")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def protocol_policies(protocol: dict[str, Any]) -> list[str]:
    values = protocol.get("policies") or [item.value for item in CONFIRMATORY_POLICIES]
    policies: list[str] = []
    for item in values:
        if isinstance(item, str):
            policies.append(item)
        elif item.get("confirmatory", True):
            policies.append(str(item["id"]))
    return policies


def protocol_workloads(protocol: dict[str, Any]) -> list[str]:
    values = protocol.get("workloads") or list(WORKLOADS)
    return [item if isinstance(item, str) else str(item["id"]) for item in values]


def validate_protocol_workloads(protocol: dict[str, Any]) -> None:
    """Ensure protocol metadata cannot silently disagree with schedule code."""

    # The original registered protocol called the sequential 16-bit stream
    # ``deterministic_sweep``; the schedule helper uses the shorter internal
    # name ``sweep``.  Treat these as the same model so loading the legacy
    # protocol remains backward compatible.
    mode_aliases = {"deterministic_sweep": "sweep"}
    for item in protocol.get("workloads", []):
        if isinstance(item, str):
            workload_id = item
            metadata = {}
        else:
            workload_id = str(item.get("id"))
            metadata = item
        if workload_id not in WORKLOAD_SPECS:
            raise ValueError(f"protocol references unknown workload: {workload_id}")
        spec = WORKLOAD_SPECS[workload_id]
        checks = {
            "occupancy_fragments_per_second": "rate_pps",
            "kind": "kind",
            "ipid_mode": "ipid_mode",
            "attack_tail": "attack_tail",
        }
        for protocol_key, spec_key in checks.items():
            if protocol_key in metadata:
                expected = spec[spec_key]
                actual = metadata[protocol_key]
                if protocol_key == "ipid_mode":
                    actual = mode_aliases.get(str(actual), actual)
                    expected = mode_aliases.get(str(expected), expected)
                if actual != expected:
                    raise ValueError(f"protocol workload {workload_id} disagrees on {protocol_key}")


def validate_factorial_protocol(protocol: dict[str, Any]) -> None:
    """Reject accidental expansion of the registered 2x2 campaign."""

    expected_policies = {"B0_OFF", "B1_RL2_TC", "B5_LOCKED_TC", "RFC_DROP_NATIVE"}
    expected_workloads = {
        "BENIGN_DIVERSE_MODERATE",
        "BENIGN_DIVERSE_HIGH",
        "ATTACK_DIVERSE_MODERATE",
        "ATTACK_DIVERSE_HIGH",
    }
    policies = set(protocol_policies(protocol))
    workloads = set(protocol_workloads(protocol))
    if policies != expected_policies:
        raise ValueError(f"factorial protocol must contain exactly four registered policies: {sorted(policies)}")
    if workloads != expected_workloads:
        raise ValueError(f"factorial protocol must contain exactly four registered workloads: {sorted(workloads)}")
    if "PREARM_TAIL_DROP" in policies:
        raise ValueError("PREARM_TAIL_DROP is pilot-only and forbidden in factorial cells")


def validate_b2_protocol(protocol: dict[str, Any]) -> None:
    """Keep the B2 addon on the original four workloads and locked N=8."""

    policies = set(protocol_policies(protocol))
    workloads = set(protocol_workloads(protocol))
    if policies != {"B2_VOLUME_TC"}:
        raise ValueError(f"B2 addon protocol must contain only B2_VOLUME_TC: {sorted(policies)}")
    if workloads != set(WORKLOADS):
        raise ValueError(f"B2 addon protocol must use the original four workloads: {sorted(workloads)}")
    point = protocol.get("e3_operating_point") or {}
    if int(point.get("min_samples", -1)) != 8:
        raise ValueError("B2 addon must keep locked N=8")
    if float(point.get("entropy_threshold_bits", -1)) != 6.0:
        raise ValueError("B2 addon must keep locked H=6.0 for the passive B5 log")
    if float(point.get("unique_ipid_ratio_threshold", -1)) != 0.90:
        raise ValueError("B2 addon must keep locked U=0.90 for the passive B5 log")


def validate_pmtud_protocol(protocol: dict[str, Any]) -> None:
    """Keep PMTUD on a separate B0/B5 attack matrix; do not pool with crafted E5."""

    if protocol.get("fragmentation_mode") != "pmtud":
        raise ValueError("PMTUD protocol must set fragmentation_mode=pmtud")
    policies = set(protocol_policies(protocol))
    workloads = set(protocol_workloads(protocol))
    if policies != {"B0_OFF", "B5_LOCKED_TC"}:
        raise ValueError(f"PMTUD protocol must contain only B0 and locked B5: {sorted(policies)}")
    if workloads != {"ATTACK_FIXED_MATCHED", "ATTACK_SWEEP_FLOOD"}:
        raise ValueError(f"PMTUD protocol must contain only the two original attack workloads: {sorted(workloads)}")
    if protocol.get("pool_with_main_e5"):
        raise ValueError("PMTUD results must not be pooled with the crafted-fragment campaign")


def build_stage_jobs(stage: str, protocol: dict[str, Any]) -> list[dict[str, Any]]:
    """Return pilot/sanity/confirmatory jobs in their registered order."""

    seed = int(protocol.get("experiment_seed", protocol.get("schedule", {}).get("experiment_seed", 20260902)))
    policies = protocol_policies(protocol)
    workloads = protocol_workloads(protocol)
    if stage == "pilot":
        stage_config = protocol.get("stages", {}).get("pilot", {})
        cells = stage_config.get("cells", protocol.get("pilot", []))
        if cells in ("all", "all_4_policies_x_all_4_workloads"):
            cells = [[policy, workload] for policy in policies for workload in workloads]
        if not cells:
            cells = [[policy, workload] for policy in policies for workload in workloads]
        return [{"stage": stage, "rep": 0, "policy": str(policy), "workload": str(workload)} for policy, workload in cells]
    if stage == "sanity":
        return [
            {"stage": stage, "rep": 0, "policy": cell.policy, "workload": cell.workload}
            for cell in make_complete_block(rep=0, seed=seed, policies=policies, workloads=workloads)
        ]
    if stage == "confirmatory":
        runs = int(protocol.get("k_runs_per_cell", protocol.get("stages", {}).get("confirmatory", {}).get("runs_per_cell", 20)))
        jobs: list[dict[str, Any]] = []
        for rep in range(1, runs + 1):
            block = make_complete_block(rep=rep, seed=seed, policies=policies, workloads=workloads)
            jobs.extend({"stage": stage, "rep": rep, "policy": cell.policy, "workload": cell.workload} for cell in block)
        return jobs
    raise ValueError(f"unknown stage: {stage}")


def _stage_trials(stage: str, protocol: dict[str, Any]) -> int:
    if stage == "pilot":
        return int(protocol.get("stages", {}).get("pilot", {}).get("trials_per_run", 5))
    return int(protocol.get("trials_per_run", protocol.get("schedule", {}).get("trials_per_run", 50)))


def _stage_duration(stage: str, protocol: dict[str, Any]) -> float:
    stage_config = protocol.get("stages", {}).get(stage, {})
    if "schedule_duration_seconds" in stage_config:
        return float(stage_config["schedule_duration_seconds"])
    # Preserve the legacy runner's short pilot while allowing the registered
    # factorial protocol to state explicit pilot/sanity durations.
    if stage == "pilot":
        return 20.0
    configured = protocol.get("schedule", {}).get("schedule_duration_seconds", 120.0)
    return float(configured)


def schedule_for_cell(root: Path, protocol: dict[str, Any], job: dict[str, Any]) -> tuple[dict[str, Any], Path]:
    stage = job["stage"]
    rep = int(job["rep"])
    workload = str(job["workload"])
    destination = root / "schedules" / stage / f"rep_{rep:02d}" / f"{workload}.json"
    schedule = build_replay_schedule(
        run_id=str(protocol["run_id"]),
        rep=rep,
        workload=workload,
        seed=int(protocol.get("experiment_seed", protocol.get("schedule", {}).get("experiment_seed", 20260902))),
        trials=_stage_trials(stage, protocol),
        duration_s=_stage_duration(stage, protocol),
    )
    expected_digest = schedule_digest(schedule)
    if destination.exists():
        existing = json.loads(destination.read_text(encoding="utf-8"))
        if schedule_digest(existing) != expected_digest:
            raise RuntimeError(f"registered schedule changed: {destination}")
    else:
        write_json(destination, schedule)
    return schedule, destination


def _wait_file(path: Path, timeout_s: float, description: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {description}: {path}")


def _service_dirs(cell_dir: Path) -> dict[str, Path]:
    result = {}
    for name in SERVICE_LOG_DIRS:
        result[name] = cell_dir / name
        result[name].mkdir(parents=True, exist_ok=True)
    return result


def _flatten_artifacts(cell_dir: Path) -> None:
    mappings = {
        "client/trials.jsonl": "trials.jsonl",
        "client/client_events.jsonl": "client_events.jsonl",
        "auth/auth_events.jsonl": "auth_events.jsonl",
        "attacker/attacker_events.jsonl": "attacker_events.jsonl",
        "ips/ips_events.jsonl": "ips_events.jsonl",
        "ips/detector_state.json": "detector_state.json",
        "ips/ips_ready.json": "ips_ready.json",
        "ips/interfaces.json": "interfaces.json",
        "ips/firewall_before.rules": "firewall_before.rules",
        "ips/firewall_after.rules": "firewall_after.rules",
        "ips/routes_before.txt": "routes_before.txt",
        "ips/routes_after.txt": "routes_after.txt",
        "ips/ip_forward_before.txt": "ip_forward_before.txt",
        "ips/ip_forward_after.txt": "ip_forward_after.txt",
        "ips/nfqueue_preflight.json": "nfqueue_preflight.json",
        "resolver/unbound_events.jsonl": "unbound_events.jsonl",
        "resolver/cache_events.jsonl": "cache_events.jsonl",
        "resolver/resolver_ready.json": "resolver_ready.json",
        "resolver/unbound_version.txt": "unbound_version.txt",
        "control/replay_start.json": "replay_start.json",
        "control/replay_started.json": "replay_started.json",
    }
    for source_name, destination_name in mappings.items():
        source = cell_dir / source_name
        destination = cell_dir / destination_name
        if source.exists():
            shutil.copy2(source, destination)
    pcap = cell_dir / "ips_pcap"
    for name in ("ips_inside.pcapng", "ips_outside.pcapng"):
        source = pcap / name
        if source.exists():
            shutil.copy2(source, cell_dir / name)


def _container_stats(command: list[str]) -> str:
    ids_result = run_command(command + ["ps", "-q"], check=False)
    ids = [line.strip() for line in ids_result.stdout.splitlines() if line.strip()]
    if not ids:
        return ""
    stats = run_command(["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids], check=False)
    return stats.stdout or ""


def _wait_for_auth_drain(auth_dir: Path, expected_qnames: set[str], timeout_s: float) -> dict[str, Any]:
    """Let the single authoritative worker finish queued trial requests.

    RFC_DROP_NATIVE intentionally produces no usable response, so a client
    deadline can expire while the authoritative UDP socket still contains
    the later scheduled qnames.  Stopping the stack immediately would turn a
    real runtime timeout into a missing-evidence artifact.  We wait only for
    the registered qnames to reach auth, with a bounded timeout, and retain
    the observed/expected counts for audit.
    """

    deadline = time.monotonic() + timeout_s
    observed: set[str] = set()
    auth_log = auth_dir / "auth_events.jsonl"
    while True:
        try:
            rows = read_jsonl(auth_log)
        except (OSError, ValueError):
            rows = []
        observed = {
            str(row.get("qname"))
            for row in rows
            if row.get("event") == "udp_receive" and isinstance(row.get("qname"), str)
        }
        if expected_qnames.issubset(observed):
            return {
                "status": "PASS",
                "expected_qnames": len(expected_qnames),
                "observed_qnames": len(expected_qnames & observed),
                "timeout_s": timeout_s,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {
                "status": "TIMEOUT",
                "expected_qnames": len(expected_qnames),
                "observed_qnames": len(expected_qnames & observed),
                "timeout_s": timeout_s,
            }
        time.sleep(min(0.25, remaining))


def _stop_stack(command: list[str]) -> None:
    run_command(command + ["exec", "-T", "ips", "/app/snapshot.sh", "before_stop"], check=False)
    run_command(command + ["logs", "--no-color"], check=False)
    run_command(command + ["down", "--volumes", "--remove-orphans"], check=False, timeout=60)


def run_cell(root: Path, protocol: dict[str, Any], job: dict[str, Any], schedule: dict[str, Any], schedule_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    stage = str(job["stage"])
    rep = int(job["rep"])
    policy = str(job["policy"])
    workload = str(job["workload"])
    cell_dir = root / "raw" / stage / f"rep_{rep:02d}" / f"{policy}__{workload}"
    if cell_dir.exists():
        raise FileExistsError(f"refusing to overwrite cell: {cell_dir}")
    cell_dir.mkdir(parents=True, exist_ok=False)
    dirs = _service_dirs(cell_dir)
    control_dir = cell_dir / "control"
    control_dir.mkdir(parents=True, exist_ok=True)
    cell_schedule = cell_dir / "schedule.json"
    write_json(cell_schedule, schedule)
    env_file = cell_dir / "runtime.env"
    write_runtime_env(
        env_file,
        run_id=str(protocol["run_id"]),
        rep=rep,
        policy=policy,
        workload=workload,
        extra={str(key): str(value) for key, value in (protocol.get("runtime_env") or {}).items()},
    )
    override = cell_dir / "compose.override.yaml"
    write_compose_override(
        override,
        log_dirs={name: dirs[name] for name in ("ips", "resolver", "auth", "attacker", "client")},
        pcap_dir=dirs["ips_pcap"],
        schedule_path=cell_schedule,
        control_path=control_dir if "replay_start_mode" in schedule else None,
    )
    command = compose_base(str(protocol["run_id"]), env_file, override)
    expected_trials = len(schedule["trials"])
    client_proc: subprocess.CompletedProcess[str] | None = None
    client_error: str | None = None
    stack_started = False
    started_ns = time.monotonic_ns()
    try:
        run_command(command + ["up", "-d", "--no-build"], timeout=90)
        stack_started = True
        _wait_file(dirs["ips"] / "ips_ready.json", 30, "IPS NFQUEUE readiness")
        _wait_file(dirs["resolver"] / "resolver_ready.json", 45, "Unbound readiness")
        _wait_file(dirs["auth"] / "auth_events.jsonl", 30, "authoritative UDP/TCP readiness")
        _wait_file(dirs["attacker"] / "attacker_events.jsonl", 30, "external attacker readiness")
        try:
            client_proc = run_command(
                command + ["exec", "-T", "client", "python3", "/app/probe.py"],
                check=False,
                timeout=max(180.0, expected_trials * 6.0),
            )
        except subprocess.TimeoutExpired as exc:
            client_error = f"client timeout: {exc}"
    finally:
        if client_proc is not None:
            (cell_dir / "client_stdout.txt").write_text(client_proc.stdout or "", encoding="utf-8")
            (cell_dir / "client_stderr.txt").write_text(client_proc.stderr or "", encoding="utf-8")
        if client_error:
            (cell_dir / "client_error.txt").write_text(client_error + "\n", encoding="utf-8")
        if stack_started:
            drain = _wait_for_auth_drain(
                dirs["auth"],
                {str(row["qname"]) for row in schedule["trials"]},
                timeout_s=max(5.0, expected_trials * 0.4 + 2.0),
            )
        else:
            drain = {
                "status": "NOT_STARTED",
                "expected_qnames": expected_trials,
                "observed_qnames": 0,
                "timeout_s": 0.0,
            }
        write_json(cell_dir / "auth_drain.json", drain)
        (cell_dir / "resource_samples.jsonl").write_text(_container_stats(command), encoding="utf-8")
        if stack_started:
            _stop_stack(command)
    _flatten_artifacts(cell_dir)
    if client_proc is None and client_error is None:
        raise RuntimeError(f"client did not run for {cell_dir}")
    metrics = compute_run_metrics(cell_dir, expected_trials=expected_trials)
    attacker_rows = read_jsonl(cell_dir / "attacker_events.jsonl")
    ips_rows = read_jsonl(cell_dir / "ips_events.jsonl")
    client_rows = read_jsonl(cell_dir / "client_events.jsonl")
    replay_validation = None
    if "replay_start_mode" in schedule:
        measurement_end = max((int(row.get("mono_ns", 0)) for row in client_rows), default=None)
        replay_validation = validate_replay_coverage(attacker_rows, schedule, ips_rows=ips_rows, measurement_end_mono_ns=measurement_end)
        if replay_validation.get("status") != "PASS":
            metrics["replay_coverage_status"] = "FAIL"
        else:
            metrics["replay_coverage_status"] = "PASS"
        metrics["replay_telemetry"] = replay_validation
    metrics.update(
        {
            "stage": stage,
            "run_id": protocol["run_id"],
            "rep": rep,
            "policy": policy,
            "workload": workload,
            "schedule_sha256": schedule_digest(schedule),
            "client_exit_code": client_proc.returncode if client_proc is not None else None,
            "client_error": client_error,
            "wall_duration_s": (time.monotonic_ns() - started_ns) / 1_000_000_000.0,
            "artifact_dir": str(cell_dir.relative_to(root)).replace("\\", "/"),
        }
    )
    wall = float(metrics["wall_duration_s"])
    if wall > 0:
        metrics["observed_query_qps"] = float(metrics["n_trials"]) / wall
    if protocol.get("fragmentation_mode") == "pmtud":
        pmtud_gate = pmtud_kernel_fragment_gate(ips_rows, attacker_rows)
        write_json(cell_dir / "pmtud_gate.json", pmtud_gate)
        metrics["pmtud_gate"] = pmtud_gate
    write_json(cell_dir / "metrics.json", metrics)
    expected = {"run_id": protocol["run_id"], "rep": rep, "policy": policy, "workload": workload}
    validation = validate_run(
        cell_dir,
        expected=expected,
        expected_qnames=[row["qname"] for row in schedule["trials"]],
        expected_trials=expected_trials,
        require_pcap=True,
        require_probe_status="replay_start_mode" in schedule,
    )
    if replay_validation is not None:
        validation["replay_coverage"] = replay_validation
        if replay_validation.get("status") != "PASS":
            validation["status"] = "FAIL"
            validation.setdefault("errors", []).extend(replay_validation.get("errors", []))
    if protocol.get("fragmentation_mode") == "pmtud":
        pmtud_gate = metrics.get("pmtud_gate") or {}
        validation["pmtud_kernel_fragments"] = pmtud_gate
        if pmtud_gate.get("status") != "PASS":
            validation["status"] = "FAIL"
            validation.setdefault("errors", []).extend(pmtud_gate.get("errors", ["PMTUD kernel-fragment gate failed"]))
    write_json(cell_dir / "validation.json", validation)
    return metrics, validation


def _compose_image_names(run_id: str, env_file: Path) -> list[str]:
    command = compose_base(run_id, env_file)
    result = run_command(command + ["config", "--images"])
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def _image_ids(image_names: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in image_names:
        inspected = run_command(["docker", "image", "inspect", name, "--format", "{{.Id}}"], check=False)
        if inspected.returncode == 0 and inspected.stdout.strip():
            result[name] = inspected.stdout.strip()
    return result


def _ensure_source_guard() -> None:
    guard = source_guard(LAB_ROOT)
    if guard["status"] != "PASS":
        raise RuntimeError("E5 source guard failed:\n" + "\n".join(guard["errors"]))


def _preflight_stack(root: Path, protocol: dict[str, Any]) -> dict[str, Any]:
    """Prove routing/NFQUEUE and the dynamic cache probe positive controls."""

    preflight = root / "preflight"
    dirs = _service_dirs(preflight)
    schedule = build_replay_schedule(
        run_id=str(protocol["run_id"]),
        rep=0,
        workload="BENIGN_LOW",
        seed=int(protocol.get("experiment_seed", 20260902)),
        trials=1,
        duration_s=1.0,
    )
    schedule_path = preflight / "schedule.json"
    write_json(schedule_path, schedule)
    env_file = preflight / "runtime.env"
    write_runtime_env(env_file, run_id=str(protocol["run_id"]), rep=0, policy="B0_OFF", workload="PREFLIGHT")
    override = preflight / "compose.override.yaml"
    write_compose_override(
        override,
        log_dirs={name: dirs[name] for name in ("ips", "resolver", "auth", "attacker", "client")},
        pcap_dir=dirs["ips_pcap"],
        schedule_path=schedule_path,
    )
    command = compose_base(str(protocol["run_id"]), env_file, override)
    started = False
    try:
        # The smoke command runs in a one-shot attacker container; keep the
        # long-lived attacker service down here so its fixed lab IP is not
        # duplicated by ``docker compose run``.  The cache positive control
        # uses a benign schedule and does not require forged-tail handling.
        run_command(command + ["up", "-d", "--no-build", "ips", "resolver", "auth"], timeout=90)
        started = True
        _wait_file(dirs["ips"] / "ips_ready.json", 30, "IPS NFQUEUE readiness")
        _wait_file(dirs["resolver"] / "resolver_ready.json", 45, "Unbound readiness")
        _wait_file(dirs["auth"] / "auth_events.jsonl", 30, "authoritative readiness")
        smoke = run_command(command + ["run", "--rm", "--no-deps", "attacker", "python3", "/app/smoke.py"], timeout=30)
        (preflight / "smoke.stdout").write_text(smoke.stdout or "", encoding="utf-8")
        (preflight / "smoke.stderr").write_text(smoke.stderr or "", encoding="utf-8")
        client = run_command(command + ["run", "--rm", "--no-deps", "client", "python3", "/app/probe.py"], timeout=60)
        (preflight / "client_stdout.txt").write_text(client.stdout or "", encoding="utf-8")
        (preflight / "client_stderr.txt").write_text(client.stderr or "", encoding="utf-8")
        _flatten_artifacts(preflight)
        trials = read_jsonl(preflight / "trials.jsonl")
        qname = str(schedule["trials"][0]["qname"])
        if len(trials) != 1:
            raise RuntimeError(f"cache positive control produced {len(trials)} trial rows")
        trial = trials[0]
        before = trial.get("cache_before", {})
        after = trial.get("cache_after", {})
        if before.get("probe_status") != "miss" or before.get("probe_valid") is not True:
            raise RuntimeError(f"cache-before positive control was not a valid miss: {before}")
        if trial.get("answer_ip") != "203.0.113.80":
            raise RuntimeError(f"cache positive control did not return legitimate answer: {trial.get('answer_ip')}")
        if after.get("probe_status") != "hit" or after.get("probe_valid") is not True or "203.0.113.80" not in after.get("answers", []):
            raise RuntimeError(f"cache-after positive control was not a valid hit: {after}")
        # Freeze Unbound while leaving the probe daemon running.  The next
        # lookup must report an explicit control-socket error and cache_hit
        # must remain unknown rather than being coerced to false.
        run_command(
            command + [
                "exec",
                "-T",
                "resolver",
                "python3",
                "-c",
                "import os; os.kill(int(open('/tmp/unbound.pid').read()), 19)",
            ],
            timeout=30,
        )
        error_probe = run_command(
            command
            + [
                "run",
                "--rm",
                "--no-deps",
                "client",
                "python3",
                "-c",
                f"import json; from probe import cache_probe; print(json.dumps(cache_probe('after', 'preflight-error', '{qname}')))",
            ],
            timeout=30,
        )
        (preflight / "cache_error_probe.txt").write_text(error_probe.stdout or "", encoding="utf-8")
        error_rows = [json.loads(line) for line in (error_probe.stdout or "").splitlines() if line.strip()]
        if not error_rows or error_rows[-1].get("probe_status") != "error" or error_rows[-1].get("cache_hit") is not None:
            raise RuntimeError(f"cache control-socket error control failed: {error_probe.stdout!r}")
        run_command(command + ["exec", "-T", "ips", "/app/snapshot.sh", "preflight_after"], check=False)
        _flatten_artifacts(preflight)
        firewall = preflight / "ips" / "firewall_preflight_after.rules"
        if not firewall.exists():
            raise RuntimeError("NFQUEUE preflight did not produce firewall counter evidence")
        firewall_text = firewall.read_text(encoding="utf-8", errors="replace")
        if "NFQUEUE" not in firewall_text or not any(int(value) > 0 for value in __import__("re").findall(r"\[(\d+):\d+\]", firewall_text)):
            raise RuntimeError("NFQUEUE preflight packet counter did not increase")
        result = {
            "status": "PASS",
            "smoke": (smoke.stdout or "").strip(),
            "cache_positive_control": {
                "qname": qname,
                "before": before,
                "answer_ip": trial.get("answer_ip"),
                "after": after,
            },
            "cache_error_control": error_rows[-1],
            "firewall": firewall_text,
            "ips_ready": json.loads((preflight / "ips" / "ips_ready.json").read_text(encoding="utf-8")),
        }
        write_json(root / "preflight.json", result)
        return result
    finally:
        if started:
            _stop_stack(command)


def prepare_registration(root: Path, protocol: dict[str, Any], protocol_path: Path = PROTOCOL_PATH) -> None:
    if root.exists():
        raise FileExistsError(f"refusing to overwrite registered output: {root}")
    _ensure_source_guard()
    root.mkdir(parents=True, exist_ok=False)
    write_json(root / "e5_protocol.json", protocol)
    runtime_env = root / "registration.env"
    write_runtime_env(runtime_env, run_id=str(protocol["run_id"]), rep=0, policy="B0_OFF", workload="REGISTRATION")
    compose = compose_base(str(protocol["run_id"]), runtime_env)
    run_command(compose + ["config", "--quiet"], timeout=60)
    print("[e5] building frozen images", flush=True)
    run_command(compose + ["build"], capture=False, timeout=1800)
    image_names = _compose_image_names(str(protocol["run_id"]), runtime_env)
    image_hashes = _image_ids(image_names)
    if len(image_hashes) != len(image_names):
        missing = sorted(set(image_names) - set(image_hashes))
        raise RuntimeError(f"could not resolve built image IDs: {missing}")
    copy_source_snapshot(root, protocol_path)
    manifest = source_manifest(protocol_path)
    write_json(
        root / "registered.json",
        {
            "schema_version": 1,
            "run_id": protocol["run_id"],
            "registered_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "protocol_sha256": hashlib.sha256(json.dumps(protocol, sort_keys=True).encode("utf-8")).hexdigest(),
            "source_manifest": manifest,
            "image_names": image_names,
            "image_ids": image_hashes,
            "docker": docker_info(),
            "command": sys.argv,
            "python": sys.version,
        },
    )
    print("[e5] registration frozen; running NFQUEUE/routing preflight", flush=True)
    _preflight_stack(root, protocol)


def ensure_registered(root: Path, protocol: dict[str, Any]) -> None:
    _ensure_source_guard()
    if not (root / "registered.json").exists() or not (root / "e5_protocol.json").exists():
        raise RuntimeError(f"no frozen registration found at {root}; run --stage preflight first")
    saved_protocol = json.loads((root / "e5_protocol.json").read_text(encoding="utf-8"))
    if saved_protocol != protocol:
        raise RuntimeError("protocol differs from the registered output; use a new run ID")
    registered = json.loads((root / "registered.json").read_text(encoding="utf-8"))
    protocol_path = Path(str(protocol.get("protocol_path", PROTOCOL_PATH))).resolve()
    if registered.get("source_manifest") != source_manifest(protocol_path):
        raise RuntimeError("source or configuration changed after registration; use a new run ID")
    for image_name, expected_id in registered.get("image_ids", {}).items():
        current = run_command(["docker", "image", "inspect", image_name, "--format", "{{.Id}}"], check=False)
        if current.returncode != 0 or current.stdout.strip() != expected_id:
            raise RuntimeError(f"frozen image changed: {image_name}; use a new run ID")
    if not (root / "preflight.json").exists() or json.loads((root / "preflight.json").read_text(encoding="utf-8")).get("status") != "PASS":
        raise RuntimeError("NFQUEUE/routing preflight is not PASS")


def aggregate_confirmatory(rows: list[dict[str, Any]], protocol: dict[str, Any]) -> dict[str, Any]:
    policies = protocol_policies(protocol)
    workloads = protocol_workloads(protocol)
    expected_runs = int(protocol.get("k_runs_per_cell", protocol.get("stages", {}).get("confirmatory", {}).get("runs_per_cell", 20)))
    expected_keys = {(rep, policy, workload) for rep in range(1, expected_runs + 1) for policy in policies for workload in workloads}
    seen: set[tuple[int, str, str]] = set()
    duplicates: list[tuple[int, str, str]] = []
    for row in rows:
        key = (int(row.get("rep", -1)), str(row.get("policy")), str(row.get("workload")))
        if key in seen:
            duplicates.append(key)
        seen.add(key)
    missing = sorted(expected_keys - seen)
    unexpected = sorted(seen - expected_keys)
    if duplicates or missing or unexpected:
        raise ValueError(
            "confirmatory rows are incomplete or duplicated: "
            f"duplicates={duplicates[:3]}, missing={missing[:3]}, unexpected={unexpected[:3]}"
        )
    output: dict[str, Any] = {"schema_version": 1, "n_runs": len(rows), "groups": {}, "paired": {}}
    for policy in policies:
        for workload in workloads:
            group = [row for row in rows if row.get("policy") == policy and row.get("workload") == workload]
            key = f"{policy}__{workload}"
            attack = workload.startswith("ATTACK_")
            def mean_metric(name: str) -> float | None:
                values = [float(row[name]) for row in group if row.get(name) is not None]
                return fmean(values) if values else None
            any_success = sum(bool(row.get("any_poison")) for row in group)
            first_success = sum(bool(row.get("first_trial_poison")) for row in group)
            entry: dict[str, Any] = {
                "policy": policy,
                "workload": workload,
                "runs": len(group),
                "any_poison_runs": any_success,
                "any_poison_rate": any_success / len(group) if group else None,
                "any_poison_ci95": list(exact_binomial_ci(any_success, len(group))) if group else None,
                "first_trial_poison_runs": first_success,
                "first_trial_poison_ci95": list(exact_binomial_ci(first_success, len(group))) if group else None,
                "mean_run_asr": mean_metric("run_asr") if attack else None,
                "mean_malicious_answer_rate": mean_metric("malicious_answer_rate"),
                "mean_cache_insertion_rate": mean_metric("cache_insertion_rate"),
                "mean_cache_probe_valid_rate": mean_metric("cache_probe_valid_rate"),
                "mean_cache_probe_error_rate": mean_metric("cache_probe_error_rate"),
                "mean_cache_before_probe_valid_rate": mean_metric("cache_before_probe_valid_rate"),
                "mean_cache_before_probe_error_rate": mean_metric("cache_before_probe_error_rate"),
                "mean_cache_after_probe_valid_rate": mean_metric("cache_after_probe_valid_rate"),
                "mean_cache_after_probe_error_rate": mean_metric("cache_after_probe_error_rate"),
                "mean_legitimate_answer_rate": mean_metric("legitimate_answer_rate"),
                "mean_noanswer_rate": mean_metric("noanswer_rate"),
                "mean_trigger_rate": mean_metric("trigger_rate"),
                "mean_detector_active_at_query_rate": mean_metric("detector_active_at_query_rate"),
                "mean_detector_active_at_enforcement_rate": mean_metric("detector_active_at_enforcement_rate"),
                "mean_volume_active_at_query_rate": mean_metric("volume_active_at_query_rate"),
                "mean_cpu_percent_median": mean_metric("cpu_percent_median"),
                "mean_cpu_percent_p95": mean_metric("cpu_percent_p95"),
                "mean_observed_query_qps": mean_metric("observed_query_qps"),
                "mean_observed_fragment_rate": mean_metric("observed_fragment_rate"),
                "mean_forged_tail_drop_rate": mean_metric("forged_tail_drop_rate"),
                "mean_tc_injection_rate": mean_metric("tc_injection_rate"),
                "mean_tcp_retry_rate": mean_metric("tcp_retry_rate"),
            }
            output["groups"][key] = entry
    seed = int(protocol.get("experiment_seed", 20260902))
    for policy in policies:
        if policy == "B0_OFF":
            continue
        for workload in workloads:
            metric = "run_asr" if workload.startswith("ATTACK_") else "legitimate_answer_rate"
            differences = paired_differences(rows, target_policy=policy, baseline_policy="B0_OFF", workload=workload, metric=metric)
            if differences:
                output["paired"][f"{policy}_vs_B0_OFF__{workload}__{metric}"] = paired_bootstrap_mean(
                    differences, replicates=5000, seed=seed + sum(ord(char) for char in policy + workload)
                )
    factorial_workloads = {
        "BENIGN_DIVERSE_MODERATE",
        "BENIGN_DIVERSE_HIGH",
        "ATTACK_DIVERSE_MODERATE",
        "ATTACK_DIVERSE_HIGH",
    }
    if set(factorial_workloads).issubset(set(workloads)) and "B5_LOCKED_TC" in policies:
        factorial: dict[str, Any] = {
            "policy": "B5_LOCKED_TC",
            "metric": "malicious_answer_rate",
            "bootstrap_replicates": 5000,
            "effects": {},
        }
        effects = {
            "attack_minus_benign_at_12_per_s": ("ATTACK_DIVERSE_MODERATE", "BENIGN_DIVERSE_MODERATE"),
            "attack_minus_benign_at_200_per_s": ("ATTACK_DIVERSE_HIGH", "BENIGN_DIVERSE_HIGH"),
            "high_minus_moderate_benign": ("BENIGN_DIVERSE_HIGH", "BENIGN_DIVERSE_MODERATE"),
            "high_minus_moderate_attack": ("ATTACK_DIVERSE_HIGH", "ATTACK_DIVERSE_MODERATE"),
        }
        effect_values: dict[str, dict[int, float]] = {}
        for name, (first_workload, second_workload) in effects.items():
            differences = paired_factorial_differences(
                rows,
                policy="B5_LOCKED_TC",
                first_workload=first_workload,
                second_workload=second_workload,
                metric="malicious_answer_rate",
            )
            effect_values[name] = differences
            if differences:
                factorial["effects"][name] = paired_bootstrap_mean(
                    differences,
                    replicates=5000,
                    seed=seed + sum(ord(char) for char in name),
                )
        attack_benign_delta = {
            rep: effect_values["attack_minus_benign_at_200_per_s"][rep]
            - effect_values["attack_minus_benign_at_12_per_s"][rep]
            for rep in set(effect_values["attack_minus_benign_at_12_per_s"])
            & set(effect_values["attack_minus_benign_at_200_per_s"])
        }
        if attack_benign_delta:
            factorial["effects"]["difference_of_attack_minus_benign_effects_high_minus_moderate"] = paired_bootstrap_mean(
                attack_benign_delta,
                replicates=5000,
                seed=seed + 2026,
            )
        output["factorial_effects"] = factorial
    return output


def _resume_row(root: Path, job: dict[str, Any], schedule: dict[str, Any]) -> dict[str, Any] | None:
    """Return a previously PASSed cell without re-running or overwriting it."""

    cell_dir = root / "raw" / str(job["stage"]) / f"rep_{int(job['rep']):02d}" / f"{job['policy']}__{job['workload']}"
    metrics_path = cell_dir / "metrics.json"
    validation_path = cell_dir / "validation.json"
    if not metrics_path.exists() or not validation_path.exists():
        return None
    try:
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if validation.get("status") != "PASS":
        return None
    if any(metrics.get(field) != job[field] for field in ("stage", "rep", "policy", "workload")):
        return None
    if metrics.get("schedule_sha256") != schedule_digest(schedule):
        return None
    return metrics


def run_stage(root: Path, protocol: dict[str, Any], stage: str, *, resume: bool = False) -> list[dict[str, Any]]:
    if stage not in STAGE_NAMES:
        raise ValueError(stage)
    if stage == "sanity":
        pilot_validation = root / "validation_pilot.json"
        if not pilot_validation.exists() or json.loads(pilot_validation.read_text(encoding="utf-8")).get("status") != "PASS":
            raise RuntimeError("sanity stage is locked behind a PASS pilot gate")
    if stage == "confirmatory":
        sanity_validation = root / "validation_sanity.json"
        if not sanity_validation.exists() or json.loads(sanity_validation.read_text(encoding="utf-8")).get("status") != "PASS":
            raise RuntimeError("confirmatory campaign is locked behind a PASS sanity gate")
    jobs = build_stage_jobs(stage, protocol)
    rows: list[dict[str, Any]] = []
    schedule_manifest: list[dict[str, Any]] = []
    partial_candidates: dict[tuple[str, int, str, str], dict[str, Any]] = {}
    partial_path = root / f"metrics_{stage}_partial.json"
    if resume and partial_path.exists():
        try:
            saved_rows = json.loads(partial_path.read_text(encoding="utf-8"))
            if isinstance(saved_rows, list):
                for row in saved_rows:
                    if not isinstance(row, dict):
                        continue
                    cell_dir = root / "raw" / str(row.get("stage", stage)) / f"rep_{int(row.get('rep', -1)):02d}" / f"{row.get('policy')}__{row.get('workload')}"
                    try:
                        validation = json.loads((cell_dir / "validation.json").read_text(encoding="utf-8"))
                    except (OSError, ValueError, json.JSONDecodeError):
                        continue
                    if validation.get("status") == "PASS":
                        key = (str(row.get("stage", stage)), int(row.get("rep", -1)), str(row.get("policy")), str(row.get("workload")))
                        partial_candidates[key] = row
        except (OSError, json.JSONDecodeError):
            pass
    completed_keys = {(row.get("stage"), int(row.get("rep", -1)), row.get("policy"), row.get("workload")) for row in rows}
    for index, job in enumerate(jobs, 1):
        print(f"[e5] {stage} {index}/{len(jobs)}: {job}", flush=True)
        schedule, schedule_path = schedule_for_cell(root, protocol, job)
        schedule_manifest.append(
            {
                **job,
                "schedule_path": str(schedule_path.relative_to(root)).replace("\\", "/"),
                "schedule_sha256": schedule_digest(schedule),
            }
        )
        write_json(root / f"schedule_manifest_{stage}_partial.json", schedule_manifest)
        key = (job["stage"], int(job["rep"]), job["policy"], job["workload"])
        if resume and key in partial_candidates:
            candidate = partial_candidates.pop(key)
            if candidate.get("schedule_sha256") == schedule_digest(schedule):
                candidate["job_index"] = index
                rows.append(candidate)
                completed_keys.add(key)
                write_json(partial_path, rows)
                continue
        if resume and key not in completed_keys:
            existing = _resume_row(root, job, schedule)
            if existing is not None:
                existing["job_index"] = index
                rows.append(existing)
                completed_keys.add(key)
                write_json(partial_path, rows)
                continue
        if key in completed_keys:
            continue
        metrics, validation = run_cell(root, protocol, job, schedule, schedule_path)
        metrics["job_index"] = index
        if validation.get("status") != "PASS":
            raise RuntimeError(f"integrity validation failed for {job}: {validation.get('errors')}")
        if stage == "sanity" and "replay_start_mode" in schedule:
            probe_errors = int(metrics.get("cache_before_probe_error_trials", 0)) + int(metrics.get("cache_after_probe_error_trials", 0))
            if probe_errors:
                validation["status"] = "FAIL"
                validation.setdefault("errors", []).append(f"sanity cache probe errors: {probe_errors}")
                write_json(root / "raw" / stage / "rep_00" / f"{job['policy']}__{job['workload']}" / "validation.json", validation)
                raise RuntimeError(f"sanity cache probe gate failed for {job}: {probe_errors} errors")
        if stage == "pilot":
            gate = pilot_gate(
                metrics,
                policy=str(job["policy"]),
                workload=str(job["workload"]),
                fragmentation_mode=str(protocol.get("fragmentation_mode") or "crafted"),
            )
            write_json(root / "raw" / stage / "rep_00" / f"{job['policy']}__{job['workload']}" / "pilot_gate.json", gate)
            if gate["status"] != "PASS":
                raise RuntimeError(f"pilot engineering gate failed for {job}: {gate['errors']}")
        # Checkpoint only a fully valid cell.  A failed cell may still have
        # raw artifacts on disk, but it must be rerun or audited on resume.
        rows.append(metrics)
        completed_keys.add(key)
        write_json(partial_path, rows)
    write_json(root / f"metrics_{stage}.json", rows)
    write_json(root / f"schedule_manifest_{stage}.json", schedule_manifest)
    stage_validation = {
        "schema_version": 1,
        "stage": stage,
        "status": "PASS" if len(rows) == len(jobs) else "FAIL",
        "expected_runs": len(jobs),
        "completed_runs": len(rows),
        "errors": [] if len(rows) == len(jobs) else ["not all registered jobs completed"],
    }
    write_json(root / f"validation_{stage}.json", stage_validation)
    if stage == "confirmatory":
        write_json(root / "aggregate_confirmatory.json", aggregate_confirmatory(rows, protocol))
    print(f"[e5] {stage} PASS ({len(rows)} runs)", flush=True)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("preflight", "pilot", "sanity", "confirmatory", "all"), default="preflight")
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH, help="registered protocol JSON")
    parser.add_argument("--resume", action="store_true", help="resume PASSed cells and a partial stage safely")
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT, help="directory for new campaign outputs")
    parser.add_argument("--dry-run", action="store_true", help="print the registered job matrix without Docker")
    args = parser.parse_args(argv)
    run_id = safe_run_id(args.run_id)
    protocol_path = args.protocol.resolve()
    protocol = load_protocol(run_id, protocol_path)
    root = args.output_root.resolve() / run_id
    if args.dry_run:
        if args.stage == "preflight":
            print(json.dumps({"stage": "preflight", "run_id": run_id}, indent=2))
            return 0
        print(json.dumps(build_stage_jobs(args.stage if args.stage != "all" else "confirmatory", protocol), indent=2))
        return 0

    stages: list[str]
    if args.stage == "all":
        stages = ["pilot", "sanity", "confirmatory"]
        docker_info()
        prepare_registration(root, protocol, protocol_path)
    elif args.stage == "preflight":
        docker_info()
        prepare_registration(root, protocol, protocol_path)
        print(f"[e5] registered output: {root}", flush=True)
        return 0
    else:
        ensure_registered(root, protocol)
        stages = [args.stage]

    for stage in stages:
        ensure_registered(root, protocol)
        try:
            run_stage(root, protocol, stage, resume=args.resume)
        except Exception as exc:
            write_json(root / "ABORT.json", {"stage": stage, "error": repr(exc), "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            raise
    write_json(root / "finished.json", {"run_id": run_id, "stages": stages, "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    print(f"[e5] COMPLETE: {root}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"[e5] ABORTED: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2) from exc
