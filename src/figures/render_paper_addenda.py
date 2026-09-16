"""Emit paper addenda from existing E1/E5/orphan artifacts.

No campaign is rerun. E1 M=65,536 remains a post-hoc descriptive sensitivity
on matched benign replay. Runtime activation/CPU/throughput are derived from
frozen confirmatory logs. Optional B2/PMTUD rows are included only when those
campaigns exist as separate run IDs.
"""
from __future__ import annotations

import csv
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

FIGURES = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(FIGURES))
import revise_paper_figures as paper  # noqa: E402

ROOT = paper.ROOT
OUT = paper.OUT
EXP = paper.EXP
E1_DIR = OUT / "controlled_ipid_sensitivity"
ORPHAN_SRC = (
    EXP
    / "Followup-IPID-Orphans/output/posthoc-s20260912-r003/paper/orphan_ratio_baseline.tex"
)
ORIGINAL = EXP / "E5/output/E5-routed-s20260902-r001"
FACTORIAL = EXP / "E5/output/E5-factorial-s20260911-r003"


def campaign_dir(*names: str) -> Path:
    paths = [EXP / "E5/output" / name for name in names]
    for path in paths:
        if (path / "validation_confirmatory.json").exists():
            return path
    return paths[0]


B2_DIR = campaign_dir("E5-b2-s20260915-r002", "E5-b2-s20260915-r001")
PMTUD_DIR = campaign_dir("E5-pmtud-s20260915-r003", "E5-pmtud-s20260915-r002", "E5-pmtud-s20260915-r001")
ICMP_JSON = OUT / "icmp_ptb_audit.json"

SHORT = {
    "B0_OFF": "B0",
    "B1_RL2_TC": "B1+TC",
    "B2_VOLUME_TC": "B2+TC",
    "B5_LOCKED_TC": "Locked B5+TC",
    "RFC_DROP_NATIVE": "Native drop",
}
ALWAYS_ON = {"B1_RL2_TC", "RFC_DROP_NATIVE"}
OCCUPANCY_PPS = {
    "BENIGN_LOW": 2.5,
    "BENIGN_BOUNDARY": 12.0,
    "ATTACK_FIXED_MATCHED": 12.0,
    "ATTACK_SWEEP_FLOOD": 200.0,
    "BENIGN_DIVERSE_MODERATE": 12.0,
    "BENIGN_DIVERSE_HIGH": 200.0,
    "ATTACK_DIVERSE_MODERATE": 12.0,
    "ATTACK_DIVERSE_HIGH": 200.0,
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def pct(value: float | None) -> str:
    if value is None:
        return r"\textemdash{}"
    return f"{100.0 * float(value):.1f}"


def fmt_ci(low: float, high: float) -> str:
    return f"{100.0 * low:.1f}--{100.0 * high:.1f}"


def write_tex_table(
    path: Path,
    *,
    caption: str,
    label: str,
    spec: str,
    header_lines: list[str],
    body_lines: list[str],
    tabcolsep: str = "3pt",
) -> None:
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{" + caption + "}",
        r"\label{" + label + "}",
        r"\begingroup",
        r"\fontsize{9}{10.8}\selectfont",
        r"\setlength{\tabcolsep}{" + tabcolsep + "}",
        r"\begin{tabular}{" + spec + "}",
        r"\hline",
        *header_lines,
        r"\hline",
        *body_lines,
        r"\hline",
        r"\end{tabular}",
        r"\endgroup",
        r"\end{table}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def load_e1_summary() -> list[dict]:
    rows = []
    with (E1_DIR / "summary.csv").open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            row["level"] = int(row["level"])
            row["space"] = int(row["space"])
            row["mean"] = float(row["mean"])
            row["ci_low"] = float(row["ci_low"])
            row["ci_high"] = float(row["ci_high"])
            row["runs"] = int(row["runs"])
            rows.append(row)
    return rows


def cell(rows: list[dict], **keys) -> dict:
    matches = [row for row in rows if all(str(row[k]) == str(v) for k, v in keys.items())]
    if len(matches) != 1:
        raise ValueError(f"expected one E1 cell for {keys}, found {len(matches)}")
    return matches[0]


def paper_activation(policy: str, run: dict) -> float:
    if policy in ALWAYS_ON:
        return 1.0
    if policy == "B2_VOLUME_TC":
        value = run.get("volume_active_at_query_rate")
        if value is not None:
            return float(value)
    value = run.get("detector_active_at_query_rate")
    if value is not None:
        return float(value)
    return float(run.get("trigger_rate") or 0.0)


def summarize_campaign(root: Path, campaign: str) -> list[dict]:
    runs = read_json(root / "metrics_confirmatory.json")
    validation = read_json(root / "validation_confirmatory.json")
    if validation.get("status") != "PASS":
        raise RuntimeError(f"{root.name} confirmatory validation is not PASS")
    by_cell: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for run in runs:
        by_cell[(str(run["policy"]), str(run["workload"]))].append(run)
    rows = []
    for (policy, workload), cell_runs in sorted(by_cell.items()):
        if sorted(int(run["rep"]) for run in cell_runs) != list(range(1, len(cell_runs) + 1)):
            raise RuntimeError(f"incomplete replicate set for {policy} {workload} in {root.name}")
        n_runs = len(cell_runs)
        malicious = [float(run.get("malicious_answer_rate") or run.get("run_asr") or 0.0) for run in cell_runs]
        noanswer = [float(run.get("noanswer_rate") or 0.0) for run in cell_runs]
        activation = [paper_activation(policy, run) for run in cell_runs]
        any_malicious = sum(bool(run.get("any_poison")) for run in cell_runs)
        low, high = _cp(any_malicious, n_runs)
        cpu_med = [run["cpu_percent_median"] for run in cell_runs if run.get("cpu_percent_median") is not None]
        cpu_p95 = [run["cpu_percent_p95"] for run in cell_runs if run.get("cpu_percent_p95") is not None]
        qps = []
        for run in cell_runs:
            wall = run.get("wall_duration_s")
            trials = run.get("n_trials") or 50
            if wall and float(wall) > 0:
                qps.append(float(trials) / float(wall))
            elif run.get("observed_query_qps") is not None:
                qps.append(float(run["observed_query_qps"]))
        frag = [run["observed_fragment_rate"] for run in cell_runs if run.get("observed_fragment_rate") is not None]
        rows.append(
            {
                "campaign": campaign,
                "policy": policy,
                "workload": workload,
                "runs": n_runs,
                "malicious_answer_rate": float(np.mean(malicious)),
                "noanswer_rate": float(np.mean(noanswer)),
                "activation_rate": float(np.mean(activation)),
                "any_malicious_runs": any_malicious,
                "any_malicious_ci_low": low,
                "any_malicious_ci_high": high,
                "cpu_percent_median": float(np.mean(cpu_med)) if cpu_med else None,
                "cpu_percent_p95": float(np.mean(cpu_p95)) if cpu_p95 else None,
                "observed_query_qps": float(np.mean(qps)) if qps else None,
                "observed_fragment_rate": float(np.mean(frag)) if frag else None,
                "occupancy_target_pps": OCCUPANCY_PPS.get(workload),
            }
        )
    return rows


def _cp(successes: int, total: int) -> tuple[float, float]:
    from scipy.stats import beta

    low = 0.0 if successes == 0 else float(beta.ppf(0.025, successes, total - successes + 1))
    high = 1.0 if successes == total else float(beta.ppf(0.975, successes + 1, total - successes))
    return low, high


def emit_e1(rows: list[dict]) -> None:
    verification = read_json(E1_DIR / "verification.json")
    if verification.get("status") != "PASS":
        raise RuntimeError("E1 65,536 sensitivity verification is not PASS")
    high_levels = [600, 1200, 1400, 1600, 1800, 2000, 3000, 6000]
    body = []
    for level in high_levels:
        old = cell(rows, behavior="random2048", phase="high_load", level=level, space=2048, configuration="locked")
        new = cell(rows, behavior="random2048", phase="high_load", level=level, space=65536, configuration="locked")
        body.append(
            f"{level} & {pct(old['mean'])} & {fmt_ci(old['ci_low'], old['ci_high'])} & "
            f"{pct(new['mean'])} & {fmt_ci(new['ci_low'], new['ci_high'])} \\\\"
        )
    write_tex_table(
        OUT / "e1_ipid_locked_highload.tex",
        caption=(
            r"Post-hoc descriptive benign sensitivity of locked B5 when the controlled IPID "
            r"space is expanded from 2,048 to 65,536. Only the archived random high-load generator "
            r"is replayed; arrival times and occupancy are matched. Each cell has 20 runs of 300 "
            r"decisions. Intervals are run-level percentile 95\% bootstrap intervals. This is not a "
            r"new held-out evaluation and does not replace the main RQ1 figure ($M=2{,}048$)."
        ),
        label="tab:e1-ipid-highload",
        spec="lrrrr",
        header_lines=[
            r"Target $n$ & $M=2{,}048$ (\%) & 95\% CI & $M=65{,}536$ (\%) & 95\% CI \\",
        ],
        body_lines=body,
    )
    main_levels = [24, 36, 60, 120, 300]
    body = []
    for behavior, name in [("random2048", "Random"), ("sequential", "Sequential")]:
        for level in main_levels:
            old = cell(rows, behavior=behavior, phase="main", level=level, space=2048, configuration="locked")
            new = cell(rows, behavior=behavior, phase="main", level=level, space=65536, configuration="locked")
            body.append(
                f"{name} & {level} & {pct(old['mean'])} & {fmt_ci(old['ci_low'], old['ci_high'])} & "
                f"{pct(new['mean'])} & {fmt_ci(new['ci_low'], new['ci_high'])} \\\\"
            )
    write_tex_table(
        OUT / "e1_ipid_locked_maingrid.tex",
        caption=(
            r"Locked-B5 benign trigger rates on the matched main grid. Sequential identifiers use "
            r"the same larger modulus; their outcome is preserved. Initial-B5 main-grid rates are "
            r"essentially unchanged across spaces and are omitted here. The pool-of-16 condition is "
            r"not modified. Post-hoc descriptive only; the locked operating point is not retuned."
        ),
        label="tab:e1-ipid-maingrid",
        spec="llrrrr",
        header_lines=[
            r"IPID & Target $n$ & $M=2{,}048$ (\%) & 95\% CI & $M=65{,}536$ (\%) & 95\% CI \\",
        ],
        body_lines=body,
    )
    init_body = []
    for level in [12, 24, 36, 60]:
        old = cell(rows, behavior="random2048", phase="main", level=level, space=2048, configuration="initial")
        new = cell(rows, behavior="random2048", phase="main", level=level, space=65536, configuration="initial")
        init_body.append(
            f"{level} & {pct(old['mean'])} & {fmt_ci(old['ci_low'], old['ci_high'])} & "
            f"{pct(new['mean'])} & {fmt_ci(new['ci_low'], new['ci_high'])} \\\\"
        )
    write_tex_table(
        OUT / "e1_ipid_initial_maingrid.tex",
        caption=(
            r"Initial-B5 benign trigger rates on the matched random main grid. Expanding the "
            r"identifier space does not change these cells; collision effects appear only at high "
            r"occupancy under the locked rule. Post-hoc descriptive sensitivity; not a new RQ1 figure."
        ),
        label="tab:e1-ipid-initial",
        spec="lrrrr",
        header_lines=[
            r"Target $n$ & $M=2{,}048$ (\%) & 95\% CI & $M=65{,}536$ (\%) & 95\% CI \\",
        ],
        body_lines=init_body,
    )
    paper.configure()
    fig, axes = plt.subplots(1, 2, figsize=(paper.WIDTH, 2.75))
    fig.subplots_adjust(left=0.13, right=0.98, bottom=0.31, top=0.87, wspace=0.35)
    for ax, config, title in zip(axes, ["initial", "locked"], ["A  Initial B5", "B  Locked B5"]):
        for space, color, style, marker in [(2048, paper.GRAY, "--", "s"), (65536, paper.BLUE, "-", "o")]:
            selected = sorted(
                [
                    row
                    for row in rows
                    if row["behavior"] == "random2048" and row["configuration"] == config and row["space"] == space
                ],
                key=lambda row: row["level"],
            )
            paper.line(ax, [row["level"] for row in selected], selected, color, marker, style, f"{space:,} values")
        ax.set_xscale("log")
        ax.set_xticks([10, 100, 1000], ["10", "100", "1,000"])
        ax.minorticks_off()
        ax.set_ylim(-0.03, 1.03)
        ax.set_yticks([0, 0.5, 1])
        ax.set_title(title, loc="left", fontweight="bold")
        paper.original.style_axes(ax)
    axes[0].set_ylabel("Benign trigger rate")
    fig.text(0.54, 0.16, "Target fragments per 2-s window", ha="center", fontsize=8.5)
    fig.legend(*axes[0].get_legend_handles_labels(), loc="lower center", ncol=2, frameon=False, bbox_to_anchor=(0.54, 0.015))
    saved = paper.OUT
    paper.OUT = OUT
    paper.save(fig, "e1_ipid_space_boundary")
    paper.OUT = saved
    shutil.copy2(OUT / "e1_ipid_space_boundary.pdf", E1_DIR / "controlled_ipid_space_boundary.pdf")
    shutil.copy2(OUT / "e1_ipid_space_boundary.png", E1_DIR / "controlled_ipid_space_boundary.png")


def workload_label(campaign: str, workload: str) -> str:
    labels = {
        "ATTACK_FIXED_MATCHED": "Fixed",
        "ATTACK_SWEEP_FLOOD": "Flood",
        "BENIGN_LOW": "Benign 2.5",
        "BENIGN_BOUNDARY": "Benign 12",
        "BENIGN_DIVERSE_MODERATE": "B12",
        "BENIGN_DIVERSE_HIGH": "B200",
        "ATTACK_DIVERSE_MODERATE": "A12",
        "ATTACK_DIVERSE_HIGH": "A200",
    }
    return labels.get(workload, workload)


def emit_runtime(
    original: list[dict],
    factorial: list[dict],
    b2: list[dict] | None,
    pmtud: list[dict] | None = None,
) -> None:
    def attack_rows(rows: list[dict], campaign: str) -> list[dict]:
        selected = [row for row in rows if row["campaign"] == campaign and str(row["workload"]).startswith("ATTACK")]
        order = {"ATTACK_FIXED_MATCHED": 0, "ATTACK_SWEEP_FLOOD": 1, "ATTACK_DIVERSE_MODERATE": 0, "ATTACK_DIVERSE_HIGH": 1}
        policies = ["B0_OFF", "B1_RL2_TC", "B5_LOCKED_TC", "RFC_DROP_NATIVE", "B2_VOLUME_TC"]
        selected.sort(key=lambda row: (policies.index(row["policy"]) if row["policy"] in policies else 99, order.get(row["workload"], 9)))
        return selected

    orig_attacks = attack_rows(original, "original")
    rq4_body = []
    for row in orig_attacks:
        rq4_body.append(
            f"{SHORT[row['policy']]} & {workload_label('original', row['workload'])} & {pct(row['activation_rate'])} & "
            f"{pct(row['malicious_answer_rate'])} & {pct(row['noanswer_rate'])} & "
            f"{row['any_malicious_runs']}/{row['runs']} & {fmt_ci(row['any_malicious_ci_low'], row['any_malicious_ci_high'])} \\\\"
        )
    write_tex_table(
        OUT / "RQ4_runtime_outcomes.tex",
        caption=(
            r"Original runtime outcomes. Activation is locked-B5 state at query start for B0/B5; "
            r"B1 and native-drop report 100\% because those policies are always on, not because B5 "
            r"triggered. Malicious-answer and no-answer rates are trial percentages (1,000 trials per "
            r"cell); affected runs contain at least one malicious answer. Intervals are exact 95\% "
            r"Clopper--Pearson intervals for the affected-run percentage; 20 recreated-stack runs per cell."
        ),
        label="tab:rq4-runtime",
        spec="llrrrrr",
        header_lines=[
            r"Policy & Attack & Act. \% & Mal. \% & None \% & Runs & 95\% CI \\",
        ],
        body_lines=rq4_body,
    )

    def section(title: str, rows: list[dict], campaign: str) -> list[str]:
        lines = [rf"\multicolumn{{7}}{{l}}{{\textit{{{title}}}}} \\", r"\hline"]
        for row in rows:
            lines.append(
                f"{SHORT[row['policy']]} & {workload_label(campaign, row['workload'])} & {pct(row['activation_rate'])} & "
                f"{pct(row['malicious_answer_rate'])} & {pct(row['noanswer_rate'])} & "
                f"{row['any_malicious_runs']}/{row['runs']} & {fmt_ci(row['any_malicious_ci_low'], row['any_malicious_ci_high'])} \\\\"
            )
        return lines

    combined = [
        *section("Original campaign", orig_attacks, "original"),
        r"\hline",
        *section("Post-hoc-designed $2\\times2$ follow-up", factorial, "factorial"),
    ]
    if b2:
        combined.extend([r"\hline", *section("B2 volume-only addon (not pooled)", b2, "original")])
    if pmtud:
        combined.extend([r"\hline", *section("PMTUD kernel-fragment branch (not pooled)", pmtud, "original")])
    write_tex_table(
        OUT / "runtime_combined.tex",
        caption=(
            r"Runtime outcomes in the original campaign and the separately analyzed $2\times2$ "
            r"follow-up. Activation is locked-B5 window state at query start for B0/B5 (passive under "
            r"B0); B1 and native-drop are recorded as 100\% policy-on. B2, when present, is volume "
            r"$n\geq 8$ at query start and is a separate campaign. Each row contains 20 recreated-stack "
            r"runs with 50 trials per run. Malicious-answer and no-answer rates are trial percentages. "
            r"Affected runs contain at least one malicious answer; intervals are exact 95\% "
            r"Clopper--Pearson intervals for the affected-run percentage. Campaigns are not pooled."
        ),
        label="tab:rq4-runtime",
        spec="llrrrrr",
        header_lines=[
            r"Policy & Workload & Act. & Malicious & No answer & Affected & 95\% CI \\",
            r" & & (\%) & (\%) & (\%) & runs & (\%) \\",
        ],
        body_lines=combined,
    )

    overhead_rows = original + factorial + (b2 or []) + (pmtud or [])
    cpu_body = []
    for row in overhead_rows:
        if not str(row["workload"]).startswith(("ATTACK", "BENIGN")):
            continue
        cpu_med = r"\textemdash{}" if row["cpu_percent_median"] is None else f"{row['cpu_percent_median']:.1f}"
        cpu_p95 = r"\textemdash{}" if row["cpu_percent_p95"] is None else f"{row['cpu_percent_p95']:.1f}"
        qps = r"\textemdash{}" if row["observed_query_qps"] is None else f"{row['observed_query_qps']:.2f}"
        occ = r"\textemdash{}" if row["occupancy_target_pps"] is None else f"{row['occupancy_target_pps']:.0f}"
        cpu_body.append(
            f"{row['campaign']} & {SHORT[row['policy']]} & {workload_label(row['campaign'], row['workload'])} & "
            f"{cpu_med} & {cpu_p95} & {qps} & {occ} \\\\"
        )
    # Compact attack-only CPU table to stay printable.
    compact = []
    for row in overhead_rows:
        if not str(row["workload"]).startswith("ATTACK"):
            continue
        cpu_med = r"\textemdash{}" if row["cpu_percent_median"] is None else f"{row['cpu_percent_median']:.1f}"
        cpu_p95 = r"\textemdash{}" if row["cpu_percent_p95"] is None else f"{row['cpu_percent_p95']:.1f}"
        qps = r"\textemdash{}" if row["observed_query_qps"] is None else f"{row['observed_query_qps']:.2f}"
        occ = r"\textemdash{}" if row["occupancy_target_pps"] is None else f"{row['occupancy_target_pps']:.0f}"
        compact.append(
            f"{row['campaign']} & {SHORT[row['policy']]} & {workload_label(row['campaign'], row['workload'])} & "
            f"{cpu_med} & {cpu_p95} & {qps} & {occ} \\\\"
        )
    write_tex_table(
        OUT / "runtime_cpu_throughput.tex",
        caption=(
            r"CPU and observed query throughput, separate from attack-success rates. CPU is the mean "
            r"across 20 recreated-stack runs of each run's median and 95th-percentile container sample. "
            r"Query rate is completed trials divided by that run's wall-clock duration, not Unbound "
            r"capacity. Occupancy is the registered background fragment rate; flood CPU tracks occupancy, "
            r"not B5 overhead. Original and factorial campaigns are not pooled."
        ),
        label="tab:runtime-cpu-throughput",
        spec="lllrrrr",
        header_lines=[
            r"Campaign & Policy & Traffic & CPU med. & CPU p95 & Query/s & Occ. /s \\",
        ],
        body_lines=compact,
    )


def emit_orphan() -> None:
    if not ORPHAN_SRC.exists():
        raise FileNotFoundError(ORPHAN_SRC)
    shutil.copy2(ORPHAN_SRC, OUT / "orphan_ratio_baseline.tex")


def emit_icmp() -> None:
    if not ICMP_JSON.exists():
        write_tex_table(
            OUT / "icmp_ptb_audit.tex",
            caption=(
                r"ICMP Path MTU Discovery audit of the original and factorial runtime captures. "
                r"The audit artifact has not been written yet."
            ),
            label="tab:icmp-ptb-audit",
            spec="lrr",
            header_lines=[r"Campaign & IPv4 PTB & IPv6 PTB \\"],
            body_lines=[r"pending & \textemdash{} & \textemdash{} \\"],
        )
        return
    payload = read_json(ICMP_JSON)
    body = []
    for row in payload.get("campaigns", []):
        body.append(
            f"{row['campaign']} & {row['ipv4_dest_unreach_frag_needed']} & {row['ipv6_packet_too_big']} \\\\"
        )
    write_tex_table(
        OUT / "icmp_ptb_audit.tex",
        caption=(
            r"ICMP Path MTU Discovery messages in archived IPS captures. IPv4 counts type~3 code~4; "
            r"IPv6 counts type~2. The main lab crafts fragments in user space (FRAGSIZE $=40$); it does "
            r"not induce kernel fragmentation via PTB. A separate PMTUD branch is required before any "
            r"PMTUD claim."
        ),
        label="tab:icmp-ptb-audit",
        spec="lrr",
        header_lines=[r"Campaign & IPv4 PTB & IPv6 Packet Too Big \\"],
        body_lines=body,
    )


def emit_prose(b2: list[dict] | None, pmtud_exists: bool) -> None:
    high = (
        "At registered high load (target $n=600$), locked B5 never triggers in the 2,048-value "
        "space (0/20 runs) and triggers in every run of the matched 65,536-value replay (20/20). "
        "The main RQ1 figures remain $M=2{,}048$."
    )
    b2_note = (
        "The B2 volume-only addon uses the same occupancy/qname schedules as the original campaign "
        "and is paired by (workload, rep). It is not pooled with the four original policies."
        if b2
        else
        "The B2 volume-only runtime addon is registered separately; confirmatory rows appear only after that campaign PASSes."
    )
    pmtud_note = (
        "The PMTUD branch is a separate campaign and is not pooled with the crafted-fragment E5 results."
        if pmtud_exists
        else
        "A PMTUD confirmatory campaign is issued only if a kernel-fragmentation pilot PASSes; otherwise only the ICMP audit is reported."
    )
    text = rf"""% Addendum blocks. Do not replace RQ1 ($M=2{{,}}048$) or pool new campaigns with locked E5.
The $M=65{{,}}536$ comparison is a post-hoc descriptive sensitivity on matched benign replay
(Tables~\ref{{tab:e1-ipid-highload}}--\ref{{tab:e1-ipid-initial}}, Figure~\ref{{fig:e1-ipid-space}}).
{high}
Sequential main-grid rates are preserved; \texttt{{smallpool16}} is unchanged.

\begin{{figure}}[t]
\centering
\includegraphics[width=\linewidth]{{figure/e1_ipid_space_boundary.pdf}}
\caption{{Post-hoc benign IPID-space sensitivity. Panel A is initial B5; panel B is locked B5.
Arrival times and occupancy are matched across $M=2{{,}}048$ and $M=65{{,}}536$. Bands are run-level
percentile 95\% intervals (20 runs, 300 decisions). This figure does not replace RQ1.}}
\label{{fig:e1-ipid-space}}
\end{{figure}}

Table~\ref{{tab:rq4-runtime}} adds an activation column. For B5 it is detector state at query start;
for B1 and native-drop it is policy-on (100\%), not B5. B0 reports passive B5 state.
Table~\ref{{tab:runtime-cpu-throughput}} reports CPU and completed-query wall throughput separately
from attack-success rates.
{b2_note}

Table~\ref{{tab:icmp-ptb-audit}} audits ICMP PTB on the crafted-fragment captures.
{pmtud_note}

Table~\ref{{tab:orphan-baseline}} is an offline orphan-fragment detector baseline on no-enforcement
traces. No orphan policy was enforced, so these rates are not poisoning-prevention or ASR.
Any PMTUD orphan score is a separate stratum and is not mixed with this table.
"""
    (OUT / "paper_addenda.tex").write_text(text, encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    e1 = load_e1_summary()
    emit_e1(e1)
    original = summarize_campaign(ORIGINAL, "original")
    factorial = summarize_campaign(FACTORIAL, "factorial")
    b2 = summarize_campaign(B2_DIR, "b2") if (B2_DIR / "validation_confirmatory.json").exists() else None
    pmtud = summarize_campaign(PMTUD_DIR, "pmtud") if (PMTUD_DIR / "validation_confirmatory.json").exists() else None
    emit_runtime(original, factorial, b2, pmtud)
    emit_orphan()
    emit_icmp()
    emit_prose(b2, pmtud is not None)
    (OUT / "qa" / "addenda_check.tex").write_text(
        r"""\documentclass{article}
\usepackage[paperwidth=154mm,paperheight=230mm,margin=16mm]{geometry}
\usepackage{graphicx}
\begin{document}
\input{../e1_ipid_locked_highload.tex}
\clearpage
\input{../e1_ipid_locked_maingrid.tex}
\clearpage
\input{../e1_ipid_initial_maingrid.tex}
\clearpage
\input{../RQ4_runtime_outcomes.tex}
\clearpage
\input{../runtime_combined.tex}
\clearpage
\input{../runtime_cpu_throughput.tex}
\clearpage
\input{../icmp_ptb_audit.tex}
\clearpage
\input{../orphan_ratio_baseline.tex}
\end{document}
""",
        encoding="utf-8",
    )
    print(f"Paper addenda written to {OUT}")


if __name__ == "__main__":
    main()
