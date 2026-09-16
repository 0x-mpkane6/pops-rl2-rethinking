"""Generate English, publication-ready figures for the RQ1--RQ4 results.

The script reads only canonical experiment artifacts and writes a separate
figure set under ``research/Report/figures/rq_summary_en``. Existing frozen
experiment figures are not modified.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENT_ROOT = REPO_ROOT / "research" / "Report" / "experiments"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "rq_summary_en"

E1_LEVELS = (
    EXPERIMENT_ROOT
    / "E1"
    / "runs"
    / "E1_confirmatory_20260810_seed20260810_raw_v2"
    / "e1_levels.csv"
)
E2_SUMMARY = (
    EXPERIMENT_ROOT
    / "E2"
    / "runs"
    / "E2_confirmatory_20260814_complete_b0_ablation"
    / "e2_summary.csv"
)
E3_GRID = EXPERIMENT_ROOT / "E3" / "e3_validation_grid.csv"
E3_TEST = EXPERIMENT_ROOT / "E3" / "e3_test_results.csv"
E5_AGGREGATE = (
    EXPERIMENT_ROOT
    / "E5"
    / "output"
    / "E5-routed-s20260902-r001"
    / "aggregate_confirmatory.json"
)
E5_METRICS = (
    EXPERIMENT_ROOT
    / "E5"
    / "output"
    / "E5-routed-s20260902-r001"
    / "metrics_confirmatory.json"
)


OKABE_ITO = {
    "blue": "#0072B2",
    "orange": "#E69F00",
    "green": "#009E73",
    "vermillion": "#D55E00",
    "purple": "#CC79A7",
    "sky": "#56B4E9",
    "black": "#000000",
    "gray": "#6B7280",
}


def configure_style() -> None:
    """Apply a consistent, print-oriented style to every output figure."""

    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
            "font.size": 8.5,
            "axes.titlesize": 10,
            "axes.labelsize": 9,
            "xtick.labelsize": 7.5,
            "ytick.labelsize": 7.5,
            "legend.fontsize": 7.5,
            "figure.titlesize": 11,
            "axes.linewidth": 0.8,
            "lines.linewidth": 1.6,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
            "savefig.facecolor": "white",
            "axes.facecolor": "white",
        }
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def number(value: str | int | float | None) -> float:
    if value is None or value == "":
        return float("nan")
    return float(value)


def errorbar_from_row(row: dict[str, str], mean_key: str, low_key: str, high_key: str) -> tuple[float, list[float]]:
    mean = number(row[mean_key])
    low = number(row[low_key])
    high = number(row[high_key])
    return mean, [[max(0.0, mean - low)], [max(0.0, high - mean)]]


def style_axes(ax: plt.Axes) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", color="#D1D5DB", linewidth=0.55, alpha=0.65)
    ax.set_axisbelow(True)


def panel_label(ax: plt.Axes, label: str) -> None:
    ax.text(
        -0.14,
        1.08,
        label,
        transform=ax.transAxes,
        fontsize=10,
        fontweight="bold",
        va="top",
        ha="left",
    )


def save_figure(fig: plt.Figure, output_dir: Path, stem: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for extension, kwargs in (
        ("png", {"dpi": 600}),
        ("pdf", {}),
        ("svg", {}),
    ):
        fig.savefig(
            output_dir / f"{stem}.{extension}",
            bbox_inches="tight",
            facecolor="white",
            **kwargs,
        )
    plt.close(fig)


def bootstrap_ci(values: Iterable[float], seed: int, replicates: int = 5000) -> tuple[float, float, float]:
    """Return mean and a run-level percentile bootstrap interval."""

    array = np.asarray(list(values), dtype=float)
    if array.size == 0:
        return float("nan"), float("nan"), float("nan")
    generator = np.random.default_rng(seed)
    samples = generator.choice(array, size=(replicates, array.size), replace=True)
    means = samples.mean(axis=1)
    return float(array.mean()), float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def make_rq1(output_dir: Path) -> None:
    rows = [row for row in read_csv(E1_LEVELS) if row["variant"] == "combined"]
    labels = {
        "random2048": "Random IPID (2,048-value space)",
        "sequential": "Sequential IPID",
        "smallpool16": "Small IPID pool (16 values)",
    }
    colors = {
        "random2048": OKABE_ITO["blue"],
        "sequential": OKABE_ITO["orange"],
        "smallpool16": OKABE_ITO["green"],
    }
    markers = {"random2048": "o", "sequential": "s", "smallpool16": "^"}
    fig, ax = plt.subplots(figsize=(5.6, 3.5), constrained_layout=True)
    for behavior in ("random2048", "sequential", "smallpool16"):
        selected = sorted(
            (row for row in rows if row["behavior"] == behavior),
            key=lambda row: int(row["level_samples_per_window"]),
        )
        x = np.asarray([int(row["level_samples_per_window"]) for row in selected])
        mean = np.asarray([number(row["fpr_run_mean"]) for row in selected])
        low = np.maximum(0.0, np.asarray([number(row["fpr_run_ci_lo"]) for row in selected]))
        high = np.minimum(1.0, np.asarray([number(row["fpr_run_ci_hi"]) for row in selected]))
        ax.fill_between(x, low, high, color=colors[behavior], alpha=0.14, linewidth=0)
        ax.plot(
            x,
            mean,
            color=colors[behavior],
            marker=markers[behavior],
            markerfacecolor="white",
            markeredgewidth=0.9,
            label=labels[behavior],
        )
    ax.axhline(0.5, color=OKABE_ITO["gray"], linestyle=(0, (3, 2)), linewidth=0.85)
    ax.text(0.99, 0.515, "50% trigger rate", transform=ax.transAxes, ha="right", va="bottom", fontsize=7)
    ax.set_xscale("symlog", linthresh=10)
    ax.set_xticks([5, 12, 18, 24, 36, 60, 120, 300])
    ax.set_xticklabels(["5", "12", "18", "24", "36", "60", "120", "300"])
    ax.set_ylim(-0.02, 1.04)
    ax.set_yticks([0, 0.25, 0.50, 0.75, 1.00])
    ax.set_xlabel("Target fragments per 2-s observation window")
    ax.set_ylabel("False-positive rate (benign trigger rate)")
    ax.set_title("Benign operating boundary")
    ax.legend(frameon=False, loc="upper left")
    style_axes(ax)
    save_figure(fig, output_dir, "RQ1_benign_boundary")


def make_rq2(output_dir: Path) -> None:
    rows = read_csv(E2_SUMMARY)
    delta = [
        row
        for row in rows
        if row["metric"] == "delta_j_combined_minus_volume"
        and row["attack_condition"] in {"attack_sweep_continuous", "attack_sweep_bursty"}
    ]
    score_rows = [
        row
        for row in rows
        if row["metric"] == "auprc_high_is_suspicious"
        and row["attack_condition"] in {"attack_sweep_continuous", "attack_sweep_bursty"}
        and row["variant_or_feature"] in {"entropy", "unique_ratio"}
    ]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.4), constrained_layout=True)
    ax = axes[0]
    profile_style = {
        "continuous": ("Continuous", OKABE_ITO["blue"], "-", "o"),
        "bursty": ("Bursty", OKABE_ITO["orange"], "--", "s"),
    }
    for profile, (label, color, linestyle, marker) in profile_style.items():
        selected = sorted(
            (row for row in delta if row["profile"] == profile),
            key=lambda row: int(row["level"]),
        )
        x = np.asarray([int(row["level"]) for row in selected])
        means = np.asarray([number(row["mean"]) for row in selected])
        low = np.asarray([number(row["ci95_lo"]) for row in selected])
        high = np.asarray([number(row["ci95_hi"]) for row in selected])
        ax.errorbar(
            x,
            means,
            yerr=np.vstack((means - low, high - means)),
            color=color,
            linestyle=linestyle,
            marker=marker,
            markerfacecolor="white",
            capsize=2.5,
            label=label,
        )
    ax.axhline(0, color=OKABE_ITO["black"], linewidth=0.85)
    ax.set_xticks([24, 60, 120, 200])
    ax.set_ylim(-0.025, 0.025)
    ax.set_yticks([-0.02, -0.01, 0, 0.01, 0.02])
    ax.set_xlabel("Target volume (fragments per window)")
    ax.set_ylabel("ΔJ (combined B5 − volume-only)")
    ax.set_title("Volume-matched rule comparison")
    ax.legend(frameon=False, loc="upper right")
    style_axes(ax)
    panel_label(ax, "A")

    ax = axes[1]
    feature_style = {
        "entropy": ("Entropy", OKABE_ITO["purple"], "s"),
        "unique_ratio": ("Unique-IPID ratio", OKABE_ITO["blue"], "o"),
    }
    for profile, (profile_label, _, linestyle, _) in profile_style.items():
        for feature, (feature_label, color, marker) in feature_style.items():
            selected = sorted(
                (
                    row
                    for row in score_rows
                    if row["profile"] == profile and row["variant_or_feature"] == feature
                ),
                key=lambda row: int(row["level"]),
            )
            x = np.asarray([int(row["level"]) for row in selected])
            means = np.asarray([number(row["mean"]) for row in selected])
            low = np.asarray([number(row["ci95_lo"]) for row in selected])
            high = np.asarray([number(row["ci95_hi"]) for row in selected])
            ax.fill_between(x, low, high, color=color, alpha=0.08, linewidth=0)
            ax.plot(
                x,
                means,
                color=color,
                linestyle=linestyle,
                marker=marker,
                markerfacecolor="white",
                markeredgewidth=0.8,
                label=f"{feature_label} ({profile_label.lower()})",
            )
    ax.axhline(0.5, color=OKABE_ITO["gray"], linestyle=(0, (3, 2)), linewidth=0.85)
    ax.set_xticks([24, 60, 120, 200])
    ax.set_ylim(0.45, 1.02)
    ax.set_xlabel("Target volume (fragments per window)")
    ax.set_ylabel("PR-AUC")
    ax.set_title("Score-level ranking evidence")
    ax.legend(frameon=False, loc="upper left", ncol=2, columnspacing=0.8, handlelength=2.1)
    style_axes(ax)
    panel_label(ax, "B")
    save_figure(fig, output_dir, "RQ2_volume_matched_discrimination")


def make_rq3(output_dir: Path) -> None:
    grid_rows = read_csv(E3_GRID)
    test_rows = read_csv(E3_TEST)
    ns = sorted({int(row["min_samples"]) for row in grid_rows})
    hs = sorted({float(row["entropy_threshold"]) for row in grid_rows})
    us = sorted({float(row["unique_ratio_threshold"]) for row in grid_rows})
    max_abs = max(abs(number(row["macro_delta_J_new_vs_B2"])) for row in grid_rows)
    color_limit = max(0.01, max_abs * 1.05)

    fig = plt.figure(figsize=(8.2, 5.0), constrained_layout=True)
    grid = fig.add_gridspec(2, 3, width_ratios=[1, 1, 1.35], height_ratios=[1, 1])
    heat_axes: list[plt.Axes] = []
    image = None
    selected_n = 8
    for index, n_value in enumerate(ns):
        ax = fig.add_subplot(grid[index // 2, index % 2])
        heat_axes.append(ax)
        matrix = np.full((len(hs), len(us)), np.nan)
        for row in grid_rows:
            if int(row["min_samples"]) != n_value:
                continue
            h_index = hs.index(float(row["entropy_threshold"]))
            u_index = us.index(float(row["unique_ratio_threshold"]))
            matrix[h_index, u_index] = number(row["macro_delta_J_new_vs_B2"])
        image = ax.imshow(
            matrix,
            origin="lower",
            aspect="auto",
            cmap="PuOr",
            vmin=-color_limit,
            vmax=color_limit,
        )
        ax.set_xticks(range(len(us)), [f"{value:g}" for value in us])
        ax.set_yticks(range(len(hs)), [f"{value:g}" for value in hs])
        ax.set_xlabel("Unique-ratio threshold")
        ax.set_ylabel("Entropy threshold")
        ax.set_title(f"Minimum samples N = {n_value}")
        ax.set_xticks(np.arange(-0.5, len(us), 1), minor=True)
        ax.set_yticks(np.arange(-0.5, len(hs), 1), minor=True)
        ax.grid(which="minor", color="white", linewidth=0.8)
        ax.tick_params(which="minor", bottom=False, left=False)
        if n_value == selected_n:
            selected_h = hs.index(6.0)
            selected_u = us.index(0.9)
            ax.scatter(
                [selected_u],
                [selected_h],
                s=72,
                facecolors="none",
                edgecolors=OKABE_ITO["black"],
                linewidths=1.5,
                zorder=3,
            )
            ax.text(selected_u + 0.10, selected_h + 0.12, "selected", fontsize=6.7, weight="bold")
        panel_label(ax, chr(ord("A") + index))

    if image is not None:
        fig.colorbar(
            image,
            ax=heat_axes,
            orientation="horizontal",
            fraction=0.05,
            pad=0.08,
            aspect=45,
            label="Validation ΔJ (new B5 − B2)",
        )

    ax = fig.add_subplot(grid[:, 2])
    metric_order = ["attack_alert_rate", "benign_trigger_rate", "FNR"]
    metric_labels = ["Attack alert", "Benign trigger", "FNR"]
    variants = [("new_B5", "Locked B5", OKABE_ITO["blue"]), ("B2", "B2 volume-only", OKABE_ITO["gray"]), ("old_B5", "Initial B5", OKABE_ITO["orange"])]
    x = np.arange(len(metric_order))
    width = 0.24
    for offset, (variant, label, color) in enumerate(variants):
        means = []
        lows = []
        highs = []
        for metric in metric_order:
            match = next(
                row
                for row in test_rows
                if row["scope"] == "primary_macro"
                and row["variant_or_comparison"] == variant
                and row["metric"] == metric
            )
            means.append(number(match["mean"]))
            lows.append(number(match["ci95_low"]))
            highs.append(number(match["ci95_high"]))
        means_array = np.asarray(means)
        ax.bar(
            x + (offset - 1) * width,
            means_array,
            width,
            color=color,
            edgecolor="white",
            linewidth=0.6,
            label=label,
            yerr=np.vstack((means_array - np.asarray(lows), np.asarray(highs) - means_array)),
            capsize=2.5,
            error_kw={"elinewidth": 0.8},
        )
    ax.set_xticks(x, metric_labels)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Macro rate")
    ax.set_title("Held-out performance")
    ax.legend(frameon=False, loc="upper right")
    style_axes(ax)
    panel_label(ax, "E")
    save_figure(fig, output_dir, "RQ3_threshold_calibration")


def make_rq4(output_dir: Path) -> None:
    aggregate = json.loads(E5_AGGREGATE.read_text(encoding="utf-8"))
    metrics = json.loads(E5_METRICS.read_text(encoding="utf-8"))
    policies = [
        ("B0_OFF", "B0 off", OKABE_ITO["black"]),
        ("B1_RL2_TC", "B1 RL2+TC", OKABE_ITO["blue"]),
        ("B5_LOCKED_TC", "Locked B5", OKABE_ITO["orange"]),
        ("RFC_DROP_NATIVE", "RFC drop-native", OKABE_ITO["purple"]),
    ]
    workloads = ["ATTACK_FIXED_MATCHED", "ATTACK_SWEEP_FLOOD"]
    workload_labels = ["Fixed-IPID matched", "Sweep flood"]
    fig, axes = plt.subplots(1, 2, figsize=(8.2, 4.5), constrained_layout=False)
    fig.subplots_adjust(left=0.08, right=0.98, bottom=0.36, top=0.92, wspace=0.28)

    ax = axes[0]
    x = np.arange(len(workloads))
    width = 0.18
    for offset, (policy, label, color) in enumerate(policies):
        means = []
        lower = []
        upper = []
        for workload in workloads:
            group = aggregate["groups"][f"{policy}__{workload}"]
            means.append(number(group["any_poison_rate"]))
            lower.append(number(group["any_poison_ci95"][0]))
            upper.append(number(group["any_poison_ci95"][1]))
        means_array = np.asarray(means)
        ax.bar(
            x + (offset - 1.5) * width,
            means_array,
            width,
            color=color,
            edgecolor="white",
            linewidth=0.6,
            label=label,
            yerr=np.vstack((means_array - np.asarray(lower), np.asarray(upper) - means_array)),
            capsize=2.2,
            error_kw={"elinewidth": 0.8},
        )
    ax.set_xticks(x, workload_labels)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Any-poison run rate")
    ax.set_title("Resolver-level security outcome")
    ax.legend(
        frameon=False,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.25),
        ncol=2,
        columnspacing=0.8,
    )
    style_axes(ax)
    panel_label(ax, "A")

    ax = axes[1]
    mechanisms = [
        ("trigger_rate", "B5 trigger", OKABE_ITO["black"], "o"),
        ("forged_tail_drop_rate", "Forged-tail drop", OKABE_ITO["blue"], "s"),
        ("tc_injection_rate", "TC injection", OKABE_ITO["orange"], "^"),
        ("tcp_retry_rate", "TCP retry", OKABE_ITO["green"], "D"),
    ]
    cell_rows = {
        workload: [row for row in metrics if row["policy"] == "B5_LOCKED_TC" and row["workload"] == workload]
        for workload in workloads
    }
    width = 0.18
    for offset, (field, label, color, _marker) in enumerate(mechanisms):
        means = []
        lows = []
        highs = []
        for index, workload in enumerate(workloads):
            values = [number(row[field]) for row in cell_rows[workload]]
            mean, low, high = bootstrap_ci(values, seed=20260902 + index * 101 + offset)
            means.append(mean)
            lows.append(low)
            highs.append(high)
        means_array = np.asarray(means)
        ax.bar(
            x + (offset - 1.5) * width,
            means_array,
            width,
            color=color,
            edgecolor="white",
            linewidth=0.6,
            label=label,
            yerr=np.vstack((means_array - np.asarray(lows), np.asarray(highs) - means_array)),
            capsize=2.2,
            error_kw={"elinewidth": 0.8},
        )
    ax.set_xticks(x, ["Fixed-IPID matched\n(detector miss)", "Sweep flood\n(mitigated)"])
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Rate")
    ax.set_title("Locked B5 mechanism chain")
    ax.legend(
        frameon=False,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.25),
        ncol=2,
        columnspacing=0.7,
    )
    style_axes(ax)
    panel_label(ax, "B")
    save_figure(fig, output_dir, "RQ4_runtime_root_cause")


def make_rq3_failure_modes(output_dir: Path) -> None:
    """Plot the registered failure probes for the locked B5 operating point."""

    rows = read_csv(E3_TEST)
    volumes = [24, 60, 120, 200]
    conditions = [
        (
            "attack_fixed_continuous",
            "Fixed-IPID attack",
            OKABE_ITO["vermillion"],
            "-",
            "o",
        ),
        (
            "attack_dup_sweep_continuous",
            "Duplicate-sweep attack",
            OKABE_ITO["blue"],
            "--",
            "s",
        ),
        (
            "attack_random_continuous",
            "Random-IPID negative control",
            OKABE_ITO["gray"],
            ":",
            "^",
        ),
    ]

    def select(condition: str, variant: str, metric: str) -> list[dict[str, str]]:
        selected = [
            row
            for row in rows
            if row["scope"] in {"failure_probes", "negative_control"}
            and row["attack_condition"] == condition
            and row["variant_or_comparison"] == variant
            and row["metric"] == metric
        ]
        return sorted(selected, key=lambda row: int(row["level"]))

    delta_variant = "Delta_J_new_B5_minus_B2"
    b5_variant = "new_B5"
    delta_rows = {
        condition: select(condition, delta_variant, "Delta_J") for condition, *_ in conditions
    }
    attack_rows = {
        condition: select(condition, b5_variant, "attack_alert_rate")
        for condition, *_ in conditions
    }
    benign_rows = {
        condition: select(condition, b5_variant, "benign_trigger_rate")
        for condition, *_ in conditions
    }

    for condition, *_ in conditions:
        if [int(row["level"]) for row in delta_rows[condition]] != volumes:
            raise ValueError(f"Missing ΔJ failure-probe levels for {condition}")
        if [int(row["level"]) for row in attack_rows[condition]] != volumes:
            raise ValueError(f"Missing attack-alert failure-probe levels for {condition}")
        if [int(row["level"]) for row in benign_rows[condition]] != volumes:
            raise ValueError(f"Missing benign-trigger failure-probe levels for {condition}")

    x = np.asarray(volumes, dtype=float)
    fig, axes = plt.subplots(1, 2, figsize=(8.3, 4.8), constrained_layout=False)
    fig.subplots_adjust(left=0.08, right=0.98, bottom=0.40, top=0.92, wspace=0.30)

    ax = axes[0]
    for condition, label, color, linestyle, marker in conditions:
        selected = delta_rows[condition]
        means = np.asarray([number(row["mean"]) for row in selected])
        low = np.asarray([number(row["ci95_low"]) for row in selected])
        high = np.asarray([number(row["ci95_high"]) for row in selected])
        ax.errorbar(
            x,
            means,
            yerr=np.vstack((means - low, high - means)),
            color=color,
            linestyle=linestyle,
            marker=marker,
            markerfacecolor="white",
            markeredgewidth=0.85,
            capsize=2.5,
            label=label,
        )
    ax.axhline(0, color=OKABE_ITO["black"], linewidth=0.85)
    ax.set_xticks(volumes)
    ax.set_ylim(-1.08, 0.08)
    ax.set_yticks([-1.0, -0.75, -0.5, -0.25, 0.0])
    ax.set_xlabel("Target volume (fragments per window)")
    ax.set_ylabel("ΔJ (locked B5 − B2)")
    ax.set_title("Separation under registered probes")
    ax.legend(
        frameon=False,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.25),
        ncol=1,
        handlelength=2.2,
    )
    style_axes(ax)
    panel_label(ax, "A")

    ax = axes[1]
    metric_styles = [
        (attack_rows, "Attack alert", "-", "o"),
        (benign_rows, "Benign trigger", "--", "s"),
    ]
    for condition, condition_label, color, _condition_linestyle, _condition_marker in conditions:
        for metric_data, metric_label, metric_linestyle, metric_marker in metric_styles:
            selected = metric_data[condition]
            means = np.asarray([number(row["mean"]) for row in selected])
            low = np.asarray([number(row["ci95_low"]) for row in selected])
            high = np.asarray([number(row["ci95_high"]) for row in selected])
            ax.errorbar(
                x,
                means,
                yerr=np.vstack((means - low, high - means)),
                color=color,
                linestyle=metric_linestyle,
                marker=metric_marker,
                markerfacecolor="white",
                markeredgewidth=0.75,
                capsize=2.2,
                label=f"{metric_label} — {condition_label}",
            )
    ax.set_xticks(volumes)
    ax.set_ylim(-0.08, 1.08)
    ax.set_yticks([0.0, 0.25, 0.50, 0.75, 1.0])
    ax.set_xlabel("Target volume (fragments per window)")
    ax.set_ylabel("Rate")
    ax.set_title("Alert coverage versus benign triggering")
    ax.legend(
        frameon=False,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.25),
        ncol=2,
        columnspacing=0.8,
        handlelength=2.0,
    )
    style_axes(ax)
    panel_label(ax, "B")
    save_figure(fig, output_dir, "RQ3_failure_modes")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output directory for English PNG/PDF/SVG figures.",
    )
    args = parser.parse_args()
    configure_style()
    make_rq1(args.output)
    make_rq2(args.output)
    make_rq3(args.output)
    make_rq3_failure_modes(args.output)
    make_rq4(args.output)
    print(f"Generated five RQ figures in {args.output.resolve()}")


if __name__ == "__main__":
    main()
