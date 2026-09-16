"""Render data-driven figures from one E2 confirmatory artifact directory."""
from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch


LABELS = {
    "attack_sweep_continuous": "Sweep / continuous",
    "attack_sweep_bursty": "Sweep / bursty",
    "attack_random_continuous": "Random-IPID control",
    "attack_fixed_continuous": "Fixed-IPID probe",
    "attack_dup_sweep_continuous": "Duplicate-sweep probe",
}
FEATURE_LABELS = {
    "entropy": "Entropy Shannon của IPID (bit)",
    "unique_ratio": "Tỷ lệ IPID khác nhau",
}


def error(values: dict) -> tuple[float, float]:
    mean = float(values["mean"])
    lo, hi = (float(value) for value in values["ci95"])
    return mean - lo, hi - mean


def cells_by_attack(results: dict) -> dict[str, list[dict]]:
    output: dict[str, list[dict]] = {}
    for cell in results["analysis"]["test_cells"]:
        output.setdefault(cell["attack_condition"], []).append(cell)
    for rows in output.values():
        rows.sort(key=lambda row: int(row["level"]))
    return output


def figure_net_separation(grouped: dict[str, list[dict]], out: Path) -> None:
    attacks = [attack for attack in ("attack_sweep_continuous", "attack_sweep_bursty")
               if attack in grouped]
    figure, axes = plt.subplots(1, max(1, len(attacks)), figsize=(6.4 * max(1, len(attacks)), 4.4),
                                sharey=True)
    if not isinstance(axes, np.ndarray):
        axes = np.asarray([axes])
    for axis, attack in zip(axes, attacks):
        rows = grouped[attack]
        levels = [int(row["level"]) for row in rows]
        plotted_means = []
        for variant, color, marker, label in (
            ("volume", "#333333", "o", "B2: chỉ đếm số fragment"),
            ("combined", "#1f77b4", "s", "B5: ba điều kiện"),
        ):
            means = [float(row["variants"][variant]["youden_j"]["mean"]) for row in rows]
            plotted_means.extend(means)
            errors = np.asarray([error(row["variants"][variant]["youden_j"]) for row in rows]).T
            axis.errorbar(levels, means, yerr=errors, color=color, marker=marker, capsize=3,
                          linewidth=1.8, label=label)
        axis.axhline(0, color="#888888", linewidth=0.8)
        # Matplotlib otherwise scales exact zeros around floating-point noise (for
        # example 1e-17), which makes an equality result needlessly hard to read.
        if plotted_means and max(abs(value) for value in plotted_means) < 1e-12:
            axis.set_ylim(-0.06, 0.06)
        axis.set_title(LABELS[attack])
        axis.set_xlabel("Mức tải mục tiêu (samples/window)")
        axis.set_xticks(levels)
        axis.grid(alpha=0.22)
    axes[0].set_ylabel("Chênh lệch alert: attack − benign (J)")
    axes[0].legend(loc="best", frameon=True)
    figure.suptitle("E2: B5 có thêm ích lợi so với B2 ở cùng timestamp trace không?", y=1.02)
    figure.text(0.5, -0.02,
                "Điểm và thanh lỗi là mean và 95% bootstrap CI theo pair (held-out test).\n"
                "Đây là controlled synthetic emulation, không phải kết quả poisoning/ASR.",
                ha="center", va="top", fontsize=8)
    figure.tight_layout()
    figure.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(figure)


def figure_delta(grouped: dict[str, list[dict]], out: Path) -> None:
    attacks = [attack for attack in LABELS if attack in grouped]
    colors = plt.cm.tab10(np.arange(len(attacks)))
    figure, axis = plt.subplots(figsize=(8.8, 4.8))
    offsets = np.linspace(-0.18, 0.18, len(attacks)) if attacks else []
    for offset, color, attack in zip(offsets, colors, attacks):
        rows = grouped[attack]
        levels = np.asarray([int(row["level"]) for row in rows], dtype=float)
        metrics = [row["delta_j_combined_minus_volume"] for row in rows]
        means = np.asarray([float(metric["mean"]) for metric in metrics])
        errors = np.asarray([error(metric) for metric in metrics]).T
        axis.errorbar(levels + offset * 20.0, means, yerr=errors, marker="o", capsize=3,
                      linewidth=1.4, color=color, label=LABELS[attack])
    axis.axhline(0, color="#222222", linewidth=1.0)
    axis.axhspan(-0.05, 0.05, color="#e8e8e8", alpha=0.7,
                label="Vùng ±0,05 đã đăng ký trước")
    axis.set_xlabel("Mức tải mục tiêu (samples/window)")
    axis.set_ylabel("ΔJ = J(B5) − J(B2)")
    axis.set_xticks([24, 60, 120, 200])
    axis.grid(alpha=0.22)
    axis.legend(loc="best", fontsize=8)
    axis.set_title("E2: hiệu ứng thêm của entropy + unique ratio so với B2")
    figure.tight_layout()
    figure.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(figure)


def figure_validation_locked_tpr_fpr(grouped: dict[str, list[dict]], out: Path) -> None:
    """Plot held-out FPR after validation locks each scalar score's TPR target."""
    attacks = [attack for attack in ("attack_sweep_continuous", "attack_sweep_bursty")
               if attack in grouped]
    figure, axes = plt.subplots(1, max(1, len(attacks)), figsize=(6.4 * max(1, len(attacks)), 4.5),
                                sharey=True)
    if not isinstance(axes, np.ndarray):
        axes = np.asarray([axes])
    feature_specs = (
        ("volume", "#333333", "o", "Volume"),
        ("entropy", "#ff7f0e", "s", "Entropy"),
        ("unique_ratio", "#1f77b4", "^", "Unique ratio"),
    )
    for axis, attack in zip(axes, attacks):
        rows = grouped[attack]
        levels = [int(row["level"]) for row in rows]
        for feature, color, marker, label in feature_specs:
            metrics = [row["frozen_threshold_diagnostics"][feature]["test_benign_trigger_rate"]
                       for row in rows]
            means = [float(metric["mean"]) for metric in metrics]
            errors = np.asarray([error(metric) for metric in metrics]).T
            axis.errorbar(levels, means, yerr=errors, color=color, marker=marker, capsize=3,
                          linewidth=1.8, label=label)
        axis.set_title(LABELS[attack])
        axis.set_xlabel("Mức tải mục tiêu (samples/window)")
        axis.set_xticks(levels)
        axis.set_ylim(-0.04, 1.04)
        axis.grid(alpha=0.22)
    axes[0].set_ylabel("FPR test tại ngưỡng khóa từ validation")
    axes[0].legend(loc="best", frameon=True)
    figure.suptitle("E2: FPR của score đơn biến tại TPR validation mục tiêu ≥ 0,95", y=1.02)
    figure.text(
        0.5,
        -0.02,
        "Ngưỡng được chọn riêng trên validation cho từng condition/level/score; điểm và thanh lỗi là "
        "mean và 95% bootstrap CI theo pair trên held-out test.",
        ha="center",
        va="top",
        fontsize=8,
    )
    figure.tight_layout()
    figure.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(figure)


def read_feature_distributions(artifact_dir: Path) -> dict[tuple[str, str, int, str], list[float]]:
    """Load held-out decision-level feature values for the two registered E2 sweeps."""
    selected = {
        "continuous": ("benign_continuous", "attack_sweep_continuous"),
        "bursty": ("benign_bursty", "attack_sweep_bursty"),
    }
    values: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)
    with gzip.open(artifact_dir / "e2_decisions.csv.gz", "rt", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            profile = row["profile"]
            condition = row["condition"]
            if row["split"] != "test" or condition not in selected.get(profile, ()):
                continue
            level = int(row["level"])
            for feature in FEATURE_LABELS:
                values[(profile, condition, level, feature)].append(float(row[feature]))
    return values


def figure_feature_distributions(artifact_dir: Path, out: Path) -> None:
    """Compare entropy and unique-ratio distributions at each matched volume."""
    values = read_feature_distributions(artifact_dir)
    profiles = (
        ("continuous", "Liên tục", "benign_continuous", "attack_sweep_continuous"),
        ("bursty", "Theo đợt", "benign_bursty", "attack_sweep_bursty"),
    )
    levels = (24, 60, 120, 200)
    figure, axes = plt.subplots(2, 2, figsize=(11.2, 7.2), sharex="col")
    colors = ("#b8b8b8", "#1f77b4")
    for row_idx, feature in enumerate(("entropy", "unique_ratio")):
        for col_idx, (profile, profile_label, benign, attack) in enumerate(profiles):
            axis = axes[row_idx, col_idx]
            datasets: list[list[float]] = []
            positions: list[float] = []
            color_cycle: list[str] = []
            for index, level in enumerate(levels):
                for offset, condition, color in ((-0.18, benign, colors[0]), (0.18, attack, colors[1])):
                    datasets.append(values[(profile, condition, level, feature)])
                    positions.append(index + offset)
                    color_cycle.append(color)
            boxes = axis.boxplot(
                datasets,
                positions=positions,
                widths=0.28,
                patch_artist=True,
                showfliers=False,
                medianprops={"color": "#222222", "linewidth": 1.1},
            )
            for box, color in zip(boxes["boxes"], color_cycle):
                box.set_facecolor(color)
                box.set_alpha(0.85)
            axis.set_xticks(range(len(levels)), levels)
            axis.set_title(f"{profile_label} — {FEATURE_LABELS[feature]}")
            axis.grid(axis="y", alpha=0.22)
            if col_idx == 0:
                axis.set_ylabel(FEATURE_LABELS[feature])
            if row_idx == 1:
                axis.set_xlabel("Mức tải mục tiêu (samples/window)")
    figure.legend(
        handles=[Patch(facecolor=colors[0], label="Benign"), Patch(facecolor=colors[1], label="Sweep-IPID")],
        loc="upper center",
        bbox_to_anchor=(0.5, 0.965),
        ncol=2,
        frameon=True,
    )
    figure.suptitle("E2: phân phối entropy và unique ratio trên test volume-matched", y=0.995)
    figure.tight_layout(rect=(0, 0, 1, 0.89))
    figure.savefig(out, dpi=180, bbox_inches="tight")
    plt.close(figure)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot confirmatory E2 results")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    root = args.artifact_dir.resolve()
    result_path = root / "e2_results.json"
    results = json.loads(result_path.read_text(encoding="utf-8"))
    if results.get("schema_version") not in (2, 3):
        raise ValueError("expected E2 confirmatory schema_version 2 or 3")
    out = (args.out or root / "figures").resolve()
    out.mkdir(parents=True, exist_ok=True)
    grouped = cells_by_attack(results)
    figure_net_separation(grouped, out / "Figure_1_net_separation.png")
    figure_delta(grouped, out / "Figure_2_delta_B5_minus_B2.png")
    figure_feature_distributions(root, out / "Figure_3_feature_distributions.png")
    figure_validation_locked_tpr_fpr(grouped, out / "Figure_4_validation_locked_tpr_fpr.png")
    print(f"[+] wrote figures to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
