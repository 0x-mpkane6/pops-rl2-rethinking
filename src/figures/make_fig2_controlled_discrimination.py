"""Create the compact E2 figure used by the conference-paper layout.

Panel (a) is derived from the frozen E2 test summary.  Panel (b) uses the
continuous-sweep PR-AUC values reported from the same held-out E2 analysis.
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
E2_SUMMARY = ROOT / "E2" / "runs" / "E2_confirmatory_20260814_complete_b0_ablation" / "e2_summary.csv"
OUTPUT = Path(__file__).with_name("fig2_controlled_discrimination.png")


def read_primary_delta_j() -> dict[str, list[dict[str, float]]]:
    """Read only the two primary, volume-matched sweep conditions."""
    rows: dict[str, list[dict[str, float]]] = {"continuous": [], "bursty": []}
    with E2_SUMMARY.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if (
                row["scope"] == "test"
                and row["metric"] == "delta_j_combined_minus_volume"
                and row["variant_or_feature"] == "combined-minus-volume"
                and row["attack_condition"]
                in {"attack_sweep_continuous", "attack_sweep_bursty"}
            ):
                rows[row["profile"]].append(
                    {
                        "level": float(row["level"]),
                        "mean": float(row["mean"]),
                        "lo": float(row["ci95_lo"]),
                        "hi": float(row["ci95_hi"]),
                    }
                )
    for values in rows.values():
        values.sort(key=lambda value: value["level"])
    return rows


def main() -> None:
    delta_j = read_primary_delta_j()
    levels = [24, 60, 120, 200]
    entropy_pr_auc = [0.514, 0.550, 0.618, 0.726]
    unique_pr_auc = [0.530, 0.666, 0.888, 0.992]

    plt.rcParams.update({"font.size": 10, "font.family": "DejaVu Sans"})
    figure, axes = plt.subplots(1, 2, figsize=(10.4, 3.5), constrained_layout=True)

    ax = axes[0]
    ax.axhspan(-0.05, 0.05, color="#e8e8e8", zorder=0, label="registered equivalence band")
    ax.axhline(0, color="#333333", linewidth=1)
    styles = {
        "continuous": ("Continuous sweep", "#1f77b4", "o"),
        "bursty": ("Bursty sweep", "#ff7f0e", "s"),
    }
    for profile, values in delta_j.items():
        label, color, marker = styles[profile]
        x_values = [entry["level"] for entry in values]
        means = [entry["mean"] for entry in values]
        errors = [[entry["mean"] - entry["lo"] for entry in values], [entry["hi"] - entry["mean"] for entry in values]]
        ax.errorbar(x_values, means, yerr=errors, marker=marker, color=color, linewidth=2, capsize=3, label=label)
    ax.set_title("(a) Old B5 versus volume-only B2")
    ax.set_xlabel("Matched volume (samples/window)")
    ax.set_ylabel(r"$\Delta J = J_{\mathrm{old\ B5}} - J_{\mathrm{B2}}$")
    ax.set_xticks(levels)
    ax.set_ylim(-0.09, 0.09)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False, fontsize=8, loc="lower right")

    ax = axes[1]
    ax.plot(levels, entropy_pr_auc, marker="o", linewidth=2, color="#ff7f0e", label="Entropy")
    ax.plot(levels, unique_pr_auc, marker="^", linewidth=2, color="#1f77b4", label="Unique-IPID ratio")
    ax.axhline(0.5, color="#555555", linestyle="--", linewidth=1, label="no-discrimination reference")
    ax.set_title("(b) Feature-level discrimination, continuous sweep")
    ax.set_xlabel("Matched volume (samples/window)")
    ax.set_ylabel("Held-out PR-AUC")
    ax.set_xticks(levels)
    ax.set_ylim(0.45, 1.03)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    figure.savefig(OUTPUT, dpi=300, bbox_inches="tight")
    print(OUTPUT)


if __name__ == "__main__":
    main()
