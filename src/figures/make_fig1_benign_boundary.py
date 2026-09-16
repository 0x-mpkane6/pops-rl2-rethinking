"""Create the paper-ready E1 benign-boundary figure from the frozen E1 CSV."""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
E1_LEVELS = ROOT / "E1" / "runs" / "E1_confirmatory_20260810_seed20260810_raw_v2" / "e1_levels.csv"
OUTPUT = Path(__file__).with_name("fig1_benign_boundary.png")


def read_combined_levels() -> dict[str, list[dict[str, float]]]:
    records: dict[str, list[dict[str, float]]] = defaultdict(list)
    with E1_LEVELS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["variant"] != "combined":
                continue
            records[row["behavior"]].append(
                {
                    "rate": float(row["actual_fragments_per_second_mean"]),
                    "mean": float(row["fpr_run_mean"]),
                    "lo": float(row["fpr_run_ci_lo"]),
                    "hi": float(row["fpr_run_ci_hi"]),
                }
            )
    for values in records.values():
        values.sort(key=lambda value: value["rate"])
    return records


def main() -> None:
    series = read_combined_levels()
    style = {
        "random2048": ("Random IPID (2,048 values)", "#1f77b4", "o"),
        "sequential": ("Sequential IPID", "#ff7f0e", "s"),
        "smallpool16": ("Small IPID pool (16 values)", "#009e73", "^")
    }
    plt.rcParams.update({"font.size": 10, "font.family": "DejaVu Sans"})
    figure, ax = plt.subplots(figsize=(6.8, 3.4), constrained_layout=True)
    for behavior, values in series.items():
        label, color, marker = style[behavior]
        x_values = [value["rate"] for value in values]
        means = [value["mean"] for value in values]
        lows = [value["lo"] for value in values]
        highs = [value["hi"] for value in values]
        ax.plot(x_values, means, marker=marker, linewidth=2, color=color, label=label)
        ax.fill_between(x_values, lows, highs, color=color, alpha=0.16)

    # E1 measures actual rate. The nominal N=24 threshold maps to about 11.5 fragments/s.
    ax.axvline(11.5, linestyle="--", linewidth=1.2, color="#444444", label=r"Nominal $N=24$ ($\approx$11.5 fragments/s)")
    ax.set_xlim(0, 160)
    ax.set_ylim(-0.03, 1.05)
    ax.set_xlabel("Actual benign fragment rate (fragments/s)")
    ax.set_ylabel("Benign trigger rate (run-level mean)")
    ax.grid(alpha=0.25)
    ax.legend(frameon=False, fontsize=8, loc="center right")
    figure.savefig(OUTPUT, dpi=300, bbox_inches="tight")
    print(OUTPUT)


if __name__ == "__main__":
    main()
