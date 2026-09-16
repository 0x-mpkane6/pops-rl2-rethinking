"""Render the paper-ready E1 benign-boundary figure from frozen results.

The figure intentionally shows only the registered initial B5 operating point;
the threshold selected later in E3 is not plotted in the RQ1 result.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


HERE = Path(__file__).resolve().parent
DEFAULT_RESULTS = (
    HERE
    / "runs"
    / "E1_confirmatory_20260810_seed20260810_raw_v2"
    / "e1_results.json"
)

# Keep visual properties tied to the E1 behavior identifiers in the artifact.
STYLE_MAP = {
    "random2048": {"label": "Random (2,048)", "color": "#0072B2", "marker": "o"},
    "sequential": {"label": "Sequential", "color": "#D55E00", "marker": "s"},
    "smallpool16": {"label": "Pool of 16", "color": "#009E73", "marker": "^"},
}


def load_series(results_path: Path) -> tuple[dict, dict[str, list[dict]]]:
    """Extract combined-rule trigger-rate summaries by behavior and target level."""
    with results_path.open(encoding="utf-8") as handle:
        results = json.load(handle)

    series = {behavior: [] for behavior in STYLE_MAP}
    for entry in results["levels"]:
        behavior = entry["behavior"]
        if behavior not in STYLE_MAP:
            continue
        combined = entry["variants"]["combined"]
        lower, upper = combined.get(
            "fpr_cluster_bootstrap_ci95", combined["fpr_run_ci95_t"]
        )
        series[behavior].append(
            {
                "level": entry["level"],
                "mean": combined["fpr_run_mean"],
                "lower": max(0.0, lower),
                "upper": min(1.0, upper),
            }
        )

    for values in series.values():
        values.sort(key=lambda row: row["level"])
    return results["meta"]["operating_point"], series


def render(results_path: Path, output: Path) -> None:
    operating_point, series = load_series(results_path)
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8,
            "axes.labelsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 8,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )

    # Match the compact two-row legend layout of the original paper figure.
    figure, axis = plt.subplots(figsize=(5.4, 3.6))
    results_levels = sorted({row["level"] for rows in series.values() for row in rows})
    level_position = {level: position for position, level in enumerate(results_levels)}
    for behavior, style in STYLE_MAP.items():
        rows = series[behavior]
        levels = [level_position[row["level"]] for row in rows]
        means = [row["mean"] for row in rows]
        lower = [row["lower"] for row in rows]
        upper = [row["upper"] for row in rows]
        axis.plot(
            levels,
            means,
            color=style["color"],
            marker=style["marker"],
            linestyle=":",
            linewidth=1.4,
            markersize=4.5,
            markerfacecolor="white",
            markeredgewidth=1.1,
            label=style["label"],
            zorder=3,
        )
        axis.fill_between(levels, lower, upper, color=style["color"], alpha=0.12, zorder=2)

    axis.set_xlim(-0.15, len(results_levels) - 0.55)
    axis.set_ylim(-0.03, 1.05)
    axis.set_xticks(range(len(results_levels)))
    axis.set_xticklabels([str(level) for level in results_levels])
    axis.set_yticks([0.0, 0.25, 0.50, 0.75, 1.0])
    axis.set_xlabel("Target fragments per 2-s window")
    axis.set_ylabel("Benign trigger rate")
    axis.grid(axis="y", color="#D9DEE3", linewidth=0.6)
    axis.spines[["top", "right"]].set_visible(False)

    rule_label = (
        "Initial B5 "
        f"({operating_point['min_samples']}, "
        f"{operating_point['entropy_threshold']:.1f}, "
        f"{operating_point['unique_ratio_threshold']:.2f})"
    )
    behavior_handles, _ = axis.get_legend_handles_labels()
    rule_handle = Line2D([], [], color="#666666", linestyle=":", linewidth=1.4, label=rule_label)
    # Matplotlib fills multi-column legends down columns. This ordering keeps
    # the three IPID behaviors on the first visual row and B5 on the second.
    legend_handles = [behavior_handles[0], rule_handle, behavior_handles[1], behavior_handles[2]]
    axis.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.22),
        ncol=3,
        frameon=False,
        columnspacing=1.2,
        handletextpad=0.5,
    )
    figure.subplots_adjust(left=0.14, right=0.99, top=0.98, bottom=0.28)

    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output.with_suffix(".png"), dpi=300)
    figure.savefig(output.with_suffix(".pdf"))
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser(description="Render the initial-B5 E1 boundary figure.")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--out", type=Path, default=HERE / "figures" / "RQ1_benign_boundary_initial_only")
    args = parser.parse_args()
    render(args.results.resolve(), args.out.resolve())
    print(f"Wrote {args.out.with_suffix('.png')}")
    print(f"Wrote {args.out.with_suffix('.pdf')}")


if __name__ == "__main__":
    main()
