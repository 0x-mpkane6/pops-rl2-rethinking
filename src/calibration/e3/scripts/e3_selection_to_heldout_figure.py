#!/usr/bin/env python3
"""Render the paper-ready E3 validation-to-held-out figure from frozen JSON.

This script reads only frozen threshold-selection and held-out artifacts.
It does not reopen decision data or recompute thresholds, metrics, or CIs.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


E3_ROOT = Path(__file__).resolve().parent.parent
GRID_PATH = E3_ROOT / "e3_validation_grid.json"
LOCK_PATH = E3_ROOT / "e3_locked_threshold.json"
TEST_PATH = E3_ROOT / "e3_test_results.json"
OUTPUT_PATH = E3_ROOT / "figures" / "validation_to_heldout.png"

# Old operating point is used only to locate its marker in the frozen grid.
OLD_B5 = (24, 4.0, 0.70)

INK = "#1a202c"
GRID = "#d7dde6"
POINT = "#9aa3af"
GREEN = "#1d815a"
BLUE = "#326dc2"
PURPLE = "#854fad"
ORANGE = "#db7e22"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def candidate_key(candidate: dict) -> tuple[int, float, float]:
    return (
        int(candidate["min_samples"]),
        float(candidate["entropy_threshold"]),
        float(candidate["unique_ratio_threshold"]),
    )


def main() -> None:
    grid = load(GRID_PATH)
    lock = load(LOCK_PATH)
    test = load(TEST_PATH)

    if grid["status"] != "validation_sweep_complete_no_selection":
        raise ValueError("Expected frozen validation grid")

    if (
        lock["status"] != "locked-before-test"
        or test["status"] != "held_out_evaluation_complete_once"
    ):
        raise ValueError("Expected locked and one-time held-out artifacts")

    if test["held_out_evaluation"]["candidate"] != lock["selected_candidate"]:
        raise ValueError("Held-out candidate differs from locked candidate")

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8.3,
            "axes.labelcolor": INK,
            "axes.edgecolor": INK,
            "xtick.color": INK,
            "ytick.color": INK,
        }
    )

    fig, (ax_a, ax_b) = plt.subplots(
        1,
        2,
        figsize=(10.6, 3.55),
        gridspec_kw={"width_ratios": [1.08, 0.92]},
    )

    # ------------------------------------------------------------------
    # (a) Validation operating points
    # ------------------------------------------------------------------
    groups: dict[tuple[float, float], list[dict]] = defaultdict(list)

    for entry in grid["candidates"]:
        macro = entry["primary"]["macro"]
        point = (
            round(macro["benign_trigger_rate"], 12),
            round(macro["attack_alert_rate"], 12),
        )
        groups[point].append(entry)

    points = list(groups.keys())

    # Pareto frontier: lower benign-trigger and higher attack-alert are better.
    frontier = []
    for x_value, y_value in points:
        dominated = any(
            other_x <= x_value
            and other_y >= y_value
            and (other_x < x_value or other_y > y_value)
            for other_x, other_y in points
        )
        if not dominated:
            frontier.append((x_value, y_value))

    frontier.sort()

    # No-discrimination reference.
    ax_a.plot(
        [0.5, 1.02],
        [0.5, 1.02],
        linestyle="--",
        color="#777777",
        linewidth=0.9,
        zorder=0,
    )

    # Pareto frontier.
    if len(frontier) > 1:
        ax_a.plot(
            *zip(*frontier),
            color=ORANGE,
            linewidth=1.7,
            label="Pareto frontier",
            zorder=1,
        )

    # All operating points.
    # Bubble size = number of threshold candidates sharing that point.
    for (x_value, y_value), entries in groups.items():
        count = len(entries)
        size = 22 + 15 * count

        ax_a.scatter(
            x_value,
            y_value,
            s=size,
            facecolor=POINT,
            edgecolor="white",
            linewidth=0.7,
            alpha=0.82,
            zorder=2,
        )

        # Show multiplicity only when several candidates collapse to one point.
        if count > 1:
            ax_a.text(
                x_value,
                y_value,
                str(count),
                ha="center",
                va="center",
                fontsize=6.2,
                color="white",
                weight="bold",
                zorder=3,
            )

    locked = candidate_key(lock["selected_candidate"])

    old_location = None
    locked_location = None

    for entry in grid["candidates"]:
        key = candidate_key(entry["candidate"])
        macro = entry["primary"]["macro"]
        xy = (
            macro["benign_trigger_rate"],
            macro["attack_alert_rate"],
        )

        if key == OLD_B5:
            old_location = xy

        if key == locked:
            locked_location = xy

    if old_location is None:
        raise ValueError("Old B5 operating point not found in validation grid")

    if locked_location is None:
        raise ValueError("Locked candidate not found in validation grid")

    # Old B5 reference.
    ax_a.scatter(
        *old_location,
        marker="s",
        s=64,
        facecolor="none",
        edgecolor=PURPLE,
        linewidth=1.8,
        zorder=5,
        label="Old B5",
    )

    ax_a.annotate(
        "old B5\n24/4.0/0.70",
        old_location,
        xytext=(-54, 13),
        textcoords="offset points",
        color=PURPLE,
        fontsize=7.0,
        weight="bold",
    )

    # Validation-selected candidate.
    ax_a.scatter(
        *locked_location,
        marker="o",
        s=68,
        facecolor="white",
        edgecolor=INK,
        linewidth=1.8,
        zorder=6,
        label="Locked candidate",
    )

    ax_a.annotate(
        "locked\n8/6.0/0.90",
        locked_location,
        xytext=(9, -29),
        textcoords="offset points",
        color=INK,
        fontsize=7.0,
        weight="bold",
    )

    ax_a.set_xlim(0.5, 1.02)
    ax_a.set_ylim(0.5, 1.02)

    ax_a.set_xlabel("Macro benign-trigger rate")
    ax_a.set_ylabel("Macro attack-alert rate")
    ax_a.set_title(
        "(a) Validation-based threshold selection",
        loc="left",
        fontsize=9.3,
        fontweight="bold",
        color=INK,
    )

    ax_a.grid(color=GRID, linewidth=0.65)
    ax_a.legend(
        frameon=False,
        fontsize=7.0,
        loc="upper left",
        handletextpad=0.5,
    )

    # ------------------------------------------------------------------
    # (b) One-time held-out evaluation
    # ------------------------------------------------------------------
    macro = test["primary"]["macro"]

    rows = [
        ("new B5", macro["variants"]["new_B5"]["J"], GREEN),
        ("B2", macro["variants"]["B2"]["J"], BLUE),
        ("old B5", macro["variants"]["old_B5"]["J"], PURPLE),
        (
            r"new B5 $-$ B2",
            macro["comparisons"]["Delta_J_new_B5_minus_B2"],
            BLUE,
        ),
        (
            r"new B5 $-$ old B5",
            macro["comparisons"]["Delta_J_new_B5_minus_old_B5"],
            PURPLE,
        ),
    ]

    y_positions = [4.3, 3.3, 2.3, 0.8, -0.2]

    ax_b.axvline(
        0,
        color="#555555",
        linewidth=1.0,
        zorder=0,
    )

    # Visually separate absolute J from paired Delta J.
    ax_b.axhline(
        1.55,
        color=GRID,
        linewidth=0.9,
    )

    for (label, value, color), y_value in zip(rows, y_positions):
        mean = value["mean"]
        lo, hi = value["ci95"]

        ax_b.errorbar(
            mean,
            y_value,
            xerr=[[mean - lo], [hi - mean]],
            fmt="o",
            color=color,
            markersize=5.7,
            capsize=3,
            linewidth=1.7,
            zorder=3,
        )

    ax_b.set_yticks(
        y_positions,
        [
            r"$J$: new B5",
            r"$J$: B2",
            r"$J$: old B5",
            r"$\Delta J$: new $-$ B2",
            r"$\Delta J$: new $-$ old B5",
        ],
    )

    # Only the scale is shown here; exact values remain in text/table.
    ax_b.set_xlim(-0.003, 0.017)
    ax_b.set_ylim(-0.75, 4.95)

    ax_b.set_xlabel(r"Held-out $J$ / $\Delta J$ (95\% CI)")
    ax_b.set_title(
        "(b) One-time held-out evaluation",
        loc="left",
        fontsize=9.3,
        fontweight="bold",
        color=INK,
    )

    ax_b.grid(
        axis="x",
        color=GRID,
        linewidth=0.65,
    )

    ax_b.tick_params(
        axis="y",
        length=0,
        pad=5,
    )

    ax_b.text(
        -0.0027,
        4.72,
        "Detector separation",
        fontsize=7.0,
        color="#555555",
        style="italic",
    )

    ax_b.text(
        -0.0027,
        1.23,
        "Paired effect",
        fontsize=7.0,
        color="#555555",
        style="italic",
    )

    # Clean publication-style frame.
    for axis in (ax_a, ax_b):
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)

    fig.subplots_adjust(
        left=0.075,
        right=0.985,
        bottom=0.18,
        top=0.90,
        wspace=0.31,
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    fig.savefig(
        OUTPUT_PATH,
        dpi=350,
        bbox_inches="tight",
    )

    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()