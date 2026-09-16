#!/usr/bin/env python3
"""Render E3 publication figures with matplotlib from frozen E3 artifacts."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parent.parent
GRID_PATH = ROOT / "e3_validation_grid.json"
LOCK_PATH = ROOT / "e3_locked_threshold.json"
TEST_PATH = ROOT / "e3_test_results.json"
OUT = ROOT / "figures"

INK, GRID = "#222222", "#d7dde6"
GREEN, BLUE, PURPLE, ORANGE = "#1b7f5a", "#1f77b4", "#8a4fb4", "#ff7f0e"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-b5", metavar=("N", "H", "U"), nargs=3, type=float, required=True)
    return parser.parse_args()


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def key(candidate: dict) -> tuple[int, float, float]:
    return int(candidate["min_samples"]), float(candidate["entropy_threshold"]), float(candidate["unique_ratio_threshold"])


def check(grid: dict, lock: dict, test: dict) -> None:
    if grid["status"] != "validation_sweep_complete_no_selection":
        raise ValueError("Validation grid is not frozen")
    if lock["status"] != "locked-before-test" or test["status"] != "held_out_evaluation_complete_once":
        raise ValueError("Lock or held-out artifact has an unexpected status")
    if test["held_out_evaluation"]["candidate"] != lock["selected_candidate"]:
        raise ValueError("Held-out candidate does not equal locked candidate")


def style() -> None:
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.titleweight": "bold"})


def grouped_points(grid: dict) -> dict[tuple[float, float], list[dict]]:
    groups: dict[tuple[float, float], list[dict]] = defaultdict(list)
    for entry in grid["candidates"]:
        macro = entry["primary"]["macro"]
        groups[(round(macro["benign_trigger_rate"], 12), round(macro["attack_alert_rate"], 12))].append(entry)
    return groups


def draw_pareto(axis: plt.Axes, grid: dict, lock: dict, old: tuple[int, float, float], panel: str | None = None) -> None:
    groups = grouped_points(grid)
    points = list(groups)
    frontier = []
    for x, y in points:
        if not any(ox <= x and oy >= y and (ox < x or oy > y) for ox, oy in points):
            frontier.append((x, y))
    frontier.sort()
    if len(frontier) > 1:
        axis.plot(*zip(*frontier), color=ORANGE, linewidth=2, label="Pareto frontier", zorder=1)
    axis.plot([0.5, 1.02], [0.5, 1.02], "--", color="#808080", linewidth=0.9, zorder=0)
    deltas = [entry["primary"]["macro"]["delta_J_new_vs_B2"] for entry in grid["candidates"]]
    norm = plt.Normalize(min(deltas), max(deltas))
    cmap = plt.get_cmap("YlOrRd")
    for (x, y), entries in groups.items():
        entry = max(entries, key=lambda item: item["primary"]["macro"]["delta_J_new_vs_B2"])
        axis.scatter(x, y, s=22 + 15 * len(entries), color=cmap(norm(entry["primary"]["macro"]["delta_J_new_vs_B2"])),
                     edgecolor="white", linewidth=0.7, zorder=2)
    locked = key(lock["selected_candidate"])
    for entry in grid["candidates"]:
        candidate, macro = key(entry["candidate"]), entry["primary"]["macro"]
        if candidate == old:
            axis.scatter(macro["benign_trigger_rate"], macro["attack_alert_rate"], s=70, marker="s", facecolor="white",
                         edgecolor=PURPLE, linewidth=2, zorder=4)
            axis.annotate("old B5\n(24, 4.0, 0.70)", (macro["benign_trigger_rate"], macro["attack_alert_rate"]),
                          xytext=(-80, 10), textcoords="offset points", color=PURPLE, fontsize=8, weight="bold")
        if candidate == locked:
            axis.scatter(macro["benign_trigger_rate"], macro["attack_alert_rate"], s=74, marker="o", facecolor="white",
                         edgecolor=INK, linewidth=2, zorder=5)
            axis.annotate("locked\n(8, 6.0, 0.90)", (macro["benign_trigger_rate"], macro["attack_alert_rate"]),
                          xytext=(10, -28), textcoords="offset points", color=INK, fontsize=8, weight="bold")
    axis.set(xlim=(0.5, 1.02), ylim=(0.5, 1.02), xlabel="Validation benign-trigger rate", ylabel="Validation attack-alert rate")
    axis.grid(color=GRID, linewidth=0.8)
    axis.set_title(f"{panel + ' ' if panel else ''}Validation operating points", loc="left")
    axis.legend(frameon=False, loc="upper left", fontsize=8)


def draw_forest(axis: plt.Axes, test: dict, panel: str | None = None) -> None:
    macro = test["primary"]["macro"]
    rows = [
        ("$J$: new B5", macro["variants"]["new_B5"]["J"], GREEN),
        ("$J$: B2", macro["variants"]["B2"]["J"], BLUE),
        ("$J$: old B5", macro["variants"]["old_B5"]["J"], PURPLE),
        (r"$\Delta J$: new B5 $-$ B2", macro["comparisons"]["Delta_J_new_B5_minus_B2"], BLUE),
        (r"$\Delta J$: new B5 $-$ old B5", macro["comparisons"]["Delta_J_new_B5_minus_old_B5"], PURPLE),
    ]
    positions = [4.4, 3.4, 2.4, 0.9, -0.1]
    axis.axvline(0, color="#555555", linewidth=1)
    axis.axhline(1.65, color=GRID, linewidth=1)
    for (label, value, color), y in zip(rows, positions):
        mean, (lo, hi) = value["mean"], value["ci95"]
        axis.errorbar(mean, y, xerr=[[mean - lo], [hi - mean]], fmt="o", color=color, markersize=6,
                      capsize=3, linewidth=1.8)
        axis.text(0.0205, y, f"{mean:+.4f} [{lo:+.4f}, {hi:+.4f}]", va="center", color=color, fontsize=8)
    axis.set(yticks=positions, yticklabels=[row[0] for row in rows], xlim=(-0.003, 0.035), ylim=(-0.7, 5.0),
             xlabel="Held-out macro value (95% paired bootstrap CI)")
    axis.grid(axis="x", color=GRID, linewidth=0.8)
    axis.tick_params(axis="y", length=0)
    axis.set_title(f"{panel + ' ' if panel else ''}Held-out evaluation", loc="left")
    axis.text(-0.0026, 4.82, "Detector separation", fontsize=8, color="#666666", style="italic")
    axis.text(-0.0026, 1.14, "Paired comparison", fontsize=8, color="#666666", style="italic")


def heatmap(grid: dict, lock: dict, old: tuple[int, float, float], output: Path) -> None:
    candidates = grid["candidates"]
    ns = sorted({int(item["candidate"]["min_samples"]) for item in candidates})
    hs = sorted({float(item["candidate"]["entropy_threshold"]) for item in candidates})
    us = sorted({float(item["candidate"]["unique_ratio_threshold"]) for item in candidates})
    lookup = {key(item["candidate"]): item for item in candidates}
    values = [item["primary"]["macro"]["delta_J_new_vs_B2"] for item in candidates]
    fig, axes = plt.subplots(1, len(ns), figsize=(10.4, 3.1), sharey=True, layout="constrained")
    for axis, n in zip(np.atleast_1d(axes), ns):
        matrix = np.array([[lookup[(n, h, u)]["primary"]["macro"]["delta_J_new_vs_B2"] for u in us] for h in hs])
        image = axis.imshow(matrix, cmap="YlOrRd", vmin=min(values), vmax=max(values), aspect="auto")
        for r, h in enumerate(hs):
            for c, u in enumerate(us):
                axis.text(c, r, f"{matrix[r, c]:+.4f}", ha="center", va="center", fontsize=7, weight="bold")
                candidate = (n, h, u)
                if candidate == old:
                    axis.scatter(c, r, marker="s", s=80, facecolors="none", edgecolors=PURPLE, linewidths=1.8)
                if candidate == key(lock["selected_candidate"]):
                    axis.scatter(c, r, marker="o", s=86, facecolors="none", edgecolors=INK, linewidths=1.8)
        axis.set(title=f"N = {n}", xticks=range(len(us)), xticklabels=[f"U={u:g}" for u in us], yticks=range(len(hs)), yticklabels=[f"H={h:g}" for h in hs])
    fig.colorbar(image, ax=axes, shrink=0.78, pad=0.02, label=r"Validation macro $\Delta J$")
    fig.suptitle("Validation threshold landscape", fontweight="bold")
    fig.savefig(output, dpi=250, bbox_inches="tight")
    plt.close(fig)


def secondary(test: dict, output: Path) -> None:
    sources = [("attack_fixed_continuous", "Fixed-IPID failure probe", test["secondary_reports"]["failure_probes"]),
               ("attack_dup_sweep_continuous", "Duplicate-sweep failure probe", test["secondary_reports"]["failure_probes"]),
               ("attack_random_continuous", "Random-IPID negative control", test["secondary_reports"]["negative_control"])]
    variants = [("new_B5", "new B5", GREEN), ("B2", "B2", BLUE), ("old_B5", "old B5", PURPLE)]
    fig, axes = plt.subplots(1, 3, figsize=(10.8, 3.2), sharey=True)
    for axis, (condition, title, source) in zip(axes, sources):
        cells = sorted((item for item in source if item["attack_condition"] == condition), key=lambda item: item["level"])
        levels = [item["level"] for item in cells]
        for offset, (variant, label, color) in zip((-2, 0, 2), variants):
            values = [cell["variants"][variant]["J"] for cell in cells]
            means = [value["mean"] for value in values]
            errors = np.asarray([[value["mean"] - value["ci95"][0], value["ci95"][1] - value["mean"]] for value in values]).T
            axis.errorbar(np.asarray(levels) + offset, means, yerr=errors, marker="o", capsize=3, linewidth=1.4, color=color, label=label)
        axis.axhline(0, color="#555555", linewidth=0.9)
        axis.set(title=title, xticks=levels, xlabel="Target samples/window", ylim=(-1.05, 0.12))
        axis.grid(axis="y", color=GRID, linewidth=0.8)
    axes[0].set_ylabel(r"Held-out $J$ (95% paired bootstrap CI)")
    axes[0].legend(frameon=False, fontsize=8, loc="lower left")
    fig.tight_layout()
    fig.savefig(output, dpi=250, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    args = parse_args()
    grid, lock, test = read(GRID_PATH), read(LOCK_PATH), read(TEST_PATH)
    check(grid, lock, test)
    old = (int(args.old_b5[0]), args.old_b5[1], args.old_b5[2])
    style(); OUT.mkdir(exist_ok=True)
    heatmap(grid, lock, old, OUT / "validation_heatmap_delta_j.png")
    fig, axis = plt.subplots(figsize=(5.3, 3.8)); draw_pareto(axis, grid, lock, old); fig.tight_layout(); fig.savefig(OUT / "pareto_operating_points.png", dpi=250, bbox_inches="tight"); plt.close(fig)
    fig, axis = plt.subplots(figsize=(5.3, 3.8)); draw_forest(axis, test); fig.tight_layout(); fig.savefig(OUT / "test_comparison_primary.png", dpi=250, bbox_inches="tight"); plt.close(fig)
    secondary(test, OUT / "failure_boundary_secondary.png")
    fig, axes = plt.subplots(1, 2, figsize=(10.8, 3.7), gridspec_kw={"width_ratios": [1.15, 0.85]}); draw_pareto(axes[0], grid, lock, old, "(a)"); draw_forest(axes[1], test, "(b)"); fig.tight_layout(); fig.savefig(OUT / "validation_to_heldout.png", dpi=300, bbox_inches="tight"); plt.close(fig)
    print(f"Wrote matplotlib E3 figures to {OUT}")


if __name__ == "__main__":
    main()
