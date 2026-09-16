"""Publication figures for E1 from e1_results.json.

Figure_1.png -- FPR vs samples/window (primary detector B5=combined), 95% CI
               bands per IPID behavior, MIN_SAMPLES marked. THE headline figure.
Figure_2.png -- entropy(rate) and unique_ratio(rate) with the two B5 gate
               thresholds, explaining *why* FPR behaves as it does.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
FIG_DIR = HERE / "figures"

# Theme-neutral, colorblind-safe palette (Okabe-Ito subset).
COLORS = {"random2048": "#0072B2", "sequential": "#D55E00", "smallpool16": "#009E73"}
MARKERS = {"random2048": "o", "sequential": "s", "smallpool16": "^"}

RESULTS = {}
META = {}
BEHAVIORS = []
LABEL = {}
SHORT = {"random2048": "random IPID", "sequential": "sequential IPID",
         "smallpool16": "small IPID pool"}
LEVELS = []
MIN_SAMPLES = 0
ENT_THR = 0.0
UNIQ_THR = 0.0
WINDOW_SECONDS = 2.0


def configure(results_path: Path, figure_dir: Path) -> None:
    global RESULTS, META, BEHAVIORS, LABEL, LEVELS
    global MIN_SAMPLES, ENT_THR, UNIQ_THR, WINDOW_SECONDS, FIG_DIR
    with results_path.open(encoding="utf-8") as f:
        RESULTS = json.load(f)
    META = RESULTS["meta"]
    BEHAVIORS = list(META["behaviors"])
    LABEL = META["behaviors"]
    LEVELS = META["levels_samples_per_window"]
    MIN_SAMPLES = META["operating_point"]["min_samples"]
    ENT_THR = META["operating_point"]["entropy_threshold"]
    UNIQ_THR = META["operating_point"]["unique_ratio_threshold"]
    WINDOW_SECONDS = META["operating_point"]["window_seconds"]
    FIG_DIR = figure_dir
    FIG_DIR.mkdir(parents=True, exist_ok=True)


def series(behavior: str, key_path):
    """Extract a per-level series for one behavior. key_path is a callable(entry)."""
    xs, ys = [], []
    for entry in RESULTS["levels"]:
        if entry["behavior"] != behavior:
            continue
        xs.append(entry["level"])
        ys.append(key_path(entry))
    order = np.argsort(xs)
    return np.array(xs)[order], np.array(ys, dtype=object)[order]


def fpr_series(behavior: str):
    xs, mean, lo, hi = [], [], [], []
    for entry in sorted((e for e in RESULTS["levels"] if e["behavior"] == behavior),
                        key=lambda e: e["level"]):
        cv = entry["variants"]["combined"]
        xs.append(entry.get("actual_fragments_per_second_mean",
                            (entry["level"] - 1) / WINDOW_SECONDS))
        mean.append(cv["fpr_run_mean"])
        lower, upper = cv.get("fpr_cluster_bootstrap_ci95", cv["fpr_run_ci95_t"])
        lo.append(max(0.0, lower))
        hi.append(min(1.0, upper))
    return np.array(xs), np.array(mean), np.array(lo), np.array(hi)


def ci_series(behavior: str, mean_key: str, ci_key: str):
    xs, mean, lo, hi = [], [], [], []
    for entry in sorted((e for e in RESULTS["levels"] if e["behavior"] == behavior),
                        key=lambda e: e["level"]):
        xs.append(entry.get("samples_mean", entry["level"]))
        mean.append(entry[mean_key])
        lower, upper = entry[ci_key]
        lo.append(lower)
        hi.append(upper)
    return np.array(xs), np.array(mean), np.array(lo), np.array(hi)


# --------------------------------------------------------------------------- #
# Figure 1 -- FPR(rate) : the operating boundary.                             #
# --------------------------------------------------------------------------- #
def legacy_fpr_series(behavior: str):
    xs, mean = [], []
    for entry in sorted((e for e in RESULTS["levels"] if e["behavior"] == behavior),
                        key=lambda e: e["level"]):
        xs.append(entry.get("actual_fragments_per_second_mean",
                            (entry["level"] - 1) / WINDOW_SECONDS))
        mean.append(entry["variants"]["legacy"]["fpr_run_mean"])
    return np.array(xs), np.array(mean)


def figure_1() -> None:
    fig, ax = plt.subplots(figsize=(8.2, 5.4))
    # Rℓ2 gốc (legacy): chặn mọi fragment -> FPR = 1.0 ở mọi tải
    xs_l, mean_l = legacy_fpr_series("random2048")
    ax.plot(xs_l, mean_l, marker="D", color="#111111", ls=(0, (4, 2)), lw=2.4, ms=7,
            zorder=4, label="Rℓ2 gốc")
    # Rℓ2 cải tiến của nhóm (combined) trên 3 nguồn IPID
    short = {"random2048": "Rℓ2 cải tiến — random IPID",
             "sequential": "Rℓ2 cải tiến — sequential IPID",
             "smallpool16": "Rℓ2 cải tiến — small IPID pool"}
    for beh in BEHAVIORS:
        xs, mean, lo, hi = fpr_series(beh)
        ax.plot(xs, mean, marker=MARKERS[beh], color=COLORS[beh], lw=2.0,
                ms=6, label=short[beh], zorder=3)
        ax.fill_between(xs, lo, hi, color=COLORS[beh], alpha=0.18, zorder=2)

    threshold_rate = (MIN_SAMPLES - 1) / WINDOW_SECONDS
    ax.axvline(threshold_rate, color="#444444", ls="--", lw=1.2, zorder=1,
               label=f"MIN_SAMPLES={MIN_SAMPLES} (~{threshold_rate:g} frag/s)")

    ax.set_xscale("log")
    rate_ticks = [(level - 1) / WINDOW_SECONDS for level in LEVELS]
    ax.set_xticks(rate_ticks)
    ax.set_xticklabels([f"{value:g}" for value in rate_ticks])
    ax.set_xlim(min(rate_ticks) * 0.85, max(rate_ticks) * 1.15)
    ax.set_ylim(-0.03, 1.05)
    ax.set_xlabel("actual benign fragment rate (fragments/s)")
    ax.set_ylabel("False Positive Rate")
    ax.grid(True, which="both", ls=":", alpha=0.4)
    ax.legend(loc="center right", fontsize=9, framealpha=0.95)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "Figure_1.png", dpi=160)
    plt.close(fig)
    print(f"[+] wrote {FIG_DIR / 'Figure_1.png'}")


# --------------------------------------------------------------------------- #
# Figure 2 -- why: entropy & unique_ratio vs the two B5 gates.                #
# --------------------------------------------------------------------------- #
def figure_2() -> None:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.4, 5.2))

    for beh in BEHAVIORS:
        xs, m, lo, hi = ci_series(beh, "entropy_mean", "entropy_ci95")
        ax1.plot(xs, m, marker=MARKERS[beh], color=COLORS[beh], lw=2, ms=6,
                 label=SHORT[beh])
        ax1.fill_between(xs, lo, hi, color=COLORS[beh], alpha=0.18)
    ax1.axhline(ENT_THR, color="#444", ls="--", lw=1.2,
                label=f"ngưỡng entropy = {ENT_THR}")
    ax1.axvline(MIN_SAMPLES, color="#888", ls=":", lw=1.1,
                label=f"MIN_SAMPLES = {MIN_SAMPLES}")
    ax1.set_xscale("log")
    ax1.set_xticks(LEVELS)
    ax1.set_xticklabels([str(v) for v in LEVELS])
    ax1.set_xlabel("samples / window")
    ax1.set_ylabel("entropy trung bình (bit)")
    ax1.set_title("(a)")
    ax1.grid(True, which="both", ls=":", alpha=0.4)
    ax1.legend(fontsize=8, loc="lower right")

    for beh in BEHAVIORS:
        xs, m, lo, hi = ci_series(beh, "unique_ratio_mean", "unique_ratio_ci95")
        ax2.plot(xs, m, marker=MARKERS[beh], color=COLORS[beh], lw=2, ms=6,
                 label=SHORT[beh])
        ax2.fill_between(xs, lo, hi, color=COLORS[beh], alpha=0.18)
    ax2.axhline(UNIQ_THR, color="#444", ls="--", lw=1.2,
                label=f"ngưỡng unique_ratio = {UNIQ_THR}")
    ax2.axvline(MIN_SAMPLES, color="#888", ls=":", lw=1.1,
                label=f"MIN_SAMPLES = {MIN_SAMPLES}")
    ax2.set_xscale("log")
    ax2.set_xticks(LEVELS)
    ax2.set_xticklabels([str(v) for v in LEVELS])
    ax2.set_xlabel("samples / window")
    ax2.set_ylabel("unique_ratio trung bình")
    ax2.set_ylim(0, 1.05)
    ax2.set_title("(b)")
    ax2.grid(True, which="both", ls=":", alpha=0.4)
    ax2.legend(fontsize=8, loc="lower left")

    fig.tight_layout()
    fig.savefig(FIG_DIR / "Figure_2.png", dpi=160)
    plt.close(fig)
    print(f"[+] wrote {FIG_DIR / 'Figure_2.png'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Render E1 publication figures")
    parser.add_argument("--results", type=Path, default=HERE / "e1_results.json")
    parser.add_argument("--out", type=Path, default=None,
                        help="figure directory (default: <results-dir>/figures)")
    args = parser.parse_args()
    figure_dir = args.out or args.results.resolve().parent / "figures"
    configure(args.results.resolve(), figure_dir.resolve())
    print("Rendering E1 figures — this is what the results are meant to show:")
    print("  Fig 1: the FPR failure boundary on benign traffic.")
    print("  Fig 2: the entropy/unique_ratio mechanism behind it.")
    figure_1()
    figure_2()
    print("[✓] figures done.")


if __name__ == "__main__":
    main()
