#!/usr/bin/env python3
"""Draw E4 figures only from frozen E4 synthesis tables."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


SCRIPT_DIR = Path(__file__).resolve().parent
E4_ROOT = SCRIPT_DIR.parent
WHITE, INK, GRID = (255, 255, 255), (28, 35, 48), (215, 222, 232)
BLUE, GREEN, PURPLE, ORANGE, RED = (54, 108, 190), (27, 132, 91), (135, 79, 175), (222, 126, 35), (192, 61, 61)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    return ImageFont.truetype(path, size)


def text(draw: ImageDraw.ImageDraw, xy: tuple[float, float], value: str, size: int = 18,
         fill: tuple[int, int, int] = INK, bold: bool = False, anchor: str | None = None) -> None:
    draw.text(xy, value, font=font(size, bold), fill=fill, anchor=anchor)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def verify(summary_meta: dict[str, Any], root: Path) -> None:
    if summary_meta.get("status") != "aggregation_complete_read_only":
        raise ValueError("E4 summary is not a read-only completed aggregation")
    if summary_meta.get("selection_or_threshold_modification") is not False or summary_meta.get("statistical_pooling_of_E2_and_E3") is not False:
        raise ValueError("E4 synthesis safety flags are invalid")
    for name, record in summary_meta.get("outputs", {}).items():
        if sha(root / name) != record.get("sha256"):
            raise ValueError(f"Frozen E4 output hash mismatch: {name}")


def xmap(value: float, left: int, right: int, low: float, high: float) -> float:
    return left + (value - low) / (high - low) * (right - left)


def forest_plot(effects: list[dict[str, str]], output: Path) -> None:
    image = Image.new("RGB", (1940, 920), WHITE)
    draw = ImageDraw.Draw(image)
    text(draw, (830, 38), "E4 paired effects: E2 and E3 reported separately", 30, INK, True, "mm")
    text(draw, (830, 76), "ΔJ = synthetic attack-alert separation; 95% paired-bootstrap CI. No E2–E3 pooling.", 17, INK, False, "mm")
    left, right, top, bottom = 430, 1370, 150, 800
    low, high = -0.055, 0.070
    for value in (-.05, 0, .05):
        x = xmap(value, left, right, low, high)
        draw.line((x, top, x, bottom), fill=GRID if value else (105, 105, 105), width=2)
        text(draw, (x, bottom + 24), f"{value:+.2f}", 15, INK, False, "ma")
    margin_left, margin_right = xmap(-.05, left, right, low, high), xmap(.05, left, right, low, high)
    draw.rectangle((margin_left, top, margin_right, bottom), outline=(190, 190, 190), width=1)
    text(draw, ((margin_left + margin_right) / 2, top + 13), "E2 registered ±0.05 practical-equivalence band", 14, (100, 100, 100), False, "ma")
    e2 = [r for r in effects if r["source_experiment"] == "E2" and r["scope"] == "primary_macro"]
    e3 = [r for r in effects if r["source_experiment"] == "E3" and r["scope"] == "primary_macro"]
    plotted = [("E2 continuous — B5 − B1", e2[0]), ("E2 continuous — B5 − B2", e2[1]),
               ("E2 continuous — B5 − B3", e2[2]), ("E2 continuous — B5 − B4", e2[3]),
               ("E2 bursty — B5 − B1", e2[4]), ("E2 bursty — B5 − B2", e2[5]),
               ("E2 bursty — B5 − B3", e2[6]), ("E2 bursty — B5 − B4", e2[7]),
               ("E3 held-out macro — new B5 − B2", e3[0]), ("E3 held-out macro — new B5 − old B5", e3[1])]
    for index, (label, record) in enumerate(plotted):
        y = 185 + index * 56
        color = BLUE if label.startswith("E2") else GREEN
        mean, lo, hi = map(float, (record["estimate"], record["ci95_low"], record["ci95_high"]))
        draw.line((left, y, right, y), fill=GRID)
        draw.line((xmap(lo, left, right, low, high), y, xmap(hi, left, right, low, high), y), fill=color, width=4)
        x = xmap(mean, left, right, low, high)
        draw.ellipse((x - 7, y - 7, x + 7, y + 7), fill=color, outline=WHITE, width=2)
        text(draw, (left - 18, y), label, 15, INK, index in (0, 4, 8), "rm")
        text(draw, (right + 16, y), f"{mean:+.4f} [{lo:+.4f}, {hi:+.4f}]", 13, color, True, "lm")
    draw.line((115, 850, 145, 850), fill=BLUE, width=5); text(draw, (153, 850), "E2 canonical test (n=20 paired traces/cell)", 15, INK, False, "lm")
    draw.line((650, 850, 680, 850), fill=GREEN, width=5); text(draw, (688, 850), "E3 repartition held-out (6 pairs/cell)", 15, INK, False, "lm")
    image.save(output)


def line_panel(draw: ImageDraw.ImageDraw, bounds: tuple[int, int, int, int], title: str,
               series: list[tuple[str, list[tuple[float, float]], tuple[int, int, int]]], y_low: float, y_high: float) -> None:
    left, top, right, bottom = bounds
    text(draw, ((left + right) / 2, top - 27), title, 18, INK, True, "mm")
    draw.rectangle(bounds, outline=INK, width=2)
    for value in (y_low, 0, y_high):
        y = bottom - (value - y_low) / (y_high - y_low) * (bottom - top)
        draw.line((left, y, right, y), fill=GRID)
        text(draw, (left - 10, y), f"{value:+.1f}", 13, INK, False, "rm")
    levels = [24, 60, 120, 200]
    for level in levels:
        x = left + (level - 24) / (200 - 24) * (right - left)
        draw.line((x, top, x, bottom), fill=GRID)
        text(draw, (x, bottom + 23), str(level), 13, INK, False, "ma")
    for label, points, color in series:
        coords = [(left + (lvl - 24) / 176 * (right - left), bottom - (val - y_low) / (y_high - y_low) * (bottom - top)) for lvl, val in points]
        draw.line(coords, fill=color, width=4)
        for x, y in coords: draw.ellipse((x - 5, y - 5, x + 5, y + 5), fill=color, outline=WHITE)
        text(draw, (left + 8, top + 16 + series.index((label, points, color)) * 22), label, 14, color, True, "la")


def failure_plot(summary: list[dict[str, str]], effects: list[dict[str, str]], output: Path) -> None:
    image = Image.new("RGB", (1680, 820), WHITE); draw = ImageDraw.Draw(image)
    text(draw, (840, 38), "E4 operating boundaries and failure probes", 29, INK, True, "mm")
    text(draw, (840, 75), "E1 is benign FPR; E2/E3 are synthetic attack–benign ΔJ. These panels are not pooled or interchangeable.", 16, INK, False, "mm")
    # E1 uses a rate-like x-axis and has a different metric/range.
    left, top, right, bottom = 80, 155, 575, 660
    text(draw, ((left + right) / 2, 125), "E1 benign combined-rule trigger rate", 18, INK, True, "mm")
    draw.rectangle((left, top, right, bottom), outline=INK, width=2)
    for yval in (0, .5, 1):
        y = bottom - yval * (bottom - top); draw.line((left, y, right, y), fill=GRID); text(draw, (left - 12, y), f"{yval:.1f}", 13, INK, False, "rm")
    behavior_colors = {"random2048": BLUE, "sequential": GREEN, "smallpool16": PURPLE}
    for behavior, color in behavior_colors.items():
        entries = [r for r in summary if r["source_experiment"] == "E1" and r["scope"] == "primary_benign" and r["benign_condition"] == behavior and r["metric"] == "benign_trigger_rate"]
        entries.sort(key=lambda r: float(r["level"]))
        coords = [(left + (float(r["level"]) - 5) / 295 * (right - left), bottom - float(r["estimate"]) * (bottom - top)) for r in entries]
        draw.line(coords, fill=color, width=4)
        for x, y in coords: draw.ellipse((x - 4, y - 4, x + 4, y + 4), fill=color, outline=WHITE)
        text(draw, (left + 10, top + 15 + list(behavior_colors).index(behavior) * 22), behavior, 14, color, True, "la")
    for level in (5, 24, 60, 120, 300):
        x = left + (level - 5) / 295 * (right - left); text(draw, (x, bottom + 23), str(level), 13, INK, False, "ma")
    text(draw, ((left + right) / 2, 708), "target samples/window", 14, INK, False, "ma")
    def points(exp: str, condition: str) -> list[tuple[float, float]]:
        return [(float(r["level"]), float(r["estimate"])) for r in effects if r["source_experiment"] == exp and r["attack_condition"] == condition and r["variant_or_comparison"] in {"combined_minus_volume", "Delta_J_new_B5_minus_B2"}]
    line_panel(draw, (665, 155, 1110, 660), "E2 old B5 − B2 failure ΔJ",
               [("fixed-IPID", points("E2", "attack_fixed_continuous"), BLUE), ("duplicate sweep", points("E2", "attack_dup_sweep_continuous"), PURPLE)], -1.05, .10)
    line_panel(draw, (1195, 155, 1640, 660), "E3 new B5 − B2 failure ΔJ",
               [("fixed-IPID", points("E3", "attack_fixed_continuous"), GREEN), ("duplicate sweep", points("E3", "attack_dup_sweep_continuous"), ORANGE)], -1.05, .10)
    text(draw, (840, 772), "J/ΔJ below 0 means benign triggering exceeds synthetic attack alert in that probe; this is not an ASR measurement.", 15, INK, False, "mm")
    image.save(output)


def coverage_plot(coverage: list[dict[str, str]], output: Path) -> None:
    image = Image.new("RGB", (1560, 855), WHITE); draw = ImageDraw.Draw(image)
    text(draw, (780, 38), "E4 metric-evidence coverage", 29, INK, True, "mm")
    text(draw, (780, 75), "Measured evidence is not the same as deployment or end-to-end security evidence.", 16, INK, False, "mm")
    left, top, metric_w, cell_w, row_h = 80, 140, 600, 275, 70
    statuses = {"measured": (202, 232, 217), "not_measured": (238, 210, 210), "not_supported": (238, 210, 210), "not_primary_metric": (239, 230, 194), "not_primary_reported_metric": (239, 230, 194), "not_applicable_to_locked_binary_combined_rule": (239, 230, 194), "not_supported_for_virtual_time": (238, 210, 210)}
    for i, label in enumerate(("Metric", "E1", "E2", "E3")):
        x = left if i == 0 else left + metric_w + (i - 1) * cell_w
        width = metric_w if i == 0 else cell_w
        draw.rectangle((x, top, x + width, top + row_h), fill=INK)
        text(draw, (x + width / 2, top + row_h / 2), label, 18, WHITE, True, "mm")
    for r, entry in enumerate(coverage):
        y = top + row_h * (r + 1)
        draw.rectangle((left, y, left + metric_w, y + row_h), fill=(245, 247, 250), outline=WHITE)
        text(draw, (left + 14, y + row_h / 2), entry["metric"], 14, INK, True, "lm")
        for i, key in enumerate(("E1_status", "E2_status", "E3_status")):
            x = left + metric_w + i * cell_w; status = entry[key]
            draw.rectangle((x, y, x + cell_w, y + row_h), fill=statuses[status], outline=WHITE)
            text(draw, (x + cell_w / 2, y + row_h / 2), status.replace("_", " "), 13, INK, False, "mm")
    text(draw, (780, 825), "Green = measured; yellow = not primary/applicable; red = not measured or unsupported. ASR and runtime metrics require E5/runtime data.", 15, INK, False, "mm")
    image.save(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=E4_ROOT / "e4_summary.csv")
    parser.add_argument("--effects", type=Path, default=E4_ROOT / "e4_paired_effects.csv")
    parser.add_argument("--coverage", type=Path, default=E4_ROOT / "e4_metric_coverage.csv")
    parser.add_argument("--metadata", type=Path, default=E4_ROOT / "e4_summary.json")
    parser.add_argument("--output-dir", type=Path, default=E4_ROOT / "figures")
    return parser.parse_args()


def main() -> int:
    args = parse_args(); metadata = json.loads(args.metadata.read_text(encoding="utf-8")); verify(metadata, E4_ROOT)
    summary, effects, coverage = load_csv(args.summary), load_csv(args.effects), load_csv(args.coverage)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    forest_plot(effects, args.output_dir / "e4_effect_sizes.png")
    failure_plot(summary, effects, args.output_dir / "e4_failure_boundaries.png")
    coverage_plot(coverage, args.output_dir / "e4_metric_coverage.png")
    print(f"Wrote 3 frozen-synthesis figures to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
