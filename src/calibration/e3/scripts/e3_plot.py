#!/usr/bin/env python3
"""Create E3 figures exclusively from frozen JSON artifacts.

No decision CSV is opened and no selection/test metric is recomputed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont


SCRIPT_DIR = Path(__file__).resolve().parent
E3_ROOT = SCRIPT_DIR.parent
WHITE = (255, 255, 255)
INK = (26, 32, 44)
GRID = (215, 221, 230)
GREEN = (29, 129, 90)
BLUE = (50, 109, 194)
PURPLE = (133, 79, 173)
ORANGE = (219, 126, 34)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    name = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    return ImageFont.truetype(name, size)


def text(draw: ImageDraw.ImageDraw, xy: tuple[float, float], content: str, size: int = 18,
         fill: tuple[int, int, int] = INK, bold: bool = False, anchor: str | None = None) -> None:
    draw.text(xy, content, fill=fill, font=font(size, bold), anchor=anchor)


def vertical_text(image: Image.Image, x: int, y: int, content: str, size: int = 18) -> None:
    """Draw a centered, readable vertical axis label."""
    label_font = font(size)
    box = label_font.getbbox(content)
    layer = Image.new("RGBA", (box[2] - box[0] + 8, box[3] - box[1] + 8), (0, 0, 0, 0))
    ImageDraw.Draw(layer).text((4 - box[0], 4 - box[1]), content, fill=INK, font=label_font)
    layer = layer.rotate(90, expand=True)
    image.paste(layer, (x - layer.width // 2, y - layer.height // 2), layer)


def map_value(value: float, low: float, high: float) -> tuple[int, int, int]:
    if high <= low:
        return (242, 174, 88)
    t = max(0.0, min(1.0, (value - low) / (high - low)))
    return (int(42 + 205 * t), int(96 + 80 * (1 - t)), int(175 - 105 * t))


def marker(draw: ImageDraw.ImageDraw, x: float, y: float, kind: str, label: str | None = None) -> None:
    if kind == "old":
        draw.rectangle((x - 7, y - 7, x + 7, y + 7), outline=PURPLE, width=4)
    else:
        draw.ellipse((x - 8, y - 8, x + 8, y + 8), outline=INK, width=4)
    if label:
        text(draw, (x + 12, y - 10), label, 14, INK, True)


def verify_artifacts(protocol: dict[str, Any], grid: dict[str, Any], lock: dict[str, Any], test: dict[str, Any],
                     protocol_path: Path, grid_path: Path) -> None:
    if grid.get("status") != "validation_sweep_complete_no_selection":
        raise ValueError("Validation grid is not the frozen no-selection artifact")
    if lock.get("status") != "locked-before-test" or test.get("status") != "held_out_evaluation_complete_once":
        raise ValueError("Lock/test artifacts are not in their required frozen states")
    if grid.get("protocol", {}).get("sha256") != sha256_file(protocol_path):
        raise ValueError("Validation grid provenance does not match protocol")
    if lock.get("validation_grid", {}).get("sha256") != sha256_file(grid_path):
        raise ValueError("Lock provenance does not match validation grid")
    if test.get("held_out_evaluation", {}).get("candidate") != lock.get("selected_candidate"):
        raise ValueError("Held-out test candidate does not match the locked candidate")
    if protocol.get("selection", {}).get("primary_criterion") != "maximize macro delta_J_new_vs_B2":
        raise ValueError("Unexpected E3 selection semantics")


def heatmap(grid: dict[str, Any], lock: dict[str, Any], output: Path) -> None:
    candidates = grid["candidates"]
    values = [c["primary"]["macro"]["delta_J_new_vs_B2"] for c in candidates]
    low, high = min(values), max(values)
    ns, hs, us = [8, 16, 24, 48], [2, 3, 4, 5, 6], [0.5, 0.7, 0.9]
    by_key = {(c["candidate"]["min_samples"], c["candidate"]["entropy_threshold"], c["candidate"]["unique_ratio_threshold"]): c for c in candidates}
    image = Image.new("RGB", (1680, 825), WHITE)
    draw = ImageDraw.Draw(image)
    text(draw, (840, 42), "Validation selection metric: macro ΔJ(new B5 − B2)", 28, INK, True, "mm")
    text(draw, (840, 78), "Equal-weight macro across sweep continuous/bursty × four levels; validation only", 16, INK, False, "mm")
    panel_w, panel_h = 375, 580
    start_x, start_y = 64, 145
    cell_w, cell_h = 104, 88
    for panel, n in enumerate(ns):
        px = start_x + panel * 402
        text(draw, (px + panel_w / 2, 116), f"min_samples = {n}", 21, INK, True, "mm")
        for r, h in enumerate(hs):
            text(draw, (px - 11, start_y + r * cell_h + cell_h / 2), f"H={h}", 16, INK, False, "rm")
            for c, u in enumerate(us):
                entry = by_key[(n, h, u)]
                value = entry["primary"]["macro"]["delta_J_new_vs_B2"]
                x0, y0 = px + c * cell_w, start_y + r * cell_h
                draw.rectangle((x0, y0, x0 + cell_w - 5, y0 + cell_h - 5), fill=map_value(value, low, high), outline=WHITE, width=2)
                text(draw, (x0 + (cell_w - 5) / 2, y0 + 40), f"{value:+.4f}", 17, WHITE, True, "mm")
                if r == len(hs) - 1:
                    text(draw, (x0 + (cell_w - 5) / 2, start_y + len(hs) * cell_h + 13), f"U={u:.1f}", 16, INK, False, "ma")
                if (n, h, u) == (24, 4, 0.7):
                    marker(draw, x0 + 13, y0 + 14, "old")
                selected = lock["selected_candidate"]
                if (n, h, u) == (selected["min_samples"], selected["entropy_threshold"], selected["unique_ratio_threshold"]):
                    marker(draw, x0 + 13, y0 + 14, "selected")
    marker(draw, 215, 715, "old")
    text(draw, (232, 715), "old B5: 24 / 4.0 / 0.70", 16, INK, True, "lm")
    marker(draw, 590, 715, "selected")
    text(draw, (607, 715), "locked: 8 / 6.0 / 0.90", 16, INK, True, "lm")
    text(draw, (840, 760), f"Color scale: {low:+.4f} to {high:+.4f}. Many candidates tie/overlap at the displayed ΔJ values.", 16, INK, False, "mm")
    image.save(output)


def pareto(grid: dict[str, Any], lock: dict[str, Any], output: Path) -> None:
    image = Image.new("RGB", (1250, 920), WHITE)
    draw = ImageDraw.Draw(image)
    text(draw, (625, 38), "Validation operating points: attack-alert vs benign-trigger", 28, INK, True, "mm")
    text(draw, (625, 75), "Bubble size reports the number of candidates at an identical operating point; color = macro ΔJ", 16, INK, False, "mm")
    left, top, right, bottom = 130, 145, 1120, 750
    draw.rectangle((left, top, right, bottom), outline=INK, width=2)
    for tick in range(0, 11, 2):
        value = tick / 10
        x = left + value * (right - left)
        y = bottom - value * (bottom - top)
        draw.line((x, top, x, bottom), fill=GRID)
        draw.line((left, y, right, y), fill=GRID)
        text(draw, (x, bottom + 25), f"{value:.1f}", 14, INK, False, "ma")
        text(draw, (left - 18, y), f"{value:.1f}", 14, INK, False, "rm")
    text(draw, ((left + right) / 2, 845), "Macro benign-trigger rate / synthetic FPR (lower is better)", 17, INK, False, "ma")
    vertical_text(image, 34, int((top + bottom) / 2), "Macro attack-alert rate / synthetic TPR", 17)
    values = [c["primary"]["macro"]["delta_J_new_vs_B2"] for c in grid["candidates"]]
    low, high = min(values), max(values)
    # Pareto means no other candidate has lower/equal benign trigger and
    # higher/equal attack alert, with at least one strict improvement.
    old = (24, 4.0, 0.7)
    selected = lock["selected_candidate"]
    groups: dict[tuple[float, float], list[dict[str, Any]]] = {}
    for entry in grid["candidates"]:
        macro = entry["primary"]["macro"]
        key = (round(macro["benign_trigger_rate"], 12), round(macro["attack_alert_rate"], 12))
        groups.setdefault(key, []).append(entry)
    coords = list(groups)
    frontier = []
    for xval, yval in coords:
        dominated = any(
            ox <= xval and oy >= yval and (ox < xval or oy > yval)
            for ox, oy in coords
        )
        if not dominated:
            frontier.append((xval, yval))
    frontier.sort()
    if len(frontier) > 1:
        draw.line([(left + x * (right - left), bottom - y * (bottom - top)) for x, y in frontier], fill=ORANGE, width=3)
    # Reference only: points on this diagonal have attack-alert equal to benign-trigger.
    draw.line((left, bottom, right, top), fill=(120, 120, 120), width=2)
    text(draw, (right - 170, top + 18), "TPR = FPR", 14, (100, 100, 100), True)
    for (xval, yval), entries in groups.items():
        representative = max(entries, key=lambda e: e["primary"]["macro"]["delta_J_new_vs_B2"])
        macro = representative["primary"]["macro"]
        x = left + xval * (right - left)
        y = bottom - yval * (bottom - top)
        color = map_value(macro["delta_J_new_vs_B2"], low, high)
        radius = 5 + int(math.sqrt(len(entries)) * 2)
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color, outline=WHITE, width=2)
        if len(entries) > 1:
            text(draw, (x, y), f"{len(entries)}", 12, WHITE, True, "mm")
    for entry in grid["candidates"]:
        macro, candidate = entry["primary"]["macro"], entry["candidate"]
        x = left + macro["benign_trigger_rate"] * (right - left)
        y = bottom - macro["attack_alert_rate"] * (bottom - top)
        key = (candidate["min_samples"], candidate["entropy_threshold"], candidate["unique_ratio_threshold"])
        if key == old:
            marker(draw, x, y, "old")
        if key == (selected["min_samples"], selected["entropy_threshold"], selected["unique_ratio_threshold"]):
            marker(draw, x, y, "selected")
    draw.line((150, 795, 190, 795), fill=ORANGE, width=3)
    text(draw, (198, 795), "Pareto frontier", 15, INK, True, "lm")
    marker(draw, 455, 795, "old")
    text(draw, (472, 795), "old B5", 15, INK, True, "lm")
    marker(draw, 630, 795, "selected")
    text(draw, (647, 795), "locked candidate", 15, INK, True, "lm")
    text(draw, (875, 795), f"ΔJ color: {low:+.4f} to {high:+.4f}", 15, INK, False, "lm")
    image.save(output)


def errorbar(draw: ImageDraw.ImageDraw, x: float, mean: float, ci: list[float], color: tuple[int, int, int],
             top: float, bottom: float, lo: float, hi: float) -> None:
    def y(value: float) -> float:
        return bottom - (value - lo) / (hi - lo) * (bottom - top)
    ym, yl, yh = y(mean), y(ci[0]), y(ci[1])
    draw.line((x, yl, x, yh), fill=color, width=4)
    draw.line((x - 8, yl, x + 8, yl), fill=color, width=3)
    draw.line((x - 8, yh, x + 8, yh), fill=color, width=3)
    draw.ellipse((x - 7, ym - 7, x + 7, ym + 7), fill=color, outline=WHITE, width=2)


def heldout_comparison(test: dict[str, Any], output: Path) -> None:
    macro = test["primary"]["macro"]
    image = Image.new("RGB", (1450, 790), WHITE)
    draw = ImageDraw.Draw(image)
    text(draw, (725, 38), "Held-out primary comparison: locked new B5 vs B2 and old B5", 28, INK, True, "mm")
    text(draw, (725, 74), "Equal-weight macro across eight primary cells; 95% stratified paired-trace bootstrap CI", 16, INK, False, "mm")
    panels = [(90, 145, 720, 665, "Primary macro J", "J"), (800, 145, 1360, 665, "Primary macro ΔJ", "Delta_J")]
    variants = [("new_B5", "new B5", GREEN), ("B2", "B2", BLUE), ("old_B5", "old B5", PURPLE)]
    for left, top, right, bottom, title, kind in panels:
        text(draw, ((left + right) / 2, 120), title, 22, INK, True, "mm")
        lo, hi = (-0.03, 0.04) if kind == "J" else (-0.01, 0.04)
        for value in (-0.02, 0.0, 0.02, 0.04) if kind == "J" else (0.0, 0.02, 0.04):
            if not lo <= value <= hi:
                continue
            y = bottom - (value - lo) / (hi - lo) * (bottom - top)
            draw.line((left, y, right, y), fill=GRID)
            text(draw, (left - 12, y), f"{value:+.2f}", 14, INK, False, "rm")
        draw.rectangle((left, top, right, bottom), outline=INK, width=2)
        if kind == "J":
            for i, (key, label, color) in enumerate(variants):
                value = macro["variants"][key]["J"]
                x = left + 115 + i * 200
                errorbar(draw, x, value["mean"], value["ci95"], color, top, bottom, lo, hi)
                text(draw, (x, bottom + 35), label, 16, color, True, "ma")
                text(draw, (x, top + 28), f"{value['mean']:+.4f}", 14, color, True, "ma")
        else:
            comparisons = [("Delta_J_new_B5_minus_B2", "new − B2", BLUE), ("Delta_J_new_B5_minus_old_B5", "new − old B5", PURPLE)]
            for i, (key, label, color) in enumerate(comparisons):
                value = macro["comparisons"][key]
                x = left + 170 + i * 210
                errorbar(draw, x, value["mean"], value["ci95"], color, top, bottom, lo, hi)
                text(draw, (x, bottom + 35), label, 16, color, True, "ma")
                text(draw, (x, top + 28), f"{value['mean']:+.4f}", 14, color, True, "ma")
    text(draw, (725, 735), "J = synthetic attack-alert − benign-trigger. This is detector separation, not ASR or poisoning-prevention evidence.", 15, INK, False, "mm")
    image.save(output)


def secondary_plot(test: dict[str, Any], output: Path) -> None:
    secondary = test["secondary_reports"]
    groups = [
        ("attack_fixed_continuous", "Fixed-IPID failure probe", secondary["failure_probes"]),
        ("attack_dup_sweep_continuous", "Duplicate-sweep failure probe", secondary["failure_probes"]),
        ("attack_random_continuous", "Random-IPID negative control", secondary["negative_control"]),
    ]
    image = Image.new("RGB", (1620, 720), WHITE)
    draw = ImageDraw.Draw(image)
    text(draw, (840, 38), "Held-out secondary conditions: detector failure probes and negative control", 27, INK, True, "mm")
    text(draw, (840, 74), "J with 95% paired bootstrap CI; these are synthetic detector conditions, not ASR or real-world bypass evidence", 16, INK, False, "mm")
    variants = [("new_B5", "new B5", GREEN), ("B2", "B2", BLUE), ("old_B5", "old B5", PURPLE)]
    for panel, (condition, title, source) in enumerate(groups):
        left, top, right, bottom = 65 + panel * 515, 145, 510 + panel * 515, 570
        cells = [c for c in source if c["attack_condition"] == condition]
        cells.sort(key=lambda c: c["level"])
        text(draw, ((left + right) / 2, 113), title, 18, INK, True, "mm")
        lo, hi = -1.05, 0.12
        for value in (-1.0, -0.5, 0.0):
            y = bottom - (value - lo) / (hi - lo) * (bottom - top)
            draw.line((left, y, right, y), fill=GRID)
            text(draw, (left - 12, y), f"{value:+.1f}", 13, INK, False, "rm")
        draw.rectangle((left, top, right, bottom), outline=INK, width=2)
        for i, cell in enumerate(cells):
            center = left + 75 + i * 115
            text(draw, (center, bottom + 32), str(cell["level"]), 14, INK, False, "ma")
            for offset, (key, _, color) in zip((-22, 0, 22), variants):
                value = cell["variants"][key]["J"]
                errorbar(draw, center + offset, value["mean"], value["ci95"], color, top, bottom, lo, hi)
        for index, (_, label, color) in enumerate(variants):
            draw.line((left + 12 + index * 145, bottom + 72, left + 40 + index * 145, bottom + 72), fill=color, width=5)
            text(draw, (left + 47 + index * 145, bottom + 72), label, 13, color, True, "lm")
    text(draw, (810, 670), "Level = target samples/window. J below zero means benign triggering exceeds synthetic attack alert in that condition.", 15, INK, False, "mm")
    image.save(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument("--grid", type=Path, default=E3_ROOT / "e3_validation_grid.json")
    parser.add_argument("--lock", type=Path, default=E3_ROOT / "e3_locked_threshold.json")
    parser.add_argument("--test", type=Path, default=E3_ROOT / "e3_test_results.json")
    parser.add_argument("--output-dir", type=Path, default=E3_ROOT / "figures")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    protocol, grid, lock, test = (load_json(path) for path in (args.protocol, args.grid, args.lock, args.test))
    verify_artifacts(protocol, grid, lock, test, args.protocol, args.grid)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    heatmap(grid, lock, args.output_dir / "validation_heatmap_delta_j.png")
    pareto(grid, lock, args.output_dir / "pareto_operating_points.png")
    heldout_comparison(test, args.output_dir / "test_comparison_primary.png")
    secondary_plot(test, args.output_dir / "failure_boundary_secondary.png")
    print(f"Wrote 4 frozen-artifact figures to {args.output_dir}")
    return 0


if __name__ == "__main__":
    main()
