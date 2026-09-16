"""Generate a data-bound Markdown report for a validated E1 campaign."""
from __future__ import annotations

import argparse
import json
import shlex
import time
from pathlib import Path

import numpy as np


HERE = Path(__file__).resolve().parent
CODE_ROOT = HERE.parents[3]
DEFAULT_DOCKER_SANITY = (
    CODE_ROOT / "artifacts" / "r2entropy" / "benign-on-fixed" / "benign-on"
)


def docker_sanity(path: Path) -> dict | None:
    decisions_path = path / "app" / "r2_entropy_decisions.jsonl"
    latency_path = path / "latency_ms.txt"
    if not decisions_path.is_file() or not latency_path.is_file():
        return None
    decisions = [json.loads(line) for line in decisions_path.read_text(
        encoding="utf-8"
    ).splitlines() if line.strip()]
    latency = np.asarray([
        float(line) for line in latency_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ])
    timestamps = [float(item["ts"]) for item in decisions]
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    return {
        "decisions": len(decisions),
        "blocks": sum(item.get("action") == "tc_block" for item in decisions),
        "entropy_mean": float(np.mean([float(item["entropy"]) for item in decisions])),
        "samples_mean": float(np.mean([float(item["samples"]) for item in decisions])),
        "unique_ratio_mean": float(np.mean([
            float(item["unique_ratio"]) for item in decisions
        ])),
        "throughput_decisions_per_second": (
            (len(decisions) - 1) / duration if len(decisions) > 1 and duration else 0.0
        ),
        "latency_p50_ms": float(np.percentile(latency, 50)),
        "latency_p95_ms": float(np.percentile(latency, 95)),
        "latency_p99_ms": float(np.percentile(latency, 99)),
        "source": str(path),
    }


def fmt_ci(values: list[float]) -> str:
    return f"[{values[0]:.3f}, {values[1]:.3f}]"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate E1 Markdown report")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--docker-sanity", type=Path, default=DEFAULT_DOCKER_SANITY)
    parser.add_argument("--docker-comparison-json", type=Path, default=None,
                        help="fresh B0/B5 Docker summary JSON to embed")
    args = parser.parse_args()
    artifact_dir = args.artifact_dir.resolve()
    output = args.out.resolve() if args.out else artifact_dir / "E1_report.md"

    validation_path = artifact_dir / "validation.json"
    if not validation_path.is_file():
        raise FileNotFoundError("run e1_validate.py before generating the report")
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    if validation.get("status") != "PASS":
        raise RuntimeError("refusing to report an E1 artifact that failed validation")

    results = json.loads((artifact_dir / "e1_results.json").read_text(encoding="utf-8"))
    meta = results["meta"]
    op = meta["operating_point"]
    entries = sorted(results["levels"], key=lambda item: (
        list(meta["behaviors"]).index(item["behavior"]), int(item["level"])
    ))

    lines: list[str] = []
    lines.extend([
        "# E1 — FPR theo tốc độ fragment hợp lệ",
        "",
        f"**Trạng thái:** VALIDATED controlled-emulation · **Run ID:** `{meta['run_id']}` · "
        f"**K:** {meta['runs_per_cell']} run/cell · "
        f"**Decision:** {meta['decisions_per_run']} / run",
        "",
        "## 1. Câu hỏi và phạm vi",
        "",
        "E1 đo false-positive rate của Rℓ₂ cải tiến trên lưu lượng fragment hợp lệ "
        "khi tải tăng. Mọi `tc_block` trong campaign benign-only là false positive. "
        "Kết luận chỉ áp dụng cho controlled emulation; không phải bằng chứng "
        "deployment/real-world.",
        "",
        "## 2. Protocol khóa trước khi chạy",
        "",
        f"- Operating point: `samples ≥ {op['min_samples']}` AND "
        f"`entropy ≥ {op['entropy_threshold']}` AND "
        f"`unique_ratio ≥ {op['unique_ratio_threshold']}`; window "
        f"`{op['window_seconds']} s`.",
        f"- Main grid: `{meta['levels_samples_per_window']}` samples/window × "
        f"{len(meta['behaviors'])} IPID behaviors × K={meta['runs_per_cell']}.",
        "- Đơn vị độc lập: run. Thứ tự cell được shuffle bằng seed đã lưu trước; "
        "cửa sổ trong cùng run không được tính là mẫu độc lập.",
        "- Primary uncertainty: cluster bootstrap trên run. Run-level t interval là "
        "sensitivity analysis.",
        "- Khi không quan sát FP, báo `0 observed`; exact binomial chỉ áp dụng cho "
        "biến độc lập `run có ít nhất một FP`, không áp dụng 6.000 cửa sổ chồng lấn.",
        "- Tải Poisson dùng `λ=(target−1)/window` vì scoring diễn ra sau khi FRAG2 "
        "hiện tại đã vào cửa sổ. Bảng luôn báo occupancy và fragment/s thực đo.",
        "",
        "## 3. Kết quả chính",
        "",
        "![FPR theo actual benign fragment rate](figures/Figure_1.png)",
        "",
        "![Entropy và unique ratio theo actual occupancy](figures/Figure_2.png)",
        "",
        "### 3.1 Bảng FPR của B5",
        "",
        "| IPID behavior | target s/win | actual s/win | actual frag/s | FP/decisions | "
        "FPR | run-cluster 95% CI | runs có FP | run-any-FP exact 95% CI | entropy | unique |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])

    for entry in entries:
        combined = entry["variants"]["combined"]
        lines.append(
            f"| `{entry['behavior']}` | {entry['level']} | {entry['samples_mean']:.2f} | "
            f"{entry['actual_fragments_per_second_mean']:.2f} | "
            f"{combined['blocks_total']}/{combined['decisions_total']} | "
            f"{combined['fpr_run_mean']:.3f} | "
            f"{fmt_ci(combined['fpr_cluster_bootstrap_ci95'])} | "
            f"{combined['runs_with_any_fp']}/{entry['n_runs']} | "
            f"{fmt_ci(combined['run_any_fp_clopper_pearson_ci95'])} | "
            f"{entry['entropy_mean']:.3f} | {entry['unique_ratio_mean']:.3f} |"
        )

    lines.extend(["", "### 3.2 Operating/failure boundary", ""])
    for behavior in meta["behaviors"]:
        cells = [item for item in entries if item["behavior"] == behavior]
        first_nonzero = next((item for item in cells
                              if item["variants"]["combined"]["blocks_total"] > 0), None)
        first_ci_confirmed = next((item for item in cells
                                   if item["variants"]["combined"]
                                   ["fpr_cluster_bootstrap_ci95"][0] > 0), None)
        first_majority = next((item for item in cells
                               if item["variants"]["combined"]["fpr_run_mean"] >= 0.5), None)
        if first_nonzero is None:
            lines.append(f"- `{behavior}`: không quan sát FP trong toàn bộ main grid; "
                         "đây không phải khẳng định FPR thật bằng 0.")
        else:
            text = (f"- `{behavior}`: FP đầu tiên xuất hiện ở target "
                    f"{first_nonzero['level']} (actual "
                    f"{first_nonzero['samples_mean']:.2f} samples/window)")
            if first_ci_confirmed is not None:
                text += (f"; cluster-bootstrap lower bound trở nên >0 tại target "
                         f"{first_ci_confirmed['level']} (actual "
                         f"{first_ci_confirmed['samples_mean']:.2f})")
            if first_majority is not None:
                text += (f"; FPR đạt ≥0.5 tại target {first_majority['level']} "
                         f"(actual {first_majority['samples_mean']:.2f}).")
            else:
                text += "."
            lines.append(text)

    same_as_volume = all(
        entry["variants"]["combined"]["blocks_total"]
        == entry["variants"]["volume"]["blocks_total"]
        for entry in entries if entry["behavior"] in ("random2048", "sequential")
    )
    lines.extend([
        "",
        "### 3.3 Ablation/mechanism",
        "",
        "- B1 legacy chặn mọi fragment nên FPR = 1 trong toàn main grid.",
        f"- Trên hai nguồn IPID đa dạng, B5 "
        f"{'trùng hoàn toàn với' if same_as_volume else 'không trùng hoàn toàn với'} "
        "B2 volume-only theo block count. Entropy/unique ratio không tạo thêm vùng "
        "bảo vệ ở các cell này.",
    ])

    if results.get("high_load"):
        lines.extend([
            "",
            "### 3.4 Exploratory high-load extension",
            "",
            "Phần này được đăng ký là exploratory và có raw per-run riêng; không dùng "
            "để thay đổi main-grid conclusion.",
            "",
            "| target s/win | actual s/win | actual frag/s | B5 FPR (95% run CI) | "
            "B2 FPR | entropy | unique |",
            "|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for row in results["high_load"]:
            lines.append(
                f"| {row['level']} | {row['samples_mean']:.2f} | "
                f"{row['actual_fragments_per_second_mean']:.2f} | "
                f"{row['combined']['fpr_run_mean']:.3f} "
                f"{fmt_ci(row['combined']['ci95'])} | "
                f"{row['volume']['fpr_run_mean']:.3f} | {row['entropy_mean']:.3f} | "
                f"{row['unique_ratio_mean']:.3f} |"
            )

    comparison = None
    if args.docker_comparison_json:
        comparison_path = args.docker_comparison_json.resolve()
        comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    sanity = None if comparison else docker_sanity(args.docker_sanity.resolve())
    lines.extend(["", "## 4. Docker low-load fidelity anchor", ""])
    if comparison:
        profiles = {item["profile"]: item for item in comparison["profiles"]}
        lines.extend([
            "Hai run benign Docker mới được chạy cho B0 (defense off) và B5 "
            "(proposed detector). Đây là sanity anchor ở tải thấp, không được trộn "
            "vào CI của campaign mô phỏng:",
            "",
            "| Profile | decisions | blocks | samples mean/max | decision/s | "
            "latency mean/p50/p95/p99 (ms) | resolver CPU mean/p95 | "
            "resolver memory mean/p95 (MiB) |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for profile_name in ("B0", "B5"):
            item = profiles[profile_name]
            lines.append(
                f"| {profile_name} | {item['decisions']} | {item['blocks']} | "
                f"{item['samples_mean']:.3f} / {item['samples_max']} | "
                f"{item['decision_rate_per_second']:.3f} | "
                f"{item['latency_mean_ms']:.3f} / {item['latency_p50_ms']:.3f} / "
                f"{item['latency_p95_ms']:.3f} / {item['latency_p99_ms']:.3f} | "
                f"{item['resolver_cpu_mean_percent']:.3f}% / "
                f"{item['resolver_cpu_p95_percent']:.3f}% | "
                f"{item['resolver_memory_mean_mib']:.3f} / "
                f"{item['resolver_memory_p95_mib']:.3f} |"
            )
        delta = comparison["b5_minus_b0"]
        lines.extend([
            "",
            "Chênh lệch mô tả B5−B0: latency mean "
            f"`{delta['latency_mean_ms']:+.3f} ms` "
            f"(`{delta['latency_mean_percent']:+.2f}%`), p50 "
            f"`{delta['latency_p50_ms']:+.3f} ms` "
            f"(`{delta['latency_p50_percent']:+.2f}%`), p95 "
            f"`{delta['latency_p95_ms']:+.3f} ms` "
            f"(`{delta['latency_p95_percent']:+.2f}%`), decision rate "
            f"`{delta['decision_rate_per_second']:+.3f}/s` "
            f"(`{delta['decision_rate_percent']:+.2f}%`). Không diễn giải p99 "
            "từ một run đơn do độ nhạy với outlier.",
            "",
            f"Chi tiết phép tính và raw paths: `{args.docker_comparison_json}`.",
        ])
    elif sanity:
        lines.extend([
            "Artifact Docker benign-on độc lập được dùng như sanity anchor ở tải thấp, "
            "không được trộn vào CI của campaign mô phỏng:",
            "",
            "| decisions | blocks | samples mean | entropy mean | unique mean | "
            "decision/s | latency p50/p95/p99 (ms) |",
            "|---:|---:|---:|---:|---:|---:|---:|",
            f"| {sanity['decisions']} | {sanity['blocks']} | {sanity['samples_mean']:.3f} | "
            f"{sanity['entropy_mean']:.4f} | {sanity['unique_ratio_mean']:.4f} | "
            f"{sanity['throughput_decisions_per_second']:.3f} | "
            f"{sanity['latency_p50_ms']:.3f} / {sanity['latency_p95_ms']:.3f} / "
            f"{sanity['latency_p99_ms']:.3f} |",
            "",
            f"Nguồn: `{sanity['source']}`.",
        ])
    else:
        lines.append("Không tìm thấy artifact Docker sanity đã đăng ký.")

    lines.extend([
        "",
        "## 5. Kết luận RQ1",
        "",
        "Campaign xác định được operating/failure boundary của B5 trong controlled "
        "emulation và cho thấy kết quả phụ thuộc mạnh vào hành vi IPID. Với nguồn IPID "
        "đa dạng, khi tải vượt vùng thấp thì B5 tiến gần B2 volume-only và false positive "
        "tăng mạnh. Vì vậy không được tuyên bố detector phân biệt benign/attack tổng quát "
        "chỉ từ E1; E2/E3 vẫn cần thiết.",
        "",
        "## 6. Threats to validity và metric chưa đóng",
        "",
        "- Đây là virtual-time Poisson controlled emulation dùng primitive detector thật, "
        "không phải Unbound/BIND hay IP fragmentation thật.",
        "- Simulator chèn FRAG2 hiện tại trước khi score, trong khi Docker auth phát "
        "FRAG1 rồi mới phát FRAG2 bất đồng bộ sau khoảng 3 ms. Đây là occupancy-stress "
        "model đã đăng ký, không phải mô phỏng chính xác event ordering của từng query.",
        "- Docker anchor chỉ ở tải thấp; topology tuần tự hiện không đạt dải 18–300 "
        "samples/window.",
        "- Latency/throughput/CPU/memory Docker chỉ là so sánh mô tả từ một run mỗi "
        "profile, không phải K=20 CI hay ước lượng overhead nhân quả.",
        "- Docker B0 và B5 chạy tuần tự, không phải randomized paired campaign; không "
        "suy diễn metric simulator thành metric hệ thống.",
        "- Main grid đóng RQ1 cho B5 và có đối chiếu cơ chế B1/B2; chưa phải ma trận "
        "hệ thống đầy đủ B0–B5 với overhead.",
        "- Với cell 0 FP, cluster bootstrap bằng 0 không ước lượng được unseen-event risk; "
        "run-any-FP exact interval được báo riêng và wording giữ ở mức '0 observed'.",
        "",
        "## 7. Reproducibility",
        "",
        "- Protocol: `e1_protocol.json`; validation: `validation.json`.",
        "- Per-run summaries: `e1_runs.csv` và `e1_high_load_runs.csv`.",
        "- Event-level raw: một JSONL/run dưới `raw_decisions/main/` và "
        "`raw_decisions/high_load/`; SHA-256 được pin trong per-run summaries.",
        *( [f"- Fresh Docker summary: `{args.docker_comparison_json}`."]
           if comparison else [] ),
        f"- Git: `{meta['git']['commit_full']}`; dirty at launch: `{meta['git']['dirty']}`.",
        "- Exact source snapshot + SHA-256: `source_snapshot/`.",
        f"- Command: `{' '.join(shlex.quote(str(part)) for part in meta['command'])}`.",
        f"- Campaign completed: {meta['completed_utc']}.",
        f"- Report generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}.",
        "",
    ])
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] wrote {output}")


if __name__ == "__main__":
    main()
