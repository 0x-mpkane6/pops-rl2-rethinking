"""Generate the canonical E2 report from a validated confirmatory artifact."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPORT_TITLE = (
    "E2 — Volume-matched benign vs attack của rule Rℓ2 ba biến"
)
VARIANT_LABELS = {
    "no_defense": "B0 — Không phòng vệ",
    "legacy": "B1 — Rℓ2 gốc",
    "volume": "B2 — volume-only",
    "entropy": "B3 — entropy-only",
    "unique": "B4 — unique-only",
    "combined": "B5 — combined",
}
BASELINE_VARIANTS = ("legacy", "volume", "entropy", "unique")


def fmt(value: float) -> str:
    return f"{value:.3f}"


def effect_sentence(effect: dict) -> str:
    result = effect["result"]
    verdict = effect["verdict"]
    meanings = {
        "meaningful_added_discrimination": "B5 có thêm ích lợi rõ ràng theo cổng đã đăng ký trước.",
        "practical_equivalence_within_registered_margin": (
            "Trong phép ablation B5–B2 này, hai rule gần như tương đương trong biên ±0,05 đã đăng ký trước."
        ),
        "meaningful_degradation": "B5 kém hơn B2 rõ ràng theo cổng đã đăng ký trước.",
        "inconclusive": "Chưa đủ bằng chứng để kết luận B5 tốt hơn, tương đương hay kém hơn B2.",
    }
    return (
        f"ΔJ trung bình = {result['mean']:+.3f}, CI 95% [{result['ci95'][0]:+.3f}, "
        f"{result['ci95'][1]:+.3f}]. {meanings[verdict]}"
    )


def table_for(rows: list[dict], attack: str) -> list[str]:
    selected = sorted([row for row in rows if row["attack_condition"] == attack],
                      key=lambda row: int(row["level"]))
    lines = [
        "| Tải | B2: benign bị bật | B2: condition attack bị bật | B5: benign bị bật | B5: condition attack bị bật | ΔJ (B5−B2), 95% CI |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in selected:
        b2 = row["variants"]["volume"]
        b5 = row["variants"]["combined"]
        delta = row["delta_j_combined_minus_volume"]
        lines.append(
            f"| {row['level']} | {fmt(b2['benign_trigger']['mean'])} | "
            f"{fmt(b2['attack_alert']['mean'])} | {fmt(b5['benign_trigger']['mean'])} | "
            f"{fmt(b5['attack_alert']['mean'])} | {fmt(delta['mean'])} "
            f"[{fmt(delta['ci95'][0])}, {fmt(delta['ci95'][1])}] |"
        )
    return lines


def failure_probe_table(rows: list[dict]) -> list[str]:
    """Show registered negative results instead of hiding them in prose."""
    by_key = {(row["attack_condition"], int(row["level"])): row for row in rows}
    lines = [
        "| Tải | B2 bật ở fixed/duplicate | B5 bật ở fixed/duplicate | ΔJ fixed, 95% CI | ΔJ duplicate, 95% CI |",
        "|---:|---:|---:|---:|---:|",
    ]
    for level in (24, 60, 120, 200):
        fixed = by_key[("attack_fixed_continuous", level)]
        duplicate = by_key[("attack_dup_sweep_continuous", level)]
        b2 = fixed["variants"]["volume"]["attack_alert"]["mean"]
        b5 = fixed["variants"]["combined"]["attack_alert"]["mean"]
        d_fixed = fixed["delta_j_combined_minus_volume"]
        d_duplicate = duplicate["delta_j_combined_minus_volume"]
        lines.append(
            f"| {level} | {fmt(b2)} | {fmt(b5)} | {fmt(d_fixed['mean'])} "
            f"[{fmt(d_fixed['ci95'][0])}, {fmt(d_fixed['ci95'][1])}] | "
            f"{fmt(d_duplicate['mean'])} [{fmt(d_duplicate['ci95'][0])}, "
            f"{fmt(d_duplicate['ci95'][1])}] |"
        )
    return lines


def feature_auprc_table(rows: list[dict]) -> list[str]:
    """Summarize score-level separation for the primary continuous sweep."""
    selected = sorted(
        [row for row in rows if row["attack_condition"] == "attack_sweep_continuous"],
        key=lambda row: int(row["level"]),
    )
    lines = [
        "| Tải | Volume | Entropy | Tỷ lệ IPID khác nhau |",
        "|---:|---:|---:|---:|",
    ]
    for row in selected:
        scores = row["feature_auprc_high_is_suspicious"]
        lines.append(
            f"| {row['level']} | {fmt(scores['volume']['mean'])} | "
            f"{fmt(scores['entropy']['mean'])} | {fmt(scores['unique_ratio']['mean'])} |"
        )
    return lines


def image_markdown(artifact_dir: Path, filename: str, alt_text: str) -> list[str]:
    """Link a generated figure only when it is present in the artifact."""
    figure = artifact_dir / "figures" / filename
    if not figure.is_file():
        return []
    return [f"![{alt_text}](figures/{filename})"]


def ablation_table(rows: list[dict], attack: str) -> list[str]:
    """Render all fixed-rule ablations at the registered operating point."""
    selected = sorted(
        [row for row in rows if row["attack_condition"] == attack],
        key=lambda row: int(row["level"]),
    )
    lines = [
        "| Tải | Biến thể | Synthetic TPR | Synthetic FNR | Synthetic FPR | Precision cân bằng | J |",
        "|---:|---|---:|---:|---:|---:|---:|",
    ]
    for row in selected:
        for variant in ("no_defense", "legacy", "volume", "entropy", "unique", "combined"):
            metrics = row["variants"][variant]
            lines.append(
                f"| {row['level']} | {VARIANT_LABELS[variant]} | "
                f"{fmt(metrics['synthetic_tpr']['mean'])} | "
                f"{fmt(metrics['synthetic_fnr']['mean'])} | "
                f"{fmt(metrics['synthetic_fpr']['mean'])} | "
                f"{fmt(metrics['balanced_precision']['mean'])} | "
                f"{fmt(metrics['youden_j']['mean'])} |"
            )
    return lines


def paired_ablation_table(effects: list[dict], attack: str) -> list[str]:
    by_baseline = {
        effect["baseline_variant"]: effect
        for effect in effects
        if effect["attack_condition"] == attack
    }
    lines = [
        "| B5 so với | ΔJ trung bình qua 4 mức tải, CI 95% | Diễn giải đăng ký trước |",
        "|---|---:|---|",
    ]
    for baseline in BASELINE_VARIANTS:
        effect = by_baseline[baseline]
        result = effect["result"]
        lines.append(
            f"| {VARIANT_LABELS[baseline]} | {fmt(result['mean'])} "
            f"[{fmt(result['ci95'][0])}, {fmt(result['ci95'][1])}] | {effect['verdict']} |"
        )
    return lines


def matched_tpr_table(rows: list[dict], attack: str) -> list[str]:
    """Report validation-locked scalar-score thresholds on the held-out test split."""
    selected = sorted(
        [row for row in rows if row["attack_condition"] == attack],
        key=lambda row: int(row["level"]),
    )
    lines = [
        "| Tải | Score | Ngưỡng khóa từ validation | PR-AUC | TPR test | FPR test | Precision cân bằng |",
        "|---:|---|---:|---:|---:|---:|---:|",
    ]
    for row in selected:
        for feature, label in (
            ("volume", "Volume"),
            ("entropy", "Entropy"),
            ("unique_ratio", "Unique ratio"),
        ):
            diagnostic = row["frozen_threshold_diagnostics"][feature]
            auprc = row["feature_auprc_high_is_suspicious"][feature]
            lines.append(
                f"| {row['level']} | {label} | {fmt(diagnostic['threshold'])} | "
                f"{fmt(auprc['mean'])} | "
                f"{fmt(diagnostic['test_attack_alert_rate']['mean'])} | "
                f"{fmt(diagnostic['test_benign_trigger_rate']['mean'])} | "
                f"{fmt(diagnostic['test_balanced_precision']['mean'])} |"
            )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Write the canonical E2 report")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    artifact_dir = args.artifact_dir.resolve()
    validation = json.loads((artifact_dir / "validation.json").read_text(encoding="utf-8"))
    if validation.get("status") != "PASS":
        raise RuntimeError("refusing to write a main E2 report before validation PASS")
    results = json.loads((artifact_dir / "e2_results.json").read_text(encoding="utf-8"))
    meta = results["meta"]
    analysis = results["analysis"]
    effects = {item["attack_condition"]: item for item in analysis["macro_effects"]}
    ablation_effects = analysis["paired_ablation_macro_effects"]
    rows = analysis["test_cells"]
    output = (args.out or artifact_dir / "E2_report.md").resolve()
    if output.exists() and not args.overwrite:
        raise FileExistsError(output)

    lines = [
        f"# {REPORT_TITLE}",
        "",
        f"**Run ID:** `{meta['run_id']}`  ",
        f"**Trạng thái kiểm tra:** `{validation['status']}`  ",
        "**Phạm vi:** mô phỏng có kiểm soát theo thời điểm query. Đây không phải thí nghiệm IP fragment thật; "
        "không đo poisoning, ASR, độ trễ, CPU hay hiệu năng triển khai.",
        "",
        "## Mục tiêu",
        "",
        "Rule đề xuất B5 block khi đồng thời đạt ba điều kiện trong cửa sổ 2 giây: số FRAG2, entropy Shannon "
        "của IPID và tỉ lệ IPID khác nhau. B1 là POPS/Rℓ2 gốc; B2, B3 và B4 lần lượt là ablation volume-only, "
        "entropy-only và unique-only.",
        "",
        "E2 đánh giá khả năng phân biệt của các cấu hình này khi benign và attack có cùng volume. Phân tích chính "
        "so sánh B5 với B2; các so sánh B5 với B1–B4 được báo cáo kèm khoảng tin cậy ghép cặp.",
        "",
        "## Thiết kế volume-matched benign vs attack",
        "",
        f"- Có {meta['split_runs']['test']} lần chạy độc lập cho mỗi ô kết quả chính (test), mỗi lần "
        f"{meta['queries_per_run']} lần chấm điểm.",
        "- Mỗi benign/attack pair dùng chung hoàn toàn thời điểm FRAG2 và thời điểm query. Vì vậy số mẫu trong "
        "từng cửa sổ là như nhau; khác biệt nếu có chỉ đến từ IPID/origin chứ không phải tải.",
        "- B0 là cấu hình không phòng vệ; B1 là rule POPS/Rℓ2 gốc; B2–B4 là các ablation; B5 là rule ba biến.",
        "- Trước test có một split kiểm tra generator và một split validation riêng. Test không được dùng để chọn "
        "ngưỡng hay chỉnh tốc độ.",
        "- Mỗi run giữ raw JSONL: event FRAG2, IPID, origin, timestamp, feature và các quyết định của biến thể rule. Validator "
        "đã đọc lại toàn bộ raw và tính lại các số trong bảng.",
        "- Hai mẫu so sánh chính là sweep IPID liên tục và sweep IPID theo đợt; IPID random là đối chứng. Fixed và duplicate "
        "là failure probe độ đa dạng IPID thấp, không phải kết quả poisoning/ASR.",
        "- Chưa có biến thể adaptive/high-entropy; không suy diễn kết quả thành khả năng né detector của đối thủ thật.",
        "",
        "## Cách đọc số",
        "",
        "- **Benign bị bật**: rule bật trên traffic benign control. Số thấp hơn là tốt hơn về mặt tránh TC/TCP không cần thiết.",
        "- **B1** là baseline POPS/Rℓ2 gốc; **B5** là rule ba biến; **B2–B4** là các ablation một biến.",
        "- **Condition attack bị bật**: rule bật trong condition stress tổng hợp. Đây chỉ là detector alert rate, **không phải** "
        "tỉ lệ ngăn poisoning thành công.",
        "- **J** = condition attack bị bật − benign bị bật. J càng cao thì rule càng tách được hai condition trong mô phỏng này.",
        "- **ΔJ (B5−baseline)** dương nghĩa là B5 tách tốt hơn baseline; âm nghĩa là kém hơn. Khoảng 95% được bootstrap theo run pair.",
        "- **Synthetic TPR/FNR/FPR** mô tả detector trên cặp condition tổng hợp, không phải poisoning/ASR. Precision là giá trị dưới tỷ lệ lớp 50:50 của thiết kế ghép cặp.",
        "- Bảng score-level chọn ngưỡng trên validation để đạt TPR mục tiêu 0,95, sau đó báo cáo TPR/FPR/precision và PR-AUC trên test duy nhất.",
        "",
        "## Kết quả",
        "",
        "### Sweep IPID liên tục",
        "",
        effect_sentence(effects["attack_sweep_continuous"]),
        "",
        *table_for(rows, "attack_sweep_continuous"),
        "",
        *image_markdown(
            artifact_dir,
            "Figure_1_net_separation.png",
            "Hình 1. J của B2 và B5 trên các sweep chính",
        ),
        "",
        "### Sweep IPID theo đợt",
        "",
        effect_sentence(effects["attack_sweep_bursty"]),
        "",
        *table_for(rows, "attack_sweep_bursty"),
        "",
        "### Phân phối entropy và unique ratio",
        "",
        "Phân phối được tổng hợp trên toàn bộ decision event của held-out test, theo profile và mức volume.",
        "",
        *image_markdown(
            artifact_dir,
            "Figure_3_feature_distributions.png",
            "Hình 3. Phân phối entropy và unique ratio trên test volume-matched",
        ),
        "",
        "### Baseline/ablation B0–B5 ở ngưỡng đã đăng ký",
        "",
        *ablation_table(rows, "attack_sweep_continuous"),
        "",
        "### Paired delta của B5 so với từng baseline",
        "",
        "#### Sweep liên tục",
        "",
        *paired_ablation_table(ablation_effects, "attack_sweep_continuous"),
        "",
        "#### Sweep theo đợt",
        "",
        *paired_ablation_table(ablation_effects, "attack_sweep_bursty"),
        "",
        "### PR-AUC và FPR tại TPR mục tiêu",
        "",
        "Các ngưỡng scalar bên dưới được khóa trên validation để đạt tỷ lệ alert attack ít nhất 0,95; "
        "bảng chỉ dùng held-out test để đánh giá. Đây là phân tích feature-level, không thay đổi ngưỡng B5 đã đăng ký.",
        "",
        *matched_tpr_table(rows, "attack_sweep_continuous"),
        "",
        *image_markdown(
            artifact_dir,
            "Figure_4_validation_locked_tpr_fpr.png",
            "Hình 4. FPR tại TPR mục tiêu của các score đơn biến",
        ),
        "",
        "### Kết quả âm: IPID cố định và IPID lặp",
        "",
        "- `attack_random_continuous` là negative control: IPID random có thể giống benign về phân phối.",
        "- `attack_fixed_continuous` và `attack_dup_sweep_continuous` là failure probe của detector: chúng chỉ cho biết "
        "rule bật hay không trong dòng IPID tổng hợp. Không được suy ra ASR, BFrag coverage hay poisoning success.",
        "",
        *failure_probe_table(rows),
        "",
        "Trong hai probe này B5 không bật, còn B2 vẫn bật; \u0394J của B5 âm tại mọi mức volume. Kết quả này được "
        "báo cáo như failure case của operating point `24/4,0/0,70`.",
        "",
        *image_markdown(
            artifact_dir,
            "Figure_2_delta_B5_minus_B2.png",
            "Hình 2. Hiệu ứng bổ sung của B5 so với B2",
        ),
        "",
        "### Phân tích bổ sung: PR-AUC/AUPRC của tín hiệu liên tục",
        "",
        *feature_auprc_table(rows),
        "",
        "Ở sweep liên tục tải 200, unique ratio đạt AUPRC cao trong khi B2 và B5 vẫn có cùng quyết định. Operating "
        "point `24/4,0/0,70` vì vậy chưa khai thác được khoảng cách score này.",
        "",
        "## Điều E2 chưa thể kết luận",
        "",
        "E2 không cho thấy B5 vượt B2 ở operating point `24/4,0/0,70` trên hai sweep chính. Kết luận về hiệu quả "
        "end-to-end so với POPS/Rℓ2 gốc cần E1/E5 với IP fragmentation thật, resolver thật, TC→TCP đầy đủ, và "
        "các metric ASR/latency/CPU.",
        "",
        "## File để kiểm tra lại",
        "",
        "- `e2_protocol.json`: thiết kế đã khóa trước khi chạy.",
        "- `e2_runs.csv`, `e2_decisions.csv.gz`, `raw_runs/`: số liệu gốc theo run/event.",
        "- `e2_results.json`, `e2_summary.csv`: tổng hợp chỉ từ test split.",
        "- `validation.json`: kết quả kiểm tra raw → bảng; phải là PASS trước khi dùng báo cáo này.",
    ]
    mode = "w" if args.overwrite else "x"
    with output.open(mode, encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"[+] wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
