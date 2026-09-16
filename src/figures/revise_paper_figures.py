"""Rebuild print-size figures and tables from frozen research artifacts.

No experiment is rerun, no threshold is selected, and no source artifact is
overwritten. All output is in rq_print_revision; identifiers follow the cloud
manuscript. Run from Code: python research/Report/figures/revise_paper_figures.py
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Rectangle
from matplotlib.text import Text
import numpy as np
from scipy.stats import beta

import generate_rq_figures_en as original

ROOT = original.REPO_ROOT
EXP = original.EXPERIMENT_ROOT
OUT = Path(__file__).resolve().parent / "rq_print_revision"
WIDTH_MM = 122.0  # Measured figure width in c_SoICT_Khang_Anh (3).pdf.
WIDTH = WIDTH_MM / 25.4
SEED = 20260912
SOURCES: dict[str, str] = {}
AUDIT: dict = {"print_width_mm": WIDTH_MM, "minimum_font_pt": 8.5, "figures": {}}
POLICIES = ["B0_OFF", "B1_RL2_TC", "B5_LOCKED_TC", "RFC_DROP_NATIVE"]
SHORT = dict(zip(POLICIES, ["B0", "B1+TC", "B5+TC", "Native drop"]))
CAMPAIGNS = {
    "original": EXP / "E5/output/E5-routed-s20260902-r001",
    "factorial": EXP / "E5/output/E5-factorial-s20260911-r003",
}
BLUE, ORANGE, GREEN = "#0072B2", "#D55E00", "#009E73"
GRAY, PURPLE = "#666666", "#AA4499"


def track(path: Path) -> bytes:
    data = path.read_bytes()
    SOURCES[str(path.relative_to(ROOT)).replace("\\", "/")] = hashlib.sha256(data).hexdigest()
    return data


def read_csv(path: Path) -> list[dict]:
    return list(csv.DictReader(track(path).decode("utf-8-sig").splitlines()))


def read_json(path: Path):
    return json.loads(track(path))


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in track(path).splitlines() if line.strip()]


def write_json(name: str, data) -> None:
    (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def write_csv(name: str, rows: list[dict]) -> None:
    with (OUT / name).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def configure() -> None:
    original.configure_style()
    plt.rcParams.update({
        "font.size": 8.5, "axes.labelsize": 8.5, "axes.titlesize": 9,
        "xtick.labelsize": 8.5, "ytick.labelsize": 8.5, "legend.fontsize": 8.5,
        "legend.title_fontsize": 8.5, "lines.markersize": 4,
        "lines.linewidth": 1.2, "mathtext.default": "regular",
    })


def save(fig, stem: str) -> None:
    fig.canvas.draw()
    texts = [t for t in fig.findobj(Text) if t.get_visible() and t.get_text()]
    texts.extend(cell.get_text() for ax in fig.axes for table in ax.tables for cell in table.get_celld().values() if cell.get_text().get_text())
    minimum = min(t.get_fontsize() for t in texts)
    assert minimum >= 8.5, (stem, minimum)
    renderer = fig.canvas.get_renderer()
    bounds = fig.bbox
    clipped = []
    for text in texts:
        # Matplotlib creates unused major tick labels beyond explicit limits.
        box = text.get_window_extent(renderer)
        if text.get_clip_on():
            continue
        if box.x0 < bounds.x0 - 1 or box.y0 < bounds.y0 - 1 or box.x1 > bounds.x1 + 1 or box.y1 > bounds.y1 + 1:
            clipped.append(text.get_text())
    if clipped:
        raise ValueError(f"Text outside the {WIDTH_MM} mm canvas in {stem}: {clipped}")
    for ext, args in [("png", {"dpi": 600}), ("pdf", {}), ("svg", {})]:
        # Preserve physical dimensions; tight cropping would alter print scale.
        fig.savefig(OUT / f"{stem}.{ext}", facecolor="white", **args)
    AUDIT["figures"][stem] = {"width_mm": WIDTH_MM, "height_mm": float(fig.get_figheight() * 25.4), "min_font_pt": minimum, "clipped_text": clipped}
    plt.close(fig)


def line(ax, x, rows, color, marker, linestyle, label, low="ci_low", high="ci_high"):
    y = np.array([float(r["mean"]) for r in rows])
    lo = np.array([float(r[low]) for r in rows])
    hi = np.array([float(r[high]) for r in rows])
    ax.fill_between(x, lo, hi, color=color, alpha=.10, linewidth=0)
    return ax.plot(x, y, color=color, marker=marker, markerfacecolor="white", linestyle=linestyle, label=label)[0]


def boundary() -> None:
    root = original.E1_LEVELS.parent
    registered_runs = read_csv(root / "e1_runs.csv")
    run_rows = []
    for row in registered_runs:
        raw = root / row["raw_decisions_file"]
        decisions = read_jsonl(raw)
        assert SOURCES[str(raw.relative_to(ROOT)).replace("\\", "/")] == row["raw_decisions_sha256"]
        assert len(decisions) == int(row["decisions"]) == 300
        initial = [d["samples"] >= 24 and d["entropy"] >= 4 and d["unique_ratio"] >= .70 for d in decisions]
        assert all(a == d["block_combined"] for a, d in zip(initial, decisions))
        locked = [d["samples"] >= 8 and d["entropy"] >= 6 and d["unique_ratio"] >= .90 for d in decisions]
        for label, flags in [("initial", initial), ("locked", locked)]:
            run_rows.append({"behavior": row["behavior"], "level": int(row["level_samples_per_window"]), "run": int(row["run_idx"]), "configuration": label, "decisions": len(flags), "triggers": sum(flags), "rate": float(np.mean(flags))})
    assert len(run_rows) == 3 * 8 * 20 * 2
    levels = sorted({r["level"] for r in run_rows})
    groups = defaultdict(list)
    for row in run_rows:
        groups[(row["behavior"], row["level"], row["configuration"])].append(row["rate"])
    summary = []
    for i, ((behavior, level, configuration), rates) in enumerate(sorted(groups.items())):
        assert len(rates) == 20
        mean, low, high = original.bootstrap_ci(rates, SEED+i)
        summary.append({"behavior": behavior, "level": level, "configuration": configuration, "mean": mean, "ci_low": low, "ci_high": high, "runs": 20})
    write_csv("benign_boundary_runs.csv", run_rows)
    write_csv("benign_boundary_summary.csv", summary)
    fig, ax = plt.subplots(figsize=(WIDTH, 2.85))
    fig.subplots_adjust(left=.14, right=.985, bottom=.29, top=.96)
    behaviors = [("random2048", "Random (2,048)", BLUE, "o"), ("sequential", "Sequential", ORANGE, "s"), ("smallpool16", "Pool of 16", GREEN, "^")]
    for behavior, label, color, marker in behaviors:
        for config, style in [("initial", ":"), ("locked", "-")]:
            selected = sorted([r for r in summary if r["behavior"] == behavior and r["configuration"] == config], key=lambda r:r["level"])
            line(ax, levels, selected, color, marker, style, f"{label}, {config}")
    ax.set_xscale("log")
    ax.set_xticks(levels, [str(v) for v in levels]); ax.minorticks_off()
    ax.set_ylim(-.03,1.03); ax.set_yticks([0,.25,.5,.75,1])
    ax.set_xlabel("Target fragments per 2-s window")
    ax.set_ylabel("Benign trigger rate")
    original.style_axes(ax)
    handles = [Line2D([], [], color=c, marker=m, label=l) for _,l,c,m in behaviors]
    fig.legend(handles=handles, loc="lower center", bbox_to_anchor=(.54,.075), ncol=3, frameon=False, handlelength=1.3, columnspacing=.8)
    fig.legend(handles=[Line2D([], [], color=GRAY, linestyle=":", label="Initial (24, 4, 0.70)"),Line2D([], [], color=GRAY, linestyle="-", label="Locked (8, 6, 0.90)")], loc="lower center", bbox_to_anchor=(.54,.0), ncol=2, frameon=False, handlelength=1.6, columnspacing=1)
    save(fig, "RQ1_benign_boundary")
    AUDIT["boundary"] = {"raw_runs": len(registered_runs), "decisions": len(registered_runs)*300, "initial_predictions_match_raw": True, "locked_analysis": "post-hoc rescoring of existing benign traces; no new traffic; no retuning", "bootstrap": "5,000 run resamples per cell"}


def discrimination() -> None:
    rows = read_csv(original.E2_SUMMARY)
    delta = [r for r in rows if r["metric"] == "delta_j_combined_minus_volume" and r["attack_condition"] in {"attack_sweep_continuous", "attack_sweep_bursty"}]
    assert len(delta) == 8
    assert all(float(r[k]) == 0 for r in delta for k in ["mean","ci95_lo","ci95_hi"])
    fig, ax = plt.subplots(figsize=(WIDTH, 2.4))
    fig.subplots_adjust(left=.14,right=.98,top=.97,bottom=.34)
    for profile, profile_label, style in [("continuous","Continuous","-"),("bursty","Bursty","--")]:
        for feature,label,color,marker in [("entropy","Entropy",PURPLE,"s"),("unique_ratio","Unique ratio",BLUE,"o")]:
            s = sorted([r for r in rows if r["metric"]=="auprc_high_is_suspicious" and r["profile"]==profile and r["variant_or_feature"]==feature and r["attack_condition"]==f"attack_sweep_{profile}"], key=lambda r:int(r["level"]))
            assert len(s)==4
            line(ax,[int(r["level"]) for r in s],s,color,marker,style,f"{label}: {profile_label.lower()}",low="ci95_lo",high="ci95_hi")
    ax.axhline(.5,color=GRAY,linewidth=.7,linestyle=":")
    ax.set_xticks([24,60,120,200]); ax.set_ylim(.45,1.02)
    ax.set_yticks([.5,.75,1]); ax.set_ylabel("PR-AUC"); ax.set_xlabel("Target fragments per 2-s window")
    original.style_axes(ax)
    fig.legend(*ax.get_legend_handles_labels(),loc="lower center",bbox_to_anchor=(.53,.0),ncol=2,frameon=False,columnspacing=1,handlelength=1.7)
    save(fig,"RQ1_volume_matched_discrimination")
    AUDIT["removed_figure_3A"] = {"cells":8,"delta_J_and_both_CI_limits_all_zero":True}


def calibration() -> None:
    rows=read_csv(original.E3_GRID); tests=read_csv(original.E3_TEST)
    ns=sorted({int(r["min_samples"]) for r in rows})
    hs=sorted({float(r["entropy_threshold"]) for r in rows})
    us=sorted({float(r["unique_ratio_threshold"]) for r in rows})
    assert len(rows)==60
    matrix=np.full((len(hs),len(ns)*len(us)),np.nan)
    for r in rows:
        matrix[hs.index(float(r["entropy_threshold"])),ns.index(int(r["min_samples"]))*len(us)+us.index(float(r["unique_ratio_threshold"]))]=float(r["macro_delta_J_new_vs_B2"])*100
    assert np.isfinite(matrix).all()
    fig=plt.figure(figsize=(WIDTH,3.35))
    ax=fig.add_axes([.13,.64,.73,.24])
    im=ax.imshow(matrix,origin="lower",aspect="auto",cmap="cividis",vmin=0,vmax=1)
    ax.set_yticks(range(len(hs)),[f"{h:g}" for h in hs]);ax.set_ylabel("Entropy threshold")
    ax.set_xticks(range(12),[f"{u:g}" for _ in ns for u in us]);ax.set_xlabel("Unique-ratio threshold")
    for k,n in enumerate(ns):
        ax.text(3*k+1,4.65,f"N = {n}",ha="center",va="bottom",fontsize=8.5)
        if k: ax.axvline(3*k-.5,color="white",linewidth=1.5)
    ax.add_patch(Rectangle((1.5,3.5),1,1,fill=False,edgecolor="#D55E00",linewidth=1.5))
    cax=fig.add_axes([.885,.64,.025,.24]);cb=fig.colorbar(im,cax=cax,ticks=[0,.5,1]);cb.set_label("ΔJ (pp)",labelpad=3)
    fig.text(.02,.955,"A  Validation grid (60 candidates)",fontweight="bold",fontsize=9)
    ax=fig.add_axes([.13,.15,.82,.31])
    metrics=["attack_alert_rate","benign_trigger_rate","FNR"]
    variants=[("new_B5","Locked B5",BLUE),("B2","B2",GRAY),("old_B5","Initial B5",ORANGE)]
    for i,(v,label,color) in enumerate(variants):
        s=[next(r for r in tests if r["scope"]=="primary_macro" and r["variant_or_comparison"]==v and r["metric"]==m) for m in metrics]
        means=np.array([float(r["mean"]) for r in s]);lo=np.array([float(r["ci95_low"]) for r in s]);hi=np.array([float(r["ci95_high"]) for r in s])
        ax.bar(np.arange(3)+(i-1)*.24,means,.24,color=color,label=label,yerr=[means-lo,hi-means],capsize=2,error_kw={"elinewidth":.8})
    ax.set_xticks(range(3),["Attack alert","Benign trigger","FNR"]);ax.set_yticks([0,.5,1]);ax.set_ylim(0,1.04);ax.set_ylabel("Macro rate")
    original.style_axes(ax)
    fig.text(.02,.50,"B  Held-out performance",fontweight="bold",fontsize=9)
    fig.legend(*ax.get_legend_handles_labels(),loc="lower center",bbox_to_anchor=(.54,.01),frameon=False,ncol=3,handlelength=1.4,columnspacing=1.1)
    save(fig,"RQ2_threshold_calibration")
    write_csv("threshold_grid_all_60.csv",rows)


def failure_modes() -> None:
    rows=read_csv(original.E3_TEST)
    specs=[("attack_fixed_continuous","Fixed",ORANGE,"o"),("attack_dup_sweep_continuous","Duplicate sweep",BLUE,"s"),("attack_random_continuous","Random control",GRAY,"^")]
    fig,axes=plt.subplots(1,2,figsize=(WIDTH,2.85))
    fig.subplots_adjust(left=.12,right=.975,bottom=.34,top=.86,wspace=.35)
    def select(c,v,m):
        s=sorted([r for r in rows if r["scope"] in {"failure_probes","negative_control"} and r["attack_condition"]==c and r["variant_or_comparison"]==v and r["metric"]==m],key=lambda r:int(r["level"]))
        assert len(s)==4
        return s
    for c,label,color,marker in specs:
        s=select(c,"Delta_J_new_B5_minus_B2","Delta_J")
        x=np.array([int(r["level"]) for r in s])
        for ax,selected,style,mark in [(axes[0],s,"-",marker),(axes[1],select(c,"new_B5","attack_alert_rate"),"-","o"),(axes[1],select(c,"new_B5","benign_trigger_rate"),"--","s")]:
            y=np.array([float(r["mean"]) for r in selected]);lo=np.array([float(r["ci95_low"]) for r in selected]);hi=np.array([float(r["ci95_high"]) for r in selected])
            ax.errorbar(x,y,yerr=[y-lo,hi-y],color=color,marker=mark,linestyle=style,markerfacecolor="white",capsize=2,elinewidth=.8)
    axes[0].set_ylim(-1.08,.06);axes[0].set_yticks([-1,-.5,0]);axes[0].set_ylabel("ΔJ (locked B5 − B2)")
    axes[1].set_ylim(-.06,1.08);axes[1].set_yticks([0,.5,1]);axes[1].set_ylabel("Rate")
    axes[0].set_title("A  Separation",loc="left",fontweight="bold")
    axes[1].set_title("B  Triggering",loc="left",fontweight="bold")
    for ax in axes:
        ax.set_xticks([24,60,120,200]);original.style_axes(ax)
    fig.text(.55,.20,"Target fragments per 2-s window",ha="center",fontsize=8.5)
    # Share the three traffic colors; B needs only two metric legend entries.
    fig.legend(handles=[Line2D([],[],color=c,label=l,linewidth=2) for _,l,c,_ in specs],loc="lower center",bbox_to_anchor=(.54,.075),frameon=False,ncol=3,handlelength=1,columnspacing=.8)
    fig.legend(handles=[Line2D([],[],color="black",marker="o",markerfacecolor="white",linestyle="-",label="Attack alert"),Line2D([],[],color="black",marker="s",markerfacecolor="white",linestyle="--",label="Benign trigger")],loc="lower center",bbox_to_anchor=(.54,0),frameon=False,ncol=2,handlelength=1.5)
    save(fig,"RQ3_failure_modes")


def latex_table(stem: str, caption: str, label: str, headers: list[str], rows: list[list[str]], widths: list[float] | None = None) -> None:
    spec="l"+"r"*(len(headers)-1)
    body="\n".join(" & ".join(row)+r" \\" for row in [headers]+rows)
    # Actual typeset table, with an explicit 8.5 pt floor and no resizebox.
    tex=(r"\begin{table}[t]"+"\n"+r"\centering"+"\n"+r"\caption{"+caption+"}\n"+r"\label{"+label+"}\n"+r"\begingroup\fontsize{9}{10.8}\selectfont"+"\n"+r"\setlength{\tabcolsep}{3pt}"+"\n"+r"\begin{tabular}{"+spec+"}\n"+r"\hline"+"\n"+body.splitlines()[0]+"\n"+r"\hline"+"\n"+"\n".join(body.splitlines()[1:])+"\n"+r"\hline"+"\n"+r"\end{tabular}"+"\n"+r"\endgroup"+"\n"+r"\end{table}"+"\n")
    (OUT/f"{stem}.tex").write_text(tex,encoding="utf-8")
    # Vector/raster preview for inspection; use the .tex table in the paper.
    height=.24*(len(rows)+1)+.12
    fig,ax=plt.subplots(figsize=(WIDTH,height));ax.axis("off")
    fig.subplots_adjust(left=.005,right=.995,bottom=.02,top=.98)
    display=lambda s:s.replace(r"\%","%").replace(r"\textemdash{}","—").replace(r"\,", " ").replace("--","–")
    table=ax.table(cellText=[[display(s) for s in row] for row in rows],colLabels=[display(s) for s in headers],cellLoc="center",loc="center",colWidths=widths)
    table.auto_set_font_size(False);table.set_fontsize(8.5);table.scale(1,1.2)
    for (r,c),cell in table.get_celld().items():
        cell.set_edgecolor("#DDDDDD");cell.set_linewidth(.3)
        if r==0:cell.set_facecolor("#EAF0F5");cell.set_text_props(weight="bold")
        elif r%2==0:cell.set_facecolor("#F8F9FA")
    save(fig,stem)


def runtime() -> None:
    metrics_out=[]
    for name,root in CAMPAIGNS.items():
        runs=read_json(root/"metrics_confirmatory.json")
        assert len(runs)==320 and {r["policy"] for r in runs}==set(POLICIES)
        assert read_json(root/"validation_confirmatory.json")["status"]=="PASS"
        by_cell=defaultdict(list)
        for run in runs: by_cell[(run["policy"],run["workload"])].append(run)
        assert len(by_cell)==16
        for (policy,workload),cell in sorted(by_cell.items()):
            assert len(cell)==20 and sorted(r["rep"] for r in cell)==list(range(1,21))
            assert all(r["n_trials"]==50 for r in cell)
            rates={}
            for field in ["tc_injection_rate","tcp_retry_rate","noanswer_rate","legitimate_answer_rate","forged_tail_drop_rate","trigger_rate"]:
                rates[field]=float(np.mean([r[field] for r in cell]))
            malicious=[r.get("malicious_answer_rate",r["run_asr"]) or 0 for r in cell]
            row={"campaign":name,"policy":policy,"workload":workload,"runs":20,"trials":1000,**rates,"malicious_answer_rate":float(np.mean(malicious))}
            row["any_malicious_runs"]=sum(r["any_poison"] for r in cell)
            for prefix,k in [("any_malicious",row["any_malicious_runs"])]:
                row[prefix+"_ci_low"]=float(beta.ppf(.025,k,20-k+1)) if k else 0.
                row[prefix+"_ci_high"]=float(beta.ppf(.975,k+1,20-k)) if k<20 else 1.
            if name=="factorial":
                row["cache_insertion_rate"]=float(np.mean([r["cache_insertion_rate"] for r in cell]))
                row["detector_active_at_query_rate"]=float(np.mean([r["detector_active_at_query_rate"] for r in cell]))
            else:
                row["cache_insertion_rate"]=None
                row["detector_active_at_query_rate"]=None
            # DNS interval only; client_latency_ms includes cache-after overhead.
            latency_values=[];successful_values=[]; medians=[];p95s=[]
            if workload.startswith("BENIGN"):
                for run in cell:
                    trials=read_jsonl(root/run["artifact_dir"]/"trials.jsonl")
                    assert len(trials)==50 and len({t["trial_id"] for t in trials})==50
                    values=[]
                    for t in trials:
                        elapsed=(t["query_end_mono_ns"]-t["query_start_mono_ns"])/1e6
                        # The logger reads monotonic_ns twice, once for the end
                        # timestamp and immediately again for latency_ms.
                        value=t["latency_ms"]
                        assert 0 <= value-elapsed < .05
                        assert value>=0
                        values.append(value)
                        if t["status"]=="legitimate_answer": successful_values.append(value)
                    latency_values.extend(values)
                    medians.append(float(np.median(values)));p95s.append(float(np.percentile(values,95)))
                    assert abs(medians[-1]-run["query_latency_median_ms"])<1e-6
                row.update({"latency_median_ms":float(np.median(latency_values)),"latency_p95_ms":float(np.percentile(latency_values,95)),"mean_run_median_ms":float(np.mean(medians)),"mean_run_p95_ms":float(np.mean(p95s)),"latency_trials":len(latency_values),"successful_latency_trials":len(successful_values)})
            else:
                row.update({k:None for k in ["latency_median_ms","latency_p95_ms","mean_run_median_ms","mean_run_p95_ms","latency_trials","successful_latency_trials"]})
            metrics_out.append(row)
        load_order={"BENIGN_LOW":0,"BENIGN_BOUNDARY":1,"BENIGN_DIVERSE_MODERATE":0,"BENIGN_DIVERSE_HIGH":1}
        benign=sorted([r for r in metrics_out if r["campaign"]==name and r["workload"].startswith("BENIGN")],key=lambda r:(POLICIES.index(r["policy"]),load_order[r["workload"]]))
        workload_labels={"BENIGN_LOW":"2.5/s","BENIGN_BOUNDARY":"12/s","BENIGN_DIVERSE_MODERATE":"12/s","BENIGN_DIVERSE_HIGH":"200/s"}
        cells=[[SHORT[r["policy"]],workload_labels[r["workload"]],f'{100*r["tc_injection_rate"]:.1f}',f'{100*r["tcp_retry_rate"]:.1f}',f'{r["latency_median_ms"]:.1f}',f'{r["latency_p95_ms"]:.1f}',f'{100*r["noanswer_rate"]:.1f}'] for r in benign]
        caption=("Benign runtime costs"+(" in the diverse-IPID factorial follow-up" if name=="factorial" else " in the original runtime campaign")+r". Rates are percentages; latency is median and 95th percentile (ms) of 1,000 query attempts per cell, including timeouts and excluding cache probes. These quantiles are descriptive; 20 recreated-stack runs are the independent units. Native dropping uses concurrent queries; the other policies use sequential queries.")
        latex_table(f"runtime_benign_cost_{name}",caption,f"tab:benign-cost-{name}",["Policy","Load",r"TC \%",r"TCP \%","Med. ms","p95 ms",r"None \%"],cells,[.185,.10,.12,.12,.165,.165,.145])
        write_csv(f"runtime_benign_cost_{name}.csv",benign)
    write_csv("runtime_all_cells.csv",metrics_out)
    # Original Figure 6 becomes one outcomes table plus two compact mechanism rows.
    attacks=[r for r in metrics_out if r["campaign"]=="original" and r["workload"].startswith("ATTACK")]
    attacks.sort(key=lambda r:(POLICIES.index(r["policy"]),r["workload"]))
    labels={"ATTACK_FIXED_MATCHED":"Fixed","ATTACK_SWEEP_FLOOD":"Flood"}
    cells=[[SHORT[r["policy"]],labels[r["workload"]],f'{100*r["malicious_answer_rate"]:.1f}',f'{100*r["noanswer_rate"]:.1f}',str(r["any_malicious_runs"])+"/20",f'{100*r["any_malicious_ci_low"]:.1f}--{100*r["any_malicious_ci_high"]:.1f}'] for r in attacks]
    latex_table("RQ4_runtime_outcomes",r"Original runtime outcomes, replacing the former runtime figure. Malicious-answer and no-answer rates are trial percentages (1,000 trials per cell); affected runs contain at least one malicious answer. Intervals are exact 95\% Clopper--Pearson intervals for the affected-run percentage; 20 recreated-stack runs per cell. Cache insertion was not independently verified in this campaign.","tab:rq4-runtime",["Policy","Attack",r"Mal. \%",r"None \%","Runs",r"95\% CI"],cells,[.20,.12,.13,.14,.14,.27])
    b5=[r for r in attacks if r["policy"]=="B5_LOCKED_TC"]
    latex_table("RQ4_runtime_mechanism",r"Locked-B5 mechanism rates in the original campaign, in percent. Each cell contains 20 recreated-stack runs and 1,000 trials. Each of the four run-level rates is constant within a workload, so its percentile bootstrap 95\% interval equals its estimate.","tab:rq4-mechanism",["Attack",r"Trigger \%",r"Drop \%",r"TC \%",r"TCP \%"],[[labels[r["workload"]]]+[f'{100*r[k]:.1f}' for k in ["trigger_rate","forged_tail_drop_rate","tc_injection_rate","tcp_retry_rate"]] for r in b5])
    factorial=[r for r in metrics_out if r["campaign"]=="factorial"]
    factorial_order={"BENIGN_DIVERSE_MODERATE":0,"BENIGN_DIVERSE_HIGH":1,"ATTACK_DIVERSE_MODERATE":2,"ATTACK_DIVERSE_HIGH":3}
    factorial.sort(key=lambda r:(POLICIES.index(r["policy"]),factorial_order[r["workload"]]))
    labels2={"ATTACK_DIVERSE_MODERATE":"Attack 12","ATTACK_DIVERSE_HIGH":"Attack 200","BENIGN_DIVERSE_MODERATE":"Benign 12","BENIGN_DIVERSE_HIGH":"Benign 200"}
    cells=[[SHORT[r["policy"]],labels2[r["workload"]],f'{100*r["detector_active_at_query_rate"]:.1f}',f'{100*r["malicious_answer_rate"]:.1f}',f'{100*r["cache_insertion_rate"]:.1f}',f'{100*r["noanswer_rate"]:.1f}'] for r in factorial]
    latex_table("runtime_factorial_results",r"Diverse-IPID factorial follow-up: forged-tail injection on/off crossed with background load (12 or 200 non-initial fragments/s). B5 state is the reconstructed locked-B5 state at query time, including passive state under other policies. All outcome columns are trial percentages; 20 runs and 1,000 trials per cell. Cache denotes a malicious A record present at the immediate post-query probe, not long-term persistence. This campaign is analyzed separately from the original runtime experiment.","tab:runtime-factorial",["Policy","Traffic /s",r"B5 state \%",r"Mal. \%",r"Cache \%",r"None \%"],cells,[.19,.21,.18,.13,.15,.14])
    AUDIT["runtime"]={"campaigns":{n:p.name for n,p in CAMPAIGNS.items()},"runs_per_campaign":320,"trials_per_campaign":16000,"benign_raw_trials_checked":16000,"latency_field":"latency_ms, cross-checked against monotonic query end minus start within 0.05 ms (two adjacent logger clock reads)", "latency_aggregation":"pooled descriptive quantiles of all attempts, including timeouts; no trial-independent inference", "campaigns_not_pooled":True}


def notes() -> None:
    extended=read_csv(EXP/"E3-Extend/e3_extend_sensitivity_grid.csv")
    assert len(extended)==16
    compact=[]
    fields=["macro_attack_alert_rate","macro_benign_trigger_rate","macro_FNR","macro_delta_J_new_vs_B2"]
    for h in [7.,8.]:
        for u in [.95,.99]:
            matches=[r for r in extended if float(r["entropy_threshold"])==h and float(r["unique_ratio_threshold"])==u]
            assert len(matches)==4
            assert all(len({float(r[k]) for r in matches})==1 for k in fields)
            compact.append([f"{h:g}",f"{u:.2f}"]+[f"{100*float(matches[0][k]):.2f}" for k in fields])
    latex_table("validation_sensitivity_posthoc",r"Post-hoc validation-only threshold sensitivity. All rates are percentages and $\Delta J$ is in percentage points. Each row has identical outcomes for N=8, 16, 24, and 48. Values are descriptive; no threshold is selected and the held-out partition is not re-evaluated.","tab:validation-sensitivity",["H","U",r"Alert \%",r"Benign \%",r"FNR \%",r"Delta J pp"],compact)
    captions={
        "RQ1_benign_boundary": ("fig:rq1-benign-boundary",r"Benign trigger rates of initial and locked B5 on the same recorded traces. Colors denote IPID behavior; dotted and solid lines denote initial and locked configurations. Bands are percentile 95\% intervals from 5,000 run-level bootstrap samples, with 20 runs and 300 decisions per run in each cell. Locked-B5 curves are post-hoc rescoring without retuning; target load differs from realized window occupancy."),
        "RQ1_volume_matched_discrimination":("fig:rq1-volume-matched",r"Score-level discrimination under volume matching. PR-AUC for entropy and unique-IPID ratio under continuous and bursty traffic; bands denote paired-trace 95\% confidence intervals, with 20 pairs per cell."),
        "RQ2_threshold_calibration":("fig:rq2-calibration",r"Validation selection and held-out performance. Panel A consolidates all 60 candidates into one heatmap; column groups denote N and the outlined cell marks the locked choice. Color represents validation $\Delta J$ in percentage points. Panel B shows held-out macro rates with stratified paired-trace 95\% bootstrap confidence intervals (six pairs per primary cell)."),
        "RQ3_failure_modes":("fig:rq3-failure-modes",r"Failure probes and negative control for locked B5. Panel A shows paired $\Delta J$ relative to B2; Panel B shows attack-alert and matched benign-trigger rates. Traffic colors are shared; solid circles and dashed squares in B denote attack alert and benign trigger. Error bars are paired-trace 95\% confidence intervals, with six pairs per cell. Fixed-IPID and duplicate-sweep estimates overlap; none was used for threshold selection."),
    }
    tex=[]
    for stem,(label,caption) in captions.items():
        tex.append(r"\begin{figure}[t]"+"\n"+r"\centering"+"\n"+r"\includegraphics[width=\linewidth]{figure/"+stem+".pdf}\n"+r"\caption{"+caption+"}\n"+r"\label{"+label+"}\n"+r"\end{figure}"+"\n")
    (OUT/"figure_blocks.tex").write_text("\n".join(tex),encoding="utf-8")
    (OUT/"text_replacements.tex").write_text(r"""% Figure 3A is removed. Keep this sentence in RQ1; do not add it twice.
Across the eight volume-matched primary cells, initial B5 and B2 have identical
separation, with macro $\Delta J=0$ (95\% CI $[0,0]$).

% Replace/extend the existing paragraph explaining the redundant N=8 gate.
Since $H\leq\log_2 n$, the locked rule requires at least 64 fragments per
two-second window together with high IPID diversity ($U\geq0.90$); at the
boundary $n=64$, all IPIDs must be distinct to attain $H=6$.
These are necessary conditions, not a replacement for the complete entropy gate.

% Replace the Figure 6 introduction and references in RQ4.
Table~\ref{tab:rq4-runtime} reports runtime outcomes.
For locked B5, detector triggering, forged-tail dropping, TC injection, and
TCP retry are all absent under the matched fixed-IPID attack and all present
in every sweep-flood trial.
% If a separate mechanism table is needed, also insert RQ4_runtime_mechanism.tex.
Table~\ref{tab:benign-cost-original} quantifies the corresponding benign costs.
The follow-up factorial outcomes and benign costs are reported separately in
Tables~\ref{tab:runtime-factorial} and~\ref{tab:benign-cost-factorial}.

% OPTIONAL: Table 1 in the available manuscript defines B0--B5 (not settings).
% Only if removing that table: replace its prose reference with this paragraph.
The baselines comprise no defense (B0), the original POPS rule (B1),
volume-only detection $n\geq N$ (B2), entropy-only detection $H\geq H_0$ (B3),
uniqueness-only detection $U\geq U_0$ (B4), and their conjunction (B5).
""",encoding="utf-8")
    (OUT/"README.md").write_text("""# Print revision and existing-log additions

Upload the four `RQ*.pdf` figures (or the matching PNGs) to the cloud project's
`figure/` folder. They use the current cloud filenames. Replace figure blocks
using `figure_blocks.tex`; use `text_replacements.tex` for changed references.
No cloud manuscript has been modified. Original figures and raw artifacts remain available.

All figures have a fixed **122 mm** width, measured from the available manuscript,
with **8.5 pt or larger** text. Include at `width=\\linewidth` in the same 122 mm
text block; do not reduce below 114.83 mm (which would lower 8.5 pt below 8 pt).
PNG export is 600 dpi; PDF/SVG are vector. LaTeX tables use 9 pt explicitly and no
`resizebox`. The PNG/PDF table companions are previews; prefer real `.tex` tables.

| Former item | Replacement |
|---|---|
| Figure 2 | `RQ1_benign_boundary`: initial and locked B5, same recorded benign traces |
| Figure 3 | `RQ1_volume_matched_discrimination`: PR-AUC only; remove the A/B wording |
| Figure 4 | `RQ2_threshold_calibration`: one heatmap with all 60 candidates, plus held-out panel B |
| Figure 5 | `RQ3_failure_modes`: shared three-color traffic key and only two metric entries for B |
| Figure 6 | `RQ4_runtime_outcomes.tex`; mechanism rates move to prose (`RQ4_runtime_mechanism.tex` is an optional extra) |
| New benign cost | `runtime_benign_cost_original.tex` and `runtime_benign_cost_factorial.tex` |
| Completed 2x2 follow-up | `runtime_factorial_results.tex` (16 cells, 320 runs, 16,000 trials) |

The zero-delta-J sentence and the entropy/volume explanation already exist in the
latest available RQ text: replace/retain them, do not duplicate them. Table 1 is
currently the **B0--B5 definition table**, not the earlier experimental-settings
table. Its removal is optional; the supplied paragraph preserves all six variants.
Final page count depends on the cloud manuscript and has not been certified.

## Data and inference

Locked benign boundary is a **post-hoc re-score**, not fresh held-out evidence.
480 original runs / 144,000 decisions are checked against recorded hashes and
initial-B5 predictions; 5,000 bootstrap resamples use runs, not decisions.
Runtime campaign summaries are kept separate. The original campaign does not
provide validated cache-insertion evidence. The factorial campaign does.

Benign latency is the query subprocess interval reconstructed from monotonic
query start/end logs, excluding cache-before/cache-after. Reported median/p95
pool 1,000 query attempts per cell, **including timeouts**, as descriptive
quantiles. Companion CSVs also give the mean of per-run medians/p95s; these are
different statistics. Trial counts are not treated as independent sample sizes.
Native-drop has concurrent queries; the other policies have sequential queries,
so differences in latency cannot be attributed to policy alone.

The factorial factors are forged-tail injection on/off and background rate under
the same sweep pattern. Background includes non-DNS occupancy; forged tails add
traffic beyond the registered background rate. The lab notifies the fragment
sender of metadata; this does not establish a natural off-path attack.

The high-threshold validation-only post-hoc analysis already exists in
`../../experiments/E3-Extend/`; it must not replace the locked operating point.
The additional `controlled_ipid_sensitivity/` directory contains a separate
post-hoc benign replay for a 65,536-value space; see its protocol and verification.
No attack-discrimination or orphan-fragment baseline is implied by that replay.
GitHub publication requires the user's resolution of the
earlier no-commit/no-push constraint.

Reproduce from Code: `python research/Report/figures/revise_paper_figures.py`.
`source_manifest.json` pins all inputs; `verification.json` records checks.
""",encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True,exist_ok=True)
    configure()
    boundary();discrimination();calibration();failure_modes();runtime();notes()
    track(Path(__file__).resolve());track(Path(original.__file__).resolve())
    write_json("source_manifest.json",SOURCES)
    AUDIT["status"]="PASS"
    write_json("verification.json",AUDIT)
    print(f"Generated four revised figures and runtime tables: {OUT}")


if __name__=="__main__":
    main()
