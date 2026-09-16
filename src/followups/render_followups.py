"""Export verified post-hoc results as print-size figures, tables and prose."""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.text import Text
import numpy as np
from scipy.stats import beta

from analyze_followups import OUTPUT

WIDTH=122/25.4
DEST=OUTPUT/"paper"


def rows(relative):
    with (OUTPUT/relative).open(encoding="utf-8") as f:return list(csv.DictReader(f))


def save(fig,stem):
    fig.canvas.draw();renderer=fig.canvas.get_renderer()
    texts=[t for t in fig.findobj(Text) if t.get_visible() and t.get_text()]
    assert min(t.get_fontsize() for t in texts)>=8.5
    for t in texts:
        if t.get_clip_on():continue
        b=t.get_window_extent(renderer);canvas=fig.bbox
        assert b.x0>=-1 and b.y0>=-1 and b.x1<=canvas.x1+1 and b.y1<=canvas.y1+1,(stem,t.get_text())
    for ext,args in [("pdf",{}),("png",{"dpi":600}),("svg",{})]:fig.savefig(DEST/f"{stem}.{ext}",**args)
    plt.close(fig)


def table(stem,caption,label,headers,data):
    lines=[r"\begin{table}[t]",r"\centering",r"\caption{"+caption+"}",r"\label{"+label+"}",r"\begingroup\fontsize{9}{10.8}\selectfont",r"\setlength{\tabcolsep}{2pt}",r"\begin{tabular}{"+"l"+"r"*(len(headers)-1)+"}",r"\hline"," & ".join(headers)+r" \\",r"\hline"]
    lines += [" & ".join(r)+r" \\" for r in data]
    lines += [r"\hline",r"\end{tabular}",r"\endgroup",r"\end{table}"]
    (DEST/f"{stem}.tex").write_text("\n".join(lines)+"\n",encoding="utf-8")


def plot_sensitivity():
    source=rows("controlled/cell_summary.csv")
    fig,axes=plt.subplots(1,2,figsize=(WIDTH,2.95))
    fig.subplots_adjust(left=.13,right=.98,bottom=.32,top=.86,wspace=.27)
    for ax,profile,title in zip(axes,["continuous","bursty"],["A  Continuous","B  Bursty"]):
        for space,color in [("2048","#0072B2"),("65536","#D55E00")]:
            for metric,marker,style in [("unique_ratio_AP","o","-"),("entropy_AP","^","--")]:
                selected=sorted([r for r in source if r["role"]=="primary" and r["profile"]==profile and r["space"]==space and r["metric"]==metric],key=lambda r:int(r["level"]))
                assert len(selected)==4
                x=[int(r["level"]) for r in selected];m=np.array([float(r["mean"]) for r in selected]);lo=np.array([float(r["ci_low"]) for r in selected]);hi=np.array([float(r["ci_high"]) for r in selected])
                ax.fill_between(x,lo,hi,color=color,alpha=.12,linewidth=0)
                ax.plot(x,m,color=color,marker=marker,linestyle=style,markerfacecolor="white")
        ax.set_xticks([24,60,120,200]);ax.set_ylim(.46,1.025);ax.set_yticks([.5,.75,1]);ax.set_title(title,fontweight="bold",loc="left")
        ax.axhline(.5,color="#555555",linestyle=":",linewidth=.7)
        ax.spines[['top','right']].set_visible(False);ax.grid(axis="y",alpha=.25)
    axes[0].set_ylabel("PR-AUC")
    fig.text(.55,.20,"Target fragments per 2-s window",ha="center",fontsize=8.5)
    fig.legend(handles=[Line2D([],[],color="#0072B2",label="2,048 values"),Line2D([],[],color="#D55E00",label="65,536 values")],loc="lower center",bbox_to_anchor=(.55,.07),frameon=False,ncol=2)
    fig.legend(handles=[Line2D([],[],color="black",marker="o",linestyle="-",markerfacecolor="white",label="Unique ratio"),Line2D([],[],color="black",marker="^",linestyle="--",markerfacecolor="white",label="Entropy")],loc="lower center",bbox_to_anchor=(.55,.0),frameon=False,ncol=2)
    save(fig,"controlled_ipid_discrimination")


def main():
    DEST.mkdir(exist_ok=True)
    for part in ["controlled","orphan"]:assert json.loads((OUTPUT/part/"verification.json").read_text())["status"]=="PASS"
    plt.rcParams.update({"font.family":"sans-serif","font.sans-serif":["Arial","DejaVu Sans"],"font.size":8.5,"axes.labelsize":8.5,"axes.titlesize":9,"xtick.labelsize":8.5,"ytick.labelsize":8.5,"legend.fontsize":8.5,"lines.markersize":4,"lines.linewidth":1.2,"pdf.fonttype":42,"svg.fonttype":"none"})
    plot_sensitivity()
    macro={(r['metric'],r['comparison']):r for r in rows("controlled/macro_summary.csv")}
    names=[("entropy_AP","Entropy AP"),("unique_ratio_AP","Unique-ratio AP"),("B5_locked_attack_alert","B5 attack alert"),("B5_locked_benign_trigger","B5 benign trigger"),("B5_locked_FNR","B5 FNR"),("B5_locked_J","B5 J")]
    data=[]
    for metric,label in names:
        a,b,d=[macro[(metric,c)] for c in ['2048','65536','65536_minus_2048']]
        data.append([label,f"{float(a['mean']):.4f}",f"{float(b['mean']):.4f}",f"{float(d['mean']):+.4f}",f"[{float(d['ci_low']):+.4f}, {float(d['ci_high']):+.4f}]"])
    table("controlled_ipid_macro",r"Post-hoc validation-only IPID-space sensitivity. Values are equally weighted macro means over eight primary cells (six matched traces per cell). The difference is 65,536 minus 2,048; intervals use 5,000 paired-trace bootstrap resamples stratified by cell. B5 uses the unchanged locked thresholds. Rates and J are on the 0--1 scale; these are descriptive intervals, not a new held-out evaluation.","tab:ipid-space",["Metric","2,048","65,536",r"Difference",r"95\% CI"],data)
    cell=rows("orphan/cell_summary.csv");lookup={(r['policy'],r['workload'],r['metric']):r for r in cell}
    comparisons=rows("orphan/paired_summary.csv")
    data=[]
    for suffix,rate in [('MODERATE',12),('HIGH',200)]:
        for criterion,metric in [(r"$O>0$","any_interval_rate"),(r"$O\geq0.5$","majority_interval_rate")]:
            benign=float(lookup[('B0_OFF','BENIGN_DIVERSE_'+suffix,metric)]['mean'])
            attack=float(lookup[('B0_OFF','ATTACK_DIVERSE_'+suffix,metric)]['mean'])
            data.append([str(rate),criterion,f'{100*benign:.2f}',f'{100*attack:.2f}',f'{attack-benign:.4f}'])
    table("orphan_ratio_baseline",r"Offline orphan-fragment baselines on the no-enforcement runtime traces. Load denotes background non-initial fragments/s. Both criteria also require $n\geq8$ in a two-second window. Alert rates count any activation from query start to completion; each traffic--rate cell has 20 recreated-stack runs and 1,000 trials. The orphan ratio O uses causal first-fragment matching by source, destination, IP protocol and IPID. No orphan policy was enforced, so these are detection rates, not poisoning-prevention rates.","tab:orphan-baseline",[r"Load (/s)","Criterion",r"Benign alert (\%)",r"Attack alert (\%)","J"],data)
    audit=json.loads((OUTPUT/'orphan/verification.json').read_text())
    controlled_audit=json.loads((OUTPUT/'controlled/verification.json').read_text())
    b0=[r for r in comparisons if r['policy']=='B0_OFF']
    fnum=audit['forged_observed'];fmatched=audit['forged_matched_at_ingress']
    report=['# Hai phân tích bổ sung: kết quả và cách dùng trong bài','',
        'Đã hoàn thành hai phần. Cả hai là post-hoc; các protocol và source snapshot được lưu trước khi tổng hợp. Ngưỡng locked vẫn là (8, 6.0, 0.90).','',
        '## 1. Phân biệt benign–attack với không gian IPID 65.536','',
        f"Chỉ mở validation: {controlled_audit['validation_decisions']:,} quyết định từ 184 condition traces. Đã tái dựng khớp {controlled_audit['source_frag2_events_checked']:,} fragment events gốc, toàn bộ n/H/U và dự đoán B2/initial B5 (sai khác đặc trưng lớn nhất bằng 0). Sau đó đổi không gian IPID từ 2.048 lên 65.536, tạo thêm 27.600 quyết định. Lịch fragment, lịch query, occupancy và vị trí benign/attack trong luồng được giữ nguyên.", '',
        'Phân tích chính gồm 48 paired traces (continuous/bursty × bốn tải × sáu cặp). Tổng cộng 120 so sánh benign–attack khi tính cả fixed, duplicate-sweep và random negative control; các probe dùng lại benign trace nên không được coi 120 so sánh là 120 đơn vị độc lập. Có 16 benign-only traces trong validation, được lưu kết quả nhưng không dùng để dựng cặp attack giả. Không mở held_out_test.csv.gz và không hiệu chỉnh threshold.', '',
        '| Metric | IPID 2.048 | IPID 65.536 | Chênh lệch [95% CI] |','|---|---:|---:|---|']
    for metric,label in names:
        a,b,d=[macro[(metric,c)] for c in ['2048','65536','65536_minus_2048']]
        report.append(f"| {label} | {float(a['mean']):.4f} | {float(b['mean']):.4f} | {float(d['mean']):+.4f} [{float(d['ci_low']):+.4f}, {float(d['ci_high']):+.4f}] |")
    report+=['','AP là average precision với class mix 50/50 trong mỗi cặp; CI resample nguyên paired trace, không coi 150 quyết định trong trace là 150 mẫu độc lập. Macro J của B2 và initial B5 đều bằng 0 trong cả hai không gian, nên J của locked B5 cũng là Delta J so với B2.', '',
        '**Diễn giải:** lợi thế phân biệt theo IPID của lưới controlled phụ thuộc mạnh vào không gian ID. Với 65.536 giá trị, entropy và uniqueness của benign tiến gần sweep attack; AP gần 0,5 và J của locked B5 gần 0. Cần bổ sung hạn chế này vào bài, không dùng kết quả cũ để khẳng định lợi thế bền vững với toàn bộ không gian IPv4 IPID.', '',
        '## 2. Baseline orphan-fragment ratio','',
        'Baseline dùng PCAP runtime có IPv4 fragment thật. Các pseudo query/FRAG1 trong controlled emulation không thiết lập quan hệ reassembly với từng FRAG2; vì vậy không ghép hai loại dữ liệu này vào cùng một baseline table hoặc giả định mọi FRAG2 synthetic là orphan.', '',
        f"Đã replay {audit['pcap_packets']:,} packet records, gồm {audit['scoped_fragments']:,} fragment observations trong scope, trên PCAP phía ngoài IPS của đủ 320 run / 16.000 trial thuộc campaign 2×2. Chỉ dùng một interface capture trước enforcement, không gộp hai interface. Vẫn giữ những lần quan sát lặp trong cùng capture; một packet hash lặp có thể là retransmission, không mặc định là một packet duy nhất. Có {audit['independent_query_snapshot_checks']:,} query snapshots được đối chiếu bằng cách tính độc lập.", '',
        'Định nghĩa O: số mảnh non-initial còn trong cửa sổ hai giây mà chưa có first fragment phù hợp, chia tổng non-initial trong cửa sổ. Key gồm src/dst/protocol/IPID. First fragment phải có offset=0 và MF=1. Head trước tail tối đa hai giây được nhận; tail đến trước head vẫn là orphan cho đến khi head thực sự được quan sát. Khi đã ghép, việc head rời cửa sổ không tự biến tail thành orphan lại. Không dùng first fragment trong tương lai.', '',
        'Đã cố định hai operating point trước phân tích: n>=8 và O>=0,5; đồng thời kiểm tra độ nhạy n>=8 và O>0. Có điểm ở query start, peak O và any activation trong toàn bộ query interval. Các policy khác được giữ thành strata riêng; B0 là so sánh chính để giảm feedback từ enforcement.', '',
        '| Policy B0: tải nền | Chỉ số | Ước lượng | 95% CI |','|---:|---|---:|---|']
    for r in b0:report.append(f"| {r['rate']} | {r['metric']} | {float(r['mean']):.4f} | [{float(r['ci_low']):.4f}, {float(r['ci_high']):.4f}] |")
    report+=['',f"Trong {audit['forged_logged']:,} forged-tail packet signatures phân biệt theo run được log, quan sát được {fnum:,} trong capture, qua {audit['forged_capture_records']:,} capture records. Cả {fmatched:,}/{fnum:,} signatures ({100*fmatched/fnum:.2f}%) có matching first fragment ở mọi lần ingress quan sát được; {audit['forged_matching_capture_records']:,}/{audit['forged_capture_records']:,} capture records cũng đã được ghép. Các số này không được gọi là số trial hay số packet gửi độc lập.", '',
        '**Giới hạn:** đây là offline baseline từ log, không phải một policy đã enforce trong Docker. Không được gán malicious-answer/cache-insertion rate cho orphan policy. Việc ghép được first fragment chỉ xác nhận quan hệ fragment header, không xác thực payload tail. Lab gửi legitimate first fragment trước khi thông báo cho forged-tail sender; đây là cơ chế cần dùng để giải thích kết quả.', '',
        f"Capture audit: có {sum(r['capture_order_inversions'] for r in audit['audit'])} chỗ record-order khác thứ tự kernel timestamp. Đã kiểm tra cả thứ tự timestamp lẫn thứ tự record: {audit['runs_with_zero_ratio_in_both_orders']}/320 run có orphan ratio bằng 0 suốt toàn bộ capture trong cả hai cách. Clock-offset range giữa client monotonic và wall clock lớn nhất là {audit['max_clock_offset_range_ms']:.3f} ms, nên không chứng nhận alignment query chính xác từ phép đổi clock này. Các tỷ lệ và AP orphan vẫn xác định được vì score luôn bằng 0, không phụ thuộc việc dịch query interval trong capture. Runner sẽ dừng nếu score thay đổi mà clock chưa đủ tin cậy. r001/r002 được giữ lại với audit các lỗi phân tích; bộ cuối là {OUTPUT.name}. Không loại run theo hiệu quả detector.", '',
        '## File để chèn vào bài','',
        '- `paper/controlled_ipid_discrimination.pdf` hoặc PNG: hình AP theo tải, font 8,5 pt ở rộng 122 mm.','- `paper/controlled_ipid_macro.tex`: bảng macro và paired difference CI.','- `paper/orphan_ratio_baseline.tex`: bảng baseline orphan trên B0.','- `paper/paper_additions.tex`: figure block, câu giới thiệu bảng và đoạn diễn giải bằng tiếng Anh.','- Các CSV đầy đủ nằm ở `controlled/` và `orphan/`; manifest chứa SHA-256 của đầu vào.','',
        '## Tái lập','',
        'Từ Code:', '',
        '```powershell',
        'python -m pytest research/Report/experiments/Followup-IPID-Orphans/test_followups.py -q',
        'python research/Report/experiments/Followup-IPID-Orphans/analyze_followups.py --stage all',
        'python research/Report/experiments/Followup-IPID-Orphans/render_followups.py',
        '```','',
        'Runner giữ nguyên output đã hoàn tất. Để tái tính hoàn toàn, dùng một output run ID mới trong một bản sao script và đăng ký snapshot mới; không ghi đè evidence hiện có. Bộ này không commit/push hoặc sửa bản Cloud.']
    (OUTPUT/'KET_QUA_VA_HUONG_DAN.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
    ap_old=float(macro[('unique_ratio_AP','2048')]['mean']);ap_new=float(macro[('unique_ratio_AP','65536')]['mean'])
    j_old=float(macro[('B5_locked_J','2048')]['mean']);j_new=float(macro[('B5_locked_J','65536')]['mean'])
    text=(r"% Post-hoc additions; do not replace the frozen held-out results."+'\n'+
        r"Table~\ref{tab:ipid-space} and Figure~\ref{fig:ipid-space-discrimination} examine IPID-space sensitivity on validation traces only. "+
        f"Expanding the IPID space from 2,048 to 65,536 reduces macro unique-ratio AP from {ap_old:.4f} to {ap_new:.4f}, while locked-B5 separation falls from $J={j_old:.5f}$ to $J={j_new:.5f}$. "+
        r"This post-hoc replay preserves fragment/query timing and occupancy and retains the locked thresholds; it is not a new held-out evaluation. The results show that the observed discrimination is sensitive to the assumed IPID space."+'\n\n'+
        r"\begin{figure}[t]"+'\n'+r"\centering"+'\n'+r"\includegraphics[width=\linewidth]{figure/controlled_ipid_discrimination.pdf}"+'\n'+
        r"\caption{Post-hoc validation-only IPID-space sensitivity under volume matching. Panels A and B show continuous and bursty profiles. Bands are descriptive 95\% confidence intervals from 5,000 paired-trace bootstrap samples; six pairs per cell, 150 decisions per condition and trace. The same arrival/query schedules and origin masks are replayed in both spaces.}"+'\n'+r"\label{fig:ipid-space-discrimination}"+'\n'+r"\end{figure}"+'\n\n'+
        r"Table~\ref{tab:orphan-baseline} reports an offline orphan-fragment-ratio baseline on the runtime captures. A matched first fragment establishes a header-level association but does not authenticate the tail payload. " +
        f"All {fnum:,} distinct logged forged-tail packet signatures observed in the captures had a matching first fragment at each observed ingress. "+
        r"The baseline is evaluated as a detector only; its poisoning-prevention performance is not measured."+'\n')
    # Exact any-event/run intervals avoid treating the 50 trials as independent
    # or interpreting a degenerate percentile interval as perfect certainty.
    run_metrics=rows('orphan/run_metrics.csv');events=[]
    for policy in sorted({r['policy'] for r in run_metrics}):
        for workload in sorted({r['workload'] for r in run_metrics}):
            selected=[r for r in run_metrics if r['policy']==policy and r['workload']==workload]
            for metric in ['majority_interval_rate','any_interval_rate']:
                k=sum(float(r[metric])>0 for r in selected);n=len(selected)
                events.append({'policy':policy,'workload':workload,'criterion':metric,'runs':n,'any_alert_runs':k,'ci_low':float(beta.ppf(.025,k,n-k+1)) if k else 0.,'ci_high':float(beta.ppf(.975,k+1,n-k)) if k<n else 1.})
    with (DEST/'orphan_any_event_runs.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(events[0]));writer.writeheader();writer.writerows(events)
    if all(r['any_alert_runs']==0 for r in events):
        text+=r" No run contained a baseline alert (0/20 per cell); the exact 95\% interval for the any-alert-run proportion is [0, 0.1684]."+'\n'
    (DEST/'paper_additions.tex').write_text(text,encoding='utf-8')
    print(f"Paper outputs: {DEST}")


if __name__=='__main__':main()
