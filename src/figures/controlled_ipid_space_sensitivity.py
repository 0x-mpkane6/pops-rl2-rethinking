"""Post-hoc benign sensitivity: matched original versus 16-bit IPID spaces.

Replay the archived Poisson generator, first proving exact agreement with the
original decision timestamps, occupancy, current IPIDs and feature values.
Only then change its random/sequential IPID space from 2,048 to 65,536.
No attack discrimination, runtime outcome, or held-out claim is made.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import random
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

import revise_paper_figures as paper

SOURCE = paper.original.E1_LEVELS.parent
OUTPUT = paper.OUT / "controlled_ipid_sensitivity"


def replay(seed: int, level: int, behavior: str, space: int, count: int):
    rng = random.Random(seed)
    current = rng.randint(0, space-1) if behavior == "sequential" else None
    window = deque()
    counts = Counter()
    moment = 0.
    produced = 0
    weighted_log = 0.
    def contribution(n):
        return n * math.log2(n) if n else 0.
    while produced < count:
        moment += rng.expovariate((level-1)/2)
        if behavior == "sequential":
            ipid = current % space
            current += 1
        else:
            ipid = rng.randint(0, space-1)
        window.append((moment,ipid))
        previous = counts[ipid]
        counts[ipid] += 1
        weighted_log += contribution(previous+1)-contribution(previous)
        while window[0][0] < moment-2:
            _,old = window.popleft()
            previous = counts[old]
            weighted_log += contribution(previous-1)-contribution(previous)
            counts[old] -= 1
            if not counts[old]: del counts[old]
        if moment < 6: continue
        produced += 1
        n = len(window)
        entropy = math.log2(n)-weighted_log/n
        # Guard the incremental implementation with a direct independent sum.
        direct = -sum((v/n)*math.log2(v/n) for v in counts.values())
        assert abs(entropy-direct)<1e-9
        yield {"decision_idx":produced,"virtual_timestamp_seconds":moment,"current_ipid":ipid,"samples":n,"entropy":entropy,"unique_ipids":len(counts),"unique_ratio":len(counts)/n}


def score(d, configuration):
    n,h,u=(24,4.,.70) if configuration=="initial" else (8,6.,.90)
    return d["samples"]>=n and d["entropy"]>=h and d["unique_ratio"]>=u


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    protocol_path=OUTPUT/"protocol.json"
    rows=[]
    for file,phase in [("e1_runs.csv","main"),("e1_high_load_runs.csv","high_load")]:
        with (SOURCE/file).open() as f:
            rows.extend({**r,"phase":phase} for r in csv.DictReader(f) if r["behavior"] in {"random2048","sequential"})
    assert len(rows)==480
    protocol={"classification":"post-hoc descriptive benign sensitivity", "created_utc":datetime.now(timezone.utc).isoformat(),"source":str(SOURCE.relative_to(paper.ROOT)),"source_code_sha256":digest(SOURCE/"source_snapshot/e1_experiment.py"),"script_sha256":digest(Path(__file__)),"spaces":[2048,65536],"runs_per_space":480,"decisions_per_run":300,"window_seconds":2,"warmup_seconds":6,"matching":"Exact decision times and occupancy checked in every old/new pair; archived generator and seed reused.","scoring":{"initial":[24,4,.70],"locked":[8,6,.90]},"analysis":"Run-level bootstrap 5,000 samples, seed 20260912; report all cells. No threshold selection or held-out access.","scope":"Random and sequential benign main-grid traces, and registered high-load random benign traces only. No synthetic attack discrimination or runtime replay."}
    # Register this addendum before computing its outcomes; retries never erase
    # an earlier successful result or silently change its generating source.
    if (OUTPUT/"verification.json").exists():
        previous=json.loads(protocol_path.read_text())
        if previous["script_sha256"]!=protocol["script_sha256"]:
            raise RuntimeError("Existing sensitivity result belongs to different code")
        print("Sensitivity already complete; preserved existing artifacts.")
        return
    protocol_path.write_text(json.dumps(protocol,indent=2)+"\n")
    summaries=[]
    max_error=0.
    with gzip.open(OUTPUT/"decision_records.jsonl.gz","wt",encoding="utf-8") as log:
        for idx,row in enumerate(rows):
            path=SOURCE/row["raw_decisions_file"]
            assert digest(path)==row["raw_decisions_sha256"]
            old=[json.loads(s) for s in path.read_text().splitlines()]
            args=(int(row["seed"]),int(row["level_samples_per_window"]),row["behavior"])
            regenerated=list(replay(*args,2048,300))
            for observed,replayed in zip(old,regenerated):
                for key in ["decision_idx","virtual_timestamp_seconds","current_ipid","samples","unique_ipids","unique_ratio"]:
                    assert observed[key]==replayed[key],(path,key)
                error=abs(observed["entropy"]-replayed["entropy"])
                max_error=max(max_error,error)
                assert error<1e-9
                assert observed["block_combined"]==score(replayed,"initial")
            new=list(replay(*args,65536,300))
            assert all(a["virtual_timestamp_seconds"]==b["virtual_timestamp_seconds"] and a["samples"]==b["samples"] for a,b in zip(old,new))
            for space,records in [(2048,old),(65536,new)]:
                base={"behavior":row["behavior"],"phase":row["phase"],"level":int(row["level_samples_per_window"]),"run":int(row["run_idx"]),"seed":args[0],"space":space}
                for d in records:
                    record={**base,**{k:d[k] for k in ["decision_idx","virtual_timestamp_seconds","current_ipid","samples","entropy","unique_ipids","unique_ratio"]}}
                    record.update({c:score(d,c) for c in ["initial","locked"]})
                    log.write(json.dumps(record,separators=(",",":"))+"\n")
                for config in ["initial","locked"]:
                    summaries.append({**base,"configuration":config,"rate":float(np.mean([score(d,config) for d in records]))})
            if (idx+1)%80==0: print(f"Matched sensitivity: {idx+1}/{len(rows)} source runs",flush=True)
    with (OUTPUT/"run_rates.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(summaries[0]));w.writeheader();w.writerows(summaries)
    groups=defaultdict(list)
    for r in summaries:groups[(r["behavior"],r["phase"],r["level"],r["space"],r["configuration"])].append(r["rate"])
    cells=[]
    for idx,(keys,values) in enumerate(sorted(groups.items())):
        assert len(values)==20
        mean,low,high=paper.original.bootstrap_ci(values,20260912+idx)
        cells.append(dict(zip(["behavior","phase","level","space","configuration"],keys),mean=mean,ci_low=low,ci_high=high,runs=20))
    with (OUTPUT/"summary.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(cells[0]));w.writeheader();w.writerows(cells)
    # Figure focuses on the random-IPID series, for which all 16 registered
    # main/high-load levels are available for both spaces.
    paper.configure()
    fig,axes=plt.subplots(1,2,figsize=(paper.WIDTH,2.75))
    fig.subplots_adjust(left=.13,right=.98,bottom=.31,top=.87,wspace=.35)
    for ax,config,title in zip(axes,["initial","locked"],["A  Initial B5","B  Locked B5"]):
        for space,color,style,marker in [(2048,paper.GRAY,"--","s"),(65536,paper.BLUE,"-","o")]:
            selected=sorted([r for r in cells if r["behavior"]=="random2048" and r["configuration"]==config and r["space"]==space],key=lambda r:r["level"])
            paper.line(ax,[r["level"] for r in selected],selected,color,marker,style,f"{space:,} values")
        ax.set_xscale("log");ax.set_xticks([10,100,1000],['10','100','1,000']);ax.minorticks_off();ax.set_ylim(-.03,1.03);ax.set_yticks([0,.5,1]);ax.set_title(title,loc="left",fontweight="bold");paper.original.style_axes(ax)
    axes[0].set_ylabel("Benign trigger rate")
    fig.text(.54,.16,"Target fragments per 2-s window",ha="center",fontsize=8.5)
    fig.legend(*axes[0].get_legend_handles_labels(),loc="lower center",ncol=2,frameon=False,bbox_to_anchor=(.54,.015))
    saved=paper.OUT;paper.OUT=OUTPUT
    paper.save(fig,"controlled_ipid_space_boundary")
    paper.OUT=saved
    verification={"status":"PASS","source_runs_reconstructed":480,"source_decisions_checked":144000,"new_decisions":144000,"source_raw_hashes_verified":True,"paired_times_and_occupancy_identical":True,"initial_predictions_match_source":True,"max_entropy_reconstruction_error":max_error,"all_cells_reported":len(cells),"held_out_accessed":False}
    (OUTPUT/"verification.json").write_text(json.dumps(verification,indent=2)+"\n")
    (OUTPUT/"README.md").write_text("""# Controlled benign IPID-space sensitivity

Post-hoc descriptive sensitivity on the archived benign generator, comparing
2,048 and 65,536 identifiers. Both initial and locked configurations are fixed.
The 480 source runs (320 random/sequential main-grid and 160 random high-load)
are first reproduced against 144,000 archived decisions. Arrival/decision times
and occupancy are then checked to match exactly across IPID spaces.
Each cell has 20 runs of 300 decisions; intervals use 5,000 run resamples.
This is new synthetic identifier replay, not a re-labeling of old IPIDs and not
new held-out or runtime evidence. Sequential IPIDs also use the larger modulus;
their main-grid outcome is preserved. The pool-of-16 condition is not changed.

Inspect `summary.csv`, `run_rates.csv`, `decision_records.jsonl.gz`, and
`verification.json`. The registered addendum is `protocol.json`.
This covers **benign sensitivity only**; it does not establish attack PR-AUC,
malicious-answer rates, or cache insertion for a changed controlled IPID space.
""",encoding="utf-8")
    print(f"Sensitivity PASS: {OUTPUT}")


if __name__=="__main__":main()
