"""Post-hoc controlled IPID discrimination and offline orphan-ratio baseline.

Uses only the validation partition for controlled sensitivity, and frozen
factorial runtime PCAPs for orphan matching. No threshold selection, no packet
transmission, no changes to original artifacts, and no new held-out evaluation.
"""
from __future__ import annotations

import argparse
import ast
import csv
import gzip
import hashlib
import io
import json
import math
import random
import shutil
import struct
import sys
import types
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score
from scapy.utils import RawPcapNgReader

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXP = HERE.parent
CONTROL = EXP / "E2/runs/E2_confirmatory_20260814_complete_b0_ablation"
VALIDATION = EXP / "E3/datasets/splits_60_20_20/validation.csv.gz"
RUNTIME = EXP / "E5/output/E5-factorial-s20260911-r003"
OUTPUT = HERE / "output/posthoc-s20260912-r003"
W = 2_000_000_000
SEED = 20260912
POLICIES = ["B0_OFF", "B1_RL2_TC", "B5_LOCKED_TC", "RFC_DROP_NATIVE"]
WORKLOADS = ["BENIGN_DIVERSE_MODERATE", "BENIGN_DIVERSE_HIGH", "ATTACK_DIVERSE_MODERATE", "ATTACK_DIVERSE_HIGH"]
SOURCES = {}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    data = path.read_bytes()
    SOURCES[str(path.relative_to(ROOT)).replace("\\", "/")] = sha(data)
    return data


def read_json(path):
    return json.loads(read(path))


def jsonl(path):
    data = read(path)
    if path.suffix == ".gz": data = gzip.decompress(data)
    return [json.loads(line) for line in data.splitlines() if line.strip()]


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False)+"\n", encoding="utf-8")


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def bootstrap(values, seed=SEED):
    a = np.asarray(values, dtype=float)
    if not len(a) or not np.isfinite(a).all(): raise ValueError("Empty/nonfinite bootstrap input")
    b = a[np.random.default_rng(seed).integers(0, len(a), (5000, len(a)))].mean(axis=1)
    return float(a.mean()), float(np.quantile(b,.025)), float(np.quantile(b,.975))


def metrics(n, h, u):
    return {"B2": n>=24, "B5_initial": n>=24 and h>=4 and u>=.70,
            "B5_locked": n>=8 and h>=6 and u>=.90}


def archived_generator(space):
    """Load only pure frozen generation functions; do not import live resolver."""
    source = read(CONTROL / "source_snapshot/e2_confirmatory.py")
    names = {"canonical_json", "sha256_bytes", "derive_seed", "SharedSchedule",
             "make_arrival_times", "build_shared_schedule", "payload_for_condition"}
    parsed = ast.parse(source)
    nodes = [n for n in parsed.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    assert {n.name for n in nodes} == names
    module = types.ModuleType(f"archived_controlled_generator_{space}")
    sys.modules[module.__name__] = module
    p = read_json(CONTROL/"e2_protocol.json")
    module.__dict__.update(random=random, hashlib=hashlib, json=json, dataclass=dataclass,
        WINDOW_SECONDS=2., WARMUP_SECONDS=6., QUERY_INTERVAL_SECONDS=.25,
        BURST_HIGH=1.75, BURST_LOW=.25, BURST_HALF_PERIOD_SECONDS=1.5,
        IPID_SPACE=space, FIXED_IPID=777, CONDITIONS=p["conditions"])
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    tree = ast.fix_missing_locations(ast.Module(body=[future]+nodes, type_ignores=[]))
    exec(compile(tree,str(CONTROL/"source_snapshot/e2_confirmatory.py"),"exec"),module.__dict__)
    return module


def rescore(arrivals, payload, query_times):
    history = deque(); index = 0; output = []
    for t in query_times:
        while index < len(arrivals) and arrivals[index] <= t:
            history.append((arrivals[index],payload[index]));index+=1
        while history and history[0][0] < t-2: history.popleft()
        ids = [v[1][1] for v in history]; n = len(ids); counts = Counter(ids)
        h = -sum((c/n)*math.log2(c/n) for c in counts.values()) if n else 0.
        u = len(counts)/n if n else 0.
        output.append({"samples":n,"entropy":h,"unique_ipids":len(counts),"unique_ratio":u,
            "attack_events_in_window":sum(v[1][0]=="attack" for v in history),
            "benign_events_in_window":sum(v[1][0]=="benign" for v in history),**metrics(n,h,u)})
    return output


def register():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    path=OUTPUT/"protocol.json"
    signature=sha(Path(__file__).read_bytes())
    if path.exists():
        p=json.loads(path.read_text())
        if p["analysis_source_sha256"]!=signature: raise RuntimeError("Source changed: use a new output run ID")
        return
    write_json(path,{
        "classification":"post-hoc descriptive analysis; specified after original study outcomes",
        "registered_utc":datetime.now(timezone.utc).isoformat(),"analysis_source_sha256":signature,
        "controlled":{
            "source_validation_sha256":sha(VALIDATION.read_bytes()),"spaces":[2048,65536],
            "permitted_data":"validation.csv.gz and only the original condition traces it names",
            "forbidden_data":"train_exploration.csv.gz and held_out_test.csv.gz; no new threshold selection",
            "matching":"arrival and query timestamps, occupancy, event origin mask; IPID space alone changes",
            "qname_equivalent":"FRAG1 schedule IPIDs also expand; equal query timestamps remain matched",
            "rules":{"B2":[24],"B5_initial":[24,4,.70],"B5_locked":[8,6,.90]},
            "primary":"continuous and bursty sweep vs matched benign, 4 target volumes; AP for entropy and uniqueness, attack alert, benign trigger, FNR, J, delta J vs B2",
            "secondary":"fixed, duplicate sweep, random negative control; report separately",
            "benign_only_traces":"score and retain them; omit from paired effects because they have no attack mate in validation",
            "inference":"5000 paired-trace bootstrap samples within each cell; equal cell weights for macro; descriptive intervals only"},
        "orphan":{
            "data":"all 320 completed factorial confirmatory runs, ips_outside.pcapng only, before enforcement",
            "capture_order":"Stable chronological sort by kernel capture timestamp; retain every scoped frame and audit file-order timestamp inversions. Original record-order assumption failed in r001; no outcome-based run exclusions.",
            "order_sensitivity":"Also replay file record order, clamping backward timestamps only for that diagnostic. Report its maximum orphan ratio; do not silently rely on timestamp sorting.",
            "packet_identity":"Report unique forged packet signatures and their repeated capture observations separately; a repeated hash is not automatically a duplicate physical send.",
            "key":["IPv4 source","IPv4 destination","IP protocol","IPID"],
            "scope":"sources 10.82.0.100 and 10.82.0.200 to resolver 10.81.0.53; all protocols including non-DNS occupancy",
            "window_seconds":2,"head_match_horizon_seconds":2,
            "definition":"fraction of non-initial fragment observations in the trailing window lacking a first fragment observed within 2 s before that tail or after that tail by the current evaluation time; matching is causal and remembered for the tail's residence in the window",
            "denominator":"all observed non-initial fragments in window; empty window -> ratio 0, active false",
            "head":"offset zero with MF set; do not use unfragmented datagrams as first-fragment evidence",
            "rules":{"orphan_majority":"n >= 8 AND orphan ratio >= 0.50","orphan_any":"n >= 8 AND orphan ratio > 0"},
            "thresholds":"fixed here, not selected from runtime outcomes",
            "timing":"ratio at query start and peak ratio/any activation during query interval; update matching when heads arrive, score tail enforcement at ingress",
            "query_clock":"wall clock from per-trial wall_ns-mono_ns offset plus query_start/end_mono_ns; report offset spread and check coverage",
            "clock_guard":"When offset spread exceeds 1 ms, accept interval ratios only if orphan ratio is identically zero over the entire capture in both timestamp and record order. Otherwise stop: exact query alignment is unresolved.",
            "primary_comparison":"B0_OFF attack vs benign at each rate, paired by recreated-run replicate; AP and fixed-rule alert rates",
            "other_policies":"descriptive separate policy strata; their feedback and query schedules change observed traffic",
            "claim_scope":"offline baseline replay only; no enforced orphan policy or counterfactual malicious-answer/cache-insertion rates"},
        "bootstrap_seed":SEED,"bootstrap_samples":5000,"no_commit_push":True})
    snap=OUTPUT/"source_snapshot";snap.mkdir(exist_ok=True)
    shutil.copy2(__file__,snap/Path(__file__).name)
    shutil.copy2(CONTROL/"source_snapshot/e2_confirmatory.py",snap/"archived_e2_confirmatory.py")


def controlled():
    folder=OUTPUT/"controlled";folder.mkdir(exist_ok=True)
    if (folder/"verification.json").exists(): print("Controlled already complete; preserved.");return
    manifest={x["path"]:x["sha256"] for x in read_json(CONTROL/"artifact_manifest.json")["files"]}
    data=list(csv.DictReader(io.StringIO(gzip.decompress(read(VALIDATION)).decode())))
    groups=defaultdict(list)
    for row in data:
        assert row["e3_split"]=="validation"
        groups[(row["source_e2_split"],row["profile"],int(row["level"]),int(row["pair_id"]),row["condition"])].append(row)
    assert len(data)==27600 and len(groups)==184
    generators={s:archived_generator(s) for s in [2048,65536]}
    by_key={}; max_error=0.; source_events=0; raw_checked=0
    with gzip.open(folder/"decisions.jsonl.gz","wt",encoding="utf-8") as out:
        for index,(key,expected) in enumerate(sorted(groups.items())):
            split,profile,level,pair,condition=key
            expected.sort(key=lambda r:int(r["query_idx"]))
            assert len(expected)==150
            rel=f"raw_runs/{split}/{condition}/level_{level}/pair_{pair:02d}.jsonl.gz"
            raw=jsonl(CONTROL/rel)
            assert SOURCES[str((CONTROL/rel).relative_to(ROOT)).replace("\\","/")]==manifest[rel]
            fragments=[r for r in raw if r["record_type"]=="frag2"]
            decisions=[r for r in raw if r["record_type"]=="decision"]
            assert len(decisions)==150
            schedules={}; payloads={}
            for space,g in generators.items():
                s=g.build_shared_schedule(20260813,split,profile,level,pair,150)
                payload_seed,payload=g.payload_for_condition(20260813,s,condition,.10)
                schedules[space]=s;payloads[space]=payload
                assert payload_seed==int(expected[0]["payload_seed"])
            old=schedules[2048];new=schedules[65536]
            assert old.arrivals==new.arrivals and old.query_times==new.query_times
            assert old.arrival_schedule_sha256==expected[0]["arrival_schedule_sha256"]
            assert old.query_schedule_sha256==expected[0]["query_schedule_sha256"]
            assert [x[0] for x in payloads[2048]]==[x[0] for x in payloads[65536]]
            assert len(fragments)==len(old.arrivals)
            for f,t,(origin,ipid) in zip(fragments,old.arrivals,payloads[2048]):
                assert (f["timestamp_seconds"],f["origin"],f["ipid"])==(t,origin,ipid)
            source_events+=len(fragments)
            for space in [2048,65536]:
                scored=rescore(schedules[space].arrivals,payloads[space],schedules[space].query_times)
                for i,(d,e,record) in enumerate(zip(scored,expected,decisions)):
                    assert d["samples"]==int(e["samples"])
                    if space==2048:
                        for k in ["samples","unique_ipids","unique_ratio","entropy","attack_events_in_window","benign_events_in_window"]:
                            error=abs(d[k]-float(e[k]));max_error=max(max_error,error)
                            assert error<1e-10 and abs(d[k]-record[k])<1e-10
                        assert d["B5_initial"]==bool(int(e["block_combined"])) and d["B2"]==bool(int(e["block_volume"]))
                        assert old.query_times[i]==float(e["query_timestamp_seconds"])==record["timestamp_seconds"]
                        assert old.frag1_ipids[i]==int(e["frag1_ipid"])
                        raw_checked+=1
                    entry={"source_split":split,"profile":profile,"level":level,"pair_id":pair,"condition":condition,"space":space,"query_idx":i+1,"query_time":old.query_times[i],"frag1_ipid":schedules[space].frag1_ipids[i],**d}
                    out.write(json.dumps(entry,separators=(",",":"))+"\n")
                by_key[(*key,space)]=scored
            if (index+1)%40==0: print(f"Controlled traces verified: {index+1}/184",flush=True)
    paired=[]
    for key in sorted(groups):
        split,profile,level,pair,condition=key
        if not condition.startswith("attack_"): continue
        role="primary" if condition in {"attack_sweep_continuous","attack_sweep_bursty"} else "secondary"
        for space in [2048,65536]:
            a=by_key[(*key,space)];b=by_key[(split,profile,level,pair,f"benign_{profile}",space)]
            base={"role":role,"source_split":split,"profile":profile,"level":level,"pair_id":pair,"condition":condition,"space":space}
            for feature in ["entropy","unique_ratio"]:
                ap=average_precision_score([0]*150+[1]*150,[d[feature] for d in b]+[d[feature] for d in a])
                paired.append({**base,"metric":feature+"_AP","value":float(ap)})
            for rule in ["B2","B5_initial","B5_locked"]:
                attack=float(np.mean([d[rule] for d in a]));benign=float(np.mean([d[rule] for d in b]))
                for metric,value in [("attack_alert",attack),("benign_trigger",benign),("FNR",1-attack),("J",attack-benign)]:
                    paired.append({**base,"metric":rule+"_"+metric,"value":value})
    write_csv(folder/"paired_metrics.csv",paired)
    cells=defaultdict(list)
    for row in paired:cells[(row["role"],row["profile"],row["level"],row["condition"],row["space"],row["metric"])].append(row["value"])
    summary=[]
    for i,(key,values) in enumerate(sorted(cells.items())):
        assert len(values)==6
        mean,lo,hi=bootstrap(values,SEED+i)
        summary.append(dict(zip(["role","profile","level","condition","space","metric"],key),mean=mean,ci_low=lo,ci_high=hi,pairs=6))
    write_csv(folder/"cell_summary.csv",summary)
    # Paired contrasts retain the same trace resample for both IPID spaces.
    primary=[r for r in paired if r["role"]=="primary"]
    metrics_set=sorted({r["metric"] for r in primary});macro=[]
    for i,metric in enumerate(metrics_set):
        cell_keys=sorted({(r["profile"],r["level"]) for r in primary})
        rng=np.random.default_rng(SEED+10000+i)
        boots={2048:[],65536:[]};observed={2048:[],65536:[]}
        for profile,level in cell_keys:
            ordered={s:sorted([r for r in primary if r["space"]==s and r["metric"]==metric and (r["profile"],r["level"])==(profile,level)],key=lambda r:(r["source_split"],r["pair_id"])) for s in [2048,65536]}
            assert [(r["source_split"],r["pair_id"]) for r in ordered[2048]]==[(r["source_split"],r["pair_id"]) for r in ordered[65536]]
            indices=rng.integers(0,6,(5000,6))
            for s in [2048,65536]:
                values=np.array([r["value"] for r in ordered[s]])
                observed[s].append(values.mean());boots[s].append(values[indices].mean(axis=1))
        for s in [2048,65536]:
            d=np.mean(boots[s],axis=0)
            macro.append({"metric":metric,"comparison":str(s),"mean":float(np.mean(observed[s])),"ci_low":float(np.quantile(d,.025)),"ci_high":float(np.quantile(d,.975)),"cells":8,"pairs_per_cell":6})
        d=np.mean(boots[65536],axis=0)-np.mean(boots[2048],axis=0)
        macro.append({"metric":metric,"comparison":"65536_minus_2048","mean":float(np.mean(observed[65536])-np.mean(observed[2048])),"ci_low":float(np.quantile(d,.025)),"ci_high":float(np.quantile(d,.975)),"cells":8,"pairs_per_cell":6})
    write_csv(folder/"macro_summary.csv",macro)
    write_json(folder/"verification.json",{"status":"PASS","validation_decisions":len(data),"source_condition_traces":len(groups),"source_frag2_events_checked":source_events,"old_decisions_recomputed":raw_checked,"new_decisions":27600,"primary_matched_pairs":48,"all_attack_benign_pairs":120,"benign_only_traces_retained":16,"max_feature_error":max_error,"arrival_query_occupancy_and_origin_matching":True,"source_raw_hashes_verified":True,"held_out_accessed":False})
    write_json(folder/"source_manifest.json",SOURCES)


@dataclass
class Fragment:
    time_ns: int
    key: tuple
    offset: int
    more: bool
    packet_sha: str = ""


def parse_ethernet(data, time_ns, linktype=1):
    if linktype!=1: raise ValueError(f"Unsupported PCAP linktype: {linktype}")
    if len(data)<14: raise ValueError("Truncated Ethernet header")
    pos=14;ether=struct.unpack("!H",data[12:14])[0]
    while ether in (0x8100,0x88A8):
        if len(data)<pos+4:raise ValueError("Truncated VLAN header")
        ether=struct.unpack("!H",data[pos+2:pos+4])[0];pos+=4
    if ether!=0x0800:return None
    ip=data[pos:]
    if len(ip)<20 or ip[0]>>4!=4:raise ValueError("Invalid IPv4 header")
    ihl=(ip[0]&15)*4;length=int.from_bytes(ip[2:4],"big")
    if ihl<20 or length<ihl or len(ip)<length:raise ValueError("Truncated IPv4 packet")
    flags=int.from_bytes(ip[6:8],"big");offset=(flags&8191)*8;more=bool(flags&8192)
    if offset==0 and not more:return None
    src=".".join(map(str,ip[12:16]));dst=".".join(map(str,ip[16:20]))
    key=(src,dst,ip[9],int.from_bytes(ip[4:6],"big"))
    return Fragment(time_ns,key,offset,more,sha(ip[:length]))


class OrphanWindow:
    """Causal matching, retaining a successful association until tail expiry."""
    def __init__(self):
        self.heads={};self.head_queue=deque();self.tails=deque();self.now=-1

    def prune(self,t):
        if t<self.now:raise ValueError("Non-monotonic event/query time")
        self.now=t
        while self.head_queue and self.head_queue[0][0]<t-W:
            ts,key=self.head_queue.popleft()
            if self.heads.get(key)==ts:del self.heads[key]
        while self.tails and self.tails[0][0]<t-W:self.tails.popleft()

    def observe(self,f):
        self.prune(f.time_ns)
        tail=None
        if f.offset==0 and f.more:
            self.heads[f.key]=f.time_ns;self.head_queue.append((f.time_ns,f.key))
            for record in self.tails:
                if record[1]==f.key:record[2]=True
        elif f.offset>0:
            tail=[f.time_ns,f.key,f.key in self.heads]
            self.tails.append(tail)
        return tail

    def snapshot(self,t):
        self.prune(t);n=len(self.tails);orphans=sum(not r[2] for r in self.tails)
        ratio=orphans/n if n else 0.
        return {"samples":n,"orphan_count":orphans,"orphan_ratio":ratio,
            "orphan_majority":n>=8 and 2*orphans>=n,"orphan_any":n>=8 and orphans>0}


def naive_snapshot(fragments,t):
    tails=[f for f in fragments if f.offset>0 and t-W<=f.time_ns<=t]
    heads=defaultdict(list)
    for f in fragments:
        if f.offset==0 and f.more and f.time_ns<=t:heads[f.key].append(f.time_ns)
    unmatched=sum(not any(f.time_ns-W<=stamp<=f.time_ns+W for stamp in heads[f.key]) for f in tails)
    n=len(tails);return n,unmatched


def pcap_fragments(path):
    read(path)  # Pin raw capture before parsing it.
    result=[]; reader=RawPcapNgReader(str(path));previous=-1;packet_count=0;inversions=[]
    try:
        for data,meta in reader:
            packet_count+=1
            timestamp=((meta.tshigh<<32)+meta.tslow)*1_000_000_000//meta.tsresol
            f=parse_ethernet(data,timestamp,meta.linktype)
            if f is None or f.key[0] not in {"10.82.0.100","10.82.0.200"} or f.key[1]!="10.81.0.53":continue
            if timestamp<previous:inversions.append(previous-timestamp)
            previous=timestamp;result.append(f)
    finally:reader.close()
    if not result:raise ValueError("Capture contains no scoped fragments")
    record_max=record_order_max_ratio(result)
    result.sort(key=lambda f:f.time_ns)
    return result,packet_count,{"capture_order_inversions":len(inversions),"max_capture_inversion_ms":max(inversions,default=0)/1e6,"record_order_max_orphan_ratio":record_max}


def record_order_max_ratio(fragments):
    window=OrphanWindow();maximum=0.
    for f in fragments:
        t=max(window.now,f.time_ns)
        window.observe(Fragment(t,f.key,f.offset,f.more))
        if f.offset:maximum=max(maximum,window.snapshot(t)["orphan_ratio"])
    return maximum


def orphan_baseline():
    folder=OUTPUT/"orphan";folder.mkdir(exist_ok=True)
    if (folder/"verification.json").exists():print("Orphan baseline already complete; preserved.");return
    registered=read_json(RUNTIME/"metrics_confirmatory.json")
    assert len(registered)==320
    rows=[];run_rows=[];audit=[];total_fragments=0;total_raw=0;forge_rows=[]
    for index,run in enumerate(registered):
        cell=RUNTIME/run["artifact_dir"]
        fragments,raw_count,capture_audit=pcap_fragments(cell/"ips_outside.pcapng")
        trials=jsonl(cell/"trials.jsonl");attacker=jsonl(cell/"attacker_events.jsonl")
        assert len(trials)==50 and len({t["trial_id"] for t in trials})==50
        forged={h:e for e in attacker if e["event"]=="forged_tail_send" for h in e["packet_sha256"]}
        base={"policy":run["policy"],"workload":run["workload"],"rep":run["rep"]}
        queries=[];offsets=[]
        for trial in trials:
            offset=trial["wall_ns"]-trial["mono_ns"];offsets.append(offset)
            start=trial["query_start_mono_ns"]+offset;end=trial["query_end_mono_ns"]+offset
            assert fragments[0].time_ns+W<=start<=end<=fragments[-1].time_ns
            queries.append((start,end,trial))
        points=sorted([(s,1,i) for i,(s,_,_) in enumerate(queries)]+[(f.time_ns,0,j) for j,f in enumerate(fragments)])
        window=OrphanWindow();query_states={};tail_states=[];forged_seen=set()
        for t,kind,j in points:
            if kind:
                state=window.snapshot(t);query_states[j]=state
                expected=naive_snapshot(fragments,t)
                assert (state["samples"],state["orphan_count"])==expected
            else:
                f=fragments[j];record=window.observe(f)
                if record is not None:
                    state=window.snapshot(t);tail_states.append((t,state))
                    if f.packet_sha in forged:
                        forged_seen.add(f.packet_sha)
                        forge_rows.append({**base,"trial_id":forged[f.packet_sha]["trial_id"],"packet_sha256":f.packet_sha,"time_ns":t,"matching_head_seen_at_ingress":bool(record[2]),**state})
        max_ratio=max(s["orphan_ratio"] for _,s in tail_states)
        invariant=max_ratio==0 and capture_audit["record_order_max_orphan_ratio"]==0
        spread_ms=(max(offsets)-min(offsets))/1e6
        if spread_ms>1 and not invariant:
            raise ValueError(f"Clock alignment unresolved and score is not invariant: {base}")
        tail_times=np.array([t for t,_ in tail_states],dtype=np.int64)
        for j,(start,end,trial) in enumerate(queries):
            state=query_states[j]
            left=np.searchsorted(tail_times,start,side="left");right=np.searchsorted(tail_times,end,side="right")
            candidates=[state]+[s for _,s in tail_states[left:right]]
            entry={**base,"trial_id":trial["trial_id"],"query_start_wall_ns":start,"query_end_wall_ns":end,
                "ratio_at_query":state["orphan_ratio"],"n_at_query":state["samples"],"orphan_at_query":state["orphan_count"],
                "peak_ratio_during_query":max(s["orphan_ratio"] for s in candidates),
                "majority_at_query":state["orphan_majority"],"any_at_query":state["orphan_any"],
                "majority_during_query":any(s["orphan_majority"] for s in candidates),
                "any_during_query":any(s["orphan_any"] for s in candidates),"zero_ratio_in_both_capture_orders":invariant,
                "query_clock_status":"ratio_invariant_despite_offset_uncertainty" if spread_ms>1 else "offset_spread_at_most_1ms"}
            rows.append(entry)
        selected=rows[-50:]
        run_rows.append({**base,"trials":50,"majority_query_rate":float(np.mean([r["majority_at_query"] for r in selected])),
            "any_query_rate":float(np.mean([r["any_at_query"] for r in selected])),
            "majority_interval_rate":float(np.mean([r["majority_during_query"] for r in selected])),
            "any_interval_rate":float(np.mean([r["any_during_query"] for r in selected])),
            "mean_query_ratio":float(np.mean([r["ratio_at_query"] for r in selected])),
            "mean_peak_ratio":float(np.mean([r["peak_ratio_during_query"] for r in selected])),
            "max_tail_ratio":max_ratio,"zero_ratio_in_both_capture_orders":invariant,
            "first_fragments":sum(f.offset==0 for f in fragments),"noninitial_fragments":len(tail_states),
            "forged_logged":len(forged),"forged_observed":len(forged_seen),
            "clock_offset_range_ms":spread_ms,**capture_audit})
        audit.append({**base,"raw_packets":raw_count,"scoped_fragments":len(fragments),"query_states_independently_checked":50,"forged_logged":len(forged),"forged_observed":len(forged_seen),**capture_audit})
        total_fragments+=len(fragments);total_raw+=raw_count
        if (index+1)%20==0:print(f"Orphan PCAP replay: {index+1}/320",flush=True)
    assert len(rows)==16000 and len(run_rows)==320
    write_csv(folder/"trial_scores.csv",rows);write_csv(folder/"run_metrics.csv",run_rows)
    write_csv(folder/"forged_tail_matching.csv",forge_rows)
    summary=[]
    for policy in POLICIES:
        for workload in WORKLOADS:
            cell=[r for r in run_rows if (r["policy"],r["workload"])==(policy,workload)]
            assert sorted(r["rep"] for r in cell)==list(range(1,21))
            for metric in ["majority_query_rate","any_query_rate","majority_interval_rate","any_interval_rate","mean_query_ratio","mean_peak_ratio"]:
                mean,lo,hi=bootstrap([r[metric] for r in cell],SEED+len(summary))
                summary.append({"policy":policy,"workload":workload,"metric":metric,"mean":mean,"ci_low":lo,"ci_high":hi,"runs":20})
    write_csv(folder/"cell_summary.csv",summary)
    comparisons=[]
    for policy in POLICIES:
        for rate in ["MODERATE","HIGH"]:
            scores=defaultdict(list)
            for rep in range(1,21):
                b=[r for r in rows if r["policy"]==policy and r["rep"]==rep and r["workload"]=="BENIGN_DIVERSE_"+rate]
                a=[r for r in rows if r["policy"]==policy and r["rep"]==rep and r["workload"]=="ATTACK_DIVERSE_"+rate]
                assert len(a)==len(b)==50
                for field in ["ratio_at_query","peak_ratio_during_query"]:
                    scores[field+"_AP"].append(float(average_precision_score([0]*50+[1]*50,[r[field] for r in b]+[r[field] for r in a])))
                for field in ["majority_during_query","any_during_query"]:
                    scores[field+"_J"].append(float(np.mean([r[field] for r in a])-np.mean([r[field] for r in b])))
            for metric,v in scores.items():
                mean,lo,hi=bootstrap(v,SEED+len(comparisons))
                comparisons.append({"policy":policy,"rate":12 if rate=="MODERATE" else 200,"metric":metric,"mean":mean,"ci_low":lo,"ci_high":hi,"run_pairs":20})
    write_csv(folder/"paired_summary.csv",comparisons)
    signature_matches=defaultdict(list)
    for row in forge_rows:signature_matches[(row["policy"],row["workload"],row["rep"],row["packet_sha256"])].append(row["matching_head_seen_at_ingress"])
    assert len(signature_matches)==sum(r["forged_observed"] for r in run_rows)
    write_json(folder/"verification.json",{"status":"PASS","runs":320,"trials":16000,"pcap_packets":total_raw,"scoped_fragments":total_fragments,
        "independent_query_snapshot_checks":16000,"forged_logged":sum(r["forged_logged"] for r in run_rows),"forged_observed":sum(r["forged_observed"] for r in run_rows),
        "forged_matched_at_ingress":sum(all(v) for v in signature_matches.values()),
        "forged_count_unit":"unique packet signatures per run",
        "forged_capture_records":len(forge_rows),"forged_matching_capture_records":sum(r["matching_head_seen_at_ingress"] for r in forge_rows),
        "runs_with_zero_ratio_in_both_orders":sum(r["zero_ratio_in_both_capture_orders"] for r in run_rows),
        "runs_clock_alignment_uncertain":sum(r["clock_offset_range_ms"]>1 for r in run_rows),
        "max_clock_offset_range_ms":max(r["clock_offset_range_ms"] for r in run_rows),"audit":audit})
    write_json(folder/"source_manifest.json",SOURCES)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--stage",choices=["controlled","orphan","all"],default="all")
    args=parser.parse_args();register()
    if args.stage in ["controlled","all"]:controlled()
    if args.stage in ["orphan","all"]:orphan_baseline()
    print(f"Analysis finished: {OUTPUT}")


if __name__=="__main__":main()
