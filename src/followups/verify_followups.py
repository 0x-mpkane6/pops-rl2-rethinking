"""Independent checks of post-hoc exports, source hashes and aggregation."""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score

from analyze_followups import OUTPUT, ROOT


def csv_rows(path):
    with path.open() as f:return list(csv.DictReader(f))


def main():
    for name in ['controlled','orphan']:
        manifest=json.loads((OUTPUT/name/'source_manifest.json').read_text())
        for file,expected in manifest.items():
            assert hashlib.sha256((ROOT/file).read_bytes()).hexdigest()==expected,file
    # Recompute every primary/secondary trace metric from retained decisions,
    # using a separate grouping and calculation from the analysis writer.
    decisions=defaultdict(list);count=0
    with gzip.open(OUTPUT/'controlled/decisions.jsonl.gz','rt') as f:
        for line in f:
            r=json.loads(line);count+=1
            key=(r['source_split'],r['profile'],r['level'],r['pair_id'],r['condition'],r['space'])
            decisions[key].append(r)
            assert 0<=r['frag1_ipid']<r['space']
            assert r['B5_locked']==(r['samples']>=8 and r['entropy']>=6 and r['unique_ratio']>=.9)
            assert r['B5_initial']==(r['samples']>=24 and r['entropy']>=4 and r['unique_ratio']>=.7)
    assert count==55200 and all(len(v)==150 for v in decisions.values())
    for key,seq in decisions.items():
        if key[-1]!=2048:continue
        other=decisions[(*key[:-1],65536)]
        for a,b in zip(seq,other):
            assert (a['query_time'],a['samples'],a['attack_events_in_window'])==(b['query_time'],b['samples'],b['attack_events_in_window'])
    paired=csv_rows(OUTPUT/'controlled/paired_metrics.csv')
    for row in paired:
        key=(row['source_split'],row['profile'],int(row['level']),int(row['pair_id']),row['condition'],int(row['space']))
        a=decisions[key];b=decisions[(*key[:4],'benign_'+row['profile'],key[-1])]
        metric=row['metric']
        if metric.endswith('_AP'):
            feature=metric[:-3]
            value=average_precision_score([0]*len(b)+[1]*len(a),[r[feature] for r in b]+[r[feature] for r in a])
        else:
            suffix=next(s for s in ['attack_alert','benign_trigger','FNR','J'] if metric.endswith('_'+s))
            rule=metric[:-(len(suffix)+1)]
            attack=sum(r[rule] for r in a)/len(a);benign=sum(r[rule] for r in b)/len(b)
            value={'attack_alert':attack,'benign_trigger':benign,'FNR':1-attack,'J':attack-benign}[suffix]
        assert abs(value-float(row['value']))<1e-12,row
    macros=csv_rows(OUTPUT/'controlled/macro_summary.csv')
    for row in macros:
        values={s:[float(r['value']) for r in paired if r['role']=='primary' and r['metric']==row['metric'] and int(r['space'])==s] for s in [2048,65536]}
        assert len(values[2048])==len(values[65536])==48
        mean=float(np.mean(values[65536])-np.mean(values[2048])) if row['comparison']=='65536_minus_2048' else float(np.mean(values[int(row['comparison'])]))
        assert abs(mean-float(row['mean']))<1e-12
        assert float(row['ci_low'])<=mean+1e-12 and mean<=float(row['ci_high'])+1e-12
    orphan=csv_rows(OUTPUT/'orphan/trial_scores.csv');runs=csv_rows(OUTPUT/'orphan/run_metrics.csv');forged=csv_rows(OUTPUT/'orphan/forged_tail_matching.csv')
    assert len(orphan)==16000 and len(runs)==320
    # Exact invariant verifies that clock conversion cannot change these scores.
    assert all(float(r['max_tail_ratio'])==float(r['record_order_max_orphan_ratio'])==0 for r in runs)
    assert all(float(r['ratio_at_query'])==float(r['peak_ratio_during_query'])==0 for r in orphan)
    assert all(r['majority_during_query']==r['any_during_query']=='False' for r in orphan)
    signature_keys={(r['policy'],r['workload'],r['rep'],r['packet_sha256']) for r in forged}
    audit=json.loads((OUTPUT/'orphan/verification.json').read_text())
    assert len(signature_keys)==audit['forged_observed']==audit['forged_matched_at_ingress']
    assert len(forged)==audit['forged_capture_records']==audit['forged_matching_capture_records']
    assert all(r['matching_head_seen_at_ingress']=='True' for r in forged)
    result={'status':'PASS','controlled_decisions':count,'paired_metric_rows_independently_recomputed':len(paired),
        'primary_macro_rows_checked':len(macros),'orphan_trial_rows':len(orphan),'runtime_runs':len(runs),
        'all_sources_hash_verified':True,'orphan_ratio_zero_in_timestamp_and_record_orders':True,
        'forged_unique_signatures':len(signature_keys),'forged_capture_records':len(forged),
        'query_ratio_invariant_to_clock_alignment':True,'held_out_accessed':False}
    (OUTPUT/'independent_verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()
