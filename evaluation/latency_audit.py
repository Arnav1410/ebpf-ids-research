#!/usr/bin/env python3
"""Read-only raw-timing audit using NumPy as an independent statistics check."""
import argparse
from collections import Counter
import gzip
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import numpy as np
from evaluation.data import digest
from evaluation.latency import MODES, SCOPES, check_block


def close(a,b):
    if not math.isclose(float(a),float(b),rel_tol=1e-12,abs_tol=1e-9):
        raise AssertionError(f'Saved/recomputed timing differs: {a} vs {b}')


def statistics_check(values,saved):
    data=np.asarray(values,dtype=np.float64)
    if len(data)!=saved['samples'] or np.any(data<=0):raise AssertionError('Missing/invalid raw timings')
    for key,value in dict(mean_ns=np.mean(data),median_ns=np.median(data),p95_ns=np.quantile(data,.95),
                          p99_ns=np.quantile(data,.99),minimum_ns=np.min(data),maximum_ns=np.max(data),
                          population_stddev_ns=np.std(data,ddof=0)).items():close(value,saved[key])


def audit(directory):
    result=json.loads((directory/'results.json').read_text());plan=json.loads((directory/'plan.json').read_text())
    if digest(directory/'raw-timings.jsonl.gz')!=result['raw_timings_sha256'] or digest(directory/'plan.json')!=result['plan_sha256']:
        raise AssertionError('Raw timing/plan hash differs')
    for p,h in plan['original_evidence_hashes'].items():
        if digest(ROOT/p)!=h:raise AssertionError('Original numerical evidence changed')
    blocks=[];controls={}
    with gzip.open(directory/'raw-timings.jsonl.gz','rt') as stream:
        for line in stream:
            record=json.loads(line)
            if 'timer_control' in record:controls[record['timer_control']]=record['observation']
            else:blocks.append(record)
    if len(blocks)!=result['trials']*6 or set(controls)!=set(MODES):raise AssertionError('Incomplete experiment')
    groups={};calls=failures=0
    for scope in SCOPES:
        for mode in MODES:
            found=sorted((b for b in blocks if b['scope']==scope and b['mode']==mode),key=lambda b:b['trial'])
            if [b['trial'] for b in found]!=list(range(result['trials'])):raise AssertionError('Duplicate/missing trial')
            saved=result['host'][scope][mode]
            for b,t in zip(found,saved['trials']):
                for kind in ('warmup','individual','batch'):
                    check_block(b[kind],result['input_count'],plan['cpu'],found[0]['warmup']['checksum'])
                    calls+=b[kind]['successful'];failures+=b[kind]['failed']
                statistics_check(b['individual']['duration_ns'],t['individual'])
                close(b['batch']['elapsed_ns'],t['batch_ns'])
                close(b['batch']['elapsed_ns']/result['input_count'],t['batch_ns_per_inference'])
            raw=[v for b in found for v in b['individual']['duration_ns']]
            statistics_check(raw,saved)
            total=sum(b['batch']['elapsed_ns'] for b in found)
            close(total,saved['batch_total_ns'])
            close(total/(result['input_count']*result['trials']),saved['batch_mean_per_inference_ns'])
            close(result['input_count']*result['trials']*1e9/total,saved['sequential_host_inferences_per_second'])
            close(np.std([t['individual']['mean_ns'] for t in saved['trials']],ddof=0),saved['trial_mean_population_stddev_ns'])
            groups[scope+':'+mode]=dict(trials=len(found),individual_samples=len(raw),batch_inferences=result['input_count']*len(found))
        baseline=result['host'][scope]['tc_q16']
        for mode in MODES:
            item=result['host'][scope][mode]
            for key,value in item['relative_to_tc_q16_percent'].items():close(100*(item[key]-baseline[key])/baseline[key],value)
    for mode,control in controls.items():
        check_block(control,result['input_count'],plan['cpu'])
        statistics_check(control['duration_ns'],result['timer_controls'][mode])
    sources=json.loads((directory/'preserved-source-hashes.json').read_text())
    if any(digest(ROOT/p)!=h for p,h in sources.items()):raise AssertionError('Preserved source changed')
    old=ROOT/result['historical_kernel_evidence']['raw_run']
    raw_kernel=json.loads((old/'blocks.json').read_text())
    for name,modes in result['historical_kernel_evidence']['summaries'].items():
        for mode,summary in modes.items():
            statistics_check([v for b in raw_kernel if b['workload']==name and b['mode']==mode for v in b['duration_ns']],summary)
    value=dict(status='PASS',method='Independent NumPy statistics from saved raw durations; no new inference/kernel execution',
        numpy_version=np.__version__,groups=groups,total_successful_inferences_including_warmup=calls,failed=failures,
        validated_intermediate_tensors=calls*6,validated_integer_outputs=calls*136,
        all_original_prediction_logit_stage_checks='Checked against archived expectations by C after every pass',
        host_statistics='PASS',historical_kernel_statistics='PASS',source_and_old_numerical_evidence_unchanged='PASS')
    (directory/'independent-audit.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',required=True,type=Path)
    audit(p.parse_args().run.resolve())
