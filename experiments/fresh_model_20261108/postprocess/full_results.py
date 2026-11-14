#!/usr/bin/env python3
"""Read-only saved-kernel postprocessing. Never loads BPF or changes frozen code."""
import argparse
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys

os.environ.setdefault('MPLCONFIGDIR','/tmp/nn-ebpf-fresh-final-plots')
ROOT=Path(__file__).resolve().parents[3]
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE));sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
import numpy as np
from pipeline import metrics
import kernel
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
r=kernel.read(a.run/'results.json');review=kernel.read(BASE/'FULL_VERIFIED.json')
assert r['status']==review['status']=='PASS' and r['phase']=='full' and r['cleanup']=='PASS'
assert review['results_sha256']==kernel.sha(a.run/'results.json') and review['raw_sha256']==kernel.sha(a.run/'measurements.jsonl.gz')
plan=kernel.check_bundle(Path(r['bundle']))
a.output.mkdir(parents=True,exist_ok=False)
raw=np.load(ROOT/'dataset/reproduction-xdp-data.npy',allow_pickle=False)
truth=np.load(ROOT/'dataset/reproduction-xdp-label.npy',allow_pickle=False).astype(np.int64)
ids=kernel.read(BASE/'run/split.json')['partitions']['test']['indices']
observed={m:{} for m in kernel.MODES};times={m:[] for m in kernel.MODES};counts={m:{'warmup':0,'measured':0} for m in kernel.MODES}
fields=['phase','mode','trial','position','row_index','duration_ns','status','cpu','stage_mask','model_slot','sequence','stage0','stage1','stage2','stage3','stage4','stage5','prediction_delta','prediction','logit0','logit1','q_logits','supplied_label']
with gzip.open(a.output/'per-vector-timings.csv.gz','wt',newline='') as f:
 writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
 for line in gzip.open(a.run/'measurements.jsonl.gz','rt'):
  row=json.loads(line)
  if row['phase']=='guard':continue
  assert row['status']=='PASS';b=row['block'];v=b['record'];index=row['row_index'];mode=row['mode']
  assert index==ids[row['position']] and v['features']==raw[index].tolist()
  assert b['samples']==1 and b['kernel_repeat']==1 and b['stage_deltas']==[1]*6 and v['mask']==63
  counts[mode][row['phase']]+=1
  if row['phase']=='measured':
   times[mode]+=b['duration_ns']
   if row['trial']==0:
    assert index not in observed[mode];observed[mode][index]=v['label']
  ev=next(e for e in r['resources'][mode] if e['event']=='inference_mode')
  q=ev['tensor_exponents'][-1] if mode=='static_q16' else ev['q_outputs'][-1]
  values=dict(phase=row['phase'],mode=mode,trial=row['trial'],position=row['position'],row_index=index,duration_ns=b['duration_ns'][0],
   status=row['status'],cpu=v['cpu'],stage_mask=v['mask'],model_slot=v['model_slot'],sequence=v['sequence'],
   prediction_delta=b['prediction_delta'],prediction=v['label'],logit0=v['tensors'][-1][0],logit1=v['tensors'][-1][1],q_logits=q,supplied_label=int(truth[index]))
  values.update({f'stage{i}':n for i,n in enumerate(b['stage_deltas'])});writer.writerow(values)
unique_metrics={m:metrics(truth[ids].tolist(),[observed[m][i] for i in ids]) for m in kernel.MODES}
for m in kernel.MODES:
 assert set(observed[m])==set(ids)
 assert unique_metrics[m]==kernel.read(BASE/'run/comparison.json')['modes'][kernel.HOST[m]]['metrics']
 assert counts[m]=={'warmup':2826,'measured':14130}
kernel.write(a.output/'kernel-unique-row-metrics.json',dict(status='PASS',execution='Actual kernel test-run model predictions, trial 0 once per test row; not live traffic',
 cohort_ids=ids,models=unique_metrics,measured_counts=counts,denominator_policy='2826 unique rows per mode; trials/warmups/guards are not independent test samples'))
colors={'static_q16':'#27648a','layer_specific':'#d68532'};labels={'static_q16':'TC Q16','layer_specific':'TC layer-specific'}
fig,axes=plt.subplots(1,3,figsize=(14,4.3),layout='constrained')
lo=min(min(v) for v in times.values())/1000;hi=max(max(v) for v in times.values())/1000
bins=np.geomspace(lo,hi,65)
for m in kernel.MODES:
 x=np.array(times[m],dtype=np.float64)/1000
 axes[0].hist(x,bins=bins,histtype='step',linewidth=1.6,label=labels[m],color=colors[m])
 axes[1].plot(np.sort(x),np.arange(1,len(x)+1)/len(x),label=labels[m],color=colors[m])
 axes[2].plot(range(1,6),[t['mean_ns']/1000 for t in r['modes'][m]['per_trial']],marker='o',label=labels[m],color=colors[m])
axes[0].set(xscale='log',yscale='log',xlabel='Kernel duration (µs, log scale)',ylabel='Measured calls (log scale)',title='Distribution: all samples retained')
axes[1].set(xscale='log',xlabel='Kernel duration (µs, log scale)',ylabel='Cumulative fraction',title='Empirical CDF',ylim=(0,1.02))
axes[2].set(xticks=range(1,6),xlabel='Measurement trial',ylabel='Mean duration (µs)',title='Same 2,826 vectors each trial')
axes[0].legend();fig.suptitle('Fresh model: actual kernel stage-chain timing — 2,826 vectors × 5 trials; no packet extraction')
fig.savefig(a.output/'fresh-kernel-distributions.png',dpi=170);fig.savefig(a.output/'fresh-kernel-distributions.pdf');plt.close(fig)
old=kernel.read(ROOT/'verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/results.json')
fig,axes=plt.subplots(1,2,figsize=(10.5,4.4),sharey=True,layout='constrained')
for ax,result,title in [(axes[0],old,'Original model: 13,844 calibration-held-out'),(axes[1],r,'Fresh model: 2,826 test-held-out')]:
 for j,m in enumerate(kernel.MODES):
  ax.bar(np.arange(4)+(j-.5)*.32,[result['modes'][m][k]/1000 for k in ('mean_ns','median_ns','p95_ns','p99_ns')],width=.3,color=colors[m],label=labels[m])
 ax.set(xticks=range(4),xticklabels=['Mean','p50','p95','p99'],title=title,xlabel='Five trials in each separate experiment')
axes[0].set_ylabel('Kernel stage-chain duration (µs)');axes[0].legend()
fig.suptitle('Different checkpoints/cohorts and run conditions — no causal old/new speedup claim')
fig.savefig(a.output/'separate-old-and-fresh-kernel.png',dpi=170);fig.savefig(a.output/'separate-old-and-fresh-kernel.pdf');plt.close(fig)
write=dict(status='PASS',raw_input_sha256=review['raw_sha256'],results_sha256=review['results_sha256'],network_or_kernel_operations='NONE',
 csv_rows=33912,csv_measurements=28260,csv_warmups=5652,guard_calls_in_raw_json_only=6,
 trial_labels='Stored trial -1 is warmup; measured trials 0..4',old_result_source=str(ROOT/'verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/results.json'))
kernel.write(a.output/'postprocess.json',write)
print(json.dumps(write,indent=2))
