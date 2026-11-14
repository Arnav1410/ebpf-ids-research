#!/usr/bin/env python3
"""Independent saved-record numerical/statistics/identity audit; no BPF operations."""
import argparse
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys
import numpy as np
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[1];sys.path.insert(0,str(BASE))
import run as h
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
r=h.read(a.run/'results.json');bundle=Path(r['bundle']);plan=h.check_bundle(bundle)
assert r['status']=='PASS' and r['cleanup']=='PASS' and r['manifest_sha256']==h.sha(bundle/'manifest.json')
assert r['model_sha256']==h.sha(bundle/'model.bin')==plan['model_sha256']
assert r['checkpoint_sha256']==plan['checkpoint_sha256']==h.sha(h.FRESH/'run/checkpoint.npz')
assert h.sha(h.FRESH/'run/model/mlp_params.bpf.h')==plan['header_sha256']
assert h.sha(h.FRESH/'run/model/calibrated.json')==plan['calibration_sha256']
refs=h.fresh.refs(h.FRESH/'run');assert refs['static_q16'].packed()==(bundle/'model.bin').read_bytes()
assert hashlib.sha256(refs['layer_specific'].packed()).hexdigest()==plan['layer_parameter_sha256']
fx=[json.loads(s) for s in gzip.open(bundle/'fixtures.jsonl.gz','rt')]
source=np.load(ROOT/'dataset/reproduction-xdp-data.npy',allow_pickle=False)
assert [c['row_index'] for c in fx]==h.read(h.FRESH/'run/split.json')['partitions']['test']['indices']
positions=plan['pilot_positions'] if r['phase']=='pilot' else list(range(len(fx)))
assert positions==sorted(positions) and len(set(positions))==r['input_count']
if r['phase']=='pilot':
 computed=sorted(sorted(range(len(fx)),key=lambda i:hashlib.sha256(('fresh-kernel-pilot-v1\n'+str(fx[i]['row_index'])).encode()).digest())[:100])
 assert positions==computed
expected={};distances={};identities={};verifier_logs=0
for pos in positions:
 c=fx[pos];assert c['features']==source[c['row_index']].tolist()
 for mode in ('static_q16','layer_specific'):
  events=[];t,label=refs[mode].infer(c['features'],events);assert not events
  assert t==c['expected'][mode]['tensors'] and label==c['expected'][mode]['prediction']
  expected[mode,pos]=(t,label)
 distances[pos]=h.certificate(expected['static_q16',pos][0])
for mode in h.MODES:
 ev=r['resources'][mode];loaded=next(e for e in ev if e['event']=='loaded');slots=[e for e in ev if e['event']=='tail_slot'];info=next(e for e in ev if e['event']=='model')
 assert len(loaded['program_ids'])==(7 if mode=='xdp_q16' else 8)
 assert len(loaded['map_ids'])==(9 if mode=='layer_specific' else 5 if mode=='xdp_q16' else 8)
 assert [e['slot'] for e in slots]==list(range(6))
 assert len(set(e['program_id'] for e in slots))==6 and all(e['type']==(6 if mode=='xdp_q16' else 3) and e['program_id'] in loaded['program_ids'] for e in slots)
 assert info==dict(event='model',bytes_per_slot=5304 if mode=='layer_specific' else 5216,slots_verified=2,active=0)
 if mode=='layer_specific':assert next(e for e in ev if e['event']=='inference_mode')['parameter_sha256']==plan['layer_parameter_sha256']
 gone=h.read(a.run/mode/'ids-absent.json');assert gone['all_absent'] and gone['program_ids']==loaded['program_ids'] and gone['map_ids']==loaded['map_ids']
 logs=[p for p in (a.run/mode).glob('verifier-*.log') if p.name!='verifier-btf.log']
 assert len(logs)==len(loaded['program_ids'])
 assert all(any(line.startswith('processed ') for line in p.read_text().splitlines()) for p in logs)
 assert (a.run/mode/'controller.log').stat().st_size==0
 verifier_logs+=len(logs);identities[mode]=dict(**loaded,tail_slot_ids=[e['program_id'] for e in slots],model=info)
seen=set();isolated=set();controls=set();guards=set();nonces=set();order=[];times={m:[] for m in h.MODES};bytrial={m:[[] for _ in range(r['trials'])] for m in h.MODES}
records=0;calls=0;workspace_reads=0;sample=None
with (a.output/'per-vector-timings.csv').open('w',newline='') as stream:
 writer=csv.DictWriter(stream,fieldnames=['mode','trial','position','row_index','phase','duration_ns','label','logit0','logit1','cpu','status']);writer.writeheader()
 for line in gzip.open(a.run/'measurements.jsonl.gz','rt'):
  row=json.loads(line);records+=1;assert row['status']=='PASS';m=row['mode'];assert m in h.MODES
  pos=row['position'];assert pos in positions;c=fx[pos];b=row['block'];cpu=r['environment']['cpu'];phase=row['phase']
  if m=='xdp_q16':
   assert b['entry_program_id']==identities[m]['program_ids'][0]
   if phase=='isolated':
    assert pos not in isolated;isolated.add(pos);h.verify_xdp(b,c,cpu,'isolated');calls+=6
    nonces_here={s['nonce'] for s in b['states']};assert len(nonces_here)==1
    meaningful=[(state['hidden2'][:6] if i==0 else state['hidden1'][:2] if i==5 else state['hidden2'] if i in (3,4) else state['hidden1']) for i,state in enumerate(b['states'])]
    assert meaningful==[expected['static_q16',pos][0][s] for s in h.STAGES]
    if sample is None:
     sample=dict(source_row=c['row_index'],features=c['features'],expected_normalized=expected['static_q16',pos][0]['normalized'],kernel_isolated_normalized=meaningful[0],expected_logits=expected['static_q16',pos][0]['logits'])
   elif phase=='failure':
    kind=row['kind'];assert kind not in controls;controls.add(kind);h.verify_xdp(b,c,cpu,'failure',kind);calls+=1
    nonces_here={s['nonce'] for s in b['states']}
    for s in b['states']:assert (s['hidden1'],s['hidden2'])!=h.states(expected['static_q16',pos][0])[-1]
   else:
    warm,samples=(1,2) if phase=='guard' else (0,1);h.verify_xdp(b,c,cpu,warm=warm,samples=samples);calls+=warm+samples
    nonces_here={s['nonce'] for s in b['states']};assert len(nonces_here)==warm+samples
    workspace_reads+=len(b['states'])
    if sample is not None and c['row_index']==sample['source_row']:sample['kernel_chain_logits']=b['states'][-1]['hidden1'][:2]
   assert not nonces.intersection(nonces_here);nonces.update(nonces_here)
  else:
   assert phase not in ('isolated','failure')
   warm,samples=(1,2) if phase=='guard' else (0,1);h.check_tc(b,m,c,cpu,warm,samples);calls+=warm+samples
   key=b['record']['key'];assert key==dict(a_ip='33.33.33.1',a_port=c['features'][3],b_ip='33.33.33.73',b_port=49500,protocol=6)
  if phase in ('isolated','failure'):continue
  if phase=='guard':assert m not in guards;guards.add(m);continue
  assert phase in ('warmup','measured') and row['row_index']==c['row_index'] and -1<=row['trial']<r['trials']
  assert (phase=='warmup')==(row['trial']==-1)
  identity=(m,row['trial'],pos);assert identity not in seen;seen.add(identity);order.append(identity)
  logits=b['states'][-1]['hidden1'][:2] if m=='xdp_q16' else b['record']['tensors'][-1]
  label=b['states'][-1]['prediction_derived'] if m=='xdp_q16' else b['record']['label']
  writer.writerow(dict(mode=m,trial=row['trial'],position=pos,row_index=c['row_index'],phase=phase,duration_ns=b['duration_ns'][0],label=label,logit0=logits[0],logit1=logits[1],cpu=cpu,status='PASS'))
  if phase=='measured':times[m]+=b['duration_ns'];bytrial[m][row['trial']]+=b['duration_ns']
expected_order=[]
for trial in range(-1,r['trials']):
 for off,pos in enumerate(positions):
  k=(off+trial)%3;expected_order.extend((m,trial,pos) for m in h.MODES[k:]+h.MODES[:k])
assert order==expected_order and len(seen)==len(positions)*3*(r['trials']+1) and guards==set(h.MODES)
assert isolated==(set(positions) if r['phase']=='pilot' else set()) and controls==(set(range(1,8)) if r['phase']=='pilot' else set())
assert calls==plan[r['phase']+'_calls']

def stats(v):
 x=np.array(v,dtype=np.float64)
 return dict(samples=len(x),mean_ns=float(x.mean()),median_ns=float(np.median(x)),p95_ns=float(np.percentile(x,95)),p99_ns=float(np.percentile(x,99)),minimum_ns=int(x.min()),maximum_ns=int(x.max()),population_stddev_ns=float(np.std(x,ddof=0)))
trials=[]
for m in h.MODES:
 saved=r['modes'][m]
 assert saved['measured_calls']==len(times[m])==r['trials']*len(positions) and saved['warmup_calls']==len(positions) and saved['failures']==0
 for key,value in stats(times[m]).items():assert math.isclose(value,saved[key],rel_tol=1e-12,abs_tol=1e-9),(m,key,value,saved[key])
 assert math.isclose(saved['kernel_time_normalized_inferences_per_second'],len(times[m])*1e9/sum(times[m]),rel_tol=1e-12)
 for i,values in enumerate(bytrial[m]):
  assert len(values)==len(positions)
  for key,value in stats(values).items():assert math.isclose(value,saved['per_trial'][i][key],rel_tol=1e-12,abs_tol=1e-9)
  trials.append(dict(mode=m,trial=i+1,**stats(values)))
with (a.output/'per-trial-summary.csv').open('w',newline='') as f:
 writer=csv.DictWriter(f,fieldnames=list(trials[0]));writer.writeheader();writer.writerows(trials)
review=dict(status='PASS',phase=r['phase'],scope='Independent read-only saved-record audit; no new kernel or network operations',raw_records=records,actual_kernel_calls=calls,
 cohort_complete_chains=len(seen),guard_complete_chains=9,isolated_stage_calls=len(isolated)*6,negative_controls=len(controls),
 numerical_mismatches=0,prediction_agreement='PASS for every complete-chain call against frozen new-model reference',minimum_cohort_completion_witness_distance=min(min(v) for v in distances.values()),
 XDP_complete_workspace_readbacks=workspace_reads,XDP_complete_workspace_integer_comparisons=workspace_reads*64,
 XDP_isolated_neural_tensor_comparisons=len(isolated)*6,XDP_isolated_neural_integer_comparisons=len(isolated)*136,
 numpy_version=np.__version__,statistics='PASS pooled and every trial; all outliers retained',model_bytes_sha256=h.sha(bundle/'model.bin'),
 checkpoint_sha256=h.sha(h.FRESH/'run/checkpoint.npz'),manifest_sha256=h.sha(bundle/'manifest.json'),
 verifier_logs_checked=verifier_logs,identities=identities,cleanup='PASS all 23 recorded program and 22 map IDs absent',
 old_files_preserved=h.preserve(),timing_boundary='Original XDP preprocessing through output including original trace; TC preprocessing through result publication; same-session rotating order',
 raw_sha256=h.sha(a.run/'measurements.jsonl.gz'),results_sha256=h.sha(a.run/'results.json'),representative_sample=sample)
h.write(a.output/'audit.json',review)
print(json.dumps({k:v for k,v in review.items() if k!='identities'},indent=2))
