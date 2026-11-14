#!/usr/bin/env python3
"""Original XDP whole-chain completion witnesses and paired private kernel timing."""
import argparse
from collections import Counter
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import platform

sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tc'))
FRESH=ROOT/'experiments/fresh_model_20261108';sys.path.insert(0,str(FRESH))
from kernel import FreshController
from evaluation.kernel_latency import BoundedController
from evaluation.latency import summary_ns
from tc.demo import Log,need
from validation.reference import STAGES
import kernel as fresh
MODES=('xdp_q16','static_q16','layer_specific')
P1=[0x5a123400+i for i in range(32)];P2=[-0x5a123400-i for i in range(32)]
def read(p):return json.loads(Path(p).read_text())
def write(p,v):Path(p).write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def preserve():
 source=read(BASE/'preservation-before.json');need(all(sha(ROOT/n)==h for n,h in source.items()),'An existing source/model/evidence file changed')
 return len(source)
def states(t):
 a=P1[:];b=P2[:];out=[(a[:],b[:])]
 b[:6]=t['normalized'];out.append((a[:],b[:]))
 a=t['linear0'][:];out.append((a[:],b[:]))
 a=t['relu0'][:];out.append((a[:],b[:]))
 b=t['linear1'][:];out.append((a[:],b[:]))
 b=t['relu1'][:];out.append((a[:],b[:]))
 a[:2]=t['logits'];out.append((a[:],b[:]))
 return out
def certificate(t):
 v=states(t);dist=[sum(a!=b for x,y in zip(s,v[-1]) for a,b in zip(x,y)) for s in v[:-1]]
 need(all(dist),'Unobservable completion: full workspace equals an early-stop prefix')
 return dist

def verify_xdp(b,case,cpu,op='measure',kind=0,warm=0,samples=1):
 t=case['expected']['static_q16']['tensors'];v=states(t);certificate(t)
 need(b['event']=='xdp_block' and b['mode']=='xdp_q16' and b['operation']==op and b['kind']==kind,'Wrong XDP command')
 need(b['cpu']==cpu and b['flags']==0 and b['kernel_repeat']==1 and b['warmup']==warm and b['samples']==samples,'Wrong XDP timing protocol')
 need(b['packet_dport']==case['features'][3],'Context port differs from stored feature')
 need(b['calls']==(6 if op=='isolated' else warm+samples),'Wrong original program invocation count')
 if op=='failure' and kind==6:
  need(not b['flow_present'] and not b['states'] and not b['duration_ns'],'Missing-flow control did not return unscored');return
 expected=v[1:] if op=='isolated' else [v[kind] if op=='failure' and kind<=5 else v[0] if op=='failure' else v[-1]]*(warm+samples)
 need(b['flow_present'] and len(b['states'])==len(expected),'Missing state readback')
 for actual,(h1,h2) in zip(b['states'],expected):
  need(actual['features']==case['features'] and actual['model_slot']==(-1 if op=='failure' and kind==7 else 0) and actual['nonce']>0,'Wrong XDP flow seed')
  need(actual['hidden1']==h1 and actual['hidden2']==h2,'Original XDP workspace/prefix mismatch')
  if op=='measure':need(actual['prediction_derived']==case['expected']['static_q16']['prediction'],'Original XDP logit-derived label mismatch')
 if op=='measure':
  need(len(b['duration_ns'])==samples and all(type(n)is int and 0<n<0xffffffff for n in b['duration_ns']),'Bad full-chain duration')
  need(len(set(s['nonce'] for s in b['states']))==warm+samples,'Reused completion in repeat guard')
 else:need(not b['duration_ns'],'Diagnostic stage/prefix timings must not be published as inference latency')

class XDPController(BoundedController):
 def __init__(self,log,bundle):
  self.log=log;self.mode='xdp_q16';self.directory=log.output/self.mode;self.directory.mkdir()
  self.events=[];self.ready=None;self.pending=b'';self.stopped=False
  self.err=(self.directory/'controller.log').open('w');self.raw_events=gzip.open(self.directory/'controller-events.jsonl.gz','wt')
  argv=[str(bundle/'.output/xdp_runner'),'--serve',str(bundle/'.output/xdp.bpf.o'),str(self.directory),str(bundle/'model.bin')]
  write(self.directory/'command.json',argv)
  try:self.proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,bufsize=0)
  except Exception:self.err.close();self.raw_events.close();raise
 def vector(self,cpu,case,op='measure',kind=0,warm=0,samples=1):
  self.proc.stdin.write((' '.join(map(str,[op,cpu,kind,warm,samples,*case['features']]))+'\n').encode());self.proc.stdin.flush()
  block=self.read('xdp_block');verify_xdp(block,case,cpu,op,kind,warm,samples);return block

def prepare(bundle):
 preserve();bundle=bundle.resolve();bundle.mkdir(parents=True,exist_ok=False);log=Log(bundle);build=bundle/'.output';build.mkdir()
 src_bundle=FRESH/'run/kernel-ready';fresh.check_bundle(src_bundle)
 cases=[json.loads(s) for s in gzip.open(src_bundle/'fixtures.jsonl.gz','rt')]
 source=fresh.refs(FRESH/'run')['static_q16'];minimum=64
 for c in cases:
  need(0<=c['features'][3]<=65535 and c['features'][5]>0,'Unsupported original context/divisor')
  events=[];values,label=source.infer(c['features'],events)
  need(not events and values==c['expected']['static_q16']['tensors'] and label==c['expected']['static_q16']['prediction'],'Fresh Q16 reference changed')
  minimum=min(minimum,*certificate(values))
 (bundle/'model.bin').write_bytes(source.packed())
 with gzip.open(bundle/'fixtures.jsonl.gz','wt') as f:
  for c in cases:f.write(json.dumps(c,separators=(',',':'))+'\n')
 # Isolate ONLY a userspace seed adaptation. No BPF instructions are changed.
 tree=build/'tree';tree.mkdir()
 import shutil
 for name in ('src','tc','quantization'):
  for p in (ROOT/name).rglob('*'):
   if p.is_file() and p.suffix in ('.c','.h') and '.output' not in p.parts:
    dst=tree/p.relative_to(ROOT);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dst)
 shutil.copyfile(FRESH/'run/model/mlp_params.bpf.h',tree/'src/mlp_params.bpf.h')
 shutil.copyfile(FRESH/'run/model/calibrated.h',tree/'quantization/calibrated.h')
 bench=tree/'quantization/benchmark.h';original=bench.read_text();patched=original
 replacements={
 'struct tc_key key=kc_key(49500);':'struct flow input=kc_tuple(49500);input.dport=htons((uint16_t)raw[3]);\n    struct tc_key key={};tc_key_build(&input,&key);',
 '.input=kc_tuple(49500),':'.input=input,',
 'values[cpu].record.input=kc_tuple(49500);':'values[cpu].record.input=input;',
 'packet[36]=5001>>8;packet[37]=5001&255;':'packet[36]=raw[3]>>8;packet[37]=raw[3]&255;'}
 for old,new in replacements.items():need(patched.count(old)==1,'TC seed adaptation context changed');patched=patched.replace(old,new)
 cleanup_anchor='    printf('
 need(patched.count(cleanup_anchor)>0,'TC publication anchor changed')
 patched=patched.replace(cleanup_anchor,'    if(bench_delete(flows,&key)||bench_delete(results_fd,&key))goto done;\n'+cleanup_anchor,1)
 bench.write_text(patched)
 import difflib
 (bundle/'TC_SEED_ONLY.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),patched.splitlines(True),fromfile='original/quantization/benchmark.h',tofile='test-only/quantization/benchmark.h')))
 include=ROOT/'.output/libbpf/usr/include';lib=ROOT/'.output/libbpf/libbpf.a';multi=subprocess.check_output(['gcc','-print-multiarch'],text=True).strip()
 log.command(['clang-12','--version'],'compiler');log.command([ROOT/'.output/bpftool/bpftool','version'],'bpftool');log.command(['uname','-a'],'kernel')
 bpf_flags=['clang-12','-g','-O3','-target','bpf','-mcpu=v3','-I'+str(ROOT/'tc/.output'),'-I'+str(include),'-I/usr/include/'+multi]
 log.command(bpf_flags+['-c',ROOT/'src/xdp.bpf.c','-o',build/'xdp.bpf.o'],'xdp-build')
 log.command(['clang-12','-O2','-g','-Wall','-Wextra','-I'+str(include),BASE/'xdp_runner.c',lib,'-lelf','-lz','-o',build/'xdp_runner'],'runner-build')
 inspect=bundle/'inspect-xdp';inspect.mkdir();log.command([build/'xdp_runner','--inspect',build/'xdp.bpf.o',inspect,bundle/'model.bin'],'xdp-ELF-inspect')
 dis=log.command(['llvm-objdump-12','-dr',build/'xdp.bpf.o'],'xdp-disassembly').stdout
 import re
 functions={}
 for i,name in enumerate(('xdp_prog','xdp_preprocessing','xdp_input_linear','xdp_input_relu','xdp_hidden_linear','xdp_hidden_relu','xdp_output_linear')):
  m=re.search(r'<'+name+r'>:\n(.*?)(?=\n[0-9a-f]+ <xdp_[a-z_]+>:\n|\Z)',dis,re.S);need(m,'Original function absent in ELF: '+name);functions[name]=m[1]
 for i,name in enumerate(('xdp_preprocessing','xdp_input_linear','xdp_input_relu','xdp_hidden_linear','xdp_hidden_relu')):
  need(len(re.findall(r'call 12\b',functions[name]))==1 and re.search(r'[rw]3 = '+str(i+1)+r'\b',functions[name]),'Tail graph disassembly changed: '+name)
 need(not re.search(r'call 12\b',functions['xdp_output_linear']),'Unexpected final tail edge')
 write(bundle/'graph-audit.json',dict(status='PASS',method='Source + original ELF disassembly; one tail edge per nonfinal stage, slots 1..5; no skipped-stage target',
  cohort_rows=len(cases),minimum_full_to_prefix_changed_values=minimum,unobservable_cohort_rows=0,extra_BPF_instructions_added=0))
 for m in ('static_q16','layer_specific'):
  defines=['-DIDS_LAYER_SPECIFIC'] if m=='layer_specific' else []
  log.command(['clang-12','-O2','-g','-Wall','-Wextra','-pthread',*defines,'-I'+str(include),tree/'tc/controller.c',lib,'-lelf','-lz','-o',build/('controller-'+m)],'controller-'+m+'-build')
  shutil.copyfile(src_bundle/'.output'/(m+'.bpf.o'),build/(m+'.bpf.o'))
 plan=dict(status='PREPARED; kernel NOT RUN',model_sha256=sha(bundle/'model.bin'),checkpoint_sha256=sha(FRESH/'run/checkpoint.npz'),header_sha256=sha(FRESH/'run/model/mlp_params.bpf.h'),
  calibration_sha256=sha(FRESH/'run/model/calibrated.json'),test_rows=len(cases),pilot_positions=read(src_bundle/'plan.json')['pilot_positions'],
  modes=list(MODES),pilot_trials=2,full_trials=5,kernel_repeat=1,warmup='One full selected-cohort pass per mode',order='Rotate first mode by (position+trial)%3',
  proof='Verified linear original tail graph + per-record final workspace distinct from every earlier prefix; negative controls and stage-isolated kernel pilot',
  objects=dict(programs=23,maps=22),pilot_calls=1516,full_calls=50877,
  layer_parameter_sha256=fresh.refs(FRESH/'run')['layer_specific'].config['parameter_sha256'],
  source_unchanged=True,original_trace='Original bpf_printk retained; no trace reader/observer/config change; trace cost included in XDP duration',
  prediction='Derived from actual kernel logits with unchanged original tie-to-1 comparison; original trace label not captured')
 write(bundle/'plan.json',plan)
 paths=set(BASE.glob('*.py'))|{BASE/'xdp_runner.c',bundle/'plan.json',bundle/'fixtures.jsonl.gz',bundle/'model.bin'}
 paths.update(p for p in build.rglob('*') if p.is_file())
 paths.update(ROOT/p for p in read(BASE/'preservation-before.json'))
 write(bundle/'manifest.json',{str(p):sha(p) for p in sorted(paths)})
 result=dict(status='PASS',kernel_execution='NOT RUN',manifest_sha256=sha(bundle/'manifest.json'),objects=plan['objects'],pilot_calls=1516,full_calls=50877,
  pilot_command=f'sudo /usr/bin/python3 {BASE}/run.py --execute-pilot {bundle}',prepared_sources_model='UNCHANGED originals',guard='Reject any row without unique final-vs-prefix witness')
 write(bundle/'preparation.json',result);print(json.dumps(result,indent=2))

def check_bundle(b):
 p=read(b/'preparation.json');need(p['status']=='PASS' and sha(b/'manifest.json')==p['manifest_sha256'],'Changed preparation')
 for n,h in read(b/'manifest.json').items():need(sha(n)==h,'Frozen source/data/evidence changed: '+n)
 return read(b/'plan.json')

def check_tc(block,m,case,cpu,warm=0,samples=1):
 wanted=case['expected'][m];fresh.verify(block,m,case['features'],[wanted['tensors'][s] for s in STAGES],wanted['prediction'],cpu,warm,samples)

def audit(out):
 r=read(out/'results.json');need(r['status']=='PASS' and r['cleanup']=='PASS','Execution failed');b=Path(r['bundle']);plan=check_bundle(b)
 cases=[json.loads(s) for s in gzip.open(b/'fixtures.jsonl.gz','rt')];positions=plan['pilot_positions'] if r['phase']=='pilot' else list(range(len(cases)))
 seen=set();diag=set();controls=set();guards=set();times={m:[] for m in MODES};count=0
 for line in gzip.open(out/'measurements.jsonl.gz','rt'):
  row=json.loads(line);m=row['mode'];need(row['status']=='PASS','Failed raw record');case=cases[row['position']];block=row['block']
  if row['phase']=='isolated':
   need(row['position'] not in diag,'Duplicate isolated test');diag.add(row['position']);verify_xdp(block,case,r['environment']['cpu'],'isolated');count+=6;continue
  if row['phase']=='failure':
   need(m=='xdp_q16' and row['kind'] not in controls,'Duplicate/wrong control');controls.add(row['kind'])
   verify_xdp(block,case,r['environment']['cpu'],'failure',row['kind']);count+=1;continue
  warm,samples=(1,2) if row['phase']=='guard' else (0,1)
  if m=='xdp_q16':verify_xdp(block,case,r['environment']['cpu'],warm=warm,samples=samples)
  else:check_tc(block,m,case,r['environment']['cpu'],warm,samples)
  count+=warm+samples
  if row['phase']=='guard':need(m not in guards,'Duplicate guard');guards.add(m);continue
  need(row['row_index']==case['row_index'],'Row identity mismatch')
  key=(m,row['trial'],row['position']);need(key not in seen and row['position'] in positions,'Duplicate/unexpected record');seen.add(key)
  if row['trial']>=0:times[m]+=block['duration_ns']
 expected={(m,t,p) for m in MODES for t in range(-1,r['trials']) for p in positions};need(seen==expected and guards==set(MODES),'Missing intended call')
 need(diag==set(positions) if r['phase']=='pilot' else not diag,'Missing/extra stage-isolated tests')
 need(controls==set(range(1,8)) if r['phase']=='pilot' else not controls,'Missing/extra negative controls')
 for m in MODES:
  for k,v in summary_ns(times[m]).items():need(r['modes'][m][k]==v,'Raw timing/statistic mismatch')
  loaded=next(e for e in r['resources'][m] if e['event']=='loaded');gone=read(out/m/'ids-absent.json')
  need(gone['all_absent'] and loaded['program_ids']==gone['program_ids'] and loaded['map_ids']==gone['map_ids'],'Cleanup ID mismatch')
 return dict(status='PASS',actual_kernel_calls=count,cohort_complete_chains=len(seen),repetition_guard_calls=9,
  isolated_stage_calls=len(diag)*6,numerical_mismatches=0,proof=plan['proof'],cleanup='PASS')

def execute(b,phase,pilot=None):
 need(os.geteuid()==0,'Explicit operator-approved root invocation required');plan=check_bundle(b)
 if phase=='full':
  need(pilot is not None,'Pilot gate required');prior=read(pilot/'results.json');need(prior['phase']=='pilot' and prior['bundle']==str(b.resolve()),'Wrong pilot');audit(pilot)
 cases=[json.loads(s) for s in gzip.open(b/'fixtures.jsonl.gz','rt')];positions=plan['pilot_positions'] if phase=='pilot' else list(range(len(cases)))
 trials=plan[phase+'_trials'];out=b/(phase+'-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));out.mkdir();log=Log(out);print('Final XDP/TC evidence:',out,flush=True)
 cpu=min(os.sched_getaffinity(0));controllers={};times={m:[] for m in MODES};pertrial={m:[[] for _ in range(trials)] for m in MODES};start=time.monotonic()
 r=dict(status='FAIL',phase=phase,bundle=str(b.resolve()),input_count=len(positions),trials=trials,network_attachments=False,
  manifest_sha256=sha(b/'manifest.json'),model_sha256=plan['model_sha256'],checkpoint_sha256=plan['checkpoint_sha256'],
  environment=dict(kernel=platform.release(),python=platform.python_version(),machine=platform.machine(),cpu=cpu,allowed_cpus=sorted(os.sched_getaffinity(0)),cpu_model=next(s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name'))))
 try:
  for m in MODES:
   c=XDPController(log,b) if m=='xdp_q16' else FreshController(log,m,b);controllers[m]=c;ready=c.read('benchmark_ready')
   need(not ready['network_attachments'] and cpu in ready['allowed_cpus'],'Unsafe readiness')
   model=next(e for e in c.events if e['event']=='model');need(model['slots_verified']==2 and model['bytes_per_slot']==(5304 if m=='layer_specific' else 5216),'Wrong parameter loading')
   if m=='layer_specific':need(next(e for e in c.events if e['event']=='inference_mode')['parameter_sha256']==plan['layer_parameter_sha256'],'Wrong new layer model')
   slots=[e for e in c.events if e['event']=='tail_slot'];need([e['slot'] for e in slots]==list(range(6)) and all(e['type']==(6 if m=='xdp_q16' else 3) for e in slots),'Wrong tail array/type')
  with gzip.open(out/'measurements.jsonl.gz','wt') as f:
   def emit(meta,fn):
    row=dict(status='FAIL',**meta)
    try:row['block']=fn();row['status']='PASS'
    except Exception as err:row['error']=str(err);raise
    finally:f.write(json.dumps(row,separators=(',',':'))+'\n')
    return row['block']
   if phase=='pilot':
    for pos in positions:emit(dict(phase='isolated',position=pos,mode='xdp_q16'),lambda pos=pos:controllers['xdp_q16'].vector(cpu,cases[pos],'isolated'))
    for kind in range(1,8):emit(dict(phase='failure',position=positions[0],kind=kind,mode='xdp_q16'),lambda kind=kind:controllers['xdp_q16'].vector(cpu,cases[positions[0]],'failure',kind))
    print('All six stage-isolated tensors and seven negative controls passed',flush=True)
   for m in MODES:
    case=cases[positions[0]]
    def guard(m=m):
     if m=='xdp_q16':return controllers[m].vector(cpu,case,warm=1,samples=2)
     block=controllers[m].measure_vector(cpu,case['features'],1,2);check_tc(block,m,case,cpu,1,2);return block
    emit(dict(phase='guard',position=positions[0],mode=m),guard)
   for trial in range(-1,trials):
    for offset,pos in enumerate(positions):
     rotation=(offset+trial)%3;order=MODES[rotation:]+MODES[:rotation]
     for m in order:
      case=cases[pos]
      def measure(m=m,case=case):
       if m=='xdp_q16':return controllers[m].vector(cpu,case)
       block=controllers[m].measure_vector(cpu,case['features']);check_tc(block,m,case,cpu);return block
      block=emit(dict(phase='warmup' if trial<0 else 'measured',trial=trial,position=pos,row_index=case['row_index'],mode=m),measure)
      if trial>=0:times[m]+=block['duration_ns'];pertrial[m][trial]+=block['duration_ns']
    print('Completed','warmup' if trial<0 else f'trial {trial+1}/{trials}',flush=True)
  r['modes']={m:dict(**summary_ns(times[m]),per_trial=[summary_ns(x) for x in pertrial[m]],measured_calls=len(times[m]),warmup_calls=len(positions),failures=0,kernel_time_normalized_inferences_per_second=len(times[m])*1e9/sum(times[m])) for m in MODES};r['status']='PASS'
 except Exception as err:r['error']=str(err)
 finally:
  clean=[]
  for m,c in controllers.items():
   try:c.stop()
   except Exception as err:r.setdefault('controller_errors',{})[m]=str(err)
   try:need(any(e['event']=='loaded' for e in c.events),'Missing loaded IDs');c.verify_ids_gone();clean.append(m)
   except Exception as err:r.setdefault('cleanup_errors',{})[m]=str(err)
  r['cleanup']='PASS' if set(clean)==set(MODES) else 'FAIL'
  if r['cleanup']!='PASS' or r.get('controller_errors'):r['status']='FAIL'
  r['resources']={m:[e for e in c.events if e['event'] in ('loaded','model','tail_slot','inference_mode','schema')] for m,c in controllers.items()};r['wall_elapsed_seconds']=time.monotonic()-start
  write(out/'results.json',r)
  if r['status']=='PASS':
   try:write(out/'audit.json',audit(out))
   except Exception as err:r['status']='FAIL';r['audit_error']=str(err);write(out/'results.json',r)
  print(json.dumps({k:v for k,v in r.items() if k!='resources'},indent=2),flush=True)
 return int(r['status']!='PASS')

def main():
 p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
 g.add_argument('--prepare',type=Path);g.add_argument('--execute-pilot',type=Path);g.add_argument('--execute-full',type=Path);g.add_argument('--audit',type=Path);p.add_argument('--pilot-evidence',type=Path);a=p.parse_args()
 if a.prepare:prepare(a.prepare)
 elif a.audit:print(json.dumps(audit(a.audit),indent=2))
 else:return execute((a.execute_pilot or a.execute_full).resolve(),'pilot' if a.execute_pilot else 'full',a.pilot_evidence)
if __name__=='__main__':sys.exit(main() or 0)
