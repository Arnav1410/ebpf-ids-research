#!/usr/bin/env python3
"""Approval-gated fresh-model private TC test-run; no network or tracing attachment."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from datetime import datetime

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tc'))
from evaluation.kernel_latency import BoundedController
from evaluation.latency import summary_ns
from tc.demo import Log,need,verify_private_ids
from validation.reference import Model,STAGES
from quantization.reference import LayerModel
MODES=('static_q16','layer_specific');HOST={'static_q16':'tc_q16','layer_specific':'tc_layer_specific'}


def read(p):return json.loads(Path(p).read_text())
def write(p,x):Path(p).write_text(json.dumps(x,indent=2,allow_nan=False)+'\n')
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def refs(experiment):
    source=Model.load(experiment/'model/mlp_params.bpf.h')
    return {'static_q16':source,'layer_specific':LayerModel.load(experiment/'model/calibrated.json',experiment/'model/mlp_params.bpf.h')}


def verify(block,mode,raw,tensors,label,cpu,warm=0,samples=1):
    need(block['mode']==mode and block['kind']=='mlp' and block['cpu']==cpu,'Wrong kernel context')
    need(block['kernel_repeat']==1 and block['warmup']==warm and block['samples']==samples,'Wrong repeat/sample accounting')
    calls=warm+samples
    need(block['prediction_delta']==calls and block['stage_deltas']==[calls]*6,'Skipped/reused inference')
    need(len(block['duration_ns'])==samples,'Missing duration')
    need(all(type(d) is int and 0<d<0xffffffff for d in block['duration_ns']),'Invalid duration')
    r=block['record']
    need(r['features']==raw and r['mask']==63 and r['cpu']==cpu and r['model_slot']==0 and r['sequence']==1,'Bad fresh result')
    need(r['tensors']==tensors and r['label']==label,'New kernel/C-host numerical mismatch')


def prepare(experiment,bundle):
    exp=experiment.resolve();bundle=bundle.resolve();need(not bundle.exists(),'Use fresh bundle path')
    result=read(exp/'comparison.json');need(result['status']=='PASS' and result['common_valid_count']==result['input_count'],'All host test variants must pass')
    q=read(exp/'quantization.json');reference=refs(exp)
    need(sha(exp/'checkpoint.npz')==q['new_checkpoint_sha256'],'Fresh checkpoint changed')
    need(sha(exp/'model/mlp_params.bpf.h')==q['header_sha256'] and sha(exp/'model/calibrated.json')==q['calibration_sha256'],'Fresh quantization changed')
    bundle.mkdir(parents=True);log=Log(bundle);tree=exp/'.output/tree';build=bundle/'.output';build.mkdir()
    log.command(['clang-12','--version'],'compiler-version')
    log.command([ROOT/'.output/bpftool/bpftool','version'],'bpftool-version')
    log.command(['uname','-a'],'kernel-version')
    include=ROOT/'.output/libbpf/usr/include';lib=ROOT/'.output/libbpf/libbpf.a'
    source_manifest=read(exp/'copied-source-manifest.json')
    for n,h in source_manifest['original_source_hashes'].items():
        need(sha(ROOT/n)==h,'Original source changed before prepare: '+n)
        if n not in source_manifest['parameter_overlays']:need(sha(tree/n)==h,'Copied logic changed: '+n)
    for n,h in source_manifest['parameter_overlays'].items():need(sha(tree/n)==h,'Copied parameter mismatch: '+n)
    for mode in MODES:
        defines=['-DIDS_LAYER_SPECIFIC'] if mode=='layer_specific' else []
        log.command(['clang-12','-O2','-g','-Wall','-Wextra','-pthread',*defines,'-I'+str(include),tree/'tc/controller.c',lib,'-lelf','-lz','-o',build/('controller-'+mode)],'controller-build-'+mode)
        log.command(['clang-12','-g','-O3','-target','bpf','-mcpu=v3',*defines,'-I'+str(ROOT/'tc/.output'),'-I'+str(include),'-I/usr/include/'+subprocess.check_output(['gcc','-print-multiarch'],text=True).strip(),'-c',tree/'tc/tc_ids.bpf.c','-o',build/(mode+'.bpf.o')],'bpf-build-'+mode)
        inspect=bundle/('inspect-'+mode);inspect.mkdir()
        log.command([build/('controller-'+mode),'--inspect',build/(mode+'.bpf.o'),inspect],'elf-inspect-'+mode)
    fixtures=[]
    with gzip.open(exp/'integer-predictions.jsonl.gz','rt') as f:
        for line in f:
            r=json.loads(line)
            for mode in MODES:
                saved=r['modes'][HOST[mode]];issues=[];v,y=reference[mode].infer(r['features'],issues)
                need(not issues and saved['status']=='PASS' and v==saved['tensors'] and y==saved['prediction'],'Fixture reference mismatch')
            fixtures.append(dict(row_index=r['row_index'],features=r['features'],expected={m:r['modes'][HOST[m]] for m in MODES}))
    need([r['row_index'] for r in fixtures]==result['test_row_ids'],'Changed held-out IDs')
    pilot=sorted(sorted(range(len(fixtures)),key=lambda i:hashlib.sha256(('fresh-kernel-pilot-v1\n'+str(fixtures[i]['row_index'])).encode()).digest())[:100])
    with gzip.open(bundle/'fixtures.jsonl.gz','wt') as f:
        for r in fixtures:f.write(json.dumps(r,separators=(',',':'))+'\n')
    plan=dict(schema=1,status='PREPARED; kernel NOT RUN',experiment=str(exp),test_count=len(fixtures),pilot_positions=pilot,
        pilot_selection='Lowest SHA256(fresh-kernel-pilot-v1 newline source ID), original order; no label/prediction selection',
        full_trials=5,pilot_trials=2,warmup='One selected-cohort pass per mode',kernel_repeat=1,
        networks=False,map_pins=False,objects=dict(programs=16,maps=17),
        model_hash=q['header_sha256'],checkpoint_sha256=q['new_checkpoint_sha256'],calibration_sha256=q['calibration_sha256'],
        parameter_sha256={m:hashlib.sha256(reference[m].packed()).hexdigest() for m in MODES},
        pilot_calls=606,full_calls=2*len(fixtures)*6+6,
        original_xdp='NOT RUN; existing per-run full-chain observability limitation',
        scope='Actual TC six-stage model chain, five tails; no packet extraction or userspace syscall wall time')
    write(bundle/'plan.json',plan)
    # Freeze all code/headers/objects used, source cohort and new model artifacts.
    paths=set(p for p in HERE.glob('*.py'))
    paths.update(tree.rglob('*.h'));paths.update(tree.rglob('*.c'));paths.update(build.iterdir())
    paths.update(ROOT/p for p in source_manifest['original_source_hashes'])
    paths.update(ROOT/p for p in ('evaluation/kernel_latency.py','evaluation/latency.py','quantization/benchmark.py','tc/demo.py'))
    paths.update(exp/p for p in ('checkpoint.npz','scaler.json','freeze.json','split.json','config.json','comparison.json','integer-predictions.jsonl.gz','quantization.json','copied-source-manifest.json','model/mlp_params.bpf.h','model/calibrated.json','model/calibrated.h'))
    paths.update([bundle/'fixtures.jsonl.gz',bundle/'plan.json'])
    write(bundle/'manifest.json',{str(p):sha(p) for p in sorted(paths) if p.is_file()})
    write(bundle/'preparation.json',dict(status='PASS',kernel_execution='NOT RUN',manifest_sha256=sha(bundle/'manifest.json'),
        pilot_command=f'sudo /usr/bin/python3 {HERE}/kernel.py --execute-pilot {bundle}',**{k:plan[k] for k in ('objects','pilot_calls','full_calls','model_hash','checkpoint_sha256','calibration_sha256')}))
    print(json.dumps(read(bundle/'preparation.json'),indent=2),flush=True)


class FreshController(BoundedController):
    def __init__(self,log,mode,bundle):
        self.log=log;self.directory=log.output/mode;self.directory.mkdir();self.mode=mode
        self.events=[];self.ready=None;self.pending=b'';self.stopped=False
        self.err=(self.directory/'controller.log').open('w');self.raw_events=gzip.open(self.directory/'controller-events.jsonl.gz','wt')
        argv=[str(bundle/'.output'/('controller-'+mode)),'--benchmark-kernel',str(bundle/'.output'/(mode+'.bpf.o')),str(self.directory)]
        write(self.directory/'command.json',argv)
        try:self.proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,bufsize=0)
        except Exception:self.err.close();self.raw_events.close();raise


def check_bundle(bundle):
    p=read(bundle/'preparation.json');need(p['status']=='PASS' and sha(bundle/'manifest.json')==p['manifest_sha256'],'Prepared manifest changed')
    for n,h in read(bundle/'manifest.json').items():need(sha(n)==h,'Prepared file changed: '+n)
    return read(bundle/'plan.json')


def audit(run):
    result=read(run/'results.json');need(result['status']=='PASS' and result['cleanup']=='PASS','Run did not pass')
    bundle=Path(result['bundle']);plan=check_bundle(bundle)
    fixtures=[json.loads(s) for s in gzip.open(bundle/'fixtures.jsonl.gz','rt')];reference=refs(Path(plan['experiment']))
    seen=set();times={m:[] for m in MODES};guards=set();positions=set(plan['pilot_positions'] if result['phase']=='pilot' else range(len(fixtures)))
    for line in gzip.open(run/'measurements.jsonl.gz','rt'):
        r=json.loads(line);need(r['status']=='PASS','Failed saved record');m=r['mode']
        if r['phase']=='guard':
            need(m not in guards,'Duplicate guard');guards.add(m);raw=list(reference[m].mean);v,y=reference[m].infer(raw)
            verify(r['block'],m,raw,[v[s] for s in STAGES],y,result['environment']['cpu'],1,2);continue
        pos=r['position'];trial=r['trial'];need(pos in positions and -1<=trial<result['trials'],'Unexpected cohort/trial')
        key=(m,trial,pos);need(key not in seen,'Duplicate invocation');seen.add(key)
        expected=fixtures[pos];need(expected['row_index']==r['row_index'],'Wrong test row')
        saved=expected['expected'][m]
        verify(r['block'],m,expected['features'],[saved['tensors'][s] for s in STAGES],saved['prediction'],result['environment']['cpu'])
        if trial>=0:times[m]+=r['block']['duration_ns']
    need(len(seen)==2*len(positions)*(result['trials']+1) and guards==set(MODES),'Incomplete experiment')
    for m in MODES:
        need(summary_ns(times[m])=={k:result['modes'][m][k] for k in summary_ns(times[m])},'Raw timing mismatch')
        loaded=next(e for e in result['resources'][m] if e['event']=='loaded');gone=read(run/m/'ids-absent.json')
        need(gone['all_absent'] and gone['program_ids']==loaded['program_ids'] and gone['map_ids']==loaded['map_ids'],'Wrong cleanup IDs')
    return dict(status='PASS',stored_cohort_calls=len(seen),guards=6,stage_tensors_checked=6*(len(seen)+2),integer_values_checked=136*(len(seen)+2))


def execute(bundle,phase,pilot=None):
    need(os.geteuid()==0,'Explicitly approved root invocation required');plan=check_bundle(bundle)
    if phase=='full':
        need(pilot is not None,'Passing pilot evidence required');prior=read(pilot/'results.json')
        need(prior['phase']=='pilot' and prior['bundle']==str(bundle.resolve()) and prior['input_count']==100,'Wrong pilot')
        audit(pilot)
    fixtures=[json.loads(s) for s in gzip.open(bundle/'fixtures.jsonl.gz','rt')];reference=refs(Path(plan['experiment']))
    positions=plan['pilot_positions'] if phase=='pilot' else list(range(len(fixtures)))
    trials=plan[phase+'_trials'];out=bundle/(phase+'-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'));out.mkdir();log=Log(out)
    print('Fresh-model kernel evidence:',out,flush=True);controllers={};times={m:[] for m in MODES};pertrial={m:[[] for _ in range(trials)] for m in MODES}
    cpu=min(os.sched_getaffinity(0));start=time.monotonic();result=dict(status='FAIL',phase=phase,bundle=str(bundle.resolve()),
        input_count=len(positions),trials=trials,checkpoint_sha256=plan['checkpoint_sha256'],model_sha256=plan['model_hash'],
        calibration_sha256=plan['calibration_sha256'],manifest_sha256=sha(bundle/'manifest.json'),network_attachments=False,
        environment=dict(kernel=platform.release(),python=platform.python_version(),machine=platform.machine(),cpu=cpu,
        allowed_cpus=sorted(os.sched_getaffinity(0)),cpu_model=next((s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),'unknown')))
    try:
        for m in MODES:
            c=FreshController(log,m,bundle);controllers[m]=c;ready=c.read('benchmark_ready')
            need(not ready['network_attachments'] and cpu in ready['allowed_cpus'],'Unsafe readiness')
            info=next(e for e in c.events if e['event']=='model')
            need(info['bytes_per_slot']==len(reference[m].packed()) and info['slots_verified']==2,'Wrong parameter readback ABI')
            slots=[e for e in c.events if e['event']=='tail_slot'];need([e['slot'] for e in slots]==list(range(6)) and all(e['type']==3 for e in slots),'Wrong tail targets')
            if m=='layer_specific':need(next(e for e in c.events if e['event']=='inference_mode')['parameter_sha256']==plan['parameter_sha256'][m],'Wrong new layer parameters')
        with gzip.open(out/'measurements.jsonl.gz','wt') as stream:
            for m in MODES:
                raw=list(reference[m].mean);v,y=reference[m].infer(raw);block=controllers[m].measure_vector(cpu,raw,1,2)
                verify(block,m,raw,[v[s] for s in STAGES],y,cpu,1,2)
                stream.write(json.dumps(dict(status='PASS',phase='guard',mode=m,block=block))+'\n')
            for trial in range(-1,trials):
                for offset,pos in enumerate(positions):
                    fixture=fixtures[pos]
                    for m in MODES if (offset+trial)%2==0 else tuple(reversed(MODES)):
                        record=dict(status='FAIL',phase='warmup' if trial<0 else 'measured',mode=m,trial=trial,position=pos,row_index=fixture['row_index'])
                        try:
                            block=controllers[m].measure_vector(cpu,fixture['features']);record['block']=block;saved=fixture['expected'][m]
                            verify(block,m,fixture['features'],[saved['tensors'][s] for s in STAGES],saved['prediction'],cpu)
                            record['status']='PASS'
                            if trial>=0:times[m]+=block['duration_ns'];pertrial[m][trial]+=block['duration_ns']
                        except Exception as err:record['error']=str(err);raise
                        finally:stream.write(json.dumps(record,separators=(',',':'))+'\n')
                print('Completed','warmup' if trial<0 else f'trial {trial+1}/{trials}',flush=True)
        result['modes']={m:dict(**summary_ns(times[m]),per_trial=[summary_ns(t) for t in pertrial[m]],
            measured_calls=len(times[m]),warmup_calls=len(positions),failures=0,
            kernel_time_normalized_inferences_per_second=len(times[m])*1e9/sum(times[m])) for m in MODES}
        result['status']='PASS'
    except Exception as err:result['error']=str(err)
    finally:
        clean=[]
        for m,c in controllers.items():
            try:c.stop()
            except Exception as err:result.setdefault('controller_errors',{})[m]=str(err)
            try:
                need(any(e['event']=='loaded' for e in c.events),'Missing loaded IDs');c.verify_ids_gone();clean.append(m)
            except Exception as err:result.setdefault('cleanup_errors',{})[m]=str(err)
        result['cleanup']='PASS' if set(clean)==set(MODES) else 'FAIL'
        if result['cleanup']!='PASS' or result.get('controller_errors'):result['status']='FAIL'
        result['resources']={m:[e for e in c.events if e['event'] in ('loaded','tail_slot','model','inference_mode','program_resources')] for m,c in controllers.items()}
        result['wall_elapsed_seconds']=time.monotonic()-start;write(out/'results.json',result)
        if result['status']=='PASS':
            try:write(out/'audit.json',audit(out))
            except Exception as err:result['status']='FAIL';result['audit_error']=str(err);write(out/'results.json',result)
        print(json.dumps({k:v for k,v in result.items() if k!='resources'},indent=2),flush=True)
    return int(result['status']!='PASS')


def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',type=Path);g.add_argument('--execute-pilot',type=Path);g.add_argument('--execute-full',type=Path);g.add_argument('--audit',type=Path)
    p.add_argument('--experiment',type=Path,default=HERE/'run');p.add_argument('--pilot-evidence',type=Path);a=p.parse_args()
    if a.prepare:prepare(a.experiment,a.prepare)
    elif a.audit:print(json.dumps(audit(a.audit),indent=2))
    else:
        bundle=(a.execute_pilot or a.execute_full).resolve()
        return execute(bundle,'pilot' if a.execute_pilot else 'full',a.pilot_evidence)

if __name__=='__main__':sys.exit(main() or 0)
