#!/usr/bin/env python3
"""Prepare or execute paired private-kernel benchmarks after both live gates."""
import argparse
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import unittest

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
# demo.py is also a standalone script and imports its sibling safety helpers.
sys.path.insert(0,str(ROOT/'tc'))
from tc.demo import Loader,Log,branch,controller_for,object_for,reference_for,stamp,sha,need
from validation.reference import STAGES

EVIDENCE=ROOT/'verification-logs/layer-specific-20261107'
MODES=('static_q16','layer_specific')


def percentile(values,fraction):
    if not values or not 0<=fraction<=1:raise ValueError('percentile domain')
    values=sorted(values);position=(len(values)-1)*fraction;left=int(position);right=min(left+1,len(values)-1)
    return values[left]+(values[right]-values[left])*(position-left)


def timing_summary(values):
    if not values or any(type(v) is not int or not 0<v<0xffffffff for v in values):
        raise ValueError('Zero, saturated or invalid duration; timing cannot be interpreted')
    return dict(samples=len(values),median_ns=statistics.median(values),p10_ns=percentile(values,.1),
                p90_ns=percentile(values,.9),minimum_ns=min(values),maximum_ns=max(values))


def paired_ratios(pairs,seed=20261107):
    if len(pairs)<2:raise ValueError('At least two paired blocks required')
    if any(a<=0 or b<=0 for a,b in pairs):raise ValueError('Nonpositive block median')
    ratios=[b/a for a,b in pairs]
    rng=random.Random(seed)
    bootstrap=[statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(10000)]
    lower,upper=percentile(bootstrap,.025),percentile(bootstrap,.975)
    return dict(paired_blocks=len(pairs),median_experimental_over_static=statistics.median(ratios),
                bootstrap_95_percentile=[lower,upper],seed=seed,
                observation='slower_in_this_microbenchmark' if lower>1 else
                    'faster_in_this_microbenchmark' if upper<1 else 'inconclusive',
                scope='Descriptive paired block bootstrap; not proof about NIC throughput or uncontrolled WSL2 scheduling')


def verify_block(block,mode,kind,raw,warm,samples,cpu):
    need(block['mode']==mode and block['kind']==kind and block['cpu']==cpu,'Benchmark context mismatch')
    need(block['kernel_repeat']==1 and block['warmup']==warm and block['samples']==samples,'Wrong benchmark repeat/warmup/sample count')
    need(block['prediction_delta']==warm+samples and block['stage_deltas']==[warm+samples]*6,'Repeated calls skipped inference')
    need(len(block['duration_ns'])==samples,'Duration count mismatch')
    timing_summary(block['duration_ns'])
    record=block['record'];issues=[];expected,label=reference_for(mode).infer(raw,issues)
    need(not issues and record['features']==raw and record['mask']==63 and record['sequence']==1
         and record['model_slot']==0 and record['cpu']==cpu,'Invalid benchmark result')
    need(record['tensors']==[expected[stage] for stage in STAGES] and record['label']==label,'Benchmark numerical parity failed')


def live_prerequisite():
    review=json.loads((EVIDENCE/'live_review.json').read_text());need(review['status']=='PASS','Gate 5 review missing')
    for mode in MODES:
        run=ROOT/review['modes'][mode]['runtime'];result=json.loads((run/'results.json').read_text())
        need(result['phase2_gate']=='PASS' and result['cleanup']=='PASS','Both live modes must pass')
        manifest=json.loads((run.parent/'manifest.json').read_text())
        for path in (object_for(mode),ROOT/'tc/tc_ids.bpf.c',ROOT/'tc/abi.h',ROOT/'quantization/arithmetic.h',
                     ROOT/'quantization/calibrated.h',ROOT/'quantization/calibrated.json',ROOT/'src/mlp_params.bpf.h'):
            name=str(path.relative_to(ROOT));expected=manifest['prototype'].get(name,manifest['protected'].get(name))
            need(expected is not None and sha(path)==expected,f'Tested inference changed after Gate 5: {name}')
    return review


def fingerprint():
    paths=[]
    for directory in (ROOT/'tc',ROOT/'quantization'):
        paths += [p for p in directory.rglob('*') if p.is_file() and '__pycache__' not in p.parts
                  and (directory.name=='tc' or '.output' not in p.parts)]
    paths += [p for p in (ROOT/'src').iterdir() if p.is_file()]
    paths += [ROOT/'validation/reference.py']
    return {str(p.relative_to(ROOT)):sha(p) for p in paths}


def prepare(output):
    branch();review=live_prerequisite();output.mkdir(parents=True,exist_ok=False);log=Log(output)
    log.command(['make','-C','tc','layer-specific'],'build')
    live_prerequisite()
    # These tests check statistics and skipped-work rejection, never kernel execution.
    from quantization import test_benchmark
    with (output/'tests.log').open('w') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(test_benchmark))
    need(result.wasSuccessful(),'Benchmark host tests failed')
    sample=next(r for r in review['packet_feature_samples'] if r['origin']=='layer_specific')['features']
    for mode in MODES:reference_for(mode).infer(sample)
    config=dict(blocks=12,warmup_per_block=32,samples_per_block=64,
                workloads=[dict(name='mlp_small_tcp',kind='mlp',raw=[20,0,20,5001,20,1]),
                           dict(name='mlp_saved_packet',kind='mlp',raw=sample),
                           dict(name='entry_fin',kind='entry',raw=[20,0,20,5001,20,1])],
                order='static first on even blocks; experimental first on odd blocks',kernel_repeat=1)
    (output/'config.json').write_text(json.dumps(config,indent=2)+'\n')
    (output/'manifest.json').write_text(json.dumps(fingerprint(),indent=2)+'\n')
    result=dict(preparation='PASS',kernel_execution='NOT RUN',host_tests=result.testsRun,
                config_sha256=sha(output/'config.json'),
                baseline_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                branch=branch(),
                approval_command=f'sudo /usr/bin/python3 {ROOT/"quantization/benchmark.py"} --execute {output}',
                scope='Two private TC objects, 16 programs and 17 maps; no interface attachment/network changes',
                planned_measured_calls=2*12*64*3,planned_warmup_calls=2*12*32*3)
    (output/'results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


class Controller(Loader):
    def __init__(self,log,mode):
        self.log=log;self.directory=log.output/mode;self.directory.mkdir()
        self.mode=mode
        self.events=[];self.ready=None;self.pending=b'';self.stopped=False
        self.err=(self.directory/'controller.log').open('w')
        argv=[str(controller_for(mode)),'--benchmark-kernel',str(object_for(mode)),str(self.directory)]
        (self.directory/'command.json').write_text(json.dumps(argv)+'\n')
        self.proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,bufsize=0)

    def measure(self,cpu,workload,warm,samples):
        values=[cpu,int(workload['kind']=='entry'),warm,samples,*workload['raw']]
        self.proc.stdin.write(('measure '+' '.join(map(str,values))+'\n').encode());self.proc.stdin.flush()
        result=self.read('benchmark_block',30)
        verify_block(result,self.mode,workload['kind'],workload['raw'],warm,samples,cpu)
        return result


def execute(bundle):
    need(os.geteuid()==0,'Approved root invocation required');branch();live_prerequisite()
    prepared=json.loads((bundle/'results.json').read_text())
    need(prepared['preparation']=='PASS','Prepare first')
    need(sha(bundle/'config.json')==prepared['config_sha256'],'Prepared workload changed')
    need(subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==prepared['baseline_commit'],
         'Prepared baseline commit changed')
    for name,h in json.loads((bundle/'manifest.json').read_text()).items():
        need(sha(ROOT/name)==h,f'Prepared source changed: {name}')
    config=json.loads((bundle/'config.json').read_text())
    out=bundle/('run-'+stamp());out.mkdir();print(f'Benchmark evidence: {out}',flush=True)
    log=Log(out);controllers={};blocks=[];result=dict(status='FAIL',timing='NOT RUN',network_attachments='NONE')
    environment=dict(kernel=platform.release(),machine=platform.machine(),python=platform.python_version(),
                     uid=os.geteuid(),parent_allowed_cpus=sorted(os.sched_getaffinity(0)),
                     baseline_commit=prepared['baseline_commit'],branch=branch(),
                     cpu_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                                     if line.startswith('model name')),'not reported'))
    try:
        ready={}
        for mode in MODES:
            controllers[mode]=Controller(log,mode)
            ready[mode]=controllers[mode].read('benchmark_ready',30)
            need(ready[mode]['mode']==mode and not ready[mode]['network_attachments'],'Unexpected benchmark attachment/mode')
            model=next(e for e in controllers[mode].events if e['event']=='model')
            need(model['bytes_per_slot']==len(reference_for(mode).packed()) and model['slots_verified']==2,'Benchmark model layout mismatch')
        allowed=set(ready[MODES[0]]['allowed_cpus']) & set(ready[MODES[1]]['allowed_cpus']) & set(environment['parent_allowed_cpus'])
        need(allowed,'No common allowed CPU');cpu=min(allowed);environment['benchmark_cpu']=cpu
        for block in range(config['blocks']):
            for workload in config['workloads']:
                for mode in MODES if block%2==0 else tuple(reversed(MODES)):
                    observation=controllers[mode].measure(cpu,workload,config['warmup_per_block'],config['samples_per_block'])
                    need(observation['mode']==mode,'Cross-mode benchmark result')
                    observation.update(block=block,workload=workload['name']);blocks.append(observation)
            print(f'Paired benchmark block {block+1}/{config["blocks"]} completed',flush=True)
        summaries={}
        for workload in config['workloads']:
            name=workload['name'];data={mode:[b for b in blocks if b['mode']==mode and b['workload']==name] for mode in MODES}
            summaries[name]={mode:timing_summary([ns for b in data[mode] for ns in b['duration_ns']]) for mode in MODES}
            pairs=[(statistics.median(data[MODES[0]][i]['duration_ns']),statistics.median(data[MODES[1]][i]['duration_ns'])) for i in range(config['blocks'])]
            summaries[name]['paired']=paired_ratios(pairs)
        result.update(status='PASS',timing='MEASURED kernel-reported test-run duration; not pure arithmetic/NIC latency',
                      summaries=summaries,measured_calls=len(blocks)*config['samples_per_block'],
                      warmup_calls=len(blocks)*config['warmup_per_block'],kernel_blocks=len(blocks),
                      numerical_parity='PASS; every call is checked for deterministic tensors and all six stages',
                      network_attachments='NONE')
    except Exception as error:result['error']=str(error)
    finally:
        cleanup=[]
        for mode,controller in controllers.items():
            try:controller.stop()
            except Exception as error:result.setdefault('controller_diagnostics',{})[mode]=str(error)
            # A controller error must not suppress the independent release check.
            try:
                identity=next((e for e in controller.events if e['event']=='loaded'),None)
                need(identity is not None,'No loaded-ID evidence');controller.verify_ids_gone();cleanup.append(mode)
            except Exception as error:result.setdefault('cleanup_errors',{})[mode]=str(error)
        result['cleanup']='PASS' if set(cleanup)==set(controllers) and controllers else 'NOT VERIFIED'
        if result['cleanup']!='PASS' or result.get('controller_diagnostics'):result['status']='FAIL'
        result['environment']=environment
        result['resources']={mode:[e for e in c.events if e['event'] in ('program_resources','map','inference_mode','model')]
                             for mode,c in controllers.items()}
        (out/'blocks.json').write_text(json.dumps(blocks,indent=2)+'\n')
        (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
        (out/'REPORT.md').write_text('# Paired private-kernel timing experiment\n\n```json\n'+json.dumps({k:v for k,v in result.items() if k!='resources'},indent=2)+'\n```\n\n'
            'Durations include kernel test-run and telemetry/publication overhead. No NIC throughput, pure arithmetic or detection accuracy claim.\n'
            'Warmups and state/map resets occur outside each recorded duration; repeat=1. Raw durations include all samples; no outlier trimming.\n')
        files=[p for p in out.rglob('*') if p.is_file()]
        (out/'SHA256SUMS').write_text(''.join(sha(p)+'  '+str(p.relative_to(out))+'\n' for p in sorted(files)))
        print(json.dumps({k:v for k,v in result.items() if k!='resources'},indent=2),flush=True)
    return int(result['status']!='PASS')


def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',action='store_true');g.add_argument('--execute',type=Path);p.add_argument('--output',type=Path)
    args=p.parse_args()
    if args.prepare:
        need(args.output is not None,'Provide --output for a new benchmark bundle');prepare(args.output.resolve());return 0
    return execute(args.execute.resolve())


if __name__=='__main__':raise SystemExit(main())
