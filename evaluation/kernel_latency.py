#!/usr/bin/env python3
"""Gated private-kernel TC latency on the unchanged 13,844-vector partition.

Preparation and unit tests are unprivileged. Execution requires explicit root
approval; existing controllers load only private unattached objects. Original
XDP is explicitly unavailable under the per-run six-stage evidence contract.
"""
import argparse
from collections import Counter
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import statistics
import struct
import sys
import time
import unittest
from zoneinfo import ZoneInfo

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tc'))
from evaluation.data import digest
from evaluation.latency import evidence_contract, summary_ns
from quantization.benchmark import Controller, verify_block
from tc.demo import Log, branch, controller_for, object_for, reference_for, need
from validation.reference import STAGES, SIZES

MODES = ('static_q16', 'layer_specific')
KEYS = {'static_q16':'tc_q16', 'layer_specific':'tc_layer_specific'}
DEFAULT_EVIDENCE = ROOT/'verification-logs/final-demo-20261107/offline-r2'
XDP_LIMIT = ('NOT RUN: original XDP has no per-stage completion record; final logits alone cannot prove '
             'every tail stage on zero/unchanged tensors. Existing stage-isolated parity is not a full-chain latency. '
             'Reliable per-run observation would need additional validated instrumentation; no modified or host '
             'implementation is substituted for original XDP timing.')


def pilot_positions(ids):
    need(len(ids)>=100 and len(set(ids))==len(ids),'Pilot requires at least 100 distinct stored row IDs')
    ranked = sorted(range(len(ids)), key=lambda i:hashlib.sha256(
        ('kernel13844-pilot-v1\n'+str(ids[i])).encode()).digest())
    return sorted(ranked[:100])


def sources():
    paths=[]
    for directory in ('src','tc','validation','quantization','evaluation'):
        paths += [p for p in (ROOT/directory).rglob('*') if p.is_file()
                  and '.output' not in p.parts and '__pycache__' not in p.parts and p.suffix in ('.py','.c','.h','.json')]
    paths += [ROOT/'dataset/reproduction-xdp-data.npy',ROOT/'dataset/reproduction-xdp-label.npy']
    paths += [controller_for(m) for m in MODES]+[object_for(m) for m in MODES]
    return {str(p.relative_to(ROOT)):digest(p) for p in sorted(set(paths))}


def check_source_manifest(manifest):
    for name,value in manifest.items():
        need(digest(ROOT/name)==value,'Prepared source/binary/data changed: '+name)


def archived_expected(contract,mode,position):
    key=KEYS[mode]
    values=struct.unpack_from('<192i',contract['packed'][key],position*192*4)
    return [list(values[32*i:32*i+n]) for i,n in enumerate(SIZES)],contract['labels'][key][position]


def check_archived(block,mode,raw,tensors,label,cpu,warm=0,samples=1):
    # The established verifier rejects repeat>1, skipped predictions, missing
    # stages, bad CPU/sequence/slot/features and unsafe arithmetic.
    verify_block(block,mode,'mlp',raw,warm,samples,cpu)
    need(block['record']['tensors']==tensors and block['record']['label']==label,
         'Kernel tensors/logits/prediction differ from frozen host archive')


def require_full_gate(pilot,bundle,manifest):
    need(pilot['phase']=='pilot' and pilot['status']=='PASS' and pilot['cleanup']=='PASS',
         'A successful cleaned-up 100-vector TC pilot is required')
    need(pilot['input_count']==100 and pilot['prepared_bundle']==str(bundle.resolve()),'Wrong pilot cohort/bundle')
    need(pilot['source_manifest_sha256']==manifest,'Pilot source contract differs')
    need(all(pilot['modes'][m]['status']=='PASS' for m in MODES),'Both TC modes must pass the pilot')


class BoundedController(Controller):
    """Reuse the existing C driver, streaming verbose events instead of RAM growth."""
    def __init__(self,log,mode):
        super().__init__(log,mode)
        try:self.raw_events=gzip.open(self.directory/'controller-events.jsonl.gz','wt')
        except Exception:
            self.proc.terminate();self.proc.communicate(timeout=6);self.err.close()
            raise

    def read(self,wanted,timeout=30):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if b'\n' not in self.pending:
                if not select.select([self.proc.stdout],[],[],.2)[0]:continue
                block=os.read(self.proc.stdout.fileno(),65536)
                need(block,f'Controller exited before {wanted}: {self.directory}/controller.log')
                self.pending+=block
                need(len(self.pending)<2*1024*1024,'Unexpected controller record size')
                if b'\n' not in self.pending:continue
            raw,self.pending=self.pending.split(b'\n',1)
            event=json.loads(raw)
            self.raw_events.write(raw.decode()+'\n')
            if event['event']!='benchmark_block':self.events.append(event)
            if event['event']==wanted:return event
        raise RuntimeError('Timed out waiting for '+wanted)

    def measure_vector(self,cpu,raw,warm=0,samples=1):
        command='measure '+' '.join(map(str,[cpu,0,warm,samples,*raw]))+'\n'
        self.proc.stdin.write(command.encode());self.proc.stdin.flush()
        return self.read('benchmark_block')

    def stop(self):
        try:super().stop()
        finally:self.raw_events.close()


def prepare(output,evidence,trials):
    need(3<=trials<=9,'Use 3–9 full-dataset trials')
    branch();output=output.resolve();output.mkdir(parents=True,exist_ok=False);log=Log(output)
    before=sources()
    contract=evidence_contract(evidence.resolve())
    revision=log.command(['git','rev-parse','HEAD'],'commit').stdout.strip()
    log.command(['uname','-r'],'kernel')
    log.command(['clang-12','--version'],'compiler')
    log.command([ROOT/'.output/bpftool/bpftool','version'],'bpftool')
    log.command(['make','-C','tc','layer-specific'],'build')
    need(all(digest(ROOT/p)==h for p,h in before.items() if not p.startswith('tc/.output/')),
         'Existing source/data changed during preparation')
    for mode in MODES:
        directory=output/('inspect-'+mode);directory.mkdir()
        log.command([controller_for(mode),'--inspect',object_for(mode),directory],'inspect-'+mode)
    plan=dict(schema=1,phase='PREPARED; KERNEL NOT RUN',input_count=13844,baseline_commit=revision,
        cohort='Unchanged reproduction scaling-heldout partition; NOT recovered original training test split',
        source_evidence=str(evidence.resolve()),original_evidence_hashes=contract['source_hashes'],
        ids=contract['ids'],pilot_positions=pilot_positions(contract['ids']),pilot_count=100,
        sampling='Lowest 100 SHA256(kernel13844-pilot-v1 newline original-row-index), then original row order; no labels/predictions used',
        full_trials=trials,pilot_trials=2,warmup='One complete selected-cohort pass per mode',
        repetition_guard='Header-mean zero-tensor fixture: warmup=1, samples=2, three fresh complete chains per mode',
        mode_order='Alternate TC mode order by trial and row position; each test-run repeat=1',
        kernel_repeat=1,network_attachments=False,map_pins=False,
        planned_pilot_kernel_calls=2*100*(1+2)+2*3,
        planned_full_kernel_calls=2*13844*(1+trials)+2*3,
        objects=dict(programs=16,maps=17,scope='Two unmodified private TC objects; no tracing attachments or namespaces'),
        original_xdp=XDP_LIMIT,
        timing='Kernel-returned test-run duration from tc_preprocessing through all six stages, real tail calls and result publication; not pure arithmetic/full packet processing/userspace wall time')
    (output/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    (output/'source-manifest.json').write_text(json.dumps(sources(),indent=2)+'\n')
    from evaluation import test_kernel_latency
    with (output/'tests.log').open('w') as stream:
        tests=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(test_kernel_latency))
    need(tests.wasSuccessful(),'Kernel-latency protocol tests failed (host-only tests)')
    result=dict(preparation='PASS',kernel_execution='NOT RUN',tests=tests.testsRun,
        source_manifest_sha256=digest(output/'source-manifest.json'),plan_sha256=digest(output/'plan.json'),
        pilot_command=f'sudo /usr/bin/python3 {ROOT}/evaluation/kernel_latency.py --execute-pilot {output}',
        scope=plan['objects'],original_xdp=XDP_LIMIT)
    (output/'preparation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2),flush=True)
    return result


def execute(bundle,phase,pilot_path=None):
    need(os.geteuid()==0,'Explicitly approved root invocation required')
    branch();bundle=bundle.resolve()
    preparation=json.loads((bundle/'preparation.json').read_text());plan=json.loads((bundle/'plan.json').read_text())
    need(preparation['preparation']=='PASS' and digest(bundle/'plan.json')==preparation['plan_sha256'],'Prepared plan changed')
    manifest_hash=digest(bundle/'source-manifest.json')
    need(manifest_hash==preparation['source_manifest_sha256'],'Prepared source manifest changed')
    check_source_manifest(json.loads((bundle/'source-manifest.json').read_text()))
    if phase=='full':
        need(pilot_path is not None,'Provide --pilot-evidence after actual pilot passes')
        require_full_gate(json.loads((pilot_path/'results.json').read_text()),bundle,manifest_hash)
    contract=evidence_contract(Path(plan['source_evidence']))
    need(contract['ids']==plan['ids'] and contract['source_hashes']==plan['original_evidence_hashes'],'Frozen cohort/archive changed')
    if phase=='full':audit_saved(pilot_path,contract,plan)
    positions=plan['pilot_positions'] if phase=='pilot' else list(range(13844))
    need(len(positions)==(100 if phase=='pilot' else 13844),'Wrong phase size')
    trials=plan['pilot_trials'] if phase=='pilot' else plan['full_trials']
    output=bundle/(phase+'-'+datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%Y%m%d-%H%M%S-%f'))
    output.mkdir();print('Kernel latency evidence: '+str(output),flush=True)
    log=Log(output);controllers={};success=Counter();failures=Counter();durations={m:[] for m in MODES}
    per_trial={m:[[] for _ in range(trials)] for m in MODES}
    cpu=min(os.sched_getaffinity(0));started=time.monotonic()
    result=dict(status='FAIL',phase=phase,input_count=len(positions),trials=trials,prepared_bundle=str(bundle),
        source_manifest_sha256=manifest_hash,original_xdp=XDP_LIMIT,cleanup='NOT VERIFIED',modes={},
        environment=dict(kernel=platform.release(),machine=platform.machine(),python=platform.python_version(),cpu=cpu,
            baseline_commit=plan['baseline_commit'],
            parent_allowed_cpus=sorted(os.sched_getaffinity(0)),cpu_model=next((s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),'unknown')))
    try:
        for mode in MODES:
            controller=BoundedController(log,mode);controllers[mode]=controller
            ready=controller.read('benchmark_ready')
            need(ready['mode']==mode and not ready['network_attachments'] and cpu in ready['allowed_cpus'],'Unsafe controller readiness')
            model=next(e for e in controller.events if e['event']=='model')
            need(model['slots_verified']==2 and model['bytes_per_slot']==len(reference_for(mode).packed()),'Model readback/layout failed')
            slots=[e for e in controller.events if e['event']=='tail_slot']
            need([e['slot'] for e in slots]==list(range(6)) and all(e['type']==3 for e in slots),'Six compatible tail-call slots not verified')
        with gzip.open(output/'measurements.jsonl.gz','wt') as rawfile:
            for mode in MODES:
                raw=list(reference_for(mode).mean);expected,label=reference_for(mode).infer(raw)
                block=controllers[mode].measure_vector(cpu,raw,warm=1,samples=2)
                check_archived(block,mode,raw,[expected[n] for n in STAGES],label,cpu,warm=1,samples=2)
                rawfile.write(json.dumps(dict(phase='repetition_guard',mode=mode,source_row=None,status='PASS',block=block))+'\n')
            for trial in range(-1,trials):
                for offset,position in enumerate(positions):
                    for mode in MODES if (offset+trial)%2==0 else tuple(reversed(MODES)):
                        tensors,label=archived_expected(contract,mode,position);raw=contract['raw'][position]
                        record=dict(phase='warmup' if trial<0 else 'measured',trial=trial,mode=mode,
                            source_row=contract['ids'][position],position=position,status='FAIL')
                        try:
                            block=controllers[mode].measure_vector(cpu,raw);record['block']=block
                            check_archived(block,mode,raw,tensors,label,cpu)
                            record['status']='PASS';success[mode]+=1
                            if trial>=0:
                                durations[mode].append(block['duration_ns'][0]);per_trial[mode][trial].append(block['duration_ns'][0])
                        except Exception as error:
                            record['error']=str(error)
                            failures[mode]+=1
                            raise
                        finally:rawfile.write(json.dumps(record,separators=(',',':'))+'\n')
                print(f'{phase} '+('warmup' if trial<0 else f'trial {trial+1}/{trials}')+' completed',flush=True)
        for mode in MODES:
            summary=summary_ns(durations[mode]);summary.update(status='PASS',successful=success[mode],failed=failures[mode],
                measured_inferences=len(durations[mode]),warmup_inferences=len(positions),
                total_kernel_duration_ns=sum(durations[mode]),
                per_trial=[summary_ns(values) for values in per_trial[mode]],
                kernel_time_normalized_inferences_per_second=len(durations[mode])*1e9/sum(durations[mode]))
            result['modes'][mode]=summary
        result['relative_layer_to_tc_q16_percent']={k:100*(result['modes']['layer_specific'][k]-result['modes']['static_q16'][k])/result['modes']['static_q16'][k]
            for k in ('mean_ns','median_ns','p95_ns','p99_ns')}
        result['status']='PASS'
    except Exception as error:result['error']=str(error)
    finally:
        cleaned=[]
        for mode,controller in controllers.items():
            try:controller.stop()
            except Exception as error:result.setdefault('controller_errors',{})[mode]=str(error)
            try:
                need(any(e['event']=='loaded' for e in controller.events),'No loaded-ID metadata')
                controller.verify_ids_gone();cleaned.append(mode)
            except Exception as error:result.setdefault('cleanup_errors',{})[mode]=str(error)
        result['cleanup']='PASS' if set(cleaned)==set(MODES) else 'FAIL'
        if result['cleanup']!='PASS' or result.get('controller_errors'):result['status']='FAIL'
        result['wall_elapsed_seconds']=time.monotonic()-started
        result['execution_counts']={m:dict(successful_warmup_and_measured=success[m],failed_records=failures[m],
            planned_measured=len(positions)*trials,recorded_measurements=len(durations[m])) for m in MODES}
        result['scope']='Real kernel TC model-stage chain; existing telemetry/map/publication and test-run overhead included. No packet feature extraction, hook attachment or syscall wall-time latency claim.'
        result['resources']={m:[e for e in c.events if e['event'] in ('loaded','tail_slot','model','program_resources')] for m,c in controllers.items()}
        (output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
        if result['status']=='PASS':
            try:audit_saved(output,contract,plan,save=True)
            except Exception as error:
                result['status']='FAIL';result['audit_error']=str(error)
                (output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
        write_run_report(output,result)
        print(json.dumps({k:v for k,v in result.items() if k!='resources'},indent=2),flush=True)
    return int(result['status']!='PASS')


def audit_saved(run,contract,plan,save=False):
    result=json.loads((run/'results.json').read_text())
    need(result['status']=='PASS' and result['cleanup']=='PASS','Kernel execution/cleanup did not pass')
    need(result['phase'] in ('pilot','full') and result['trials']==plan[result['phase']+'_trials'],
         'Wrong number of kernel trials')
    positions=plan['pilot_positions'] if result['phase']=='pilot' else list(range(13844))
    position_set=set(positions)
    need(result['input_count']==len(positions),'Audit cohort count mismatch')
    seen=set();guards=set();data={m:[] for m in MODES};count=0
    with gzip.open(run/'measurements.jsonl.gz','rt') as stream:
        for line in stream:
            record=json.loads(line);mode=record['mode'];need(mode in MODES,'Unexpected inference mode')
            need(record['status']=='PASS','Failed record cannot support passing benchmark')
            if record['phase']=='repetition_guard':
                need(mode not in guards,'Duplicate repetition guard');guards.add(mode)
                raw=list(reference_for(mode).mean);stages,label=reference_for(mode).infer(raw)
                check_archived(record['block'],mode,raw,[stages[n] for n in STAGES],label,result['environment']['cpu'],1,2)
                continue
            position=record['position'];trial=record['trial']
            need(position in position_set and record['source_row']==contract['ids'][position],'Row/vector identity mismatch')
            need((record['phase']=='warmup' and trial==-1) or
                 (record['phase']=='measured' and 0<=trial<result['trials']),'Wrong trial/phase')
            identity=(mode,trial,position);need(identity not in seen,'Repeated source record within trial');seen.add(identity)
            tensors,label=archived_expected(contract,mode,position)
            check_archived(record['block'],mode,contract['raw'][position],tensors,label,result['environment']['cpu'])
            if trial>=0:data[mode].append(record['block']['duration_ns'][0])
            count+=1
    need(guards==set(MODES) and count==2*len(positions)*(result['trials']+1),'Missing warmup/measured/repetition evidence')
    for mode in MODES:
        summary=summary_ns(data[mode])
        need(all(result['modes'][mode][k]==v for k,v in summary.items()),'Statistics do not match saved timings')
        need(result['modes'][mode]['total_kernel_duration_ns']==sum(data[mode]) and
             result['modes'][mode]['kernel_time_normalized_inferences_per_second']==len(data[mode])*1e9/sum(data[mode]),
             'Kernel-duration throughput denominator mismatch')
        gone=json.loads((run/mode/'ids-absent.json').read_text())
        loaded=next(e for e in result['resources'][mode] if e['event']=='loaded')
        need(gone['all_absent'] and gone['program_ids']==loaded['program_ids'] and gone['map_ids']==loaded['map_ids'],
             'Cleanup evidence does not match loaded private IDs')
    report=dict(status='PASS',scope='Read-only replay of actual per-vector kernel records',
        stored_records=count,repetition_guards=2,stored_stage_tensors=count*6+12,stored_integer_values=count*136+272,
        executing_controller_checked_stage_tensors=count*6+36,
        executing_controller_checked_integer_values=count*136+816,
        measured_kernel_calls=sum(len(v) for v in data.values()),warmup_kernel_calls=2*len(positions),
        repetition_guard_kernel_calls=6,failed=0,original_xdp='NOT RUN; explicit observability limitation')
    if save:(run/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def write_run_report(output,result):
    text=f"# Actual private-kernel TC {result['phase']}\n\nStatus: **{result['status']}**. "
    text+=f"Cohort: {result['input_count']} stored vectors; {result['trials']} measurement trials.\n\n"
    text+='Original XDP: **NOT RUN**, per-run observability limitation. No XDP latency is fabricated.\n\n'
    text+='| Metric | TC Q16 | TC layer-specific |\n| --- | ---: | ---: |\n'
    for title,key in (('Mean µs','mean_ns'),('p50 µs','median_ns'),('p95 µs','p95_ns'),('p99 µs','p99_ns'),
                      ('Minimum µs','minimum_ns'),('Maximum µs','maximum_ns'),('Population SD µs','population_stddev_ns')):
        values=[f"{result['modes'][m][key]/1000:.6f}" if m in result['modes'] else 'NOT RUN' for m in MODES]
        text+='| '+title+' | '+' | '.join(values)+' |\n'
    text+='\nDurations are the kernel-returned model-stage-chain test-run time, including existing TC '
    text+='telemetry/map/publication overhead. They exclude userspace reset/IPC/readback and packet feature extraction. '
    text+='Kernel-time-normalized throughput is not achieved network throughput.\n\n'
    text+=f"Cleanup: **{result['cleanup']}**. No interfaces, qdiscs, pins or namespaces created.\n\n"
    if result.get('error'):text+='Error: '+result['error']+'\n\n'
    text+='[Results](results.json), [raw records](measurements.jsonl.gz). '
    text+='Per-program verifier logs and owned-ID checks are in the two mode directories.\n'
    (output/'REPORT.md').write_text(text)


def plot(run,output):
    result=json.loads((run/'results.json').read_text());need(result['status']=='PASS','Plot requires actual successful kernel measurements')
    output.mkdir(parents=True,exist_ok=False)
    os.environ.setdefault('MPLCONFIGDIR','/tmp/nn-ebpf-kernel-latency-mpl')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(7,4),layout='constrained')
    for index,key in enumerate(('mean_ns','median_ns','p95_ns','p99_ns')):
        for j,mode in enumerate(MODES):
            ax.bar(index+(j-.5)*.32,result['modes'][mode][key]/1000,.3,label=mode if index==0 else None)
    ax.set(xticks=range(4),xticklabels=['Mean','p50','p95','p99'],ylabel='Kernel model-stage-chain duration (µs)',
           title=f"{result['phase']}: {result['input_count']} vectors × {result['trials']} trials; XDP not measured")
    ax.legend();fig.savefig(output/'kernel-latency.png',dpi=180);fig.savefig(output/'kernel-latency.pdf');plt.close(fig)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',action='store_true');g.add_argument('--execute-pilot',type=Path)
    g.add_argument('--execute-full',type=Path);g.add_argument('--plot',type=Path)
    g.add_argument('--audit',type=Path)
    p.add_argument('--output',type=Path);p.add_argument('--pilot-evidence',type=Path)
    p.add_argument('--source-evidence',type=Path,default=DEFAULT_EVIDENCE);p.add_argument('--trials',type=int,default=5)
    a=p.parse_args()
    if a.prepare:
        need(a.output is not None,'Provide --output');prepare(a.output,a.source_evidence,a.trials)
    elif a.plot:
        need(a.output is not None,'Provide fresh --output for figures');plot(a.plot,a.output)
    elif a.audit:
        result=json.loads((a.audit/'results.json').read_text());bundle=Path(result['prepared_bundle'])
        plan=json.loads((bundle/'plan.json').read_text());contract=evidence_contract(Path(plan['source_evidence']))
        print(json.dumps(audit_saved(a.audit,contract,plan),indent=2))
    else:raise SystemExit(execute(a.execute_pilot or a.execute_full,'pilot' if a.execute_pilot else 'full',a.pilot_evidence))
