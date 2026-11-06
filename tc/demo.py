#!/usr/bin/env python3
"""Separate TC demo. --prepare is unprivileged; --run/--cleanup need approval."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import time
import unittest
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'validation'))
sys.path.insert(0, str(ROOT / 'tc/tests'))
from reference import Model, STAGES
from safety import require_attached_filter, require_detach_ack, require_empty_filters
from packet_witness import compare_snapshot
import test_tc

SERVER, CLIENT = 'tcids-server', 'tcids-client'
SIF, CIF = 'tcids-s0', 'tcids-c0'


def stamp():
    return datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%Y%m%d-%H%M%S-%f')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def need(value, message):
    if not value: raise RuntimeError(message)


def protected():
    paths = [p for p in (ROOT/'src').iterdir() if p.is_file()]
    paths += [p for p in (ROOT/'validation').rglob('*') if p.is_file() and '.output' not in p.parts and '__pycache__' not in p.parts]
    paths += list((ROOT/'dataset').glob('*.npy'))
    paths += [ROOT/p for p in ('run-baseline.sh', 'Makefile', 'BASELINE_SUMMARY.md')]
    return {str(p.relative_to(ROOT)): sha(p) for p in paths}


class Log:
    def __init__(self, output): self.output = output; self.number = 0
    def command(self, argv, name=None, check=True):
        self.number += 1
        name = name or f'command-{self.number:03d}'
        print('[command] ' + shlex.join(map(str, argv)), flush=True)
        r = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, text=True, timeout=30)
        (self.output/(name+'.log')).write_text(r.stdout+r.stderr)
        with (self.output/'commands.jsonl').open('a') as f:
            f.write(json.dumps(dict(argv=list(map(str, argv)), exit_code=r.returncode, log=name+'.log'))+'\n')
        if check: need(r.returncode == 0, f'{name} failed ({r.returncode}); see {name}.log')
        return r


def branch():
    r = subprocess.run(['git','branch','--show-current'], cwd=ROOT, capture_output=True, text=True, check=True)
    need(r.stdout.strip().startswith('feature/'), 'Refusing work outside a feature branch')
    return r.stdout.strip()


def finish(output, result):
    (output/'results.json').write_text(json.dumps(result, indent=2)+'\n')
    display=result
    if 'kernel_checks' in result:
        display={k:v for k,v in result.items() if not k.endswith('_snapshot')}
        display['packet_observations']={k.removesuffix('_snapshot'):
            {name:v[name] for name in ('packets','bytes','egress_packets','egress_bytes','matched','predictions','stages','tail_failures') if name in v}
            for k,v in result.items() if k.endswith('_snapshot')}
        display['tensor_evidence']='Full records in results.json and each phase/snapshot.json'
    (output/'REPORT.md').write_text('# TC ingress prototype run\n\n```json\n'+json.dumps(display,indent=2)+'\n```\n\n'
        'PASS in preparation means compilation and host tests only. Runtime evidence requires --run.\n'
        'TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.\n'
        'Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.\n'
        'Original XDP/validation/model files are unchanged. Egress monitoring statistics are separate from ingress-leg MLP features.\n')
    files = [p for p in output.rglob('*') if p.is_file() and p.name != 'SHA256SUMS']
    (output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+str(p.relative_to(output))+'\n' for p in sorted(files)))
    print(json.dumps(display,indent=2),flush=True)
    print(f'Report: {output / "REPORT.md"}',flush=True)


def prepare(args):
    out = (args.output or ROOT/'verification-logs'/('tc-prepare-'+stamp())).resolve()
    out.mkdir(parents=True,exist_ok=False)
    log = Log(out); before = protected()
    result = dict(preparation='FAIL', runtime='NOT RUN', optional_egress='NOT IMPLEMENTED')
    try:
        result['branch'] = branch()
        result['commit'] = log.command(['git','rev-parse','HEAD'],'commit').stdout.strip()
        result['kernel'] = log.command(['uname','-r'],'kernel').stdout.strip()
        log.command(['clang-12','--version'],'compiler')
        log.command([ROOT/'.output/bpftool/bpftool','version'],'bpftool')
        log.command(['make','-C','tc'],'build')
        for name in ('tc_min','tc_ids'):
            directory = out/name; directory.mkdir()
            log.command([ROOT/'tc/.output/controller','--inspect',ROOT/f'tc/.output/{name}.bpf.o',directory], 'inspect-'+name)
        log.command(['clang-12','-O3','-shared','-fPIC','-pthread','-I'+str(ROOT/'tc/tests/include'),
                     '-I'+str(ROOT/'validation/include'),ROOT/'tc/tests/native.c','-o',out/'host-tc.so'],'build-host-tests')
        test_tc.CONTEXT = out/'host-tc.so', ROOT
        with (out/'tests.log').open('w') as stream:
            tests = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(test_tc))
        need(tests.wasSuccessful(),'TC host tests failed; see tests.log')
        result['nonprivileged_tests'] = dict(run=tests.testsRun, failures=len(tests.failures), errors=len(tests.errors))
        need(before == protected(),'Protected baseline files changed')
        result['protected_files'] = 'UNCHANGED'
        manifest = {str(p.relative_to(ROOT)): sha(p) for p in (ROOT/'tc').rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        manifest['run-tc-smoke.sh'] = sha(ROOT/'run-tc-smoke.sh')
        (out/'manifest.json').write_text(json.dumps(dict(protected=before, prototype=manifest),indent=2)+'\n')
        result['preparation'] = 'PASS'
        result['approval_command'] = f'sudo -n /usr/bin/python3 {ROOT / "tc/demo.py"} --run {out}'
        if args.phase1:
            result['approval_command'] += ' --phase1'
            result['phase1_gate'] = 'PENDING: actual kernel suite and live ingress tests required'
        if args.egress_counter:
            result['approval_command'] += ' --egress-counter'
            result['phase2_stage'] = 'EGRESS COUNTER ONLY; flow tracking not started'
            result['egress_counter_gate'] = 'PENDING: actual attached ingress/egress packet observation required'
        if args.phase2:
            result['approval_command']+=' --phase2'
            result['phase2_gate']='PENDING: attached bidirectional traffic and all regressions required'
    except Exception as e: result['error'] = str(e)
    finish(out,result)
    return int(result['preparation'] != 'PASS')


class Loader:
    def __init__(self, log, mode, inode):
        self.directory = log.output/mode; self.directory.mkdir()
        self.events = []; self.log = log; self.ready = None; self.pending = b''; self.stopped = False
        self.err = (self.directory/'controller.log').open('w')
        minimal=mode in ('minimal','egress-counter')
        argv = ['ip','netns','exec',SERVER,str(ROOT/'tc/.output/controller'),'--run',
                str(ROOT/f'tc/.output/{"tc_min" if minimal else "tc_ids"}.bpf.o'),SIF,str(inode),str(self.directory)]
        if mode=='egress-counter': argv.append('--egress-counter')
        if mode.startswith('bidirectional'):argv.append('--bidirectional')
        if not minimal:argv+=['--client-ip','33.33.33.73']
        (self.directory/'command.json').write_text(json.dumps(argv)+'\n')
        self.proc = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,bufsize=0)
    def read(self, wanted, timeout=20):
        deadline = time.monotonic()+timeout
        while time.monotonic()<deadline:
            if b'\n' not in self.pending:
                if not select.select([self.proc.stdout],[],[],0.2)[0]: continue
                block = os.read(self.proc.stdout.fileno(), 65536)
                need(block, f'controller exited before {wanted}; see {self.directory}/controller.log')
                self.pending += block
                if b'\n' not in self.pending: continue
            raw, self.pending = self.pending.split(b'\n', 1)
            line = raw.decode()+'\n'
            with (self.directory/'events.jsonl').open('a') as f: f.write(line)
            e = json.loads(line); self.events.append(e)
            if e['event']=='ready': self.ready=e
            if e['event']==wanted: return e
        raise RuntimeError(f'Timed out waiting for {wanted}')
    def snapshot(self):
        self.proc.stdin.write(b'snapshot\n'); self.proc.stdin.flush()
        return self.read('snapshot')
    def stop(self):
        if self.stopped:
            self.validate_stop()
            return
        if self.proc.poll() is None:
            try: self.proc.stdin.write(b'stop\n'); self.proc.stdin.flush()
            except BrokenPipeError: pass
        try:
            stdout,_=self.proc.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            self.proc.kill(); stdout,_=self.proc.communicate(); raise RuntimeError('Controller required SIGKILL')
        stdout = self.pending + stdout
        self.pending = b''
        if stdout:
            with (self.directory/'events.jsonl').open('a') as f: f.write(stdout.decode())
            self.events.extend(json.loads(s) for s in stdout.splitlines())
        self.err.close()
        self.stopped = True
        self.validate_stop()
    def validate_stop(self):
        need(self.proc.returncode == 0,'Controller cleanup failed')
        if self.ready:
            egress=self.ready.get('egress_program_id')
            require_detach_ack(self.events, self.ready['program_id'], 'ingress' if egress else None)
            if egress: require_detach_ack(self.events, egress, 'egress')
    def verify_ids_gone(self):
        identity=self.ready or next((e for e in self.events if e['event']=='loaded'),None)
        if identity: verify_private_ids(self.log, self.directory, identity)


class Witness:
    def __init__(self,directory):
        self.directory=directory;self.stopped=False
        self.output=(directory/'witness.log').open('w')
        argv=['ip','netns','exec',SERVER,sys.executable,str(ROOT/'tc/packet_witness.py'),SIF,str(directory)]
        (directory/'witness-command.json').write_text(json.dumps(argv)+'\n')
        self.proc=subprocess.Popen(argv,stdout=self.output,stderr=subprocess.STDOUT)
    def wait_ready(self):
        deadline=time.monotonic()+10
        while not (self.directory/'witness.ready').exists():
            need(self.proc.poll() is None and time.monotonic()<deadline,'Independent packet witness not ready')
            time.sleep(.02)
    def stop(self):
        if not self.stopped:
            (self.directory/'witness.stop').write_text('stop\n')
            try:self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.terminate();self.proc.wait(timeout=3)
            self.output.close();self.stopped=True
        need(self.proc.returncode==0,'Independent packet witness failed; see witness.log')
        return json.loads((self.directory/'packets.json').read_text())


def verify_private_ids(log, directory, identity):
    for kind, ids in (('prog',identity['program_ids']),('map',identity['map_ids'])):
        remaining = set(ids)
        for attempt in range(50):
            # GET_NEXT_ID only: bpftool show opens FDs and can interfere
            # with last-user prog-array deferred teardown on this kernel.
            r = log.command([ROOT/'tc/.output/controller','--list-ids',kind],check=True)
            live = json.loads(r.stdout)
            need(isinstance(live,list) and all(type(i) is int and i>0 for i in live),'Invalid ID registry scan')
            remaining = set(live).intersection(ids)
            if not remaining: break
            time.sleep(.1)
        else: raise RuntimeError(f'Private {kind} IDs remain: {sorted(remaining)}')
    (directory/'ids-absent.json').write_text(json.dumps(dict(
        program_ids=identity['program_ids'], map_ids=identity['map_ids'],
        all_absent=True, method='BPF_*_GET_NEXT_ID; no object FDs opened'), indent=2)+'\n')

def compare_records(records):
    model=Model.load(ROOT/'src/mlp_params.bpf.h')
    for r in records:
        need(r['mask']==63 and r['model_slot']==0,'Incomplete six-stage prediction')
        arithmetic=[]; expected,label=model.infer(r['features'],arithmetic)
        need(not arithmetic,'Unsafe arithmetic on observed features')
        need(r['tensors']==[expected[n] for n in STAGES] and r['label']==label,'TC/reference parity mismatch')
    return dict(records=len(records), stage_tensors=len(records)*6,
                integers=sum(sum(len(t) for t in r['tensors']) for r in records))


def kernel_checks(log,bidirectional=False):
    name='bidirectional-kernel-checks' if bidirectional else 'kernel-checks'
    directory=log.output/name; directory.mkdir()
    r=log.command([ROOT/'tc/.output/controller','--bidirectional-tests' if bidirectional else '--kernel-tests',ROOT/'tc/.output/tc_ids.bpf.o',directory],
                  name,check=False)
    (directory/'events.jsonl').write_text(r.stdout)
    (directory/'controller.log').write_text(r.stderr)
    events=[json.loads(s) for s in r.stdout.splitlines()]
    loaded=next((e for e in events if e['event']=='loaded'),None)
    if loaded: verify_private_ids(log,directory,loaded)
    need(r.returncode==0,'Kernel concurrency/failure suite failed; inspect kernel-checks.log and verifier logs')
    cases={e['name'] for e in events if e['event']=='kernel_case' and e['assertions']=='PASS'}
    if bidirectional:
        need(cases=={'fixed_mean_above_below_full_chain','bidirectional_same_flow','bidirectional_distinct_flows',
                     'egress_first_and_duplicate_result_immutable','malformed_egress_pass_unscored','egress_flow_capacity_pass'},
             'Bidirectional kernel suite incomplete')
        s=next(e for e in events if e['event']=='snapshot')
        need(s['predictions']==15 and len(s['results'])==15 and s['stages']==[15]*6,'Bidirectional kernel result/stage counts')
        need(s['tail_failures']==s['inference_failures']==s['workspace_busy']==s['result_failures']==0
             and s['flow_full']==1 and s['egress_rejected']==3,'Unexpected bidirectional failure accounting')
        same=next(f for f in s['flows'] if f['source_port']==47000)
        need(same['packets']==514 and same['hooks']['ingress']['packets']==514
             and same['hooks']['egress']['packets']==514,'Bidirectional same-flow counts')
        need(all(f['state']==2 for f in s['flows']),'Bidirectional flow not complete')
        comparisons=compare_records(s['results'])
        (directory/'comparisons.json').write_text(json.dumps(comparisons,indent=2)+'\n')
        return dict(status='PASS',cases=sorted(cases),numerical=comparisons,same_flow=same,
                    scheduling='CPU-pinned workers on both programs; exact overlap not forced',cleanup='PASS')
    need(cases=={'same_flow','distinct_flows','all_missing_tail_slots_retry','missing_model_retry',
                 'duplicate_result_immutable','malformed_pass_unscored','flow_capacity_pass',
                 'result_capacity_retry','injected_reentrancy_guard','fixed_mean_above_below_full_chain'},
         'Kernel suite incomplete')
    s=next(e for e in events if e['event']=='snapshot')
    need(len(s['results'])==23 and s['predictions']==23,'Kernel result count mismatch')
    need((s['tail_failures'],s['inference_failures'],s['flow_full'],s['workspace_busy'],s['result_failures'])
         ==(6,8,1,1,1),'Unexpected failure accounting')
    same=next(f for f in s['flows'] if f['source_port']==41000)
    need(same['packets']==4*257+5 and same['bytes']==20*same['packets'] and same['duplicates']==8,
         'Same-flow counters inconsistent')
    need(all(f['state']==2 for f in s['flows']),'Flow left running or retry incomplete')
    comparisons=compare_records(s['results'])
    (directory/'comparisons.json').write_text(json.dumps(comparisons,indent=2)+'\n')
    return dict(status='PASS', cases=sorted(cases), numerical=comparisons,
                same_flow=same, scheduling='CPU-pinned workers; exact overlap not forced',
                reentrancy='Injected busy guard tested; actual interrupt nesting not forced', cleanup='PASS')


def qdisc_cleanup(log, directory):
    dumps = {}
    for direction in ('ingress','egress'):
        r=log.command(['ip','netns','exec',SERVER,'tc','-j','filter','show','dev',SIF,direction])
        require_empty_filters(r.stdout, r.returncode)
        dumps[direction] = json.loads(r.stdout)
    (directory/'filter-absence.json').write_text(json.dumps(dumps, indent=2)+'\n')
    q=json.loads(log.command(['ip','netns','exec',SERVER,'tc','-j','qdisc','show','dev',SIF]).stdout)
    if any(v['kind']=='clsact' for v in q):
        log.command(['ip','netns','exec',SERVER,'tc','qdisc','del','dev',SIF,'clsact'])


def cleanup_loader(log, loader):
    """Check resource absence even if the controller exited with a runtime error."""
    evidence={}; errors=[]
    try: loader.stop()
    except Exception as e:
        evidence['controller_diagnostic']=str(e)
        if not loader.stopped: errors.append('Controller could not be stopped')
    for name,action in (('filters',lambda:qdisc_cleanup(log,loader.directory)),
                        ('owned_ids',loader.verify_ids_gone)):
        try: action(); evidence[name]='PASS'
        except Exception as e: evidence[name]=str(e); errors.append(f'{name}: {e}')
    evidence['status']='FAIL' if errors else 'PASS'
    (loader.directory/'cleanup-status.json').write_text(json.dumps(evidence,indent=2)+'\n')
    need(not errors,'; '.join(errors))


def cleanup_namespaces(log, owned):
    errors=[]
    for name, inode in reversed(list(owned.items())):
        try:
            path=Path('/run/netns')/name
            if not path.exists(): continue
            need(path.stat().st_ino == inode,f'Namespace {name} replaced; refusing deletion')
            need(not log.command(['ip','netns','pids',name]).stdout.strip(),f'Namespace {name} still contains processes')
            log.command(['ip','netns','delete',name])
            need(not path.exists(),f'Namespace {name} remains')
        except Exception as e: errors.append(str(e))
    need(not errors,'; '.join(errors))


def traffic(log, mode, port, count=1, repeat=1):
    directory=log.output/mode
    marker=directory/'server.ready'
    server_log=(directory/'server.log').open('w')
    argv=['ip','netns','exec',SERVER,sys.executable,str(ROOT/'tc/traffic.py'),'server',str(marker),str(count),str(repeat)]
    (directory/'server-command.json').write_text(json.dumps(argv)+'\n')
    server=subprocess.Popen(argv,stdout=server_log,stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+10
        while not marker.exists():
            need(server.poll() is None and time.monotonic()<deadline,'TCP server not ready')
            time.sleep(.05)
        log.command(['ip','netns','exec',CLIENT,sys.executable,ROOT/'tc/traffic.py','client',str(port),str(count),str(repeat)],mode+'-client')
        need(server.wait(timeout=15)==0,'TCP server exchange failed')
    finally:
        if server.poll() is None: server.terminate(); server.wait(timeout=3)
        server_log.close()


def run(args):
    need(os.geteuid()==0,'--run needs an approved sudo invocation')
    bundle=args.run.resolve(); manifest=json.loads((bundle/'manifest.json').read_text())
    need(json.loads((bundle/'results.json').read_text())['preparation']=='PASS','Preparation did not pass')
    branch()
    for group in manifest.values():
        for name, expected in group.items(): need(sha(ROOT/name)==expected,f'Prepared source/build changed: {name}; prepare again')
    out=bundle/('run-'+stamp()); out.mkdir(); print(f'TC evidence: {out}',flush=True)
    log=Log(out); owned={}; loader=None; witness=None; lock=None
    result=dict(minimal_ingress='NOT RUN', full_inference='NOT RUN', cleanup='NOT RUN', optional_egress='NOT IMPLEMENTED')
    try:
        lock=open('/run/tcids-demo.lock','a+'); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        names=[s.split()[0] for s in log.command(['ip','netns','list'],'namespaces-before').stdout.splitlines()]
        need(SERVER not in names and CLIENT not in names,'Demo namespace names already exist')
        if args.phase1 or args.phase2:
            result['kernel_checks']='FAIL'
            result['kernel_checks']=kernel_checks(log)
        if args.phase2:
            result['bidirectional_kernel_checks']='FAIL'
            result['bidirectional_kernel_checks']=kernel_checks(log,True)
        for name in (SERVER,CLIENT):
            log.command(['ip','netns','add',name]); owned[name]=(Path('/run/netns')/name).stat().st_ino
            (out/'owned.json').write_text(json.dumps(owned,indent=2)+'\n')
        log.command(['ip','-n',SERVER,'link','add',SIF,'type','veth','peer','name',CIF])
        log.command(['ip','-n',SERVER,'link','set',CIF,'netns',CLIENT])
        token='tcids-'+uuid.uuid4().hex
        for name,iface,address in ((SERVER,SIF,'33.33.33.1/24'),(CLIENT,CIF,'33.33.33.73/24')):
            log.command(['ip','-n',name,'link','set',iface,'alias',token])
            log.command(['ip','-n',name,'addr','add',address,'dev',iface])
            log.command(['ip','-n',name,'link','set',iface,'up'])
            log.command(['ip','-n',name,'link','set','lo','up'])
        phases=[('minimal',40001,1),('inference',40002,1)]
        if args.phase1 or args.phase2: phases.append(('concurrent',41000,10))
        if args.phase2:phases += [('bidirectional',40004,1),('bidirectional-concurrent',42000,10),('bidirectional-burst',43000,1)]
        if args.egress_counter:
            phases=[('egress-counter',40003,1)]
            result['phase2_stage']='EGRESS COUNTER ONLY; canonical keys and directional flow state not implemented'
        for mode,port,count in phases:
            if mode=='inference' and args.minimal_only: break
            info=json.loads(log.command(['ip','-n',SERVER,'-j','-d','link','show','dev',SIF]).stdout)[0]
            need(info['linkinfo']['info_kind']=='veth' and info.get('ifalias')==token,'Interface ownership mismatch')
            loader=Loader(log,mode,owned[SERVER])
            loader.read('ready')
            filters=log.command(['ip','netns','exec',SERVER,'tc','-j','filter','show','dev',SIF,'ingress'],mode+'-attachment')
            require_attached_filter(filters.stdout, loader.ready['program_id'])
            if mode=='egress-counter' or mode.startswith('bidirectional'):
                need(loader.ready.get('egress_program_id'),'No attached egress program reported')
                filters=log.command(['ip','netns','exec',SERVER,'tc','-j','filter','show','dev',SIF,'egress'],mode+'-egress-attachment')
                require_attached_filter(filters.stdout,loader.ready['egress_program_id'])
                before_traffic=loader.snapshot()
                (loader.directory/'counters-before-traffic.json').write_text(json.dumps(before_traffic,indent=2)+'\n')
            if mode.startswith('bidirectional'):
                witness=Witness(loader.directory);witness.wait_ready()
            traffic(log,mode,port,count,128 if mode=='bidirectional-burst' else 1)
            snapshot=loader.snapshot()
            # Read counters after traffic quiesces, rather than assuming one
            # application write corresponds to one skb or a fixed packet count.
            stable=0
            for attempt in range(50):
                time.sleep(.05)
                latest=loader.snapshot()
                if latest['packets']==snapshot['packets'] and latest['egress_packets']==snapshot['egress_packets']:
                    stable+=1
                else:stable=0
                snapshot=latest
                if stable>=5:break
            else: raise RuntimeError('Controlled traffic did not quiesce')
            if witness:
                observed=witness.stop();witness=None
                snapshot=loader.snapshot()
                (loader.directory/'snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
                comparison=compare_snapshot(snapshot,observed,port,count)
                (loader.directory/'packet-comparisons.json').write_text(json.dumps(comparison,indent=2)+'\n')
                result[mode+'_packets']=dict(status='PASS',flows=count,non_timing_features_checked=comparison['non_timing_features_checked'])
            need(snapshot['packets']>0 and snapshot['bytes']>0,'Ingress counter did not observe controlled traffic')
            if mode in ('minimal','egress-counter'):
                result['minimal_ingress']='PASS'
                if mode=='egress-counter':
                    deltas={name:snapshot[name]-before_traffic[name]
                            for name in ('packets','bytes','egress_packets','egress_bytes')}
                    need(all(value>0 for value in deltas.values()),'Both hooks must observe new traffic during the controlled exchange')
                    need(snapshot['predictions']==0 and snapshot['stages']==[0]*6 and not snapshot['results'] and not snapshot['flows'],
                         'Minimal counter unexpectedly ran inference or flow tracking')
                    result['egress_counter']='PASS'
                    result['counter_deltas']=deltas
                    result['optional_egress']='COUNTER ONLY; no bidirectional IDS claim'
            else:
                need(snapshot['matched']>=3*count and snapshot['predictions']==count and snapshot['tail_failures']==0,'Inference counters failed')
                need(snapshot['workspace_busy']==snapshot['inference_failures']==snapshot['flow_full']==snapshot['result_failures']==0,
                     'Unexpected live resource or inference failure')
                need(all(v>=1 for v in snapshot['stages']),'Not all six tail-call stages executed')
                records=[r for r in snapshot['results'] if port<=r['source_port']<port+count]
                need(len(records)==count,'Missing or mixed controlled-flow predictions')
                comparisons=compare_records(records)
                for r in records:
                    need(r['features'][3]==5001 and r['features'][5]>=3,'Wrong controlled-flow features')
                    need(r['sequence']==1,'Unexpected inference repetition')
                need(len(snapshot['flows'])==count and all(f['state']==2 and f['failures']==0 for f in snapshot['flows']),
                     'Incomplete or mixed persistent flow state')
                need(sum(f['packets'] for f in snapshot['flows'])==snapshot['matched'],'Lost live per-flow packet updates')
                result['full_inference']='PASS'
                result[mode+'_numerical']=comparisons
                result['reference_comparisons']=result.get('reference_comparisons',0)+len(records)*6
                if mode=='concurrent': result['concurrent_flows']='PASS'
                if mode.startswith('bidirectional'):
                    need(snapshot['egress_matched']>0 and snapshot['ingress_other_direction']==0,'Missing egress or mixed ingress MLP leg')
                    result['optional_egress']='PASS: shared bidirectional monitoring; ingress-leg classification'
                    result[mode]='PASS'
            (out/mode/'snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
            result[mode+'_snapshot']=snapshot
            loader.stop()
            qdisc_cleanup(log, loader.directory)
            loader.verify_ids_gone(); loader=None
    except Exception as e: result['error']=str(e)
    finally:
        errors=[]
        if witness:
            try:witness.stop()
            except Exception as e:errors.append(str(e))
        if loader:
            try: cleanup_loader(log,loader)
            except Exception as e: errors.append(str(e))
        try: cleanup_namespaces(log,owned)
        except Exception as e: errors.append(str(e))
        result['cleanup']='FAIL' if errors else 'PASS'
        if errors: result['cleanup_errors']=errors
        need_integrity = all(sha(ROOT/name)==expected for name,expected in manifest['protected'].items())
        result['protected_files']='UNCHANGED' if need_integrity else 'CHANGED'
        if args.phase1:
            result['phase1_gate']='PASS' if (
                result.get('minimal_ingress')=='PASS' and result.get('full_inference')=='PASS'
                and result.get('concurrent_flows')=='PASS' and result['cleanup']=='PASS'
                and result['protected_files']=='UNCHANGED' and 'error' not in result
                and isinstance(result.get('kernel_checks'),dict) and result['kernel_checks']['status']=='PASS'
            ) else 'FAIL'
        if args.egress_counter:
            result['egress_counter_gate']='PASS' if (
                result.get('minimal_ingress')=='PASS' and result.get('egress_counter')=='PASS'
                and result['cleanup']=='PASS' and result['protected_files']=='UNCHANGED' and 'error' not in result
            ) else 'FAIL'
        if args.phase2:
            result['phase2_gate']='PASS' if (
                result.get('minimal_ingress')=='PASS' and result.get('full_inference')=='PASS'
                and result.get('concurrent_flows')=='PASS' and result['cleanup']=='PASS'
                and result['protected_files']=='UNCHANGED' and 'error' not in result
                and all(isinstance(result.get(k),dict) and result[k]['status']=='PASS'
                        for k in ('kernel_checks','bidirectional_kernel_checks'))
                and all(result.get(k)=='PASS' for k in ('bidirectional','bidirectional-concurrent','bidirectional-burst'))
            ) else 'FAIL'
        if lock: lock.close()
        finish(out,result)
    success=result['minimal_ingress']=='PASS' and (args.minimal_only or result['full_inference']=='PASS')
    if args.egress_counter: success=result.get('egress_counter_gate')=='PASS'
    if args.phase1: success=success and result.get('phase1_gate')=='PASS'
    if args.phase2:success=success and result.get('phase2_gate')=='PASS'
    return int(not success or result['cleanup']!='PASS' or result['protected_files']!='UNCHANGED' or 'error' in result)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',action='store_true')
    g.add_argument('--run',type=Path,metavar='BUNDLE')
    g.add_argument('--cleanup',type=Path,metavar='RUN_DIRECTORY')
    p.add_argument('--minimal-only',action='store_true')
    p.add_argument('--phase1',action='store_true',help='Run private kernel SMP/failure suite, ingress regression and ten live flows')
    p.add_argument('--phase2',action='store_true',help='Ingress regression, two-hook kernel stress and attached bidirectional packet comparisons')
    p.add_argument('--egress-counter',action='store_true',help='Phase 2 first gate: attach minimal ingress/egress counters only')
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    need(not(args.phase1 and args.minimal_only),'--phase1 requires full inference')
    need(not(args.phase2 and (args.phase1 or args.minimal_only or args.egress_counter)),'--phase2 is a separate integrated suite')
    need(not(args.egress_counter and (args.phase1 or args.minimal_only or args.phase2)),
         '--egress-counter is a separate staged test; do not combine with other test modes')
    if args.prepare: return prepare(args)
    if args.run:
        def interrupted(signum,frame): raise RuntimeError(f'Interrupted by signal {signum}')
        signal.signal(signal.SIGINT,interrupted); signal.signal(signal.SIGTERM,interrupted)
        return run(args)
    need(os.geteuid()==0,'Cleanup needs an approved sudo invocation')
    owned=json.loads((args.cleanup/'owned.json').read_text())
    need(set(owned).issubset({SERVER,CLIENT}),'Unknown namespace names in ownership record')
    branch()
    cleanup_output=args.cleanup/('cleanup-'+stamp()); cleanup_output.mkdir()
    cleanup_namespaces(Log(cleanup_output),owned)
    print('Owned namespaces removed; their veth/qdisc/filter resources removed with them.')
    return 0


if __name__=='__main__': raise SystemExit(main())
