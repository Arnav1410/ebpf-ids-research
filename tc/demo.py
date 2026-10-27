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
    (output/'REPORT.md').write_text('# TC ingress prototype run\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n\n'
        'PASS in preparation means compilation and host tests only. Runtime evidence requires --run.\n'
        'TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.\n'
        'Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.\n'
        'Original XDP/validation/model files are unchanged. Egress is NOT IMPLEMENTED in this iteration.\n')
    files = [p for p in output.rglob('*') if p.is_file() and p.name != 'SHA256SUMS']
    (output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+str(p.relative_to(output))+'\n' for p in sorted(files)))
    print(json.dumps(result,indent=2),flush=True)
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
        log.command(['clang-12','-O3','-shared','-fPIC','-I'+str(ROOT/'tc/tests/include'),
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
    except Exception as e: result['error'] = str(e)
    finish(out,result)
    return int(result['preparation'] != 'PASS')


class Loader:
    def __init__(self, log, mode, inode):
        self.directory = log.output/mode; self.directory.mkdir()
        self.events = []; self.log = log; self.ready = None; self.pending = b''; self.stopped = False
        self.err = (self.directory/'controller.log').open('w')
        argv = ['ip','netns','exec',SERVER,str(ROOT/'tc/.output/controller'),'--run',
                str(ROOT/f'tc/.output/{"tc_min" if mode == "minimal" else "tc_ids"}.bpf.o'),SIF,str(inode),str(self.directory)]
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
            require_detach_ack(self.events, self.ready['program_id'])
    def verify_ids_gone(self):
        if not self.ready: return
        for kind, ids in (('prog',self.ready['program_ids']),('map',self.ready['map_ids'])):
            remaining = set(ids)
            for attempt in range(50):
                # GET_NEXT_ID only: bpftool show opens FDs and can interfere
                # with last-user prog-array deferred teardown on this kernel.
                r = self.log.command([ROOT/'tc/.output/controller','--list-ids',kind],check=True)
                live = json.loads(r.stdout)
                need(isinstance(live,list) and all(type(i) is int and i>0 for i in live),'Invalid ID registry scan')
                remaining = set(live).intersection(ids)
                if not remaining: break
                time.sleep(.1)
            else: raise RuntimeError(f'Private {kind} IDs remain: {sorted(remaining)}')
        (self.directory/'ids-absent.json').write_text(json.dumps(dict(
            program_ids=self.ready['program_ids'], map_ids=self.ready['map_ids'],
            all_absent=True, method='BPF_*_GET_NEXT_ID; no object FDs opened'), indent=2)+'\n')


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


def traffic(log, mode, port):
    directory=log.output/mode
    marker=directory/'server.ready'
    server_log=(directory/'server.log').open('w')
    argv=['ip','netns','exec',SERVER,sys.executable,str(ROOT/'tc/traffic.py'),'server',str(marker)]
    (directory/'server-command.json').write_text(json.dumps(argv)+'\n')
    server=subprocess.Popen(argv,stdout=server_log,stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+10
        while not marker.exists():
            need(server.poll() is None and time.monotonic()<deadline,'TCP server not ready')
            time.sleep(.05)
        log.command(['ip','netns','exec',CLIENT,sys.executable,ROOT/'tc/traffic.py','client',str(port)],mode+'-client')
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
    log=Log(out); owned={}; loader=None; lock=None
    result=dict(minimal_ingress='NOT RUN', full_inference='NOT RUN', cleanup='NOT RUN', optional_egress='NOT IMPLEMENTED')
    try:
        lock=open('/run/tcids-demo.lock','a+'); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        names=[s.split()[0] for s in log.command(['ip','netns','list'],'namespaces-before').stdout.splitlines()]
        need(SERVER not in names and CLIENT not in names,'Demo namespace names already exist')
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
        for mode,port in (('minimal',40001),('inference',40002)):
            if mode=='inference' and args.minimal_only: break
            info=json.loads(log.command(['ip','-n',SERVER,'-j','-d','link','show','dev',SIF]).stdout)[0]
            need(info['linkinfo']['info_kind']=='veth' and info.get('ifalias')==token,'Interface ownership mismatch')
            loader=Loader(log,mode,owned[SERVER])
            loader.read('ready')
            filters=log.command(['ip','netns','exec',SERVER,'tc','-j','filter','show','dev',SIF,'ingress'],mode+'-attachment')
            require_attached_filter(filters.stdout, loader.ready['program_id'])
            traffic(log,mode,port)
            snapshot=loader.snapshot()
            need(snapshot['packets']>0 and snapshot['bytes']>0,'Ingress counter did not observe controlled traffic')
            if mode=='minimal': result['minimal_ingress']='PASS'
            else:
                need(snapshot['matched']>=3 and snapshot['predictions']>=1 and snapshot['tail_failures']==0,'Inference counters failed')
                need(all(v>=1 for v in snapshot['stages']),'Not all six tail-call stages executed')
                records=[r for r in snapshot['results'] if r['source_port']==port]
                need(records,'No prediction for controlled source port')
                model=Model.load(ROOT/'src/mlp_params.bpf.h')
                for r in records:
                    need(r['mask']==63 and r['model_slot']==0,'Incomplete six-stage prediction')
                    arithmetic=[]; expected,label=model.infer(r['features'],arithmetic)
                    need(not arithmetic,'Unsafe arithmetic on observed features')
                    need(r['tensors']==[expected[n] for n in STAGES] and r['label']==label,'TC/reference parity mismatch')
                    need(r['features'][3]==5001 and r['features'][5]>=3,'Wrong controlled-flow features')
                result['full_inference']='PASS'
                result['reference_comparisons']=len(records)*6
            (out/mode/'snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
            result[mode+'_snapshot']=snapshot
            loader.stop()
            qdisc_cleanup(log, loader.directory)
            loader.verify_ids_gone(); loader=None
    except Exception as e: result['error']=str(e)
    finally:
        errors=[]
        if loader:
            try: loader.stop(); loader.verify_ids_gone()
            except Exception as e: errors.append(str(e))
        try: cleanup_namespaces(log,owned)
        except Exception as e: errors.append(str(e))
        result['cleanup']='FAIL' if errors else 'PASS'
        if errors: result['cleanup_errors']=errors
        need_integrity = all(sha(ROOT/name)==expected for name,expected in manifest['protected'].items())
        result['protected_files']='UNCHANGED' if need_integrity else 'CHANGED'
        if lock: lock.close()
        finish(out,result)
    success=result['minimal_ingress']=='PASS' and (args.minimal_only or result['full_inference']=='PASS')
    return int(not success or result['cleanup']!='PASS' or result['protected_files']!='UNCHANGED' or 'error' in result)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',action='store_true')
    g.add_argument('--run',type=Path,metavar='BUNDLE')
    g.add_argument('--cleanup',type=Path,metavar='RUN_DIRECTORY')
    p.add_argument('--minimal-only',action='store_true')
    p.add_argument('--output',type=Path)
    args=p.parse_args()
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
