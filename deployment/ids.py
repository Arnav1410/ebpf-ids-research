#!/usr/bin/env python3
"""Local operator-controlled TC deployment and privileged snapshot collector."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import platform
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from dashboard.telemetry import Collector,RotatingLog,atomic_json
from deployment.model_config import model_spec,verify_loaded

DEFAULT_STATE=Path('/run/nn-ebpf-ids')
HANDLE=0x4e4e;PRIORITY=49152


def command(argv):
    result=subprocess.run([str(v) for v in argv],capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError(' '.join(map(str,argv))+': '+result.stderr.strip())
    return result.stdout


def tc_state(interface):
    return {name:json.loads(command(['tc','-j',name,'show','dev',interface])) if name=='qdisc'
            else json.loads(command(['tc','-j','filter','show','dev',interface,name]))
            for name in ('qdisc','ingress','egress')}


def program_id(f):
    return f.get('options',{}).get('prog',{}).get('id',f.get('options',{}).get('id'))


def owns_filter(f,expected,handle=HANDLE,priority=PRIORITY):
    options=f.get('options',{});h=options.get('handle')
    try:h=int(h,0) if isinstance(h,str) else h
    except ValueError:return False
    return (f.get('kind')=='bpf' and program_id(f)==expected and f.get('pref')==priority
            and h==handle and options.get('direct-action') is True)


def check_empty(state):
    if state['ingress'] or state['egress']:raise RuntimeError('Existing classifiers: refusing to change their behavior')
    if any(q['kind']=='ingress' for q in state['qdisc']):raise RuntimeError('Legacy ingress qdisc conflicts with two-hook deployment')
    if any('block' in str(k) and v for q in state['qdisc'] for k,v in q.items()):
        raise RuntimeError('Shared classifier block: operator review required')


def paths(mode,model='original'):
    suffix='_layer' if mode=='layer_specific' else ''
    selected='_fresh' if model=='fresh' else ''
    return ROOT/f'tc/.output/controller{selected}{suffix}',ROOT/f'tc/.output/tc_ids{suffix}.bpf.o'


def identity(interface):
    return dict(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                netns_inode=os.stat('/proc/self/ns/net').st_ino,ifindex=socket.if_nametoindex(interface),interface=interface)


def preflight(args):
    interface=args.interface;ident=identity(interface)
    addresses=json.loads(command(['ip','-j','addr','show','dev',interface]))
    if len(addresses)!=1 or addresses[0]['ifindex']!=ident['ifindex']:raise RuntimeError('Interface identity changed')
    if addresses[0].get('link_type')!='ether' or 'UP' not in addresses[0].get('flags',[]):
        raise RuntimeError('Select an already UP Ethernet interface; no link settings will be changed')
    state=tc_state(interface);check_empty(state)
    selected=getattr(args,'model','original');model=model_spec(selected,args.mode)
    ctl,obj=paths(args.mode,selected)
    if not ctl.is_file() or not obj.is_file():raise RuntimeError('Build natively first: make -C tc demo-models CLANG=clang')
    with tempfile.TemporaryDirectory(prefix='tcids-inspect-') as directory:
        schema=[json.loads(v) for v in command([ctl,'--inspect',obj,directory]).splitlines()]
    status=Path('/proc/self/status').read_text();cap=int(next(s.split()[1] for s in status.splitlines() if s.startswith('CapEff:')),16)
    capable=bool(cap&(1<<12)) and bool(cap&((1<<39)|(1<<21)))
    return dict(status='PASS',operation='READ_ONLY_PREFLIGHT',**ident,kernel=platform.release(),architecture=platform.machine(),
                addresses=addresses,existing=state,mode=args.mode,model=selected,model_identity=model,
                application_port=getattr(args,'app_port',None),controller=str(ctl),object=str(obj),schema=schema,
                kernel_btf=Path('/sys/kernel/btf/vmlinux').is_file(),effective_capabilities=hex(cap),
                attachment_capabilities=capable,required='CAP_NET_ADMIN and CAP_BPF (or CAP_SYS_ADMIN); actual load/verifier still required',
                planned=dict(ingress='tc_entry',egress='tc_egress',handle=HANDLE,priority=PRIORITY,
                             qdisc='create or reuse empty clsact; never delete',client_ip=args.client_ip,
                             application_port=getattr(args,'app_port',None),
                             port_filter='No kernel port filter; client-IP scope unchanged; connections matched by complete TCP tuple'),
                model_bytes_per_slot=5304 if args.mode=='layer_specific' else 5216,
                physical_verification='NOT RUN',network_changes='NONE')


def secure_directory(path):
    if not path.is_absolute():raise RuntimeError('Use an absolute runtime directory')
    # Resolve no symlinks, including intermediate components.
    if path.resolve()!=path:raise RuntimeError('Runtime path contains symlinks')
    path.mkdir(mode=0o755,parents=False,exist_ok=True)
    s=path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o022:
        raise RuntimeError('Runtime directory must be owned by collector UID and not group/world writable')


def control_path(directory):
    path=directory/'control.sock'
    if len(os.fsencode(path))>107:raise RuntimeError('Runtime path too long for a Linux Unix socket; use /run/nn-ebpf-ids')
    return path


class Controller:
    def __init__(self,args,directory):
        ctl,obj=paths(args.mode,getattr(args,'model','original'));self.events=[];self.pending=b'';self.directory=directory
        self.stderr=(directory/'controller.log').open('w')
        self.proc=subprocess.Popen([str(ctl),'--deploy',str(obj),args.interface,str(directory),
            '--client-ip',args.client_ip],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,
            bufsize=0,start_new_session=True)

    def accept(self,line):
        value=json.loads(line)
        if value['event']!='snapshot':
            self.events.append(value)
            with (self.directory/'events.jsonl').open('a') as f:f.write(json.dumps(value)+'\n')
        return value

    def read(self,event,timeout=20):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if b'\n' in self.pending:
                line,self.pending=self.pending.split(b'\n',1);value=self.accept(line)
                if value['event']==event:return value
                continue
            if not select.select([self.proc.stdout],[],[],.1)[0]:continue
            block=os.read(self.proc.stdout.fileno(),65536)
            if not block:raise RuntimeError('Controller exited; inspect '+str(self.directory/'controller.log'))
            self.pending+=block
            if len(self.pending)>64*1024*1024:raise RuntimeError('Snapshot exceeds bounded map-output limit')
        raise RuntimeError('Controller timeout waiting for '+event)

    def snapshot(self):
        self.proc.stdin.write(b'snapshot\n');self.proc.stdin.flush();return self.read('snapshot')

    def stop(self):
        if self.proc.poll() is None:
            try:self.proc.stdin.write(b'stop\n');self.proc.stdin.flush()
            except BrokenPipeError:pass
        try:remaining,_=self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.terminate();remaining,_=self.proc.communicate(timeout=5)
        for line in (self.pending+remaining).splitlines():self.accept(line)
        self.pending=b'';self.stderr.close()
        if self.proc.returncode:raise RuntimeError('Controller exited with status '+str(self.proc.returncode))


def hook_status(args,owner):
    state=tc_state(args.interface);ready=owner['ready']
    return {h:dict(attached=any(owns_filter(f,ready['program_id' if h=='ingress' else 'egress_program_id']) for f in state[h]),
                   program_id=ready['program_id' if h=='ingress' else 'egress_program_id']) for h in ('ingress','egress')}


def start(args):
    socket_path=control_path(args.state_dir)
    plan=preflight(args)
    if args.dry_run:print(json.dumps(plan,indent=2));return 0
    if os.geteuid() or not plan['attachment_capabilities'] or not plan['kernel_btf']:
        raise RuntimeError('Explicit root invocation, kernel BTF and required capabilities are needed')
    directory=args.state_dir;secure_directory(directory)
    lockfd=os.open(directory/'collector.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:os.close(lockfd);raise RuntimeError('Collector already running')
    session=uuid.uuid4().hex;logs=directory/('verifier-'+session);logs.mkdir(mode=0o755)
    controller=None;control=None;owner=None;latest=None;stop_requested=False;rc=0
    def stop_signal(*_):
        nonlocal stop_requested;stop_requested=True
    signal.signal(signal.SIGTERM,stop_signal);signal.signal(signal.SIGINT,stop_signal)
    try:
        atomic_json(directory/'preflight.json',plan)
        controller=Controller(args,logs);ready=controller.read('ready')
        loaded_model=verify_loaded(logs,getattr(args,'model','original'),args.mode)
        arithmetic=next(e for e in controller.events if e['event']=='inference_mode')
        if arithmetic['mode']!=args.mode or (args.mode=='layer_specific' and arithmetic['q_outputs'][-1]!=loaded_model['logit_q']):
            raise RuntimeError('Loaded arithmetic metadata differs from selected model')
        current_identity=identity(args.interface)
        if ready['ifindex']!=plan['ifindex'] or any(current_identity[k]!=plan[k] for k in current_identity):
            raise RuntimeError('Interface identity changed after preflight')
        owner=dict(**identity(args.interface),session=session,mode=args.mode,model=getattr(args,'model','original'),
                   model_identity=loaded_model,application_port=getattr(args,'app_port',None),
                   experiment_id=getattr(args,'experiment_id',None),ready=ready,collector_pid=os.getpid(),active=True)
        atomic_json(directory/'owner.json',owner)
        if socket_path.exists():
            if not stat.S_ISSOCK(socket_path.lstat().st_mode):raise RuntimeError('Refusing non-socket control path')
            socket_path.unlink()
        control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);control.bind(str(socket_path));os.chmod(socket_path,0o600);control.listen(4)
        server_ips=[v['local'] for link in plan['addresses'] for v in link.get('addr_info',[]) if v.get('family')=='inet']
        collector=Collector(args.interface,args.mode,session,RotatingLog(directory/'classifications.jsonl'),server_ips,
                            model_identity=loaded_model,application_port=getattr(args,'app_port',None),
                            experiment_id=getattr(args,'experiment_id',None))
        print(json.dumps(dict(event='deployment_ready',**owner,telemetry=str(directory/'telemetry.json'))),flush=True)
        while not stop_requested:
            hooks=hook_status(args,owner)
            if not all(v['attached'] for v in hooks.values()):raise RuntimeError('Owned attachment changed; refusing to continue as live')
            latest=collector.update(controller.snapshot(),hooks);atomic_json(directory/'telemetry.json',latest)
            if select.select([control],[],[],args.interval)[0]:
                conn,_=control.accept()
                with conn:
                    conn.settimeout(5);request=conn.recv(64)
                    if request==b'stop\n':stop_requested=True;conn.sendall(b'stopping\n')
                    elif request==b'snapshot\n':conn.sendall((json.dumps(controller.snapshot())+'\n').encode())
                    else:conn.sendall(b'unsupported\n')
    except Exception as error:
        rc=1;print(str(error),file=sys.stderr)
        latest=latest or dict(schema=1,source='LIVE',interface=args.interface,mode=args.mode,flows=[],errors=[])
        latest['status']='ERROR';latest['errors']=latest.get('errors',[])+[str(error)]
    finally:
        errors=[]
        if controller:
            try:controller.stop()
            except Exception as error:errors.append(str(error));rc=1
            loaded=next((e for e in controller.events if e['event']=='loaded'),None)
            if loaded:
                for kind,key in (('prog','program_ids'),('map','map_ids')):
                    try:
                        for _ in range(50):
                            if not set(json.loads(command([paths('static_q16')[0],'--list-ids',kind])))&set(loaded[key]):break
                            time.sleep(.1)
                        else:raise RuntimeError('Owned '+kind+' IDs remain')
                    except Exception as error:errors.append(str(error));rc=1
        try:
            after=tc_state(args.interface)
            if owner and any(owns_filter(f,owner['ready']['program_id' if h=='ingress' else 'egress_program_id']) for h in ('ingress','egress') for f in after[h]):
                raise RuntimeError('Owned filters still present')
            atomic_json(directory/'cleanup.json',dict(session=session,status='FAIL' if errors else 'PASS',errors=errors,after=after,
                qdisc='LEFT IN PLACE',network_addresses_routes='NOT MODIFIED'))
        except Exception as error:errors.append(str(error));rc=1
        if owner:owner['active']=False;atomic_json(directory/'owner.json',owner)
        if latest:
            latest['status']='ERROR' if rc else 'STOPPED';latest['errors']=latest.get('errors',[])+errors
            if not rc:latest['hooks']={h:{**v,'attached':False} for h,v in latest.get('hooks',{}).items()}
            atomic_json(directory/'telemetry.json',latest)
        if control:control.close();socket_path.unlink(missing_ok=True)
        os.close(lockfd)
    return rc


def stop(args):
    if os.geteuid():raise RuntimeError('Stopping the privileged collector requires explicit sudo')
    secure_directory(args.state_dir)
    owner=json.loads((args.state_dir/'owner.json').read_text())
    if any(owner[k]!=v for k,v in identity(args.interface).items()):raise RuntimeError('Stale interface/boot/namespace identity; refusing detach')
    socket_path=control_path(args.state_dir)
    if socket_path.exists():
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.settimeout(2);s.connect(str(socket_path));s.sendall(b'stop\n');print(s.recv(64).decode().strip())
            for _ in range(200):
                current=json.loads((args.state_dir/'owner.json').read_text())
                if not current['active']:
                    cleanup=json.loads((args.state_dir/'cleanup.json').read_text())
                    if cleanup['session']!=owner['session'] or cleanup['status']!='PASS':raise RuntimeError('Collector cleanup did not pass')
                    if any(v['attached'] for v in hook_status(args,owner).values()):raise RuntimeError('Owned filter remains')
                    print('Owned filters and private IDs released; clsact left in place');return 0
                time.sleep(.1)
            raise RuntimeError('Collector did not finish cleanup within 20 seconds')
        except ConnectionRefusedError:pass
    # Recovery after supervisor death. Never signal a PID from an old file.
    lockfd=os.open(args.state_dir/'collector.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:os.close(lockfd);raise RuntimeError('Collector is starting/stopping; wait and retry, no recovery detach performed')
    if json.loads((args.state_dir/'owner.json').read_text())['session']!=owner['session']:
        os.close(lockfd);raise RuntimeError('Collector session changed; refusing recovery detach')
    state=tc_state(args.interface);ready=owner['ready'];ids=[]
    for h in ('ingress','egress'):
        expected=ready['program_id' if h=='ingress' else 'egress_program_id']
        if any(owns_filter(f,expected) for f in state[h]):ids.append(expected)
        elif any(f.get('pref')==PRIORITY for f in state[h]):raise RuntimeError('Attachment identity changed: refusing recovery detach')
        else:ids.append(0)
    if any(ids):print(command([paths(owner['mode'],owner.get('model','original'))[0],'--detach-owned',args.interface,owner['ifindex'],HANDLE,PRIORITY,*ids]))
    for kind,key in (('prog','program_ids'),('map','map_ids')):
        for _ in range(50):
            if not set(json.loads(command([paths('static_q16')[0],'--list-ids',kind])))&set(owner['ready'][key]):break
            time.sleep(.1)
        else:os.close(lockfd);raise RuntimeError('Detached filters, but loader still holds private '+kind+' IDs; inspect controller process')
    owner['active']=False;atomic_json(args.state_dir/'owner.json',owner)
    atomic_json(args.state_dir/'cleanup.json',dict(session=owner['session'],status='PASS',recovery=True,
        after=tc_state(args.interface),qdisc='LEFT IN PLACE',network_addresses_routes='NOT MODIFIED'))
    state_path=args.state_dir/'telemetry.json'
    if state_path.exists():
        value=json.loads(state_path.read_text());value['status']='STOPPED'
        value['hooks']={h:{**v,'attached':False} for h,v in value.get('hooks',{}).items()};atomic_json(state_path,value)
    os.close(lockfd)
    print(json.dumps(dict(status='RECOVERY_CLEANUP_PASS',qdisc='LEFT IN PLACE')));return 0


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('preflight','start','status','stop','snapshot'))
    p.add_argument('--interface',required=True);p.add_argument('--mode',choices=('static_q16','layer_specific'),default='static_q16')
    p.add_argument('--model',choices=('original','fresh'),default='original')
    p.add_argument('--app-port',type=int,help='Application metadata; kernel still monitors client-scoped TCP on every port')
    p.add_argument('--experiment-id',help='Experiment identity included in live telemetry and JSONL')
    p.add_argument('--client-ip',default='any');p.add_argument('--state-dir',type=Path,default=DEFAULT_STATE)
    p.add_argument('--dry-run',action='store_true');p.add_argument('--interval',type=float,default=1)
    args=p.parse_args()
    if not 0.2<=args.interval<=30:p.error('interval must be 0.2..30 seconds')
    if args.app_port is not None and not 1<=args.app_port<=65535:p.error('app-port must be 1..65535')
    if args.client_ip!='any':ipaddress.IPv4Address(args.client_ip)
    if not args.interface or '/' in args.interface or len(args.interface)>15:p.error('Invalid interface name')
    try:
        if args.action=='preflight':print(json.dumps(preflight(args),indent=2));return 0
        if args.action=='start':return start(args)
        if args.action=='stop':return stop(args)
        owner=json.loads((args.state_dir/'owner.json').read_text())
        if any(owner[k]!=v for k,v in identity(args.interface).items()):raise RuntimeError('Recorded interface identity differs')
        if args.action=='snapshot':
            if os.geteuid():raise RuntimeError('Full map snapshot requires the privileged collector control socket')
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.settimeout(20);s.connect(str(control_path(args.state_dir)));s.sendall(b'snapshot\n');data=b''
                while b'\n' not in data:
                    block=s.recv(65536)
                    if not block:raise RuntimeError('Incomplete collector response')
                    data+=block
                    if len(data)>64*1024*1024:raise RuntimeError('Snapshot size limit')
            print(json.dumps(json.loads(data)));return 0
        print(json.dumps(dict(owner=owner,hooks=hook_status(args,owner)),indent=2));return 0
    except (OSError,RuntimeError,ValueError,subprocess.SubprocessError) as error:print(str(error),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
