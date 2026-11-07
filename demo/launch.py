#!/usr/bin/env python3
"""One operator command for existing IDS, unprivileged TCP service and dashboard."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
from deployment.ids import preflight,control_path
from dashboard.telemetry import atomic_json
from evaluation.data import digest


def wait_json(path,predicate,process,seconds=15):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if process.poll() is not None:raise RuntimeError('Child exited; inspect experiment logs')
        try:
            value=json.loads(path.read_text())
            if value.get('status')=='ERROR':raise RuntimeError(str(value.get('errors')))
            if predicate(value):return value
        except (FileNotFoundError,ValueError):pass
        time.sleep(.1)
    raise RuntimeError('Startup deadline: '+str(path))


def launch(args):
    if os.geteuid()!=0:raise RuntimeError('Use sudo from your ordinary Linux account; web/application children will drop privileges')
    uid=int(os.environ.get('SUDO_UID','0'));gid=int(os.environ.get('SUDO_GID','0'))
    if uid<=0:raise RuntimeError('SUDO_UID is required; do not run the web server as root')
    args.state_dir=Path('/run')/('idsdemo-'+uuid.uuid4().hex[:12]);args.dry_run=False
    args.interval=.2;args.client_ip=args.client_ip
    plan=preflight(args)
    if not any(a.get('local')==args.server_ip for link in plan['addresses'] for a in link['addr_info']):raise RuntimeError('Server IP is not already configured on selected interface')
    print(json.dumps(plan,indent=2),flush=True)
    dry=subprocess.run([sys.executable,ROOT/'deployment/ids.py','start','--interface',args.interface,'--mode',args.mode,
                        '--client-ip',args.client_ip,'--state-dir',args.state_dir,'--dry-run'],check=True,capture_output=True,text=True)
    print(dry.stdout,flush=True)
    confirmation=args.confirm_interface or input('Type ATTACH '+args.interface+' to attach both TC hooks: ')
    if confirmation not in (args.interface,'ATTACH '+args.interface):raise RuntimeError('Attachment not confirmed')
    experiment=uuid.uuid4().hex;out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);os.chown(out,uid,gid)
    (out/'application_events.jsonl').touch();os.chown(out/'application_events.jsonl',uid,gid)
    control_path(args.state_dir);children=[];collector=None;dashboard=None;application=None;stopping=False;runtime_inode=None
    data=dict(experiment_id=experiment,mode=args.mode,interface=args.interface,server_ip=args.server_ip,client_ip=args.client_ip,
              port=args.port,start_unix=time.time(),start_monotonic_ns=time.monotonic_ns(),status='STARTING',collector_session=None,
              model_sha256=digest(ROOT/'src/mlp_params.bpf.h'),kernel=os.uname().release,operator_uid=uid,
              baseline_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip() if (ROOT/'.git').exists() else 'source-archive')
    def signal_stop(*_):
        nonlocal stopping;stopping=True
    signal.signal(signal.SIGINT,signal_stop);signal.signal(signal.SIGTERM,signal_stop)
    def drop():os.setgroups([]);os.setgid(gid);os.setuid(uid)
    def spawn(argv,name,unprivileged=False):
        f=(out/(name+'.log')).open('w')
        p=subprocess.Popen(list(map(str,argv)),stdout=f,stderr=subprocess.STDOUT,start_new_session=True,
                           preexec_fn=drop if unprivileged else None,cwd=ROOT)
        children.append((p,f));return p
    rc=0
    try:
        atomic_json(out/'preflight.json',plan)
        collector=spawn([sys.executable,ROOT/'deployment/ids.py','start','--interface',args.interface,'--mode',args.mode,
                         '--client-ip',args.client_ip,'--state-dir',args.state_dir,'--interval','.2'],'collector')
        owner=wait_json(args.state_dir/'owner.json',lambda v:v.get('active'),collector)
        runtime_inode=args.state_dir.stat().st_ino;data['collector_session']=owner['session'];data['attachments']=owner['ready']
        wait_json(args.state_dir/'telemetry.json',lambda v:v['status']=='CONNECTED',collector)
        application=spawn([sys.executable,ROOT/'demo/server.py','--server-ip',args.server_ip,'--port',args.port,
                           '--experiment-id',experiment,'--events',out/'application_events.jsonl','--ready',out/'application_ready.json'],'application',True)
        wait_json(out/'application_ready.json',lambda v:v['uid']==uid,application)
        dashboard=spawn([sys.executable,ROOT/'dashboard/server.py','--state',args.state_dir/'telemetry.json','--port',args.dashboard_port],'dashboard',True)
        deadline=time.monotonic()+8
        while 'Read-only dashboard:' not in (out/'dashboard.log').read_text():
            if dashboard.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Dashboard startup failed; port may already be in use')
            time.sleep(.1)
        data['status']='RUNNING';atomic_json(out/'experiment.json',data)
        print(json.dumps(dict(event='experiment_ready',experiment_id=experiment,output=str(out),
            dashboard=f'http://127.0.0.1:{args.dashboard_port}/',
            windows_command=f'py -3 client.py --input scenarios.csv --count 10 --concurrency 10 --server-ip {args.server_ip} --source-ip {args.client_ip} --port {args.port} --experiment-id {experiment} --output client-{experiment[:8]}')),flush=True)
        while not stopping:
            if collector.poll() is not None or dashboard.poll() is not None:raise RuntimeError('IDS or dashboard process stopped unexpectedly')
            if application.poll() is not None:
                if application.returncode:raise RuntimeError('Application server failed')
                break
            time.sleep(.2)
    except Exception as error:rc=1;data['error']=str(error);print(str(error),file=sys.stderr)
    finally:
        errors=[]
        # Stop accepting new app work and drain bounded active sockets before
        # the final map snapshot. PID handles refer only to children we spawned.
        if application and application.poll() is None:
            application.terminate()
            try:application.wait(timeout=15)
            except subprocess.TimeoutExpired:application.kill();application.wait();errors.append('Application required SIGKILL')
        if collector:
            try:
                if collector.poll() is None:
                    # A final BPF snapshot alone would not flush the collector's
                    # JSONL logger. Observe two NEW poll publications after the
                    # application is drained, so every retained result is seen.
                    last=json.loads((args.state_dir/'telemetry.json').read_text()).get('collected_unix');updates=0;deadline=time.monotonic()+10
                    while updates<2:
                        v=json.loads((args.state_dir/'telemetry.json').read_text())
                        if v.get('collected_unix')!=last:updates+=1;last=v.get('collected_unix')
                        if collector.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Collector did not drain retained results')
                        time.sleep(.05)
                    snapshot=subprocess.run([sys.executable,ROOT/'deployment/ids.py','snapshot','--interface',args.interface,'--state-dir',args.state_dir],capture_output=True,text=True,timeout=25)
                    if snapshot.returncode:raise RuntimeError('Final snapshot failed: '+snapshot.stderr)
                    (out/'kernel_snapshot.json').write_text(snapshot.stdout)
                    stop=subprocess.run([sys.executable,ROOT/'deployment/ids.py','stop','--interface',args.interface,'--state-dir',args.state_dir],capture_output=True,text=True,timeout=30)
                    (out/'stop.log').write_text(stop.stdout+stop.stderr)
                    if stop.returncode:raise RuntimeError('Owned detach failed; inspect runtime directory '+str(args.state_dir))
                if collector.wait(timeout=15):raise RuntimeError('Collector returned failure')
            except Exception as error:errors.append(str(error))
        if dashboard and dashboard.poll() is None:dashboard.terminate();dashboard.wait(timeout=5)
        for p,f in children:f.close()
        if args.state_dir.exists():
            try:
                if runtime_inode is not None and args.state_dir.stat().st_ino!=runtime_inode:raise RuntimeError('Runtime identity changed; refusing removal')
                for name in ('owner.json','cleanup.json','telemetry.json'):
                    if (args.state_dir/name).exists():shutil.copyfile(args.state_dir/name,out/name)
                logs=[args.state_dir/('classifications.jsonl'+suffix) for suffix in ('.3','.2','.1','')]
                with (out/'server_classifications.jsonl').open('w') as dest:
                    for p in logs:
                        if p.exists():dest.write(p.read_text())
                cleanup=json.loads((args.state_dir/'cleanup.json').read_text())
                if cleanup['status']!='PASS':raise RuntimeError('Collector cleanup evidence did not pass')
                if errors:raise RuntimeError('Runtime retained for cleanup diagnosis')
                shutil.rmtree(args.state_dir) # Sole fresh, owned per-experiment runtime; clsact is untouched.
            except Exception as error:errors.append(str(error))
        data.update(end_unix=time.time(),end_monotonic_ns=time.monotonic_ns(),status='FAIL' if rc or errors else 'PASS',cleanup_errors=errors,
                    evidence_type='Actual local TCP/kernel experiment; physical two-laptop scope depends on where operator ran it')
        atomic_json(out/'experiment.json',data)
        print(json.dumps(data,indent=2),flush=True)
    return int(data['status']!='PASS')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--interface',default='enp7s0');p.add_argument('--server-ip',default='192.168.77.3')
    p.add_argument('--client-ip',default='192.168.77.2');p.add_argument('--port',type=int,default=9000);p.add_argument('--dashboard-port',type=int,default=8080)
    p.add_argument('--mode',choices=('static_q16','layer_specific'),default='static_q16');p.add_argument('--output',type=Path,required=True)
    p.add_argument('--confirm-interface',help='Explicit operator confirmation; omitted means interactive confirmation after preflight')
    a=p.parse_args()
    if not 1024<=a.port<=65535 or not 1024<=a.dashboard_port<=65535:p.error('Use unprivileged port numbers')
    raise SystemExit(launch(a))
