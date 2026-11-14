#!/usr/bin/env python3
"""One operator command for existing IDS, unprivileged TCP service and dashboard."""
import argparse
from datetime import datetime
import http.client
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid
import pwd

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
from deployment.ids import preflight,control_path
from dashboard.telemetry import atomic_json
from demo.listener import reserve


def local_configuration(args,plan):
    address=ipaddress.IPv4Interface(f'{args.server_ip}/{args.prefix_length}')
    if not any(a.get('family')=='inet' and a.get('local')==args.server_ip and a.get('prefixlen')==args.prefix_length
               for link in plan['addresses'] for a in link['addr_info']):
        raise RuntimeError(f'{args.server_ip}/{args.prefix_length} is not assigned to {args.interface}. Inspect ip -4 addr; startup never configures addresses.')
    if ipaddress.IPv4Address(args.client_ip) not in address.network or args.client_ip==args.server_ip:
        raise RuntimeError('Client/server addresses must be distinct members of the selected demonstration subnet')
    if any(link.get('operstate') in ('DOWN','LOWERLAYERDOWN','DORMANT') for link in plan['addresses']):
        raise RuntimeError('Selected interface has no operational link; inspect cabling/VM adapter without changing the NAT interface')


def dashboard_state(address,port):
    conn=http.client.HTTPConnection(address,port,timeout=2)
    try:
        conn.request('GET','/api/state');response=conn.getresponse()
        if response.status!=200:raise RuntimeError('Dashboard API returned '+str(response.status))
        return json.loads(response.read(32*1024*1024))
    finally:conn.close()


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
    args.state_dir=Path('/run')/('idsdemo-'+uuid.uuid4().hex[:12])
    args.app_port=args.port;args.interval=.2
    plan=preflight(args);local_configuration(args,plan)
    print(json.dumps(plan,indent=2),flush=True)
    if args.dry_run:
        print('DRY RUN: no listener, program load, attachment or network change',flush=True);return 0
    if os.geteuid()!=0:raise RuntimeError('Use sudo from your ordinary Linux account; web/application children will drop privileges')
    uid=int(os.environ.get('SUDO_UID','0'));gid=int(os.environ.get('SUDO_GID','0'))
    if uid<=0:raise RuntimeError('SUDO_UID is required; do not run the web server as root')
    if not plan['attachment_capabilities'] or not plan['kernel_btf']:raise RuntimeError('Required BPF/NET_ADMIN capabilities or kernel BTF missing')
    dry=subprocess.run([sys.executable,ROOT/'deployment/ids.py','start','--interface',args.interface,'--mode',args.mode,
                        '--model',args.model,'--app-port',str(args.port),
                        '--client-ip',args.client_ip,'--state-dir',args.state_dir,'--dry-run'],check=True,capture_output=True,text=True)
    print(dry.stdout,flush=True)
    confirmation=args.confirm_interface or input('Type ATTACH '+args.interface+' to attach both TC hooks: ')
    if confirmation not in (args.interface,'ATTACH '+args.interface):raise RuntimeError('Attachment not confirmed')
    experiment=uuid.uuid4().hex
    if args.output is None:args.output=Path(pwd.getpwuid(uid).pw_dir)/'ids-runs'/datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);os.chown(out,uid,gid)
    (out/'application_events.jsonl').touch();os.chown(out/'application_events.jsonl',uid,gid)
    control_path(args.state_dir);children=[];listeners=[];collector=None;dashboard=None;application=None;stopping=False;runtime_inode=None
    data=dict(experiment_id=experiment,mode=args.mode,interface=args.interface,server_ip=args.server_ip,client_ip=args.client_ip,
              prefix_length=args.prefix_length,model=args.model,model_identity=plan['model_identity'],
              dashboard_bind=args.dashboard_bind,dashboard_port=args.dashboard_port,state_dir=str(args.state_dir),
              port=args.port,start_unix=time.time(),start_monotonic_ns=time.monotonic_ns(),status='STARTING',collector_session=None,
              model_sha256=plan['model_identity']['header_sha256'],kernel=os.uname().release,operator_uid=uid,
              baseline_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip() if (ROOT/'.git').exists() else 'source-archive')
    def signal_stop(*_):
        nonlocal stopping;stopping=True
    signal.signal(signal.SIGINT,signal_stop);signal.signal(signal.SIGTERM,signal_stop)
    def drop():os.setgroups([]);os.setgid(gid);os.setuid(uid)
    def spawn(argv,name,unprivileged=False,pass_fds=()):
        f=(out/(name+'.log')).open('w')
        p=subprocess.Popen(list(map(str,argv)),stdout=f,stderr=subprocess.STDOUT,start_new_session=True,
                           preexec_fn=drop if unprivileged else None,cwd=ROOT,pass_fds=pass_fds)
        children.append((p,f));return p
    rc=0
    try:
        atomic_json(out/'preflight.json',plan)
        atomic_json(out/'experiment.json',data)
        # Reserve both selected ports before any IDS load. Root opens port 80;
        # only ordinary-user children accept/serve using inherited descriptors.
        app_listener=reserve(args.server_ip,args.port,'TCP application');listeners.append(app_listener)
        web_listener=reserve(args.dashboard_bind,args.dashboard_port,'Dashboard');listeners.append(web_listener)
        if shutil.which('ping'):
            check=subprocess.run(['ping','-n','-c','1','-W','1',args.client_ip],capture_output=True,text=True,timeout=3)
            (out/'client-reachability.log').write_text(check.stdout+check.stderr)
            data['client_icmp']='REACHABLE' if check.returncode==0 else 'UNCONFIRMED; ICMP may be blocked or client not ready'
        else:data['client_icmp']='NOT RUN; ping unavailable'
        print('Client ICMP: '+data['client_icmp'],flush=True)
        collector=spawn([sys.executable,ROOT/'deployment/ids.py','start','--interface',args.interface,'--mode',args.mode,
                         '--model',args.model,'--app-port',args.port,'--experiment-id',experiment,
                         '--client-ip',args.client_ip,'--state-dir',args.state_dir,'--interval','.2'],'collector')
        owner=wait_json(args.state_dir/'owner.json',lambda v:v.get('active'),collector)
        runtime_inode=args.state_dir.stat().st_ino;data['collector_session']=owner['session'];data['attachments']=owner['ready']
        data['model_identity']=owner['model_identity']
        if owner['model_identity']['kernel_readback']!='PASS':raise RuntimeError('Kernel parameter readback not verified')
        data['parameter_sha256']=owner['model_identity']['parameter_sha256'];data['scaler_sha256']=owner['model_identity']['scaler_sha256']
        wait_json(args.state_dir/'telemetry.json',lambda v:v['status']=='CONNECTED',collector)
        application=spawn([sys.executable,ROOT/'demo/server.py','--server-ip',args.server_ip,'--port',args.port,
                           '--experiment-id',experiment,'--events',out/'application_events.jsonl','--ready',out/'application_ready.json',
                           '--listen-fd',app_listener.fileno()],'application',True,(app_listener.fileno(),))
        app_listener.close()
        wait_json(out/'application_ready.json',lambda v:v['uid']==uid and v['pid']==application.pid and v['address']==[args.server_ip,args.port],application)
        dashboard=spawn([sys.executable,ROOT/'dashboard/server.py','--state',args.state_dir/'telemetry.json',
                         '--bind',args.dashboard_bind,'--port',args.dashboard_port,'--listen-fd',web_listener.fileno()],
                         'dashboard',True,(web_listener.fileno(),))
        web_listener.close()
        deadline=time.monotonic()+8
        while 'Read-only dashboard:' not in (out/'dashboard.log').read_text():
            if dashboard.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Dashboard startup failed; port may already be in use')
            time.sleep(.1)
        health=dashboard_state(args.dashboard_bind,args.dashboard_port)
        if (health['status']!='CONNECTED' or health['application_port']!=args.port or health['experiment_id']!=experiment
                or health['model_identity']['parameter_sha256']!=data['parameter_sha256']
                or not all(h['attached'] for h in health['hooks'].values())):
            raise RuntimeError('Dashboard LIVE API or TC attachment readiness did not match experiment')
        atomic_json(out/'dashboard-ready.json',health)
        listener_check=subprocess.run(['ss','-H','-ltn','sport','=',':'+str(args.port)],capture_output=True,text=True,check=True)
        if not listener_check.stdout.strip():raise RuntimeError('Selected TCP application listener absent from ss')
        (out/'listeners.txt').write_text(listener_check.stdout)
        data['status']='RUNNING';atomic_json(out/'experiment.json',data)
        print(f'MODEL: {args.model}\nARITHMETIC: {args.mode}\nHEADER SHA256: {data["model_sha256"]}\nPARAMETER SHA256: {data["parameter_sha256"]}\nSCALER SHA256: {data["scaler_sha256"]}\nKERNEL MODEL READBACK: PASS (slots 0 and 1)',flush=True)
        print(f'TCP LISTENING: {args.server_ip}:{args.port}\nDASHBOARD: http://{args.dashboard_bind}:{args.dashboard_port}/\nDashboard logs: tail -f {str(out/"dashboard.log")!r}',flush=True)
        print(json.dumps(dict(event='experiment_ready',experiment_id=experiment,output=str(out),
            dashboard=f'http://{args.dashboard_bind}:{args.dashboard_port}/',
            windows_command=f'py -3.13 client.py --input scenarios-reproduction-informed.csv --count 1 --concurrency 1 --server-ip {args.server_ip} --source-ip {args.client_ip} --port {args.port} --experiment-id {experiment} --output client-{experiment[:8]}-one')),flush=True)
        while not stopping:
            if collector.poll() is not None or dashboard.poll() is not None:raise RuntimeError('IDS or dashboard process stopped unexpectedly')
            if application.poll() is not None:
                if application.returncode:raise RuntimeError('Application server failed')
                break
            time.sleep(.2)
    except Exception as error:rc=1;data['error']=str(error);print(str(error),file=sys.stderr)
    finally:
        errors=[]
        for listener in listeners:listener.close()
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
        if dashboard and dashboard.poll() is None:
            dashboard.terminate()
            try:dashboard.wait(timeout=5)
            except subprocess.TimeoutExpired:dashboard.kill();dashboard.wait();errors.append('Dashboard required SIGKILL')
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
        elif collector is None:
            atomic_json(out/'cleanup.json',dict(status='PASS',scope='No IDS process started; reserved sockets closed; no BPF or network changes'))
        data.update(end_unix=time.time(),end_monotonic_ns=time.monotonic_ns(),status='FAIL' if rc or errors else 'PASS',cleanup_errors=errors,
                    evidence_type='Actual local TCP/kernel experiment; physical two-laptop scope depends on where operator ran it')
        atomic_json(out/'experiment.json',data)
        print(json.dumps(data,indent=2),flush=True)
    return int(data['status']!='PASS')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--interface',default='enp7s0');p.add_argument('--server-ip',default='192.168.77.3')
    p.add_argument('--client-ip',default='192.168.77.2');p.add_argument('--port',type=int,default=9000);p.add_argument('--dashboard-port',type=int,default=8080)
    p.add_argument('--prefix-length',type=int,default=24);p.add_argument('--dashboard-bind',default='127.0.0.1')
    p.add_argument('--model',choices=('original','fresh'),default='original',help='Fresh is always an explicit selection; original remains the rollback default')
    p.add_argument('--mode',choices=('static_q16','layer_specific'),default='static_q16');p.add_argument('--output',type=Path)
    p.add_argument('--dry-run',action='store_true',help='Read-only interface/model preflight; no listener or kernel load')
    p.add_argument('--confirm-interface',help='Explicit operator confirmation; omitted means interactive confirmation after preflight')
    a=p.parse_args()
    if not 1<=a.port<=65535 or not 1<=a.dashboard_port<=65535:p.error('TCP ports must be 1..65535')
    try:
        a.server_ip=str(ipaddress.IPv4Address(a.server_ip));a.client_ip=str(ipaddress.IPv4Address(a.client_ip))
        if not 0<=a.prefix_length<=32 or not ipaddress.IPv4Address(a.dashboard_bind).is_loopback:raise ValueError('Use prefix 0..32 and IPv4 loopback dashboard bind')
        return launch(a)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:print(str(error),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
