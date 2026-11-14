#!/usr/bin/env python3
"""Prepare without privilege; operator-approved kernel/network tests use veth only."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import shutil
import socket
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tc'))
from tc.demo import Log,sha,stamp,compare_records
from deployment.ids import tc_state,paths,owns_filter,HANDLE,PRIORITY

SERVER='idsdep-server';CLIENT='idsdep-client';SIF='idsdep-s0';CIF='idsdep-c0'


def need(value,message):
    if not value:raise RuntimeError(message)


def address_configuration(value):
    """Configured identities, not expiring lifetimes, DAD or carrier status."""
    links=json.loads(value) if isinstance(value,str) else value
    result=[]
    for link in links:
        addresses=[{k:a[k] for k in ('family','local','address','prefixlen','scope','label','broadcast','peer') if k in a}
                   for a in link.get('addr_info',[])]
        result.append(dict(ifindex=link['ifindex'],ifname=link['ifname'],mtu=link['mtu'],mac=link.get('address'),
                           admin_up='UP' in link.get('flags',[]),addresses=sorted(addresses,key=lambda a:json.dumps(a,sort_keys=True))))
    return result


def sources():
    p=[p for d in ('deployment','dashboard','tc','quantization') for p in (ROOT/d).rglob('*')
       if p.is_file() and '__pycache__' not in p.parts and (d=='tc' or '.output' not in p.parts) and p.suffix!='.md']
    p += [ROOT/'run-tc-smoke.sh']
    return {str(f.relative_to(ROOT)):sha(f) for f in p}


def verified_regressions(bundle):
    verified={}
    for mode in ('static_q16','layer_specific'):
        prepared=bundle/('regression-'+mode)
        manifest=json.loads((prepared/'manifest.json').read_text())
        for group in ('protected','prototype'):
            for path,digest in manifest[group].items():need(sha(ROOT/path)==digest,'Prior regression source changed: '+path)
        candidates=sorted(prepared.glob('run-*/results.json'))
        need(candidates,'No prior kernel regression evidence')
        last=candidates[-1];result=json.loads(last.read_text())
        need(result.get('phase2_gate')=='PASS' and result.get('cleanup')=='PASS','Prior regression did not pass')
        verified[mode]=str(last)
    return verified


def prepare(output,reuse=None):
    output.mkdir(parents=True,exist_ok=False);log=Log(output)
    log.command(['make','-C','tc','layer-specific'],'build')
    log.command([sys.executable,'-m','unittest','-v','deployment.tests.test_dashboard'],'unit-tests')
    if reuse:
        (output/'verified-regressions.json').write_text(json.dumps(dict(bundle=str(reuse),results=verified_regressions(reuse)),indent=2)+'\n')
    else:
        for mode in ('static_q16','layer_specific'):
            log.command(['./run-tc-smoke.sh','--prepare','--phase2','--mode',mode,'--output',output/('regression-'+mode)],'prepare-'+mode)
    (output/'manifest.json').write_text(json.dumps(sources(),indent=2)+'\n')
    print(json.dumps(dict(preparation='PASS',kernel='NOT RUN',deployment='PENDING USER EXECUTION',
        command=f'sudo /usr/bin/python3 {ROOT/"deployment/test_isolated.py"} --run {output}',
        scope='Original two-mode namespace regressions, then dedicated veth deployment/collector/unprivileged dashboard; never a physical interface'),indent=2))


def wait_file(path,predicate,timeout=20):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            value=json.loads(path.read_text())
            if predicate(value):return value
        except (FileNotFoundError,ValueError):pass
        time.sleep(.1)
    raise RuntimeError('Timed out waiting for '+str(path))


def client(port,count):
    def exchange(i):
        with socket.socket() as s:
            s.settimeout(10);s.bind(('33.33.33.73',port+i));s.connect(('33.33.33.1',8000))
            s.sendall(b'GET / HTTP/1.0\r\nHost: ids-demo\r\nConnection: close\r\n\r\n');s.shutdown(socket.SHUT_WR)
            data=b''
            while True:
                chunk=s.recv(4096)
                if not chunk:break
                data+=chunk;need(len(data)<1024*1024,'Unexpected response size')
            need(data.startswith(b'HTTP/1.0 200'),'HTTP request failed')
            return dict(source_port=port+i,status=200,response_bytes=len(data))
    with ThreadPoolExecutor(max_workers=count) as pool:print(json.dumps(list(pool.map(exchange,range(count)))))


def run(bundle):
    need(os.geteuid()==0,'Run approved command using sudo from a normal user')
    uid=int(os.environ.get('SUDO_UID','0'));gid=int(os.environ.get('SUDO_GID','0'))
    need(uid>0,'SUDO_UID required to run the HTTP dashboard without root')
    for p,digest in json.loads((bundle/'manifest.json').read_text()).items():need(sha(ROOT/p)==digest,'Prepared source changed: '+p)
    out=bundle/('run-'+stamp());out.mkdir();log=Log(out);result=dict(status='FAIL',native_linux='NOT RUN',two_laptop='NOT RUN')
    print('Deployment evidence: '+str(out),flush=True)
    processes=[];owned={};owner=uuid.uuid4().hex;runtime=Path('/run')/('idsdep-'+owner[:12]);runtime_inode=None
    def ns(argv):return ['ip','netns','exec',SERVER,*map(str,argv)]
    def popen(argv,name):
        stream=(out/(name+'.log')).open('w');p=subprocess.Popen(list(map(str,argv)),stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append((p,stream));return p
    try:
        if (bundle/'verified-regressions.json').exists():
            saved=json.loads((bundle/'verified-regressions.json').read_text())
            result['reused_verified_regressions']=verified_regressions(Path(saved['bundle']))
        else:
            for mode in ('static_q16','layer_specific'):
                log.command(['./run-tc-smoke.sh','--run',bundle/('regression-'+mode),'--phase2','--mode',mode],'regression-'+mode)
        for mode in ('static_q16','layer_specific'):result[mode+'_regression']='PASS'
        listed=log.command(['ip','netns','list'],'namespaces-before').stdout
        need(not any(n in [line.split()[0] for line in listed.splitlines()] for n in (SERVER,CLIENT)),'Test namespace already exists')
        for name in (SERVER,CLIENT):
            log.command(['ip','netns','add',name]);owned[name]=os.stat('/run/netns/'+name).st_ino
        log.command(['ip','-n',SERVER,'link','add',SIF,'type','veth','peer','name',CIF])
        log.command(['ip','-n',SERVER,'link','set',CIF,'netns',CLIENT])
        for name,iface,address in ((SERVER,SIF,'33.33.33.1/24'),(CLIENT,CIF,'33.33.33.73/24')):
            log.command(['ip','-n',name,'link','set',iface,'alias','idsdep-'+owner])
            log.command(['ip','-n',name,'addr','add',address,'dev',iface]);log.command(['ip','-n',name,'link','set',iface,'up'])
            log.command(['ip','-n',name,'link','set','lo','up'])
        address_before=log.command(['ip','-n',SERVER,'-j','addr','show','dev',SIF],'address-before').stdout
        routes_before=log.command(['ip','-n',SERVER,'-j','route','show'],'routes-before').stdout
        runtime.mkdir(mode=0o755);runtime_inode=runtime.stat().st_ino
        log.command(ns(['setpriv','--reuid',uid,'--regid',gid,'--clear-groups','/usr/bin/python3','-m','unittest','-v',
                        'deployment.tests.test_dashboard']),'unprivileged-dashboard-tests')
        http=popen(ns(['/usr/bin/python3','-u','-m','http.server','8000','--bind','33.33.33.1','--directory',ROOT/'deployment/http-root']),'http-service')
        deadline=time.monotonic()+8
        while 'Serving HTTP' not in (out/'http-service.log').read_text():
            need(http.poll() is None and time.monotonic()<deadline,'HTTP service did not start');time.sleep(.1)
        for mode in ('static_q16','layer_specific'):
            state=runtime/mode;preflight=ns(['/usr/bin/python3',ROOT/'deployment/ids.py','preflight','--interface',SIF,'--mode',mode])
            log.command(preflight,'preflight-'+mode)
            log.command(ns(['/usr/bin/python3',ROOT/'deployment/ids.py','start','--interface',SIF,'--mode',mode,'--dry-run']),'dry-run-'+mode)
            collector=popen(ns(['/usr/bin/python3',ROOT/'deployment/ids.py','start','--interface',SIF,'--mode',mode,
                               '--client-ip','33.33.33.73','--state-dir',state,'--interval','.2']),'collector-'+mode)
            initial=wait_file(state/'telemetry.json',lambda v:v['status']=='CONNECTED')
            need(initial['aggregate']['tracked_flows']==0,'Fresh deployment should have zero flows')
            dash=popen(ns(['setpriv','--reuid',uid,'--regid',gid,'--clear-groups','/usr/bin/python3',ROOT/'dashboard/server.py',
                           '--state',state/'telemetry.json','--port','8080']),'dashboard-'+mode)
            deadline=time.monotonic()+8
            while 'Read-only dashboard:' not in (out/('dashboard-'+mode+'.log')).read_text():
                need(dash.poll() is None and time.monotonic()<deadline,'Unprivileged dashboard did not start');time.sleep(.1)
            base=51000 if mode=='static_q16' else 55000
            for count,port in ((1,base),(10,base+100)):
                log.command(['ip','netns','exec',CLIENT,'/usr/bin/python3',ROOT/'deployment/test_isolated.py','--client',str(port),str(count)],mode+'-http-'+str(count))
                expected=1 if count==1 else 11
                value=wait_file(state/'telemetry.json',lambda v:v.get('aggregate',{}).get('completed_results')==expected)
                need(value['aggregate']['tracked_flows']==expected,'Connections merged or extra flow')
                need(all(f['hooks']['ingress']['packets']>0 and f['hooks']['egress']['packets']>0 and f['state']=='DONE' for f in value['flows']),'Missing directional flow or inference')
                need(all(f['client_ip']=='33.33.33.73' and f['server_port']==8000 for f in value['flows']),'Wrong physical-mode client/port semantics')
                (out/(mode+'-'+str(count)+'-telemetry.json')).write_text(json.dumps(value,indent=2)+'\n')
            log.command(ns(['/usr/bin/python3',ROOT/'deployment/ids.py','status','--interface',SIF,'--state-dir',state]),'status-'+mode)
            raw=json.loads(log.command(ns(['/usr/bin/python3',ROOT/'deployment/ids.py','snapshot','--interface',SIF,'--state-dir',state]),'map-snapshot-'+mode).stdout)
            parity=compare_records(raw['results'],mode)
            records=[json.loads(s) for s in (state/'classifications.jsonl').read_text().splitlines()]
            need(len(records)==11 and len({r['flow_id'] for r in records})==11,'Prediction log lost or duplicated connections')
            api=log.command(ns(['/usr/bin/python3','-c','import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8080/api/state",timeout=5).read().decode())']),'dashboard-api-'+mode)
            api_state=json.loads(api.stdout);need(api_state['source']=='LIVE' and len(api_state['flows'])==11,'Dashboard not displaying actual collector')
            uid_status=Path('/proc')/str(dash.pid)/'status'
            need(int(next(line for line in uid_status.read_text().splitlines() if line.startswith('Uid:')).split()[1])==uid,'HTTP dashboard is privileged')
            # Add one test-owned unrelated classifier AFTER measurements; it must
            # survive owned IDS cleanup and cause the next deployment to refuse.
            log.command(ns(['tc','filter','add','dev',SIF,'egress','pref','12345','protocol','all','matchall','action','pass']),mode+'-foreign-add')
            log.command(ns(['/usr/bin/python3',ROOT/'deployment/ids.py','stop','--interface',SIF,'--state-dir',state]),'stop-'+mode)
            need(collector.wait(timeout=10)==0,'Collector cleanup failed')
            dash.terminate();dash.wait(timeout=5)
            cleanup=json.loads((state/'cleanup.json').read_text());need(cleanup['status']=='PASS','Deployment cleanup failure')
            need(any(f.get('pref')==12345 for f in cleanup['after']['egress']),'Foreign classifier was removed')
            rejected=log.command(preflight,mode+'-foreign-preflight',check=False);need(rejected.returncode!=0,'Occupied hook accepted')
            reject_dir=out/(mode+'-direct-conflict');reject_dir.mkdir()
            rejected=log.command(ns([paths(mode)[0],'--deploy',paths(mode)[1],SIF,reject_dir]),mode+'-direct-refusal',check=False)
            need(rejected.returncode!=0,'Direct controller accepted foreign hook')
            log.command(ns(['tc','filter','del','dev',SIF,'egress','pref','12345','protocol','all']),mode+'-foreign-remove')
            # A new TCP connection still completes after detachment.
            log.command(['ip','netns','exec',CLIENT,'/usr/bin/python3',ROOT/'deployment/test_isolated.py','--client',str(base+200),'1'],mode+'-post-detach-http')
            result[mode+'_deployment']=dict(status='PASS',flows=11,predictions=11,logits_reference='PASS',
                 tensors_reference=parity,dashboard='PASS actual LIVE HTTP API; unprivileged process',foreign_filter_preserved='PASS',cleanup='PASS')
        address_after=log.command(['ip','-n',SERVER,'-j','addr','show','dev',SIF],'address-after').stdout
        need(address_configuration(address_after)==address_configuration(address_before),'Address configuration changed')
        need(log.command(['ip','-n',SERVER,'-j','route','show'],'routes-after').stdout==routes_before,'Routes changed')
        result['address_and_route_preservation']='PASS';result['unprivileged_http_endpoint_tests']='PASS'
        result['status']='PASS'
    except Exception as error:result['error']=str(error)
    finally:
        for p,stream in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=15)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            stream.close()
        errors=[]
        if runtime_inode is not None:
            try:
                need(runtime.stat().st_ino==runtime_inode and runtime.stat().st_uid==0,'Runtime directory ownership changed')
                for mode in ('static_q16','layer_specific'):
                    if (runtime/mode).exists():shutil.copytree(runtime/mode,out/mode,ignore=shutil.ignore_patterns('control.sock'))
                shutil.rmtree(runtime)
            except Exception as error:errors.append(str(error))
        verified=[]
        for name in owned:
            try:
                need(os.stat('/run/netns/'+name).st_ino==owned[name],'Namespace ownership changed')
                need(not log.command(['ip','netns','pids',name]).stdout.strip(),'Processes remain in owned namespace')
                verified.append(name)
            except Exception as error:errors.append(str(error))
        if len(verified)==len(owned):
            for name in reversed(verified):
                try:log.command(['ip','netns','delete',name])
                except Exception as error:errors.append(str(error))
        result['namespace_cleanup']='FAIL' if errors else 'PASS'
        if errors:result['status']='FAIL';result['cleanup_errors']=errors
        (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
        (out/'REPORT.md').write_text('# Isolated deployment validation\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n')
        print(json.dumps(result,indent=2));print('Report: '+str(out/'REPORT.md'))
    return int(result['status']!='PASS')


def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',action='store_true');g.add_argument('--run',type=Path);g.add_argument('--client',nargs=2,type=int)
    p.add_argument('--output',type=Path);p.add_argument('--reuse-regressions',type=Path);args=p.parse_args()
    if args.client:
        need(1<=args.client[1]<=10,'Only bounded test clients supported');client(*args.client);return 0
    if args.prepare:
        need(args.output is not None,'New --output path required');prepare(args.output.resolve(),args.reuse_regressions.resolve() if args.reuse_regressions else None);return 0
    return run(args.run.resolve())


if __name__=='__main__':raise SystemExit(main())
