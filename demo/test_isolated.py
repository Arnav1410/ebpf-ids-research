#!/usr/bin/env python3
"""Approve --run separately: only fresh owned network namespaces/veth are used."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tc'));sys.dont_write_bytecode=True
from tc.demo import Log,sha,stamp,compare_records
from demo.evaluate import run as evaluate
from argparse import Namespace

NS='idsdemo-server';CLIENT='idsdemo-client';SIF='idsdemo-s0';CIF='idsdemo-c0'


def need(condition,message):
    if not condition:raise RuntimeError(message)


def hashes():
    files=[p for d in ('demo','evaluation','deployment','dashboard','tc','quantization','src') for p in (ROOT/d).rglob('*')
           if p.is_file() and '__pycache__' not in p.parts and (d=='tc' or '.output' not in p.parts) and p.suffix!='.md']
    return {str(p.relative_to(ROOT)):sha(p) for p in files}


def prepare(output):
    output.mkdir(parents=True,exist_ok=False);log=Log(output)
    log.command(['make','-C','tc','layer-specific'],'build')
    log.command([sys.executable,'-m','unittest','-v','evaluation.test_audit','evaluation.test_metrics','demo.test_demo'],'host-tests')
    need(subprocess.run(['git','diff','--quiet','0ba2b2b','--','tc','src','validation','quantization','deployment','dashboard']).returncode==0,'Verified deployment/core changed')
    (output/'manifest.json').write_text(json.dumps(hashes(),indent=2)+'\n')
    print(json.dumps(dict(preparation='PASS',kernel_execution='NOT RUN',
        approval_command=f'sudo /usr/bin/python3 {ROOT/"demo/test_isolated.py"} --run {output}',
        scope='Two inference modes, owned idsdemo-server/client namespaces and veth only; TCP batches 1/10/32; no physical interface'),indent=2))


def wait(path,predicate,process,timeout=20):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if process.poll() is not None:raise RuntimeError('Launcher exited before ready; inspect launcher log')
        try:
            value=json.loads(path.read_text())
            if predicate(value):return value
        except (FileNotFoundError,ValueError):pass
        if time.monotonic()>deadline:break
        time.sleep(.1)
    raise RuntimeError('Timed out: '+str(path))


def run(bundle):
    need(os.geteuid()==0,'Approved sudo invocation required');uid=int(os.environ.get('SUDO_UID','0'));gid=int(os.environ.get('SUDO_GID','0'));need(uid>0,'Use sudo from an ordinary account')
    for p,h in json.loads((bundle/'manifest.json').read_text()).items():need(sha(ROOT/p)==h,'Prepared source changed: '+p)
    out=bundle/('run-'+stamp());out.mkdir();log=Log(out);owned={};processes=[];result=dict(status='FAIL',windows_native='NOT RUN',vm_two_machine='NOT RUN');nonce=uuid.uuid4().hex
    print('Harness evidence: '+str(out),flush=True)
    def ns(argv,name=NS):return ['ip','netns','exec',name,*map(str,argv)]
    def ordinary(argv,name=NS):return ns(['setpriv','--reuid',uid,'--regid',gid,'--clear-groups',*map(str,argv)],name)
    def spawn(argv,name):
        f=(out/(name+'.log')).open('w');p=subprocess.Popen(list(map(str,argv)),stdout=f,stderr=subprocess.STDOUT,cwd=ROOT,start_new_session=True)
        processes.append((p,f));return p
    try:
        existing=log.command(['ip','netns','list']).stdout.splitlines()
        need(not {NS,CLIENT}&{line.split()[0] for line in existing},'Test namespace exists; refusing reuse')
        for name in (NS,CLIENT):log.command(['ip','netns','add',name]);owned[name]=os.stat('/run/netns/'+name).st_ino
        log.command(['ip','-n',NS,'link','add',SIF,'type','veth','peer','name',CIF]);log.command(['ip','-n',NS,'link','set',CIF,'netns',CLIENT])
        for name,iface,ip in ((NS,SIF,'33.33.33.1/24'),(CLIENT,CIF,'33.33.33.73/24')):
            log.command(['ip','-n',name,'link','set',iface,'alias','idsdemo-'+nonce]);log.command(['ip','-n',name,'addr','add',ip,'dev',iface])
            log.command(['ip','-n',name,'link','set',iface,'up']);log.command(['ip','-n',name,'link','set','lo','up'])
        log.command(ordinary(['/usr/bin/python3','-m','unittest','-v','evaluation.test_audit','evaluation.test_metrics','demo.test_demo']),'unprivileged-tests')
        for mode in ('static_q16','layer_specific'):
            work=out/mode;work.mkdir();os.chown(work,uid,gid);experiment=work/'experiment'
            launch=['/usr/bin/python3',ROOT/'demo/launch.py','--interface',SIF,'--server-ip','33.33.33.1','--client-ip','33.33.33.73',
                    '--mode',mode,'--output',experiment,'--confirm-interface',SIF]
            process=spawn(ns(launch),mode+'-launcher');info=wait(experiment/'experiment.json',lambda v:v['status']=='RUNNING',process)
            for count in (1,10,32):
                log.command(ordinary(['/usr/bin/python3',ROOT/'demo/client.py','--input',ROOT/'demo/scenarios.csv','--count',count,'--concurrency',count,
                    '--server-ip','33.33.33.1','--source-ip','33.33.33.73','--experiment-id',info['experiment_id'],'--output',work/('client-'+str(count))],CLIENT),mode+'-client-'+str(count))
                summary=json.loads((work/('client-'+str(count))/'client_summary.json').read_text());need(summary['completed']==count and summary['failed']==0,'Client connection failure')
            process.terminate();need(process.wait(timeout=35)==0,'Launcher failed cleanup')
            info=json.loads((experiment/'experiment.json').read_text());need(info['status']=='PASS','Experiment did not pass')
            raw=json.loads((experiment/'kernel_snapshot.json').read_text());need(len(raw['results'])==43 and raw['stages']==[43]*6,'FIN-trigger or retention lost cases')
            parity=compare_records(raw['results'],mode)
            for count in (1,10,32):
                dest=work/('join-'+str(count));evaluate(Namespace(experiment=experiment,client=work/('client-'+str(count))/'client_results.csv',output=dest,attack_class=1,label_provenance='Paper IV-B3 intended coding; controlled benign demo'))
                joined=json.loads((dest/'evaluation_summary.json').read_text());need(joined['matched_predictions']==count and joined['classification_coverage_all']==1,'Tuple/run matching incomplete')
                need(joined['metrics']['f1'] is None,'Benign-only test invented intrusion F1')
            cleanup=json.loads((experiment/'cleanup.json').read_text());need(cleanup['status']=='PASS','Owned cleanup failed')
            result[mode]=dict(status='PASS',tcp_batches=[1,10,32],retained_predictions=43,numerical=parity,matching='PASS',cleanup='PASS')
        # An occupied application port must cause targeted rollback, leaving the
        # unrelated, test-owned listener alive. No listener is killed by discovery.
        occupied=spawn(ordinary(['/usr/bin/python3','-u','-m','http.server','9000','--bind','33.33.33.1','--directory',ROOT/'deployment/http-root']),'occupied-port')
        deadline=time.monotonic()+8
        while 'Serving HTTP' not in (out/'occupied-port.log').read_text():
            need(occupied.poll() is None and time.monotonic()<deadline,'Owned listener did not start');time.sleep(.1)
        negative=out/'partial-startup'
        bad=spawn(ns(['/usr/bin/python3',ROOT/'demo/launch.py','--interface',SIF,'--server-ip','33.33.33.1','--client-ip','33.33.33.73',
            '--output',negative,'--confirm-interface',SIF]),'partial-startup')
        need(bad.wait(timeout=35)!=0,'Occupied application port unexpectedly accepted')
        info=json.loads((negative/'experiment.json').read_text());need(info['status']=='FAIL' and json.loads((negative/'cleanup.json').read_text())['status']=='PASS','Partial startup rollback failed')
        need(occupied.poll() is None,'Existing listener was killed');result['partial_startup_rollback']='PASS'
        result['status']='PASS'
    except Exception as error:result['error']=str(error)
    finally:
        for p,f in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=35)
                except subprocess.TimeoutExpired:p.kill();p.wait();result['status']='FAIL';result['forced_kill']=True
            f.close()
        errors=[]
        for name,inode in owned.items():
            try:
                need(os.stat('/run/netns/'+name).st_ino==inode,'Namespace ownership changed')
                need(not log.command(['ip','netns','pids',name]).stdout.strip(),'Processes remain in owned namespace')
            except Exception as error:errors.append(str(error))
        if not errors:
            for name in reversed(owned):log.command(['ip','netns','delete',name])
        result['namespace_cleanup']='FAIL' if errors else 'PASS'
        if errors:result.update(status='FAIL',cleanup_errors=errors)
        (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
        (out/'REPORT.md').write_text('# Isolated final harness\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n')
        print(json.dumps(result,indent=2));print('Report: '+str(out/'REPORT.md'))
    return int(result['status']!='PASS')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--prepare',action='store_true');g.add_argument('--run',type=Path)
    p.add_argument('--output',type=Path);a=p.parse_args()
    if a.prepare:
        need(a.output is not None,'New output directory required');prepare(a.output.resolve())
    else:raise SystemExit(run(a.run.resolve()))
