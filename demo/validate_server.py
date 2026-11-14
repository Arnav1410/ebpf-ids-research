#!/usr/bin/env python3
"""Gated verification: private kernel model pilot, then owned namespace demo.

No physical interface is selected. Each privileged phase is invoked manually.
"""
import argparse
from argparse import Namespace
import gzip
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from deployment.ids import Controller,paths,tc_state
from deployment.model_config import model_spec,reference,verify_loaded,sha
from deployment.test_isolated import address_configuration
from demo.evaluate import run as evaluate
from tc.demo import Log,stamp,verify_private_ids
from validation.reference import STAGES

NS='idsfresh-server';CLIENT='idsfresh-client';SIF='idsfresh-s0';CIF='idsfresh-c0'


def need(value,message):
    if not value:raise RuntimeError(message)


def read(path):return json.loads(Path(path).read_text())
def write(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')


def sources():
    found=[]
    for directory in ('demo','deployment','dashboard','tc','src','validation','quantization'):
        found.extend(p for p in (ROOT/directory).rglob('*') if p.is_file()
                     and '.output' not in p.parts and '__pycache__' not in p.parts
                     and p.suffix not in ('.log','.md'))
    found.extend(ROOT/'tc/.output'/n for n in ('controller','controller_layer','controller_fresh','controller_fresh_layer','tc_ids.bpf.o','tc_ids_layer.bpf.o','tc_min.bpf.o'))
    return {str(p.relative_to(ROOT)):sha(p) for p in sorted(set(found))}


def prepare(directory):
    directory.mkdir(parents=True,exist_ok=False);log=Log(directory)
    log.command(['make','-C','tc','-B','demo-models'],'build')
    log.command([sys.executable,'-B','-m','unittest','-v','demo.test_demo','demo.test_final_server','deployment.tests.test_dashboard'],'host-tests')
    for model in ('original','fresh'):
        for mode in ('static_q16','layer_specific'):
            ctl,obj=paths(mode,model);target=directory/(model+'-'+mode);target.mkdir()
            log.command([ctl,'--inspect',obj,target],'inspect-'+model+'-'+mode)
            write(target/'model-identity.json',model_spec(model,mode))
    write(directory/'manifest.json',sources())
    print(json.dumps(dict(preparation='PASS',kernel_execution='NOT RUN',network_execution='NOT RUN',
        pilot_command=f'sudo /usr/bin/python3 {ROOT/"demo/validate_server.py"} --pilot {directory}',
        scope='Fresh 100-vector six-stage pilot first; no attachment or network change'),indent=2))


def checked(directory):
    for name,digest in read(directory/'manifest.json').items():need(sha(ROOT/name)==digest,'Prepared runtime changed: '+name)


def protected(directory):
    for name,digest in read(ROOT/'verification-logs/fresh-live-demo-20261108/protected.json').items():
        need(sha(ROOT/name)==digest,'Protected model/benchmark changed: '+name)


def pilot_compatibility(directory,pilot_evidence):
    """Explicit test-only edits can reuse evidence for identical runtime bytes."""
    proof=read(pilot_evidence/'results.json');old_path=pilot_evidence.parent/'manifest.json'
    need(proof['status']=='PASS' and proof['gate']=='FRESH MODEL KERNEL PILOT'
         and proof['manifest_sha256']==sha(old_path),'Unverified pilot evidence/manifest')
    old=read(old_path);current=read(directory/'manifest.json')
    need(set(old)==set(current),'Pilot/runtime file sets differ')
    changed={p for p in old if old[p]!=current[p]}
    need(changed.issubset({'demo/validate_server.py','tc/tests/test_tc.py'}),'Kernel/model/deployment inputs differ from passed pilot: '+str(sorted(changed)))
    return dict(status='PASS',pilot=str(pilot_evidence),pilot_manifest_sha256=sha(old_path),
                current_manifest_sha256=sha(directory/'manifest.json'),
                test_driver_changes_only=sorted(changed),unchanged_files=len(old)-len(changed))


def prepare_network(directory,pilot_evidence):
    directory.mkdir(parents=True,exist_ok=False);log=Log(directory)
    for mode in ('static_q16','layer_specific'):
        log.command([ROOT/'run-tc-smoke.sh','--prepare','--phase2','--mode',mode,
                     '--output',directory/('original-regression-'+mode)],'prepare-regression-'+mode)
        need(read(directory/('original-regression-'+mode)/'results.json')['preparation']=='PASS','Regression preparation failed')
    write(directory/'manifest.json',sources())
    compatibility=pilot_compatibility(directory,pilot_evidence);protected(directory)
    write(directory/'pilot-compatibility.json',compatibility)
    print(json.dumps(dict(preparation='PASS',network='NOT RUN',pilot_compatibility=compatibility,
        command=f'sudo /usr/bin/python3 {ROOT/"demo/validate_server.py"} --network {directory} --pilot-evidence {pilot_evidence}'),indent=2))


def authorized():
    need(os.geteuid()==0,'Manually invoke this phase with sudo after review')
    uid=int(os.environ.get('SUDO_UID','0'));gid=int(os.environ.get('SUDO_GID','0'))
    need(uid>0,'Invoke sudo from an ordinary account; web/application children must be unprivileged')
    return uid,gid


def new_run(directory,phase):
    checked(directory);out=directory/(phase+'-'+stamp());out.mkdir();print('Final demo evidence: '+str(out),flush=True)
    return out,Log(out)


class PilotController(Controller):
    def __init__(self,log,directory,mode):
        self.directory=directory;directory.mkdir();self.events=[];self.pending=b''
        self.stderr=(directory/'controller.log').open('w');ctl,obj=paths(mode,'fresh')
        argv=list(map(str,[ctl,'--benchmark-kernel',obj,directory]));write(directory/'command.json',argv)
        self.proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,bufsize=0,start_new_session=True)


def pilot(directory):
    authorized();out,log=new_run(directory,'pilot')
    result=dict(status='FAIL',gate='FRESH MODEL KERNEL PILOT',network_attachments=False,
                kernel=platform.release(),manifest_sha256=sha(directory/'manifest.json'))
    try:
        fixtures=[json.loads(s) for s in (ROOT/'deployment/models/fresh/pilot.jsonl').read_text().splitlines()]
        need(len(fixtures)==100,'Pilot must use the frozen 100 held-out vectors')
        cpu=min(os.sched_getaffinity(0));result['cpu']=cpu
        for mode in ('static_q16','layer_specific'):
            controller=PilotController(log,out/mode,mode);checks=0
            try:
                controller.read('benchmark_ready');identity=verify_loaded(controller.directory,'fresh',mode)
                ref=reference('fresh',mode)
                # Same vector three times, freshly seeded by the existing driver.
                cases=[(fixtures[0],1,2)]+[(c,0,1) for c in fixtures]
                for case,warm,samples in cases:
                    tensors,label=ref.infer(case['features'],[])
                    want=case['expected'][mode]
                    need(want['tensors']==tensors and want['prediction']==label,'Packaged pilot reference changed')
                    line=' '.join(map(str,['measure',cpu,0,warm,samples,*case['features']]))+'\n'
                    controller.proc.stdin.write(line.encode());controller.proc.stdin.flush();b=controller.read('benchmark_block')
                    calls=warm+samples;record=b['record']
                    need(b['prediction_delta']==calls and b['stage_deltas']==[calls]*6,'Incomplete or reused inference')
                    need(record['features']==case['features'] and record['mask']==63 and record['model_slot']==0,'Wrong snapshot/model slot')
                    need(record['label']==label and record['tensors']==[tensors[s] for s in STAGES],'Kernel/reference mismatch')
                    checks+=calls
                need(checks==103,'Wrong pilot execution count')
                result[mode]=dict(status='PASS',vectors=100,kernel_calls=checks,stages=[checks]*6,
                                  numerical_mismatches=0,model_identity=identity)
            finally:
                controller.stop();loaded=next((e for e in controller.events if e['event']=='loaded'),None)
                if loaded:verify_private_ids(log,controller.directory,loaded)
            print(mode+': 100 vectors, 103 fresh six-stage executions and model readbacks PASS',flush=True)
        protected(directory);result.update(status='PASS',cleanup='PASS',kernel_calls=206)
    except Exception as error:result['error']=str(error)
    write(out/'results.json',result);print(json.dumps(result,indent=2))
    return int(result['status']!='PASS')


def wait(path,predicate,process,seconds=30):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        need(process.poll() is None,'Launcher exited; inspect its log')
        try:
            v=read(path)
            if predicate(v):return v
        except (FileNotFoundError,ValueError):pass
        time.sleep(.1)
    raise RuntimeError('Readiness timed out: '+str(path))


def network(directory,pilot_evidence):
    uid,gid=authorized();compatibility=pilot_compatibility(directory,pilot_evidence)
    out,log=new_run(directory,'network');owned={};processes=[];nonce=uuid.uuid4().hex
    result=dict(status='FAIL',physical_two_laptop='NOT RUN',windows_python_313='NOT RUN',pilot=str(pilot_evidence),pilot_compatibility=compatibility)
    def ns(argv,name=NS):return ['ip','netns','exec',name,*map(str,argv)]
    def ordinary(argv,name=NS):return ns(['setpriv','--reuid',uid,'--regid',gid,'--clear-groups',*argv],name)
    def spawn(argv,name):
        f=(out/(name+'.log')).open('w');p=subprocess.Popen(list(map(str,argv)),stdout=f,stderr=subprocess.STDOUT,cwd=ROOT,start_new_session=True)
        processes.append((p,f));return p
    try:
        # Existing original-model numerical/concurrency/network regressions.
        for mode in ('static_q16','layer_specific'):
            target=directory/('original-regression-'+mode)
            log.command([ROOT/'run-tc-smoke.sh','--run',target,'--phase2','--mode',mode],'regression-'+mode)
            summary=read(sorted(target.glob('run-*/results.json'))[-1])
            need(summary['phase2_gate']=='PASS' and summary['cleanup']=='PASS','Original-model regression failed')
            result['original_'+mode+'_regression']='PASS'
        existing=log.command(['ip','netns','list']).stdout.splitlines()
        need(not {NS,CLIENT}&{x.split()[0] for x in existing},'Owned test namespace names already exist; refusing reuse')
        for name in (NS,CLIENT):log.command(['ip','netns','add',name]);owned[name]=os.stat('/run/netns/'+name).st_ino
        log.command(['ip','-n',NS,'link','add',SIF,'type','veth','peer','name',CIF]);log.command(['ip','-n',NS,'link','set',CIF,'netns',CLIENT])
        for name,iface,address in ((NS,SIF,'33.33.33.1/24'),(CLIENT,CIF,'33.33.33.73/24')):
            log.command(['ip','-n',name,'link','set',iface,'alias','idsfresh-'+nonce]);log.command(['ip','-n',name,'addr','add',address,'dev',iface])
            log.command(['ip','-n',name,'link','set',iface,'up']);log.command(['ip','-n',name,'link','set','lo','up'])
        before_addresses=address_configuration(log.command(['ip','-n',NS,'-j','addr','show','dev',SIF]).stdout)
        before_routes=log.command(['ip','-n',NS,'-j','route','show']).stdout
        log.command(ordinary(['/usr/bin/python3','-B','-m','unittest','-v','demo.test_demo','demo.test_final_server','deployment.tests.test_dashboard']),'unprivileged-tests')
        runs=[('fresh','static_q16',80),('fresh','static_q16',9000),('fresh','layer_specific',80),('fresh','layer_specific',9000),('original','static_q16',9000)]
        for model,mode,port in runs:
            name=f'{model}-{mode}-{port}';work=out/name;work.mkdir();os.chown(work,uid,gid);experiment=work/'experiment'
            argv=[ROOT/'demo/start_server.sh','--interface',SIF,'--server-ip','33.33.33.1','--prefix-length','24',
                  '--client-ip','33.33.33.73','--model',model,'--mode',mode,'--port',port,'--dashboard-port','8080',
                  '--confirm-interface',SIF,'--output',experiment]
            process=spawn(ns(argv),name);info=wait(experiment/'experiment.json',lambda v:v['status']=='RUNNING',process)
            need(info['model_identity']['kernel_readback']=='PASS' and info['model']==model and info['port']==port,'Incorrect operational model/port')
            for count in (1,10):
                log.command(ordinary(['/usr/bin/python3','-B',ROOT/'demo/client.py','--input',ROOT/'demo/scenarios-reproduction-informed.csv',
                    '--count',count,'--concurrency',count,'--server-ip','33.33.33.1','--source-ip','33.33.33.73',
                    '--port',port,'--experiment-id',info['experiment_id'],'--output',work/f'client-{count}'],CLIENT),name+f'-client-{count}')
                need(read(work/f'client-{count}/client_summary.json')['completed']==count,'TCP connection/acknowledgement failure')
            live=read(Path(info['state_dir'])/'telemetry.json')
            if live['aggregate']['predictions']!=11:
                time.sleep(.5);live=read(Path(info['state_dir'])/'telemetry.json')
            api=log.command(ordinary(['/usr/bin/python3','-B','-c',
                "import json; from demo.launch import dashboard_state; print(json.dumps(dashboard_state('127.0.0.1',8080)))"]),name+'-live-http-api')
            live=json.loads(api.stdout)
            need(live['status']=='CONNECTED' and live['model']==model and live['application_port']==port,'Incorrect live dashboard state')
            need(len(live['flows'])==11 and len({f['client_port'] for f in live['flows']})==11,'Flows mixed or lost')
            need(all(f['server_port']==port and f['state']=='DONE' and f['features'] and f['hooks']['ingress']['packets']>0
                     and f['hooks']['egress']['packets']>0 for f in live['flows']),'Directional/feature records incomplete')
            write(work/'live-telemetry.json',live)
            # Deliberate foreign test filter added AFTER attach must survive stop.
            log.command(ns(['tc','filter','add','dev',SIF,'egress','pref','12345','protocol','all','matchall','action','pass']))
            process.terminate();need(process.wait(timeout=40)==0,'Launcher cleanup failed')
            info=read(experiment/'experiment.json');raw=read(experiment/'kernel_snapshot.json')
            need(info['status']=='PASS' and len(raw['results'])==11 and raw['stages']==[11]*6,'Inference count/chain failure')
            need(all(raw[k]==0 for k in ('tail_failures','inference_failures','workspace_busy','flow_full','result_failures')),'Unexpected kernel diagnostic')
            ref=reference(model,mode)
            for record in raw['results']:
                events=[];t,y=ref.infer(record['features'],events)
                need(not events and record['mask']==63 and record['label']==y and record['tensors']==[t[s] for s in STAGES],'Live kernel/reference parity failed')
            for count in (1,10):
                dest=work/f'join-{count}'
                evaluate(Namespace(experiment=experiment,client=work/f'client-{count}/client_results.csv',output=dest,
                                   attack_class=1,label_provenance='Ordinary bounded benign TCP; no intrusion F1 claimed'))
                need(read(dest/'evaluation_summary.json')['matched_predictions']==count,'Tuple/experiment matching failed')
            records=[json.loads(v) for v in (experiment/'server_classifications.jsonl').read_text().splitlines()]
            need(len(records)==11 and all(v['model']==model and v['experiment_id']==info['experiment_id'] and v['application_port']==port for v in records),'Classification logging metadata mismatch')
            after=json.loads(log.command(ns(['tc','-j','filter','show','dev',SIF,'egress'])).stdout)
            need(any(v['pref']==12345 and v['kind']=='matchall' for v in after),'Foreign filter lost')
            need(read(experiment/'cleanup.json')['status']=='PASS','Owned-ID cleanup failed')
            log.command(ns(['tc','filter','del','dev',SIF,'egress','pref','12345','protocol','all']))
            result[name]=dict(status='PASS',connections=11,port=port,predictions=11,stages=raw['stages'],
                             packets=raw['packets'],egress_packets=raw['egress_packets'],model_identity=info['model_identity'],
                             numerical_tensors=66,numerical_integers=1496,foreign_filter_preserved='PASS',cleanup='PASS')
            print(name+': real listener, 1/10 connections, LIVE dashboard, six-stage parity and cleanup PASS',flush=True)
        # Occupied application/dashboard ports are refused BEFORE BPF load.
        for occupied_port,app_port,dashboard_port in ((9000,9000,8080),(8080,9000,8080)):
            other=spawn(ordinary(['/usr/bin/python3','-B','-u','-m','http.server',occupied_port,'--bind','0.0.0.0','--directory',ROOT/'deployment/http-root']),f'occupied-{occupied_port}')
            deadline=time.monotonic()+5
            while 'Serving HTTP' not in (out/f'occupied-{occupied_port}.log').read_text():
                need(other.poll() is None and time.monotonic()<deadline,'Conflict fixture failed');time.sleep(.1)
            failure=out/f'conflict-{occupied_port}'
            bad=spawn(ns([ROOT/'demo/start_server.sh','--interface',SIF,'--server-ip','33.33.33.1','--client-ip','33.33.33.73',
                          '--model','fresh','--port',app_port,'--dashboard-port',dashboard_port,'--confirm-interface',SIF,'--output',failure]),f'conflict-{occupied_port}')
            need(bad.wait(timeout=20)!=0 and other.poll() is None,'Port conflict was ignored or foreign service terminated')
            need(read(failure/'cleanup.json')['status']=='PASS' and not (Path(read(failure/'experiment.json')['state_dir'])).exists(),'Conflict loaded BPF or left runtime')
            other.terminate();other.wait(timeout=10)
        result['occupied_port_refusal']='PASS'
        need(address_configuration(log.command(['ip','-n',NS,'-j','addr','show','dev',SIF]).stdout)==before_addresses,'Addresses changed')
        need(log.command(['ip','-n',NS,'-j','route','show']).stdout==before_routes,'Routes changed')
        protected(directory);result.update(status='PASS',address_and_route_preservation='PASS')
    except Exception as error:result['error']=str(error)
    finally:
        errors=[]
        for process,stream in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=40)
                except subprocess.TimeoutExpired:process.kill();process.wait();errors.append('Owned child required SIGKILL')
            stream.close()
        for name,inode in owned.items():
            try:
                need(os.stat('/run/netns/'+name).st_ino==inode,'Namespace ownership changed')
                need(not log.command(['ip','netns','pids',name]).stdout.strip(),'Processes remain in test namespace')
            except Exception as error:errors.append(str(error))
        if not errors:
            for name in reversed(owned):log.command(['ip','netns','delete',name])
        result['namespace_cleanup']='FAIL' if errors else 'PASS'
        if errors:result.update(status='FAIL',cleanup_errors=errors)
        write(out/'results.json',result);(out/'REPORT.md').write_text('# Isolated fresh-model demo\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n')
        print(json.dumps(result,indent=2));print('Report: '+str(out/'REPORT.md'))
    return int(result['status']!='PASS')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',type=Path);g.add_argument('--pilot',type=Path);g.add_argument('--network',type=Path);g.add_argument('--prepare-network',type=Path)
    p.add_argument('--pilot-evidence',type=Path);a=p.parse_args()
    if a.prepare:prepare(a.prepare.resolve())
    elif a.pilot:raise SystemExit(pilot(a.pilot.resolve()))
    elif a.prepare_network:
        need(a.pilot_evidence is not None,'--pilot-evidence is required')
        prepare_network(a.prepare_network.resolve(),a.pilot_evidence.resolve())
    else:
        need(a.pilot_evidence is not None,'--pilot-evidence is required')
        raise SystemExit(network(a.network.resolve(),a.pilot_evidence.resolve()))
