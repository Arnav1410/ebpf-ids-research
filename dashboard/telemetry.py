"""Decode controller snapshots, retain every immutable result, never read payloads."""
from collections import deque
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import time
import tempfile

CAPACITY=8192
COUNTERS=('packets','bytes','egress_packets','egress_bytes','predictions','inference_failures',
          'tail_failures','result_failures','flow_full','workspace_busy','timestamp_reorders')


def flow_id(key):
    return f"{key['protocol']}|{key['a_ip']}:{key['a_port']}|{key['b_ip']}:{key['b_port']}"


def json_safe(value):
    # Browsers cannot exactly represent all u64 counters/helper timestamps.
    if type(value) is int and abs(value)>2**53-1:return str(value)
    if isinstance(value,dict):return {k:json_safe(v) for k,v in value.items()}
    if isinstance(value,list):return [json_safe(v) for v in value]
    return value


def atomic_json(path,value):
    path=Path(path);fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',suffix='.tmp',dir=path.parent);tmp=Path(name)
    try:
        os.fchmod(fd,0o644)
        with os.fdopen(fd,'w') as f:
            json.dump(json_safe(value),f,separators=(',',':'));f.write('\n');f.flush()
        os.replace(tmp,path)
    finally:
        if tmp.exists():tmp.unlink()


class RotatingLog:
    def __init__(self,path,limit=2*1024*1024,backups=3):
        self.path=Path(path);self.limit=limit;self.backups=backups

    def append(self,record):
        data=(json.dumps(record,separators=(',',':'))+'\n').encode()
        if self.path.exists() and self.path.stat().st_size+len(data)>self.limit:
            for i in range(self.backups,0,-1):
                source=self.path if i==1 else self.path.with_name(self.path.name+f'.{i-1}')
                target=self.path.with_name(self.path.name+f'.{i}')
                if source.exists():os.replace(source,target)
        fd=os.open(self.path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'ab') as f:f.write(data)


class Collector:
    def __init__(self,interface,mode,session,log,server_ips=(),model_identity=None,application_port=None,experiment_id=None):
        self.interface=interface;self.mode=mode;self.session=session;self.log=log
        self.model_identity=model_identity
        self.model=model_identity['model'] if model_identity else 'original'
        self.logit_q=model_identity['logit_q'] if model_identity else (18 if mode=='layer_specific' else 16)
        self.application_port=application_port;self.experiment_id=experiment_id
        self.server_ips=set(server_ips);self.seen=set();self.recent=deque(maxlen=50)

    def update(self,snapshot,hooks,now=None):
        now=time.time() if now is None else now
        if snapshot.get('event')!='snapshot' or snapshot.get('inference_mode')!=self.mode:
            raise ValueError('Wrong controller snapshot or inference mode')
        flows=snapshot.get('flows',[]);records=snapshot.get('results',[])
        if len(flows)>CAPACITY or len(records)>CAPACITY:raise ValueError('Map capacity exceeded')
        for name in COUNTERS:
            if type(snapshot.get(name)) is not int or snapshot[name]<0:raise ValueError('Invalid kernel counter: '+name)
        results={};errors=[]
        for r in records:
            identity=flow_id(r['key'])
            if identity in results:raise ValueError('Duplicate canonical result')
            tensors=r.get('tensors',[])
            complete=(r.get('mask')==63 and r.get('label') in (0,1) and r.get('model_slot')==0
                      and len(tensors)==6 and all(len(t)==n for t,n in zip(tensors,(6,32,32,32,32,2))))
            if not complete:errors.append('Incomplete prediction: '+identity);continue
            logits=tensors[-1]
            if r['label']!=(0 if logits[0]>logits[1] else 1):raise ValueError('Logit/class inconsistency')
            results[identity]=r
        rows=[];flow_ids=set()
        for f in flows:
            key=f['key'];identity=flow_id(key)
            if identity in flow_ids:raise ValueError('Duplicate canonical flow')
            flow_ids.add(identity);r=results.get(identity)
            if f.get('input_initialized'):
                src,dst=('a','b') if f['mlp_input_direction']==0 else ('b','a')
                basis='first eligible ingress leg (not TCP handshake reconstruction)'
            else:
                dst='a' if key['a_ip'] in self.server_ips else 'b' if key['b_ip'] in self.server_ips else None
                src=('b' if dst=='a' else 'a') if dst else None;basis='interface IPv4' if dst else 'unknown'
            state={0:'IDLE',1:'RUNNING',2:'DONE'}.get(f['state'],'UNKNOWN')
            if state=='DONE' and not r:state='DONE_WITHOUT_COMPLETE_RESULT'
            row=dict(id=identity,key=key,client_ip=key[src+'_ip'] if src else None,
                     client_port=key[src+'_port'] if src else None,server_ip=key[dst+'_ip'] if dst else None,
                     server_port=key[dst+'_port'] if dst else None,role_basis=basis,
                     hooks=f['hooks'],state=state,failures=f['failures'],duplicates=f['duplicates'],
                     label=r['label'] if r else None,logits=r['tensors'][-1] if r else None,
                     logit_q=self.logit_q,
                     completed_ns=r['completed_ns'] if r else None,features=r['features'] if r else None,
                     sequence=f['sequence'])
            rows.append(row)
        # Results remain immutable and retained by canonical key, independent of
        # per-CPU scratch. Also log a result if a flow snapshot is unavailable.
        by_id={r['id']:r for r in rows}
        for identity,r in results.items():
            token=(identity,r['sequence'],r['completed_ns'])
            if token in self.seen:continue
            if len(self.seen)>=CAPACITY:raise ValueError('Result retention capacity exhausted')
            f=by_id.get(identity)
            record=dict(session=self.session,flow_id=identity,key=r['key'],mode=self.mode,
                        model=self.model,model_identity=self.model_identity,experiment_id=self.experiment_id,
                        application_port=self.application_port,
                        inference_monotonic_ns=r['completed_ns'],collected_unix=now,
                        label=r['label'],logits=r['tensors'][-1],logit_q=self.logit_q,
                        features=r['features'],sequence=r['sequence'],
                        error='Earlier inference attempts failed; reason unavailable' if f and f['failures'] else None,
                        client_ip=f['client_ip'] if f else None,client_port=f['client_port'] if f else None,
                        server_ip=f['server_ip'] if f else None,server_port=f['server_port'] if f else None,
                        directional_stats=f['hooks'] if f else None,
                        prior_flow_failures=f['failures'] if f else None,
                        statistics_basis='collection-time snapshot; not atomic with inference publication')
            self.log.append(record);self.seen.add(token);self.recent.append(record)
        if any(f['failures'] for f in flows):errors.append('Flow inference failures recorded; per-flow reason unavailable')
        diagnostics=snapshot.get('numerical_diagnostics',{})
        if any(diagnostics.values()):errors.append('Experimental arithmetic rejections recorded')
        return json_safe(dict(schema=1,source='LIVE',status='CONNECTED',session=self.session,
            model=self.model,model_identity=self.model_identity,application_port=self.application_port,experiment_id=self.experiment_id,
            interface=self.interface,mode=self.mode,hooks=hooks,collected_unix=now,
            collected_utc=datetime.fromtimestamp(now,timezone.utc).isoformat(),
            aggregate={**{k:snapshot[k] for k in COUNTERS},'tracked_flows':len(flows),'completed_results':len(results)},
            flow_capacity=CAPACITY,flows=sorted(rows,key=lambda f:f['id']),recent_predictions=list(self.recent),
            numerical_diagnostics=diagnostics,errors=errors,
            semantics='Ingress-leg MLP; bidirectional monitoring. Kernel ns are monotonic; snapshots are not globally atomic.'))
