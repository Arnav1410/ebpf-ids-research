#!/usr/bin/env python3
"""Join live socket records by experiment, TCP tuple and retained kernel session."""
import argparse
from collections import Counter,defaultdict
import csv
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from demo.common import canonical,write_csv,CLIENT_FIELDS
from evaluation.metrics import binary_metrics


def key_of(record):
    k=record['key']
    if k['protocol']!=6:raise ValueError('Non-TCP prediction')
    return canonical(k['a_ip'],k['a_port'],k['b_ip'],k['b_port'])


def tuple_of(record):return canonical(record['client_ip'],record['client_port'],record['server_ip'],record['server_port'])


def join(experiment,clients,events,predictions,attack_class=None,label_provenance=''):
    if attack_class is not None and (attack_class not in (0,1) or not label_provenance):raise ValueError('Explicit class mapping requires provenance')
    run=experiment['experiment_id'];session=experiment['collector_session'];mode=experiment['mode']
    by_key=defaultdict(list);duplicates=foreign=0;seen=set();app=defaultdict(list)
    for p in predictions:
        if p.get('session')!=session or p.get('mode')!=mode:foreign+=1;continue
        signature=json.dumps(p,sort_keys=True)
        if signature in seen:duplicates+=1;continue
        seen.add(signature);by_key[key_of(p)].append(p)
    for e in events:
        if e.get('experiment_id')==run:app[(e.get('case_id'),tuple_of(e))].append(e)
    identities=[]
    for r in clients:
        try:identities.append(tuple_of(r))
        except (ValueError,KeyError,TypeError):identities.append(None)
    multiplicity=Counter(k for k in identities if k);case_count=Counter(r['case_id'] for r in clients)
    joined=[];truth=[];predicted=[];matched=0;success=0
    for r,key in zip(clients,identities):
        status='MISSING_PREDICTION';p=None;timing='';success+=r.get('completion')=='PASS'
        if str(r.get('protocol','6'))!='6':status='INVALID_PROTOCOL'
        elif r.get('experiment_id')!=run:status='WRONG_EXPERIMENT'
        elif case_count[r['case_id']]!=1:status='DUPLICATE_CASE_ID'
        elif r.get('completion')!='PASS' or not key:status='CLIENT_ERROR'
        elif multiplicity[key]>1:status='AMBIGUOUS_SOURCE_PORT_REUSE'
        elif len(app[(r['case_id'],key)])!=1 or app[(r['case_id'],key)][0].get('status')!='PASS':status='MISSING_OR_AMBIGUOUS_APPLICATION_RECORD'
        elif len(by_key[key])>1:status='AMBIGUOUS_PREDICTIONS'
        elif by_key[key]:
            candidate=by_key[key][0]
            logits=candidate.get('logits');label=candidate.get('label')
            if (type(label) is not int or label not in (0,1) or not isinstance(logits,list) or len(logits)!=2
                or any(type(v) is not int or not -(1<<31)<=v<(1<<31) for v in logits)
                or label!=(0 if logits[0]>logits[1] else 1)):status='INVALID_PREDICTION'
            else:
                p=candidate;status='MATCHED';matched+=1
                # Both clocks are server-side monotonic; never compare Windows
                # wall time to kernel helper time to select a connection.
                stamp=int(p['inference_monotonic_ns']);start=int(experiment.get('start_monotonic_ns',0));end=int(experiment.get('end_monotonic_ns',2**63-1))
                if not start-2_000_000_000<=stamp<=end+2_000_000_000:timing='Outside recorded server run clock window; investigate'
        known=r.get('ground_truth') in ('benign','intrusion') and bool(r.get('ground_truth_provenance'))
        truth.append((1 if r['ground_truth']=='intrusion' else 0) if known and attack_class is not None else None)
        predicted.append((1 if p['label']==attack_class else 0) if p and not timing and attack_class is not None else None)
        joined.append({**r,'canonical_flow_id':key,'match_status':status,'predicted_label':p['label'] if p else None,
                       'logits':json.dumps(p['logits']) if p else '', 'inference_monotonic_ns':p['inference_monotonic_ns'] if p else None,'timing_warning':timing})
    metrics=binary_metrics(truth,predicted) if attack_class is not None else None
    summary=dict(experiment_id=run,collector_session=session,mode=mode,experiment_type='LIVE socket/kernel observation; NOT offline dataset evaluation',
        input_connections=len(clients),completed_connections=success,matched_predictions=matched,
        classification_coverage_all=matched/len(clients) if clients else None,
        classification_coverage_completed=matched/success if success else None,
        statuses=dict(Counter(r['match_status'] for r in joined)),duplicate_identical_prediction_records=duplicates,ignored_foreign_session_records=foreign,
        unmatched_prediction_flows=sum(k not in identities for k in by_key),attack_class=attack_class,label_mapping_provenance=label_provenance,
        metrics=metrics,metrics_status='PASS' if metrics else 'NOT RUN: explicit semantic class mapping not supplied',
        scope='Benign-only runs report conditional FPR and coverage; intrusion recall/F1 unavailable. Unknown labels remain unknown; missing predictions are abstentions.')
    return joined,summary


def jsonl(path):
    values=[]
    with path.open() as f:
        for line in f:
            if line.strip():values.append(json.loads(line))
            if len(values)>4096:raise ValueError('Bounded experiment log exceeded')
    return values


def run(args):
    args.output.mkdir(parents=True,exist_ok=False)
    experiment=json.loads((args.experiment/'experiment.json').read_text())
    with args.client.open(newline='',encoding='utf-8-sig') as f:clients=list(csv.DictReader(f))
    if not 0<len(clients)<=128:raise ValueError('Expected 1..128 bounded client records')
    joined,summary=join(experiment,clients,jsonl(args.experiment/'application_events.jsonl'),jsonl(args.experiment/'server_classifications.jsonl'),args.attack_class,args.label_provenance)
    shutil.copyfile(args.client,args.output/'client_results.csv');shutil.copyfile(args.experiment/'server_classifications.jsonl',args.output/'server_classifications.jsonl')
    fields=list(CLIENT_FIELDS)+['canonical_flow_id','match_status','predicted_label','logits','inference_monotonic_ns','timing_warning']
    write_csv(args.output/'joined_results.csv',joined,fields)
    (args.output/'evaluation_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (args.output/'REPORT.md').write_text('# Live experiment matching\n\n```json\n'+json.dumps(summary,indent=2)+'\n```\n')
    print(json.dumps(summary,indent=2));return 0


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--experiment',type=Path,required=True);p.add_argument('--client',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--attack-class',type=int,choices=(0,1));p.add_argument('--label-provenance',default='')
    raise SystemExit(run(p.parse_args()))
