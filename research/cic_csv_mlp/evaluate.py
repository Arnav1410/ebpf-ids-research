"""One final test evaluation, only after both model checkpoints are frozen."""
from collections import Counter
import csv
import gzip
import json
import numpy as np

from .common import archive, read, write, sha, freeze, verify_hashes
from .metrics import classification, paired_bootstrap
from .train import setup, reload_model


def port_classifier(train_ports,train_labels,test_ports):
    majority=int(np.count_nonzero(train_labels==1)>np.count_nonzero(train_labels==0))
    learned={}
    for port in np.unique(train_ports):
        labels=train_labels[train_ports==port]
        learned[int(port)]=int(np.count_nonzero(labels==1)>np.count_nonzero(labels==0))
    return majority,np.array([learned.get(int(p),majority) for p in test_ports],dtype=np.int64),learned


def evaluate(out):
    verify_hashes(out,'data-freeze.json');verify_hashes(out,'split-freeze.json');verify_hashes(out,'models-freeze.json')
    if (out/'evaluation').exists():raise ValueError('Final evaluation already exists; never overwrite predictions')
    for mode in ('forward','bidirectional'):verify_hashes(out/mode,'freeze.json')
    spec=read(out/'protocol.json');t=setup(spec['seed'])
    test=archive(out/'test.npz');train=archive(out/'train.npz');split=archive(out/'split.npz')
    with gzip.open(out/'records.jsonl.gz','rt') as f:metadata=[json.loads(line) for line in f]
    records=[metadata[int(i)] for i in test['indices']]
    truth=test['labels'];groups=split['group_id'][test['indices']]
    assert all(r['index']==i and r['source_line']==line and r['label']==y for r,i,line,y in
               zip(records,test['indices'],test['source_lines'],truth))
    dest=out/'evaluation';dest.mkdir()
    arrays=dict(indices=test['indices'],source_lines=test['source_lines'],truth=truth,group_id=groups)
    result=dict(scope='Offline FP32 CICFlowMeter CSV held-out classification; not kernel or live IDS performance',
                source_csv_sha256=spec['source_member_sha256'],split_sha256=sha(out/'split.npz'),
                protocol_sha256=sha(out/'protocol.json'),input_count=len(truth),models={},per_category={},per_port={})
    for mode in ('forward','bidirectional'):
        scaler=archive(out/mode/'scaler.npz')
        normalized=((test[mode].astype(np.float64)-scaler['mean'])/scaler['scale']).astype(np.float32)
        assert np.isfinite(normalized).all()
        model=reload_model(out/mode/'checkpoint.npz')
        with t.no_grad():logits=model(t.from_numpy(normalized)).numpy()
        assert logits.shape==(len(truth),2) and np.isfinite(logits).all()
        pred=logits.argmax(axis=1);margin=logits[:,1].astype(np.float64)-logits[:,0].astype(np.float64)
        arrays[mode+'_logits']=logits;arrays[mode+'_prediction']=pred;arrays[mode+'_margin']=margin
        metrics=classification(truth,pred,margin)
        assert metrics['valid_predictions']==len(truth) and metrics['missing_invalid']==0
        result['models'][mode]=dict(metrics=metrics,checkpoint_sha256=sha(out/mode/'checkpoint.npz'),
            scaler_sha256=sha(out/mode/'scaler.npz'),exact_logit_ties=int((logits[:,0]==logits[:,1]).sum()),
            normalized_test_min=normalized.min(0).tolist(),normalized_test_max=normalized.max(0).tolist(),
            normalized_inputs_finite=True,train_validation_test_rows_identical_across_models=True)
        per={}
        categories=np.array([r['category'] for r in records])
        for category in sorted(set(categories)):
            mask=categories==category;part=classification(truth[mask],pred[mask])
            per[category]=dict(support=int(mask.sum()),predicted_intrusion=int(pred[mask].sum()),
                intrusion_detection_recall=float((pred[mask]==1).mean()) if category!='BENIGN' else None,
                benign_false_positive_rate=float((pred[mask]==1).mean()) if category=='BENIGN' else None,
                confusion_matrix=part['confusion_matrix'])
        result['per_category'][mode]=per
        # Port subgroups are descriptive; no thresholds/models are selected here.
        ports=test['forward'][:,3]
        for port,count in Counter(ports.tolist()).most_common():
            if count<100 and port not in (21,22):continue
            mask=ports==port
            result['per_port'].setdefault(str(port),{})[mode]=classification(truth[mask],pred[mask])
    a=arrays['forward_prediction'];b=arrays['bidirectional_prediction']
    changed=a!=b;corrected=(a!=truth)&(b==truth);regressed=(a==truth)&(b!=truth)
    result['paired']=dict(disagreements=int(changed.sum()),corrected=int(corrected.sum()),made_incorrect=int(regressed.sum()),
        by_class={str(k):dict(support=int((truth==k).sum()),changed=int((changed&(truth==k)).sum()),
            corrected=int((corrected&(truth==k)).sum()),made_incorrect=int((regressed&(truth==k)).sum())) for k in (0,1)},
        f1_difference=result['models']['bidirectional']['metrics']['f1']-result['models']['forward']['metrics']['f1'])
    assert int(corrected.sum()+regressed.sum())==int(changed.sum())
    result['paired']['f1_difference_percentage_points']=100*result['paired']['f1_difference']
    result['paired']['bootstrap']=paired_bootstrap(truth,a,b,groups)
    majority,port_pred,learned=port_classifier(train['forward'][:,3],train['labels'],test['forward'][:,3])
    result['baselines']=dict(training_majority_class=majority,
        majority=classification(truth,np.full(len(truth),majority,dtype=np.int64)),
        destination_port_only=classification(truth,port_pred),
        destination_port_rule='Training-only majority label per port; ties class 0; unseen port -> training majority',
        port_training_counts={str(port):dict(Counter(map(str,train['labels'][train['forward'][:,3]==port].tolist()))) for port in learned},
        port_predictions={str(k):v for k,v in learned.items()})
    arrays['port_baseline_prediction']=port_pred
    np.savez_compressed(dest/'predictions.npz',**arrays)
    with gzip.open(dest/'predictions.csv.gz','wt',newline='') as f:
        writer=csv.writer(f)
        names=['array_index','source_record_id','source_line','flow_id','timestamp','category','truth','group_id']
        names += [mode+'_feature_'+str(i) for mode in ('forward','bidirectional') for i in range(6)]
        names += [mode+'_'+k for mode in ('forward','bidirectional') for k in ('logit0','logit1','prediction','status')]
        names += ['port_baseline_prediction','different','corrected_by_bidirectional','made_incorrect_by_bidirectional']
        writer.writerow(names)
        for j,r in enumerate(records):
            row=[int(test['indices'][j]),r['source_record_id'],r['source_line'],r['flow_id'],r['timestamp'],r['category'],int(truth[j]),int(groups[j])]
            row += test['forward'][j].tolist()+test['bidirectional'][j].tolist()
            for mode in ('forward','bidirectional'):row += arrays[mode+'_logits'][j].tolist()+[int(arrays[mode+'_prediction'][j]),'PASS']
            row += [int(port_pred[j]),int(changed[j]),int(corrected[j]),int(regressed[j])]
            writer.writerow(row)
    result['prediction_archive_sha256']=sha(dest/'predictions.npz')
    result['prediction_csv_sha256']=sha(dest/'predictions.csv.gz')
    write(dest/'metrics.json',result)
    freeze(dest,'freeze.json',['metrics.json','predictions.npz','predictions.csv.gz'])
    print(json.dumps({mode:result['models'][mode]['metrics'] for mode in ('forward','bidirectional')},indent=2),flush=True)
    print('Paired F1 difference, percentage points:',result['paired']['f1_difference_percentage_points'],flush=True)
