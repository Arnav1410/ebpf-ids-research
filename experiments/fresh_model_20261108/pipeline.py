#!/usr/bin/env python3
"""Isolated fresh-model experiment. Never edits the deployed source or model."""
import argparse
from collections import Counter
import ctypes
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('MPLCONFIGDIR', '/tmp/nn-ebpf-fresh-matplotlib')
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn import metrics as sm

SEED = 20261108
CONFIG = dict(seed=SEED, fractions=[.70,.15,.15], epochs=32, batch_size=512,
    learning_rate=.001, optimizer='Adam; PyTorch defaults', loss='CrossEntropyLoss',
    architecture=[6,32,32,2], biases=False, activations=['ReLU','ReLU'],
    checkpoint='Minimum validation cross-entropy; earliest epoch on exact tie',
    fp32_ties='argmax: class 0, as authors training code',
    integer_ties='class 1, as original kernel code', device='cpu', threads=1,
    calibration='ALL training rows ONLY; existing conservative bound selector',
    labels={'0':'supplied benign','1':'supplied intrusion'})


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')


def read(path): return json.loads(Path(path).read_text())


def preservation():
    expected=read(HERE/'preservation-before.json')
    changed=[p for p,h in expected.items() if not (ROOT/p).is_file() or sha(ROOT/p)!=h]
    if changed: raise AssertionError('Protected files changed: '+str(changed))
    return dict(status='PASS',unchanged_files=len(expected))


def load_numeric(path):
    with np.load(path,allow_pickle=False) as z: return {k:z[k].copy() for k in z.files}


def grouped_split(x,y,seed=SEED):
    groups={}
    for i,row in enumerate(x): groups.setdefault(struct.pack('<6q',*map(int,row)),[]).append(i)
    assert all(len(set(map(int,y[ids])))==1 for ids in groups.values()), 'Conflicting labels in duplicate group'
    bins=[[],[],[]];rng=np.random.default_rng(seed)
    for label in (0,1):
        g=[ids for key,ids in sorted(groups.items()) if int(y[ids[0]])==label]
        rng.shuffle(g);sizes=np.array([len(ids) for ids in g]);sums=np.concatenate(([0],np.cumsum(sizes)))
        total=int(sums[-1]);a=int(np.argmin(abs(sums-total*.7)))
        b=a+int(np.argmin(abs(sums[a:]-total*.85)))
        for dst,part in zip(bins,(g[:a],g[a:b],g[b:])):
            dst.extend(i for ids in part for i in ids)
    bins=[sorted(b) for b in bins]
    assert len(set().union(*map(set,bins)))==len(x) and sum(map(len,bins))==len(x)
    sets=[{struct.pack('<6q',*map(int,x[i])) for i in ids} for ids in bins]
    assert all(not sets[a]&sets[b] for a,b in ((0,1),(0,2),(1,2)))
    return bins,groups


def prepare(out):
    preservation();out.mkdir(parents=True,exist_ok=False)
    x=np.load(ROOT/'dataset/reproduction-xdp-data.npy',allow_pickle=False)
    raw_y=np.load(ROOT/'dataset/reproduction-xdp-label.npy',allow_pickle=False)
    assert x.shape==(18840,6) and x.dtype==np.dtype('int64') and np.isfinite(x).all()
    assert raw_y.shape==(18840,) and np.isfinite(raw_y).all() and set(raw_y)=={0,1}
    y=raw_y.astype(np.int64);parts,groups=grouped_split(x,y)
    split=dict(schema=1,seed=SEED,method='Per-label shuffled exact-feature groups; nearest cumulative 70/85 percent row boundary',
        dataset={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/'dataset/reproduction-xdp-data.npy',ROOT/'dataset/reproduction-xdp-label.npy')},
        samples=len(x),distinct_vectors=len(groups),duplicate_excess=len(x)-len(groups),
        metadata='No trusted capture-day/session identifiers; group-separated random within-dataset split',partitions={},groups=[])
    for name,ids in zip(('train','validation','test'),parts):
        np.savez_compressed(out/(name+'.npz'),indices=np.array(ids),features=x[ids],labels=y[ids])
        split['partitions'][name]=dict(count=len(ids),support=dict(Counter(map(int,y[ids]))),indices=ids,
            archive_sha256=sha(out/(name+'.npz')),features_sha256=hashlib.sha256(x[ids].astype('<i8').tobytes()).hexdigest())
    assignment={i:name for name,ids in zip(('train','validation','test'),parts) for i in ids}
    for key,ids in sorted(groups.items()):
        split['groups'].append(dict(feature_sha256=hashlib.sha256(key).hexdigest(),indices=ids,label=int(y[ids[0]]),partition=assignment[ids[0]]))
    write(out/'split.json',split);write(out/'config.json',CONFIG)
    write(out/'gate1.json',dict(status='PASS',duplicate_group_overlap=0,row_overlap=0,total=len(x),split_sha256=sha(out/'split.json'),
        frozen_inputs={n:sha(out/n) for n in ('train.npz','validation.npz','test.npz','config.json')}))
    print(json.dumps({n:{k:v for k,v in a.items() if k not in ('indices',)} for n,a in split['partitions'].items()},indent=2))


def check_split(out):
    split=read(out/'split.json');gate=read(out/'gate1.json')
    assert sha(out/'split.json')==gate['split_sha256'] and read(out/'config.json')==CONFIG
    for n,h in gate['frozen_inputs'].items():assert sha(out/n)==h,n
    ids=[set(a['indices']) for a in split['partitions'].values()]
    assert sum(map(len,ids))==len(set.union(*ids))==18840
    assign={i:n for n,p in split['partitions'].items() for i in p['indices']}
    assert all({assign[i] for i in g['indices']}=={g['partition']} for g in split['groups'])
    return split


def authors_net():
    spec=importlib.util.spec_from_file_location('authors_mlp',ROOT/'src/mlp.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m.Net(6,2)


def torch_setup():
    import torch
    random.seed(SEED);np.random.seed(SEED);torch.manual_seed(SEED)
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    return torch


def checked_model(out):
    t=torch_setup();model=authors_net();saved=load_numeric(out/'checkpoint.npz')
    assert set(saved)==set(model.state_dict())
    model.load_state_dict({k:t.from_numpy(v) for k,v in saved.items()},strict=True);model.eval()
    assert sum(p.numel() for p in model.parameters())==1280
    return model


def train(out):
    t=torch_setup();check_split(out);preservation()
    assert not (out/'checkpoint.npz').exists(),'Never overwrite a frozen selected checkpoint'
    # Trainer opens ONLY training and validation archives. Test file is only hashed for preservation.
    train=load_numeric(out/'train.npz');val=load_numeric(out/'validation.npz')
    scaler=StandardScaler().fit(train['features'])
    assert np.array_equal(scaler.mean_,train['features'].mean(axis=0))
    assert np.allclose(scaler.var_,train['features'].var(axis=0),rtol=1e-14,atol=1e-9)
    write(out/'scaler.json',dict(mean=scaler.mean_.tolist(),scale=scaler.scale_.tolist(),var=scaler.var_.tolist(),
        n_samples_seen=int(scaler.n_samples_seen_),fit_partition='train',fit_row_indices=train['indices'].tolist(),
        input_sha256=sha(out/'train.npz'),ddof=0))
    x=t.from_numpy(scaler.transform(train['features']).astype(np.float32));y=t.from_numpy(train['labels'])
    vx=t.from_numpy(scaler.transform(val['features']).astype(np.float32));vy=t.from_numpy(val['labels'])
    model=authors_net();assert sum(p.numel() for p in model.parameters())==1280
    assert len(list(model.parameters()))==3 and all('bias' not in k for k in model.state_dict())
    optimizer=t.optim.Adam(model.parameters(),lr=CONFIG['learning_rate']);loss_fn=t.nn.CrossEntropyLoss()
    loader=t.utils.data.DataLoader(t.utils.data.TensorDataset(x,y),batch_size=512,shuffle=True,num_workers=0,
        generator=t.Generator().manual_seed(SEED))
    best=float('inf');selected=None;weights=None;history=[]
    for epoch in range(1,33):
        model.train();total=0.
        for bx,by in loader:
            optimizer.zero_grad();loss=loss_fn(model(bx),by);assert t.isfinite(loss)
            loss.backward();optimizer.step();total+=loss.item()*len(bx)
        model.eval()
        with t.no_grad():logits=model(vx);vl=float(loss_fn(logits,vy));pred=logits.argmax(1).numpy()
        assert np.isfinite(logits.numpy()).all() and all(t.isfinite(p).all() for p in model.parameters())
        m=metrics(val['labels'].tolist(),pred.tolist())
        history.append(dict(epoch=epoch,training_loss=total/len(x),validation_loss=vl,
            validation_accuracy=m['accuracy'],validation_precision=m['precision'],validation_recall=m['recall'],validation_f1=m['f1']))
        if vl<best:
            best=vl;selected=epoch;weights={k:v.detach().cpu().numpy().copy() for k,v in model.state_dict().items()}
        print(f'Epoch {epoch:02d}/32 train_CE={total/len(x):.6f} validation_CE={vl:.6f}',flush=True)
    np.savez_compressed(out/'checkpoint.npz',**weights);write(out/'history.json',history)
    import sklearn
    write(out/'freeze.json',dict(status='PASS',selected_epoch=selected,criterion=CONFIG['checkpoint'],validation_loss=best,
        checkpoint_sha256=sha(out/'checkpoint.npz'),scaler_sha256=sha(out/'scaler.json'),split_sha256=sha(out/'split.json'),
        config_sha256=sha(out/'config.json'),history_sha256=sha(out/'history.json'),
        architecture=[6,32,32,2],parameters=1280,train_read_archives=['train.npz','validation.npz'],
        test_used=False,packages=dict(torch=t.__version__,numpy=np.__version__,sklearn=sklearn.__version__),
        python=platform.python_version(),kernel=platform.release(),machine=platform.machine(),device='cpu',threads=t.get_num_threads(),
        git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),preservation=preservation()))
    print('Gate 2 PASS; selected epoch',selected,'test not evaluated',flush=True)


def metrics(truth,predictions):
    assert len(truth)==len(predictions)
    valid=[(int(t),int(p)) for t,p in zip(truth,predictions) if p is not None]
    assert all(t in (0,1) and p in (0,1) for t,p in valid)
    tn=sum(t==p==0 for t,p in valid);tp=sum(t==p==1 for t,p in valid)
    fp=sum(t==0 and p==1 for t,p in valid);fn=sum(t==1 and p==0 for t,p in valid)
    div=lambda n,d:n/d if d else None
    def cls(a,b,c,s):return dict(precision=div(a,a+b),recall=div(a,a+c),f1=div(2*a,2*a+b+c),support=s)
    per={'0':cls(tn,fn,fp,tn+fp),'1':cls(tp,fp,fn,tp+fn)}
    n=len(valid);rec=div(tp,tp+fn);spec=div(tn,tn+fp)
    den=math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    result=dict(TP=tp,FP=fp,TN=tn,FN=fn,confusion_matrix=[[tn,fp],[fn,tp]],accuracy=div(tp+tn,n),
        precision=div(tp,tp+fp),recall=rec,f1=div(2*tp,2*tp+fp+fn),specificity=spec,false_positive_rate=div(fp,fp+tn),
        balanced_accuracy=(rec+spec)/2 if rec is not None and spec is not None else None,
        mcc=div(tp*tn-fp*fn,den),per_class=per,
        macro_f1=sum(p['f1'] for p in per.values())/2 if all(p['f1'] is not None for p in per.values()) else None,
        weighted_f1=sum(p['f1']*p['support'] for p in per.values())/n if n and all(p['f1'] is not None for p in per.values()) else None,
        input_count=len(truth),valid_predictions=n,invalid_missing=len(truth)-n,coverage=div(n,len(truth)),
        support={str(k):v for k,v in Counter(map(int,truth)).items()})
    if n:
        t,p=map(list,zip(*valid));assert sm.confusion_matrix(t,p,labels=[0,1]).tolist()==result['confusion_matrix']
        checks={'accuracy':sm.accuracy_score(t,p),'precision':sm.precision_score(t,p,zero_division=np.nan),
            'recall':sm.recall_score(t,p,zero_division=np.nan),'f1':sm.f1_score(t,p,zero_division=np.nan),
            'macro_f1':sm.f1_score(t,p,average='macro',zero_division=np.nan),'weighted_f1':sm.f1_score(t,p,average='weighted',zero_division=np.nan)}
        if den:checks['mcc']=sm.matthews_corrcoef(t,p)
        if rec is not None and spec is not None:checks['balanced_accuracy']=sm.balanced_accuracy_score(t,p)
        for k,v in checks.items():
            if result[k] is None:
                if k not in ('macro_f1','weighted_f1'):assert np.isnan(v),(k,result[k],v)
            else:assert math.isclose(result[k],float(v),rel_tol=1e-12,abs_tol=1e-12),(k,result[k],v)
    return result


def frozen(out):
    f=read(out/'freeze.json')
    for n,k in [('checkpoint.npz','checkpoint_sha256'),('scaler.json','scaler_sha256'),('split.json','split_sha256'),('config.json','config_sha256'),('history.json','history_sha256')]:assert sha(out/n)==f[k],n
    check_split(out);return f


def fp32_evaluate(out):
    f=frozen(out);assert not (out/'fp32-predictions.jsonl.gz').exists(),'Evaluation already frozen'
    t=torch_setup();model=checked_model(out);test=load_numeric(out/'test.npz');s=read(out/'scaler.json')
    normalized=((test['features']-np.array(s['mean']))/np.array(s['scale'])).astype(np.float32)
    with t.no_grad():logits=model(t.from_numpy(normalized)).numpy()
    assert logits.shape==(len(normalized),2) and np.isfinite(logits).all()
    predictions=np.argmax(logits,axis=1).tolist()
    with gzip.open(out/'fp32-predictions.jsonl.gz','wt') as stream:
        for i,raw,y,x,z,p in zip(test['indices'],test['features'],test['labels'],normalized,logits,predictions):
            stream.write(json.dumps(dict(row_index=int(i),features=raw.tolist(),truth=int(y),normalized_fp32=x.tolist(),
                logits=z.tolist(),prediction=p,status='PASS',model_sha256=f['checkpoint_sha256'],scaler_sha256=f['scaler_sha256']))+'\n')
    result=metrics(test['labels'].tolist(),predictions);assert sum(sum(a) for a in result['confusion_matrix'])==len(normalized)
    rows=[json.loads(s) for s in gzip.open(out/'fp32-predictions.jsonl.gz','rt')]
    assert metrics([r['truth'] for r in rows],[r['prediction'] for r in rows])==result
    write(out/'fp32-metrics.json',dict(status='PASS',execution='FP32 PyTorch CPU HOST; no kernel execution',metrics=result,
        ties=int(np.sum(logits[:,0]==logits[:,1])),prediction_sha256=sha(out/'fp32-predictions.jsonl.gz'),
        model_sha256=f['checkpoint_sha256'],scaler_sha256=f['scaler_sha256'],preservation=preservation()))
    print('Gate 3 PASS',json.dumps(result),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('stage',choices=['prepare','train','fp32','quantize','compare','audit','report'])
    p.add_argument('--output',type=Path,default=HERE/'run');a=p.parse_args()
    if a.stage=='prepare':prepare(a.output)
    elif a.stage=='train':train(a.output)
    elif a.stage=='fp32':fp32_evaluate(a.output)
    elif a.stage in ('quantize','compare'):
        import integer
        getattr(integer,a.stage)(a.output)
    elif a.stage=='audit':print(json.dumps(dict(preservation=preservation(),freeze=frozen(a.output)['status'])))
    else:
        import report
        report.generate(a.output)

if __name__=='__main__':main()
