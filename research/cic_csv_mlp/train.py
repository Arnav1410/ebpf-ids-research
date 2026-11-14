"""Train only on frozen training IDs; checkpoint selection uses validation."""
import importlib.util
import hashlib
import os
import platform
import random
import subprocess
import time
import numpy as np
from sklearn.preprocessing import StandardScaler

from .common import ROOT, archive, read, write, sha, freeze, verify_hashes


def setup(seed):
    import torch
    random.seed(seed);np.random.seed(seed);torch.manual_seed(seed)
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    return torch


def network():
    spec=importlib.util.spec_from_file_location('authors_cic_net',ROOT/'src/mlp.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    net=m.Net(6,2)
    assert sum(p.numel() for p in net.parameters())==1280
    assert len(list(net.parameters()))==3 and all('bias' not in k for k in net.state_dict())
    return net


def weights_digest(model):
    return hashlib.sha256(b''.join(k.encode()+v.detach().cpu().numpy().astype('<f4').tobytes()
                                   for k,v in model.state_dict().items())).hexdigest()


def reload_model(path):
    import torch
    net=network();saved=archive(path)
    assert set(saved)==set(net.state_dict())
    for k,v in net.state_dict().items():
        assert saved[k].shape==tuple(v.shape) and saved[k].dtype==np.float32 and np.isfinite(saved[k]).all()
    net.load_state_dict({k:torch.from_numpy(v) for k,v in saved.items()},strict=True)
    net.eval();return net


def train_one(out, mode):
    verify_hashes(out,'data-freeze.json');verify_hashes(out,'split-freeze.json')
    spec=read(out/'protocol.json');t=setup(spec['seed'])
    dest=out/mode;dest.mkdir(exist_ok=False)
    train=archive(out/'train.npz');val=archive(out/'validation.npz')
    x=train[mode].astype(np.float64);v=val[mode].astype(np.float64)
    scaler=StandardScaler().fit(x)
    assert np.allclose(scaler.mean_,x.mean(0),rtol=1e-14,atol=1e-10)
    assert np.allclose(scaler.var_,x.var(0),rtol=1e-13,atol=1e-9)
    a=scaler.transform(x).astype(np.float32);b=scaler.transform(v).astype(np.float32)
    if not np.isfinite(a).all() or not np.isfinite(b).all():raise ValueError('Invalid normalized input')
    np.savez_compressed(dest/'scaler.npz',mean=scaler.mean_,scale=scaler.scale_,variance=scaler.var_)
    write(dest/'scaler.json',dict(mean=scaler.mean_.tolist(),scale=scaler.scale_.tolist(),variance=scaler.var_.tolist(),
          fit_partition='train',fit_rows=len(x),fit_archive_sha256=sha(out/'train.npz'),
          fit_indices_sha256=hashlib.sha256(train['indices'].astype('<i8').tobytes()).hexdigest(),
          normalization='(x-mean)/scale in float64, then float32 network input',ddof=0,
          normalized_train_min=a.min(0).tolist(),normalized_train_max=a.max(0).tolist(),
          normalized_validation_min=b.min(0).tolist(),normalized_validation_max=b.max(0).tolist()))
    tx=t.from_numpy(a);ty=t.from_numpy(train['labels']);vx=t.from_numpy(b);vy=t.from_numpy(val['labels'])
    model=network();initial=weights_digest(model)
    loss_fn=t.nn.CrossEntropyLoss();optimizer=t.optim.Adam(model.parameters(),lr=.001)
    loader=t.utils.data.DataLoader(t.utils.data.TensorDataset(tx,ty),batch_size=512,shuffle=True,num_workers=0,
        generator=t.Generator().manual_seed(spec['seed']))
    best=float('inf');epoch_chosen=None;best_weights=None;history=[];started=time.monotonic()
    for epoch in range(1,spec['epochs']+1):
        model.train();online=0.
        for bx,by in loader:
            optimizer.zero_grad();loss=loss_fn(model(bx),by)
            if not t.isfinite(loss):raise ValueError('Nonfinite training loss')
            loss.backward();optimizer.step();online+=float(loss.detach())*len(bx)
        model.eval()
        with t.no_grad():
            tr=model(tx);vl=model(vx)
            tr_loss=float(loss_fn(tr,ty));val_loss=float(loss_fn(vl,vy))
        if not t.isfinite(vl).all() or not t.isfinite(tr).all():raise ValueError('Invalid validation/train logits')
        entry=dict(epoch=epoch,training_loss=tr_loss,online_training_loss=online/len(x),validation_loss=val_loss,
            validation_accuracy=float((vl.argmax(1)==vy).float().mean()),elapsed_seconds=time.monotonic()-started)
        history.append(entry)
        if val_loss<best:
            best=val_loss;epoch_chosen=epoch
            best_weights={k:v.detach().cpu().numpy().copy() for k,v in model.state_dict().items()}
        print(f'{mode} epoch {epoch:02d}/32 train_CE={tr_loss:.6f} validation_CE={val_loss:.6f}',flush=True)
    np.savez_compressed(dest/'checkpoint.npz',**best_weights)
    model.load_state_dict({k:t.from_numpy(v) for k,v in best_weights.items()});model.eval()
    with t.no_grad():expected=model(vx).numpy()
    reloaded=reload_model(dest/'checkpoint.npz')
    saved=archive(dest/'scaler.npz');repeat=((v-saved['mean'])/saved['scale']).astype(np.float32)
    assert np.array_equal(repeat,b)
    with t.no_grad():actual=reloaded(t.from_numpy(repeat)).numpy()
    assert np.array_equal(expected,actual),'Saved checkpoint/scaler reload changed outputs'
    np.savez_compressed(dest/'validation_logits.npz',indices=val['indices'],logits=actual)
    write(dest/'history.json',history)
    import sklearn,torch
    write(dest/'training.json',dict(status='PASS',mode=mode,best_epoch=epoch_chosen,best_validation_loss=best,
        train_rows=len(x),validation_rows=len(v),initial_weights_sha256=initial,selected_weights_sha256=weights_digest(reloaded),
        checkpoint_sha256=sha(dest/'checkpoint.npz'),scaler_sha256=sha(dest/'scaler.npz'),architecture=[6,32,32,2],weights=1280,bias=False,
        optimizer='Adam',learning_rate=.001,epochs=32,batch_size=512,seed=spec['seed'],threads=1,device='cpu',
        criterion='Minimum validation cross-entropy; earliest exact tie',test_used=False,reload_logits_bitwise_equal=True,
        validation_reload_records=len(v),data_freeze_sha256=sha(out/'data-freeze.json'),split_freeze_sha256=sha(out/'split-freeze.json'),
        authors_net_sha256=sha(ROOT/'src/mlp.py'),python=platform.python_version(),kernel=platform.release(),
        packages=dict(torch=torch.__version__,numpy=np.__version__,sklearn=sklearn.__version__),
        wall_seconds=time.monotonic()-started,git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()))
    freeze(dest,'freeze.json',['checkpoint.npz','scaler.npz','scaler.json','history.json','training.json','validation_logits.npz'])


def train_both(out):
    for mode in ('forward','bidirectional'):train_one(out,mode)
    a=read(out/'forward/training.json');b=read(out/'bidirectional/training.json')
    assert a['initial_weights_sha256']==b['initial_weights_sha256']
    assert a['split_freeze_sha256']==b['split_freeze_sha256'] and not a['test_used'] and not b['test_used']
    freeze(out,'models-freeze.json',['forward/freeze.json','bidirectional/freeze.json','protocol.json','split-freeze.json'],
           same_initialization=True,same_partitions=True,test_evaluated=False)
