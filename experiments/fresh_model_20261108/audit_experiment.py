"""Read-only independent reconstruction of split, scaler, checkpoint and saved metrics."""
import gzip
import hashlib
import json
from pathlib import Path
import sys
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parent))
from pipeline import HERE,ROOT,read,write,sha,load_numeric,metrics,preservation
from validation.reference import Model,STAGES
from quantization.reference import LayerModel

import argparse
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=HERE/'run')
out=parser.parse_args().output;split=read(out/'split.json');freeze=read(out/'freeze.json')
x=np.load(ROOT/'dataset/reproduction-xdp-data.npy',allow_pickle=False);y=np.load(ROOT/'dataset/reproduction-xdp-label.npy',allow_pickle=False).astype(np.int64)
arrays={n:load_numeric(out/(n+'.npz')) for n in ('train','validation','test')}
seen=set();vectors=[]
for name,data in arrays.items():
    ids=data['indices'].tolist();assert ids==split['partitions'][name]['indices']
    assert not seen.intersection(ids);seen.update(ids)
    assert np.array_equal(data['features'],x[ids]) and np.array_equal(data['labels'],y[ids])
    vectors.append({tuple(r) for r in data['features'].tolist()})
assert seen==set(range(18840))
assert all(not vectors[a].intersection(vectors[b]) for a,b in ((0,1),(0,2),(1,2)))
s=read(out/'scaler.json');tx=arrays['train']['features'].astype(np.float64)
assert s['fit_row_indices']==arrays['train']['indices'].tolist() and s['n_samples_seen']==len(tx)
assert np.allclose(np.mean(tx,axis=0),s['mean'],rtol=1e-14,atol=1e-12)
assert np.allclose(np.std(tx,axis=0,ddof=0),s['scale'],rtol=1e-13,atol=1e-12)
assert read(out/'history.json')[freeze['selected_epoch']-1]['validation_loss']==min(r['validation_loss'] for r in read(out/'history.json'))
assert not freeze['test_used'] and freeze['train_read_archives']==['train.npz','validation.npz']
weights=load_numeric(out/'checkpoint.npz');base=Model.load(out/'model/mlp_params.bpf.h');layer=LayerModel.load(out/'model/calibrated.json',out/'model/mlp_params.bpf.h')
for i,j in enumerate((0,2,4)):
    expected=np.rint(weights[f'model.{j}.weight']*np.float32(65536)).astype(np.int64).ravel().tolist()
    assert base.weights[i]==expected
assert base.mean==np.rint(s['mean']).astype(np.int64).tolist() and base.scale==np.rint(s['scale']).astype(np.int64).tolist()
assert layer.config['selection_row_ids']==arrays['train']['indices'].tolist()
assert not set(layer.config['selection_row_ids']).intersection(arrays['test']['indices'].tolist())
max_delta=np.max(np.abs(arrays['train']['features']-np.array(base.mean,dtype=np.int64)),axis=0).tolist()
for delta,scale,bound,limit in zip(max_delta,base.scale,layer.config['normalized_domain'],layer.config['delta_limits']):
    assert bound>0 and bound&(bound-1)==0 and limit==bound*scale and limit>=2*delta
    assert bound==1 or limit//2<2*delta
fp=[json.loads(s) for s in gzip.open(out/'fp32-predictions.jsonl.gz','rt')]
assert [r['row_index'] for r in fp]==arrays['test']['indices'].tolist()
fpstats=read(out/'fp32-metrics.json');assert metrics([r['truth'] for r in fp],[r['prediction'] for r in fp])==fpstats['metrics']
integer=[json.loads(s) for s in gzip.open(out/'integer-predictions.jsonl.gz','rt')];comparison=read(out/'comparison.json')
assert [r['row_index'] for r in integer]==[r['row_index'] for r in fp]==comparison['test_row_ids']
count=0
for row in integer:
    i=row['row_index'];assert row['features']==x[i].tolist() and row['truth']==int(y[i])
    for mode,saved in row['modes'].items():
        if saved['status']=='FAIL':assert saved['prediction'] is None;continue
        events=[];values,label=(layer if mode=='tc_layer_specific' else base).infer(row['features'],events)
        assert not events and saved['prediction']==label and saved['tensors']==values;count+=1
for mode,value in comparison['modes'].items():assert metrics([r['truth'] for r in integer],[r['modes'][mode]['prediction'] for r in integer])==value['metrics']
result=dict(status='PASS',scope='Read-only independent audit; no training or kernel execution',
    partition_rows={n:len(v['indices']) for n,v in arrays.items()},split_group_overlap=0,
    train_only_scaler='PASS',test_excluded_from_calibration='PASS',checkpoint_selection='Minimum validation CE',
    fp32_prediction_count=len(fp),integer_records=count,stage_tensors=count*6,integers=count*136,
    independently_recomputed_metrics='PASS all four models',preservation=preservation())
write(out/'independent-audit.json',result);print(json.dumps(result,indent=2))
