"""New parameters in copied build trees; original XDP/TC arithmetic unchanged."""
from collections import Counter
import gzip
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import numpy as np
from pipeline import ROOT,HERE,read,write,sha,preservation,frozen,load_numeric,metrics
from validation.reference import Model,STAGES,SIZES
from quantization.reference import LayerModel,ExactModel,ArithmeticFailure
from quantization.calibrate import select,emit_header
from evaluation.offline import Host

MODES=('xdp_q16','tc_q16','tc_layer_specific')


def q16(values):
    a=np.rint(np.asarray(values,dtype=np.float32)*np.float32(65536))
    if not np.isfinite(a).all() or (a.astype(np.float64)<-(1<<31)).any() or (a.astype(np.float64)>(1<<31)-1).any():raise ValueError('Unrepresentable Q16 weight')
    return a.astype(np.int32)


def emit(weights,mean,scale):
    text='#ifndef PARAMS_BPF_H\n#define PARAMS_BPF_H\n#define FIX_POINT 16\n'
    for i,n in enumerate((6,32,32,2)):text+=f'#define N{i} {n}\n'
    for i,w in enumerate(weights):
        v=w.flatten().tolist();text+=f'static const int32_t layer_{i}_weight[{len(v)}] = {{'+','.join(map(str,v))+'};\n'
    for name,v in [('mean',mean),('scale',scale)]:text+=f'static const int64_t {name}[6] = {{'+','.join(map(str,v))+'};\n'
    return text+'#endif\n'


def command(out,argv,name):
    p=subprocess.run(list(map(str,argv)),capture_output=True,text=True,cwd=ROOT)
    (out/(name+'.log')).write_text(p.stdout+p.stderr)
    with (out/'build-commands.jsonl').open('a') as f:f.write(json.dumps(dict(argv=list(map(str,argv)),returncode=p.returncode))+'\n')
    if p.returncode:raise RuntimeError('Build failed: '+name+'; see log')


def quantize(out):
    freeze=frozen(out);preservation();assert not (out/'quantization.json').exists()
    weights=load_numeric(out/'checkpoint.npz');scaler=read(out/'scaler.json')
    qweights=[q16(weights[f'model.{i}.weight']) for i in (0,2,4)]
    mean=np.rint(scaler['mean']).astype(np.int64).tolist();scale=np.rint(scaler['scale']).astype(np.int64).tolist()
    assert all(0<s<(1<<63) for s in scale)
    modeldir=out/'model';modeldir.mkdir()
    header=modeldir/'mlp_params.bpf.h';header.write_text(emit(qweights,mean,scale));source=Model.load(header)
    train=load_numeric(out/'train.npz');config=select(source,train['features'].tolist())
    config['source_header_sha256']=sha(header)
    config.update(selection_partition='train',selection_row_ids=train['indices'].tolist(),
        calibration_data_sha256=sha(out/'train.npz'),new_fp32_checkpoint_sha256=freeze['checkpoint_sha256'],
        pretrained_original_used=False)
    layer=LayerModel(source,config);layer.validate();config['parameter_sha256']=sha_bytes(layer.packed())
    write(modeldir/'calibrated.json',config);(modeldir/'calibrated.h').write_text(emit_header(layer))
    write(modeldir/'normalization.json',dict(float_mean=scaler['mean'],float_scale=scaler['scale'],integer_mean=mean,integer_scale=scale,
        policy='Nearest-even rounding to int64 as original quantizer; never fit on validation/test',
        mean_rounding_error=(np.array(mean)-np.array(scaler['mean'])).tolist(),scale_rounding_error=(np.array(scale)-np.array(scaler['scale'])).tolist()))
    LayerModel.load(modeldir/'calibrated.json',header)
    # Verify representability on calibration data; no test features/labels inform scale selection.
    checked=0
    for row in train['features'].tolist():
        events=[];source.infer(row,events)
        if events:raise ValueError('Training row unsafe for Q16: '+str(events))
        layer.infer(row);checked+=1
    tree=out/'.output/tree';tree.mkdir(parents=True)
    copied={}
    for name in ('src','tc','validation','quantization','evaluation'):
        for p in (ROOT/name).rglob('*'):
            if p.is_file() and p.suffix in ('.c','.h') and '.output' not in p.parts:
                dest=tree/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
                copied[str(p.relative_to(ROOT))]=sha(p)
    shutil.copyfile(header,tree/'src/mlp_params.bpf.h')
    shutil.copyfile(modeldir/'calibrated.h',tree/'quantization/calibrated.h')
    write(out/'copied-source-manifest.json',dict(original_source_hashes=copied,parameter_overlays={
        'src/mlp_params.bpf.h':sha(header),'quantization/calibrated.h':sha(modeldir/'calibrated.h')}))
    build=out/'.output'
    for mode in MODES:
        argv=['clang-12','-O3','-shared','-fPIC','-pthread','-I'+str(tree/('validation/include' if mode=='xdp_q16' else 'tc/tests/include')),
              '-I'+str(tree/'validation/include')]
        if mode=='tc_layer_specific':argv+=['-DIDS_LAYER_SPECIFIC']
        argv+=[tree/('validation/native.c' if mode=='xdp_q16' else 'evaluation/tc_vectors.c'),'-o',build/(mode+'.so')]
        command(out,argv,mode+'-build')
    result=dict(status='PASS',execution='Host builds only; kernel NOT RUN',mean=mean,scale=scale,
        weight_shapes=[list(w.shape) for w in qweights],weight_max=[int(np.max(np.abs(w.astype(np.int64)))) for w in qweights],
        header_sha256=sha(header),calibration_sha256=sha(modeldir/'calibrated.json'),model_parameter_sha256=sha_bytes(source.packed()),
        layer_parameter_sha256=config['parameter_sha256'],training_range_checks=checked,calibration_exponents=layer.exponents,
        training_and_scale_data_only=True,new_checkpoint_sha256=freeze['checkpoint_sha256'],
        parameter_bytes=dict(q16=len(source.packed()),layer_specific=len(layer.packed())),preservation=preservation())
    write(out/'quantization.json',result);print(json.dumps(result,indent=2),flush=True)


def sha_bytes(value):
    import hashlib
    return hashlib.sha256(value).hexdigest()


def float_stages(raw,weights,scaler):
    # Independent float64 arithmetic of the NEW FP32 weights and precise training-only scaler.
    a=(np.asarray(raw,dtype=np.float64)-np.array(scaler['mean']))/np.array(scaler['scale']);result=[a]
    for w in weights:
        a=np.array(w,dtype=np.float64)@a;result.append(a)
        if len(a)!=2:a=np.maximum(0,a);result.append(a)
    return {n:a.tolist() for n,a in zip(STAGES,result)}


def compare(out):
    frozen(out);q=read(out/'quantization.json');assert q['status']=='PASS'
    assert not (out/'comparison.json').exists(),'Never retune/overwrite an evaluated test comparison'
    source=Model.load(out/'model/mlp_params.bpf.h');layer=LayerModel.load(out/'model/calibrated.json',out/'model/mlp_params.bpf.h')
    exact=ExactModel(source);refs={'xdp_q16':source,'tc_q16':source,'tc_layer_specific':layer}
    hosts={m:Host(out/'.output'/(m+'.so'),m=='xdp_q16') for m in MODES}
    test=load_numeric(out/'test.npz');fp=[json.loads(s) for s in gzip.open(out/'fp32-predictions.jsonl.gz','rt')]
    assert [r['row_index'] for r in fp]==test['indices'].tolist()
    params=load_numeric(out/'checkpoint.npz');weights=[params[f'model.{i}.weight'] for i in (0,2,4)]
    scaler=read(out/'scaler.json');model=__import__('pipeline').checked_model(out)
    predictions={m:[] for m in MODES};invalid={m:Counter() for m in MODES};ties=Counter();mismatch=0
    # Errors versus actual PyTorch FP32 stages, float64 checkpoint network, exact rational header network.
    errors={m:{ref:{s:dict(sum_abs=0.,max_abs=0.,values=0) for s in STAGES} for ref in ('fp32','float64_checkpoint','exact_header')} for m in MODES}
    aligned={s:dict(different_values=0,values=0) for s in STAGES}
    import torch
    batch=[]
    with torch.no_grad():
        value=torch.tensor([r['normalized_fp32'] for r in fp],dtype=torch.float32);batch.append(value.numpy().copy())
        for mod in model.model:
            value=mod(value);batch.append(value.numpy().copy())
    assert np.array_equal(batch[-1],np.array([r['logits'] for r in fp],dtype=np.float32))
    with gzip.open(out/'integer-predictions.jsonl.gz','wt') as stream:
        for pos,(index,raw,y) in enumerate(zip(test['indices'],test['features'],test['labels'])):
            raw=raw.tolist();base_fp=fp[pos]
            torch_values={n:v[pos].tolist() for n,v in zip(STAGES,batch)}
            floating=float_stages(raw,weights,scaler);exnums,exdens,_=exact.infer(raw)
            record=dict(row_index=int(index),features=raw,truth=int(y),fp32_prediction=base_fp['prediction'],modes={});actual={}
            for mode in MODES:
                issues=[]
                try:
                    expected,label=refs[mode].infer(raw,issues)
                    if issues:raise ArithmeticFailure('static_arithmetic_event',str(issues))
                    vals,observed=hosts[mode].infer(raw)
                    assert vals==expected and observed==label,(int(index),mode,'C/Python mismatch')
                    actual[mode]=vals;predictions[mode].append(label);exponents=layer.exponents if mode=='tc_layer_specific' else [16]*6
                    ties[mode]+=vals['logits'][0]==vals['logits'][1]
                    for stage,e in zip(STAGES,exponents):
                        actual_real=np.array(vals[stage],dtype=np.float64)/(1<<e)
                        exact_real=[n/exdens[stage] for n in exnums[stage]]
                        for ref,values in [('fp32',torch_values[stage]),('float64_checkpoint',floating[stage]),('exact_header',exact_real)]:
                            delta=np.abs(actual_real-np.array(values));d=errors[mode][ref][stage]
                            d['sum_abs']+=float(np.sum(delta));d['max_abs']=max(d['max_abs'],float(np.max(delta)));d['values']+=len(delta)
                    record['modes'][mode]=dict(status='PASS',prediction=label,logits=vals['logits'],exponents=exponents,tensors=vals)
                except ArithmeticFailure as err:
                    predictions[mode].append(None);invalid[mode][err.code]+=1
                    record['modes'][mode]=dict(status='FAIL',prediction=None,error=str(err),code=err.code)
            if 'xdp_q16' in actual and 'tc_q16' in actual:
                assert actual['xdp_q16']==actual['tc_q16'],('Q16 difference',int(index))
            if 'tc_q16' in actual and 'tc_layer_specific' in actual:
                for stage,e in zip(STAGES,layer.exponents):
                    # Exact comparison at common binary scale; integer-only to avoid float ambiguity.
                    a=actual['tc_q16'][stage];b=actual['tc_layer_specific'][stage]
                    aligned[stage]['different_values']+=sum((int(x)<<e)!=(int(z)<<16) for x,z in zip(a,b));aligned[stage]['values']+=len(a)
            stream.write(json.dumps(record,separators=(',',':'))+'\n')
            if pos%500==0:print('Compared fresh model row',pos,'/',len(test['indices']),flush=True)
    result=dict(status='PASS',execution='HOST-C original XDP arithmetic and actual TC inference stages; NO kernel execution',
        input_count=len(test['indices']),test_row_ids=test['indices'].tolist(),new_checkpoint_sha256=sha(out/'checkpoint.npz'),
        header_sha256=q['header_sha256'],calibration_sha256=q['calibration_sha256'],q16_tensor_mismatch_rows=0,modes={},
        fp32_q16_changes=sum(p is not None and p!=r['prediction'] for p,r in zip(predictions['tc_q16'],fp)),
        q16_layer_changes=sum(a is not None and b is not None and a!=b for a,b in zip(predictions['tc_q16'],predictions['tc_layer_specific'])),
        q16_layer_scaled_tensor_differences=aligned)
    common=[i for i in range(len(fp)) if all(predictions[m][i] is not None for m in MODES)];result['common_valid_count']=len(common)
    truth=test['labels'].tolist()
    for m in MODES:
        for ref in errors[m].values():
            for stage,v in ref.items():v['mean_abs']=v.pop('sum_abs')/v['values'] if v['values'] else None
        result['modes'][m]=dict(metrics=metrics(truth,predictions[m]),common_valid_metrics=metrics([truth[i] for i in common],[predictions[m][i] for i in common]),
            rejection_reasons=dict(invalid[m]),ties=ties[m],errors_vs_fp32=errors[m]['fp32'],errors_vs_float64_checkpoint=errors[m]['float64_checkpoint'],
            errors_vs_exact_rational_header=errors[m]['exact_header'])
    rows=[json.loads(s) for s in gzip.open(out/'integer-predictions.jsonl.gz','rt')]
    for m in MODES:assert metrics([r['truth'] for r in rows],[r['modes'][m]['prediction'] for r in rows])==result['modes'][m]['metrics']
    result['numerical_comparisons']=dict(records=sum(sum(p is not None for p in predictions[m]) for m in MODES),
        stage_tensors=6*sum(sum(p is not None for p in predictions[m]) for m in MODES),
        integers=136*sum(sum(p is not None for p in predictions[m]) for m in MODES))
    result['prediction_archive_sha256']=sha(out/'integer-predictions.jsonl.gz');result['preservation']=preservation()
    write(out/'comparison.json',result);print(json.dumps({k:v for k,v in result.items() if k not in ('test_row_ids','modes')},indent=2),flush=True)
