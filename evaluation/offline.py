#!/usr/bin/env python3
"""Three-way HOST-C model comparison; no packet processing or kernel claims."""
import argparse
from collections import Counter
import ctypes as C
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
from evaluation.data import reproduction,digest
from evaluation.metrics import binary_metrics
from validation.reference import Model,STAGES,SIZES
from quantization.reference import LayerModel,ExactModel,ArithmeticFailure
from quantization.calibrate import split

MODES=('xdp_q16','tc_q16','tc_layer_specific')


class Host:
    def __init__(self,path,original=False):
        self.lib=C.CDLL(str(path));self.original=original
        if original:
            self.lib.native_reset();self.fn=self.lib.native_mlp
            self.fn.argtypes=[C.POINTER(C.c_int64),C.POINTER(C.c_int32)];self.fn.restype=C.c_int
        else:
            self.fn=self.lib.vector_infer;self.fn.argtypes=[C.POINTER(C.c_int64),C.POINTER(C.c_int32),C.POINTER(C.c_int32)];self.fn.restype=C.c_int

    def infer(self,raw):
        x=(C.c_int64*6)(*raw);out=(C.c_int32*192)();label=C.c_int32()
        if self.original:label.value=self.fn(x,out)
        elif self.fn(x,out,C.byref(label)):raise ArithmeticFailure('rejected','TC host chain did not publish a complete result')
        return {n:list(out[i*32:i*32+k]) for i,(n,k) in enumerate(zip(STAGES,SIZES))},label.value


def run(args):
    out=args.output;out.mkdir(parents=True,exist_ok=False);build=out/'.output';build.mkdir()
    for mode in MODES:
        source=ROOT/('validation/native.c' if mode=='xdp_q16' else 'evaluation/tc_vectors.c')
        include=ROOT/('validation/include' if mode=='xdp_q16' else 'tc/tests/include')
        argv=[args.compiler,'-O3','-shared','-fPIC','-pthread','-I'+str(include),'-I'+str(ROOT/'validation/include')]
        if mode=='tc_layer_specific':argv+=['-DIDS_LAYER_SPECIFIC']
        argv += [str(source),'-o',str(build/(mode+'.so'))]
        p=subprocess.run(argv,capture_output=True,text=True);(out/(mode+'-build.log')).write_text(p.stdout+p.stderr)
        with (out/'commands.jsonl').open('a') as f:f.write(json.dumps(dict(argv=argv,exit_code=p.returncode))+'\n')
        if p.returncode:raise RuntimeError('Host build failed: '+mode)
    rows,labels=reproduction(ROOT);indices=list(range(len(rows))) if args.split=='all' else split(rows)[1]
    base=Model.load(ROOT/'src/mlp_params.bpf.h');layer=LayerModel.load();exact=ExactModel(base)
    hosts={m:Host(build/(m+'.so'),m=='xdp_q16') for m in MODES}
    refs={'xdp_q16':base,'tc_q16':base,'tc_layer_specific':layer}
    summaries={m:dict(valid=0,invalid=0,predictions=[],errors={s:dict(sum_abs=0.,max_abs=0.,values=0) for s in STAGES}) for m in MODES}
    eligible_truth=[];samples=[];q16_differences=flips=0;encoded=Counter()
    with gzip.open(out/'predictions.jsonl.gz','wt') as f:
        for position,i in enumerate(indices):
            raw=rows[i];truth=labels[i];eligible_truth.append(truth);encoded[truth]+=1
            numerators,denominators,_=exact.infer(raw);record=dict(row_index=i,features=raw,encoded_label=truth,configurations={})
            actual={}
            for mode in MODES:
                issues=[]
                try:
                    expected,y=refs[mode].infer(raw,issues)
                    if issues:raise ArithmeticFailure('unsafe','Q16 arithmetic events: '+str(issues))
                    values,label=hosts[mode].infer(raw)
                    if values!=expected or label!=y:raise AssertionError(f'{mode} tensor mismatch row {i}')
                    actual[mode]=values;summary=summaries[mode];summary['valid']+=1;summary['predictions'].append(label)
                    exps=layer.exponents if mode=='tc_layer_specific' else [16]*6
                    for s,q in zip(STAGES,exps):
                        for v,n in zip(values[s],numerators[s]):
                            error=abs(v*denominators[s]-(n<<q))/(denominators[s]*(1<<q))
                            e=summary['errors'][s];e['sum_abs']+=error;e['max_abs']=max(e['max_abs'],error);e['values']+=1
                    record['configurations'][mode]=dict(status='PASS',label=label,logits=values['logits'],q_logits=exps[-1],
                        stage_sha256={s:hashlib.sha256(struct.pack('<'+'i'*len(values[s]),*values[s])).hexdigest() for s in STAGES})
                except ArithmeticFailure as error:
                    summaries[mode]['invalid']+=1;summaries[mode]['predictions'].append(None)
                    record['configurations'][mode]=dict(status='FAIL',error=str(error),label=None)
            if 'xdp_q16' in actual and 'tc_q16' in actual and actual['xdp_q16']!=actual['tc_q16']:q16_differences+=1
            if summaries['xdp_q16']['predictions'][-1]!=summaries['tc_layer_specific']['predictions'][-1]:flips+=1
            f.write(json.dumps(record,separators=(',',':'))+'\n')
            if len(samples)<3:samples.append(dict(record=record,intermediate_tensors=actual))
            if position%2000==0:print(f'Host model rows {position}/{len(indices)}',flush=True)
    common=[i for i in range(len(indices)) if all(summaries[m]['predictions'][i] is not None for m in MODES)]
    for mode,r in summaries.items():
        predicted=r.pop('predictions');r['coverage']=r['valid']/len(indices);r['class_counts']=dict(Counter(p for p in predicted if p is not None))
        if args.encoded_label_diagnostics:
            r['supplied_code_label_diagnostics']=binary_metrics([eligible_truth[i] for i in common],[predicted[i] for i in common])
            r['diagnostic_scope']='Scores supplied numeric labels under paper coding; collection labels and model training overlap unverified. NOT independent detection effectiveness.'
        for v in r['errors'].values():v['mean_abs']=v.pop('sum_abs')/v['values'] if v['values'] else None
    result=dict(status='PASS',execution='Host-compiled original XDP and actual TC C arithmetic; NO kernel execution or live packet evaluation',
        dataset='Checked-in reproduction numeric arrays',split=args.split,input_count=len(indices),encoded_support=dict(encoded),common_eligible_cases=len(common),
        excluded_from_common=len(indices)-len(common),checkpoint_sha256=digest(ROOT/'src/mlp_params.bpf.h'),
        preprocessing='Unchanged rounded header scaler; no fitting or retraining',
        q16_tensor_differences=q16_differences,layer_specific_prediction_changes=flips,
        numerical_reference='Exact rational reconstruction of Q16 header; not original FP32',configurations=summaries,
        independently_labeled_intrusion_metrics=dict(status='NOT RUN',accuracy=None,precision=None,recall=None,f1=None,
            reason='No independently verified collection/split provenance; CIC feature/checkpoint compatibility not established'),
        split_warning='Scaling-heldout excludes offline scale-calibration vectors, NOT necessarily original model training rows',
        paper_reference=dict(cic_offline=dict(accuracy=.974,f1=.933),reproduction_realtime=dict(accuracy=.994,f1=.992),scope='Published Table V values; unequal protocol, not our results'))
    (out/'metrics.json').write_text(json.dumps(result,indent=2)+'\n');(out/'samples.json').write_text(json.dumps(samples,indent=2)+'\n')
    (out/'REPORT.md').write_text('# Three-way model-level comparison\n\nHOST execution only. Independently labeled effectiveness: NOT RUN.\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n')
    print(json.dumps({k:v for k,v in result.items() if k!='configurations'},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--compiler',default='clang-12')
    p.add_argument('--split',choices=('all','scaling-heldout'),default='scaling-heldout')
    p.add_argument('--encoded-label-diagnostics',action='store_true',help='Explicitly score supplied codes; never claim independently labeled held-out F1')
    run(p.parse_args())
