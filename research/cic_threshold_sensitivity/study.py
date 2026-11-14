"""Separate selection and one-time test application; never trains an NN."""
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path
import platform
import numpy as np
from sklearn.metrics import roc_auc_score,precision_recall_curve

from research.cic_csv_mlp.common import ROOT,sha,read,write,verify_hashes,archive,freeze
from research.cic_csv_mlp.metrics import classification,paired_bootstrap
from .core import margins,sigmoid,apply_threshold,choose_threshold

HERE=Path(__file__).resolve().parent
MODES=('forward','bidirectional')


def score_summary(truth,score,threshold):
    result={}
    for label in (0,1):
        values=score[truth==label]
        result[str(label)]=dict(count=len(values),minimum=float(values.min()),maximum=float(values.max()),
            mean=float(values.mean()),population_std=float(values.std()),
            margin_percentiles={str(q):float(v) for q,v in zip((1,5,25,50,75,95,99),np.percentile(values,[1,5,25,50,75,95,99]))},
            softmax_percentiles={str(q):float(v) for q,v in zip((1,5,25,50,75,95,99),np.percentile(sigmoid(values),[1,5,25,50,75,95,99]))},
            margin_at_or_below_zero=int((values<=0).sum()),above_zero=int((values>0).sum()),
            at_or_above_selected=int((values>=threshold).sum()),below_selected=int((values<threshold).sum()))
    result['roc_auc']=float(roc_auc_score(truth,score))
    return result


def verify_source(source):
    for name in ('data-freeze.json','split-freeze.json','models-freeze.json'):verify_hashes(source,name)
    for mode in MODES:verify_hashes(source/mode,'freeze.json')
    verify_hashes(source/'evaluation','freeze.json')


def snapshot(source):
    paths=[p for p in source.parent.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    paths.append(ROOT/'CIC_FORWARD_VS_BIDIRECTIONAL_MLP.md')
    return {str(p.relative_to(ROOT)):sha(p) for p in sorted(set(paths))}


def selector_code():
    return {str(p.relative_to(ROOT)):sha(p) for p in (HERE/'core.py',HERE/'study.py',HERE/'PROTOCOL.json')}


def select(source,out):
    source=source.resolve();out.mkdir(parents=True,exist_ok=False);verify_source(source)
    write(out/'PROTOCOL.json',read(HERE/'PROTOCOL.json'))
    write(out/'source_snapshot.json',snapshot(source))
    write(out/'selector_code.json',selector_code())
    # Only validation label/ID keys are parsed in this process. Frozen test
    # files are hashed for preservation, never opened as arrays for selection.
    with np.load(source/'validation.npz',allow_pickle=False) as a:
        y=a['labels'].copy();indices=a['indices'].copy();lines=a['source_lines'].copy()
    result=dict(source_run=str(source),objective='Maximum binary validation F1; exact-rational ties: fewer FP, then largest threshold',
        score='float64(logit1)-float64(logit0)',selected_rule='intrusion iff margin >= threshold',
        validation_count=len(y),validation_support={str(k):int((y==k).sum()) for k in (0,1)},models={},
        parsed_selection_inputs=['validation.npz:labels,indices,source_lines']+[m+'/validation_logits.npz:indices,logits' for m in MODES],
        test_arrays_parsed=False,test_labels_used_for_thresholds=False)
    arrays=dict(truth=y,indices=indices,source_lines=lines)
    for mode in MODES:
        data=archive(source/mode/'validation_logits.npz')
        assert data['logits'].dtype==np.float32 and np.array_equal(data['indices'],indices)
        score=margins(data['logits']);threshold,index,curve=choose_threshold(y,score)
        chosen=apply_threshold(score,threshold);argmax=(score>0).astype(np.int64)
        assert np.array_equal(argmax,data['logits'].argmax(1))
        metrics=classification(y,chosen,score)
        assert [metrics[k] for k in ('TP','FP','TN','FN')]==[int(curve[k][index]) for k in ('TP','FP','TN','FN')]
        # Independent sklearn threshold sweep is validation-only too.
        precision,recall,_=precision_recall_curve(y,score)
        f1=np.divide(2*precision*recall,precision+recall,out=np.zeros_like(precision),where=(precision+recall)!=0)
        assert abs(metrics['f1']-float(f1.max()))<1e-12
        np.savez_compressed(out/(mode+'-validation-curve.npz'),**curve)
        result['models'][mode]=dict(threshold=threshold,threshold_hex=threshold.hex(),
            softmax_threshold_display=float(sigmoid(threshold)),candidate_count=len(curve['threshold']),selected_candidate_index=index,
            validation_argmax=classification(y,argmax,score),validation_selected=metrics,
            validation_score_distribution=score_summary(y,score,threshold),
            checkpoint_sha256=sha(source/mode/'checkpoint.npz'),scaler_sha256=sha(source/mode/'scaler.npz'),
            validation_logits_sha256=sha(source/mode/'validation_logits.npz'))
        arrays[mode+'_margin']=score;arrays[mode+'_argmax']=argmax;arrays[mode+'_selected']=chosen
    np.savez_compressed(out/'validation_decisions.npz',**arrays)
    write(out/'thresholds.json',result)
    freeze(out,'THRESHOLDS_FROZEN.json',['thresholds.json','PROTOCOL.json','source_snapshot.json','selector_code.json',
        'validation_decisions.npz','forward-validation-curve.npz','bidirectional-validation-curve.npz'],
        test_arrays_parsed=False,test_evaluation_started=False)
    print(json.dumps({m:{k:result['models'][m][k] for k in ('threshold','threshold_hex','softmax_threshold_display','validation_argmax','validation_selected')} for m in MODES},indent=2),flush=True)


def evaluate(out):
    verify_hashes(out,'THRESHOLDS_FROZEN.json')
    if read(out/'selector_code.json')!=selector_code():raise ValueError('Frozen selector implementation changed')
    selection=read(out/'thresholds.json');source=Path(selection['source_run']);verify_source(source)
    for name,h in read(out/'source_snapshot.json').items():
        if sha(ROOT/name)!=h:raise ValueError('Original artifact changed: '+name)
    # Exclusive marker is created BEFORE test arrays are parsed.
    write(out/'TEST_APPLICATION_STARTED.json',dict(threshold_freeze_sha256=sha(out/'THRESHOLDS_FROZEN.json'),
          selected_thresholds_fixed=True,test_source_sha256=sha(source/'evaluation/predictions.npz'),
          application_count_planned_per_model=1))
    data=archive(source/'evaluation/predictions.npz')
    y=data['truth'];indices=data['indices'];lines=data['source_lines']
    old=read(source/'evaluation/metrics.json');result=dict(scope='POST-HOC validation-threshold sensitivity on reused frozen CSV test set',
        test_count=len(y),test_support={str(k):int((y==k).sum()) for k in (0,1)},
        threshold_freeze_sha256=sha(out/'THRESHOLDS_FROZEN.json'),source_test_sha256=sha(source/'evaluation/predictions.npz'),
        threshold_selection_used_test_labels=False,threshold_application_count_per_model=1,models={})
    arrays=dict(truth=y,indices=indices,source_lines=lines,group_id=data['group_id'])
    for mode in MODES:
        threshold=float.fromhex(selection['models'][mode]['threshold_hex'])
        assert threshold==selection['models'][mode]['threshold']
        score=margins(data[mode+'_logits'])
        assert np.array_equal(score,data[mode+'_margin'])
        before=(score>0).astype(np.int64);after=apply_threshold(score,threshold)
        assert np.array_equal(before,data[mode+'_prediction'])
        base=classification(y,before,score);selected=classification(y,after,score)
        assert base==old['models'][mode]['metrics']
        counts=dict(predictions_changed=int((before!=after).sum()),
            original_false_negatives_recovered=int(((y==1)&(before==0)&(after==1)).sum()),
            original_true_positives_lost=int(((y==1)&(before==1)&(after==0)).sum()),
            additional_false_positives=int(((y==0)&(before==0)&(after==1)).sum()),
            original_false_positives_removed=int(((y==0)&(before==1)&(after==0)).sum()))
        counts['fraction_original_FN_recovered']=counts['original_false_negatives_recovered']/base['FN'] if base['FN'] else None
        result['models'][mode]=dict(threshold=threshold,softmax_threshold_display=selection['models'][mode]['softmax_threshold_display'],
            argmax=base,validation_selected_threshold=selected,changes=counts,
            f1_change_percentage_points=100*(selected['f1']-base['f1']),recall_change_percentage_points=100*(selected['recall']-base['recall']),
            test_score_distribution=score_summary(y,score,threshold))
        arrays[mode+'_margin']=score;arrays[mode+'_argmax']=before;arrays[mode+'_selected']=after
    result['paired_selected_thresholds']=dict(
        f1_B_minus_A_percentage_points=100*(result['models']['bidirectional']['validation_selected_threshold']['f1']-result['models']['forward']['validation_selected_threshold']['f1']),
        bootstrap=paired_bootstrap(y,arrays['forward_selected'],arrays['bidirectional_selected'],data['group_id'],seed=20261111))
    lookup={int(i):j for j,i in enumerate(indices)};categories=np.empty(len(indices),dtype=object)
    with gzip.open(source/'records.jsonl.gz','rt') as f:
        for i,line in enumerate(f):
            if i in lookup:
                row=json.loads(line);j=lookup[i]
                assert row['source_line']==int(lines[j]) and row['label']==int(y[j])
                categories[j]=row['category']
    assert all(isinstance(c,str) for c in categories)
    result['per_category']={}
    for mode in MODES:
        result['per_category'][mode]={}
        for category in sorted(set(categories)):
            mask=categories==category
            result['per_category'][mode][category]={
                'argmax':classification(y[mask],arrays[mode+'_argmax'][mask]),
                'selected':classification(y[mask],arrays[mode+'_selected'][mask])}
    np.savez_compressed(out/'test_decisions.npz',**arrays)
    with gzip.open(out/'test_decisions.csv.gz','xt',newline='') as f:
        writer=csv.writer(f);writer.writerow(['source_record_id','array_index','source_line','truth','category','group_id',
            'forward_margin','forward_argmax','forward_selected','bidirectional_margin','bidirectional_argmax','bidirectional_selected'])
        prefix=read(source/'protocol.json')['source_member_sha256']
        for j in range(len(y)):
            writer.writerow([prefix+':'+str(lines[j]),indices[j],lines[j],y[j],categories[j],data['group_id'][j]]+
                [arrays[mode+'_'+key][j] for mode in MODES for key in ('margin','argmax','selected')])
    write(out/'results.json',result)
    freeze(out,'RESULTS_FROZEN.json',['test_decisions.npz','test_decisions.csv.gz','results.json','TEST_APPLICATION_STARTED.json','THRESHOLDS_FROZEN.json'])
    print(json.dumps({m:{k:result['models'][m][k] for k in ('threshold','argmax','validation_selected_threshold','changes')} for m in MODES},indent=2),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('stage',choices=['select','evaluate','report','audit'])
    p.add_argument('--source',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve()
    if a.stage=='select':
        if a.source is None:p.error('--source is required for validation selection')
        select(a.source,out)
    elif a.stage=='evaluate':evaluate(out)
    else:
        from .report import report,audit
        {'report':report,'audit':audit}[a.stage](out)


if __name__=='__main__':main()
