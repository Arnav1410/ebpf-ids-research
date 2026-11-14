"""Independent confusion-count formulas cross-checked with scikit-learn."""
import math
import numpy as np
from sklearn import metrics as sk


def divide(a,b):return float(a/b) if b else None


def scores_from_counts(tn,fp,fn,tp):
    recall=divide(tp,tp+fn);specificity=divide(tn,tn+fp)
    denominator=math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return dict(TN=int(tn),FP=int(fp),FN=int(fn),TP=int(tp),confusion_matrix=[[int(tn),int(fp)],[int(fn),int(tp)]],
        accuracy=divide(tp+tn,tp+tn+fp+fn),precision=divide(tp,tp+fp),recall=recall,
        f1=divide(2*tp,2*tp+fp+fn),specificity=specificity,false_positive_rate=divide(fp,fp+tn),
        balanced_accuracy=(recall+specificity)/2 if recall is not None and specificity is not None else None,
        mcc=divide(tp*tn-fp*fn,denominator))


def independent_pr(y,score):
    order=np.argsort(-score,kind='stable');v=y[order];s=score[order]
    ends=np.r_[np.flatnonzero(s[1:]!=s[:-1]),len(s)-1]
    tp=np.cumsum(v,dtype=np.int64)[ends];precision=tp/(ends+1)
    if not tp[-1]:return None,None
    recall=tp/tp[-1]
    ap=float(np.sum(np.diff(np.r_[0.,recall])*precision))
    area=float(np.trapezoid(np.r_[1.,precision],np.r_[0.,recall]))
    return ap,area


def classification(y,prediction,score=None):
    y=np.asarray(y,dtype=np.int64);raw=np.asarray(prediction,dtype=object)
    if len(y)!=len(raw) or not np.isin(y,[0,1]).all():raise ValueError('Invalid truth/length')
    valid=np.array([p is not None and p in (0,1) for p in raw],dtype=bool)
    v=y[valid];p=np.array(raw[valid],dtype=np.int64)
    tn=int(((v==0)&(p==0)).sum());fp=int(((v==0)&(p==1)).sum())
    fn=int(((v==1)&(p==0)).sum());tp=int(((v==1)&(p==1)).sum())
    result=scores_from_counts(tn,fp,fn,tp)
    result.update(input_count=len(y),valid_predictions=int(valid.sum()),missing_invalid=int((~valid).sum()),
        coverage=divide(valid.sum(),len(y)),support={str(k):int((y==k).sum()) for k in (0,1)},
        scored_support={str(k):int((v==k).sum()) for k in (0,1)},
        missing_by_class={str(k):int(((y==k)&~valid).sum()) for k in (0,1)},
        average_precision=None,pr_auc_trapezoidal=None)
    if len(v):
        assert sk.confusion_matrix(v,p,labels=[0,1]).tolist()==result['confusion_matrix']
        checks=dict(accuracy=sk.accuracy_score(v,p),precision=sk.precision_score(v,p,zero_division=0),
            recall=sk.recall_score(v,p,zero_division=0),f1=sk.f1_score(v,p,zero_division=0))
        if result['mcc'] is not None:checks['mcc']=sk.matthews_corrcoef(v,p)
        if result['balanced_accuracy'] is not None:checks['balanced_accuracy']=sk.balanced_accuracy_score(v,p)
        for name,value in checks.items():
            if result[name] is not None:assert math.isclose(result[name],float(value),abs_tol=1e-12,rel_tol=1e-12),(name,result[name],value)
    if score is not None and len(v) and tp+fn:
        s=np.asarray(score,dtype=np.float64)
        if len(s)!=len(y) or not np.isfinite(s).all():raise ValueError('Invalid PR scores')
        s=s[valid];ap,area=independent_pr(v,s)
        result['average_precision']=float(sk.average_precision_score(v,s))
        precision,recall,_=sk.precision_recall_curve(v,s)
        result['pr_auc_trapezoidal']=float(sk.auc(recall,precision))
        assert math.isclose(ap,result['average_precision'],abs_tol=1e-12)
        assert math.isclose(area,result['pr_auc_trapezoidal'],abs_tol=1e-12)
    return result


def paired_bootstrap(y,a,b,group_id,draws=2000,seed=20261110):
    _,which=np.unique(group_id,return_inverse=True);g=int(which.max())+1
    counts=[]
    for p in (a,b):
        matrix=np.zeros((g,4),dtype=np.int64)
        bins=(2*np.asarray(y)+np.asarray(p)).astype(np.int64)
        np.add.at(matrix,(which,bins),1);counts.append(matrix)
    rng=np.random.default_rng(seed);deltas=[]
    for _ in range(draws):
        sample=rng.integers(g,size=g)
        f=[]
        for matrix in counts:
            tn,fp,fn,tp=map(int,matrix[sample].sum(0));f.append(divide(2*tp,2*tp+fp+fn))
        if all(x is not None for x in f):deltas.append(f[1]-f[0])
    if not deltas:raise ValueError('No defined bootstrap F1 draws')
    return dict(method='Paired test union-component percentile bootstrap',groups=g,draws=draws,valid_draws=len(deltas),seed=seed,
        f1_difference_95_percentile=np.percentile(deltas,[2.5,97.5]).tolist(),
        percentage_point_95_percentile=(100*np.percentile(deltas,[2.5,97.5])).tolist(),
        limitation='Conditional on frozen models and imperfect proxy groups; residual campaign correlation and training-seed variability are not covered.')
