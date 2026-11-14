"""Threshold selection functions accept validation arrays, never a test dataset."""
import math
import numpy as np


def margins(logits):
    logits=np.asarray(logits)
    if logits.ndim!=2 or logits.shape[1]!=2 or not np.isfinite(logits).all():
        raise ValueError('Expected finite two-logit rows')
    return logits[:,1].astype(np.float64)-logits[:,0].astype(np.float64)


def sigmoid(value):
    x=np.asarray(value,dtype=np.float64);out=np.empty_like(x)
    positive=x>=0
    out[positive]=1/(1+np.exp(-x[positive]))
    e=np.exp(x[~positive]);out[~positive]=e/(1+e)
    return out


def apply_threshold(score,threshold):
    score=np.asarray(score,dtype=np.float64)
    if not math.isfinite(threshold) or not np.isfinite(score).all():raise ValueError('Invalid score/threshold')
    return (score>=threshold).astype(np.int64)


def choose_threshold(truth,score):
    raw=np.asarray(truth)
    if not np.isin(raw,[0,1]).all():raise ValueError('Invalid binary validation labels')
    truth=raw.astype(np.int64);score=np.asarray(score,dtype=np.float64)
    if truth.shape!=score.shape or truth.ndim!=1 or not len(truth) or set(truth.tolist())!={0,1}:
        raise ValueError('Validation must have matching arrays and both binary classes')
    if not np.isfinite(score).all():raise ValueError('Nonfinite validation scores')
    order=np.argsort(-score,kind='stable');s=score[order];y=truth[order]
    ends=np.r_[np.flatnonzero(s[1:]!=s[:-1]),len(s)-1]
    tp=np.cumsum(y,dtype=np.int64)[ends];fp=ends+1-tp
    fn=int(truth.sum())-tp;tn=len(y)-int(truth.sum())-fp
    thresholds=s[ends]
    # Include all-negative without Infinity in saved JSON or decision inputs.
    thresholds=np.r_[np.nextafter(s[0],np.inf),thresholds]
    tp=np.r_[0,tp];fp=np.r_[0,fp];fn=np.r_[int(truth.sum()),fn];tn=np.r_[len(y)-int(truth.sum()),tn]
    best=0
    for i in range(1,len(thresholds)):
        a,b=int(2*tp[i]),int(2*tp[best])
        da,db=int(2*tp[i]+fp[i]+fn[i]),int(2*tp[best]+fp[best]+fn[best])
        left,right=a*db,b*da
        if left>right or left==right and (fp[i]<fp[best] or fp[i]==fp[best] and thresholds[i]>thresholds[best]):
            best=i
    curve=dict(threshold=thresholds,TP=tp,FP=fp,FN=fn,TN=tn,
               f1=(2*tp)/(2*tp+fp+fn))
    return float(thresholds[best]),best,curve
