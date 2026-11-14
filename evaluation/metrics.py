"""Metrics for explicitly mapped binary labels; missing predictions are abstentions."""
from collections import Counter


def binary_metrics(truth,predicted):
    if len(truth)!=len(predicted):raise ValueError('Unaligned metric inputs')
    if any(y not in (0,1,None) for y in truth) or any(p not in (0,1,None) for p in predicted):raise ValueError('Invalid binary label')
    known=[(y,p) for y,p in zip(truth,predicted) if y is not None];valid=[(y,p) for y,p in known if p is not None]
    counts=Counter((y,p) for y,p in valid);tp,fp,tn,fn=(counts[k] for k in ((1,1),(0,1),(0,0),(1,0)))
    support=Counter(y for y,p in known);both=bool(support[0] and support[1])
    return dict(input_count=len(truth),labeled_cases=len(known),unknown_truth=len(truth)-len(known),scored_cases=len(valid),
        missing_invalid_predictions=len(known)-len(valid),classification_coverage=len(valid)/len(known) if known else None,
        support=dict(support),TP=tp,FP=fp,TN=tn,FN=fn,
        accuracy=(tp+tn)/len(valid) if valid else None,
        precision=tp/(tp+fp) if both and tp+fp else None,
        recall=tp/(tp+fn) if both and tp+fn else None,
        f1=2*tp/(2*tp+fp+fn) if both and 2*tp+fp+fn else None,
        benign_false_positive_rate=fp/(fp+tn) if fp+tn else None,
        metric_basis='Conditional on valid predictions; abstentions reported separately. Intrusion precision/recall/F1 withheld for single-class truth.')
