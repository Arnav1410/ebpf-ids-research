"""Independent binary counts/formulas, explicitly cross-checked with sklearn."""
from collections import Counter
import math


def metrics(truth, predictions, crosscheck=True):
    if len(truth) != len(predictions) or any(type(y) is not int or y not in (0, 1) for y in truth):
        raise ValueError("Invalid/alignment-ambiguous labeled cohort")
    if any(p is not None and (type(p) is not int or p not in (0, 1)) for p in predictions):
        raise ValueError("Invalid prediction code")
    valid = [(y, p) for y, p in zip(truth, predictions) if p is not None]
    counts = Counter(valid)
    tn, fp, fn, tp = (counts[pair] for pair in ((0, 0), (0, 1), (1, 0), (1, 1)))
    def ratio(a, b):
        return a / b if b else None
    recall = ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    result = dict(input_count=len(truth), valid_predictions=len(valid),
                  missing_predictions=len(truth) - len(valid),
                  missing_by_class=dict(Counter(y for y, p in zip(truth, predictions) if p is None)),
                  class_support=dict(Counter(truth)), scored_class_support=dict(Counter(y for y, p in valid)),
                  classification_coverage=ratio(len(valid), len(truth)),
                  TP=tp, FP=fp, TN=tn, FN=fn, confusion_matrix=[[tn, fp], [fn, tp]],
                  accuracy=ratio(tp + tn, len(valid)), precision=ratio(tp, tp + fp), recall=recall,
                  specificity=specificity, false_positive_rate=ratio(fp, fp + tn),
                  f1=ratio(2 * tp, 2 * tp + fp + fn),
                  balanced_accuracy=(recall + specificity) / 2 if recall is not None and specificity is not None else None,
                  mcc=(tp * tn - fp * fn) / math.sqrt(denominator) if denominator else None,
                  mcc_zero_denominator=not bool(denominator),
                  denominator_policy="Metrics conditional on valid predictions; missing predictions remain abstentions. Undefined denominators are null.")
    if crosscheck and valid:
        import sklearn
        from sklearn import metrics as sk
        y, p = map(list, zip(*valid))
        matrix = sk.confusion_matrix(y, p, labels=[0, 1]).tolist()
        if matrix != result["confusion_matrix"]:
            raise AssertionError("Independent/sklearn confusion matrices differ")
        values = dict(accuracy=sk.accuracy_score(y, p),
                      precision=sk.precision_score(y, p, zero_division=0),
                      recall=sk.recall_score(y, p, zero_division=0),
                      f1=sk.f1_score(y, p, zero_division=0),
                      mcc=sk.matthews_corrcoef(y, p))
        if recall is not None and specificity is not None:
            values["balanced_accuracy"] = sk.balanced_accuracy_score(y, p)
        for name, value in values.items():
            if result[name] is not None and not math.isclose(result[name], float(value), abs_tol=1e-12):
                raise AssertionError("Independent/sklearn metric differs: " + name)
        # sklearn uses zero for several undefined ratios. Preserve nulls in our
        # result rather than silently converting an undefined metric to a score.
        result["sklearn_crosscheck"] = dict(status="PASS", version=sklearn.__version__, values={k:float(v) for k,v in values.items()},
                                            undefined_convention="sklearn zeros may correspond to explicitly null undefined ratios")
    else:
        result["sklearn_crosscheck"] = dict(status="NOT RUN", reason="No valid predictions" if not valid else "Explicitly disabled")
    return result
