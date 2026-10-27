"""Metrics use numeric classes; no benign/attack mapping is invented."""


def classification_metrics(labels, predictions):
    labels, predictions = list(labels), list(predictions)
    if not labels or len(labels) != len(predictions):
        raise ValueError("Expected equal, nonempty label and prediction sequences")
    matrix = [[0, 0], [0, 0]]
    for actual, predicted in zip(labels, predictions):
        if actual not in (0, 1) or predicted not in (0, 1):
            raise ValueError("Metrics require binary numeric labels and predictions")
        matrix[actual][predicted] += 1

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    classes = {}
    for label in (0, 1):
        tp, fn = matrix[label][label], matrix[label][1 - label]
        fp, tn = matrix[1 - label][label], matrix[1 - label][1 - label]
        classes[str(label)] = {"support": tp + fn, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                               "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
                               "f1": ratio(2 * tp, 2 * tp + fp + fn),
                               "false_positive_rate": ratio(fp, fp + tn)}
    f1s = [classes[str(label)]["f1"] for label in (0, 1)]
    return {"samples": len(labels), "predictions": len(predictions), "coverage": 1.0,
            "accuracy": (matrix[0][0] + matrix[1][1]) / len(labels),
            "confusion_matrix": {"rows": "actual [0,1]", "columns": "predicted [0,1]", "counts": matrix},
            "per_class": classes, "macro_f1": sum(f1s) / 2 if all(x is not None for x in f1s) else None,
            "undefined_metric_policy": "null when the denominator is zero",
            "label_mapping": {"0": "unverified", "1": "unverified"}}
