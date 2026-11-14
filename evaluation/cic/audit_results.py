#!/usr/bin/env python3
"""Recompute scores from saved predictions, with per-flow numerical diagnostics.

No C execution, training, source changes or network access. Original observed
prediction archive is preserved; diagnostics use separately verified references.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import math
from pathlib import Path

from evaluation.cic.reconstruct import fingerprint
from evaluation.cic.evaluate import tensor_hash
from evaluation.cic.metrics import metrics
from evaluation.offline import MODES
from validation.reference import Model, STAGES
from quantization.reference import LayerModel, ExactModel, ArithmeticFailure

ROOT = Path(__file__).resolve().parents[2]


def json_value(value):
    """Normalize integer dictionary keys as saved JSON does; retain values."""
    return json.loads(json.dumps(value))


def audit(args):
    saved = json.loads((args.results / "metrics.json").read_text())
    if fingerprint(args.cohort) != saved["cohort_sha256"]:
        raise ValueError("Cohort changed")
    if fingerprint(ROOT / "src/mlp_params.bpf.h") != saved["checkpoint_sha256"]:
        raise ValueError("Model changed")
    args.output.mkdir(parents=True, exist_ok=False)
    cohort = [json.loads(line) for line in args.cohort.read_text().splitlines()]
    static, layer = Model.load(ROOT / "src/mlp_params.bpf.h"), LayerModel.load()
    exact = ExactModel(static)
    truth, predicted = [], {mode: [] for mode in MODES}
    failures = {mode: Counter() for mode in MODES}
    domain_features = Counter()
    duplicates = Counter()
    per_mode_error = {mode: dict(total=0., maximum=0., integers=0) for mode in MODES}
    common_error = {mode: dict(total=0., maximum=0., integers=0) for mode in MODES}
    minimum_margin = {mode: None for mode in MODES}
    tensor_count = integer_count = 0
    raw_count = 0
    with gzip.open(args.results / "predictions.jsonl.gz", "rt") as source, gzip.open(args.output / "prediction-diagnostics.jsonl.gz", "wt") as dest:
        for raw_count, line in enumerate(source, 1):
            row = json.loads(line)
            record = cohort[raw_count - 1]
            for key in ("source_record_id", "features", "label", "category", "capture_day"):
                if row[key] != record[key]:
                    raise AssertionError("Saved prediction/cohort identity mismatch")
            truth.append(row["label"])
            duplicates[tuple(row["features"])] += 1
            numerators, denominators, _ = exact.infer(row["features"])
            diagnostic = dict(source_record_id=row["source_record_id"], configurations={})
            all_valid = all(row["configurations"][m]["prediction"] is not None for m in MODES)
            for mode in MODES:
                item = row["configurations"][mode]
                model = layer if mode == "tc_layer_specific" else static
                events = []
                try:
                    values, label = model.infer(row["features"], events)
                    if events:
                        raise ArithmeticFailure("unsafe_arithmetic", str(events))
                    if item["status"] != "PASS" or label != item["prediction"] or values["logits"] != item["logits"]:
                        raise AssertionError("Observed logits/label differ from rebuilt reference")
                    hashes = {stage: tensor_hash(values[stage]) for stage in STAGES}
                    if hashes != item["stage_sha256"] or hashes != item["reference_stage_sha256"]:
                        raise AssertionError("Observed/reference intermediate hashes differ")
                    exponents = layer.exponents if mode == "tc_layer_specific" else [16] * 6
                    stage_errors = {}
                    for stage, q in zip(STAGES, exponents):
                        errors = [abs(v * denominators[stage] - (n << q)) / (denominators[stage] * (1 << q))
                                  for v, n in zip(values[stage], numerators[stage])]
                        stage_errors[stage] = dict(mean_absolute=sum(errors) / len(errors), maximum_absolute=max(errors))
                    logit_errors = [abs(v * denominators["logits"] - (n << exponents[-1])) / (denominators["logits"] * (1 << exponents[-1]))
                                    for v, n in zip(values["logits"], numerators["logits"])]
                    for summary in (per_mode_error[mode], common_error[mode] if all_valid else None):
                        if summary is not None:
                            summary["total"] += sum(logit_errors)
                            summary["maximum"] = max(summary["maximum"], max(logit_errors))
                            summary["integers"] += 2
                    margin = abs(values["logits"][0] - values["logits"][1])
                    if minimum_margin[mode] is None or margin < minimum_margin[mode]["raw_margin"]:
                        minimum_margin[mode] = dict(source_record_id=row["source_record_id"], raw_margin=margin,
                            scaled_margin=margin/(1 << exponents[-1]), logits=values["logits"], label=label)
                    diagnostic["configurations"][mode] = dict(status="PASS", stage_errors=stage_errors,
                        exact_header_logit_values=[n / denominators["logits"] for n in numerators["logits"]],
                        observed_scaled_logit_values=[v/(1 << exponents[-1]) for v in values["logits"]],
                        absolute_logit_errors=logit_errors)
                    tensor_count += 6
                    integer_count += sum(map(len, values.values()))
                except ArithmeticFailure as error:
                    if item["prediction"] is not None or item["status"] != "FAIL":
                        raise AssertionError("Missing-prediction status disagrees with reference failure")
                    failures[mode][error.code] += 1
                    violations = [i for i, (x, mu, limit) in enumerate(zip(row["features"], layer.mean, layer.config["delta_limits"])) if abs(x-mu) > limit] if mode == "tc_layer_specific" else []
                    domain_features.update(violations)
                    diagnostic["configurations"][mode] = dict(status="FAIL", error=str(error), violated_feature_indices=violations)
                predicted[mode].append(item["prediction"])
            dest.write(json.dumps(diagnostic, separators=(",", ":")) + "\n")
    if raw_count != len(cohort):
        raise AssertionError("Raw archive count differs")
    summaries = {}
    for mode in MODES:
        summary = json_value(metrics(truth, predicted[mode]))
        for key, value in summary.items():
            if saved["configurations"][mode][key] != value:
                raise AssertionError("Recomputed aggregate differs: " + mode + ":" + key)
        if dict(failures[mode]) != saved["configurations"][mode]["arithmetic_errors"]:
            raise AssertionError("Failure counts differ")
        summaries[mode] = summary
        for error in (per_mode_error[mode], common_error[mode]):
            error["mean_absolute"] = error.pop("total") / error["integers"] if error["integers"] else None
        for metric, value in (("mean_abs", per_mode_error[mode]["mean_absolute"]), ("max_abs", per_mode_error[mode]["maximum"])):
            if not math.isclose(saved["configurations"][mode]["numerical_error"]["logits"][metric], value, abs_tol=1e-14):
                raise AssertionError("Logit error aggregate differs")
    result = dict(status="PASS", input_count=len(cohort), recomputed_metrics=summaries,
        prediction_archive_sha256=fingerprint(args.results / "predictions.jsonl.gz"),
        rebuilt_tensor_hash_comparisons=tensor_count, rebuilt_integer_values=integer_count,
        mismatches=0, per_mode_logit_errors=per_mode_error, common_success_logit_errors=common_error,
        calibrated_domain_violations_by_feature_index=dict(domain_features), smallest_observed_logit_margins=minimum_margin,
        selected_vector_duplicates=sum(n-1 for n in duplicates.values()),
        scope="Independent reference reconstruction and saved host-C archive audit; no new C/kernel/network execution")
    (args.output / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k:v for k,v in result.items() if k!="recomputed_metrics"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("results", "cohort", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    audit(parser.parse_args())
