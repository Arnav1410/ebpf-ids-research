#!/usr/bin/env python3
"""Frozen-model HOST-C external evaluation; never kernel/network execution."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from evaluation.offline import Host, MODES
from evaluation.data import reproduction
from evaluation.cic.metrics import metrics
from evaluation.cic.reconstruct import fingerprint
from validation.reference import Model, STAGES
from quantization.reference import LayerModel, ExactModel, ArithmeticFailure


def tensor_hash(values):
    return hashlib.sha256(struct.pack("<" + "i" * len(values), *values)).hexdigest()


def build(out, compiler):
    directory = out / ".output"
    directory.mkdir()
    result = {}
    for mode in MODES:
        source = ROOT / ("validation/native.c" if mode == "xdp_q16" else "evaluation/tc_vectors.c")
        include = ROOT / ("validation/include" if mode == "xdp_q16" else "tc/tests/include")
        path = directory / (mode + ".so")
        command = [compiler, "-O3", "-shared", "-fPIC", "-pthread", "-I" + str(include), "-I" + str(ROOT / "validation/include")]
        if mode == "tc_layer_specific":
            command.append("-DIDS_LAYER_SPECIFIC")
        command += [str(source), "-o", str(path)]
        p = subprocess.run(command, capture_output=True, text=True)
        (out / (mode + "-build.log")).write_text(p.stdout + p.stderr)
        with (out / "commands.jsonl").open("a") as dest:
            dest.write(json.dumps(dict(argv=command, exit_code=p.returncode)) + "\n")
        if p.returncode:
            raise RuntimeError("Host C inference build failed: " + mode)
        result[mode] = Host(path, mode == "xdp_q16")
    return result


def evaluate(args):
    started = time.monotonic()
    cohort_hash = fingerprint(args.cohort)
    validation = json.loads(args.validation.read_text())
    if validation["status"] != "PASS" or validation["cohort_sha256"] != cohort_hash:
        raise ValueError("Exact cohort has not passed independent feature/label validation")
    if validation["source_binding_sha256"] != fingerprint(args.binding):
        raise ValueError("Source binding differs from validated cohort")
    policy = json.loads((ROOT / "evaluation/cic/SELECTION_POLICY.json").read_text())
    if fingerprint(ROOT / "src/mlp_params.bpf.h") != policy["model_contract"]["header_sha256"]:
        raise ValueError("Frozen model changed")
    if fingerprint(ROOT / "quantization/calibrated.json") != policy["model_contract"]["calibration_sha256"]:
        raise ValueError("Frozen calibration changed")
    records = [json.loads(line) for line in args.cohort.read_text().splitlines() if line.strip()]
    if not 0 < len(records) <= 30000 or len({r["source_record_id"] for r in records}) != len(records):
        raise ValueError("Invalid/duplicated cohort IDs")
    if len(records) != validation["records"]:
        raise ValueError("Cohort count differs from validation")
    args.output.mkdir(parents=True, exist_ok=False)
    hosts = build(args.output, args.compiler)
    original = Model.load(ROOT / "src/mlp_params.bpf.h")
    layer = LayerModel.load()
    exact = ExactModel(original)
    predictions = {m: [] for m in MODES}
    errors = {m: Counter() for m in MODES}
    numerical = {m: {s: dict(sum_abs=0., max_abs=0., values=0) for s in STAGES} for m in MODES}
    samples = []
    sample_counts = Counter()
    compared_tensors = Counter()
    ties = Counter()
    truth = [r["label"] for r in records]
    with gzip.open(args.output / "predictions.jsonl.gz", "wt") as dest:
        for position, record in enumerate(records):
            raw = record["features"]
            n, d, _ = exact.infer(raw)
            saved = {k: record[k] for k in ("source_record_id", "csv_line", "original_flow_id", "capture_day", "category", "label", "features")}
            saved["configurations"] = {}
            tensors = {}
            for mode in MODES:
                model = layer if mode == "tc_layer_specific" else original
                events = []
                try:
                    expected, expected_label = model.infer(raw, events)
                    if events:
                        raise ArithmeticFailure("unsafe_arithmetic", str(events))
                    actual, label = hosts[mode].infer(raw)
                    if actual != expected or label != expected_label:
                        raise AssertionError("Host-C/reference tensor disagreement: " + mode + " " + record["source_record_id"])
                    exponents = layer.exponents if mode == "tc_layer_specific" else [16] * 6
                    for stage, q in zip(STAGES, exponents):
                        for value, numerator in zip(actual[stage], n[stage]):
                            error = abs(value * d[stage] - (numerator << q)) / (d[stage] * (1 << q))
                            item = numerical[mode][stage]
                            item["sum_abs"] += error
                            item["max_abs"] = max(item["max_abs"], error)
                            item["values"] += 1
                    logits = actual["logits"]
                    ties[mode] += logits[0] == logits[1]
                    compared_tensors[mode] += 6
                    predictions[mode].append(label)
                    saved["configurations"][mode] = dict(status="PASS", prediction=label, logits=logits,
                        logit_q=exponents[-1], stage_sha256={s:tensor_hash(actual[s]) for s in STAGES},
                        reference_stage_sha256={s:tensor_hash(expected[s]) for s in STAGES}, arithmetic_events=[])
                    tensors[mode] = actual
                except ArithmeticFailure as error:
                    errors[mode][error.code] += 1
                    predictions[mode].append(None)
                    saved["configurations"][mode] = dict(status="FAIL", prediction=None,
                        logits=None, error=str(error), arithmetic_events=events,
                        execution="NOT EXECUTED on unsafe/out-of-domain C input; retained as missing prediction")
            if tensors.get("xdp_q16") != tensors.get("tc_q16"):
                raise AssertionError("Original/TC Q16 tensor parity failed")
            dest.write(json.dumps(saved, separators=(",", ":")) + "\n")
            if sample_counts[record["category"]] < 1:
                sample_counts[record["category"]] += 1
                samples.append(dict(record=saved, tensors=tensors))
            if position % 2000 == 0:
                print("Host-C evaluated records", position, "/", len(records), flush=True)
    common = [i for i in range(len(records)) if all(predictions[m][i] is not None for m in MODES)]
    summaries = {}
    for mode in MODES:
        summary = metrics(truth, predictions[mode])
        summary["arithmetic_errors"] = dict(errors[mode])
        summary["intermediate_tensors_compared"] = compared_tensors[mode]
        summary["equal_logit_predictions"] = ties[mode]
        summary["numerical_error"] = numerical[mode]
        for value in numerical[mode].values():
            value["mean_abs"] = value.pop("sum_abs") / value["values"] if value["values"] else None
        summary["paired_common_success_metrics"] = metrics([truth[i] for i in common], [predictions[mode][i] for i in common])
        summary["per_category"] = {}
        for category in sorted({r["category"] for r in records}):
            indices = [i for i, r in enumerate(records) if r["category"] == category]
            values = [predictions[mode][i] for i in indices]
            positive = sum(v == 1 for v in values)
            valid = sum(v is not None for v in values)
            summary["per_category"][category] = dict(support=len(indices), scored=valid, missing=len(indices)-valid,
                predicted_intrusion=positive, recall=positive/valid if valid and category != "BENIGN" else None,
                benign_false_positive_rate=positive/valid if valid and category == "BENIGN" else None,
                coverage=valid/len(indices))
        summary["per_capture_day"] = {day: metrics([truth[i] for i,r in enumerate(records) if r["capture_day"]==day],
            [predictions[mode][i] for i,r in enumerate(records) if r["capture_day"]==day]) for day in sorted({r["capture_day"] for r in records})}
        summaries[mode] = summary
    disagreements = {}
    for a, b in (("xdp_q16", "tc_q16"), ("xdp_q16", "tc_layer_specific"), ("tc_q16", "tc_layer_specific")):
        comparable = [i for i in range(len(records)) if predictions[a][i] is not None and predictions[b][i] is not None]
        disagreements[a + "_vs_" + b] = dict(comparable=len(comparable),
            prediction_changes=sum(predictions[a][i] != predictions[b][i] for i in comparable),
            differing_failure_status=sum((predictions[a][i] is None) != (predictions[b][i] is None) for i in range(len(records))))
    reproduction_rows, reproduction_labels = reproduction(ROOT)
    stored = set(map(tuple, reproduction_rows))
    vector_counts = Counter(tuple(r["features"]) for r in records)
    collisions = sum(tuple(r["features"]) in stored for r in records)
    import sklearn, numpy, scipy
    result = dict(status="PASS", execution="Host C original XDP/Q16 and actual TC stage code; NOT kernel or live packet processing",
        input_count=len(records), cohort_sha256=cohort_hash, source_binding_sha256=fingerprint(args.binding),
        checkpoint_sha256=policy["model_contract"]["header_sha256"], calibration_sha256=policy["model_contract"]["calibration_sha256"],
        labels="Original CIC source labels, 0 benign / 1 intrusion; inherited source-label errors remain possible",
        support=dict(Counter(truth)), categories=dict(Counter(r["category"] for r in records)),
        common_success_count=len(common), common_success_ids_sha256=hashlib.sha256("\n".join(records[i]["source_record_id"] for i in common).encode()).hexdigest(),
        configurations=summaries, disagreements=disagreements,
        overlap=dict(selected_vector_duplicates=len(records)-len(vector_counts),
                     selected_vectors_colliding_with_reproduction=collisions,
                     unique_vector_collisions=sum(v in stored for v in vector_counts),
                     interpretation="Six-vector equality is not flow identity; zero collisions cannot establish unseen checkpoint history; none excluded for numerical collision"),
        numerical_reference="Exact rational reconstruction of unchanged Q16 header network, not original FP32",
        limits=["Strict first-incoming-FIN/RST window and exact source-row match subset; exclusion bias must be reported",
                "Sample class prevalence differs from source/deployment; no representative intrusion-effectiveness claim",
                "Single capture day and correlated attack activity; no independent-row confidence interval",
                "Checkpoint training membership unknown; not identical-protocol reproduction of paper Table V"],
        software=dict(python=platform.python_version(),kernel=platform.release(),machine=platform.machine(),
                      sklearn=sklearn.__version__,numpy=numpy.__version__,scipy=scipy.__version__),
        baseline_commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        elapsed_seconds=round(time.monotonic()-started,3))
    (args.output / "metrics.json").write_text(json.dumps(result,indent=2)+"\n")
    (args.output / "tensor_samples.json").write_text(json.dumps(samples,indent=2)+"\n")
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/nn-ebpf-cic-matplotlib")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1,3,figsize=(11,3.7),layout="constrained")
    for ax,mode in zip(axes,MODES):
        matrix=numpy.array(summaries[mode]["confusion_matrix"])
        ax.imshow(matrix,cmap="Blues")
        for y in range(2):
            for x in range(2):ax.text(x,y,str(matrix[y,x]),ha="center",va="center",color="white" if matrix[y,x]>matrix.max()/2 else "black")
        ax.set(xticks=[0,1],yticks=[0,1],xticklabels=["Benign","Intrusion"],yticklabels=["Benign","Intrusion"],xlabel="Predicted",ylabel="Source label",title=mode+"\nvalid="+str(summaries[mode]["valid_predictions"]))
    fig.suptitle("External offline CIC subset: valid predictions; missing predictions reported separately")
    fig.savefig(args.output/"confusion-matrices.png",dpi=180)
    fig.savefig(args.output/"confusion-matrices.pdf")
    plt.close(fig)
    print(json.dumps({k:v for k,v in result.items() if k!="configurations"},indent=2),flush=True)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("cohort","validation","binding","output"):
        parser.add_argument("--"+name,required=True,type=Path)
    parser.add_argument("--compiler",default="clang-12")
    evaluate(parser.parse_args())
