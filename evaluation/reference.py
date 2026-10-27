"""Diagnostic reports and comparison with the actual host-compiled C header."""
import json
import random
import struct
import subprocess

from .artifacts import ROOT, environment, sha256, write_json
from .metrics import classification_metrics
from .model import STAGES, infer, model_identity, pack_model

RECORD = struct.Struct("=" + "i" * (sum(count for _, count in STAGES) + 1))


def diagnostic(dataset, model, directory, trace_limit=16):
    predictions = []
    with (directory / "predictions.jsonl").open("x") as rows, (directory / "traces.jsonl").open("x") as traces:
        for index, (features, label) in enumerate(zip(dataset.features, dataset.labels)):
            result = infer(model, features)
            predictions.append(result["label"])
            rows.write(json.dumps({"row": index, "actual": label, "predicted": result["label"],
                                   "scores": result["output"]}) + "\n")
            if index < trace_limit:
                traces.write(json.dumps({"row": index, "features": features, **result}) + "\n")
    report = {"schema_version": 1, "claim": "diagnostic_not_held_out",
              "dataset_identity": dataset.identity, "model_sha256": model_identity(model),
              "environment": environment(), "metrics": classification_metrics(dataset.labels, predictions),
              "limitations": ["Original training overlap of the supplied model is unknown.",
                              "Label semantics and feature units have not been independently verified.",
                              "This is neither paper reproduction nor packet/kernel validation."]}
    write_json(directory / "report.json", report)
    return report


def conformance_vectors(dataset, limit=128):
    if limit <= 0:
        raise ValueError("Sample limit must be positive")
    chosen = sorted(random.Random(0).sample(range(len(dataset.features)), min(limit, len(dataset.features))))
    vectors = [dataset.features[index] for index in chosen]
    # Exercise normalization's unsigned wrap, signed narrowing, and both branches.
    vectors += [(0,) * 6, ((1 << 63) - 1,) * 6, (-(1 << 63),) * 6,
                tuple((1 << 63) - 1 if column % 2 else -(1 << 63) for column in range(6))]
    return vectors


def native_conformance(dataset, model, directory, limit=128):
    source = ROOT / "evaluation/native_reference.c"
    if not (ROOT / "src/.output/vmlinux.h").exists():
        raise ValueError("Native conformance needs the generated kernel header; run make -C src first")
    command = ["cc", "-O2", "-fwrapv", "-I" + str(ROOT / "src/.output"),
               str(source), "-o", str(directory / "native-reference")]
    with (directory / "build.log").open("x") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    (directory / "model.bin").write_bytes(pack_model(model))
    vectors = conformance_vectors(dataset, limit)
    with (directory / "vectors.bin").open("xb") as stream:
        for vector in vectors:
            stream.write(struct.pack("=6q", *vector))
    output = subprocess.run([str(directory / "native-reference"), str(directory / "model.bin"),
                             str(directory / "vectors.bin")], capture_output=True, check=True).stdout
    if len(output) != len(vectors) * RECORD.size:
        raise ValueError("Native driver returned an incomplete set of traces")
    mismatches = []
    for index, vector in enumerate(vectors):
        values = RECORD.unpack_from(output, index * RECORD.size)
        expected, offset = infer(model, vector), 0
        for stage, count in STAGES:
            actual = list(values[offset:offset + count])
            if actual != expected[stage]:
                mismatches.append({"vector": index, "stage": stage, "features": vector,
                                   "expected": expected[stage], "actual": actual})
            offset += count
        if values[-1] != expected["label"]:
            mismatches.append({"vector": index, "stage": "label", "expected": expected["label"], "actual": values[-1]})
    report = {"schema_version": 1, "claim": "host_header_arithmetic_conformance_not_kernel_parity",
              "status": "pass" if not mismatches else "fail", "vectors": len(vectors),
              "dataset_identity": dataset.identity, "model_sha256": model_identity(model),
              "arithmetic_header_sha256": sha256(ROOT / "src/mlp.bpf.h"),
              "driver_sha256": sha256(source), "compiler_command": command, "environment": environment(),
              "mismatches": mismatches}
    write_json(directory / "report.json", report)
    return report
