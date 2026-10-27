"""Deterministic CPU holdout training and paired JSON checkpoint evaluation.

Float argmax ties choose class 0; the kernel integer reference chooses class 1.
No ML dependency is imported until training or floating evaluation is requested.
"""
import hashlib
import json
import math
from pathlib import Path
import random
import struct

from .artifacts import environment, read_json, sha256, write_json
from .metrics import classification_metrics
from .model import FIELDS, header_text, infer, model_identity, validate_model
from .split import validate_split

WEIGHT_FIELDS = FIELDS[:3]
DIMENSIONS = [6, 32, 32, 2]
TRACE_LIMIT = 16
TIE_RULES = {"float": "argmax: equal scores select class 0",
             "integer": "kernel: equal scores select class 1"}


def _identity(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _dependencies():
    try:
        import numpy as np
        import torch
    except ImportError as exc:
        raise RuntimeError("Training/evaluation requires the pinned evaluation NumPy/PyTorch environment") from exc
    return np, torch


def _finite_values(values, count, name):
    if not isinstance(values, (list, tuple)) or len(values) != count:
        raise ValueError(f"Model field {name} requires {count} elements")
    try:
        finite = all(type(value) in (float, int) and math.isfinite(value) for value in values)
    except OverflowError as exc:
        raise ValueError(f"Model field {name} exceeds finite numeric range") from exc
    if not finite:
        raise ValueError(f"Model field {name} must contain finite numbers")


def validate_float_model(model):
    if (not isinstance(model, dict) or model.get("schema_version") != 1
            or model.get("dimensions") != DIMENSIONS or model.get("dtype") != "float32"
            or model.get("bias") is not False):
        raise ValueError("Floating model must be a schema-1 bias-free float32 [6,32,32,2] MLP")
    for name, count, _ in WEIGHT_FIELDS:
        _finite_values(model.get(name), count, name)
        for value in model[name]:
            try:
                stored = struct.unpack("f", struct.pack("f", value))[0]
            except (OverflowError, struct.error) as exc:
                raise ValueError(f"Model field {name} exceeds float32 range") from exc
            if stored != value:
                raise ValueError(f"Model field {name} is not an exact float32 checkpoint value")
    for name in ("mean", "scale"):
        _finite_values(model.get(name), 6, name)
    if any(value <= 0 for value in model["scale"]):
        raise ValueError("Floating normalization scales must be positive")
    return model


def float_model_identity(model):
    validate_float_model(model)
    return _identity({key: model[key] for key in
                      ("schema_version", "dimensions", "dtype", "bias", "mean", "scale",
                       *(field[0] for field in WEIGHT_FIELDS))})


def quantize_model(floating):
    """Match mlp_quant.py: binary32 weights * 2**16, nearest-even, int32.

    Mean/scale are float64, rounded nearest-even to signed int64, without a
    fixed-point multiplier. Reject overflow before conversion, not after wrap.
    """
    validate_float_model(floating)
    quantized = {"schema_version": 1, "dimensions": DIMENSIONS.copy(), "fixed_point": 16}
    for name, count, width in FIELDS:
        multiplier = 65536 if name.startswith("layer_") else 1
        values = []
        for value in floating[name]:
            scaled = value * multiplier
            if not math.isfinite(scaled):
                raise ValueError(f"Nonfinite quantization in {name}")
            rounded = round(scaled)
            if not -(1 << (width - 1)) <= rounded < (1 << (width - 1)):
                raise ValueError(f"Quantization of {name} exceeds signed int{width}")
            values.append(rounded)
        quantized[name] = values
    quantized["provenance"] = {"kind": "quantized_same_checkpoint",
                               "float_model_identity": float_model_identity(floating),
                               "rounding": "nearest-even", "weight_fractional_bits": 16}
    return validate_model(quantized)


def validate_model_pair(floating, quantized):
    """Validate linkage AND derive every integer parameter from the saved float."""
    validate_float_model(floating)
    if not isinstance(quantized, dict) or quantized.get("schema_version") != 1:
        raise ValueError("Quantized model requires schema_version 1")
    validate_model(quantized)
    identity = float_model_identity(floating)
    provenance = quantized.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("float_model_identity") != identity:
        raise ValueError("Quantized model is not linked to this floating checkpoint")
    expected = quantize_model(floating)
    if model_identity(expected) != model_identity(quantized):
        raise ValueError("Integer parameters do not quantize from the paired floating checkpoint")
    return floating, quantized


def fit_preprocessing(dataset, train_indices):
    """Fit population mean/std in float64 on training rows only."""
    np, _ = _dependencies()
    rows = np.asarray([dataset.features[index] for index in train_indices], dtype=np.float64)
    if rows.ndim != 2 or rows.shape[1] != 6 or not len(rows):
        raise ValueError("Scaler requires nonempty six-feature training rows")
    mean, scale = rows.mean(axis=0), rows.std(axis=0, ddof=0)
    scale[scale == 0] = 1.0
    if not np.isfinite(mean).all() or not np.isfinite(scale).all():
        raise ValueError("Nonfinite training preprocessing")
    return mean.tolist(), scale.tolist()


def _normalize(np, dataset, indices, mean, scale):
    rows = np.asarray([dataset.features[index] for index in indices], dtype=np.float64)
    normalized = ((rows - np.asarray(mean, dtype=np.float64))
                  / np.asarray(scale, dtype=np.float64)).astype(np.float32)
    if not np.isfinite(normalized).all():
        raise ValueError("Normalized inputs exceed finite float32 range")
    return normalized


def _network(torch):
    return torch.nn.Sequential(
        torch.nn.Linear(6, 32, bias=False, device="cpu", dtype=torch.float32), torch.nn.ReLU(),
        torch.nn.Linear(32, 32, bias=False, device="cpu", dtype=torch.float32), torch.nn.ReLU(),
        torch.nn.Linear(32, 2, bias=False, device="cpu", dtype=torch.float32))


def _versions(np, torch):
    return {**environment(), "numpy": str(np.__version__), "torch": str(torch.__version__)}


def _artifact_identities(directory):
    return {name: sha256(Path(directory) / name) for name in
            ("split.json", "float-model.json", "quantized-model.json", "mlp_params.bpf.h")}


def _score(dataset, split, floating, quantized, directory, source, versions):
    np, torch = _dependencies()
    _, test_indices = validate_split(dataset, split)
    validate_model_pair(floating, quantized)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    weights = [torch.tensor(floating[name], dtype=torch.float32, device="cpu").reshape(
        DIMENSIONS[layer + 1], DIMENSIONS[layer])
        for layer, (name, _, _) in enumerate(WEIGHT_FIELDS)]
    float_predictions, integer_predictions, labels = [], [], []
    disagreement_count, float_ties, integer_ties, traces = 0, 0, 0, 0
    directory = Path(directory)
    with ((directory / "predictions.jsonl").open("x", encoding="utf-8") as predictions,
          (directory / "traces.jsonl").open("x", encoding="utf-8") as trace_stream,
          torch.no_grad()):
        for start in range(0, len(test_indices), 512):
            indices = test_indices[start:start + 512]
            normalized = torch.from_numpy(_normalize(np, dataset, indices, floating["mean"], floating["scale"]))
            input_linear = torch.nn.functional.linear(normalized, weights[0])
            input_relu = torch.relu(input_linear)
            hidden_linear = torch.nn.functional.linear(input_relu, weights[1])
            hidden_relu = torch.relu(hidden_linear)
            output = torch.nn.functional.linear(hidden_relu, weights[2])
            if not torch.isfinite(output).all():
                raise ValueError("Floating checkpoint produced nonfinite output scores")
            stages = {"normalized": normalized, "input_linear": input_linear,
                      "input_relu": input_relu, "hidden_linear": hidden_linear,
                      "hidden_relu": hidden_relu, "output": output}
            scores, selected = output.tolist(), output.argmax(dim=1).tolist()
            for position, index in enumerate(indices):
                integer = infer(quantized, dataset.features[index])
                fp, ip = selected[position], integer["label"]
                label = dataset.labels[index]
                different = fp != ip
                float_predictions.append(fp)
                integer_predictions.append(ip)
                labels.append(label)
                disagreement_count += different
                float_ties += scores[position][0] == scores[position][1]
                integer_ties += integer["output"][0] == integer["output"][1]
                row = {"index": index, "label": label, "float_prediction": fp,
                       "integer_prediction": ip, "float_output": scores[position],
                       "integer_output": integer["output"], "disagreement": different}
                predictions.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
                # First eight held-out rows, then up to eight additional disagreements.
                if start + position < TRACE_LIMIT // 2 or (different and traces < TRACE_LIMIT):
                    trace = {"index": index, "label": label,
                             "float": {name: value[position].tolist() for name, value in stages.items()},
                             "integer": integer, "float_prediction": fp, "disagreement": different}
                    trace_stream.write(json.dumps(trace, sort_keys=True, allow_nan=False) + "\n")
                    traces += 1
    report = {"schema_version": 1, "claim": "local_grouped_held_out", "status": "complete",
              "dataset_identity": dataset.identity, "split_identity": _identity(split),
              "float_model_identity": float_model_identity(floating),
              "quantized_model_identity": model_identity(quantized),
              "source": source, "environment": versions,
              "train_samples": len(split["train_indices"]), "test_samples": len(test_indices),
              "float_metrics": classification_metrics(labels, float_predictions),
              "integer_metrics": classification_metrics(labels, integer_predictions),
              "disagreement": {"count": disagreement_count, "samples": len(labels),
                               "rate": disagreement_count / len(labels)},
              "tie_rules": TIE_RULES.copy(),
              "ties": {"float": float_ties, "integer": integer_ties},
              "predictions": "predictions.jsonl", "traces": "traces.jsonl", "trace_count": traces,
              "trace_policy": "first eight test rows and up to eight later disagreements (maximum 16)",
              "limitations": ["Local exact-feature grouped holdout is not the paper's date/session protocol.",
                              "Dataset provenance, feature units and numeric label meanings are unverified.",
                              "Exact-feature grouping preserves every row; it does not establish flow identity."]}
    write_json(directory / "report.json", report)
    return report


def train_experiment(dataset, split, directory, seed=2026, epochs=32,
                     batch_size=512, learning_rate=0.001):
    """Train once; export and score the float/integer versions of that checkpoint."""
    train_indices, _ = validate_split(dataset, split)
    if type(seed) is not int or not 0 <= seed < 2 ** 32:
        raise ValueError("Training seed must be an integer in [0, 2**32)")
    if type(epochs) is not int or epochs <= 0 or type(batch_size) is not int or batch_size <= 0:
        raise ValueError("epochs and batch_size must be positive integers")
    if (type(learning_rate) not in (int, float) or not math.isfinite(learning_rate)
            or learning_rate <= 0):
        raise ValueError("learning_rate must be finite and positive")
    np, torch = _dependencies()
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    mean, scale = fit_preprocessing(dataset, train_indices)
    normalized = _normalize(np, dataset, train_indices, mean, scale)
    labels = torch.tensor([dataset.labels[index] for index in train_indices], dtype=torch.long, device="cpu")
    generator = torch.Generator(device="cpu").manual_seed(seed)
    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(torch.from_numpy(normalized), labels),
        batch_size=batch_size, shuffle=True, num_workers=0, generator=generator)
    network = _network(torch)
    optimizer = torch.optim.Adam(network.parameters(), lr=learning_rate)
    criterion = torch.nn.CrossEntropyLoss()
    history = []
    network.train()
    for epoch in range(epochs):
        total_loss, correct = 0.0, 0
        for features, actual in loader:
            optimizer.zero_grad(set_to_none=True)
            output = network(features)
            loss = criterion(output, actual)
            if not torch.isfinite(loss):
                raise ValueError("Training produced a nonfinite loss")
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(actual)
            correct += int((output.argmax(dim=1) == actual).sum().item())
        history.append({"epoch": epoch + 1, "train_cross_entropy": total_loss / len(train_indices),
                        "train_accuracy": correct / len(train_indices)})
    floating = {"schema_version": 1, "dtype": "float32", "bias": False,
                "dimensions": DIMENSIONS.copy(), "mean": mean, "scale": scale,
                "provenance": {"kind": "new_local_holdout_training", "seed": seed,
                               "dataset_identity": dataset.identity, "split_identity": _identity(split),
                               "checkpoint": "final_epoch", "epochs": epochs}}
    for layer, (name, _, _) in enumerate(WEIGHT_FIELDS):
        floating[name] = network[2 * layer].weight.detach().cpu().reshape(-1).tolist()
    quantized = quantize_model(floating)
    validate_model_pair(floating, quantized)
    directory = Path(directory)
    write_json(directory / "split.json", split)
    write_json(directory / "float-model.json", floating)
    write_json(directory / "quantized-model.json", quantized)
    with (directory / "mlp_params.bpf.h").open("x", encoding="utf-8") as stream:
        stream.write(header_text(quantized))
    versions = _versions(np, torch)
    training = {"schema_version": 1, "dataset_identity": dataset.identity,
                "split_identity": _identity(split), "float_model_identity": float_model_identity(floating),
                "quantized_model_identity": model_identity(quantized), "environment": versions,
                "hyperparameters": {"seed": seed, "epochs": epochs, "batch_size": batch_size,
                                    "learning_rate": learning_rate, "optimizer": "Adam",
                                    "adam_betas": [0.9, 0.999], "adam_eps": 1e-8,
                                    "weight_decay": 0, "loss": "CrossEntropyLoss",
                                    "device": "cpu", "cpu_threads": 1, "deterministic_algorithms": True,
                                    "shuffle": "seeded torch.Generator; num_workers=0",
                                    "architecture": DIMENSIONS.copy(), "bias": False},
                "preprocessing": {"fit_partition": "train_indices", "statistics_dtype": "float64",
                                  "input_dtype": "float32", "std_ddof": 0,
                                  "constant_feature_scale": 1},
                "checkpoint": "final_epoch", "history": history,
                "artifact_sha256": _artifact_identities(directory), "tie_rules": TIE_RULES.copy()}
    write_json(directory / "training.json", training)
    return _score(dataset, split, floating, quantized, directory,
                  {"kind": "training", "artifact_sha256": training["artifact_sha256"],
                   "training_sha256": sha256(directory / "training.json")}, versions)


def evaluate_experiment(dataset, model_dir, directory):
    """Reload portable paired artifacts and frozen membership; never retrain."""
    model_dir, directory = Path(model_dir), Path(directory)
    split = read_json(model_dir / "split.json")
    validate_split(dataset, split)
    floating = read_json(model_dir / "float-model.json")
    quantized = read_json(model_dir / "quantized-model.json")
    validate_model_pair(floating, quantized)
    training = read_json(model_dir / "training.json")
    if not isinstance(training, dict) or training.get("schema_version") != 1:
        raise ValueError("Training manifest requires schema_version 1")
    expected = {"dataset_identity": dataset.identity, "split_identity": _identity(split),
                "float_model_identity": float_model_identity(floating),
                "quantized_model_identity": model_identity(quantized)}
    for key, value in expected.items():
        if training.get(key) != value:
            raise ValueError(f"Saved training manifest has a mismatched {key}")
    provenance = floating.get("provenance")
    if (not isinstance(provenance, dict) or provenance.get("dataset_identity") != dataset.identity
            or provenance.get("split_identity") != _identity(split)):
        raise ValueError("Floating checkpoint provenance does not match this dataset/split")
    artifacts = _artifact_identities(model_dir)
    if training.get("artifact_sha256") != artifacts:
        raise ValueError("Saved checkpoint artifacts differ from the training manifest")
    if (model_dir / "mlp_params.bpf.h").read_text(encoding="utf-8") != header_text(quantized):
        raise ValueError("Exported header differs from the paired integer model")
    np, torch = _dependencies()
    write_json(directory / "split.json", split)
    return _score(dataset, split, floating, quantized, directory,
                  {"kind": "reevaluation", "model_directory": str(model_dir.resolve()),
                   "artifact_sha256": artifacts, "training_sha256": sha256(model_dir / "training.json")},
                  _versions(np, torch))
