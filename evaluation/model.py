"""Explicit eBPF integer semantics, independent of NumPy/PyTorch arithmetic."""
import hashlib
import json
from pathlib import Path
import re
import struct

from .artifacts import read_json, sha256

FIELDS = (("layer_0_weight", 192, 32), ("layer_1_weight", 1024, 32),
          ("layer_2_weight", 64, 32), ("mean", 6, 64), ("scale", 6, 64))
STAGES = (("normalized", 6), ("input_linear", 32), ("input_relu", 32),
          ("hidden_linear", 32), ("hidden_relu", 32), ("output", 2))
MASK64 = (1 << 64) - 1


def signed(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value >= 1 << (width - 1) else value


def validate_model(model):
    if model.get("fixed_point") != 16 or model.get("dimensions") != [6, 32, 32, 2]:
        raise ValueError("Model must use dimensions [6,32,32,2] and 16 fractional bits")
    for name, count, width in FIELDS:
        values = model.get(name)
        if not isinstance(values, (list, tuple)) or len(values) != count:
            raise ValueError(f"Model field {name} requires {count} elements")
        if any(type(x) is not int or not -(1 << (width - 1)) <= x < (1 << (width - 1)) for x in values):
            raise ValueError(f"Model field {name} must contain signed int{width} values")
    if any(value == 0 for value in model["scale"]):
        raise ValueError("Quantized normalization contains a zero divisor")
    return model


def load_model(path):
    path = Path(path)
    if path.suffix == ".json":
        return validate_model(read_json(path))
    text = path.read_text(encoding="utf-8")
    fixed = re.search(r"^\s*#define\s+FIX_POINT\s+(\d+)\s*$", text, re.M)
    if fixed is None:
        raise ValueError("Header lacks an explicit FIX_POINT definition")
    model = {"schema_version": 1, "fixed_point": int(fixed[1]), "dimensions": [6, 32, 32, 2]}
    for name, count, width in FIELDS:
        matches = re.findall(r"\bint" + str(width) + r"_t\s+" + name + r"\s*\[(\d+)\]\s*=\s*\{([^}]+)\}", text)
        if len(matches) != 1 or int(matches[0][0]) != count:
            raise ValueError(f"Cannot locate a unique {name}[{count}] array in header")
        tokens = [token.strip() for token in matches[0][1].split(",") if token.strip()]
        if any(re.fullmatch(r"[+-]?\d+", token) is None for token in tokens):
            raise ValueError(f"Only literal decimal integers are accepted in {name}")
        model[name] = [int(token) for token in tokens]
    model["provenance"] = {"kind": "existing_header", "path": str(path.resolve()), "sha256": sha256(path),
                           "original_training_overlap": "unknown"}
    return validate_model(model)


def model_identity(model):
    core = {key: model[key] for key in ("fixed_point", "dimensions", *(field[0] for field in FIELDS))}
    encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def pack_model(model):
    validate_model(model)
    return b"".join(struct.pack("=" + ("i" if width == 32 else "q") * count, *model[name])
                    for name, count, width in FIELDS)


def header_text(model):
    validate_model(model)
    lines = ["#ifndef MLP_PARAMS_BPF_H", "#define MLP_PARAMS_BPF_H", "", "#define FIX_POINT 16",
             "#define N0 6", "#define N1 32", "#define N2 32", "#define N3 2", ""]
    for name, count, width in FIELDS:
        lines += [f"static const int{width}_t {name}[{count}] = {{" + ", ".join(map(str, model[name])) + "};", ""]
    return "\n".join(lines + ["#endif", ""])


def normalize(features, mean, scale):
    result = []
    for x, center, divisor in zip(features, mean, scale):
        denominator = divisor & MASK64
        if denominator == 0:
            raise ValueError("Zero normalization divisor")
        magnitude = ((center - x if center > x else x - center) & MASK64)
        quotient = ((magnitude << 16) & MASK64) // denominator
        value = signed(quotient, 32)
        result.append(signed(-value, 32) if center > x else value)
    return result


def linear(weights, inputs, outputs):
    width = len(inputs)
    return [signed(signed(sum(weights[row * width + column] * inputs[column]
                             for column in range(width)), 64) >> 16, 32)
            for row in range(outputs)]


def infer(model, features):
    if len(features) != 6 or any(type(x) is not int or not -(1 << 63) <= x < 1 << 63 for x in features):
        raise ValueError("Inference requires six signed int64 feature values")
    normalized = normalize(features, model["mean"], model["scale"])
    input_linear = linear(model["layer_0_weight"], normalized, 32)
    input_relu = [max(x, 0) for x in input_linear]
    hidden_linear = linear(model["layer_1_weight"], input_relu, 32)
    hidden_relu = [max(x, 0) for x in hidden_linear]
    output = linear(model["layer_2_weight"], hidden_relu, 2)
    return {"normalized": normalized, "input_linear": input_linear, "input_relu": input_relu,
            "hidden_linear": hidden_linear, "hidden_relu": hidden_relu,
            "output": output, "label": 0 if output[0] > output[1] else 1}
