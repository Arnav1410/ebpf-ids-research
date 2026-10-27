"""Numeric-only NPY input and evidence about the supplied six-feature dataset."""
import ast
from collections import Counter, defaultdict
from dataclasses import dataclass
import math
from pathlib import Path
import statistics
import struct

from .artifacts import DEFAULT_DATA, DEFAULT_LABELS, environment, sha256

FEATURES = (
    ("max_packet_length", "TCP segment bytes"),
    ("max_duration", "forward inter-arrival nanoseconds"),
    ("min_packet_length", "TCP segment bytes"),
    ("dst_port", "port number"),
    ("header_length", "cumulative TCP header bytes"),
    ("num_packet", "forward packet count"),
)
DTYPES = {"i1": "b", "u1": "B", "i2": "h", "u2": "H", "i4": "i",
          "u4": "I", "i8": "q", "u8": "Q", "f4": "f", "f8": "d"}


def read_npy(path):
    """Read a one/two-dimensional numeric NPY; never enable pickle/object loading."""
    path = Path(path)
    with path.open("rb") as stream:
        if stream.read(6) != b"\x93NUMPY":
            raise ValueError(f"Not an NPY file: {path}")
        version = tuple(stream.read(2))
        if version not in ((1, 0), (2, 0), (3, 0)):
            raise ValueError(f"Unsupported NPY version: {version}")
        width = 2 if version[0] == 1 else 4
        raw_length = stream.read(width)
        if len(raw_length) != width:
            raise ValueError("Truncated NPY header length")
        length = int.from_bytes(raw_length, "little")
        if not 0 < length <= 65536:
            raise ValueError("NPY header exceeds the supported 64-KiB bound")
        header = stream.read(length)
        if len(header) != length:
            raise ValueError("Truncated NPY header")
        try:
            metadata = ast.literal_eval(header.decode("utf-8" if version[0] == 3 else "latin1"))
        except (SyntaxError, ValueError, UnicodeError) as exc:
            raise ValueError("Invalid NPY header") from exc
        if not isinstance(metadata, dict) or set(metadata) != {"descr", "fortran_order", "shape"}:
            raise ValueError("Unexpected NPY header fields")
        shape, dtype = metadata["shape"], metadata["descr"]
        if (not isinstance(shape, tuple) or len(shape) not in (1, 2)
                or any(type(n) is not int or n <= 0 for n in shape)):
            raise ValueError("Expected a nonempty one/two-dimensional numeric array")
        if metadata["fortran_order"] is not False:
            raise ValueError("Fortran-order arrays are not supported; use explicit C-order input")
        if not isinstance(dtype, str) or len(dtype) < 3 or dtype[0] not in "<>=|" or dtype[1:] not in DTYPES:
            raise ValueError(f"Unsupported NPY dtype {dtype!r}; object/pickle arrays are forbidden")
        order = {"<": "<", ">": ">", "=": "=", "|": "="}[dtype[0]]
        fmt = order + DTYPES[dtype[1:]]
        size = struct.calcsize(fmt)
        count = math.prod(shape)
        remaining = path.stat().st_size - stream.tell()
        if remaining != count * size:
            raise ValueError("NPY payload length does not match its declared shape/dtype")
        payload = stream.read()
    values = [row[0] for row in struct.iter_unpack(fmt, payload)]
    if any(isinstance(x, float) and not math.isfinite(x) for x in values):
        raise ValueError("Dataset contains non-finite numeric values")
    return metadata, values


@dataclass(frozen=True)
class Dataset:
    features: tuple
    labels: tuple
    identity: dict
    data_path: str
    labels_path: str
    data_metadata: dict
    labels_metadata: dict


def load_dataset(data_path=DEFAULT_DATA, labels_path=DEFAULT_LABELS):
    data_path, labels_path = Path(data_path), Path(labels_path)
    data_meta, values = read_npy(data_path)
    label_meta, labels = read_npy(labels_path)
    if len(data_meta["shape"]) != 2 or data_meta["shape"][1] != 6:
        raise ValueError("Features must have shape (N, 6)")
    if label_meta["shape"] != (data_meta["shape"][0],):
        raise ValueError("Labels must have shape (N,) matching feature rows")
    if any(x != int(x) or not -(1 << 63) <= x < (1 << 63) for x in values):
        raise ValueError("Kernel feature vectors must contain signed int64 integers")
    if any(x not in (0, 1) for x in labels):
        raise ValueError("Labels must be numeric 0 or 1; their semantic meaning is not inferred")
    features = tuple(tuple(int(x) for x in values[i:i + 6]) for i in range(0, len(values), 6))
    return Dataset(features, tuple(int(x) for x in labels),
                   {"data_sha256": sha256(data_path), "labels_sha256": sha256(labels_path)},
                   str(data_path.resolve()), str(labels_path.resolve()), data_meta, label_meta)


def audit_dataset(dataset):
    groups = defaultdict(list)
    for index, row in enumerate(dataset.features):
        groups[row].append(index)
    counts = Counter(dataset.labels)
    statistics_by_feature = []
    for column, (name, unit) in enumerate(FEATURES):
        values = [row[column] for row in dataset.features]
        statistics_by_feature.append({"column": column, "name": name,
                                      "expected_kernel_unit": unit,
                                      "dataset_unit_verified": False,
                                      "min": min(values), "max": max(values),
                                      "mean": statistics.fmean(values),
                                      "unique_values": len(set(values)),
                                      "negative_values": sum(x < 0 for x in values)})
    return {"schema_version": 1, "claim": "dataset_audit_only", "identity": dataset.identity,
            "environment": environment(), "rows": len(dataset.features), "columns": 6,
            "files": {"data": {"path": dataset.data_path, **dataset.data_metadata},
                      "labels": {"path": dataset.labels_path, **dataset.labels_metadata}},
            "label_counts": {str(label): counts[label] for label in (0, 1)},
            "label_mapping": {"0": "unverified", "1": "unverified"},
            "features": statistics_by_feature,
            "feature_groups": {"unique": len(groups),
                               "repeated_groups": sum(len(rows) > 1 for rows in groups.values()),
                               "rows_beyond_first": len(dataset.features) - len(groups),
                               "conflicting_label_groups": sum(len({dataset.labels[i] for i in rows}) > 1
                                                               for rows in groups.values())},
            "limitations": ["Dataset provenance, capture dates, feature units and label meanings are unverified.",
                            "Training overlap of checked-in model weights is unknown.",
                            "Identical feature vectors are not proof of duplicated underlying traffic.",
                            "The supplied arrays do not establish the paper's dated train/test protocol."]}
