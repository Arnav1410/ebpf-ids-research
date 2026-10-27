"""Artifact directories are append-only experiments, never implicit overwrites."""
import hashlib
import json
import platform
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "dataset/reproduction-xdp-data.npy"
DEFAULT_LABELS = ROOT / "dataset/reproduction-xdp-label.npy"
DEFAULT_MODEL = ROOT / "src/mlp_params.bpf.h"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_directory(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=False)
    return path


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def read_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def environment():
    return {"python": sys.version, "platform": platform.platform(),
            "machine": platform.machine(), "byteorder": sys.byteorder}
