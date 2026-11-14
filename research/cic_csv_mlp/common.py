import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''): h.update(b)
    return h.hexdigest()


def write(path, data):
    with Path(path).open('x') as f:
        json.dump(data, f, indent=2, allow_nan=False)
        f.write('\n')


def read(path):
    return json.loads(Path(path).read_text())


def protocol():
    return read(HERE / 'PROTOCOL.json')


def verify_hashes(out, manifest):
    for name, expected in read(out / manifest)['files'].items():
        if sha(out / name) != expected: raise ValueError('Frozen artifact changed: ' + name)


def archive(path):
    import numpy as np
    with np.load(path, allow_pickle=False) as a:
        return {k: a[k].copy() for k in a.files}


def freeze(out, filename, paths, **extra):
    write(out / filename, dict(files={str(p): sha(out / p) for p in paths}, **extra))
