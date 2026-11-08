"""Frozen runtime model identities and verification of actual kernel readbacks.

No training, calibration, checkpoint deserialization or parameter mutation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
FRESH = ROOT / 'deployment/models/fresh'
ORIGINAL_HEADER_SHA256 = 'f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11'
FRESH_HEADER_SHA256 = 'e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391'
FRESH_CHECKPOINT_SHA256 = 'd299f964ecaa7b918eca65529371dbfa6db8797df97ee24b73a324ab52acef1b'
FRESH_PARAMETERS = dict(static_q16='1558c438e06600d8e3a5eeb28fe23c6aed94cb693a75dea4817497add71bd8d9',
                        layer_specific='1db06f441987ef7eb282b5954f158fbe861a74bf59bdcbf7988c7ec5c7e2357f')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reference(model='original', mode='static_q16'):
    from validation.reference import Model
    from quantization.reference import LayerModel
    if model not in ('original', 'fresh') or mode not in ('static_q16', 'layer_specific'):
        raise ValueError('Unsupported model/arithmetic selection')
    header = ROOT / 'src/mlp_params.bpf.h' if model == 'original' else FRESH / 'mlp_params.bpf.h'
    config = ROOT / 'quantization/calibrated.json' if model == 'original' else FRESH / 'calibrated.json'
    if model == 'fresh':
        manifest = json.loads((FRESH / 'manifest.json').read_text())
        for name, expected in manifest['files'].items():
            if Path(name).name != name or sha(FRESH / name) != expected:
                raise ValueError('Frozen fresh artifact changed: ' + name)
        if sha(header) != FRESH_HEADER_SHA256 or manifest['checkpoint_sha256'] != FRESH_CHECKPOINT_SHA256:
            raise ValueError('Fresh checkpoint/header is not the approved frozen model')
    elif sha(header) != ORIGINAL_HEADER_SHA256:
        raise ValueError('Original parameter header changed')
    return Model.load(header) if mode == 'static_q16' else LayerModel.load(config, header)


def model_spec(model='original', mode='static_q16'):
    ref = reference(model, mode)
    source = ref if mode == 'static_q16' else ref.source
    packed = ref.packed()
    header = ROOT / 'src/mlp_params.bpf.h' if model == 'original' else FRESH / 'mlp_params.bpf.h'
    scaler = struct.pack('<12q', *source.mean, *source.scale)
    info = dict(model=model, mode=mode, header_sha256=sha(header),
                parameter_sha256=hashlib.sha256(packed).hexdigest(),
                scaler_sha256=hashlib.sha256(scaler).hexdigest(),
                scaler_hash_basis='96 kernel-facing bytes: six int64 means then six int64 scales, little endian',
                parameter_bytes=len(packed), mean=source.mean, scale=source.scale,
                logit_q=16 if mode == 'static_q16' else ref.config['q_outputs'][-1],
                header=str(header), kernel_readback='NOT RUN')
    if model == 'fresh':
        manifest = json.loads((FRESH / 'manifest.json').read_text())
        if info['parameter_sha256'] != manifest['parameter_sha256'][mode] or info['parameter_sha256'] != FRESH_PARAMETERS[mode]:
            raise ValueError('Frozen fresh packed parameter identity mismatch')
        info.update(checkpoint_sha256=manifest['checkpoint_sha256'],
                    normalization_json_sha256=sha(FRESH / 'normalization.json'),
                    scaler_provenance=manifest['scaler_provenance'])
    return info


def verify_loaded(directory, model='original', mode='static_q16'):
    """Check bytes read from both actual kernel-map slots by the C controller."""
    info = model_spec(model, mode)
    expected = reference(model, mode).packed()
    for slot in (0, 1):
        actual = (Path(directory) / f'model-readback-{slot}.bin').read_bytes()
        if actual != expected:
            raise ValueError(f'Kernel model slot {slot} differs from selected {model}/{mode}')
        if hashlib.sha256(actual[5120:5216]).hexdigest() != info['scaler_sha256']:
            raise ValueError('Kernel scaler readback mismatch')
    return dict(info, kernel_readback='PASS', slots_verified=[0, 1], active_slot=0)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model', choices=('original', 'fresh'), required=True)
    p.add_argument('--mode', choices=('static_q16', 'layer_specific'), default='static_q16')
    a = p.parse_args()
    print(json.dumps(model_spec(a.model, a.mode), indent=2))
