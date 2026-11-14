#!/usr/bin/env python3
"""Read-only submission links, frozen artifacts, evidence and staged-path checks."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((ROOT / name).read_text())


def main():
    for name, expected in read('docs/evidence/FROZEN_INPUT_HASHES.json').items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    missing = []
    # Current submission guides; old reports retain references to archived logs.
    guides = [ROOT / 'README.md', *sorted((ROOT / 'docs').glob('*.md'))]
    for guide in guides:
        for target in re.findall(r'\]\(([^)]+)\)', guide.read_text()):
            target = target.split(' "', 1)[0].strip('<>')
            if target.startswith(('https:', 'http:', '#', 'mailto:')):
                continue
            target = unquote(target.split('#', 1)[0])
            if not (guide.parent / target).exists():
                missing.append((str(guide.relative_to(ROOT)), target))
    assert not missing, missing
    m = read('docs/evidence/fresh-heldout.json')['metrics']
    assert (m['TP'], m['FP'], m['TN'], m['FN']) == (1984, 9, 829, 4)
    assert sum(m[k] for k in ('TP', 'FP', 'TN', 'FN')) == 2826
    assert abs(m['f1'] - 2 * m['TP'] / (2*m['TP'] + m['FP'] + m['FN'])) < 1e-15
    timing = read('docs/evidence/fresh-kernel-latency.json')
    assert timing['status'] == timing['cleanup'] == 'PASS'
    assert timing['input_count'] == 2826 and timing['trials'] == 5
    for mode in ('xdp_q16', 'static_q16', 'layer_specific'):
        assert timing['modes'][mode]['measured_calls'] == 14130
        assert timing['modes'][mode]['failures'] == 0
    original = read('docs/evidence/original-model-offline.json')['configurations']
    ratio = original['tc_q16']['errors']['logits']['mean_abs'] / original['tc_layer_specific']['errors']['logits']['mean_abs']
    assert 179 < ratio < 180
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    forbidden = [n for n in names if n and (
        n.startswith(('dataset-instance/', '.aws/', '.codex/', '.agents/'))
        or any(p in Path(n).parts for p in ('.output', '__pycache__', '.venv'))
        or n.endswith(('.pcap', '.pcapng', '.so', '.o', '.pem', '.key'))
        or Path(n).name.lower() in ('token.txt', '.env', 'credentials', 'id_rsa'))]
    assert not forbidden, forbidden
    print(json.dumps(dict(status='PASS', current_guides=len(guides),
                          frozen_hashes='PASS', saved_metric_consistency='PASS',
                          historical_kernel_summary='PASS; not new execution',
                          original_logit_error_ratio=ratio,
                          forbidden_tracked_paths=0), indent=2))


if __name__ == '__main__':
    main()
