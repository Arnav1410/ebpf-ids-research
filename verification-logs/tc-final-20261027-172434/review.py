#!/usr/bin/env python3
"""Offline review of the successful attached TC run; no BPF/network syscalls."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
PREP = ROOT / 'verification-logs/tc-prepare-20261027-171811-753128'
RUN = PREP / 'run-20261027-172125-858078'
sys.path[:0] = [str(ROOT / 'validation'), str(ROOT / 'tc')]
from reference import Model, STAGES
from safety import require_attached_filter, require_detach_ack


def read(path):
    return json.loads(path.read_text())


def check(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksums(directory):
    count = 0
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split('  ', 1)
        check(sha(directory / name) == expected, f'Evidence checksum mismatch: {name}')
        count += 1
    return count


def main():
    report = {'review': 'PASS', 'method': 'offline replay of actual saved kernel evidence',
              'runtime_evidence': str(RUN), 'new_privileged_operations': 0}
    report['preparation_checksums_verified'] = checksums(PREP)
    report['runtime_checksums_verified'] = checksums(RUN)
    manifest = read(PREP / 'manifest.json')
    for group, files in manifest.items():
        for name, expected in files.items():
            check(sha(ROOT / name) == expected, f'{group} changed: {name}')
    report['source_and_binary_hashes_verified'] = {k: len(v) for k, v in manifest.items()}
    prepared = read(PREP / 'results.json')
    report['commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    report['branch'] = subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip()
    check(report['commit'] == prepared['commit'] and report['branch'] == prepared['branch'], 'Checkout changed')
    check(not subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], cwd=ROOT, text=True).strip(),
          'Tracked files changed')
    check(prepared['preparation'] == 'PASS' and prepared['nonprivileged_tests'] ==
          {'run': 11, 'failures': 0, 'errors': 0}, 'Preparation not verified')
    report['previously_executed_nonprivileged_tests'] = prepared['nonprivileged_tests']
    result = read(RUN / 'results.json')
    for name in ('minimal_ingress', 'full_inference', 'cleanup'):
        check(result[name] == 'PASS', f'Runtime result failed: {name}')
    check('error' not in result and result['protected_files'] == 'UNCHANGED', 'Runtime error/integrity failure')
    commands = [json.loads(s) for s in (RUN / 'commands.jsonl').read_text().splitlines()]
    check(all(c['exit_code'] == 0 for c in commands), 'Recorded command failed')
    report['successful_logged_commands'] = len(commands)
    scans = {kind: read(RUN / next(c['log'] for c in reversed(commands)
                 if c['argv'][-2:] == ['--list-ids', kind])) for kind in ('prog', 'map')}
    report['phases'] = {}
    for mode, count in (('minimal', 1), ('inference', 7)):
        directory = RUN / mode
        events = [json.loads(s) for s in (directory / 'events.jsonl').read_text().splitlines()]
        schema = next(e for e in events if e['event'] == 'schema')
        ready = next(e for e in events if e['event'] == 'ready')
        check(schema['program_type'] == 3 and schema['programs'] == count and schema['pins_disabled'], 'Wrong type/pins')
        require_attached_filter((RUN / (mode + '-attachment.log')).read_text(), ready['program_id'])
        require_detach_ack(events, ready['program_id'])
        check((directory / 'controller.log').read_text() == '', 'Controller emitted errors')
        verifier = sorted(directory.glob('verifier-*.log'))
        check(len(verifier) == count and all('processed ' in p.read_text() for p in verifier), 'Missing verifier logs')
        check(read(directory / 'filter-absence.json') == {'ingress': [], 'egress': []}, 'Filters remain')
        absent = read(directory / 'ids-absent.json')
        check(absent['all_absent'] and absent['program_ids'] == ready['program_ids']
              and absent['map_ids'] == ready['map_ids'], 'Missing owned-ID release proof')
        check(not set(ready['program_ids']).intersection(scans['prog'])
              and not set(ready['map_ids']).intersection(scans['map']), 'Owned objects remain in registry')
        check(read(RUN / (mode + '-client.log'))['response'] == 'tc-demo-ok\n', 'TCP response missing')
        server = read(directory / 'server.log')
        check(server['greeting'] == 'hello\n' and server['client_fin'], 'TCP greeting/FIN missing')
        snapshot = read(directory / 'snapshot.json')
        check(snapshot == result[mode + '_snapshot'], 'Snapshot/result mismatch')
        report['phases'][mode] = {'verifier_programs': count, 'entry_id': ready['program_id'],
            'program_ids': ready['program_ids'], 'map_ids': ready['map_ids'],
            'packets': snapshot['packets'], 'bytes': snapshot['bytes'], 'cleanup': 'PASS'}
        if mode == 'inference':
            model_event = next(e for e in events if e['event'] == 'model')
            check(model_event == {'event': 'model', 'bytes_per_slot': 5216, 'slots_verified': 2, 'active': 0}, 'Model loading')
            slots = [e for e in events if e['event'] == 'tail_slot']
            check([e['slot'] for e in slots] == list(range(6)) and all(e['type'] == 3 for e in slots), 'Tail slots')
            check([e['program_id'] for e in slots] == ready['program_ids'][1:], 'Tail program IDs differ')
            check(snapshot['stages'] == [1]*6 and snapshot['tail_failures'] == 0
                  and snapshot['predictions'] == 1, 'Stage/prediction counters differ')
            model = Model.load(ROOT / 'src/mlp_params.bpf.h')
            report['comparisons'] = []
            for record in snapshot['results']:
                check(record['mask'] == 63 and record['model_slot'] == 0 and record['source_port'] == 40002, 'Wrong record')
                arithmetic = []
                tensors, label = model.infer(record['features'], arithmetic)
                matches = {stage: tensors[stage] == record['tensors'][i] for i, stage in enumerate(STAGES)}
                check(all(matches.values()) and record['label'] == label and not arithmetic, 'Numerical mismatch/overflow')
                report['comparisons'].append({'features': record['features'], 'stage_matches': matches,
                    'scalar_values_compared': sum(map(len, record['tensors'])), 'logits': tensors['logits'],
                    'label': label, 'arithmetic_events': arithmetic})
            check(len(report['comparisons']) == 1 and result['reference_comparisons'] == 6, 'Expected captured prediction')
    owned = read(RUN / 'owned.json')
    check(set(owned) == {'tcids-server', 'tcids-client'}, 'Unexpected namespaces')
    try:
        check(all(not (Path('/run/netns') / n).exists() for n in owned), 'Owned namespace path still exists')
        report['current_namespace_path_recheck'] = 'PASS: paths absent'
    except PermissionError:
        report['current_namespace_path_recheck'] = 'NOT RUN: unprivileged access to /run/netns denied'
    for name in owned:
        check(any(c['argv'] == ['ip', 'netns', 'delete', name] for c in commands), 'Namespace deletion missing')
    report['namespace_cleanup_saved_evidence'] = {'names': sorted(owned),
        'result': 'PASS: recorded deletions and privileged runner absence checks'}
    report['historical_map_56'] = ('STILL PRESENT in saved global scan; from preceding failed run, '
                                  'outside this run\'s owned IDs' if 56 in scans['map'] else 'ABSENT in saved global scan')
    report['optional_egress'] = result['optional_egress']
    report['scope'] = 'One attached live TCP/FIN flow; no accuracy/performance or general numerical-correctness claim'
    destination = Path(__file__).with_name('audit.json')
    destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
