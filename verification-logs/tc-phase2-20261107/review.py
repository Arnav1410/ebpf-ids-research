#!/usr/bin/env python3
"""Read saved evidence only; no BPF, networking or new kernel execution."""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation'))
from reference import Model, STAGES


def read(path):
    return json.loads(path.read_text())


def main():
    output = Path(__file__).resolve().parent
    bundle = output / 'ready'
    runtime = bundle / 'run-20261107-015636-807250'
    failures = []
    checksums = (runtime / 'SHA256SUMS').read_text().splitlines()
    for line in checksums:
        expected, name = line.split('  ', 1)
        assert hashlib.sha256((runtime / name).read_bytes()).hexdigest() == expected, name
    manifest = read(bundle / 'manifest.json')
    for group, entries in manifest.items():
        for name, expected in entries.items():
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
                failures.append(dict(group=group, path=name))
    # Completion documentation may change after a run. Runtime source must not.
    assert all(f['group'] == 'prototype' and f['path'].endswith('.md') for f in failures), failures
    result = read(runtime / 'results.json')
    assert result['phase2_gate'] == result['cleanup'] == 'PASS'
    model = Model.load(ROOT / 'src/mlp_params.bpf.h')
    phases = {}
    counts = dict(records=0, stage_tensors=0, integers=0)
    all_programs, all_maps = set(), set()
    for name in ('kernel-checks', 'bidirectional-kernel-checks', 'minimal',
                 'inference', 'concurrent', 'bidirectional',
                 'bidirectional-concurrent', 'bidirectional-burst'):
        directory = runtime / name
        events = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
        loaded = next(e for e in events if e['event'] == 'loaded')
        ready = next((e for e in events if e['event'] == 'ready'), None)
        snapshot = next(e for e in reversed(events) if e['event'] == 'snapshot')
        absent = read(directory / 'ids-absent.json')
        assert absent['all_absent'] and absent['program_ids'] == loaded['program_ids']
        assert absent['map_ids'] == loaded['map_ids']
        all_programs.update(loaded['program_ids']); all_maps.update(loaded['map_ids'])
        verifier = sorted(directory.glob('verifier-*.log'))
        assert len(verifier) == len(loaded['program_ids'])
        assert all('processed ' in path.read_text() and ' insns ' in path.read_text() for path in verifier)
        if ready:
            assert read(directory / 'filter-absence.json') == dict(ingress=[], egress=[])
            for direction, program in (('ingress', ready['program_id']),
                                       ('egress', ready.get('egress_program_id'))):
                if program:
                    assert any(e['event'] == 'detach_acknowledged' and e['program_id'] == program
                               and e['direction'] == direction for e in events)
        numerical = dict(records=0, stage_tensors=0, integers=0)
        for record in snapshot['results']:
            arithmetic = []
            expected, label = model.infer(record['features'], arithmetic)
            assert not arithmetic and record['mask'] == 63
            for stage, actual in zip(STAGES, record['tensors']):
                assert expected[stage] == actual, (name, record['source_port'], stage)
                numerical['stage_tensors'] += 1
                numerical['integers'] += len(actual)
            assert label == record['label'] == (0 if record['tensors'][-1][0] > record['tensors'][-1][1] else 1)
            numerical['records'] += 1
        for key in counts: counts[key] += numerical[key]
        phase = dict(program_ids=loaded['program_ids'], map_ids=loaded['map_ids'],
                     ingress_program_id=ready['program_id'] if ready else None,
                     egress_program_id=ready.get('egress_program_id') if ready else None,
                     observed={k: snapshot[k] for k in ('packets', 'bytes', 'matched', 'egress_packets',
                         'egress_bytes', 'egress_matched', 'predictions', 'stages', 'tail_failures', 'timestamp_reorders')},
                     numerical=numerical, cleanup='PASS', verifier='PASS (saved load events and verifier summaries)')
        if name.startswith('bidirectional') and name != 'bidirectional-kernel-checks':
            witness = read(directory / 'packets.json')
            assert witness['capture_drops'] == 0
            # Independently recompute from saved packet observations; do not
            # reuse the runtime's packet_witness comparison function.
            flow_evidence = []
            for flow in snapshot['flows']:
                port = flow['source_port']
                groups = {hook: [p for p in witness['packets'] if p['hook'] == hook
                                 and (p['source_port'] if hook == 'ingress' else p['dest_port']) == port]
                          for hook in ('ingress', 'egress')}
                key = dict(a_ip='33.33.33.1', a_port=5001, b_ip='33.33.33.73', b_port=port, protocol=6)
                assert flow['key'] == key
                for hook, packets in groups.items():
                    assert packets and flow['hooks'][hook]['packets'] == len(packets)
                    assert flow['hooks'][hook]['bytes'] == sum(p['skb_bytes'] for p in packets)
                assert flow['endpoint_packets'] == [len(groups['egress']), len(groups['ingress'])]
                incoming = groups['ingress']; prefix = []
                for packet in incoming:
                    prefix.append(packet)
                    if packet['tcp_flags'] & 5: break
                assert prefix[-1]['tcp_flags'] & 5
                record = next(r for r in snapshot['results'] if r['source_port'] == port)
                expected = [max(p['segment_bytes'] for p in prefix), None,
                            min(p['segment_bytes'] for p in prefix), 5001,
                            sum(p['tcp_header_bytes'] for p in prefix), len(prefix)]
                assert all(record['features'][i] == expected[i] for i in (0, 2, 3, 4, 5))
                flow_evidence.append(dict(key=key, ingress_packets=len(incoming),
                    egress_packets=len(groups['egress']), features=record['features'],
                    first_linear_expected=model.infer(record['features'])[0][STAGES[1]],
                    first_linear_kernel=record['tensors'][1], logits=record['tensors'][-1], label=record['label']))
            phase['independent_packet_checks'] = dict(flows=len(flow_evidence),
                non_timing_features=5*len(flow_evidence), capture_drops=0, records=flow_evidence,
                iat='Not checked against capture clock; arithmetic uses actual kernel feature')
        phases[name] = phase
    assert counts == dict(records=61, stage_tensors=366, integers=8296), counts
    commands = [json.loads(line) for line in (runtime / 'commands.jsonl').read_text().splitlines()]
    assert all(command['exit_code'] == 0 for command in commands)
    owned = read(runtime / 'owned.json')
    assert set(owned) == {'tcids-server', 'tcids-client'}
    assert all(not (Path('/run/netns') / name).exists() for name in owned)
    review = dict(status='PASS', review_kind='Offline saved-evidence review; no privileged rerun',
        runtime=str(runtime.relative_to(ROOT)), checksum_entries=len(checksums), checksum_failures=0,
        prepared_manifest_entries=sum(map(len, manifest.values())),
        documentation_changes_after_run=failures, runtime_source_changes=0,
        comparisons=counts, comparison_failures=0, programs_released=len(all_programs),
        maps_released=len(all_maps), namespaces_absent=list(owned), phases=phases)
    (output / 'VERIFIED.json').write_text(json.dumps(review, indent=2)+'\n')
    print(json.dumps({k: v for k, v in review.items() if k != 'phases'}, indent=2))


if __name__ == '__main__':main()
