"""Owned Stage04 biflow sessions, inspection and real-packet acceptance proof.

No inference, prevention or per-packet UI stream is implemented. Diagnostic
headers are opt-in and bounded; ordinary Flow sessions have capture disabled.
The original RX FIN/RST scoring boundary is distinct from biflow full closure.
"""
from collections import Counter
import json
import time

from .flow_fixture import Fixture, controlled_phases, tcp_frame, unsupported_frames, TCP_PORT, DESTINATION_MAC
from .flow_reference import compare_capture, compare_snapshot, parse_headers
from .lab import SERVER_IF
from .tc import Probe, HOOKS, NS_PATH, _need, _object, _uint

COUNTERS = ('tracked', 'created', 'replaced', 'unknown', 'skip_truncated',
            'skip_vlan', 'skip_ipv6', 'skip_non_ipv4', 'skip_fragment',
            'skip_non_tcp', 'skip_malformed', 'skip_nonlinear', 'capacity_failure',
            'resolve_failure', 'observation_loss', 'gc_expired', 'gc_delete_failure',
            'id_exhausted')
LOSS_COUNTERS = ('capacity_failure', 'resolve_failure', 'observation_loss',
                 'gc_delete_failure', 'id_exhausted', 'diagnostic_buffer_loss')
SKIP_COUNTERS = tuple(name for name in COUNTERS if name.startswith('skip_'))
MAP_ABI = {
    'hook_counts': ('percpu_array', 4, 8, 2),
    'flow_index': ('lru_hash', 20, 8, 16384),
    'flow_stats': ('hash', 8, 208, 8192),
    'flow_serial': ('array', 4, 8, 1),
    'flow_config': ('array', 4, 24, 1),
    'tracking': ('percpu_array', 4, 8, len(COUNTERS)),
    'observations': ('ringbuf', 0, 0, 1 << 20),
}


class Flow(Probe):
    """Share Probe's strict identity, FD ownership, attach and release lifecycle."""
    program_keys = ('ingress', 'egress', 'gc')
    map_keys = tuple(MAP_ABI)
    max_event_bytes = 32 * 1024 * 1024

    def __init__(self, recorder, lab, loader, obj, bpftool, *, label='flows',
                 capture=False, idle_ms=120000, closed_ms=2000, gc_ms=250):
        super().__init__(recorder, lab, loader, obj, bpftool, label=label)
        for name, value in (('idle_ms', idle_ms), ('closed_ms', closed_ms), ('gc_ms', gc_ms)):
            if type(value) is not int or not 1 <= value <= 3600000:
                raise ValueError(name + ' must be 1..3600000')
        if type(capture) is not bool:
            raise ValueError('capture must be a boolean')
        self.configuration = {'idle_ms': idle_ms, 'closed_ms': closed_ms,
                              'gc_ms': gc_ms, 'capture_enabled': capture,
                              'capacity': 8192, 'index_capacity': 16384,
                              'diagnostic_capacity': 16384}
        self.observations = []
        self.skipped_observations = []
        self._ordinals = set()
        self._runtime_start_ns = None

    def start(self):
        _need(not self._started and self._closed is None, 'Flow instances cannot be restarted')
        self._runtime_start_ns = time.monotonic_ns()
        self.evidence['runtime_start_ns'] = self._runtime_start_ns
        return super().start()

    def _loader_args(self):
        config = self.configuration
        args = ['--idle-ms', str(config['idle_ms']), '--closed-ms', str(config['closed_ms']),
                '--gc-ms', str(config['gc_ms'])]
        return args + (['--capture'] if config['capture_enabled'] else [])

    def _validate_objects(self, ready):
        _need(ready.get('backend') == 'flows' and ready.get('flow_abi_version') == 1 and
              ready.get('feature_schema') == 'stage04-rx-v1' and
              ready.get('clock') == 'monotonic-lock-observed-clamped' and
              ready.get('snapshot_scope') == 'per-generation-locked-not-global',
              'Unexpected flow backend/schema/clock contract')
        _need(ready.get('config') == self.configuration, 'Loader flow configuration differs from request')
        programs, maps = {}, {}
        map_ids = set(ready['map_ids'].values())
        used = set()
        for role in self.program_keys:
            ident = ready['program_ids'][role]
            program = _object(self._bpf('prog', 'show', 'id', ident))
            bindings = program.get('map_ids')
            _need(program.get('id') == ident and program.get('name') == 'flow_' + role and
                  program.get('type') == 'sched_cls' and not program.get('pinned') and
                  isinstance(bindings, list) and bindings and set(bindings) <= map_ids,
                  'Wrong flow program identity/type/private map bindings: ' + role)
            if role in HOOKS:
                _need(ready['map_ids']['hook_counts'] in bindings, 'Flow role lacks its real hook counter')
            used.update(bindings)
            programs[role] = program
        _need(used == map_ids, 'Owned flow maps are not all bound to the loaded programs')
        for name, expected in MAP_ABI.items():
            ident = ready['map_ids'][name]
            actual = _object(self._bpf('map', 'show', 'id', ident))
            layout = tuple(actual.get(field) for field in ('type', 'bytes_key', 'bytes_value', 'max_entries'))
            _need(actual.get('id') == ident and actual.get('name') == name and
                  not actual.get('pinned') and layout == expected,
                  f'Unexpected owned map ABI for {name}: {layout}, expected {expected}')
            maps[name] = actual
        self.evidence['maps'] = maps
        return programs, maps['hook_counts']

    def snapshot(self):
        stats = super().snapshot()
        received_ns = time.monotonic_ns()
        _need(isinstance(stats.get('flows'), list) and isinstance(stats.get('observations'), list),
              'Flow stats omitted flows/observations')
        counters = stats.get('counters')
        _need(isinstance(counters, dict) and all(_uint(counters.get(name)) for name in COUNTERS),
              'Invalid tracking counters')
        _need(_uint(stats.get('snapshot_ns')) and _uint(stats.get('snapshot_end_ns')) and
              self._runtime_start_ns <= stats['snapshot_ns'] <=
              stats['snapshot_end_ns'] <= received_ns,
              'Controller snapshot clock is outside its independently measured runtime')
        ids = set()
        for flow in stats['flows']:
            _need(isinstance(flow, dict) and _uint(flow.get('id')) and flow['id'] > 0 and
                  flow['id'] not in ids and isinstance(flow.get('key'), dict), 'Invalid/duplicate flow generation')
            ids.add(flow['id'])
        for row in stats['observations']:
            _need(self.configuration['capture_enabled'], 'Production session unexpectedly streamed packet observations')
            _need(isinstance(row, dict) and all(_uint(row.get(name)) for name in
                  ('flow_id', 'ordinal', 'timestamp_ns', 'ifindex')) and
                  row['flow_id'] > 0 and row['ordinal'] > 0 and
                  row.get('direction') in (0, 1) and row.get('hook') in (0, 1) and
                  row['ifindex'] == self.ready['ifindex'], 'Invalid observation metadata')
            _need(self._runtime_start_ns <= row['timestamp_ns'] <= stats['snapshot_end_ns'],
                  'Kernel observation clock is outside the measured session/snapshot window')
            packet = parse_headers(row.get('header_hex', ''))
            _need(packet['direction'] == row['direction'], 'Observation direction disagrees with raw header')
            identity = (row['flow_id'], row['ordinal'])
            _need(identity not in self._ordinals, 'Duplicate diagnostic observation')
            self._ordinals.add(identity)
            self.observations.append(row)
        skipped = stats.get('skipped_observations')
        _need(isinstance(skipped, list), 'Flow stats omitted counted skip diagnostics')
        for row in skipped:
            _need(self.configuration['capture_enabled'] and isinstance(row, dict) and
                  row.get('reason') in SKIP_COUNTERS and row.get('hook') in (0, 1) and
                  row.get('ifindex') == self.ready['ifindex'] and
                  _uint(row.get('timestamp_ns')) and self._runtime_start_ns <=
                  row['timestamp_ns'] <= stats['snapshot_end_ns'],
                  'Invalid counted skip metadata/clock')
            raw = bytes.fromhex(row.get('header_hex', ''))
            maximum = 54 if row['reason'] == 'skip_ipv6' else 14
            _need(len(raw) <= maximum, 'Skip diagnostics exported more than fixed headers')
            if row['reason'] == 'skip_ipv6':
                _need(raw[12:14] == b'\x86\xdd', 'IPv6 skip disagrees with Ethernet protocol')
            self.skipped_observations.append(row)
        self.evidence['observation_count'] = len(self.observations)
        self.evidence['last_snapshot_received_ns'] = received_ns
        self._save()
        return stats

    def inspect(self):
        """Read-only coherent per-flow snapshots, without replay or synthetic time."""
        return self.snapshot()


def _loss_free(stats):
    counters = stats['counters']
    for name in LOSS_COUNTERS:
        value = counters.get(name, stats.get(name, 0))
        _need(_uint(value) and value == 0, f'Unexpected flow loss/error: {name}={value}')


def _by_port(stats, port):
    return [flow for flow in stats['flows'] if port in
            (flow['key']['a_port'], flow['key']['b_port'])]


def _check_state(stats, port, state, *, generation=None):
    matches = _by_port(stats, port)
    if generation is not None:
        matches = [flow for flow in matches if flow['id'] == generation]
    _need(len(matches) == 1 and matches[0]['state'] == state,
          f'Port {port} expected one {state} generation, observed {matches}')
    return matches[0]


def _proof(session, stats, *, excluded=()):
    _loss_free(stats)
    flows = [flow for flow in stats['flows'] if flow['id'] not in excluded]
    observations = [row for row in session.observations if row['flow_id'] not in excluded]
    return compare_snapshot(flows, observations, session.ready['ifindex'])


def _settled(session):
    """Wait for quiescent counters and a complete observation prefix.

    A flow dump is individually locked, not a global transaction. Controlled
    senders have finished before this call; two equal samples plus exact
    per-generation ordinals avoid comparing an in-flight dump with a later
    diagnostic-ring drain.
    """
    deadline = time.monotonic() + 3
    previous = None
    while True:
        stats = session.snapshot()
        _loss_free(stats)
        fingerprint = (tuple(sorted(stats['counters'].items())),
                       tuple(sorted((flow['id'], flow['ordinal']) for flow in stats['flows'])))
        seen = Counter(row['flow_id'] for row in session.observations)
        complete = all(seen[flow['id']] == flow['ordinal'] for flow in stats['flows'])
        skipped = Counter(row['reason'] for row in session.skipped_observations)
        complete = complete and all(skipped[name] == stats['counters'][name] for name in SKIP_COUNTERS)
        if fingerprint == previous and complete:
            return stats
        _need(time.monotonic() < deadline, 'Flow counters/diagnostics did not reach a complete quiescent prefix')
        previous = fingerprint
        time.sleep(0.05)



def _inspect_map(session, *, excluded=()):
    session._guard()
    utility = session.loader_path.parent / 'flow-inspect'
    completed = session.recorder.run([
        'nsenter', '--net=' + str(NS_PATH), '--', str(utility),
        str(session.ready['map_ids']['flow_stats']), SERVER_IF, str(NS_PATH),
        '--owner-pid', str(session.proc.pid)], timeout=10)
    events = [json.loads(line) for line in completed.stdout.splitlines() if line]
    inspections = [event for event in events if event.get('event') == 'inspection']
    stopped = [event for event in events if event.get('event') == 'stopped']
    _need(len(inspections) == 1 and len(stopped) == 1 and not stopped[0].get('errors'),
          'Read-only flow inspector omitted its snapshot/release evidence')
    snapshot = inspections[0]
    _need(snapshot.get('flow_abi_version') == 1 and
          snapshot.get('map_id') == session.ready['map_ids']['flow_stats'] and
          _uint(snapshot.get('snapshot_ns')) and
          _uint(snapshot.get('snapshot_end_ns')) and
          snapshot['snapshot_end_ns'] >= snapshot['snapshot_ns'],
          'Read-only inspector snapshot ABI/clock/map identity mismatch')
    proof = compare_snapshot(
        [flow for flow in snapshot['flows'] if flow['id'] not in excluded],
        [row for row in session.observations if row['flow_id'] not in excluded],
        session.ready['ifindex'])
    return {'status': 'pass', 'events': events, 'proof': proof,
            'scope': 'FD-proven owned map, BPF_F_RDONLY descriptor and individually locked snapshots'}

def _skip_accounting(expected, rows, delta):
    observed = Counter(row['reason'] for row in rows)
    _need(all(observed[name] == delta[name] for name in SKIP_COUNTERS),
          'Skip counter delta disagrees with exact diagnostic observations')
    fixture = Counter(row['reason'] for row in rows
                      if row['header_hex'].startswith(DESTINATION_MAC.hex()))
    _need(fixture == expected, f'Fixture skip reasons differ: {dict(fixture)} != {dict(expected)}')
    return {'status': 'pass', 'expected_fixture': dict(expected),
            'observed_fixture': dict(fixture), 'observed_total': dict(observed),
            'background_records': [row for row in rows
                                   if not row['header_hex'].startswith(DESTINATION_MAC.hex())]}


def _controlled_cycle(recorder, lab, loader, obj, bpftool, index):
    session = Flow(recorder, lab, loader, obj, bpftool, label=f'flow-cycle-{index}',
                   capture=True, idle_ms=120000, closed_ms=60000, gc_ms=100)
    fixture = Fixture(recorder, lab, session.label)
    result = {'cycle': index, 'status': 'fail', 'evidence_file': session.label + '.json', 'phases': []}
    try:
        result['ready'] = session.start()
        fixture.start_capture()
        base = _settled(session)
        _need(not base['flows'] and not session.observations,
              'Unattached selftest state leaked into attached flow tables')
        original = None
        excluded = set()
        for name, frames in controlled_phases():
            phase = {'name': name, 'injection': fixture.send(frames)}
            stats = _settled(session)
            if name == 'syn':
                original = _check_state(stats, 15001, 'open')
                _need(original['initiator'] == 'b' and original['ordinal'] == 4,
                      'Initial SYN orientation/retransmit counting is wrong')
                _need(original['a_to_b']['packets'] == 1 and original['b_to_a']['packets'] == 3,
                      'Reverse TC role was confused with canonical flow direction')
            elif name == 'options_and_unknown':
                unknown = _check_state(stats, 15002, 'open')
                _need(unknown['initiator'] == 'unknown' and unknown['a_to_b']['packets'] == 1 and
                      unknown['b_to_a']['packets'] == 1, 'Non-SYN traffic guessed an initiator')
            elif name == 'half_close':
                _check_state(stats, 15001, 'half_closed', generation=original['id'])
            elif name == 'both_fin':
                _check_state(stats, 15001, 'closing', generation=original['id'])
            elif name == 'full_close':
                original = _check_state(stats, 15001, 'closed', generation=original['id'])
            elif name == 'reuse':
                old = [flow for flow in _by_port(stats, 15001) if flow['id'] == original['id']]
                new = [flow for flow in _by_port(stats, 15001) if flow['id'] != original['id']]
                _need(len(old) == len(new) == 1 and new[0]['state'] == 'reset' and
                      new[0]['initiator'] == 'b' and new[0]['ordinal'] == 3,
                      'Tuple reuse did not publish a separate reset generation')
                _need(old[0]['state'] == 'replaced', 'New SYN did not retire the prior generation')
                _need(all(old[0][key] == original[key] for key in
                          ('a_to_b', 'b_to_a', 'ordinal', 'key', 'first_ns', 'last_ns')),
                      'Tuple reuse mutated the published old generation statistics')
                excluded.add(original['id'])
                phase['old_generation_before'] = original
                phase['old_generation_after'] = old[0]
            phase.update(stats=stats, proof=_proof(session, stats, excluded=excluded), status='pass')
            result['phases'].append(phase)
            recorder.write_json(session.label + '-proof.json', result)
        before = _settled(session)
        skip_start = len(session.skipped_observations)
        unsupported = unsupported_frames()
        result['unsupported_injection'] = fixture.send([(False, raw) for raw in unsupported.values()])
        after = _settled(session)
        expected = Counter({'skip_non_ipv4': 1, 'skip_vlan': 1, 'skip_ipv6': 1,
                            'skip_fragment': 1, 'skip_non_tcp': 1,
                            'skip_malformed': 2, 'skip_truncated': 1})
        delta = {name: after['counters'][name] - before['counters'][name] for name in COUNTERS}
        _need(delta['tracked'] == 0, 'Unsupported fixture accidentally entered TCP flow statistics')
        _loss_free(after)
        result['unsupported'] = _skip_accounting(
            expected, session.skipped_observations[skip_start:], delta)
        result['concurrent_tcp'] = fixture.concurrent_tcp(8)
        stats = _settled(session)
        connections = _by_port(stats, TCP_PORT)
        ports = {row['client_port'] for row in result['concurrent_tcp']['client']['connections']}
        _need(len(ports) == len(connections) == 8 and
              {flow['key']['b_port'] for flow in connections} == ports and
              all(flow['initiator'] == 'b' and flow['a_to_b']['packets'] > 0 and
                  flow['b_to_a']['packets'] > 0 for flow in connections),
              'Concurrent TCP connections shared/missed generation state')
        result['concurrent_proof'] = _proof(session, stats, excluded=excluded)
        # Stop capture only after draining the final real packet observations.
        capture = fixture.stop_capture()
        stats = _settled(session)
        result['capture'] = capture
        ipv6_capture = Counter(row['header_hex'] for row in capture['records']
                               if row['header_hex'][24:28] == '86dd')
        window_ipv6 = Counter(row['header_hex'] for row in
                              result['unsupported']['background_records'] if row['reason'] == 'skip_ipv6')
        _need(not (window_ipv6 - ipv6_capture), 'Background IPv6 skips lack independent AF_PACKET headers')
        result['capture_proof'] = compare_capture(session.observations, capture['records'],
                                                  ports={15001, 15002, TCP_PORT})
        result['final_proof'] = _proof(session, stats, excluded=excluded)
        result['read_only_inspection'] = _inspect_map(session, excluded=excluded)
        result['status'] = 'pass'
    finally:
        try:
            if fixture.capture_process is not None:
                result['capture_on_failure'] = fixture.stop_capture()
        finally:
            result['cleanup'] = session.close()
            recorder.write_json(session.label + '-proof.json', result)
    _need(result['cleanup']['complete'], 'Flow cleanup failed: ' + str(result['cleanup']['errors']))
    result['connectivity_after_detach'] = lab.exchange()
    return result


def _expiration_cycle(recorder, lab, loader, obj, bpftool):
    session = Flow(recorder, lab, loader, obj, bpftool, label='flow-expiration',
                   capture=True, idle_ms=6000, closed_ms=2500, gc_ms=50)
    fixture = Fixture(recorder, lab, session.label)
    result = {'status': 'fail'}
    try:
        session.start()
        fixture.send([(False, tcp_frame(sport=41010, dport=15010).hex()),
                      (False, tcp_frame(sport=41011, dport=15011, flags=4).hex())])
        first = _settled(session)
        opened = _check_state(first, 15010, 'open')
        closed = _check_state(first, 15011, 'reset')
        result['initial_proof'] = _proof(session, first)
        # Expire an old generation while a replacement with the SAME canonical
        # key remains live. A key-based delete would destroy the replacement.
        fixture.send([(False, tcp_frame(sport=41011, dport=15011,
                                       flags=2, sequence=123456).hex())])
        reused = _settled(session)
        replacements = [flow for flow in _by_port(reused, 15011) if flow['id'] != closed['id']]
        _need(len(replacements) == 1 and replacements[0]['state'] == 'open',
              'Same-tuple replacement did not create a new open generation')
        replacement = replacements[0]
        retired = _check_state(reused, 15011, 'replaced', generation=closed['id'])
        _need(all(retired[key] == value for key, value in closed.items() if key != 'state'),
              'Replacement changed the old generation statistics or expiry deadline')
        result['replacement_before_gc'] = {
            'retired': retired, 'replacement': replacement,
            'proof': _proof(session, reused, excluded=(closed['id'],))}
        deadline = time.monotonic() + 12
        snapshots = []
        expiration_ns = {
            opened['id']: opened['last_ns'] + session.configuration['idle_ms'] * 1000000,
            closed['id']: closed['closed_ns'] + session.configuration['closed_ms'] * 1000000,
            replacement['id']: replacement['last_ns'] + session.configuration['idle_ms'] * 1000000}
        disappearance = {}
        previous_ns = reused['snapshot_ns']
        saw_closed_first = False
        while True:
            stats = session.snapshot()
            _loss_free(stats)
            snapshots.append(stats)
            ids = {flow['id'] for flow in stats['flows']}
            for ident, expected_ns in expiration_ns.items():
                if ident not in ids and ident not in disappearance:
                    _need(stats['snapshot_ns'] >= expected_ns, 'GC expired a generation before its configured TTL')
                    disappearance[ident] = {'expected_not_before_ns': expected_ns,
                                            'observed_present_at_ns': previous_ns,
                                            'observed_absent_at_ns': stats['snapshot_ns'],
                                            'scheduler_tolerance_ns': 5000000000}
                    _need(stats['snapshot_ns'] <= expected_ns + 5000000000,
                          'Periodic GC exceeded its explicit five-second scheduling tolerance')
            previous_ns = stats['snapshot_ns']
            if closed['id'] not in ids and opened['id'] in ids:
                saw_closed_first = True
            if closed['id'] not in ids and replacement['id'] in ids:
                surviving = _check_state(stats, 15011, 'open', generation=replacement['id'])
                _need(surviving == replacement, 'Old-generation GC mutated its same-key replacement')
                result.setdefault('replacement_survived_old_gc',
                                  {'snapshot_ns': stats['snapshot_ns'], 'flow': surviving})
            if not ids:
                break
            _need(time.monotonic() < deadline, 'Periodic GC did not expire idle/closed real flow IDs')
            time.sleep(0.05)
        _need(saw_closed_first and result.get('replacement_survived_old_gc') and
              stats['counters']['gc_expired'] >= 3,
              'Closed/idle TTLs or same-key generation-safe GC were not independently observed')
        # Stale bounded canonical-index entries must resolve a new ID, never revive
        # or reset a deleted published statistics value.
        fixture.send([(False, tcp_frame(sport=41010, dport=15010).hex())])
        recreated = _settled(session)
        fresh = _check_state(recreated, 15010, 'open')
        _need(fresh['id'] not in expiration_ns and fresh['ordinal'] == 1,
              'Expired index resolution revived an old generation')
        rows = [row for row in session.observations if row['flow_id'] == fresh['id']]
        result.update(status='pass', snapshots=snapshots, expiration_proof=disappearance,
                      initial=first, recreated=recreated,
                      recreation_proof=compare_snapshot([fresh], rows, session.ready['ifindex']))
    finally:
        result['cleanup'] = session.close()
        recorder.write_json('flow-expiration-proof.json', result)
    _need(result['cleanup']['complete'], 'Expiration session cleanup failed')
    return result


def run_flows(recorder, lab, loader, obj, bpftool):
    """Run real Stage04 acceptance twice, plus periodic-GC/stale-index proof."""
    result = {'schema_version': 1, 'stage': 'stage04', 'status': 'fail',
              'cleanup_complete': False, 'cycles': []}
    try:
        for index in (1, 2):
            result['cycles'].append(_controlled_cycle(recorder, lab, loader, obj, bpftool, index))
            recorder.write_json('flows.json', result)
        result['expiration'] = _expiration_cycle(recorder, lab, loader, obj, bpftool)
        result.update(status='pass', cleanup_complete=True)
        return result
    except BaseException as exc:
        result['error'] = str(exc)
        # Individual session proof files retain cleanup even if an action raises.
        cleanups = []
        for label in ('flow-cycle-1', 'flow-cycle-2', 'flow-expiration'):
            path = recorder.out / (label + '.json')
            if path.exists():
                cleanups.append(json.loads(path.read_text(encoding='utf-8')).get('cleanup', {}).get('complete', False))
        result['cleanup_complete'] = bool(cleanups) and all(cleanups)
        raise
    finally:
        recorder.write_json('flows.json', result)
