"""Owned Stage05 TC inference and explicit, detect-only acceptance evidence.

Ordinary Probe and Flow defaults are untouched. All programs/maps, including the
six-stage tail-call chain, belong to one strict Flow/Probe lifetime. No global
BPF mutation, original-XDP release exception or floating-original claim exists.
"""
import hashlib
import json
from pathlib import Path
import struct
import tempfile

from evaluation.artifacts import DEFAULT_MODEL, read_json
from evaluation.dataset import load_dataset
from evaluation.model import infer, load_model, model_identity, pack_model, validate_model
from .flow_fixture import Fixture, controlled_phases, tcp_frame, TCP_PORT
from .flow_reference import compare_capture, compare_snapshot
from .flows import Flow, MAP_ABI as FLOW_MAP_ABI, _by_port, _loss_free, _settled
from .inference_reference import (STATUS_NAMES, arithmetic_edges, compare_trace,
                                  compare_triggers, compare_vectors, labeled_vectors,
                                  paired_evaluation, paired_selected_metrics)
from .lab import SERVER_IF
from .tc import HOOKS, NS_PATH, _need, _object, _raw, _uint

NN_COUNTERS = ('trigger', 'complete', 'unready', 'job_full', 'tail_missing',
               'bad_params', 'trace_full', 'result_full', 'rx_full', 'missing_job', 'bad_stage',
               'event_emitted', 'event_dropped', 'event_missing_counts')
NN_MAP_ABI = {
    'nn_rx': ('hash', 8, 56, 8192),
    'nn_jobs': ('hash', 16, 432, 8192),
    'nn_params': ('array', 4, 5216, 2),
    'nn_slots': ('array', 4, 40, 2),
    'nn_control': ('array', 4, 16, 1),
    'nn_tails': ('prog_array', 4, 4, 6),
    'nn_results': ('hash', 16, 152, 8192),
    'nn_traces': ('hash', 16, 544, 8192),
    'nn_zero': ('array', 4, 432, 1),
    'nn_tzero': ('array', 4, 544, 1),
    'nn_counts': ('percpu_array', 4, 8, len(NN_COUNTERS)),
    'nn_events': ('ringbuf', 0, 0, 1 << 20),
    'nn_event_seq': ('array', 4, 8, 1),
}
MAP_ABI = {**FLOW_MAP_ABI, **NN_MAP_ABI}
TAIL_ROLES = ('normalize', 'linear0', 'relu0', 'linear1', 'relu1', 'output')


class Inference(Flow):
    """Strict private inference profile, retaining all Flow/Probe safety checks."""
    program_keys = Flow.program_keys + ('vector',) + TAIL_ROLES
    map_keys = tuple(MAP_ABI)

    def __init__(self, recorder, lab, loader, obj, bpftool, model, *, label='inference',
                 capture=False, trace=False, idle_ms=120000, closed_ms=60000, gc_ms=100,
                 event_ring_bytes=1 << 20):
        super().__init__(recorder, lab, loader, obj, bpftool, label=label,
                         capture=capture, idle_ms=idle_ms, closed_ms=closed_ms, gc_ms=gc_ms)
        _need(type(trace) is bool, 'trace must be a boolean')
        _need(type(event_ring_bytes) is int and 4096 <= event_ring_bytes <= 1 << 20 and
              event_ring_bytes & (event_ring_bytes - 1) == 0,
              'event_ring_bytes must be a power of two from 4096 through 1048576')
        self.event_ring_bytes = event_ring_bytes
        self.model = validate_model(model) if isinstance(model, dict) else load_model(model)
        self.model_id = model_identity(self.model)
        self.parameters = pack_model(self.model)
        _need(len(self.parameters) == 5216, 'Unexpected serialized model ABI')
        self.trace_enabled = trace
        self.params_path = None
        self._runtime_files = None
        self._vector_serial = 0
        self.results = {}
        self.evidence.update(model_id=self.model_id, parameter_sha256=hashlib.sha256(self.parameters).hexdigest(),
                             trace_enabled=trace)

    def start(self):
        _need(not self._started and self._closed is None, 'Inference instances cannot be restarted')
        self._runtime_files = tempfile.TemporaryDirectory(prefix='nn-ebpf-inference-')
        self.params_path = Path(self._runtime_files.name) / 'params.bin'
        with self.params_path.open('xb') as stream:
            stream.write(self.parameters)
        return super().start()

    def close(self):
        try:
            return super().close()
        finally:
            if self._runtime_files is not None and (self.proc is None or self.proc.poll() is not None):
                self._runtime_files.cleanup()
                self._runtime_files = None

    def _loader_args(self):
        return super()._loader_args() + ['--params', str(self.params_path), '--model-id', self.model_id,
                                       '--event-ring-bytes', str(self.event_ring_bytes)] + (
            ['--trace'] if self.trace_enabled else [])

    def _lookup(self, name, index, size):
        entry = _object(self._bpf('map', 'lookup', 'id', self.ready['map_ids'][name],
                                  'key', 'hex', *[f'{byte:02x}' for byte in struct.pack('=I', index)]))
        return _raw(entry.get('value'), size)

    def _verify_model(self):
        control = self._lookup('nn_control', 0, 16)
        active, trace, serial = struct.unpack('=IIQ', control)
        _need(active in (0, 1) and trace == int(self.trace_enabled),
              'Unexpected active model/trace control')
        slots = [self._lookup('nn_slots', slot, 40) for slot in range(2)]
        readiness = [struct.unpack_from('=II', slot) for slot in slots]
        _need(all(ready in (0, 1) and reserved == 0 for ready, reserved in readiness) and
              readiness[active][0] == 1, 'Model slot is not explicitly initialized')
        raw = self._lookup('nn_params', active, 5216)
        _need(self._lookup('nn_zero', 0, 432) == bytes(432) and
              self._lookup('nn_tzero', 0, 544) == bytes(544),
              'Owned immutable inference initialization templates are not zero')
        digest = hashlib.sha256(raw).hexdigest()
        _need(raw == self.parameters and slots[active][8:].hex() == self.model_id,
              'Actual owned model map bytes/slot identity differ from the requested model')
        tails = []
        for index, role in enumerate(TAIL_ROLES):
            ident, = struct.unpack('=I', self._lookup('nn_tails', index, 4))
            _need(ident == self.ready['program_ids'][role], 'Owned tail-call slot differs: ' + role)
            tails.append(ident)
        proof = {'active_slot': active, 'ready_slots': [value[0] for value in readiness],
                 'model_id': self.model_id, 'actual_parameter_sha256': digest,
                 'slot_bytes_sha256': hashlib.sha256(b''.join(slots)).hexdigest(),
                 'tail_program_ids': tails, 'vector_serial': serial,
                 'identity_binding': 'independent raw owned map readback, not loader CLI text'}
        self.evidence['model_readback'] = proof
        self._save()
        return proof

    def _validate_objects(self, ready):
        _need(ready.get('backend') == 'inference' and ready.get('flow_abi_version') == 1 and
              ready.get('nn_abi_version') == 2 and ready.get('feature_schema') == 'original-rx-six-v1' and
              ready.get('model_schema') == 'mlp-6-32-32-2-no-bias-q16-v1' and
              ready.get('quantization') == 16 and ready.get('model_id') == self.model_id and
              ready.get('trace_enabled') is self.trace_enabled and
              ready.get('clock') == 'monotonic-lock-observed-clamped' and
              ready.get('snapshot_scope') == 'per-generation-locked-not-global',
              'Unexpected inference backend/model/feature/clock contract')
        _need(ready.get('event_ring_bytes') == self.event_ring_bytes and
              ready.get('event_schema_version') == 1 and ready.get('event_size') == 256,
              'Unexpected completion event ring/schema contract')
        _need(ready.get('config') == self.configuration, 'Inference flow configuration differs from request')
        programs, maps, used = {}, {}, set()
        all_maps = set(ready['map_ids'].values())
        for role in self.program_keys:
            ident = ready['program_ids'][role]
            actual = _object(self._bpf('prog', 'show', 'id', ident))
            expected_name = ('flow_' if role in Flow.program_keys else 'nn_') + role
            bindings = actual.get('map_ids')
            _need(actual.get('id') == ident and actual.get('name') == expected_name and
                  actual.get('type') == 'sched_cls' and not actual.get('pinned') and
                  isinstance(bindings, list) and bindings and set(bindings) <= all_maps,
                  'Unexpected private inference program identity/bindings: ' + role)
            if role in HOOKS:
                _need(ready['map_ids']['hook_counts'] in bindings, 'Inference hook lost its actual counter')
            used.update(bindings)
            programs[role] = actual
        _need(used == all_maps, 'Inference manifest includes unbound or omits real owned maps')
        for name, expected in MAP_ABI.items():
            if name == 'nn_events':
                expected = (*expected[:3], self.event_ring_bytes)
            ident = ready['map_ids'][name]
            actual = _object(self._bpf('map', 'show', 'id', ident))
            layout = tuple(actual.get(field) for field in ('type', 'bytes_key', 'bytes_value', 'max_entries'))
            _need(actual.get('id') == ident and actual.get('name') == name and
                  not actual.get('pinned') and layout == expected,
                  f'Unexpected owned inference map ABI for {name}: {layout}, expected {expected}')
            if name in NN_MAP_ABI:
                frozen = name in ('nn_params', 'nn_zero', 'nn_tzero')
                flags = 128 if frozen else 1 if name == 'nn_traces' else 0
                _need(actual.get('flags') == flags and (not frozen or actual.get('frozen') == 1),
                      'Unexpected inference map access/allocation/freeze flags: ' + name)
            maps[name] = actual
        self.evidence['maps'] = maps
        self._verify_model()
        return programs, maps['hook_counts']

    def snapshot(self):
        stats = super().snapshot()
        rows, counters = stats.get('inference_results'), stats.get('inference_counters')
        _need(isinstance(rows, list) and isinstance(counters, dict) and
              set(counters) == set(NN_COUNTERS) and all(_uint(value) for value in counters.values()),
              'Inference snapshot omitted exact result/counter ABI')
        seen = set()
        for row in rows:
            _need(isinstance(row, dict), 'Invalid inference result')
            fields = {'flow_id', 'trigger_ordinal', 'timestamp_ns', 'features', 'model_id',
                      'stage_bitmap', 'status', 'slot', 'label', 'output', 'key', 'trigger_flags'}
            _need(set(row) in (fields, fields | {'stages'}),
                  'Inference result omitted public ABI fields or exported private kernel context')
            key = (row.get('flow_id'), row.get('trigger_ordinal'))
            _need(all(_uint(value) and value > 0 for value in key) and key not in seen,
                  'Duplicate, invalid or vector-only live inference job key')
            seen.add(key)
            _need(_uint(row.get('trigger_flags'), 8) and row['trigger_flags'] & 5,
                  'Live inference result lacks the actual FIN/RST trigger flags')
            _need(_uint(row.get('timestamp_ns')) and self._runtime_start_ns <= row['timestamp_ns'] <=
                  stats['snapshot_end_ns'] and isinstance(row.get('features'), list) and
                  len(row['features']) == 6 and all(type(value) is int and -(1 << 63) <= value < 1 << 63
                                                 for value in row['features']),
                  'Inference result features/clock are outside the actual runtime')
            _need(type(row.get('status')) is int and row['status'] in range(len(STATUS_NAMES)) and
                  _uint(row.get('stage_bitmap'), 6), 'Invalid inference result status/bitmap')
            _need(isinstance(row.get('output'), list) and len(row['output']) == 2 and
                  all(type(value) is int and -(1 << 31) <= value < 1 << 31 for value in row['output']),
                  'Inference logits are not two signed32 integers')
            if row['status'] == 0:
                _need(row['stage_bitmap'] == 63 and type(row.get('label')) is int and row['label'] in (0, 1) and
                      row.get('model_id') == self.model_id and row.get('slot') in (0, 1),
                      'Complete inference is partial or unbound to the loaded model')
            else:
                _need(row.get('label') is None, 'Failed inference exported a partial label')
            if self.trace_enabled:
                compare_trace(row, self.model, row['features'], success=row['status'] == 0)
            else:
                _need('stages' not in row or row['stages'] is None,
                      'Production inference unexpectedly exported diagnostic intermediate arrays')
            _need(key not in self.results or self.results[key] == row, 'Published immutable job result changed')
            self.results[key] = row
        self.evidence['inference_result_count'] = len(self.results)
        self._save()
        return stats

    def vectors(self, declared, *, fault=None):
        """Invoke only the native FD-proven test-run entry in this owned session."""
        _need(self.trace_enabled and self.ready is not None and self.proc.poll() is None and
              self._closed is None, 'Vector validation requires an active diagnostic session')
        _need(isinstance(declared, list) and 1 <= len(declared) <= 4096, 'Vector batch exceeds native bound')
        self._guard()
        self._vector_serial += 1
        path = self.params_path.parent / f'vectors-{self._vector_serial}.bin'
        with path.open('xb') as stream:
            for sample in declared:
                features = sample['features']
                infer(self.model, features)  # Reuse the canonical signed64 input validation.
                stream.write(struct.pack('=6q', *features))
        before = self._verify_model()
        argv = ['nsenter', '--net=' + str(NS_PATH), '--', str(self.loader_path.parent / 'nn-vectors'),
                str(self.ready['program_ids']['vector']), SERVER_IF, str(NS_PATH),
                '--owner-pid', str(self.proc.pid)]
        for option, name in (('--results', 'nn_results'), ('--traces', 'nn_traces'),
                             ('--control', 'nn_control'), ('--slots', 'nn_slots'), ('--tails', 'nn_tails')):
            argv += [option, str(self.ready['map_ids'][name])]
        argv += ['--input', str(path)]
        if fault == 'unready':
            argv += ['--unready']
        elif type(fault) is int and 0 <= fault < 6:
            argv += ['--missing-slot', str(fault)]
        else:
            _need(fault is None, 'Unsupported owned diagnostic fault mode')
        completed = self.recorder.run(argv, timeout=120)
        events = [json.loads(line) for line in completed.stdout.splitlines() if line]
        batches = [event for event in events if isinstance(event, dict) and 'vectors' in event]
        stopped = [event for event in events if isinstance(event, dict) and event.get('event') == 'stopped']
        _need(len(batches) == 1 and len(stopped) == 1 and not stopped[0].get('errors') and
              len(events) == 2, 'Native vector utility omitted clean descriptor-release evidence')
        output = batches[0]
        _need(isinstance(output, dict) and output.get('schema_version') == 1 and
              output.get('count') == len(declared) and _uint(output.get('elapsed_ns')) and
              isinstance(output.get('vectors'), list) and len(output['vectors']) == len(declared),
              'Native inference vector utility omitted measured batch/elapsed evidence')
        _need(output.get('owned_keys_removed') is True and output.get('slots_restored') is True,
              'Native utility did not remove its private jobs/restore fault slots')
        job_keys = {(row.get('flow_id'), row.get('trigger_ordinal')) for row in output['vectors']}
        for name in ('nn_jobs', 'nn_results', 'nn_traces'):
            entries = self._bpf('map', 'dump', 'id', self.ready['map_ids'][name])
            _need(isinstance(entries, list), 'Invalid owned inference map dump')
            for entry in entries:
                key = struct.unpack('=QQ', _raw(entry.get('key'), 16))
                _need(key not in job_keys, 'Native vector utility retained a consumed job: ' + name)
        after = self._verify_model()
        _need(all(before[field] == after[field] for field in
                  ('active_slot', 'ready_slots', 'slot_bytes_sha256', 'model_id',
                   'actual_parameter_sha256', 'tail_program_ids')),
              'Owned fault utility failed to restore model readiness/tail-call slots')
        for row in output['vectors']:
            _need(row.get('cb_restored') is True and row.get('retval') == 0,
                  'Vector test-run did not restore all skb control words/TC_ACT_OK')
        if fault is None:
            proof = compare_vectors(output['vectors'], declared, self.model)
        else:
            expected_status = 1 if fault == 'unready' else 3
            expected_bitmap = 0 if fault == 'unready' else (1 << fault) - 1
            for row, sample in zip(output['vectors'], declared):
                compare_trace(row, self.model, sample['features'], success=False)
                _need(row['status'] == expected_status and row['stage_bitmap'] == expected_bitmap,
                      'Diagnostic fault did not produce the expected observable error/stage prefix')
            proof = {'status': 'pass', 'fault': fault, 'expected_status': expected_status,
                     'stage_bitmap': expected_bitmap, 'partial_label': False, 'cb_restored': True,
                     'owned_slots_restored': True}
        self.recorder.write_json(f'{self.label}-vectors-{self._vector_serial}.json',
                                 {'native': output, 'proof': proof, 'model_readback': after})
        return proof


def _inference_loss_free(stats, baseline):
    _loss_free(stats)
    delta = {name: value - baseline['inference_counters'][name]
             for name, value in stats['inference_counters'].items()}
    _need(all(value >= 0 for value in delta.values()), 'Inference counters regressed')
    for name, value in delta.items():
        if name not in ('trigger', 'complete', 'event_emitted'):
            _need(value == 0, f'Unexpected live inference loss/failure: {name}={value}')
    _need(delta['trigger'] == delta['complete'],
          'A live trigger failed to produce complete inference')
    _need(delta['event_emitted'] == delta['trigger'],
          'A live trigger failed to publish its completion event')


def _live_cycle(session, fixture):
    result = {'status': 'fail', 'phases': []}
    fixture.start_capture()
    initial = _settled(session)
    _need(not initial['flows'] and not initial['inference_results'] and not session.observations,
          'Native/unattached test state leaked into real packet generations')
    generation, half_close_key, closed_generation = None, None, None
    for name, frames in controlled_phases():
        fixture.send(frames)
        stats = _settled(session)
        _inference_loss_free(stats, initial)
        proof = compare_triggers(list(session.results.values()), session.observations,
                                 session.model, session.ready['ifindex'])
        if name == 'half_close':
            flows = _by_port(stats, 15001)
            _need(len(flows) == 1 and flows[0]['state'] == 'half_closed',
                  'First RX FIN did not precede bidirectional full closure')
            generation = flows[0]['id']
            keys = [key for key in session.results if key[0] == generation]
            _need(len(keys) == 1, 'First matching RX FIN failed to trigger before full close')
            half_close_key = keys[0]
        if name == 'both_fin':
            _need(len([key for key in session.results if key[0] == generation]) == 1,
                  'Reverse FIN incorrectly triggered original matching-RX inference')
        if name == 'full_close':
            _need(any(flow['id'] == generation and flow['state'] == 'closed' for flow in stats['flows']) and
                  half_close_key in session.results, 'Full-close boundary lost the earlier FIN score')
            closed_generation = next(flow for flow in stats['flows'] if flow['id'] == generation)
        if name == 'reuse':
            old = next((flow for flow in stats['flows'] if flow['id'] == generation), None)
            new = [flow for flow in _by_port(stats, 15001) if flow['id'] != generation]
            _need(old is not None and old['state'] == 'replaced' and len(new) == 1 and
                  new[0]['ordinal'] == 3 and new[0]['state'] == 'reset' and
                  all(old[field] == closed_generation[field] for field in
                      ('key', 'ordinal', 'first_ns', 'last_ns', 'a_to_b', 'b_to_a')),
                  'Tuple reuse carried RX history or mutated the retired flow generation')
            new_scores = [row for row in session.results.values() if row['flow_id'] == new[0]['id']]
            _need(len(new_scores) == 1 and new_scores[0]['features'][-1] == 2,
                  'Replacement generation inherited old RX packet accumulation')
            result['generation_reuse'] = {'retired': generation, 'replacement': new[0]['id'],
                                          'old_result_retained': half_close_key in session.results}
        result['phases'].append({'name': name, 'trigger_proof': proof})
    # Repeated FIN/RST must not be collapsed to first FIN or full biflow close.
    fixture.send([(False, tcp_frame(sport=41020, dport=15020, flags=2, sequence=300).hex()),
                  (False, tcp_frame(sport=41020, dport=15020, flags=17, sequence=301).hex()),
                  (False, tcp_frame(sport=41020, dport=15020, flags=17, sequence=301).hex()),
                  (False, tcp_frame(sport=41020, dport=15020, flags=4, sequence=302).hex()),
                  (False, tcp_frame(sport=41020, dport=15020, flags=4, sequence=302).hex())])
    stats = _settled(session)
    repeated = _by_port(stats, 15020)
    _need(len(repeated) == 1 and len([key for key in session.results if key[0] == repeated[0]['id']]) == 4,
          'Repeated matching FIN/RST packets did not retain four independent jobs')
    # AF_PACKET also observes frames which bypass the source-IP scoring filter.
    altered = bytearray(tcp_frame(sport=41021, dport=15021, flags=4))
    altered[29] = 74
    fixture.send([(False, bytes(altered).hex())])
    stats = _settled(session)
    _need(not [row for row in session.results.values() if row['key']['b_port'] == 41021],
          'Nonmatching source IP was scored')
    result['concurrent_tcp'] = fixture.concurrent_tcp(8)
    stats = _settled(session)
    _inference_loss_free(stats, initial)
    connections = _by_port(stats, TCP_PORT)
    ports = {row['client_port'] for row in result['concurrent_tcp']['client']['connections']}
    _need(len(connections) == len(ports) == 8 and
          {flow['key']['b_port'] for flow in connections} == ports,
          'Eight real simultaneous TCP connections shared or lost flow generation state')
    scored_ids = {row['flow_id'] for row in session.results.values()}
    _need(all(flow['id'] in scored_ids for flow in connections), 'Concurrent TCP closure omitted a matching RX score')
    capture = fixture.stop_capture()
    stats = _settled(session)
    _inference_loss_free(stats, initial)
    result['trigger_proof'] = compare_triggers(list(session.results.values()), session.observations,
                                              session.model, session.ready['ifindex'])
    retired = {flow['id'] for flow in stats['flows'] if flow['state'] == 'replaced'}
    # Replacement is a lifecycle marker, not derivable from the old packet prefix;
    # its unchanged arithmetic was independently checked at the reuse boundary.
    result['retired_generation_ids'] = sorted(retired)
    result['flow_proof'] = compare_snapshot(
        [flow for flow in stats['flows'] if flow['id'] not in retired],
        [row for row in session.observations if row['flow_id'] not in retired],
        session.ready['ifindex'])
    result['capture'] = capture
    result['capture_proof'] = compare_capture(session.observations, capture['records'],
                                              ports={15001, 15002, 15020, 15021, TCP_PORT})
    result['status'] = 'pass'
    return result


def _session_proof(recorder, lab, loader, obj, bpftool, model, label, declared, *, live=False,
                   faults=False, require_both=False):
    session = Inference(recorder, lab, loader, obj, bpftool, model, label=label,
                        capture=live, trace=True)
    fixture = Fixture(recorder, lab, label)
    result = {'status': 'fail', 'model_id': session.model_id}
    try:
        result['ready'] = session.start()
        result['vectors'] = session.vectors(declared)
        if require_both:
            _need(result['vectors']['predicted_classes'] == [0, 1],
                  'Declared integer kernel pipeline did not exercise both predicted classes')
        if faults:
            result['faults'] = [session.vectors([declared[0]], fault='unready')]
            result['faults'] += [session.vectors([declared[0]], fault=index) for index in range(6)]
            # A complete rerun proves restored slots are executable, not just present.
            result['after_faults'] = session.vectors([declared[0]])
        if live:
            result['live'] = _live_cycle(session, fixture)
        result['actions_complete'] = True
    finally:
        try:
            if fixture.capture_process is not None:
                result['capture_on_failure'] = fixture.stop_capture()
        finally:
            result['cleanup'] = session.close()
            result['status'] = 'fail'
            recorder.write_json(label + '-proof.json', result)
    try:
        _need(result['cleanup']['complete'],
              'Inference private-object cleanup failed: ' + str(result['cleanup']['errors']))
        result['forwarding_after_detach'] = lab.exchange()
        result['status'] = 'pass'
    finally:
        recorder.write_json(label + '-proof.json', result)
    return result


def _near_zero_model(original):
    """Explicit test-only model, never a substitute for original or paired weights."""
    model = {**original, 'mean': [0] * 6, 'scale': [1] * 6,
             'layer_0_weight': [0] * 192, 'layer_1_weight': [0] * 1024,
             'layer_2_weight': [0] * 64}
    model['layer_0_weight'][0] = 1
    model['layer_1_weight'][0] = 65536
    model['layer_2_weight'][0] = 65536
    model['provenance'] = {'kind': 'synthetic_owned_near_zero_tie_test_only'}
    return validate_model(model)


def _overflow_model(original):
    """Force signed64 dot-product wrap and signed32 narrowing in a private model."""
    model = {**original, 'mean': [0] * 6, 'scale': [65536] * 6,
             'layer_0_weight': [(1 << 31) - 1] * 192,
             'layer_1_weight': [(1 << 31) - 1] * 1024,
             'layer_2_weight': [(1 << 31) - 1] * 32 + [-(1 << 31)] * 32,
             'provenance': {'kind': 'synthetic_owned_int64_accumulator_overflow_test_only'}}
    return validate_model(model)


def run_inference(recorder, lab, loader, obj, bpftool, model, paired_dir):
    """Complete Stage05 proof; compilation and root opt-in belong to the caller."""
    result = {'schema_version': 1, 'stage': 'stage05', 'status': 'fail',
              'cleanup_complete': False, 'sessions': [],
              'limitations': ['Original floating checkpoint is absent; no original float metrics are claimed.',
                              'Original weight accuracy is diagnostic: training overlap unknown.',
                              'Numeric label semantics and dataset feature units are unverified.',
                              'Detect-only TC_ACT_OK; no throughput or prevention claim.']}
    labels = []
    try:
        dataset = load_dataset()
        original = load_model(model)
        _need(model_identity(original) == model_identity(load_model(DEFAULT_MODEL)),
              'Stage05 primary must be the unchanged original weights; the actual M3 pair is a separate control')
        result['original_model_id'] = model_identity(original)
        split_path = Path(paired_dir) / 'split.json'
        split = read_json(split_path) if split_path.is_file() else None
        labeled, selection = labeled_vectors(dataset, split)
        result['sample_selection'] = selection
        recorder.write_json('inference-samples.json', {'selection': selection, 'samples': labeled})
        declared = labeled + arithmetic_edges(original)
        labels.append('inference-original-1')
        result['sessions'].append(_session_proof(recorder, lab, loader, obj, bpftool, original,
            labels[-1], declared, live=True, faults=True, require_both=True))
        result['original_metrics_scope'] = 'diagnostic static weights; frozen membership does not prove original training exclusion'
        # Repeat a fresh owned loader/flow/job lifetime, not a reused global scratch map.
        labels.append('inference-original-2')
        result['sessions'].append(_session_proof(recorder, lab, loader, obj, bpftool, original,
            labels[-1], declared, live=True, require_both=True))
        pair_out = recorder.out / 'inference-paired-float'
        pair_out.mkdir(exist_ok=False)
        try:
            pair = paired_evaluation(dataset, paired_dir, pair_out)
        except (FileNotFoundError, ImportError, ModuleNotFoundError) as exc:
            result['status'] = 'blocked'
            raise RuntimeError('Actual saved paired M3 float/quantized checkpoint or float dependencies unavailable: ' + str(exc)) from exc
        except RuntimeError as exc:
            if isinstance(exc.__cause__, ImportError):
                result['status'] = 'blocked'
            raise
        quantized = pair.pop('quantized')
        result['paired_actual_M3_not_original'] = pair
        labels.append('inference-paired-M3')
        result['sessions'].append(_session_proof(recorder, lab, loader, obj, bpftool, quantized,
            labels[-1], labeled + arithmetic_edges(quantized), require_both=True))
        result['paired_selected_same_membership'] = paired_selected_metrics(
            pair_out, labeled, result['sessions'][-1]['vectors']['proofs'])
        synthetic = _near_zero_model(original)
        synthetic_vectors = [{'features': [value, 0, 0, 0, 0, 0], 'kind': 'synthetic_arithmetic',
                              'name': f'near_zero_weight_input_{value}'} for value in (-1, 0, 1, 65535, 65536)]
        labels.append('inference-synthetic-near-zero')
        result['sessions'].append(_session_proof(recorder, lab, loader, obj, bpftool, synthetic,
            labels[-1], synthetic_vectors, require_both=True))
        overflow = _overflow_model(original)
        overflow_vectors = [{'features': row, 'kind': 'synthetic_arithmetic',
                             'name': f'int64_accumulator_overflow_{index}'}
                            for index, row in enumerate(([0] * 6, [(1 << 31) - 1] * 6,
                                [-(1 << 31)] * 6, [(1 << 31) - 1, -(1 << 31)] * 3))]
        labels.append('inference-synthetic-overflow')
        result['sessions'].append(_session_proof(recorder, lab, loader, obj, bpftool, overflow,
            labels[-1], overflow_vectors))
        result.update(status='pass', cleanup_complete=True)
        return result
    except BaseException as exc:
        result['error'] = str(exc)
        cleanups = []
        for label in labels:
            path = recorder.out / (label + '.json')
            cleanups.append(path.is_file() and read_json(path).get('cleanup', {}).get('complete') is True)
        result['cleanup_complete'] = bool(cleanups) and all(cleanups)
        raise
    finally:
        recorder.write_json('inference.json', result)
