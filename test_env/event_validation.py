"""Real-kernel Stage06 gate, not a replay or userspace inference substitute."""
import errno
import json
import signal

from evaluation.artifacts import DEFAULT_MODEL
from evaluation.model import infer, load_model, model_identity
from .collector import Collector
from .event_schema import COUNT_FIELDS, FLOW_STATES, RESULT_FIELDS
from .flow_fixture import Fixture, tcp_frame
from .flow_reference import reference_flow
from .inference import Inference, _live_cycle
from .tc import _need


def _synchronize(collector, sequence):
    collector.proc.send_signal(signal.SIGUSR1)
    collector.wait_for(lambda: collector.state.source_sequence >= sequence and
                       collector.state.native_counters is not None,
                       'independent native source counters')


def _drained(collector, count):
    collector.wait_for(lambda: collector.state.counts['accepted_classifications'] == count and
                       not collector.state.queue, 'all expected completions')


def compare_events(events, session):
    """Every exported integer and coherent count prefix must have real proof."""
    expected = session.results
    observed = {(row['flow_id'], row['trigger_ordinal']): row for row in events}
    _need(len(observed) == len(events) and set(observed) == set(expected),
          'Missing, duplicated or unexpected public completion jobs')
    proofs = []
    for key, event in observed.items():
        result = expected[key]
        _need(all(event[name] == result[name] for name in RESULT_FIELDS),
              'Public completion differs from actual kernel result ledger')
        oracle = infer(session.model, event['features'])
        _need(event['output'] == oracle['output'] and event['label'] == oracle['label'],
              'Public completion differs from exact integer reference')
        _need(event['counts_valid'], 'Validation completion lacks coherent direction counts')
        prefix = [row for row in session.observations if row['flow_id'] == key[0] and
                  row['ordinal'] <= event['counts_ordinal']]
        flow = reference_flow(prefix, session.ready['ifindex'])
        _need(flow['ordinal'] == event['counts_ordinal'] and flow['key'] == event['key'] and
              flow['last_ns'] == event['counts_timestamp_ns'] and
              flow['state'] == FLOW_STATES[event['flow_state']] and
              event['direction_counts'] == {name: {field: flow[name][field] for field in COUNT_FIELDS}
                                             for name in ('a_to_b', 'b_to_a')},
              'Event count prefix differs from independently parsed packet observations')
        proofs.append({'flow_id': key[0], 'trigger_ordinal': key[1],
                       'sequence': event['sequence'], 'counts_ordinal': flow['ordinal'],
                       'model_id': event['model_id'], 'label': event['label'],
                       'output': event['output'], 'integer_tolerance': 0})
    return {'status': 'pass', 'events': len(events), 'proofs': proofs}


def _normal(collector, expected):
    _drained(collector, expected)
    _synchronize(collector, expected)
    health = collector.health()
    _need(health['kernel_ring_drops'] == health['python_queue_drops'] ==
          health['reader_decode_errors'] == health['schema_errors'] == health['error_count'] == 0 and
          health['journal']['journal_dropped_records'] == 0 and
          health['sequence']['sequence_gaps'] == health['sequence']['duplicates'] == 0,
          'Ordinary collector execution lost, duplicated or rejected a completion')
    return health


def _parity(recorder, lab, session, collector, fixture):
    proof = {'live': _live_cycle(session, fixture)}
    expected = len(session.results)
    proof['normal_health'] = _normal(collector, expected)
    proof['event_parity'] = compare_events(collector.events(), session)
    duplicate = recorder.run(collector.reader_argv(), check=False, timeout=10)
    rows = [json.loads(line) for line in duplicate.stdout.splitlines() if line]
    _need(duplicate.returncode != 0 and any(row.get('event') == 'error' and
          row.get('errno') == errno.EADDRINUSE for row in rows) and collector.proc.poll() is None,
          'A competing native consumer was not refused without disrupting the first reader')
    proof['duplicate_reader'] = {'exit_code': duplicate.returncode, 'records': rows}
    fixture.send([(False, tcp_frame(sport=41050, dport=15050, flags=2).hex())])
    collector.proc.send_signal(signal.SIGUSR1)
    collector.wait_for(lambda: any(row['flow']['key']['b_port'] == 41050 and
                       row['classification_state'] == 'unclassified' for row in collector.flows()),
                       'genuine unclassified flow telemetry')
    proof['pending_flow'] = next(row for row in collector.flows() if row['flow']['key']['b_port'] == 41050)
    proof['reader_stop'] = collector.stop_reader()
    _need(not collector.health()['connected'], 'Stopped reader still claims a live connection')
    # Complete inference with no reader process at all; restart drains the ring.
    fixture.send([(False, tcp_frame(sport=41051, dport=15051, flags=4).hex())])
    session.inspect()
    _need(len(session.results) == expected + 1 and session.proc.poll() is None,
          'Inference depended on an attached userspace reader')
    proof['restart_ready'] = collector.restart_reader()
    proof['restart_health'] = _normal(collector, expected + 1)
    _need(proof['restart_health']['reader_restarts'] == 1, 'Reader restart was not observable')
    proof['event_parity_after_restart'] = compare_events(collector.events(), session)
    # A real unmodified TCP exchange still works after the restart.
    proof['forwarding'] = lab.exchange()
    session.inspect()
    _normal(collector, len(session.results))
    sample = collector.events()[:16]
    with (recorder.out / 'sample-live-events.jsonl').open('x', encoding='utf-8') as stream:
        for event in sample:
            stream.write(json.dumps(event, sort_keys=True) + '\n')
    proof['sample_records'] = len(sample)
    return proof


def _burst(fixture, port, count=64):
    return fixture.send([(False, tcp_frame(sport=port, dport=15060, flags=4,
                         sequence=100 + index).hex()) for index in range(count)])


def _pressure(recorder, lab, session, collector, fixture, *, kernel):
    before = session.inspect()['inference_counters']
    if kernel:
        collector.pause_reader()
    else:
        collector.pause_aggregation()
    proof = {'burst': _burst(fixture, 41060 if kernel else 41061)}
    stats = session.inspect()
    delta = {name: value - before[name] for name, value in stats['inference_counters'].items()}
    _need(delta['trigger'] == delta['complete'] == 64 and
          delta['event_emitted'] + delta['event_dropped'] == 64 and
          not session._bpf('map', 'dump', 'id', session.ready['map_ids']['nn_jobs']),
          'Pressure interrupted complete kernel inference or left an unfinished job')
    for event in session.results.values():
        oracle = infer(session.model, event['features'])
        _need(event['output'] == oracle['output'] and event['label'] == oracle['label'],
              'Pressure changed the kernel numerical result')
    if kernel:
        _need(delta['event_dropped'] > 0 and delta['event_emitted'] > 0,
              'Small paused ring did not exercise actual bounded overflow')
        proof['forwarding_while_reader_stopped'] = lab.exchange()
        _need(session.proc.poll() is None, 'Producer stopped when consumer was paused')
        collector.resume_reader()
        final = session.inspect()['inference_counters']
        _drained(collector, final['event_emitted'])
        _synchronize(collector, final['trigger'])
        _need(collector.health()['kernel_ring_drops'] == final['event_dropped'] and
              collector.health()['python_queue_drops'] == 0,
              'Kernel overflow was hidden or confused with consumer queue loss')
    else:
        collector.wait_for(lambda: collector.state.counts['accepted_classifications'] == 64,
                           'all native records while Python aggregation is paused')
        health = collector.health()
        _need(health['queue_size'] == 4 and health['python_queue_drops'] == 60 and
              health['aggregated_classifications'] == 0 and delta['event_dropped'] == 0,
              'Bounded drop-newest queue did not report its actual consumer loss')
        collector.resume_aggregation()
        collector.wait_for(lambda: not collector.state.queue, 'queue drain after aggregation resumes')
        _synchronize(collector, 64)
        _need(len(collector.events()) == 4, 'Dropped consumer records were fabricated into history')
    proof['inference_delta'] = delta
    proof['health'] = collector.health()
    _need(proof['health']['reader_decode_errors'] == proof['health']['schema_errors'] ==
          proof['health']['error_count'] == 0 and
          proof['health']['journal']['journal_dropped_records'] == 0,
          'Pressure caused unaccounted reader/schema/journal errors')
    return proof


def run_events(recorder, lab, loader, obj, bpftool, reader, model):
    """Run three owned real sessions; only return PASS after all FDs/maps release."""
    original = load_model(DEFAULT_MODEL)
    _need(model_identity(load_model(model)) == model_identity(original),
          'Stage06 acceptance requires unchanged original weights')
    result = {'schema_version': 1, 'stage': 'stage06', 'status': 'fail',
              'cleanup_complete': False, 'sessions': []}
    try:
        for kind in ('parity', 'kernel-pressure', 'python-pressure'):
            label = 'events-' + kind
            session = Inference(recorder, lab, loader, obj, bpftool, model, label=label,
                capture=kind == 'parity', trace=kind == 'parity',
                event_ring_bytes=4096 if kind == 'kernel-pressure' else 1 << 20)
            fixture = Fixture(recorder, lab, label)
            collector = None
            proof = {'kind': kind, 'status': 'fail'}
            result['sessions'].append(proof)
            try:
                proof['ready'] = session.start()
                collector = Collector(recorder, session, reader, label=label,
                                      queue_capacity=4 if kind == 'python-pressure' else 1024)
                proof['reader_ready'] = collector.start()
                proof['runtime'] = (_parity(recorder, lab, session, collector, fixture)
                    if kind == 'parity' else _pressure(recorder, lab, session, collector, fixture,
                                                       kernel=kind == 'kernel-pressure'))
            finally:
                try:
                    if fixture.capture_process is not None:
                        proof['capture_on_failure'] = fixture.stop_capture()
                finally:
                    try:
                        if collector is not None:
                            proof['collector_close'] = collector.close()
                            proof['reader_exits'] = collector.reader_exits
                            _need(proof['collector_close']['error_count'] == 0,
                                  'Collector did not release cleanly')
                    finally:
                        proof['cleanup'] = session.close()
                        recorder.write_json(label + '-proof.json', proof)
            _need(proof['cleanup']['complete'], 'Owned event producer resources remain')
            proof['forwarding_after_detach'] = lab.exchange()
            proof['status'] = 'pass'
            recorder.write_json(label + '-proof.json', proof)
        result['cleanup_complete'] = all(row['cleanup']['complete'] for row in result['sessions'])
        result['status'] = 'pass'
        return result
    finally:
        recorder.write_json('events.json', result)
