"""Versioned, payload-free native event boundary; this module never infers labels.

JSON records are the decoder's public representation of the 256-byte little-
endian ring ABI. Source identity is supplied by an independently owned producer,
not adopted from the first record. Unit fixtures are not live provenance proof.
"""
import ipaddress
import json
import re

SCHEMA_VERSION = 1
EVENT_SCHEMA_VERSION = 1
EVENT_SIZE = 256
NN_ABI_VERSION = 2
FEATURE_SCHEMA = 'original-rx-six-v1'
MODEL_SCHEMA = 'mlp-6-32-32-2-no-bias-q16-v1'
MAX_RECORD_BYTES = 65536
NN_COUNTERS = ('trigger', 'complete', 'unready', 'job_full', 'tail_missing',
               'bad_params', 'trace_full', 'result_full', 'rx_full', 'missing_job',
               'bad_stage', 'event_emitted', 'event_dropped', 'event_missing_counts')
COUNT_FIELDS = ('packets', 'ipv4_bytes', 'tcp_segment_bytes', 'tcp_header_bytes')
FLOW_STATES = ('open', 'half_closed', 'closing', 'closed', 'reset', 'replaced')
SOURCE_IDS = ('owner_pid', 'ring_map_id', 'counters_map_id', 'sequence_map_id',
              'slots_map_id', 'control_map_id', 'hook_counts_map_id', 'flow_stats_map_id')
COMMON = {'schema_version', 'event', 'source', 'mode', 'clock'}
RESULT_FIELDS = {'flow_id', 'trigger_ordinal', 'timestamp_ns', 'features', 'model_id',
                 'stage_bitmap', 'status', 'slot', 'label', 'output', 'key', 'trigger_flags'}
CLASSIFICATION_FIELDS = RESULT_FIELDS | {
    'sequence', 'event_schema_version', 'counts_ordinal', 'counts_timestamp_ns',
    'direction_counts', 'flow_state', 'counts_valid', 'reason'}
READY_FIELDS = {'nn_abi_version', 'event_schema_version', 'event_size', 'event_ring_bytes',
                'feature_schema', 'model_schema', 'quantization', 'ifindex'}
COUNTER_FIELDS = {'timestamp_ns', 'sequence', 'inference_counters', 'reader_decode_errors', 'hook_counts',
                  'snapshot_ns', 'snapshot_end_ns', 'flow_limit', 'flows_total', 'flows_truncated', 'flows'}


class SchemaError(ValueError):
    """Untrusted native data cannot enter the live consumer state."""


def _require(condition, message):
    if not condition:
        raise SchemaError(message)


def uint(value, bits=64):
    return type(value) is int and 0 <= value < 1 << bits


def _hex_id(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_source(source):
    _require(isinstance(source, dict) and set(source) == set(SOURCE_IDS) | {'model_id'},
             'Invalid source identity fields')
    _require(all(uint(source[name], 32) and source[name] > 0 for name in SOURCE_IDS) and
             _hex_id(source['model_id']), 'Invalid source IDs or model identity')
    _require(len({source[name] for name in SOURCE_IDS if name != 'owner_pid'}) == len(SOURCE_IDS) - 1,
             'Source maps are not distinct')
    return source


def source_for(producer):
    """Build expected identity only after Inference.start verified actual held FDs."""
    if producer.ready is None or producer.proc is None or producer.proc.poll() is not None:
        raise ValueError('Collector requires a live, verified owned producer')
    maps = producer.ready['map_ids']
    return validate_source({'owner_pid': producer.proc.pid,
                            'ring_map_id': maps['nn_events'],
                            'counters_map_id': maps['nn_counts'],
                            'sequence_map_id': maps['nn_event_seq'],
                            'slots_map_id': maps['nn_slots'],
                            'control_map_id': maps['nn_control'],
                            'hook_counts_map_id': maps['hook_counts'],
                            'flow_stats_map_id': maps['flow_stats'],
                            'model_id': producer.model_id})


def _key(key):
    _require(isinstance(key, dict) and set(key) ==
             {'a_addr', 'a_port', 'b_addr', 'b_port', 'ifindex', 'protocol'},
             'Invalid canonical flow key fields')
    try:
        a = ipaddress.IPv4Address(key['a_addr'])
        b = ipaddress.IPv4Address(key['b_addr'])
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise SchemaError('Invalid IPv4 flow key') from exc
    _require(str(a) == key['a_addr'] and str(b) == key['b_addr'] and
             all(uint(key[name], 16) for name in ('a_port', 'b_port')) and
             uint(key['ifindex'], 32) and key['ifindex'] > 0 and
             type(key['protocol']) is int and key['protocol'] == 6 and
             (int(a), key['a_port']) <= (int(b), key['b_port']), 'Invalid canonical IPv4/TCP flow key')


def _classification(record, source):
    _require(record['event_schema_version'] == EVENT_SCHEMA_VERSION and
             type(record['event_schema_version']) is int, 'Unsupported event wire schema')
    _require(all(uint(record[name]) and record[name] > 0 for name in
                 ('sequence', 'flow_id', 'trigger_ordinal', 'timestamp_ns')),
             'Vector-only or invalid classification identity/clock')
    _require(isinstance(record['features'], list) and len(record['features']) == 6 and
             all(type(value) is int and -(1 << 63) <= value < 1 << 63
                 for value in record['features']), 'Features must be six signed64 integers')
    _require(isinstance(record['output'], list) and len(record['output']) == 2 and
             all(type(value) is int and -(1 << 31) <= value < 1 << 31
                 for value in record['output']), 'Logits must be two signed32 integers')
    _require(_hex_id(record['model_id']) and uint(record['stage_bitmap'], 6) and
             type(record['status']) is int and record['status'] in range(7) and
             type(record['slot']) is int and record['slot'] in (0, 1),
             'Invalid model/status/stage metadata')
    if record['status'] == 0:
        _require(record['model_id'] == source['model_id'] and record['stage_bitmap'] == 63 and
                 type(record['label']) is int and record['label'] in (0, 1),
                 'Complete result is not bound to the actual model or complete kernel label')
    else:
        _require(record['label'] is None, 'Failed inference must not publish a label')
    _key(record['key'])
    flags = record['trigger_flags']
    _require(uint(flags, 8) and flags & 5, 'Completion lacks an actual FIN/RST trigger')
    expected = 'fin_rst' if flags & 5 == 5 else 'rst' if flags & 4 else 'fin'
    _require(record['reason'] == expected, 'Reason differs from actual trigger flags')
    _require(type(record['counts_valid']) is bool and uint(record['counts_ordinal']) and
             uint(record['counts_timestamp_ns']) and type(record['flow_state']) is int and
             record['flow_state'] in range(len(FLOW_STATES)), 'Invalid count snapshot metadata')
    directions = record['direction_counts']
    _require(isinstance(directions, dict) and set(directions) == {'a_to_b', 'b_to_a'},
             'Missing canonical direction counts')
    for counts in directions.values():
        _require(isinstance(counts, dict) and set(counts) == set(COUNT_FIELDS) and
                 all(uint(value) for value in counts.values()), 'Invalid direction count ABI')
    if record['counts_valid']:
        _require(record['counts_ordinal'] >= record['trigger_ordinal'] and
                 record['counts_timestamp_ns'] >= record['timestamp_ns'] and
                 sum(row['packets'] for row in directions.values()) == record['counts_ordinal'],
                 'Count snapshot precedes its trigger or omits packets')
    else:
        _require(record['counts_ordinal'] == 0 and record['counts_timestamp_ns'] == 0 and
                 all(value == 0 for counts in directions.values() for value in counts.values()),
                 'Unavailable flow counts must not claim a valid prefix/clock')


def validate_flow_rows(record):
    fields = {'id', 'key', 'initiator', 'state', 'first_ns', 'last_ns', 'closed_ns',
              'ordinal', 'a_to_b', 'b_to_a'}
    direction_fields = set(COUNT_FIELDS) | {
        'first_ns', 'last_ns', 'max_iat_ns', 'min_segment_bytes', 'max_segment_bytes'}
    rows = record.get('flows')
    _require(uint(record.get('snapshot_ns')) and uint(record.get('snapshot_end_ns')) and
             record['snapshot_ns'] <= record['snapshot_end_ns'] and
             type(record.get('flow_limit')) is int and 1 <= record['flow_limit'] <= 8192 and
             uint(record.get('flows_total')) and type(record.get('flows_truncated')) is bool and
             isinstance(rows, list) and len(rows) == min(record['flows_total'], record['flow_limit']) and
             record['flows_truncated'] == (record['flows_total'] > record['flow_limit']),
             'Invalid bounded flow snapshot population/clock')
    ids = set()
    for row in rows:
        _require(isinstance(row, dict) and set(row) == fields and
                 all(uint(row[name]) for name in ('id', 'first_ns', 'last_ns', 'closed_ns', 'ordinal')) and
                 row['id'] > 0 and row['id'] not in ids and row['ordinal'] > 0 and
                 row['first_ns'] <= row['last_ns'] <= record['snapshot_end_ns'] and
                 row['initiator'] in ('a', 'b', 'unknown') and row['state'] in FLOW_STATES,
                 'Invalid coherent flow row')
        ids.add(row['id'])
        _key(row['key'])
        for name in ('a_to_b', 'b_to_a'):
            counts = row[name]
            _require(isinstance(counts, dict) and set(counts) == direction_fields and
                     all(uint(value, 32 if field in ('min_segment_bytes', 'max_segment_bytes') else 64)
                         for field, value in counts.items()),
                     'Invalid flow direction statistics')
        _require(row['a_to_b']['packets'] + row['b_to_a']['packets'] == row['ordinal'],
                 'Flow ordinal differs from direction counts')
    return rows


def validate_record(record, expected_source):
    """Reject unknown versions, private data, identity changes and partial labels.

    This validates the transport contract, NOT model arithmetic or provenance.
    Actual map/diagnostic/oracle parity is enforced by event_validation's gate.
    """
    validate_source(expected_source)
    _require(isinstance(record, dict) and COMMON <= set(record), 'Missing native common fields')
    _require(type(record['schema_version']) is int and record['schema_version'] == SCHEMA_VERSION and
             record['mode'] == 'live' and record['clock'] == 'monotonic',
             'Unsupported native schema/mode/clock')
    validate_source(record['source'])
    _require(record['source'] == expected_source, 'Native source differs from the owned producer')
    name = record['event']
    fields = {'ready': READY_FIELDS, 'classification': CLASSIFICATION_FIELDS,
              'source_counters': COUNTER_FIELDS, 'stopped': COUNTER_FIELDS | {'errors'},
              'error': {'stage', 'errno', 'message'}}
    _require(isinstance(name, str) and name in fields and set(record) == COMMON | fields[name],
             'Unknown native event or unexpected/private fields')
    if name == 'classification':
        _classification(record, expected_source)
    elif name == 'ready':
        _require(type(record['nn_abi_version']) is int and record['nn_abi_version'] == NN_ABI_VERSION and
                 type(record['event_schema_version']) is int and
                 record['event_schema_version'] == EVENT_SCHEMA_VERSION and
                 type(record['event_size']) is int and record['event_size'] == EVENT_SIZE and
                 record['feature_schema'] == FEATURE_SCHEMA and record['model_schema'] == MODEL_SCHEMA and
                 type(record['quantization']) is int and record['quantization'] == 16 and
                 uint(record['ifindex'], 32) and record['ifindex'] > 0,
                 'Unsupported native event/model/quantization ABI')
        capacity = record['event_ring_bytes']
        _require(type(capacity) is int and 4096 <= capacity <= 1048576 and
                 capacity & (capacity - 1) == 0, 'Invalid owned ring capacity')
    elif name in ('source_counters', 'stopped'):
        _require(uint(record['timestamp_ns']) and record['timestamp_ns'] > 0 and
                 uint(record['sequence']) and uint(record['reader_decode_errors']) and
                 isinstance(record['inference_counters'], dict) and
                 set(record['inference_counters']) == set(NN_COUNTERS) and
                 all(uint(value) for value in record['inference_counters'].values()),
                 'Invalid source counter snapshot')
        _require(isinstance(record['hook_counts'], dict) and
                 set(record['hook_counts']) == {'ingress', 'egress'} and
                 all(uint(value) for value in record['hook_counts'].values()),
                 'Invalid actual hook counters')
        validate_flow_rows(record)
        if name == 'stopped':
            _require(uint(record['errors'], 32), 'Invalid native shutdown error count')
    else:
        _require(isinstance(record['stage'], str) and 0 < len(record['stage']) <= 128 and
                 type(record['errno']) is int and -(1 << 31) <= record['errno'] < 1 << 31 and
                 isinstance(record['message'], str) and len(record['message']) <= 4096,
                 'Invalid native error details')
    return record


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SchemaError('Duplicate JSON field: ' + key)
        result[key] = value
    return result


def decode_record(line, expected_source):
    if isinstance(line, str):
        line = line.encode('utf-8')
    _require(isinstance(line, bytes) and 0 < len(line) <= MAX_RECORD_BYTES,
             'Native JSONL record exceeded its byte bound')
    try:
        record = json.loads(line.decode('utf-8'), object_pairs_hook=_unique_pairs,
                            parse_constant=lambda value: (_ for _ in ()).throw(
                                SchemaError('Nonfinite JSON constant: ' + value)))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SchemaError('Malformed native JSONL') from exc
    return validate_record(record, expected_source)
