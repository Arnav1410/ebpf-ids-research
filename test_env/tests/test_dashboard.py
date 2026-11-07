"""Replay boundary/provenance regressions; these records are not live evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_env.dashboard import MAX_REPLAY_BYTES, MAX_REPLAY_RECORDS, ReplayState
from test_env.event_schema import COUNT_FIELDS, SchemaError

SOURCE = {'owner_pid': 1000, 'ring_map_id': 11, 'counters_map_id': 12,
          'sequence_map_id': 13, 'slots_map_id': 14, 'control_map_id': 15,
          'hook_counts_map_id': 16, 'flow_stats_map_id': 17, 'model_id': 'a' * 64}


def recorded(sequence, ordinal=None):
    ordinal = sequence if ordinal is None else ordinal
    return {
        'schema_version': 1, 'event_schema_version': 1, 'event': 'classification',
        'source': copy.deepcopy(SOURCE), 'mode': 'live', 'clock': 'monotonic',
        'sequence': sequence, 'flow_id': 7, 'trigger_ordinal': ordinal,
        'timestamp_ns': 9007199254740993 + ordinal,
        'features': [20, 0, 20, 15060, 20 * ordinal, ordinal],
        'model_id': SOURCE['model_id'], 'stage_bitmap': 63, 'status': 0,
        'slot': 0, 'label': 1, 'output': [-4, 8],
        'key': {'a_addr': '33.33.33.1', 'b_addr': '33.33.33.73', 'a_port': 15060,
                'b_port': 41060, 'ifindex': 1, 'protocol': 6},
        'trigger_flags': 4, 'reason': 'rst', 'counts_valid': True,
        'counts_ordinal': ordinal, 'counts_timestamp_ns': 9007199254740993 + ordinal,
        'flow_state': 4,
        'direction_counts': {'a_to_b': dict.fromkeys(COUNT_FIELDS, 0), 'b_to_a': {
            'packets': ordinal, 'ipv4_bytes': 40 * ordinal,
            'tcp_segment_bytes': 20 * ordinal, 'tcp_header_bytes': 20 * ordinal}},
    }


class ReplayTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'sample.jsonl'

    def replay(self, records):
        self.path.write_text('\n'.join(json.dumps(row) for row in records) + '\n',
                             encoding='utf-8')
        return ReplayState(self.path)

    def test_exact_file_and_record_bounds_count_blank_lines_without_skipping_records(self):
        row = json.dumps(recorded(1)).encode('utf-8') + b'\n'
        self.path.write_bytes(row + b' ' * (MAX_REPLAY_BYTES - len(row)))
        state = ReplayState(self.path)
        self.assertEqual(state.advance(), 1)
        self.assertEqual(state.events(), [recorded(1)])
        self.path.write_bytes(row + b' ' * (MAX_REPLAY_BYTES - len(row) + 1))
        with self.assertRaisesRegex(SchemaError, 'byte bound'):
            ReplayState(self.path)

        records = [recorded(index) for index in range(1, MAX_REPLAY_RECORDS + 1)]
        state = self.replay(records)
        self.assertEqual(state.advance(MAX_REPLAY_RECORDS + 10), MAX_REPLAY_RECORDS)
        self.assertEqual(state.events(), records)
        with self.assertRaisesRegex(SchemaError, '256'):
            self.replay(records + [recorded(MAX_REPLAY_RECORDS + 1)])
        self.path.write_bytes(b'\n \t\r\n')
        with self.assertRaisesRegex(SchemaError, 'no classification'):
            ReplayState(self.path)

    def test_invalid_or_mixed_capture_fails_before_revealing_any_prefix(self):
        other_source = recorded(2)
        other_source['source']['ring_map_id'] = 111
        duplicate = recorded(1)
        unknown = {**recorded(2), 'saved_packet': 'private data'}
        failed_with_label = {**recorded(2), 'status': 3, 'stage_bitmap': 7}
        for invalid, message in ((other_source, 'source differs'),
                                 (duplicate, 'Duplicate replay sequence'),
                                 (unknown, 'unexpected/private'),
                                 (failed_with_label, 'must not publish a label')):
            with self.subTest(message=message), self.assertRaisesRegex(SchemaError, 'Replay line 2:.*' + message):
                self.replay([recorded(1), invalid])
        self.path.write_text(json.dumps(recorded(1)) + '\n{broken}\n', encoding='utf-8')
        with self.assertRaisesRegex(SchemaError, 'Replay line 2:.*Malformed'):
            ReplayState(self.path)
        raw = json.dumps(recorded(1))[:-1] + ', "sequence": 2}\n'
        self.path.write_text(raw, encoding='utf-8')
        with self.assertRaisesRegex(SchemaError, 'Duplicate JSON field'):
            ReplayState(self.path)
        self.path.write_text('{"event":"classification"}\n', encoding='utf-8')
        with self.assertRaisesRegex(SchemaError, 'Replay line 1:.*source identity'):
            ReplayState(self.path)

    def test_reordering_preserves_capture_order_and_does_not_roll_back_flow_snapshot(self):
        newer = recorded(9, 6)
        older = recorded(2, 3)
        state = self.replay([newer, older])
        state.advance()
        state.advance()
        self.assertEqual(state.events(), [newer, older])
        flow = state.flows()[0]
        self.assertEqual(flow['classification'], newer)
        self.assertEqual(flow['flow']['ordinal'], 6)
        self.assertEqual(flow['flow']['b_to_a']['packets'], 6)
        self.assertEqual(flow['flow']['last_ns'], newer['counts_timestamp_ns'])
        self.assertEqual(flow['flow']['state'], 'reset')
        self.assertIsNone(flow['active'])
        self.assertIsNone(flow['flow']['first_ns'])
        self.assertIsNone(flow['flow']['closed_ns'])
        self.assertIsNone(flow['flow']['b_to_a']['max_iat_ns'])
        self.assertEqual(state.summary()['numeric_labels'], {0: 0, 1: 2})

    def test_missing_count_snapshot_does_not_turn_native_zero_placeholders_into_measurements(self):
        missing = recorded(1)
        missing.update(counts_valid=False, counts_ordinal=0, counts_timestamp_ns=0,
                       flow_state=0, direction_counts={
                           'a_to_b': dict.fromkeys(COUNT_FIELDS, 0),
                           'b_to_a': dict.fromkeys(COUNT_FIELDS, 0)})
        state = self.replay([missing])
        state.advance()
        flow = state.flows()[0]
        for field in ('state', 'ordinal', 'last_ns', 'a_to_b', 'b_to_a'):
            self.assertIsNone(flow['flow'][field], field)
        self.assertIsNone(flow['active'])
        self.assertEqual(flow['classification'], missing)
        for field in ('rates', 'inference_counters', 'hook_counts', 'flow_inspection'):
            self.assertIsNone(state.summary()[field], field)
        for field in ('kernel_ring_drops', 'python_queue_drops', 'source_timestamp_ns'):
            self.assertIsNone(state.health()[field], field)

    def test_newer_classification_without_counts_keeps_last_recorded_counts_explicitly_older(self):
        available = recorded(1, 3)
        missing = recorded(2, 5)
        missing.update(counts_valid=False, counts_ordinal=0, counts_timestamp_ns=0,
                       flow_state=0, direction_counts={
                           'a_to_b': dict.fromkeys(COUNT_FIELDS, 0),
                           'b_to_a': dict.fromkeys(COUNT_FIELDS, 0)})
        state = self.replay([available, missing])
        state.advance(2)
        flow = state.flows()[0]
        self.assertEqual(flow['classification'], missing)
        self.assertEqual(flow['flow']['ordinal'], 3)
        self.assertEqual(flow['flow']['last_ns'], available['counts_timestamp_ns'])
        self.assertIsNone(flow['active'])

    def test_reset_repeat_and_returned_data_mutation_cannot_change_recorded_predictions(self):
        first = {**recorded(3), 'label': 0, 'output': [-999, 999]}
        failed = {**recorded(2), 'status': 3, 'stage_bitmap': 7, 'label': None}
        state = self.replay([first, failed])
        initial_health = state.health()
        self.assertEqual(state.advance(0), 0)
        self.assertEqual(state.advance(1000), 2)
        self.assertEqual(state.advance(), 0)
        events, flows, summary = state.events(), state.flows(), state.summary()
        complete_health = state.health()
        self.assertFalse(complete_health['connected'])
        self.assertEqual(complete_health['reader_status'], 'simulated')
        self.assertTrue(complete_health['simulated'])
        self.assertEqual(complete_health['replay_progress'], {'visible': 2, 'total': 2, 'complete': True})
        self.assertEqual(events, [first, failed])
        self.assertEqual(summary['numeric_labels'], {0: 1, 1: 0})
        self.assertEqual(summary['failed_classifications'], 1)
        state.events()[0]['output'][0] = 0
        state.flows()[0]['classification']['key']['a_addr'] = '0.0.0.0'
        state.health()['source']['model_id'] = 'b' * 64
        state.summary()['numeric_labels'][0] = 999
        self.assertEqual(state.events(), events)
        self.assertEqual(state.flows(), flows)
        self.assertEqual(state.summary(), summary)
        self.assertEqual(state.health(), complete_health)
        state.reset()
        self.assertEqual(state.health(), initial_health)
        self.assertEqual(state.events(), [])
        self.assertEqual(state.flows(), [])
        self.assertEqual(state.summary()['numeric_labels'], {0: 0, 1: 0})
        self.assertEqual(state.summary()['failed_classifications'], 0)
        state.advance(2)
        self.assertEqual(state.events(), events)
        self.assertEqual(state.flows(), flows)
        self.assertEqual(state.summary(), summary)
        self.assertEqual(state.health(), complete_health)

    def test_invalid_advance_count_cannot_partially_reveal_history(self):
        state = self.replay([recorded(1), recorded(2)])
        for count in (-1, True, 1.0, None):
            with self.subTest(count=count), self.assertRaises(ValueError):
                state.advance(count)
            self.assertEqual(state.events(), [])
        self.assertEqual(state.advance(), 1)
        self.assertEqual(state.events(), [recorded(1)])
