"""Unit records exercise consumer invariants; only the opt-in gate is live proof."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from test_env.collector import EventBuffer, EventJournal, SequenceWindow
from test_env.commands import Recorder
from test_env.event_schema import (COUNT_FIELDS, NN_COUNTERS, SchemaError,
                                   decode_record, validate_record)
from test_env.event_validation import run_events
from test_env.lab import CLIENT_NS, SERVER_NS, Lab
from evaluation.artifacts import DEFAULT_MODEL

ROOT = Path(__file__).resolve().parents[2]
SOURCE = {'owner_pid': 1000, 'ring_map_id': 11, 'counters_map_id': 12,
          'sequence_map_id': 13, 'slots_map_id': 14, 'control_map_id': 15,
          'hook_counts_map_id': 16, 'flow_stats_map_id': 17, 'model_id': 'a' * 64}


def common(event):
    return {'schema_version': 1, 'event': event, 'source': copy.deepcopy(SOURCE),
            'mode': 'live', 'clock': 'monotonic'}


def ready():
    return {**common('ready'), 'nn_abi_version': 2, 'event_schema_version': 1,
            'event_size': 256, 'event_ring_bytes': 1048576, 'feature_schema': 'original-rx-six-v1',
            'model_schema': 'mlp-6-32-32-2-no-bias-q16-v1', 'quantization': 16, 'ifindex': 1}


def completion(sequence, ordinal=None):
    ordinal = sequence if ordinal is None else ordinal
    counts = {field: 0 for field in COUNT_FIELDS}
    return {**common('classification'), 'event_schema_version': 1, 'sequence': sequence,
            'flow_id': 7, 'trigger_ordinal': ordinal, 'timestamp_ns': ordinal,
            'features': [20, 0, 20, 15060, 20 * ordinal, ordinal], 'model_id': SOURCE['model_id'],
            'stage_bitmap': 63, 'status': 0, 'slot': 0, 'label': 1, 'output': [-4, 8],
            'key': {'a_addr': '33.33.33.1', 'b_addr': '33.33.33.73', 'a_port': 15060,
                    'b_port': 41060, 'ifindex': 1, 'protocol': 6},
            'trigger_flags': 4, 'reason': 'rst', 'counts_ordinal': ordinal,
            'counts_timestamp_ns': ordinal, 'flow_state': 4, 'counts_valid': True,
            'direction_counts': {'a_to_b': counts, 'b_to_a': {
                'packets': ordinal, 'ipv4_bytes': 40 * ordinal,
                'tcp_segment_bytes': 20 * ordinal, 'tcp_header_bytes': 20 * ordinal}}}


def counters(sequence, timestamp):
    return {**common('source_counters'), 'timestamp_ns': timestamp, 'sequence': sequence,
            'inference_counters': {name: sequence if name in ('trigger', 'complete', 'event_emitted')
                                   else 0 for name in NN_COUNTERS},
            'reader_decode_errors': 0, 'hook_counts': {'ingress': sequence, 'egress': sequence},
            'snapshot_ns': timestamp - 1, 'snapshot_end_ns': timestamp,
            'flow_limit': 32, 'flows_total': 0, 'flows_truncated': False, 'flows': []}


def connected(**kwargs):
    state = EventBuffer(SOURCE, **kwargs)
    state.reader_starting()
    state.ingest(ready())
    return state


class ConsumerTests(unittest.TestCase):
    def test_reordered_delivery_heals_gaps_without_rolling_back_latest_flow(self):
        state = connected(history_capacity=2)
        state.ingest(completion(2))
        self.assertEqual(state.health()['sequence']['recent_unresolved_gaps'], 1)
        state.ingest(completion(1))
        self.assertEqual(state.health()['sequence']['sequence_gaps'], 0)
        self.assertFalse(state.ingest(completion(2)))
        state.aggregate()
        self.assertEqual([row['sequence'] for row in state.events()], [2, 1])
        self.assertEqual(state.classified[7]['trigger_ordinal'], 2)
        self.assertEqual(state.health()['sequence']['duplicates'], 1)

    def test_bounded_queue_drops_newest_but_journals_every_accepted_record(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = EventJournal(Path(directory) / 'events.jsonl')
            try:
                state = connected(queue_capacity=2, journal=journal)
                for sequence in (1, 2, 3):
                    state.ingest(completion(sequence))
                self.assertEqual(state.health()['python_queue_drops'], 1)
                self.assertEqual(state.events(), [])
                state.aggregate()
                self.assertEqual([row['sequence'] for row in state.events()], [1, 2])
                rows = [json.loads(line) for line in journal.path.read_text().splitlines()]
                self.assertEqual([row['sequence'] for row in rows if row['event'] == 'classification'], [1, 2, 3])
            finally:
                journal.close()

    def test_journal_capacity_never_overwrites_previous_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            journal = EventJournal(path, max_bytes=64)
            try:
                self.assertTrue(journal.append({'sequence': 1, 'value': 'x' * 20}))
                before = path.read_bytes()
                self.assertFalse(journal.append({'sequence': 2, 'value': 'y' * 20}))
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(journal.snapshot()['journal_dropped_records'], 1)
            finally:
                journal.close()

    def test_retention_is_distinct_from_delivery_loss_and_failed_scores_have_no_label(self):
        state = connected(history_capacity=1)
        state.ingest(completion(1))
        failed = {**completion(2), 'status': 3, 'stage_bitmap': 7, 'label': None}
        state.ingest(failed)
        state.aggregate()
        self.assertEqual(state.events(), [failed])
        self.assertEqual(state.health()['history_retention_evictions'], 1)
        self.assertEqual(state.health()['python_queue_drops'], 0)
        self.assertEqual(state.summary()['failed_classifications'], 1)
        self.assertEqual(state.summary()['numeric_labels'], {0: 0, 1: 1})

    def test_restart_preserves_counter_epoch_and_rates_use_real_source_delta(self):
        state = connected()
        state.ingest(counters(1, 100))
        stopped = {**counters(1, 100), 'event': 'stopped', 'errors': 0}
        state.ingest(stopped)
        state.disconnected()
        state.reader_starting()
        state.ingest(ready())
        state.ingest(counters(2, 200))
        self.assertEqual(state.summary()['rates']['hook_packets_per_second']['ingress'], 10000000)
        with self.assertRaisesRegex(SchemaError, 'regressed'):
            state.ingest(counters(1, 300))

    def test_schema_rejects_wrong_source_partial_labels_private_context_and_duplicate_json(self):
        mutations = ({'source': {**SOURCE, 'owner_pid': 999}}, {'status': 3},
                     {'saved_cb': [1] * 5}, {'output': [-4.0, 8]}, {'reason': 'fin'},
                     {'counts_ordinal': 0}, {'event_schema_version': 99})
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(SchemaError):
                validate_record({**completion(1), **mutation}, SOURCE)
        raw = json.dumps(completion(1))[:-1] + ', "status":0}'
        with self.assertRaisesRegex(SchemaError, 'Duplicate'):
            decode_record(raw, SOURCE)

    def test_window_finalizes_only_unseen_old_sequences_and_reports_too_late_records(self):
        window = SequenceWindow(4)
        for sequence in (2, 1, 6, 5):
            self.assertTrue(window.observe(sequence))
        self.assertEqual(window.snapshot()['sequence_gaps'], 2)  # missing 3 and 4
        self.assertTrue(window.observe(4))
        self.assertFalse(window.observe(1))
        self.assertEqual(window.snapshot()['late_outside_window'], 1)
        self.assertEqual(window.snapshot()['sequence_gaps'], 1)


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('NN_EBPF_RUN_LAB_TESTS') == '1',
                     'Requires explicit isolated-VM root opt-in')
class LiveEventsTests(unittest.TestCase):
    def test_live_event_parity_overflows_restart_and_owned_release(self):
        values = [os.environ.get(name) for name in
                  ('NN_EBPF_NN_LOADER', 'NN_EBPF_NN_OBJECT', 'NN_EBPF_BPFTOOL')]
        if not all(values):
            self.skipTest('Explicit built NN loader/object/bpftool paths required')
        loader, obj, bpftool = [Path(value).resolve() for value in values]
        reader = loader.parent / 'nn-collect'
        if not all(path.is_file() for path in (loader, obj, bpftool, reader)):
            self.skipTest('Native event pipeline build products unavailable')
        if any(os.path.lexists(Path('/run/netns') / name) for name in (CLIENT_NS, SERVER_NS)):
            self.skipTest('Existing lab namespaces must not be adopted')
        with tempfile.TemporaryDirectory(prefix='nn-ebpf-events-tests-') as directory:
            out = Path(os.environ.get('NN_EBPF_LAB_EVIDENCE_ROOT', directory)) / self._testMethodName
            recorder = Recorder(out)
            try:
                with Lab(recorder) as lab:
                    result = run_events(recorder, lab, loader, obj, bpftool, reader, DEFAULT_MODEL)
                    self.assertEqual(result['status'], 'pass')
                    self.assertTrue(result['cleanup_complete'])
                    for session in result['sessions']:
                        self.assertFalse(any(session['cleanup']['remaining_owned_ids'].values()))
            finally:
                recorder.close()
