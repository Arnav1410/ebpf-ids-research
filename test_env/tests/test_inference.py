"""Pure Stage05 proofs by default; real TC work requires explicit root opt-in.

Fabricated unit records below exercise rejection/reference logic only. They are
never reported as evidence of a kernel execution or a floating original model.
"""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from evaluation.artifacts import DEFAULT_MODEL, ROOT, read_json
from evaluation.dataset import load_dataset
from evaluation.model import STAGES, infer, load_model, model_identity, pack_model
from test_env.commands import Recorder
from test_env.flow_fixture import controlled_phases, tcp_frame
from test_env.flow_reference import parse_headers
from test_env.inference import Inference, _near_zero_model, _overflow_model, run_inference
from test_env.inference_reference import (arithmetic_edges, compare_trace, compare_triggers,
                                         compare_vectors, labeled_vectors, paired_selected_metrics,
                                         trigger_features)
from test_env.lab import CLIENT_NS, SERVER_NS, Lab


def model_fixture():
    return {'schema_version': 1, 'fixed_point': 16, 'dimensions': [6, 32, 32, 2],
            'mean': [0] * 6, 'scale': [1] * 6, 'layer_0_weight': [0] * 192,
            'layer_1_weight': [0] * 1024, 'layer_2_weight': [0] * 64}


def unit_record(model, features, *, flow_id=0, ordinal=1):
    expected = infer(model, features)
    return {'flow_id': flow_id, 'trigger_ordinal': ordinal, 'features': list(features),
            'model_id': model_identity(model), 'stage_bitmap': 63, 'status': 0,
            'label': expected['label'], 'output': expected['output'],
            'stages': {name: expected[name] for name, _ in STAGES},
            'cb_restored': True, 'retval': 0, 'slot': 0, 'trigger_flags': 0}


def unit_observations(frames, *, flow_id=7):
    rows = []
    for ordinal, (reverse, raw) in enumerate(frames, 1):
        packet = parse_headers(raw)
        rows.append({'flow_id': flow_id, 'ordinal': ordinal, 'timestamp_ns': ordinal * 100,
                     'ifindex': 2, 'direction': packet['direction'], 'hook': int(reverse),
                     'header_hex': packet['header_hex']})
    return rows


class SampleSelectionTests(unittest.TestCase):
    def test_predeclared_512_is_reproducible_and_has_both_labels(self):
        dataset = SimpleNamespace(features=tuple((i + 1, 0, 20, 80, 20, 1) for i in range(1024)),
                                  labels=tuple(i % 2 for i in range(1024)), identity={'fixture': 'unit-only'})
        first, meta = labeled_vectors(dataset)
        second, other = labeled_vectors(dataset)
        self.assertEqual(first, second)
        self.assertEqual(meta, other)
        self.assertEqual(len(first), 512)
        self.assertEqual(len({row['index'] for row in first}), 512)
        self.assertEqual(meta['numeric_label_counts'], {'0': 256, '1': 256})
        self.assertIn('unknown', meta['scope'])

    def test_insufficient_or_trivial_samples_do_not_get_fabricated(self):
        dataset = SimpleNamespace(features=((0,) * 6,) * 600, labels=(0, 1) * 300, identity={})
        with self.assertRaisesRegex(ValueError, 'Insufficient'):
            labeled_vectors(dataset)

    def test_invalid_present_split_does_not_fall_back_to_training(self):
        dataset = SimpleNamespace(features=((1,) * 6,) * 600, labels=(0, 1) * 300, identity={})
        with self.assertRaises(ValueError):
            labeled_vectors(dataset, {'schema_version': 999})

    def test_saved_membership_is_validated_and_selection_stays_held_out(self):
        dataset = load_dataset()
        path = ROOT / '.output/evaluation/m3-train/split.json'
        if not path.is_file():
            self.skipTest('Saved paired checkpoint is optional for pure discovery')
        split = read_json(path)
        samples, meta = labeled_vectors(dataset, split)
        self.assertEqual(len(samples), 512)
        self.assertTrue({row['index'] for row in samples} <= set(split['test_indices']))
        self.assertTrue({row['index'] for row in samples}.isdisjoint(split['train_indices']))
        self.assertEqual(meta['dataset_identity'], dataset.identity)
        broken = copy.deepcopy(split)
        broken['dataset_identity']['data_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            labeled_vectors(dataset, broken)


class IntegerPipelineTests(unittest.TestCase):
    def setUp(self):
        self.model = model_fixture()
        self.features = [0] * 6
        self.record = unit_record(self.model, self.features)

    def test_tie_class_one_and_all_six_stages(self):
        proof = compare_trace(self.record, self.model, self.features)
        self.assertEqual(proof['label'], 1)
        self.assertEqual(proof['stage_bitmap'], 63)
        self.assertEqual(proof['tolerance'], 0)

    def test_every_single_integer_at_every_stage_is_checked(self):
        for name, width in STAGES:
            for column in range(width):
                with self.subTest(stage=name, column=column):
                    record = copy.deepcopy(self.record)
                    record['stages'][name][column] += 1
                    with self.assertRaises(AssertionError):
                        compare_trace(record, self.model, self.features)

    def test_partial_bitmap_missing_stage_and_wrong_label_are_rejected(self):
        for name in ('bitmap', 'stage', 'label', 'float_integer'):
            with self.subTest(mutation=name):
                record = copy.deepcopy(self.record)
                if name == 'bitmap':
                    record['stage_bitmap'] = 31
                elif name == 'stage':
                    del record['stages']['normalized']
                elif name == 'label':
                    record['label'] = 0
                else:
                    record['stages']['output'][0] = 0.0
                with self.assertRaises(AssertionError):
                    compare_trace(record, self.model, self.features)

    def test_error_never_publishes_partial_label(self):
        record = {**self.record, 'status': 3, 'stage_bitmap': 7, 'label': None}
        self.assertFalse(compare_trace(record, self.model, self.features, success=False)['partial_label'])
        record['label'] = 1
        with self.assertRaises(AssertionError):
            compare_trace(record, self.model, self.features, success=False)

    def test_duplicate_job_model_mismatch_and_cb_corruption_rejected(self):
        sample = {'features': self.features, 'kind': 'synthetic_arithmetic'}
        for mutation in ('duplicate', 'identity', 'cb', 'nonreserved'):
            with self.subTest(mutation=mutation):
                record = copy.deepcopy(self.record)
                if mutation == 'duplicate':
                    records, declared = [record, record], [sample, sample]
                else:
                    records, declared = [record], [sample]
                    if mutation == 'identity':
                        record['model_id'] = '0' * 64
                    elif mutation == 'cb':
                        record['cb_restored'] = False
                    else:
                        record['flow_id'] = 1
                with self.assertRaises(AssertionError):
                    compare_vectors(records, declared, self.model)

    def test_near_zero_and_tie_model_is_explicit_separate_synthetic(self):
        original = load_model(DEFAULT_MODEL)
        before = pack_model(original)
        model = _near_zero_model(original)
        self.assertEqual(pack_model(original), before)
        self.assertNotEqual(model_identity(original), model_identity(model))
        self.assertEqual(infer(model, [0] * 6)['label'], 1)
        self.assertEqual(infer(model, [1, 0, 0, 0, 0, 0])['label'], 0)
        self.assertIn('synthetic', model['provenance']['kind'])

    def test_overflow_model_really_exceeds_signed64_accumulator_range(self):
        model = _overflow_model(model_fixture())
        features = [(1 << 31) - 1] * 6
        expected = infer(model, features)
        mathematical_sum = sum(a * b for a, b in
                               zip(model['layer_0_weight'][:6], expected['normalized']))
        self.assertGreater(mathematical_sum, (1 << 64) - 1)
        self.assertTrue(all(-(1 << 31) <= value < 1 << 31 for name, _ in STAGES
                            for value in expected[name]))
        self.assertEqual(compare_trace(unit_record(model, features), model, features)['tolerance'], 0)

    def test_private_context_is_rejected_and_float_values_cannot_mimic_integers(self):
        for field, value in (('saved_cb', [1] * 5), ('unrelated_context', 7), ('output', [0.0, 0.0])):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                compare_trace({**self.record, field: value}, self.model, self.features)

    def test_edges_include_exact_signed64_extremes_and_both_branches(self):
        vectors = arithmetic_edges(load_model(DEFAULT_MODEL))
        rows = [row['features'] for row in vectors]
        self.assertIn([-(1 << 63)] * 6, rows)
        self.assertIn([(1 << 63) - 1] * 6, rows)
        self.assertTrue(all(row['kind'] == 'synthetic_arithmetic' and 'label' not in row for row in vectors))
        self.assertTrue(any('delta_-1' in row['name'] for row in vectors))
        self.assertTrue(any('delta_1' in row['name'] for row in vectors))


class PairedMetricTests(unittest.TestCase):
    def test_same_membership_reports_real_float_decision_differences_not_logit_equality(self):
        samples = [{'index': 10, 'label': 0}, {'index': 20, 'label': 1}]
        proofs = [{'label': 0, 'output': [3, 2]}, {'label': 1, 'output': [0, 0]}]
        rows = [{'index': 10, 'label': 0, 'float_prediction': 0, 'integer_prediction': 0,
                 'integer_output': [3, 2], 'float_output': [0.25, -0.5]},
                {'index': 20, 'label': 1, 'float_prediction': 0, 'integer_prediction': 1,
                 'integer_output': [0, 0], 'float_output': [0.0, 0.0]}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'predictions.jsonl'
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
            report = paired_selected_metrics(directory, samples, proofs)
            self.assertEqual(report['disagreement_count'], 1)
            self.assertEqual(report['disagreement_rate'], 0.5)
            self.assertEqual(report['TC_integer_metrics']['accuracy'], 1.0)
            self.assertEqual(report['float_metrics']['accuracy'], 0.5)
            self.assertIn('not_original', report['claim'])
            self.assertEqual(report['tie_rules'], {'float': 'first maximum (class 0)', 'integer': 'class 1'})
            with self.assertRaises(AssertionError):
                paired_selected_metrics(directory, samples, [{'label': 1, 'output': [0, 0]}, proofs[1]])
            with self.assertRaises(AssertionError):
                paired_selected_metrics(directory, samples + [{'index': 30, 'label': 0}], proofs)


class RxTriggerTests(unittest.TestCase):
    def test_every_rx_fin_rst_includes_packet_and_ignores_reverse_fin(self):
        frames = [(False, tcp_frame(flags=2, payload=b'abc').hex()),
                  (True, tcp_frame(reverse=True, flags=17).hex()),
                  (False, tcp_frame(flags=17, tcp_options=b'\x01' * 4).hex()),
                  (False, tcp_frame(flags=17).hex()),
                  (False, tcp_frame(flags=4).hex()),
                  (False, tcp_frame(flags=4).hex())]
        expected = trigger_features(unit_observations(frames), 2)
        self.assertEqual(set(expected), {(7, 3), (7, 4), (7, 5), (7, 6)})
        self.assertEqual(expected[(7, 3)]['features'], [24, 200, 23, 15001, 44, 2])
        self.assertEqual(expected[(7, 6)]['features'], [24, 200, 20, 15001, 104, 5])

    def test_half_close_scores_before_full_close_no_first_fin_collapse(self):
        prefix = []
        phases = dict(controlled_phases())
        for name in ('syn', 'options_and_unknown', 'half_close'):
            prefix.extend(phases[name])
        # This reducer test uses one tuple only; the live runner checks all tuples.
        prefix = [(reverse, raw) for reverse, raw in prefix if
                  {parse_headers(raw)['a'][1], parse_headers(raw)['b'][1]} == {15001, 41001}]
        early = trigger_features(unit_observations(prefix), 2)
        self.assertEqual(len(early), 1)
        prefix += phases['both_fin'] + phases['full_close']
        self.assertEqual(len(trigger_features(unit_observations(prefix), 2)), 1)

    def test_generation_reset_does_not_carry_old_tuple_history(self):
        old = unit_observations([(False, tcp_frame(flags=2).hex()),
                                 (False, tcp_frame(flags=4).hex())], flow_id=7)
        new = unit_observations([(False, tcp_frame(flags=4, payload=b'new').hex())], flow_id=8)
        proof = trigger_features(old + new, 2)
        self.assertEqual(proof[(7, 2)]['features'][-1], 2)
        self.assertEqual(proof[(8, 1)]['features'], [23, 0, 23, 15001, 20, 1])

    def test_trigger_uses_real_clamped_clock_and_requires_complete_ordinals(self):
        frames = [(False, tcp_frame(flags=2).hex()), (False, tcp_frame(flags=4).hex())]
        rows = unit_observations(frames)
        rows[1]['timestamp_ns'] = rows[0]['timestamp_ns']
        self.assertEqual(trigger_features(rows, 2)[(7, 2)]['features'][1], 0)
        rows[1]['timestamp_ns'] -= 1
        with self.assertRaises(AssertionError):
            trigger_features(rows, 2)
        with self.assertRaises(AssertionError):
            trigger_features(unit_observations(frames)[1:], 2)

    def test_nonmatching_source_and_wrong_hook_are_not_scored(self):
        raw = bytearray(tcp_frame(flags=4))
        raw[29] = 74
        self.assertEqual(trigger_features(unit_observations([(False, raw.hex())]), 2), {})
        self.assertEqual(trigger_features(unit_observations([(True, tcp_frame(flags=4).hex())]), 2), {})

    def test_packet_tuple_clock_model_and_exact_job_membership_checked(self):
        model = model_fixture()
        rows = unit_observations([(False, tcp_frame(flags=4).hex())])
        expected = trigger_features(rows, 2)[(7, 1)]
        record = {**unit_record(model, expected['features'], flow_id=7),
                  'timestamp_ns': expected['timestamp_ns'], 'key': expected['key'],
                  'trigger_flags': expected['trigger_flags']}
        self.assertEqual(compare_triggers([record], rows, model, 2)['triggers'], 1)
        with self.assertRaises(AssertionError):
            compare_triggers([], rows, model, 2)
        for field, value in (('timestamp_ns', 99), ('model_id', '0' * 64), ('key', {}), ('trigger_flags', 1)):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                compare_triggers([{**record, field: value}], rows, model, 2)


class SessionContractTests(unittest.TestCase):


    def test_acceptance_rejects_nonoriginal_primary_before_any_kernel_access(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = {}
            recorder = SimpleNamespace(out=Path(directory),
                write_json=lambda name, value: evidence.update({name: value}))
            path = Path(directory) / 'not-original.json'
            path.write_text(json.dumps(model_fixture()), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'unchanged original weights'):
                run_inference(recorder, None, '/no/loader', '/no/object', '/no/bpftool',
                              path, Path(directory) / 'no-pair')
            self.assertEqual(evidence['inference.json']['status'], 'fail')
            self.assertEqual(evidence['inference.json']['sessions'], [])


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('NN_EBPF_RUN_LAB_TESTS') == '1',
                     'Requires explicit isolated-VM root opt-in')
class LiveInferenceTests(unittest.TestCase):
    def test_original_pair_packets_faults_concurrency_and_owned_release(self):
        names = ('NN_EBPF_NN_LOADER', 'NN_EBPF_NN_OBJECT', 'NN_EBPF_BPFTOOL')
        values = [os.environ.get(name) for name in names]
        if not all(values):
            self.skipTest('Explicit built NN loader/object/bpftool paths required')
        loader, obj, bpftool = [Path(value).resolve() for value in values]
        pair = Path(os.environ.get('NN_EBPF_PAIRED_DIR', ROOT / '.output/evaluation/m3-train'))
        if not all(path.is_file() for path in (loader, obj, bpftool, loader.parent / 'nn-vectors')):
            self.skipTest('NN build products unavailable')
        if any(os.path.lexists(Path('/run/netns') / name) for name in (CLIENT_NS, SERVER_NS)):
            self.skipTest('Existing lab namespaces must not be adopted')
        with tempfile.TemporaryDirectory(prefix='nn-ebpf-inference-tests-') as directory:
            evidence = Path(os.environ.get('NN_EBPF_LAB_EVIDENCE_ROOT', directory)) / self._testMethodName
            recorder = Recorder(evidence)
            try:
                with Lab(recorder) as lab:
                    result = run_inference(recorder, lab, loader, obj, bpftool, DEFAULT_MODEL, pair)
                    self.assertEqual(result['status'], 'pass')
                    self.assertTrue(result['cleanup_complete'])
                    for session in result['sessions']:
                        self.assertFalse(any(session['cleanup']['remaining_owned_ids'].values()))
                    for session in result['sessions'][:4]:
                        self.assertEqual(session['vectors']['predicted_classes'], [0, 1])
                    for session in result['sessions'][:2]:
                        self.assertEqual(session['live']['concurrent_tcp']['count'], 8)
                        self.assertEqual(session['live']['capture']['socket_drops'], 0)
                    self.assertEqual(len(result['sessions'][0]['faults']), 7)
                    # Exercise the actual ordinary profile, not construction
                    # defaults: predictions work without exporting diagnostics.
                    production = Inference(recorder, lab, loader, obj, bpftool,
                                           DEFAULT_MODEL, label='inference-production')
                    try:
                        production.start()
                        exchange = lab.exchange()
                        stats = production.inspect()
                        flow = next(row for row in stats['flows']
                                    if row['key']['b_port'] == exchange['client_port'])
                        prediction = [row for row in production.results.values()
                                      if row['flow_id'] == flow['id']][-1]
                        expected = infer(production.model, prediction['features'])
                        self.assertEqual(prediction['key'], flow['key'])
                        self.assertEqual(prediction['stage_bitmap'], 63)
                        self.assertEqual(prediction['status'], 0)
                        self.assertEqual(prediction['output'], expected['output'])
                        self.assertEqual(prediction['label'], expected['label'])
                        self.assertIsNone(prediction.get('stages'))
                        self.assertEqual(stats['observations'], [])
                        self.assertEqual(production._bpf('map', 'dump', 'id',
                            production.ready['map_ids']['nn_traces']), [])
                        recorder.write_json('production-profile.json', {
                            'status': 'pass', 'flow': flow, 'prediction': prediction,
                            'header_observations': 0, 'intermediate_trace_entries': 0})
                    finally:
                        released = production.close()
                    self.assertTrue(released['complete'])
                    self.assertFalse(production.params_path.exists())
            finally:
                recorder.close()
