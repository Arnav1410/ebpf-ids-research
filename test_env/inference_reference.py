"""Stage05 proofs, reusing evaluation.model's *only* integer convention.

Synthetic vectors test arithmetic, not traffic accuracy. Packet features are
reduced from independent headers and the real per-generation clamped clocks.
The checked-in weights have unknown training overlap and no floating original.
"""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import random

from evaluation.artifacts import read_json, sha256
from evaluation.metrics import classification_metrics
from evaluation.model import STAGES, infer, model_identity
from evaluation.split import validate_split
from .flow_reference import canonical_key, parse_headers

SOURCE = 555819337
STAGE_BITMAP = (1 << len(STAGES)) - 1
STATUS_NAMES = ('complete', 'model_unready', 'job_full', 'tail_missing',
                'bad_params', 'trace_full', 'bad_stage')


def labeled_vectors(dataset, split=None, count=512):
    """Predeclare a seeded, distinct-index, balanced-label membership selection.

    A present but invalid frozen split is an error, never an excuse to silently
    sample training rows. Selection does not inspect predictions or model weights.
    """
    if type(count) is not int or count < 2:
        raise ValueError('At least two labeled samples are required')
    if split is None:
        candidates = list(range(len(dataset.features)))
        scope = 'dataset diagnostic; original training overlap unknown'
    else:
        _, candidates = validate_split(dataset, split)
        scope = 'frozen local exact-feature-grouped held-out membership'
    groups = {label: [i for i in candidates if dataset.labels[i] == label and
                      any(dataset.features[i])] for label in (0, 1)}
    rng = random.Random(2026)
    for group in groups.values():
        rng.shuffle(group)
    quotas = {0: count // 2, 1: count - count // 2}
    if any(len(groups[label]) < quotas[label] for label in (0, 1)):
        raise ValueError('Insufficient nontrivial frozen samples for both numeric labels')
    selected = sorted(groups[0][:quotas[0]] + groups[1][:quotas[1]])
    records = [{'index': i, 'features': list(dataset.features[i]),
                'label': dataset.labels[i], 'kind': 'labeled_dataset'} for i in selected]
    encoded = json.dumps(records, sort_keys=True, separators=(',', ':')).encode()
    return records, {'selection': 'seed2026-balanced-labels-without-prediction-selection-v1',
                     'count': count, 'scope': scope, 'dataset_identity': dataset.identity,
                     'membership_sha256': hashlib.sha256(encoded).hexdigest(),
                     'numeric_label_counts': dict(Counter(str(row['label']) for row in records)),
                     'metric_population': 'balanced selected subset, not natural dataset prevalence',
                     'label_semantics': {'0': 'unverified', '1': 'unverified'}}


def arithmetic_edges(model):
    """Unlabeled signed64, normalization branch, near-zero and overflow probes."""
    low, high = -(1 << 63), (1 << 63) - 1
    center = list(model['mean'])
    vectors = [('zero', [0] * 6), ('negative', [-1] * 6),
               ('int64_min', [low] * 6), ('int64_max', [high] * 6),
               ('alternating_extremes', [low, high] * 3), ('at_mean_tie', center)]
    for column in range(6):
        for delta in (-1, 1, -65536, 65536, -(1 << 47), 1 << 47):
            row = center.copy()
            row[column] = max(low, min(high, row[column] + delta))
            vectors.append((f'normalization_column_{column}_delta_{delta}', row))
    return [{'features': list(row), 'kind': 'synthetic_arithmetic', 'name': name}
            for name, row in vectors]


def compare_trace(record, model, features, *, success=True):
    """Require exact signed integers at *all six* real tail-call stages."""
    if (not isinstance(record, dict) or record.get('features') != list(features) or
            any(type(value) is not int for value in record['features'])):
        raise AssertionError('Kernel features differ from the declared integer input')
    allowed = {'flow_id', 'trigger_ordinal', 'timestamp_ns', 'features', 'model_id',
               'stage_bitmap', 'status', 'slot', 'label', 'output', 'key', 'stages',
               'cb_restored', 'retval', 'trigger_flags'}
    if set(record) - allowed:
        raise AssertionError('Inference export contains unknown/private kernel context')
    if type(record.get('trigger_flags')) is not int or not 0 <= record['trigger_flags'] <= 255:
        raise AssertionError('Invalid actual trigger flags')
    if type(record.get('status')) is not int or record['status'] not in range(len(STATUS_NAMES)):
        raise AssertionError('Invalid inference result status')
    bitmap = record.get('stage_bitmap')
    if type(bitmap) is not int or bitmap < 0 or bitmap > STAGE_BITMAP:
        raise AssertionError('Invalid inference stage bitmap')
    trace = record.get('stages')
    if trace is not None:
        if not isinstance(trace, dict) or set(trace) != {name for name, _ in STAGES}:
            raise AssertionError('Unversioned six-stage diagnostic trace')
        for stage, width in STAGES:
            actual = trace[stage]
            if (not isinstance(actual, list) or len(actual) != width or
                    any(type(value) is not int or not -(1 << 31) <= value < 1 << 31 for value in actual)):
                raise AssertionError(f'Invalid signed32 diagnostic stage: {stage}')
    if not success:
        if record['status'] == 0 or record.get('label') is not None:
            raise AssertionError('Failed/partial inference published a class label')
        return {'status': 'pass', 'observed_status': STATUS_NAMES[record['status']],
                'stage_bitmap': bitmap, 'partial_label': False}
    if record['status'] != 0 or bitmap != STAGE_BITMAP or trace is None:
        raise AssertionError('Inference did not complete all six traced tail calls')
    expected = infer(model, features)
    for stage, _ in STAGES:
        if trace[stage] != expected[stage]:
            raise AssertionError(f'Exact integer stage mismatch: {stage}')
    if (type(record.get('label')) is not int or record['label'] != expected['label'] or
            not isinstance(record.get('output'), list) or
            any(type(value) is not int for value in record['output']) or
            record['output'] != expected['output']):
        raise AssertionError('Final logits/argmax differ from the integer reference')
    return {'status': 'pass', 'stage_bitmap': bitmap, 'tolerance': 0,
            'label': expected['label'], 'output': expected['output']}


def compare_vectors(records, declared, model):
    if not isinstance(records, list) or len(records) != len(declared):
        raise AssertionError('Incomplete kernel vector batch')
    proofs, keys = [], set()
    for actual, sample in zip(records, declared):
        key = (actual.get('flow_id'), actual.get('trigger_ordinal'))
        if (type(key[0]) is not int or key[0] != 0 or type(key[1]) is not int or
                not 0 < key[1] < 1 << 64 or key in keys):
            raise AssertionError('Native vector jobs lack distinct reserved identities')
        keys.add(key)
        if actual.get('model_id') != model_identity(model):
            raise AssertionError('Kernel vector is not bound to the loaded model')
        if actual.get('cb_restored') is not True:
            raise AssertionError('Vector skb control words were not genuinely restored')
        proofs.append(compare_trace(actual, model, sample['features']))
    labeled = [(sample['label'], proof['label']) for sample, proof in zip(declared, proofs)
               if sample['kind'] == 'labeled_dataset']
    return {'status': 'pass', 'vectors': len(records), 'stage_count': len(STAGES),
            'tolerance': 0, 'predicted_classes': sorted({proof['label'] for proof in proofs}),
            'metrics': classification_metrics([a for a, _ in labeled], [b for _, b in labeled])
            if labeled else None, 'proofs': proofs}


def trigger_features(observations, ifindex):
    """Original matching-RX accumulation; every FIN/RST includes its own packet.

    Direction is derived from raw addresses, not canonical forward orientation.
    Generations reset deliberately, unlike the original indefinitely reused tuple.
    """
    groups = defaultdict(list)
    for row in observations:
        groups[row['flow_id']].append(row)
    results = {}
    for flow_id, rows in groups.items():
        ordered = sorted(rows, key=lambda row: row['ordinal'])
        if [row['ordinal'] for row in ordered] != list(range(1, len(ordered) + 1)):
            raise AssertionError('Incomplete/duplicate bidirectional packet observation prefix')
        previous_all, previous_rx, sizes, gaps, headers = None, None, [], [], 0
        for row in ordered:
            packet = parse_headers(row['header_hex'])
            timestamp = row['timestamp_ns']
            if type(timestamp) is not int or timestamp < 0 or (previous_all is not None and timestamp < previous_all):
                raise AssertionError('Invalid clamped kernel observation clock')
            previous_all = timestamp
            source = packet['b'] if packet['direction'] else packet['a']
            destination = packet['a'] if packet['direction'] else packet['b']
            if row['hook'] != 0 or source[0] != SOURCE:
                continue
            sizes.append(packet['tcp_segment_bytes'])
            if previous_rx is not None:
                gaps.append(timestamp - previous_rx)
            previous_rx = timestamp
            headers += packet['tcp_header_bytes']
            if packet['flags'] & (1 | 4):
                results[(flow_id, row['ordinal'])] = {
                    'features': [max(sizes), max(gaps, default=0), min(sizes),
                                 destination[1], headers, len(sizes)],
                    'timestamp_ns': timestamp, 'key': canonical_key(packet, ifindex),
                    'trigger_flags': packet['flags']}
    return results


def compare_triggers(records, observations, model, ifindex):
    expected = trigger_features(observations, ifindex)
    actual = {(row['flow_id'], row['trigger_ordinal']): row for row in records}
    if len(actual) != len(records) or set(actual) != set(expected):
        raise AssertionError(f'FIN/RST job membership differs: expected={sorted(expected)}, actual={sorted(actual)}')
    proofs = []
    for key, reference in sorted(expected.items()):
        row = actual[key]
        if (row.get('timestamp_ns') != reference['timestamp_ns'] or row.get('key') != reference['key'] or
                row.get('model_id') != model_identity(model) or
                row.get('trigger_flags') != reference['trigger_flags']):
            raise AssertionError('Trigger timestamp/tuple/frozen model identity mismatch')
        proofs.append({'flow_id': key[0], 'trigger_ordinal': key[1],
                       **compare_trace(row, model, reference['features'])})
    return {'status': 'pass', 'triggers': len(proofs), 'tolerance': 0, 'proofs': proofs,
            'feature_clock': 'real monotonic lock-observed clamped kernel timestamps',
            'lifecycle_difference': 'new immutable flow generation resets RX history; original reused tuples do not'}


def paired_evaluation(dataset, paired_dir, directory):
    """Validate and score the saved real M3 pair using existing training helpers."""
    from evaluation.training import evaluate_experiment
    report = evaluate_experiment(dataset, paired_dir, directory)
    return {'claim': 'separate_actual_M3_float_and_its_quantized_checkpoint_not_original',
            'report': report, 'artifacts': {name: sha256(Path(paired_dir) / name) for name in
                ('float-model.json', 'quantized-model.json', 'split.json')},
            'quantized': read_json(Path(paired_dir) / 'quantized-model.json')}


def paired_selected_metrics(directory, samples, kernel_proofs):
    """Compare actual saved FP32 outputs with TC Q16 on the same frozen 512 rows."""
    selected = {sample['index']: sample for sample in samples}
    if len(selected) != len(samples) or len(kernel_proofs) < len(samples):
        raise AssertionError('Invalid same-membership paired metric input')
    rows = {}
    with (Path(directory) / 'predictions.jsonl').open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row['index'] in selected:
                if row['index'] in rows:
                    raise AssertionError('Duplicate paired held-out prediction')
                rows[row['index']] = row
    if set(rows) != set(selected):
        raise AssertionError('Selected TC samples are absent from actual paired held-out evaluation')
    actual_labels, floating_labels, integer_labels, disagreements = [], [], [], []
    for sample, proof in zip(samples, kernel_proofs):
        row = rows[sample['index']]
        if (row['label'] != sample['label'] or row['integer_prediction'] != proof['label'] or
                row['integer_output'] != proof['output']):
            raise AssertionError('Paired saved integer result differs from exact TC pipeline')
        actual_labels.append(sample['label'])
        floating_labels.append(row['float_prediction'])
        integer_labels.append(proof['label'])
        if row['float_prediction'] != proof['label']:
            disagreements.append({'index': sample['index'], 'label': sample['label'],
                                  'float_prediction': row['float_prediction'],
                                  'TC_integer_prediction': proof['label'],
                                  'float_logits': row['float_output'], 'Q16_logits': proof['output']})
    return {'claim': 'separate_actual_M3_checkpoint_float_to_its_quantized_TC_not_original',
            'samples': len(samples), 'population': 'balanced selected frozen held-out membership',
            'float_metrics': classification_metrics(actual_labels, floating_labels),
            'TC_integer_metrics': classification_metrics(actual_labels, integer_labels),
            'disagreement_count': len(disagreements),
            'disagreement_rate': len(disagreements) / len(samples),
            'disagreements': disagreements,
            'comparison': 'numeric class decisions; floating logits are not required to equal Q16 logits',
            'tie_rules': {'float': 'first maximum (class 0)', 'integer': 'class 1'}}
