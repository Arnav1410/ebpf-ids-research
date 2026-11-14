"""Host-only statistics, real C adapters and incorrect-output rejection tests."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from evaluation.latency import summary_ns, build, Buffers, check_block, MODES, ROOT
from quantization.reference import LayerModel
from validation.reference import Model, STAGES
import os
import struct


class Statistics(unittest.TestCase):
    def test_tail_percentiles_keep_slow_samples(self):
        result = summary_ns([1, 2, 3, 4, 100])
        self.assertEqual(result['samples'], 5)
        self.assertEqual(result['mean_ns'], 22)
        self.assertEqual(result['median_ns'], 3)
        self.assertAlmostEqual(result['p95_ns'], 80.8)
        self.assertAlmostEqual(result['p99_ns'], 96.16)
        self.assertEqual(result['maximum_ns'], 100)
        self.assertGreater(result['population_stddev_ns'], 30)

    def test_bad_timings_are_not_silently_filtered(self):
        for values in ([], [0], [1, -1], [True], [1.0]):
            with self.assertRaises(ValueError):
                summary_ns(values)

    def test_counts_cpu_and_changed_checksum_fail(self):
        good = dict(exit_code=0, failed=0, successful=2, checksum=123,
                    start_cpu=3, end_cpu=3, kind=1, duration_ns=[100, 200])
        check_block(good, 2, 3, 123)
        for key, value in (('exit_code', -1), ('failed', 1), ('successful', 1),
                           ('start_cpu', 4), ('end_cpu', 4), ('checksum', 124), ('duration_ns', [100])):
            bad = deepcopy(good);bad[key] = value
            with self.assertRaises(RuntimeError):
                check_block(bad, 2, 3, 123)


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.libs = build(Path(cls.tmp.name), 'clang-12')
        cls.original = Model.load(ROOT/'src/mlp_params.bpf.h')
        cls.raw = [cls.original.mean, [x+s for x,s in zip(cls.original.mean, cls.original.scale)],
                   [x-s for x,s in zip(cls.original.mean, cls.original.scale)]]

    def buffer(self, mode):
        model = LayerModel.load() if mode == 'tc_layer_specific' else self.original
        packed = bytearray();labels = []
        for raw in self.raw:
            stages, label = model.infer(raw)
            values = [0]*192
            for i, name in enumerate(STAGES):
                values[32*i:32*i+len(stages[name])] = stages[name]
            packed.extend(struct.pack('<192i', *values));labels.append(label)
        return Buffers(self.raw, packed, labels)

    def test_every_adapter_and_measurement_kind_matches_all_stages(self):
        for mode,lib in self.libs.items():
            buffer = self.buffer(mode)
            checksum = None
            for scope in (0, 1):
                for kind in (0, 1, 2):
                    with self.subTest(mode=mode, scope=scope, kind=kind):
                        block = buffer.run(lib, scope, kind)
                        self.assertEqual(block['exit_code'], 0)
                        self.assertEqual(block['successful'], 3)
                        self.assertEqual(block['failed'], 0)
                        if checksum is not None:self.assertEqual(block['checksum'], checksum)
                        checksum = block['checksum']
                        if kind==1:self.assertEqual(len(block['duration_ns']), 3)
                        if kind==2:self.assertGreater(block['elapsed_ns'], 0)

    def test_wrong_intermediate_tensor_and_label_are_detected(self):
        for mode,lib in self.libs.items():
            for kind in (0, 1, 2):
                with self.subTest(mode=mode, kind=kind):
                    buffer = self.buffer(mode)
                    buffer.expected[32] += 1  # Corrupt a linear tensor, not just logits.
                    buffer.expected_labels[1] ^= 1
                    block = buffer.run(lib, 0, kind)
                    self.assertEqual(block['failed'], 2)
                    self.assertEqual(block['successful'], 1)
                    self.assertEqual(block['first_bad'], 0)

    def test_timer_control_is_an_explicit_non_inference(self):
        for mode,lib in self.libs.items():
            block = self.buffer(mode).run(lib, 0, 3)
            self.assertEqual(block['kind'], 3)
            self.assertEqual(block['checksum'], 0)
            self.assertEqual(len(block['duration_ns']), 3)
            self.assertGreater(lib.latency_clock_resolution_ns(), 0)


if __name__ == '__main__':
    unittest.main()
