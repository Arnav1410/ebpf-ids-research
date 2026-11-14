"""Deterministic arithmetic, provenance, domain and calibration checks."""
from copy import deepcopy
from fractions import Fraction
import hashlib
import itertools
import unittest

from validation.reference import Model, STAGES, read_npy_rows
from quantization.calibrate import select, split
from quantization.reference import (ROOT, LayerModel, ExactModel, ArithmeticFailure,
    I32_MIN, I32_MAX, I64_MIN, I64_MAX, linear, normalize, round_div, shift)


class IntegerRules(unittest.TestCase):
    def test_positive_negative_zero_and_nearest_even_ties(self):
        inputs = [-7, -5, -3, -1, 0, 1, 3, 5, 7]
        self.assertEqual([round_div(v, 2) for v in inputs], [-4, -2, -2, 0, 0, 0, 2, 2, 4])

    def test_rounding_non_ties_and_integer_divisors(self):
        self.assertEqual([round_div(v, 3) for v in (1, 2, 4, 5, -1, -2, -4, -5)], [0, 1, 1, 2, 0, -1, -1, -2])
        self.assertEqual(round_div(17, 1), 17)

    def test_shift_zero_and_negative_arithmetic(self):
        self.assertEqual(shift(I32_MIN, 0), I32_MIN)
        self.assertEqual(shift(-3, 1), -2)
        self.assertEqual(shift(-1, 1), 0)

    def test_minimum_int64_without_signed_negation(self):
        self.assertEqual(shift(I64_MIN, 32), I32_MIN)
        self.assertEqual(shift(I64_MIN, 62), -2)
        with self.assertRaises(ArithmeticFailure): shift(I64_MAX, 32)

    def test_invalid_shifts_and_divisors(self):
        for bits in (-1, 63, 64):
            with self.assertRaises(ArithmeticFailure): shift(1, bits)
        for divisor in (0, -1):
            with self.assertRaises(ArithmeticFailure): round_div(1, divisor)

    def test_narrowing_is_rejected_not_wrapped(self):
        for value in (I32_MAX+1, I32_MIN-1):
            with self.assertRaises(ArithmeticFailure): shift(value, 0)

    def test_accumulator_overflow_is_rejected(self):
        with self.assertRaises(ArithmeticFailure): linear([I32_MIN]*2, [I32_MIN]*2, 1, 32)
        with self.assertRaises(ArithmeticFailure): linear([I32_MAX], [I32_MAX], 1, 0)

    def test_widen_before_multiplication(self):
        self.assertEqual(linear([1 << 30], [4], 1, 4), [1 << 28])

    def test_small_weights_and_sum_before_rounding(self):
        self.assertEqual(linear([1, 1], [1, 1], 1, 1), [1])
        self.assertEqual(linear([1], [1], 1, 2), [0])

    def test_manually_checkable_scale_transition(self):
        # 3/2**2 times 2/2**1 = 3/4; accumulator q3 -> output q2.
        self.assertEqual(linear([2], [3], 1, 1), [3])

    def test_normalization_rounding_and_signed_extrema(self):
        self.assertEqual(normalize([1, -1, 3, -3, 0, I64_MIN],
            [0, 0, 0, 0, 0, I64_MIN], [2]*6, 0, [4]*6), [0, 0, 2, -2, 0, 0])

    def test_normalization_configuration_and_domain_errors(self):
        for sigma, q, limit in ((0, 0, 1), (-1, 0, 1), (1, 25, 1), (1, 0, 0)):
            with self.assertRaises(ArithmeticFailure): normalize([0]*6, [0]*6, [sigma]*6, q, [limit]*6)
        with self.assertRaises(ArithmeticFailure): normalize([I64_MIN]*6, [I64_MAX]*6, [1]*6, 0, [I64_MAX]*6)


class WholeModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = LayerModel.load()
        cls.rows = read_npy_rows(ROOT/'dataset/reproduction-xdp-data.npy')

    def test_zero_normalized_network_and_tie_rule(self):
        values, label = self.model.infer(self.model.mean)
        self.assertTrue(all(v == 0 for tensor in values.values() for v in tensor))
        self.assertEqual(label, 1)

    def test_all_domain_corners_have_proven_bounds(self):
        history = self.model.config['integer_abs_bounds']
        limits = [history[i] for i in (0, 1, 1, 2, 2, 3)]
        for signs in itertools.product((-1, 1), repeat=6):
            raw = [mu+s*bound for mu, s, bound in zip(self.model.mean, signs, self.model.config['delta_limits'])]
            values, _ = self.model.infer(raw)
            for stage, bounds in zip(STAGES, limits):
                self.assertTrue(all(abs(v) <= b for v, b in zip(values[stage], bounds)))

    def test_domain_boundary_and_one_beyond(self):
        for j in range(6):
            for sign in (-1, 1):
                raw = list(self.model.mean); raw[j] += sign*self.model.config['delta_limits'][j]
                self.model.infer(raw)
                raw[j] += sign
                with self.assertRaises(ArithmeticFailure): self.model.infer(raw)

    def test_relu_sign_and_boundary(self):
        values, _ = self.model.infer([mu+s for mu, s in zip(self.model.mean, self.model.scale)])
        for before, after in (('linear0', 'relu0'), ('linear1', 'relu1')):
            self.assertEqual(values[after], [max(0, v) for v in values[before]])

    def test_determinism_and_metadata_integrity(self):
        raw = self.rows[0]
        self.assertEqual(self.model.infer(raw), self.model.infer(raw))
        self.assertEqual(len(self.model.metadata()), 88)
        self.assertEqual(len(self.model.packed()), 5304)
        self.assertEqual(hashlib.sha256(self.model.packed()).hexdigest(), self.model.config['parameter_sha256'])

    def test_invalid_mode_metadata_is_rejected(self):
        for field, value in (('q_normalized', 25), ('q_weights', [15]*3), ('q_outputs', [63]*3), ('schema', 2)):
            cfg = deepcopy(self.model.config); cfg[field] = value
            with self.assertRaises(ArithmeticFailure): LayerModel(self.model.source, cfg).infer(self.rows[0])

    def test_split_is_grouped_disjoint_and_reproducible(self):
        cal, heldout = split(self.rows)
        self.assertEqual((len(cal), len(heldout)), (4996, 13844))
        self.assertEqual((cal, heldout), split(self.rows))
        self.assertTrue(set(self.rows[i] for i in cal).isdisjoint(self.rows[i] for i in heldout))

    def test_calibration_reproduces_frozen_configuration(self):
        cal, _ = split(self.rows)
        config = select(self.model.source, [self.rows[i] for i in cal])
        for key, value in config.items(): self.assertEqual(value, self.model.config[key], key)
        self.assertEqual(config['q_outputs'], [23, 21, 18])
        self.assertTrue(all(layer[-1]['max_abs_error'] == 0 for layer in config['weight_candidates']))

    def test_exact_reconstruction_manually_checkable_path(self):
        weights = [[0]*(6*32), [0]*(32*32), [0]*64]
        weights[0][0] = 32768; weights[1][0] = 3*65536
        weights[2][0] = 2*65536; weights[2][32] = -65536
        toy = ExactModel(Model(weights, [0]*6, [2, 1, 1, 1, 1, 1]))
        numerators, denominators, label = toy.infer([1, 0, 0, 0, 0, 0])
        actual = [Fraction(numerators[name][0], denominators[name]) for name in ('normalized','linear0','linear1','logits')]
        self.assertEqual(actual, [Fraction(1,2), Fraction(1,4), Fraction(3,4), Fraction(3,2)])
        self.assertEqual(Fraction(numerators['logits'][1], denominators['logits']), Fraction(-3,4))
        self.assertEqual(label, 0)


if __name__ == '__main__': unittest.main()
