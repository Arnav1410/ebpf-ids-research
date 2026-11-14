"""Behavioral characterization: known baseline defects are asserted and recorded.

PASS for a defect case means we reproduced it, never that it is corrected.
"""
from collections import Counter
import hashlib
import json
import random
import struct
import subprocess
import unittest

from reference import (FlowReference, I32_MIN, I32_MAX, I64_MIN, I64_MAX, Q,
                       STAGES, linear, normalize, paper_prediction, prediction,
                       read_npy_rows, signed, tcp_packet)

CONTEXT = None


class Validation(unittest.TestCase):
    def setUp(self):
        self.ctx = CONTEXT
        self.model = self.ctx.model
        self.native = self.ctx.native
        self.native.lib.native_reset()

    def compare(self, raw):
        events = []
        stages, label = self.model.infer(raw, events)
        self.assertFalse(events, f"not a safe parity vector: {events}")
        actual, native_label = self.native.infer(raw)
        for name in STAGES:
            self.assertEqual(actual[name], stages[name], name)
        self.assertEqual(native_label, label)
        return stages, label

    def test_01_parameter_layout(self):
        self.assertEqual([len(w) for w in self.model.weights], [192, 1024, 64])
        self.assertEqual(len(self.model.packed()), 5216)
        self.assertTrue(all(v > 0 for v in self.model.scale))
        self.ctx.evidence["parameter_bytes"] = len(self.model.packed())

    def test_02_saved_smoke_parameter_bytes(self):
        if self.ctx.smoke is None:
            self.skipTest("no --smoke-log supplied; does not affect offline arithmetic checks")
        data = json.loads((self.ctx.smoke / "active-model.json").read_text())
        raw = bytes(int(v, 16) if isinstance(v, str) else v for v in data["value"])
        self.assertEqual(raw, self.model.packed())
        self.ctx.evidence["saved_smoke_parameters"] = "5216 bytes identical (historical dump, no live map access)"

    def test_03_normalization_sign_zero_and_truncation(self):
        for x, mu, sigma, expected in [(0, 0, 3, 0), (1, 0, 3, 21845), (-1, 0, 3, -21845),
                                       (5, 5, 7, 0), (6, 5, 7, 9362), (4, 5, 7, -9362),
                                       (-8, -5, 2, -98304), (-2, -5, 2, 98304),
                                       (1, 0, 131072, 0), (-1, 0, 131072, 0)]:
            with self.subTest(x=x, mean=mu, scale=sigma):
                self.assertEqual(normalize([x], [mu], [sigma]), [expected])
                self.assertEqual(self.native.normalize([x], [mu], [sigma]), [expected])

    def test_04_linear_arithmetic_shifts_and_sum_order(self):
        for w, x, expected in [([1], [1], 0), ([1], [-1], -1),
                                ([1], [32768], 0), ([1], [-32768], -1),
                                ([1], [65536], 1), ([1], [-65537], -2),
                                ([32768, 32768], [1, 1], 1),
                                ([1, 1], [-1, -65535], -1),
                                ([65536, -65536], [9, 9], 0)]:
            with self.subTest(weights=w, x=x):
                self.assertEqual(linear(w, x, 1), [expected])
                self.assertEqual(self.native.linear(w, x, 1), [expected])

    def test_05_multiply_widened_before_product(self):
        self.assertEqual(self.native.linear([1 << 30], [Q], 1), [1 << 30])
        self.assertEqual(linear([1 << 30], [Q], 1), [1 << 30])

    def test_06_relu_int32_boundaries(self):
        values = [I32_MIN, -Q, -1, 0, 1, Q, I32_MAX]
        self.assertEqual(self.native.relu(values), [0, 0, 0, 0, 1, Q, I32_MAX])

    def test_07_normalization_safe_int32_endpoints(self):
        values = [I32_MAX, I32_MIN + 1]
        self.assertEqual(self.native.normalize(values, [0, 0], [Q, Q]), values)
        # Exactly INT_MIN on the negative branch instead goes to the isolated
        # UBSan test, never into the in-process shared library.

    def test_08_int64_normalization_endpoints(self):
        x, mu, scale = [I64_MIN, I64_MAX, 0], [I64_MIN, I64_MAX, I64_MIN], [1, 1, I64_MAX]
        events = []
        expected = normalize(x, mu, scale, events)
        self.assertEqual(self.native.normalize(x, mu, scale), expected)
        self.assertTrue(any(e["kind"] == "normalization_uint64_multiply_wrap" for e in events))

    def test_09_uint64_normalization_multiply_wrap(self):
        events = []
        actual = self.native.normalize([1 << 48], [0], [1 << 40])
        self.assertEqual(actual, normalize([1 << 48], [0], [1 << 40], events))
        self.assertEqual(actual, [0])
        self.assertEqual(((1 << 48) * Q) // (1 << 40), 1 << 24)
        self.assertEqual(events[0]["kind"], "normalization_uint64_multiply_wrap")
        self.ctx.evidence["uint64_normalization_wrap"] = {
            "input": 1 << 48, "mean": 0, "scale": 1 << 40,
            "source_output": actual[0], "unbounded_formula": 1 << 24}

    def test_10_positive_normalization_narrowing_changes_sign(self):
        events = []
        actual = self.native.normalize([32769], [0], [1])
        self.assertEqual(actual, normalize([32769], [0], [1], events))
        self.assertEqual(actual, [-2147418112])
        self.assertEqual(events[0]["kind"], "normalization_int32_narrow")
        self.ctx.evidence["normalization_sign_change"] = {"input": 32769, "mean": 0,
            "scale": 1, "exact_scaled_value": 2147549184, "source_output": actual[0]}

    def test_11_linear_int32_narrowing_changes_sign(self):
        events = []
        expected = linear([I32_MAX], [Q + 1], 1, events)
        self.assertEqual(self.native.linear([I32_MAX], [Q + 1], 1), expected)
        self.assertLess(expected[0], 0)
        self.assertEqual(events[0]["kind"], "linear_int32_narrow")
        self.ctx.evidence["linear_narrowing"] = {"output": expected[0], "events": events}

    def test_12_reference_reports_64_bit_sum_overflow(self):
        events = []
        output = linear([I32_MIN, I32_MIN], [I32_MIN, I32_MIN], 1, events)
        self.assertEqual(output, [0])
        self.assertEqual(events[0]["kind"], "signed_int64_accumulator_overflow")
        # Wrapped bit-vector output is NOT a portable native-C expectation.

    def sanitizer(self, name, expected):
        result = subprocess.run([str(self.ctx.sanitizer), name], capture_output=True, text=True)
        (self.ctx.output / ("ubsan-" + name + ".log")).write_text(result.stdout + result.stderr)
        self.ctx.evidence.setdefault("ubsan", {})[name] = {
            "exit_code": result.returncode, "diagnostic": result.stderr.strip()}
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected, result.stderr)
        self.assertIn("runtime error:", result.stderr)

    def test_13_ubsan_accumulator_overflow(self):
        self.sanitizer("accumulator-overflow", "signed integer overflow")

    def test_14_ubsan_int_min_negation(self):
        self.sanitizer("negation-overflow", "negation of -2147483648")

    def test_15_zero_divisor_has_no_c_guard(self):
        with self.assertRaises(ZeroDivisionError):
            normalize([1], [0], [0])
        self.sanitizer("zero-divisor", "division by zero")

    def test_16_ubsan_flow_counter_overflow(self):
        self.sanitizer("flow-counter-overflow", "signed integer overflow")

    def test_17_negative_scale_uses_unsigned_division(self):
        events = []
        self.assertEqual(self.native.normalize([1], [0], [-3]), [0])
        self.assertEqual(normalize([1], [0], [-3], events), [0])
        self.assertEqual(events[0]["kind"], "negative_scale_cast_unsigned")

    def test_18_all_layers_on_fixed_vectors(self):
        vectors = {"raw_zero": [0] * 6, "stored_mean": self.model.mean,
                   "one_scale_above": [m + s for m, s in zip(self.model.mean, self.model.scale)],
                   "one_scale_below": [m - s for m, s in zip(self.model.mean, self.model.scale)],
                   "small_tcp": [20, 0, 20, 5001, 20, 1],
                   "packet_fixture": [124, 5000, 20, 5001, 64, 3]}
        fixtures = {}
        for name, raw in vectors.items():
            with self.subTest(name=name):
                stages, label = self.compare(raw)
                floats = self.model.surrogate_float(raw)
                fixtures[name] = dict(raw=list(raw), stages=stages, prediction=label,
                    dequantized_header_float_diagnostic={stage: {
                        "values": floats[stage],
                        "max_abs_difference": max(abs(a / Q - b) for a, b in zip(stages[stage], floats[stage]))}
                        for stage in STAGES})
        self.ctx.evidence["fixtures"] = fixtures

    def test_19_seeded_layer_inputs(self):
        rng = random.Random(20241024)
        for i, (w, columns, rows) in enumerate(zip(self.model.weights, (6, 32, 32), (32, 32, 2))):
            for case in range(32):
                x = [rng.randint(-16 * Q, 16 * Q) for _ in range(columns)]
                events = []
                expected = linear(w, x, rows, events)
                self.assertFalse(events)
                self.assertEqual(self.native.linear(w, x, rows), expected, f"layer={i} case={case}")
        self.ctx.evidence["seeded_layer_vectors"] = 96

    def test_20_all_dataset_rows_each_layer(self):
        rows = read_npy_rows(self.ctx.root / "dataset/reproduction-xdp-data.npy")
        counts = Counter()
        bounds = {stage: [I32_MAX, I32_MIN] for stage in STAGES}
        digests = {stage: hashlib.sha256() for stage in STAGES}
        ties = 0
        for index, raw in enumerate(rows):
            events = []
            expected, label = self.model.infer(raw, events)
            self.assertFalse(any(e["kind"].startswith("signed_") for e in events),
                             f"row {index}: source C undefined; unsafe to compare natively: {events}")
            actual, native_label = self.native.infer(raw)
            for stage in STAGES:
                self.assertEqual(actual[stage], expected[stage], f"row={index} stage={stage}")
                digests[stage].update(struct.pack("<" + "i" * len(expected[stage]), *expected[stage]))
                bounds[stage][0] = min(bounds[stage][0], min(expected[stage]))
                bounds[stage][1] = max(bounds[stage][1], max(expected[stage]))
            self.assertEqual(native_label, label, f"row={index}")
            counts.update(e["kind"] for e in events)
            ties += expected["logits"][0] == expected["logits"][1]
        self.ctx.evidence["dataset"] = dict(rows=len(rows), stage_comparisons=len(rows) * 6,
            arithmetic_events=dict(counts), stage_min_max=bounds, equal_logits=ties,
            stage_tensor_sha256={stage: digest.hexdigest() for stage, digest in digests.items()},
            classification_accuracy="NOT EVALUATED; labels are not used")

    def test_21_equal_logit_rule_and_actual_zero_network(self):
        stages, label = self.compare(self.model.mean)
        self.assertTrue(all(all(v == 0 for v in stage) for stage in stages.values()))
        self.assertEqual(label, 1)
        self.assertEqual(paper_prediction(stages["logits"]), 0)
        for pair in ((0, 0), (7, 7), (-7, -7), (I32_MIN, I32_MIN), (I32_MAX, I32_MAX),
                     (7, -1), (-1, 7), (I32_MAX, I32_MIN), (I32_MIN, I32_MAX)):
            with self.subTest(logits=pair):
                self.assertEqual(self.native.lib.native_classify(*pair), prediction(pair))
        self.ctx.evidence["equal_logit_discrepancy"] = dict(raw=self.model.mean,
            logits=[0, 0], source_label=1, paper_equation_5_label=0)

    def test_22_original_float_checkpoint(self):
        # Do not deserialize arbitrary pickle files or pretend header/Q is FP32.
        candidates = sorted(str(p.relative_to(self.ctx.root)) for directory in ("src", "dataset")
                            for p in (self.ctx.root / directory).rglob("*")
                            if p.suffix in (".th", ".pt", ".pth", ".pkl", ".onnx"))
        self.ctx.evidence["original_float"] = dict(status="NOT VERIFIED", candidates=candidates,
            reason="No original floating-point checkpoint available" if not candidates
                   else "Checkpoint present; explicit format-aware trusted export required")
        self.skipTest(self.ctx.evidence["original_float"]["reason"])

    def send(self, reference, packet, ns):
        reference.packet(packet, ns)
        self.assertEqual(self.native.packet(packet, ns), 2)
        self.assertEqual(self.native.flows(), list(reference.flows.values()))
        self.assertEqual(self.native.lib.native_prediction_count(), reference.inferences)

    def test_23_six_features_golden_flow_and_actual_tail_call_stages(self):
        reference = FlowReference()
        packets = [(tcp_packet(flags=2), 1000),
                   (tcp_packet(payload=b"x" * 100, tcp_options=b"\x01" * 4), 4000),
                   (tcp_packet(flags=0x11), 9000)]
        golden = [[20, 0, 20, 5001, 20, 1], [124, 3000, 20, 5001, 44, 2],
                  [124, 5000, 20, 5001, 64, 3]]
        for (packet, ns), features in zip(packets, golden):
            self.send(reference, packet, ns)
            self.assertEqual(self.native.flows()[0][:6], features)
        expected, label = self.model.infer(golden[-1])
        self.assertEqual(self.native.snapshots(), expected)
        self.assertEqual(self.native.lib.native_label(), label)
        self.assertEqual(self.native.lib.native_stage_mask(), 63)
        self.assertEqual([self.native.lib.native_call_count(i) for i in range(6)], [1] * 6)
        self.ctx.evidence["golden_flow"] = dict(features_after_each_packet=golden,
            time_unit="nanoseconds", stages=expected, label=label,
            mechanism="unchanged XDP C executed with host helper mocks; no real BPF tail calls")

    def test_24_rst_triggers_and_is_counted(self):
        reference = FlowReference()
        self.send(reference, tcp_packet(flags=4, payload=b"123"), 500)
        self.assertEqual(self.native.flows()[0], [23, 0, 23, 5001, 20, 1, 500, 500])
        self.assertEqual(reference.inferences, 1)

    def test_25_no_fin_rst_no_inference(self):
        reference = FlowReference()
        self.send(reference, tcp_packet(flags=2), 100)
        self.send(reference, tcp_packet(flags=0x18, payload=b"hello"), 1100)
        self.assertEqual(reference.inferences, 0)
        self.assertEqual(self.native.lib.native_stage_mask(), 0)

    def test_26_direction_source_gate_and_tuple_isolation(self):
        reference = FlowReference()
        self.send(reference, tcp_packet(), 10)
        self.send(reference, tcp_packet(source="33.33.33.1", dest="33.33.33.73", sport=5001,
                                        dport=12345, flags=0x11), 20)
        self.send(reference, tcp_packet(source="33.33.33.74", flags=0x11), 30)
        self.assertEqual(len(reference.flows), 1)
        self.send(reference, tcp_packet(sport=12346), 40)
        self.send(reference, tcp_packet(dest="33.33.33.2"), 50)
        self.assertEqual(len(reference.flows), 3)
        self.assertEqual(reference.inferences, 0)

    def test_27_same_timestamp_zero_iat(self):
        reference = FlowReference()
        for _ in range(3):
            self.send(reference, tcp_packet(), 1000)
        self.assertEqual(self.native.flows()[0][:6], [20, 0, 20, 5001, 60, 3])

    def test_28_fin_repetition_and_tuple_reuse_do_not_reset(self):
        reference = FlowReference()
        self.send(reference, tcp_packet(flags=0x11), 1000)
        self.send(reference, tcp_packet(flags=0x11), 2000)
        self.send(reference, tcp_packet(flags=2), 10000)
        self.assertEqual(self.native.flows()[0][:6], [20, 8000, 20, 5001, 60, 3])
        self.assertEqual(reference.inferences, 2)
        self.ctx.evidence["flow_lifecycle"] = "Repeated FIN re-infers; new SYN on same tuple retains old counters and IAT"

    def test_29_map_full_skips_new_flow(self):
        reference = FlowReference(capacity=1)
        self.native.lib.native_capacity(1)
        self.send(reference, tcp_packet(), 1000)
        self.send(reference, tcp_packet(sport=12346, flags=0x11), 2000)
        self.assertEqual(len(reference.flows), 1)
        self.assertEqual(reference.inferences, 0)

    def test_30_truncation_and_non_tcp_frames_ignored(self):
        reference = FlowReference()
        packet = tcp_packet(flags=0x11)
        for n in (0, 13, 14, 33, 34, 53):
            self.send(reference, packet[:n], 1000)
        self.send(reference, tcp_packet(protocol=17), 2000)
        self.send(reference, tcp_packet(ethertype=0x86dd), 3000)
        self.assertEqual(self.native.flows(), [])

    def test_31_ipv4_options_expose_fixed_offset_parser(self):
        reference = FlowReference()
        packet = tcp_packet(ip_options=b"\x01" * 4, flags=0x11)
        self.send(reference, packet, 1000)
        actual = self.native.flows()[0][:6]
        self.assertEqual(actual, [20, 0, 20, 257, 0, 1])
        self.assertEqual(reference.inferences, 0)
        self.ctx.evidence["ipv4_options_parser"] = dict(actual=actual,
            correctly_offset_features=[20, 0, 20, 5001, 20, 1],
            actual_inferences=0, expected_fin_inferences=1)

    def test_32_invalid_ip_length_produces_negative_feature(self):
        reference = FlowReference()
        self.send(reference, tcp_packet(total_length=10), 1000)
        actual = self.native.flows()[0][:6]
        self.assertEqual(actual, [-10, 0, 0x3fffffffffffffff, 5001, 20, 1])
        self.ctx.evidence["malformed_ip_length"] = dict(actual=actual,
            reason="tot_len - IHL is negative, converted to u64 then narrowed to signed feature; minimum sentinel persists")

    def test_33_q16_reference_width_casts(self):
        self.assertEqual(signed(1 << 31, 32), I32_MIN)
        self.assertEqual(signed((1 << 32) - 1, 32), -1)
        self.assertEqual(signed(1 << 63, 64), I64_MIN)
        self.assertEqual(signed(1 << 64, 64), 0)

    def test_34_real_header_iat_multiply_wrap(self):
        raw = self.model.mean.copy()
        raw[1] += 1 << 48
        events = []
        stages, label = self.model.infer(raw, events)
        actual, native_label = self.native.infer(raw)
        self.assertEqual(actual, stages)
        self.assertEqual(native_label, label)
        self.assertEqual(stages["normalized"], [0] * 6)
        self.assertEqual([e["kind"] for e in events], ["normalization_uint64_multiply_wrap"])
        exact = ((1 << 48) * Q) // self.model.scale[1]
        self.assertLess(exact, I32_MAX)
        self.ctx.evidence["real_header_iat_wrap"] = dict(raw=raw, source_normalized=stages["normalized"],
            exact_normalized_iat=exact, difference_ns=1 << 48,
            difference_days=(1 << 48) / (1e9 * 86400), logits=stages["logits"], label=label,
            scope="adversarial feature vector with unchanged checked-in model; not observed in stored rows or live traffic")
