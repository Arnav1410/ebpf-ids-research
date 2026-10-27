"""Synthetic protocol regression tests only: these do not load or execute eBPF."""
import copy
import json
import unittest

from evaluation.kernel import compare_kernel_output, _assess_driver_result, _unique_object
from evaluation.model import infer


def comparison_fixture():
    """Build internally consistent records, not evidence of a kernel run."""
    model = {"fixed_point": 16, "dimensions": [6, 32, 32, 2],
             "layer_0_weight": [65536 if i % 7 == 0 else -32768 for i in range(192)],
             "layer_1_weight": [65536 if i % 33 == 0 else 0 for i in range(1024)],
             "layer_2_weight": [65536] * 32 + [-65536] * 32,
             "mean": [0] * 6, "scale": [65536] * 6}
    vectors = [(30, 0, 30, 5001, 20, 1), (64, 5000150, 20, 5001, 64, 3)]
    records = []
    for index, vector in enumerate(vectors):
        expected = infer(model, vector)
        records.append({"index": index, **expected, "chain_output": expected["output"][:],
                        "chain_label": expected["label"]})
    cases = []
    for index, (payload, header, duration, prior) in enumerate(
            ((10, 20, 0, 0), (40, 24, 5000150, 0), (0, 20, 5000150, 5000150))):
        before = (index + 1) * 1_000_000_000
        seeded = None if index == 0 else before - (5_000_100 if index == 1 else 1_000_100)
        cases.append({"name": f"valid_{index + 1}", "kind": "valid",
                      "payload_bytes": payload, "tcp_header_bytes": header, "retval": 2,
                      "time_before_ns": before, "time_after_ns": before + 100,
                      "seeded_previous_ns": seeded, "previous_max_duration": prior,
                      "state": {"max_packet_length": (30, 64, 64)[index],
                                "max_duration": duration, "min_packet_length": (30, 30, 20)[index],
                                "dst_port": 5001, "header_length": (20, 44, 64)[index],
                                "num_packet": index + 1, "last_packet_time": before + 50}})
    # Deliberately enumerate expectations separately from the production constants.
    for name in ("source_mismatch", "non_ipv4", "non_tcp", "truncated_ethernet",
                 "truncated_ipv4", "truncated_tcp"):
        cases.append({"name": name, "kind": "skipped", "retval": 2, "flow_entries": 0})
        if name == "truncated_ethernet":
            cases[-1]["test_run_context"] = {"input_bytes": 14, "data": 0,
                                             "data_end": 13, "data_meta": 0}
    return model, vectors, {"schema_version": 1, "executed": True, "vectors": records,
                           "feature_cases": cases,
                           "cleanup": {"private_pin_root": "/sys/fs/bpf/nn_ebpf_eval_fixture",
                                       "complete": True}}


class KernelComparisonTests(unittest.TestCase):
    def setUp(self):
        self.model, self.vectors, self.record = comparison_fixture()

    def errors(self, record=None):
        return compare_kernel_output(self.record if record is None else record, self.vectors, self.model)

    def test_consistent_fixture_has_no_discrepancies_not_execution_evidence(self):
        self.assertEqual(self.errors(), [])

    def test_every_layer_and_full_chain_value_is_compared(self):
        for field in ("normalized", "input_linear", "input_relu", "hidden_linear", "hidden_relu",
                      "output", "chain_output"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.record)
                changed["vectors"][0][field][0] += 1
                errors = self.errors(changed)
                self.assertTrue(any(error["location"] == f"vectors[0].{field}" for error in errors))
                mismatch = next(error for error in errors if error["location"] == f"vectors[0].{field}")
                self.assertNotEqual(mismatch["expected"], mismatch["actual"])

    def test_both_labels_are_compared(self):
        for field in ("label", "chain_label"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.record)
                changed["vectors"][0][field] ^= 1
                self.assertTrue(self.errors(changed))

    def test_missing_duplicate_out_of_range_and_malformed_vectors(self):
        variants = []
        changed = copy.deepcopy(self.record)
        changed["vectors"].pop()
        variants.append(changed)
        for index in (0, -1, 2, True, "1"):
            changed = copy.deepcopy(self.record)
            changed["vectors"][1]["index"] = index
            variants.append(changed)
        for value in (None, {}, [None], "invalid"):
            changed = copy.deepcopy(self.record)
            changed["vectors"] = value
            variants.append(changed)
        for changed in variants:
            with self.subTest(records=changed["vectors"]):
                self.assertTrue(self.errors(changed))

    def test_stage_lengths_types_ranges_and_missing_fields(self):
        for value in ([0], None, [True] * 32, [1 << 31] * 32, [0.0] * 32):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.record)
                changed["vectors"][0]["input_linear"] = value
                self.assertTrue(self.errors(changed))
        del self.record["vectors"][0]["output"]
        self.assertTrue(self.errors())

    def test_missing_extra_duplicate_and_reordered_cases(self):
        variants = []
        for index in range(9):
            changed = copy.deepcopy(self.record)
            del changed["feature_cases"][index]
            variants.append(changed)
        changed = copy.deepcopy(self.record)
        changed["feature_cases"].append(changed["feature_cases"][-1])
        variants.append(changed)
        changed = copy.deepcopy(self.record)
        changed["feature_cases"][4] = changed["feature_cases"][3]
        variants.append(changed)
        changed = copy.deepcopy(self.record)
        changed["feature_cases"].reverse()
        variants.append(changed)
        for changed in variants:
            with self.subTest(names=[case["name"] for case in changed["feature_cases"]]):
                self.assertTrue(self.errors(changed))

    def test_wrong_count_length_port_and_headers(self):
        for field in ("num_packet", "max_packet_length", "min_packet_length", "dst_port", "header_length"):
            for index in range(3):
                with self.subTest(field=field, index=index):
                    changed = copy.deepcopy(self.record)
                    changed["feature_cases"][index]["state"][field] += 1
                    self.assertTrue(self.errors(changed))

    def test_case_descriptors_are_not_trusted(self):
        for field, value in (("payload_bytes", 11), ("tcp_header_bytes", 21),
                             ("kind", "skipped"), ("retval", 1)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.record)
                changed["feature_cases"][0][field] = value
                self.assertTrue(self.errors(changed))

    def test_source_filter_and_all_other_skipped_cases(self):
        for index in range(3, 9):
            for field, value in (("flow_entries", 1), ("retval", 0), ("flow_entries", False)):
                with self.subTest(index=index, field=field, value=value):
                    changed = copy.deepcopy(self.record)
                    changed["feature_cases"][index][field] = value
                    self.assertTrue(self.errors(changed))

    def test_short_ethernet_requires_a_real_13_byte_visible_frame(self):
        bad_contexts = (None, {}, {"input_bytes": 13, "data": 0, "data_end": 13, "data_meta": 0},
                        {"input_bytes": 14, "data": 0, "data_end": 14, "data_meta": 0},
                        {"input_bytes": 17, "data": 4, "data_end": 17, "data_meta": 0},
                        {"input_bytes": 16, "data": 3, "data_end": 16, "data_meta": 0},
                        {"input_bytes": 17, "data": 4, "data_end": 18, "data_meta": 0},
                        {"input_bytes": 17, "data": 4, "data_end": 17, "data_meta": 1})
        for context in bad_contexts:
            with self.subTest(context=context):
                changed = copy.deepcopy(self.record)
                changed["feature_cases"][6]["test_run_context"] = context
                self.assertTrue(self.errors(changed))
        # A fragment keeps the complete frame valid while the linear header is short.
        self.record["feature_cases"][6]["test_run_context"] = {
            "input_bytes": 22, "data": 8, "data_end": 21, "data_meta": 0}
        self.assertEqual(self.errors(), [])

    def test_failed_driver_still_compares_completed_inference(self):
        partial = copy.deepcopy(self.record)
        partial["feature_cases"] = partial["feature_cases"][:6]
        partial["reason"] = "Packet test failed"
        assessment = _assess_driver_result(partial, 1, self.vectors, self.model)
        self.assertEqual(assessment["status"], "fail")
        self.assertTrue(assessment["comparison_performed"])
        self.assertTrue(assessment["mismatches"])
        self.assertFalse(any(error["location"].startswith("vectors") for error in assessment["mismatches"]))
        partial["vectors"][0]["output"][0] += 1
        assessment = _assess_driver_result(partial, 1, self.vectors, self.model)
        self.assertTrue(any(error["location"] == "vectors[0].output" for error in assessment["mismatches"]))

    def test_pre_execution_block_is_not_an_empty_successful_comparison(self):
        blocked = {"schema_version": 1, "executed": False, "reason": "Permission denied",
                   "cleanup": {"complete": True, "private_pin_root": None}}
        assessment = _assess_driver_result(blocked, 77, self.vectors, self.model)
        self.assertEqual(assessment["status"], "blocked")
        self.assertFalse(assessment["comparison_performed"])
        self.assertFalse(assessment["executed"])
        blocked["cleanup"]["complete"] = False
        self.assertEqual(_assess_driver_result(blocked, 77, self.vectors, self.model)["status"], "fail")

    def test_monotonic_bounds_and_controlled_seed(self):
        mutations = ((0, "seeded_previous_ns", 1), (0, "time_before_ns", -1),
                     (1, "time_after_ns", 0), (1, "seeded_previous_ns", 2_000_000_000),
                     (2, "previous_max_duration", 0), (1, "time_before_ns", True))
        for index, field, value in mutations:
            with self.subTest(index=index, field=field):
                changed = copy.deepcopy(self.record)
                changed["feature_cases"][index][field] = value
                self.assertTrue(self.errors(changed))
        for index, field, value in ((0, "max_duration", 1), (0, "last_packet_time", 0),
                                    (1, "last_packet_time", 2_000_000_101),
                                    (1, "max_duration", 5000099), (1, "max_duration", 5000201),
                                    (2, "max_duration", 1000200), (2, "max_duration", None)):
            with self.subTest(index=index, field=field, value=value):
                changed = copy.deepcopy(self.record)
                changed["feature_cases"][index]["state"][field] = value
                self.assertTrue(self.errors(changed))

    def test_malformed_features_do_not_raise_or_pass(self):
        for value in (None, [], {"num_packet": 1}):
            changed = copy.deepcopy(self.record)
            changed["feature_cases"][0]["state"] = value
            self.assertTrue(self.errors(changed))
        for value in (None, [], [None] * 9):
            changed = copy.deepcopy(self.record)
            changed["feature_cases"] = value
            self.assertTrue(self.errors(changed))

    def test_cleanup_is_required_and_cannot_touch_global_pins(self):
        for value in (None, {}, {"complete": False}, {"complete": 1},
                      {"complete": True, "private_pin_root": "/sys/fs/bpf/nn_parameters"},
                      {"complete": True, "private_pin_root": "/sys/fs/bpf/nn_ebpf_eval_x/child"}):
            with self.subTest(cleanup=value):
                changed = copy.deepcopy(self.record)
                changed["cleanup"] = value
                self.assertTrue(self.errors(changed))

    def test_execution_and_schema_are_required(self):
        for field, value in (("executed", False), ("executed", 1), ("schema_version", True),
                             ("schema_version", 2)):
            changed = copy.deepcopy(self.record)
            changed[field] = value
            self.assertTrue(self.errors(changed))
        self.assertTrue(self.errors([]))

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate JSON field"):
            json.loads('{"cleanup":{"complete":false,"complete":true}}', object_pairs_hook=_unique_object)


if __name__ == "__main__":
    unittest.main()
