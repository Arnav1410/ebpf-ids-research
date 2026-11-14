"""Unprivileged protocol/comparator tests. All kernel events here are MOCKS."""
import copy
import struct
import unittest

from reference import FlowReference, STAGES
from parity import PROGRAMS, binary_input, compare_events

CONTEXT = None


def mocked_events(bundle, model):
    events = [dict(event="schema", all_pin_paths_disabled=True),
              dict(event="loaded", programs=[dict(name=name, id=i + 1, type=6, xlated_prog_len=128)
                    for i, name in enumerate(PROGRAMS)], maps=[dict(id=i + 101) for i in range(5)]),
              dict(event="model", slot=0, bytes_verified=5216), dict(event="model", slot=1, bytes_verified=5216),
              dict(event="tail_call_slots", slots=6, empty=True)]

    def call(kind, index, name):
        events.append(dict(event="test_run", kind=kind, index=index, stage=name,
                           program_id=PROGRAMS.index(name) + 1, retval=2, repeat=1, flags=0))

    for i, case in enumerate(bundle["fixtures"]):
        for name in PROGRAMS[:6]:
            call("fixture", i, name)
        events.append(dict(event="fixture", index=i, features=case["raw"],
                           stages=[case["stages"][name] for name in STAGES], prediction_derived=case["prediction"]))
    reference = FlowReference()
    for i, case in enumerate(bundle["packets"]):
        if case["reset"]:
            reference = FlowReference()
        packet = bytes.fromhex(case["packet"])
        state = reference.packet(packet, (i + 1) * 1000)
        call("packet", i, "xdp_prog")
        record = dict(event="packet", index=i, flow_present=state is not None)
        if state:
            record.update(features=state[:6], last_packet_time=state[6], detection_start_time=state[7])
            if packet[47] & 5:
                stages, _ = model.infer(state[:6])
                record["stages"] = [stages[name] for name in STAGES]
                for name in PROGRAMS[:6]:
                    call("packet", i, name)
        events.append(record)
    events.append(dict(event="cleanup", private_program_ids_absent=True, private_map_ids_absent=True,
                       attachments_created=0, pins_created=0))
    return copy.deepcopy(events)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.bundle, self.model = CONTEXT
        self.events = mocked_events(self.bundle, self.model)

    def test_small_safe_fixture_set(self):
        self.assertEqual(len(self.bundle["fixtures"]), 7)
        for case in self.bundle["fixtures"]:
            events = []
            self.model.infer(case["raw"], events)
            self.assertFalse(events)
            self.assertNotEqual(case["raw"][5], 0)

    def test_binary_model_and_counts(self):
        data = binary_input(self.bundle, self.model)
        self.assertEqual(data[:8], b"NNKPAR1\0")
        self.assertEqual(struct.unpack_from("<II", data, 8), (7, 5))
        self.assertEqual(data[16:16 + 5216], self.model.packed())

    def test_mock_comparison_accepts_complete_protocol(self):
        result = compare_events(self.bundle, self.model, self.events)
        self.assertEqual(result["test_run_invocations"], 59)
        self.assertEqual(result["tensor_comparisons"], 54)
        self.assertEqual(result["packet_fixtures"][2]["features"], [124, 1000, 20, 5001, 64, 3])

    def test_rejects_missing_stage_invocation(self):
        self.events.pop(next(i for i, e in enumerate(self.events) if e["event"] == "test_run"))
        with self.assertRaisesRegex(ValueError, "invocation sequence"):
            compare_events(self.bundle, self.model, self.events)

    def test_rejects_wrong_intermediate_tensor(self):
        next(e for e in self.events if e["event"] == "fixture")["stages"][1][0] += 1
        with self.assertRaisesRegex(ValueError, "tensor mismatch"):
            compare_events(self.bundle, self.model, self.events)

    def test_rejects_wrong_packet_feature(self):
        next(e for e in self.events if e["event"] == "packet" and e["index"] == 1)["features"][1] += 1
        with self.assertRaisesRegex(ValueError, "packet features mismatch"):
            compare_events(self.bundle, self.model, self.events)

    def test_rejects_live_frame_flag(self):
        next(e for e in self.events if e["event"] == "test_run")["flags"] = 1
        with self.assertRaisesRegex(ValueError, "mode/result"):
            compare_events(self.bundle, self.model, self.events)

    def test_rejects_unreleased_objects(self):
        self.events[-1]["private_map_ids_absent"] = False
        with self.assertRaisesRegex(ValueError, "cleanup"):
            compare_events(self.bundle, self.model, self.events)

    def test_rejects_model_readback_failure(self):
        next(e for e in self.events if e["event"] == "model")["bytes_verified"] = 0
        with self.assertRaisesRegex(ValueError, "parameter readback"):
            compare_events(self.bundle, self.model, self.events)

    def test_rejects_host_only_records_as_execution(self):
        self.events = [e for e in self.events if e["event"] != "loaded"]
        with self.assertRaisesRegex(ValueError, "object-load metadata"):
            compare_events(self.bundle, self.model, self.events)

    def test_rejects_wrong_program_id(self):
        next(e for e in self.events if e["event"] == "test_run")["program_id"] = 999
        with self.assertRaisesRegex(ValueError, "program ID mismatch"):
            compare_events(self.bundle, self.model, self.events)
