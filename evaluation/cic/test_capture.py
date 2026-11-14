"""Unprivileged synthetic/parser checks; host C functions are NOT kernel runs."""
import ctypes as C
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from evaluation.cic.capture import (CaptureError, PacketError, Reader, Packet,
                                    FeatureWindow, decode_tcp, MAX_BLOCK, I64_MAX)
from validation.reference import tcp_packet, Model, STAGES

ROOT = Path(__file__).resolve().parents[2]


def block(kind, body, order="<"):
    length = len(body) + 12
    return struct.pack(order + "II", kind, length) + body + struct.pack(order + "I", length)


def section(order="<"):
    return block(0x0a0d0d0a, struct.pack(order + "IHHq", 0x1a2b3c4d, 1, 0, -1), order)


def option(code, data, order="<"):
    return struct.pack(order + "HH", code, len(data)) + data + b"\0" * (-len(data) % 4)


def interface(order="<", extra=b"", linktype=1):
    return block(1, struct.pack(order + "HHI", linktype, 0, 262144) + extra, order)


def enhanced(frame, ticks=1_000_002, order="<", interface_id=0):
    return block(6, struct.pack(order + "IIIII", interface_id, ticks >> 32,
                               ticks & 0xffffffff, len(frame), len(frame))
                 + frame + b"\0" * (-len(frame) % 4), order)


def packet(frame=None, stamp=1000, index=1):
    frame = frame if frame is not None else tcp_packet()
    return Packet(index, index + 2, 92, 0, 0, stamp, len(frame), 1, frame)


class Containers(unittest.TestCase):
    def read(self, raw):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "input.pcap"
            p.write_bytes(raw)
            reader = Reader(p)
            values = list(reader)
            self.assertEqual(p.read_bytes(), raw)
            self.assertTrue(reader.complete)
            self.assertEqual(reader.digest.hexdigest(), hashlib.sha256(raw).hexdigest())
            self.assertEqual(reader.md5.hexdigest(), hashlib.md5(raw, usedforsecurity=False).hexdigest())
            return values, reader.metadata

    def test_classic_both_orders_and_precisions(self):
        frame = tcp_packet()
        for order, magic, fraction, expected in (
            ("<", b"\xd4\xc3\xb2\xa1", 2, 1_000_002_000),
            (">", b"\xa1\xb2\xc3\xd4", 2, 1_000_002_000),
            ("<", b"\x4d\x3c\xb2\xa1", 2, 1_000_000_002),
            (">", b"\xa1\xb2\x3c\x4d", 2, 1_000_000_002),
        ):
            with self.subTest(order=order, magic=magic):
                raw = (magic + struct.pack(order + "HHiIII", 2, 4, 0, 0, 262144, 1)
                       + struct.pack(order + "IIII", 1, fraction, len(frame), len(frame)) + frame)
                records, meta = self.read(raw)
                self.assertEqual(records[0].timestamp_ns, expected)
                self.assertEqual(records[0].data, frame)
                self.assertEqual(meta["format"], "pcap")

    def test_ng_default_precision_and_references(self):
        records, meta = self.read(section() + interface() + enhanced(tcp_packet()))
        self.assertEqual(records[0].timestamp_ns, 1_000_002_000)
        self.assertEqual(records[0].reference()["file_offset"], 48)
        self.assertEqual(records[0].block_index, 3)
        self.assertEqual(meta["interfaces"][0]["ticks_per_second"], 1_000_000)

    def test_ng_resolution_offset_and_big_endian(self):
        for order in ("<", ">"):
            extra = option(9, b"\x09", order) + option(14, struct.pack(order + "q", -1), order)
            raw = section(order) + interface(order, extra) + enhanced(tcp_packet(), 2_000_000_003, order)
            records, _ = self.read(raw)
            self.assertEqual(records[0].timestamp_ns, 1_000_000_003)

    def test_ng_binary_resolution_and_fraction_rejection(self):
        raw = section() + interface(extra=option(9, b"\x83")) + enhanced(tcp_packet(), 1)
        self.assertEqual(self.read(raw)[0][0].timestamp_ns, 125_000_000)
        raw = section() + interface(extra=option(9, b"\x8a")) + enhanced(tcp_packet(), 1)
        with self.assertRaisesRegex(CaptureError, "integer ns"):
            self.read(raw)

    def test_section_changes_reset_interface_numbers(self):
        raw = (section() + interface() + enhanced(tcp_packet()) + section(">")
               + interface(">") + enhanced(tcp_packet(), order=">"))
        records, meta = self.read(raw)
        self.assertEqual([p.section for p in records], [0, 1])
        self.assertEqual([p.interface for p in records], [0, 0])
        self.assertEqual(meta["sections"], 2)

    def test_simple_and_legacy_packet_blocks(self):
        frame = tcp_packet()
        padded = frame + b"\0" * (-len(frame) % 4)
        simple = block(3, struct.pack("<I", len(frame)) + padded)
        legacy = block(2, struct.pack("<HHIIII", 0, 0, 0, 1_000_002, len(frame), len(frame)) + padded)
        records, _ = self.read(section() + interface() + simple + legacy)
        self.assertIsNone(records[0].timestamp_ns)
        self.assertEqual(records[1].timestamp_ns, 1_000_002_000)

    def test_corrupt_lengths_interfaces_options_and_truncation(self):
        valid = section() + interface() + enhanced(tcp_packet())
        cases = [valid[:-1], valid[:-4] + b"\0\0\0\0",
                 section() + interface() + enhanced(tcp_packet(), interface_id=1),
                 section() + interface(extra=option(9, b"\x06") * 2),
                 section() + interface(extra=struct.pack("<HH", 9, 300)),
                 section() + struct.pack("<III", 6, MAX_BLOCK + 4, 0),
                 b"not a capture", section() + enhanced(tcp_packet())]
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(CaptureError):
                self.read(raw)


class Features(unittest.TestCase):
    client = (0x21212149, 12345)
    server = (0x21212101, 5001)

    def test_incoming_fin_included_reverse_and_later_packets_excluded(self):
        window = FeatureWindow(self.client, self.server)
        trace = [(1000, tcp_packet(flags=2)),
                 (1050, tcp_packet(source="33.33.33.1", dest="33.33.33.73", sport=5001, dport=12345, flags=0x12)),
                 (1080, tcp_packet()), (2000, tcp_packet(payload=b"hello")),
                 (2500, tcp_packet(flags=0x11)), (3000, tcp_packet(flags=4, payload=b"later"))]
        for i, (stamp, frame) in enumerate(trace, 1):
            p = packet(frame, stamp, i)
            window.add(p, decode_tcp(p))
        self.assertEqual(window.snapshot["features"], [25, 920, 20, 5001, 80, 4])
        self.assertEqual(window.snapshot["trigger"]["packet_index"], 5)
        self.assertEqual(window.snapshot["trigger_flags"], 0x11)
        self.assertEqual([p["packet_index"] for p in window.snapshot["packet_references"]], [1, 3, 4, 5])

    def test_tcp_options_rst_and_zero_interval(self):
        window = FeatureWindow(self.client, self.server)
        frames = [tcp_packet(flags=2, tcp_options=b"\1" * 20),
                  tcp_packet(flags=4, tcp_options=b"\1" * 12, payload=b"ok")]
        for i, frame in enumerate(frames, 1):
            p = packet(frame, 0, i)
            window.add(p, decode_tcp(p))
        self.assertEqual(window.snapshot["features"], [40, 0, 34, 5001, 72, 2])
        self.assertEqual(window.snapshot["trigger_flags"], 4)

    def test_timestamp_and_resource_boundaries(self):
        p = packet(stamp=I64_MAX)
        window = FeatureWindow(self.client, self.server, max_packets=1)
        window.add(p, decode_tcp(p))
        for bad, reason in ((replace(p, timestamp_ns=None), "MISSING_TIMESTAMP"),
                            (replace(p, timestamp_ns=-1), "TIMESTAMP_INT64_RANGE"),
                            (replace(p, timestamp_ns=I64_MAX + 1), "TIMESTAMP_INT64_RANGE"),
                            (replace(p, timestamp_ns=0), "TIMESTAMP_REORDER"),
                            (p, "FLOW_PACKET_RESOURCE_LIMIT")):
            with self.subTest(reason=reason), self.assertRaisesRegex(PacketError, reason):
                window.add(bad, decode_tcp(bad))
        self.assertEqual(window.values[5], 1)

    def test_int64_counter_overflow_rejected(self):
        p = packet()
        window = FeatureWindow(self.client, self.server)
        window.values[4] = I64_MAX
        with self.assertRaisesRegex(PacketError, "FEATURE_INT64_OVERFLOW"):
            window.add(p, decode_tcp(p))

    def test_unsupported_and_malformed_packet_scope(self):
        base = tcp_packet()
        fragment = bytearray(base);fragment[20] = 0x20
        bad_doff = bytearray(base);bad_doff[46] = 0x40
        cases = [(replace(packet(), linktype=113), "UNSUPPORTED_LINKTYPE"),
                 (replace(packet(), wire_length=len(base) + 1), "TRUNCATED_PACKET"),
                 (packet(tcp_packet(ip_options=b"\1" * 4)), "IPV4_OPTIONS_OR_INVALID_IHL"),
                 (packet(bytes(fragment)), "IPV4_FRAGMENT"),
                 (packet(bytes(bad_doff)), "INVALID_TCP_HEADER_LENGTH"),
                 (packet(tcp_packet(ethertype=0x8100)), "UNSUPPORTED_ETHERTYPE"),
                 (packet(tcp_packet(protocol=17)), "NON_TCP")]
        for p, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(PacketError, reason):
                decode_tcp(p)


class OriginalCChecks(unittest.TestCase):
    """Compile unchanged original XDP/TC C under existing host mocks."""
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.libs = {}
        for mode, source, includes in (
            ("xdp", "evaluation/cic/feature_probe.c", ["validation/include"]),
            ("tc", "evaluation/cic/feature_probe.c", ["tc/tests/include", "validation/include"]),
        ):
            out = Path(cls.tmp.name) / (mode + ".so")
            command = ["clang-12", "-O2", "-shared", "-fPIC", "-pthread"]
            if mode == "tc":
                command.append("-DPROBE_TC")
            command += ["-I" + str(ROOT / p) for p in includes]
            command += [str(ROOT / source), "-o", str(out)]
            result = subprocess.run(command, capture_output=True, text=True)
            print(json.dumps(dict(check="host_C_build", mode=mode, argv=command,
                                  exit_code=result.returncode, compiler_output=result.stdout + result.stderr)), flush=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            cls.libs[mode] = C.CDLL(str(out))

    def test_hand_trace_features_against_both_original_C_implementations(self):
        xdp, tc = self.libs["xdp"], self.libs["tc"]
        xdp.native_reset();tc.host_reset()
        xdp.native_packet.argtypes = [C.c_void_p, C.c_size_t, C.c_uint64]
        xdp.native_flow.argtypes = [C.c_int, C.POINTER(C.c_int64)]
        tc.host_packet.argtypes = [C.c_void_p, C.c_uint, C.c_uint64]
        tc.host_record.argtypes = [C.POINTER(C.c_int64), C.POINTER(C.c_int32), C.POINTER(C.c_int32), C.POINTER(C.c_uint64)]
        window = FeatureWindow(Features.client, Features.server)
        trace = [(1000, tcp_packet(flags=2)), (1080, tcp_packet()),
                 (2000, tcp_packet(payload=b"hello")), (2500, tcp_packet(flags=0x11))]
        for stamp, frame in trace:
            p = packet(frame, stamp)
            window.add(p, decode_tcp(p))
            buf = C.create_string_buffer(frame)
            self.assertEqual(xdp.native_packet(buf, len(frame), stamp), 2)
            self.assertEqual(tc.host_packet(buf, len(frame), stamp), 0)
        original = (C.c_int64 * 8)()
        self.assertEqual(xdp.native_flow(0, original), 0)
        raw, tensors, label, mask = (C.c_int64 * 6)(), (C.c_int32 * 192)(), C.c_int32(), C.c_uint64()
        tc.host_record(raw, tensors, C.byref(label), C.byref(mask))
        self.assertEqual(list(original[:6]), window.snapshot["features"])
        self.assertEqual(list(raw), [25, 920, 20, 5001, 80, 4])
        self.assertEqual(mask.value, 63)
        expected, y = Model.load(ROOT / "src/mlp_params.bpf.h").infer(list(raw))
        sizes = [6, 32, 32, 32, 32, 2]
        self.assertEqual([list(tensors[i * 32:i * 32 + n]) for i, n in enumerate(sizes)],
                         [expected[name] for name in STAGES])
        self.assertEqual(label.value, y)

    def test_feature_only_probes_do_not_execute_neural_inference(self):
        for name, lib in self.libs.items():
            with self.subTest(mode=name):
                lib.probe_reset()
                lib.probe_packet.argtypes = [C.c_void_p, C.c_uint, C.c_uint64]
                lib.probe_features.argtypes = [C.POINTER(C.c_int64)]
                for stamp, frame in ((1000, tcp_packet(flags=2)),
                                      (2000, tcp_packet(flags=0x11, payload=b"ok"))):
                    buf = C.create_string_buffer(frame)
                    self.assertEqual(lib.probe_packet(buf, len(frame), stamp), 0)
                result = (C.c_int64 * 6)()
                self.assertEqual(lib.probe_features(result), 0)  # Also checks prediction counter == 0.
                self.assertEqual(list(result), [22, 1000, 20, 5001, 40, 2])


if __name__ == "__main__":
    unittest.main()
