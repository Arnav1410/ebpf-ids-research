import ctypes as C
import errno
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
import threading
from reference import Model, STAGES, SIZES, tcp_packet
from safety import require_attached_filter, require_detach_ack, require_empty_filters

CONTEXT = None


class CleanupEvidence(unittest.TestCase):
    def test_detach_requires_ack_for_exact_program(self):
        require_detach_ack([{'event': 'detach_acknowledged', 'program_id': 374}], 374)
        for events in ([], [{'event': 'closed'}],
                       [{'event': 'detach_acknowledged', 'program_id': 375}],
                       [{'event': 'query', 'error': -22}]):
            with self.assertRaises(RuntimeError):
                require_detach_ack(events, 374)

    def test_only_successful_empty_dump_establishes_absence(self):
        require_empty_filters('[]\n', 0)
        for stdout, code in (('[]', 2), ('Cannot find specified filter chain', 2),
                             ('[{"kind":"bpf"}]', 0), ('{}', 0), ('null', 0)):
            with self.assertRaises(RuntimeError):
                require_empty_filters(stdout, code)
        with self.assertRaises(ValueError):
            require_empty_filters('', 0)

    def test_attachment_uses_structured_id_and_direct_action(self):
        import json
        f = {'kind': 'bpf', 'pref': 1, 'options': {'handle': '0x1',
             'direct-action': True, 'prog': {'id': 374}}}
        require_attached_filter(json.dumps([{'kind': 'bpf', 'chain': 0}, f]), 374)
        with self.assertRaises(RuntimeError):
            require_attached_filter(json.dumps([f]), 37)  # No substring match.
        for key, value in (('direct-action', False), ('handle', '0x2')):
            changed = json.loads(json.dumps(f)); changed['options'][key] = value
            with self.assertRaises(RuntimeError):
                require_attached_filter(json.dumps([changed]), 374)


class HostTC(unittest.TestCase):
    def setUp(self):
        path, root = CONTEXT
        self.lib = C.CDLL(str(path))
        self.lib.host_packet.argtypes = [C.c_void_p, C.c_uint, C.c_uint64]
        self.lib.host_parse.argtypes = [C.c_void_p, C.c_uint]
        self.lib.host_record.argtypes = [C.POINTER(C.c_int64), C.POINTER(C.c_int32), C.POINTER(C.c_int32), C.POINTER(C.c_uint64)]
        self.lib.host_stats.argtypes = [C.POINTER(C.c_uint64)]
        self.lib.host_reset()
        self.model = Model.load(root / 'src/mlp_params.bpf.h')

    def scan(self, mode):
        self.lib.host_scan_ids.argtypes = [C.c_int, C.c_void_p, C.c_uint]
        buffer = C.create_string_buffer(256)
        code = self.lib.host_scan_ids(mode, buffer, len(buffer))
        return code, buffer.value.decode()

    def test_registry_walk_sparse_ids_and_empty_registry(self):
        code, output = self.scan(0)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), [7, 56])
        code, output = self.scan(1)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), [])

    def test_registry_walk_does_not_treat_errors_as_absence(self):
        for mode, error in ((2, errno.EPERM), (3, errno.EINVAL), (4, errno.EIO)):
            code, output = self.scan(mode)
            self.assertEqual(code, -error)
            with self.assertRaises(ValueError):
                json.loads(output)

    def send(self, packet, timestamp=1000):
        buf = C.create_string_buffer(packet)
        self.assertEqual(self.lib.host_packet(buf, len(packet), timestamp), 0)

    def result(self):
        raw, tensors, label, mask = (C.c_int64 * 6)(), (C.c_int32 * 192)(), C.c_int32(), C.c_uint64()
        self.lib.host_record(raw, tensors, C.byref(label), C.byref(mask))
        return list(raw), {name: list(tensors[i*32:i*32+n]) for i, (name, n) in enumerate(zip(STAGES, SIZES))}, label.value, mask.value

    def assert_parity(self):
        raw, actual, label, mask = self.result()
        events = []
        expected, expected_label = self.model.infer(raw, events)
        self.assertFalse(events)
        self.assertEqual(mask, 63)
        self.assertEqual(actual, expected)
        self.assertEqual(label, expected_label)

    def flow(self):
        value = (C.c_uint64 * 8)(); self.lib.host_flow(value)
        return list(value)

    def test_duplicate_fin_is_counted_without_reinference(self):
        self.send(tcp_packet(flags=0x11), 1000)
        first = self.result()
        self.send(tcp_packet(flags=4), 2000)
        self.assertEqual(self.result(), first)
        self.assertEqual(self.flow()[:6], [2, 40, 2, 1, 0, 1])
        self.assertEqual(self.lib.host_is_busy(), 0)

    def test_missing_stats_value_passes_without_inference_or_owner_leak(self):
        self.lib.host_missing_stats(1)
        self.send(tcp_packet(flags=0x11))
        self.assertEqual(self.flow(), [0]*8)
        self.assertEqual(self.result()[3], 0)
        self.assertEqual(self.lib.host_is_busy(), 0)
        self.lib.host_missing_stats(0)
        self.send(tcp_packet(flags=0x11), 2000)
        self.assertEqual(self.result()[0], [20, 0, 20, 5001, 20, 1])
        self.assert_parity()

    def test_each_missing_tail_target_releases_owner_and_retries(self):
        for slot in range(6):
            with self.subTest(slot=slot):
                self.lib.host_reset()
                self.lib.host_missing_slot(slot)
                self.send(tcp_packet(flags=0x11))
                self.assertEqual(self.flow()[2:5], [0, 1, 1])
                self.assertEqual(self.lib.host_is_busy(), 0)
                self.lib.host_missing_slot(-1)
                self.send(tcp_packet(flags=0x11), 2000)
                self.assertEqual(self.flow()[2:5], [2, 2, 1])
                self.assert_parity()

    def test_missing_model_and_result_publication_failures_are_retryable(self):
        for name, bad, good in (('host_model_slot', 2, 0), ('host_result_failure', 1, 0)):
            with self.subTest(failure=name):
                self.lib.host_reset()
                getattr(self.lib, name)(bad)
                self.send(tcp_packet(flags=4))
                self.assertEqual(self.flow()[2:5], [0, 1, 1])
                self.assertEqual(self.lib.host_is_busy(), 0)
                getattr(self.lib, name)(good)
                self.send(tcp_packet(flags=4), 2000)
                self.assert_parity()

    def test_creation_race_relooks_up_winning_value(self):
        self.lib.host_creator_race()
        self.send(tcp_packet(flags=0x11))
        self.assertEqual(self.flow()[:4], [1, 20, 2, 1])
        self.assert_parity()

    def test_capacity_and_reentrant_workspace_rejection_pass_packets(self):
        self.lib.host_capacity(0)
        self.send(tcp_packet(flags=4))
        self.assertEqual(self.result()[3], 0)
        self.lib.host_capacity(64)
        self.lib.host_busy(1)
        self.send(tcp_packet(flags=4))
        self.assertEqual(self.flow()[:4], [1, 20, 0, 0])
        self.assertEqual(self.lib.host_is_busy(), 1)
        self.lib.host_busy(0)
        self.send(tcp_packet(flags=4), 2000)
        self.assert_parity()

    def test_out_of_order_helper_samples_never_underflow_iat(self):
        self.send(tcp_packet(), 3000)
        self.send(tcp_packet(), 1000)
        self.send(tcp_packet(flags=0x11), 4000)
        self.assertEqual(self.result()[0][1], 1000)
        self.assertEqual(self.flow()[6:], [1000, 1])
        self.assert_parity()

    def test_ten_distinct_simultaneous_host_flows_keep_results(self):
        barrier = threading.Barrier(10)
        def worker(i):
            packet = tcp_packet(sport=41000+i, flags=0x11, payload=b'x'*i)
            barrier.wait()
            self.send(packet, 1000)
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(worker, range(10)))
        for i in range(10):
            self.lib.host_select_port(41000+i)
            self.assertEqual(self.flow()[:4], [1, 20+i, 2, 1])
            self.assertEqual(self.result()[0], [20+i, 0, 20+i, 5001, 20, 1])
            self.assert_parity()

    def test_same_flow_host_concurrent_updates_and_duplicate_triggers(self):
        barrier = threading.Barrier(8)
        def worker(i):
            barrier.wait()
            for j in range(50):
                self.send(tcp_packet(), 1000+i*50+j)
            self.send(tcp_packet(flags=0x11), 2000+i)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))
        self.lib.host_select_port(12345)
        self.assertEqual(self.flow()[:6], [408, 8160, 2, 1, 0, 7])
        self.assert_parity()

    def test_golden_six_features_and_all_layers(self):
        self.send(tcp_packet(flags=2), 1000)
        self.send(tcp_packet(payload=b'x'*100, tcp_options=b'\x01'*4), 4000)
        self.send(tcp_packet(flags=0x11), 9000)
        self.assertEqual(self.result()[0], [124, 5000, 20, 5001, 64, 3])
        self.assert_parity()
        counters = (C.c_uint64 * 12)(); self.lib.host_stats(counters)
        self.assertEqual(list(counters)[4:10], [1]*6)
        self.assertEqual(counters[10], 1)
        self.assertEqual(counters[11], 0)

    def test_rst_triggers(self):
        self.send(tcp_packet(flags=4, payload=b'123'))
        self.assertEqual(self.result()[0], [23, 0, 23, 5001, 20, 1])
        self.assert_parity()

    def test_ipv4_options_are_parsed_at_correct_tcp_offset(self):
        self.send(tcp_packet(flags=0x11, ip_options=b'\x01'*4))
        self.assertEqual(self.result()[0], [20, 0, 20, 5001, 20, 1])
        self.assert_parity()

    def test_source_gate_and_nonclosing_traffic(self):
        self.send(tcp_packet(source='33.33.33.74', flags=0x11))
        self.send(tcp_packet(flags=0x10))
        self.assertEqual(self.result()[3], 0)

    def test_truncation_and_invalid_lengths_pass_unscored(self):
        packet = tcp_packet(flags=0x11)
        for n in (0, 13, 14, 33, 34, 53):
            self.send(packet[:n])
        self.send(tcp_packet(total_length=10))
        self.send(tcp_packet(total_length=1000))
        self.assertEqual(self.result()[3], 0)

    def test_fragments_and_invalid_doff_pass_unscored(self):
        for offset, value in ((20, 0x20), (46, 0x40)):
            packet = bytearray(tcp_packet(flags=0x11)); packet[offset] = value
            self.send(bytes(packet))
        self.assertEqual(self.result()[3], 0)
