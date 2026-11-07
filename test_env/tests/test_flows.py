"""Pure header/oracle regressions plus explicitly opted-in real Stage04 proof.

Synthetic unit observations exercise the reference reducer only. They are not
kernel evidence; live acceptance exclusively uses the BPF diagnostic clock.
"""
from collections import Counter
import os
from pathlib import Path
import tempfile
import unittest

from test_env.commands import Recorder
from test_env.flow_fixture import controlled_phases, tcp_frame, unsupported_frames
from test_env.flow_reference import (Unsupported, canonical_key, compare_capture,
                                    compare_snapshot, parse_headers, reference_flow)
from test_env.flows import Flow, run_flows, SKIP_COUNTERS, _skip_accounting
from test_env.lab import CLIENT_IP, CLIENT_NS, Lab, SERVER_IP, SERVER_NS


def unit_rows(frames):
    """Explicit synthetic reducer input, never used by live validation."""
    rows = []
    for ordinal, raw in enumerate(frames, 1):
        packet = parse_headers(raw)
        rows.append({'flow_id': 7, 'ordinal': ordinal, 'timestamp_ns': ordinal * 100,
                     'ifindex': 2, 'direction': packet['direction'], 'hook': 0,
                     'header_hex': packet['header_hex']})
    return rows


class HeaderReferenceTests(unittest.TestCase):
    def test_canonical_direction_is_not_tc_role(self):
        forward = parse_headers(tcp_frame(flags=2))
        backward = parse_headers(tcp_frame(reverse=True, flags=18))
        self.assertEqual(canonical_key(forward, 2), canonical_key(backward, 2))
        self.assertEqual((forward['direction'], backward['direction']), (1, 0))
        self.assertNotEqual(canonical_key(forward, 2), canonical_key(forward, 3))

    def test_unknown_orientation_stays_unknown_without_bare_syn(self):
        rows = unit_rows([tcp_frame(flags=16), tcp_frame(reverse=True, flags=18)])
        result = reference_flow(rows, 2)
        self.assertEqual(result['initiator'], 'unknown')
        self.assertEqual(result['a_to_b']['packets'], 1)
        self.assertEqual(result['b_to_a']['packets'], 1)

    def test_variable_ip_and_tcp_options_use_declared_lengths(self):
        packet = parse_headers(tcp_frame(ip_options=b'\x01' * 8,
                                         tcp_options=b'\x01' * 12, payload=b'abcde'))
        self.assertEqual(packet['ipv4_bytes'], 65)
        self.assertEqual(packet['tcp_segment_bytes'], 37)
        self.assertEqual(packet['tcp_header_bytes'], 32)
        self.assertEqual(packet['payload_bytes'], 5)
        self.assertEqual(len(bytes.fromhex(packet['header_hex'])), 74)
        # Ring data is header-only, but a purported complete linear frame may
        # not silently claim absent payload bytes.
        parse_headers(packet['header_hex'])
        with self.assertRaises(Unsupported):
            parse_headers(packet['header_hex'], packet_length=74)

    def test_unsupported_and_malformed_reasons_are_explicit(self):
        for reason, raw in unsupported_frames().items():
            with self.subTest(reason=reason), self.assertRaisesRegex(Unsupported, '^' + reason + '$'):
                parse_headers(raw)
        for length in (0, 13, 20, 33):
            with self.subTest(length=length), self.assertRaises(Unsupported):
                parse_headers(tcp_frame()[:length])

    def test_background_ipv6_is_accounted_without_weakening_fixture_checks(self):
        frame = bytes.fromhex(unsupported_frames()['ipv6'])
        fixture = {'reason': 'skip_ipv6', 'header_hex': frame.hex()}
        background = {'reason': 'skip_ipv6',
                      'header_hex': (bytes.fromhex('333300000002') + frame[6:]).hex()}
        delta = {name: 0 for name in SKIP_COUNTERS}
        delta['skip_ipv6'] = 2
        proof = _skip_accounting(Counter(skip_ipv6=1), [fixture, background], delta)
        self.assertEqual(proof['observed_fixture'], {'skip_ipv6': 1})
        self.assertEqual(proof['observed_total'], {'skip_ipv6': 2})
        self.assertEqual(proof['background_records'], [background])
        with self.assertRaisesRegex(RuntimeError, 'counter delta'):
            _skip_accounting(Counter(skip_ipv6=1), [fixture, background],
                             {**delta, 'skip_ipv6': 3})
        with self.assertRaisesRegex(RuntimeError, 'Fixture skip reasons'):
            _skip_accounting(Counter(skip_ipv6=2), [fixture, background], delta)
        with self.assertRaisesRegex(RuntimeError, 'Fixture skip reasons'):
            _skip_accounting(Counter(skip_ipv6=1), [fixture, fixture], delta)

    def test_observed_retransmits_count_without_deduplication(self):
        raw = tcp_frame(flags=2)
        rows = unit_rows([raw, raw, tcp_frame(reverse=True, flags=18)])
        result = reference_flow(rows, 2)
        self.assertEqual(result['initiator'], 'b')
        self.assertEqual(result['b_to_a']['packets'], 2)
        self.assertEqual(result['b_to_a']['ipv4_bytes'], 80)
        self.assertEqual(result['b_to_a']['tcp_header_bytes'], 40)
        self.assertEqual(result['b_to_a']['max_iat_ns'], 100)
        self.assertEqual(result['a_to_b']['max_iat_ns'], 0)

    def test_half_close_both_fin_and_final_ack_are_distinct(self):
        frames = []
        expectations = {'half_close': 'half_closed', 'both_fin': 'closing', 'full_close': 'closed'}
        for name, phase in controlled_phases():
            if name == 'reuse':
                break
            frames.extend(bytes.fromhex(raw) for _, raw in phase
                          if 15001 in (parse_headers(raw)['a'][1], parse_headers(raw)['b'][1]))
            if name in expectations:
                result = reference_flow(unit_rows(frames), 2)
                self.assertEqual(result['state'], expectations[name])
                self.assertEqual(result['closed_ns'] > 0, name == 'full_close')

    def test_rst_immediately_closes_and_counts_packet(self):
        result = reference_flow(unit_rows([tcp_frame(flags=2), tcp_frame(reverse=True, flags=4)]), 2)
        self.assertEqual(result['state'], 'reset')
        self.assertEqual(result['ordinal'], 2)
        self.assertEqual(result['closed_ns'], 200)

    def test_fin_ack_wraparound_is_serial_not_integer_order(self):
        rows = unit_rows([tcp_frame(flags=2, sequence=0xfffffffd),
                          tcp_frame(flags=17, sequence=0xffffffff),
                          tcp_frame(reverse=True, flags=17, sequence=90, acknowledgement=0),
                          tcp_frame(flags=16, sequence=0, acknowledgement=91)])
        self.assertEqual(reference_flow(rows, 2)['state'], 'closed')

    def test_ordinal_sorting_handles_cross_cpu_ring_delivery(self):
        rows = unit_rows([tcp_frame(flags=2), tcp_frame(reverse=True, flags=18)])
        expected = reference_flow(rows, 2)
        self.assertEqual(reference_flow(list(reversed(rows)), 2), expected)
        proofs = compare_snapshot([expected], list(reversed(rows)), 2)
        self.assertEqual(proofs[0]['expected'], proofs[0]['observed'])
        wrong = dict(expected, ordinal=3)
        with self.assertRaises(AssertionError):
            compare_snapshot([wrong], rows, 2)

    def test_loss_duplicate_and_bad_clock_are_not_tolerated(self):
        rows = unit_rows([tcp_frame(flags=2), tcp_frame(reverse=True, flags=18)])
        for malformed in ([rows[1]], [rows[0], rows[0]],
                          [rows[0], dict(rows[1], timestamp_ns=1)]):
            with self.subTest(rows=malformed), self.assertRaises(AssertionError):
                reference_flow(malformed, 2)
        with self.assertRaises(AssertionError):
            compare_capture(rows, rows[:1])
        self.assertEqual(compare_capture(rows, rows)['observation_packets'], 2)


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get('NN_EBPF_RUN_LAB_TESTS') == '1',
                     'Requires explicit isolated-VM root opt-in')
class LiveFlowTests(unittest.TestCase):
    def setUp(self):
        names = ('NN_EBPF_FLOW_LOADER', 'NN_EBPF_FLOW_OBJECT', 'NN_EBPF_BPFTOOL')
        settings = [os.environ.get(name) for name in names]
        if not all(settings):
            self.skipTest('Explicit built flow loader/object/bpftool paths required')
        self.loader, self.obj, self.bpftool = map(lambda value: Path(value).resolve(), settings)
        if not all(path.is_file() for path in (self.loader, self.obj, self.bpftool)):
            self.skipTest('Flow build products unavailable')
        if any(os.path.lexists(Path('/run/netns') / name) for name in (CLIENT_NS, SERVER_NS)):
            self.skipTest('Existing lab namespaces must not be adopted')
        evidence = os.environ.get('NN_EBPF_LAB_EVIDENCE_ROOT')
        self.temporary = None
        if evidence is None:
            self.temporary = tempfile.TemporaryDirectory(prefix='nn-ebpf-flow-tests-')
            evidence = self.temporary.name
        self.recorder = Recorder(Path(evidence) / self._testMethodName)

    def tearDown(self):
        self.recorder.close()
        if self.temporary is not None:
            self.temporary.cleanup()

    def test_real_bidirectional_generations_concurrency_and_expiration(self):
        with Lab(self.recorder) as lab:
            result = run_flows(self.recorder, lab, self.loader, self.obj, self.bpftool)
            self.assertEqual(result['status'], 'pass')
            self.assertTrue(result['cleanup_complete'])
            self.assertEqual(len(result['cycles']), 2)
            self.assertEqual(result['expiration']['status'], 'pass')
            for cycle in result['cycles']:
                self.assertEqual(cycle['capture_proof']['status'], 'pass')
                self.assertEqual(cycle['capture']['socket_drops'], 0)
                self.assertTrue(cycle['cleanup']['complete'])

    def test_normal_tracking_exports_no_packet_headers(self):
        with Lab(self.recorder) as lab:
            session = Flow(self.recorder, lab, self.loader, self.obj, self.bpftool)
            try:
                ready = session.start()
                self.assertFalse(ready['config']['capture_enabled'])
                exchange = lab.exchange()
                stats = session.inspect()
                by_client = {flow['key']['b_port']: flow for flow in stats['flows']}
                observed = by_client[exchange['client_port']]
                self.assertEqual(observed['key'], {
                    'a_addr': SERVER_IP, 'a_port': exchange['server_port'],
                    'b_addr': CLIENT_IP, 'b_port': exchange['client_port'],
                    'ifindex': ready['ifindex'], 'protocol': 6})
                self.assertEqual(observed['initiator'], 'b')
                for direction, expected_bytes in (
                    ('a_to_b', exchange['response_bytes']),
                    ('b_to_a', exchange['request_bytes']),
                ):
                    counts = observed[direction]
                    self.assertGreaterEqual(counts['tcp_segment_bytes'] -
                                            counts['tcp_header_bytes'], expected_bytes)
                self.assertEqual(stats['observations'], [])
            finally:
                first = session.close()
            self.assertTrue(first['complete'])
            self.assertFalse(any(first['remaining_owned_ids'].values()))


if __name__ == '__main__':
    unittest.main()
