import ctypes as C
import errno
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
import threading
from reference import Model, STAGES, SIZES, tcp_packet
from safety import require_attached_filter, require_detach_ack, require_empty_filters

CONTEXT = None


class PacketWitness(unittest.TestCase):
    def test_independent_packet_parser_units_and_options(self):
        from packet_witness import parse_frame
        packet=tcp_packet(flags=0x11,payload=b'hello\n',tcp_options=b'\x01'*4,ip_options=b'\x01'*4)
        parsed=parse_frame(packet,'ingress')
        self.assertEqual((parsed['segment_bytes'],parsed['tcp_header_bytes'],parsed['skb_bytes']),
                         (30,24,len(packet)))
        self.assertEqual((parsed['source_ip'],parsed['dest_port'],parsed['tcp_flags']),('33.33.33.73',5001,0x11))
        self.assertEqual(parsed['hook'],'ingress')
        self.assertIsNone(parse_frame(packet[:53],'ingress'))
        bad=bytearray(packet);bad[20]=0x20
        self.assertIsNone(parse_frame(bad,'egress'))

    def test_witness_comparison_detects_counter_and_feature_contamination(self):
        from copy import deepcopy
        from packet_witness import parse_frame,compare_snapshot
        packets=[parse_frame(tcp_packet(flags=2),'ingress'),
                 parse_frame(tcp_packet(payload=b'hello\n',flags=0x11),'ingress'),
                 parse_frame(tcp_packet(source='33.33.33.1',dest='33.33.33.73',sport=5001,dport=12345,payload=b'tc-demo-ok\n'),'egress')]
        key=dict(a_ip='33.33.33.1',a_port=5001,b_ip='33.33.33.73',b_port=12345,protocol=6)
        flow=dict(source_port=12345,key=key,hooks=dict(ingress=dict(packets=2,bytes=114),egress=dict(packets=1,bytes=65)),
                  endpoint_packets=[1,2],endpoint_bytes=[65,114],packets=2,bytes=46,input_initialized=True,mlp_input_direction=1)
        record=dict(source_port=12345,key=key,features=[26,1234,20,5001,40,2],mlp_input_direction=1)
        snapshot=dict(flows=[flow],results=[record],matched=2,egress_matched=1)
        witness=dict(packets=packets,capture_drops=0)
        self.assertEqual(compare_snapshot(snapshot,witness,12345,1)['status'],'PASS')
        for change in ('counter','feature','drops'):
            s,w=deepcopy(snapshot),deepcopy(witness)
            if change=='counter':s['flows'][0]['hooks']['egress']['packets']=2
            if change=='feature':s['results'][0]['features'][5]=3
            if change=='drops':w['capture_drops']=1
            with self.assertRaises(RuntimeError):compare_snapshot(s,w,12345,1)


class CleanupEvidence(unittest.TestCase):
    def test_controller_error_does_not_skip_resource_absence_checks(self):
        import demo
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import Mock, patch
        with TemporaryDirectory() as directory:
            loader=Mock(directory=Path(directory),stopped=True)
            loader.stop.side_effect=RuntimeError('Controller cleanup failed')
            with patch.object(demo,'qdisc_cleanup') as filters:
                demo.cleanup_loader(None,loader)
            filters.assert_called_once_with(None,loader.directory)
            loader.verify_ids_gone.assert_called_once()
            evidence=json.loads((loader.directory/'cleanup-status.json').read_text())
            self.assertEqual(evidence['status'],'PASS')
            self.assertIn('controller_diagnostic',evidence)

    def test_cleanup_id_failure_still_checks_filters_and_reports_failure(self):
        import demo
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import Mock, patch
        with TemporaryDirectory() as directory:
            loader=Mock(directory=Path(directory),stopped=True)
            loader.verify_ids_gone.side_effect=RuntimeError('owned ID remains')
            with patch.object(demo,'qdisc_cleanup') as filters:
                with self.assertRaisesRegex(RuntimeError,'owned ID remains'):
                    demo.cleanup_loader(None,loader)
            filters.assert_called_once()
            self.assertEqual(json.loads((loader.directory/'cleanup-status.json').read_text())['status'],'FAIL')

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

    def test_two_hook_detach_requires_each_id_and_direction(self):
        events=[{'event':'detach_acknowledged','program_id':10,'direction':'ingress'},
                {'event':'detach_acknowledged','program_id':11,'direction':'egress'}]
        require_detach_ack(events,10,'ingress')
        require_detach_ack(events,11,'egress')
        for program,direction in ((10,'egress'),(11,'ingress'),(12,'egress')):
            with self.assertRaises(RuntimeError):
                require_detach_ack(events,program,direction)

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
        self.lib.host_egress_packet.argtypes = [C.c_void_p, C.c_uint, C.c_uint64]
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

    def egress(self,packet,timestamp=1000):
        buf=C.create_string_buffer(packet)
        self.assertEqual(self.lib.host_egress_packet(buf,len(packet),timestamp),0)

    def directional(self):
        value=(C.c_uint64*12)();self.lib.host_directional(value);return list(value)

    def reverse(self,**kwargs):
        return tcp_packet(source='33.33.33.1',dest='33.33.33.73',sport=5001,
                          dport=kwargs.pop('port',12345),**kwargs)

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

    def test_reorder_policy_can_overestimate_chronological_sample_gap(self):
        times=[1000,3000,2000]
        for i,now in enumerate(times): self.send(tcp_packet(flags=0x11 if i==2 else 0x10),now)
        chronological=sorted(times)
        oracle=max(b-a for a,b in zip(chronological,chronological[1:]))
        self.assertEqual(oracle,1000)
        self.assertEqual(self.result()[0][1],2000)
        self.assertGreater(self.result()[0][1],oracle)
        self.assert_parity()  # NN parity does not establish feature timing accuracy.

    def test_reorder_policy_can_underestimate_chronological_sample_gap(self):
        times=[3000,1000,2000]
        for i,now in enumerate(times): self.send(tcp_packet(flags=0x11 if i==2 else 0x10),now)
        chronological=sorted(times)
        oracle=max(b-a for a,b in zip(chronological,chronological[1:]))
        self.assertEqual(oracle,1000)
        self.assertEqual(self.result()[0][1],0)
        self.assertLess(self.result()[0][1],oracle)
        self.assert_parity()

    def test_minimal_hook_counters_are_separate_and_pass_packets(self):
        for n in (54,60): self.assertEqual(self.lib.host_minimal_ingress(n),0)
        for n in (60,100,54): self.assertEqual(self.lib.host_minimal_egress(n),0)
        counters=(C.c_uint64*4)(); self.lib.host_hook_counters(counters)
        self.assertEqual(list(counters),[2,114,3,214])
        self.assertEqual(self.result()[3],0)
        self.assertEqual(self.lib.host_is_busy(),0)

    def test_minimal_both_hooks_pass_when_stats_missing(self):
        self.lib.host_missing_stats(1)
        self.assertEqual(self.lib.host_minimal_ingress(54),0)
        self.assertEqual(self.lib.host_minimal_egress(54),0)
        counters=(C.c_uint64*4)(); self.lib.host_hook_counters(counters)
        self.assertEqual(list(counters),[0,0,0,0])

    def test_canonical_key_matches_reverse_and_numeric_endpoint_order(self):
        import ipaddress
        import sys
        self.lib.host_key.argtypes=[C.c_void_p,C.c_uint,C.POINTER(C.c_uint32)]
        for source,destination,sport,dport in (
                ('33.33.33.73','33.33.33.1',41000,5001),
                ('200.0.0.1','10.255.255.1',1,65535),
                ('10.0.0.1','10.0.0.1',256,1)):
            with self.subTest(source=source,destination=destination,sport=sport,dport=dport):
                packet=tcp_packet(source=source,dest=destination,sport=sport,dport=dport)
                reverse=tcp_packet(source=destination,dest=source,sport=dport,dport=sport)
                keys=[]; directions=[]
                for frame in (packet,reverse):
                    key=(C.c_uint32*5)();buf=C.create_string_buffer(frame)
                    directions.append(self.lib.host_key(buf,len(frame),key));keys.append(list(key))
                endpoints=sorted(((int(ipaddress.IPv4Address(source)),sport),
                                  (int(ipaddress.IPv4Address(destination)),dport)))
                expected=[]
                for address,port in endpoints:
                    expected.extend((int.from_bytes(address.to_bytes(4,'big'),sys.byteorder),
                                     int.from_bytes(port.to_bytes(2,'big'),sys.byteorder)))
                expected.append(6)
                self.assertEqual(keys,[expected,expected])
                self.assertEqual(directions[0]+directions[1],1)

    def test_canonical_keys_keep_distinct_source_ports_separate(self):
        self.lib.host_key.argtypes=[C.c_void_p,C.c_uint,C.POINTER(C.c_uint32)]
        keys=[]
        for port in (41000,41001):
            packet=tcp_packet(sport=port);key=(C.c_uint32*5)()
            self.lib.host_key(C.create_string_buffer(packet),len(packet),key);keys.append(list(key))
        self.assertNotEqual(*keys)

    def test_bidirectional_counters_do_not_change_ingress_features(self):
        self.egress(self.reverse(flags=0x12),500)
        self.assertEqual(self.flow()[:4],[0,0,0,0])
        self.assertEqual(self.directional()[10],0) # Egress cannot choose the MLP leg.
        self.send(tcp_packet(flags=2),1000)
        self.send(tcp_packet(payload=b'hello\n'),2000)
        self.egress(self.reverse(payload=b'tc-demo-ok\n'),3000)
        self.send(tcp_packet(flags=0x11),5000)
        first=self.result()
        self.egress(self.reverse(flags=0x11),6000)
        self.egress(self.reverse(flags=4),7000)
        self.assertEqual(self.result(),first)
        self.assertEqual(first[0],[26,3000,20,5001,60,3])
        d=self.directional()
        self.assertEqual(d[:8],[3,168,1000,5000,4,227,500,7000])
        self.assertEqual(d[8:],[4,3,1,1])
        self.assertEqual(self.flow()[:6],[3,66,2,1,0,0])
        self.assert_parity()

    def test_same_key_both_hooks_concurrent_updates_remain_separate(self):
        barrier=threading.Barrier(4)
        def worker(i):
            barrier.wait()
            for j in range(50):
                if i%2:self.egress(self.reverse(),1000+j)
                else:self.send(tcp_packet(),1000+j)
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(worker,range(4)))
        self.send(tcp_packet(flags=0x11),3000)
        self.assertEqual(self.directional()[0:2],[101,5454])
        self.assertEqual(self.directional()[4:6],[100,5400])
        self.assertEqual(self.directional()[8:10],[100,101])
        self.assertEqual(self.flow()[:6],[101,2020,2,1,0,0])
        self.assert_parity()

    def test_ten_bidirectional_host_connections_do_not_mix(self):
        barrier=threading.Barrier(10)
        def worker(i):
            port=41000+i;barrier.wait()
            self.egress(self.reverse(port=port,flags=0x12),500)
            self.send(tcp_packet(sport=port,flags=2),1000)
            self.egress(self.reverse(port=port,payload=b'x'*i),1500)
            self.send(tcp_packet(sport=port,payload=b'y'*i,flags=0x11),2000)
        with ThreadPoolExecutor(max_workers=10) as pool:list(pool.map(worker,range(10)))
        for i in range(10):
            self.lib.host_select_port(41000+i)
            self.assertEqual(self.directional()[0:2],[2,108+i])
            self.assertEqual(self.directional()[4:6],[2,108+i])
            self.assertEqual(self.result()[0],[20+i,1000,20,5001,40,2])
            self.assert_parity()

    def test_client_filter_is_optional_and_applies_to_egress_destination(self):
        self.egress(tcp_packet(source='33.33.33.1',dest='33.33.33.74',sport=5001,dport=12345,flags=4))
        self.assertEqual(self.directional(),[0]*12)
        self.lib.host_filter(0,0)
        self.send(tcp_packet(source='33.33.33.74',flags=0x11))
        self.assertEqual(self.result()[0],[20,0,20,5001,20,1])
        self.assert_parity()

    def test_malformed_egress_passes_without_flow_or_inference(self):
        self.egress(b'x'*12)
        self.assertEqual(self.directional(),[0]*12)
        self.assertEqual(self.result()[3],0)

    def test_reverse_ingress_is_monitored_but_not_mixed_into_mlp_leg(self):
        self.lib.host_filter(0,0)
        self.send(tcp_packet(flags=2),1000)
        self.send(self.reverse(flags=0x11),2000)
        self.assertEqual(self.result()[3],0)
        self.send(tcp_packet(flags=0x11),3000)
        self.assertEqual(self.result()[0],[20,2000,20,5001,40,2])
        self.assertEqual(self.directional()[0:2],[3,162])
        self.assertEqual(self.directional()[8:10],[1,2])
        self.assertEqual(self.flow()[:6],[2,40,2,1,0,0])
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
