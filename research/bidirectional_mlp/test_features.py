import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from evaluation.cic.capture import MAX_BLOCK
from research.bidirectional_mlp.features import Event, State, ClosingWindow, I64_MAX, CLOSE_GRACE_NS, checked_sum
from research.bidirectional_mlp.audit import number, clean_csv, read_packet, summary_vector, NUMERIC


def e(direction, ns, length=32, flags=16, header=32):
    return Event(direction, ns, length, header, flags)


class Features(unittest.TestCase):
    def test_empty_direction_never_contributes_zero_minimum(self):
        state=State(80)
        with self.assertRaisesRegex(ValueError,'EMPTY'):state.vector()
        state.add(e(0,0,40,2,40))
        self.assertEqual(state.vector(),[40,0,40,80,40,1])

    def test_iat_is_within_direction_not_interleaved(self):
        s=State(9000)
        for x in [e(0,0,40,2,40),e(1,10),e(0,20),e(1,100)]:s.add(x)
        self.assertEqual(s.vector(),[40,90,32,9000,136,4])

    def test_egress_changes_actual_proposed_vector_with_ingress_held_fixed(self):
        ingress=[e(0,0,40,2,40),e(0,100),e(0,1000,32,17)]
        s=State(80);t=State(80)
        for x in sorted(ingress+[e(1,20),e(1,30)],key=lambda x:x.timestamp_ns):s.add(x)
        for x in sorted(ingress+[e(1,20,1200),e(1,999,20,16,20)],key=lambda x:x.timestamp_ns):t.add(x)
        self.assertEqual(s.vector(False),t.vector(False))
        self.assertEqual(s.vector(),[40,900,32,80,168,5])
        self.assertEqual(t.vector(),[1200,979,20,80,156,5])
        # This is an offline formula test, not proof of kernel integration.

    def test_retransmissions_and_every_tcp_control_packet_count(self):
        s=State(21)
        for x in [e(0,1,40,2,40),e(0,1,40,2,40),e(0,2),e(0,3,32,17),e(0,4,32,4)]:s.add(x)
        self.assertEqual(s.vector(),[40,1,32,21,176,5])

    def test_port_is_explicit_server_port_not_last_packet_destination(self):
        s=State(22);s.add(e(1,0,40,18,40))
        self.assertEqual(s.vector()[3],22)

    def test_reordering_and_nanoseconds(self):
        s=State(80);s.add(e(0,1_000_000_000));s.add(e(0,1_000_003_000))
        self.assertEqual(s.vector()[1],3000)
        with self.assertRaisesRegex(ValueError,'REORDER'):s.add(e(0,0))

    def test_counter_and_aggregate_overflows_reject(self):
        s=State(80);s.add(e(0,0));s.directions[0].count=I64_MAX
        with self.assertRaisesRegex(ValueError,'OVERFLOW'):s.add(e(0,1))
        t=State(80);t.add(e(0,0));t.add(e(1,1));t.directions[0].header_total=I64_MAX
        with self.assertRaisesRegex(ValueError,'OVERFLOW'):t.vector()
        with self.assertRaises(ValueError):checked_sum(-1,1)

    def test_invalid_lengths_flags_and_timestamps(self):
        for x in [e(0,0,19,16,20),e(0,0,32,16,21),e(0,-1),e(0,0,65516),e(2,0),e(0,0,32,256)]:
            with self.subTest(x=x),self.assertRaises(ValueError):x.validate()

    def test_batch_reference_agrees_on_asymmetric_trace(self):
        events=[e(0,100,40,2,40),e(1,150,1500),e(1,1000,1200),e(0,1500,32,17)]
        s=State(80)
        for x in events:s.add(x)
        self.assertEqual(s.vector(),summary_vector(events,80))

    def test_closing_waits_for_response_and_second_fin(self):
        w=ClosingWindow(80)
        events=[e(0,100,40,2,40),e(1,200,40,18,40),e(0,300,32,17),
                e(1,400,1200),e(1,500,32,17)]
        for x in events[:-1]:self.assertIsNone(w.add(x))
        self.assertEqual(w.add(events[-1]),[1200,200,32,80,176,5])
        old=list(w.snapshot)
        self.assertIsNone(w.add(e(1,600,2000)))
        self.assertEqual(w.snapshot,old)

    def test_server_first_fin_then_client_fin(self):
        w=ClosingWindow(80)
        w.add(e(0,0,40,2,40));w.add(e(1,1,32,17))
        self.assertIsNotNone(w.add(e(0,2,32,17)))

    def test_rst_immediate_and_one_direction(self):
        w=ClosingWindow(80);w.add(e(0,0,40,2,40))
        self.assertEqual(w.add(e(0,1,20,4,20)),[40,1,20,80,60,2])

    def test_missing_start_stays_unscored(self):
        for x in [e(1,0,40,18,40),e(0,0,32,16)]:
            w=ClosingWindow(80);self.assertIsNone(w.add(x))
            self.assertEqual(w.reason,'MISSING_INITIAL_CLIENT_SYN')
            self.assertIsNone(w.add(e(0,1,40,2,40)))

    def test_expiration_does_not_classify_a_late_packet(self):
        w=ClosingWindow(80);w.add(e(0,0,40,2,40));w.add(e(0,1,32,17))
        self.assertIsNone(w.add(e(1,CLOSE_GRACE_NS+2,32,17)))
        self.assertEqual(w.reason,'CLOSING_GRACE_EXPIRED_UNSCORED')
        self.assertIsNone(w.snapshot)
        self.assertEqual(w.state.directions[1].count,0)

    def test_grace_endpoint_inclusive(self):
        w=ClosingWindow(80);w.add(e(0,0,40,2,40));w.add(e(0,1,32,17))
        self.assertIsNotNone(w.add(e(1,CLOSE_GRACE_NS+1,32,17)))


class InputBounds(unittest.TestCase):
    def test_invalid_numeric_never_silently_imputed(self):
        for x in ['NaN','inf','-1','1.5',str(I64_MAX+1),'']:
            with self.subTest(x=x),self.assertRaises(ValueError):number(x)
        self.assertEqual(number(' 12.0 '),12)

    def test_duplicate_named_header_must_agree(self):
        names=list(NUMERIC)+['Fwd Header Length','Source IP','Destination IP','Source Port','Flow ID','Timestamp','Label']
        pos={name:[i for i,n in enumerate(names) if n==name] for name in names}
        row=['1']*len(names)
        for name,value in [('Source IP','192.168.0.1'),('Destination IP','192.168.0.2')]:row[pos[name][0]]=value
        self.assertEqual(clean_csv(row,pos)['Fwd Header Length'],1)
        row[pos['Fwd Header Length'][1]]='2'
        with self.assertRaisesRegex(ValueError,'CONFLICTING_DUPLICATE_HEADER'):clean_csv(row,pos)

    def test_packet_block_bounds_checked_before_allocating(self):
        interface=dict(snaplen=262144,ticks_per_second=1_000_000,seconds_offset=0,linktype=1)
        for length in [0,28,MAX_BLOCK+4,34]:
            with self.assertRaises(ValueError):read_packet(io.BytesIO(struct.pack('<II',6,length)),1,0,interface,'<')
        with self.assertRaises(ValueError):read_packet(io.BytesIO(),1,-1,interface,'<')

    def test_malformed_packet_footer_rejected(self):
        data=struct.pack('<II5I',6,32,0,0,1,0,0)+struct.pack('<I',36)
        interface=dict(snaplen=262144,ticks_per_second=1_000_000,seconds_offset=0,linktype=1)
        with self.assertRaisesRegex(ValueError,'FOOTER'):read_packet(io.BytesIO(data),1,0,interface,'<')


if __name__=='__main__':unittest.main()
