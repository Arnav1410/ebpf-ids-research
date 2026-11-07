from argparse import Namespace
from copy import deepcopy
import csv
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from demo.common import scenarios,canonical
from demo.client import connection
from demo.evaluate import join

ROOT=Path(__file__).resolve().parents[1]


class Scenarios(unittest.TestCase):
    def test_prefix_bounds_and_ground_truth(self):
        rows=scenarios(ROOT/'demo/scenarios.csv',10);self.assertEqual(len(rows),10);self.assertEqual(rows[-1]['case_id'],'demo010')
        self.assertEqual(rows[7]['ground_truth'],'unknown')
        for count in (0,65):
            with self.assertRaises(ValueError):scenarios(ROOT/'demo/scenarios.csv',count)

    def test_canonical_numeric_direction_and_ports(self):
        key=canonical('192.168.77.2',12345,'192.168.77.3',9000)
        self.assertEqual(key,canonical('192.168.77.3',9000,'192.168.77.2',12345))
        self.assertNotEqual(key,canonical('192.168.77.2',12346,'192.168.77.3',9000))


def fixtures():
    experiment=dict(experiment_id='run1',collector_session='kernel1',mode='static_q16',start_monotonic_ns=0,end_monotonic_ns=100)
    clients=[];events=[];predictions=[]
    for i,(truth,label) in enumerate((('intrusion',1),('benign',1),('benign',0),('intrusion',0))):
        r=dict(experiment_id='run1',case_id='case'+str(i),protocol=6,ground_truth=truth,ground_truth_provenance='SYNTHETIC UNIT FIXTURE ONLY',
               client_ip='192.168.77.2',client_port=40000+i,server_ip='192.168.77.3',server_port=9000,completion='PASS')
        clients.append(r);events.append({**r,'status':'PASS'})
        predictions.append(dict(session='kernel1',mode='static_q16',key=dict(a_ip='192.168.77.2',a_port=40000+i,b_ip='192.168.77.3',b_port=9000,protocol=6),
            label=label,logits=[0,1] if label else [1,0],inference_monotonic_ns=50,sequence=1))
    return experiment,clients,events,predictions


class Matching(unittest.TestCase):
    def test_all_confusion_cells_and_permuted_order(self):
        e,c,a,p=fixtures();rows,r=join(e,c,list(reversed(a)),list(reversed(p)),1,'synthetic fixture')
        self.assertEqual([x['predicted_label'] for x in rows],[1,1,0,0]);self.assertEqual(r['metrics']['f1'],.5)
        self.assertEqual(r['classification_coverage_all'],1)

    def test_missing_and_identical_duplicates_not_benign(self):
        e,c,a,p=fixtures();rows,r=join(e,c,a,p[:3]+[p[0]],1,'fixture')
        self.assertEqual(rows[-1]['match_status'],'MISSING_PREDICTION');self.assertIsNone(rows[-1]['predicted_label'])
        self.assertEqual(r['duplicate_identical_prediction_records'],1);self.assertEqual(r['metrics']['missing_invalid_predictions'],1)

    def test_conflicting_duplicates_are_ambiguous(self):
        e,c,a,p=fixtures();other=deepcopy(p[0]);other['sequence']=2
        rows,r=join(e,c,a,p+[other]);self.assertEqual(rows[0]['match_status'],'AMBIGUOUS_PREDICTIONS')

    def test_port_reuse_does_not_use_nearest_timestamp(self):
        e,c,a,p=fixtures();c[1]['client_port']=c[0]['client_port'];a[1]['client_port']=a[0]['client_port']
        rows,r=join(e,c,a,p);self.assertTrue(all(x['match_status']=='AMBIGUOUS_SOURCE_PORT_REUSE' for x in rows[:2]))

    def test_foreign_session_wrong_experiment_and_client_error(self):
        e,c,a,p=fixtures();p[0]['session']='old';c[1]['experiment_id']='other';c[2]['completion']='FAIL'
        rows,r=join(e,c,a,p);self.assertEqual(r['ignored_foreign_session_records'],1)
        self.assertEqual([x['match_status'] for x in rows[:3]],['MISSING_PREDICTION','WRONG_EXPERIMENT','CLIENT_ERROR'])

    def test_unknown_truth_and_benign_only_have_no_intrusion_f1(self):
        e,c,a,p=fixtures()
        for row in c:row['ground_truth']='benign'
        c[0]['ground_truth']='unknown'
        _,r=join(e,c,a,p,1,'published intended mapping, fixture');self.assertIsNone(r['metrics']['f1']);self.assertEqual(r['metrics']['unknown_truth'],1)
        _,r=join(e,c,a,p);self.assertIsNone(r['metrics'])

    def test_duplicate_case_and_missing_app_record(self):
        e,c,a,p=fixtures();c[0]['case_id']=c[1]['case_id'];rows,_=join(e,c,a,p)
        self.assertEqual(rows[0]['match_status'],'DUPLICATE_CASE_ID')
        e,c,a,p=fixtures();rows,_=join(e,c,a[1:],p);self.assertEqual(rows[0]['match_status'],'MISSING_OR_AMBIGUOUS_APPLICATION_RECORD')

    def test_invalid_logits_are_abstentions(self):
        e,c,a,p=fixtures();p[0]['logits']=[float('nan'),1]
        rows,r=join(e,c,a,p,1,'fixture');self.assertEqual(rows[0]['match_status'],'INVALID_PREDICTION')
        self.assertIsNone(rows[0]['predicted_label']);self.assertEqual(r['metrics']['missing_invalid_predictions'],1)


class SocketProtocol(unittest.TestCase):
    def test_actual_tcp_half_close_and_socket_identity(self):
        # A real unprivileged loopback socket test; no BPF or interface changes.
        try:
            with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        except PermissionError:self.skipTest('Sandbox socket restriction; run in isolated operator suite')
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);log=(d/'server.log').open('w')
            server=subprocess.Popen([sys.executable,str(ROOT/'demo/server.py'),'--server-ip','127.0.0.1','--port',str(port),
                '--experiment-id','unit','--events',str(d/'events.jsonl'),'--ready',str(d/'ready.json')],stdout=log,stderr=subprocess.STDOUT)
            try:
                deadline=time.monotonic()+5
                while not (d/'ready.json').exists():
                    if server.poll() is not None or time.monotonic()>deadline:self.fail((d/'server.log').read_text())
                    time.sleep(.05)
                row=scenarios(ROOT/'demo/scenarios.csv',1)[0]
                r=connection(row,Namespace(experiment_id='unit',server_ip='127.0.0.1',source_ip='127.0.0.1',port=port))
                self.assertEqual(r['completion'],'PASS');self.assertGreater(r['client_port'],0)
                self.assertEqual(r['client_ip'],'127.0.0.1');self.assertEqual(r['payload_bytes_sent'],row['payload_length'])
            finally:server.terminate();server.wait(timeout=10);log.close()
            event=json.loads((d/'events.jsonl').read_text());self.assertEqual(event['case_id'],row['case_id'])
            self.assertEqual(event['client_port'],r['client_port'])


if __name__=='__main__':unittest.main()
