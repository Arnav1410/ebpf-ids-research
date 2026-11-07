"""Unprivileged snapshot, retention, deployment-policy and local HTTP tests."""
from copy import deepcopy
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

from dashboard.telemetry import Collector,RotatingLog,atomic_json,CAPACITY,json_safe
from dashboard.server import handler,read_state,main as server_main,LIMIT
from deployment.ids import check_empty,owns_filter,program_id,control_path,start

FIXTURES=Path(__file__).parent/'fixtures'


def fixture(mode='static_q16',count=1):
    s=json.loads((FIXTURES/(mode+'.json')).read_text())['snapshot']
    original_flow=s['flows'][0];original_result=s['results'][0];s['flows']=[];s['results']=[]
    for i in range(count):
        f=deepcopy(original_flow);r=deepcopy(original_result)
        f['key']['b_port']=40000+i;r['key']['b_port']=40000+i
        f['source_port']=r['source_port']=40000+i;s['flows'].append(f);s['results'].append(r)
    return s


class Telemetry(unittest.TestCase):
    def collect(self,snapshot,mode='static_q16',log=None):
        return Collector('test0',mode,'unit-session',log or Mock(),['33.33.33.1']).update(snapshot,{},now=100)

    def test_one_flow_has_real_directions_logits_and_roles(self):
        s=fixture();value=self.collect(s);f=value['flows'][0]
        self.assertEqual(f['client_ip'],'33.33.33.73');self.assertEqual(f['server_ip'],'33.33.33.1')
        self.assertEqual(f['hooks'],s['flows'][0]['hooks']);self.assertEqual(f['logits'],s['results'][0]['tensors'][-1])
        self.assertEqual(f['state'],'DONE');self.assertEqual(value['source'],'LIVE')

    def test_ten_connections_from_one_ip_not_merged(self):
        s=fixture(count=10);log=Mock();value=self.collect(s,log=log)
        self.assertEqual(len({f['id'] for f in value['flows']}),10);self.assertEqual(log.append.call_count,10)
        self.assertEqual(len({f['client_ip'] for f in value['flows']}),1)

    def test_both_modes_keep_kernel_logit_scales(self):
        for mode,q in (('static_q16',16),('layer_specific',18)):
            self.assertEqual(self.collect(fixture(mode),mode)['flows'][0]['logit_q'],q)

    def test_zero_flows_not_disconnected(self):
        s=fixture(count=0);s.update({k:0 for k in ('packets','bytes','predictions','egress_packets','egress_bytes')})
        value=self.collect(s);self.assertEqual(value['status'],'CONNECTED');self.assertEqual(value['aggregate']['tracked_flows'],0)

    def test_long_running_updates_do_not_duplicate_logs(self):
        log=Mock();c=Collector('test0','static_q16','unit-session',log);s=fixture()
        for i in range(1000):v=c.update(s,{},now=i)
        self.assertEqual(log.append.call_count,1);self.assertEqual(len(c.seen),1);self.assertEqual(len(v['recent_predictions']),1)

    def test_restart_has_new_session_identity(self):
        log=Mock();s=fixture()
        for session in ('one','two'):Collector('test0','static_q16',session,log).update(s,{})
        self.assertEqual([c.args[0]['session'] for c in log.append.call_args_list],['one','two'])

    def test_missing_incomplete_or_inconsistent_results(self):
        s=fixture();s['results']=[];self.assertIsNone(self.collect(s)['flows'][0]['label'])
        s=fixture();s['results'][0]['mask']=31;log=Mock();v=self.collect(s,log=log)
        self.assertEqual(v['flows'][0]['state'],'DONE_WITHOUT_COMPLETE_RESULT');log.append.assert_not_called()
        s=fixture();s['results'][0]['label']=1-s['results'][0]['label']
        with self.assertRaisesRegex(ValueError,'Logit'):self.collect(s)

    def test_egress_first_flow_not_mislabeled_as_classified(self):
        s=fixture();s['results']=[];s['flows'][0].update(input_initialized=False,state=0)
        row=self.collect(s)['flows'][0];self.assertIsNone(row['label']);self.assertEqual(row['server_ip'],'33.33.33.1')

    def test_error_counters_and_numerical_rejections_visible(self):
        s=fixture('layer_specific');s['flows'][0]['failures']=2;s['numerical_diagnostics']={'range':1}
        v=self.collect(s,'layer_specific');self.assertEqual(len(v['errors']),2)

    def test_wrong_mode_duplicate_key_and_bad_counter_rejected(self):
        s=fixture()
        with self.assertRaises(ValueError):self.collect(s,'layer_specific')
        s['flows']*=2
        with self.assertRaises(ValueError):self.collect(s)
        s=fixture();s['packets']=-1
        with self.assertRaises(ValueError):self.collect(s)

    def test_full_supported_map_is_retained_and_bounded(self):
        log=Mock();s=fixture(count=CAPACITY);v=self.collect(s,log=log)
        self.assertEqual(len(v['flows']),CAPACITY);self.assertEqual(log.append.call_count,CAPACITY)
        self.assertEqual(len(v['recent_predictions']),50)
        self.assertLess(len(json.dumps(v)),LIMIT)
        s['flows'].append(s['flows'][0])
        with self.assertRaisesRegex(ValueError,'capacity'):self.collect(s)

    def test_u64_values_do_not_lose_browser_precision(self):
        self.assertEqual(json_safe({'ns':2**64-1,'class':0}),{'ns':'18446744073709551615','class':0})

    def test_logging_contains_no_payload_and_rotation_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'predictions.jsonl';log=RotatingLog(p,limit=1500,backups=2)
            for _ in range(20):self.collect(fixture(),log=log)
            self.assertLessEqual(len(list(Path(d).iterdir())),3)
            r=json.loads(p.read_text().splitlines()[-1]);self.assertIn('logits',r);self.assertNotIn('payload',r)
            self.assertIn('statistics_basis',r)


class DeploymentPolicy(unittest.TestCase):
    def test_address_comparison_ignores_dad_but_detects_actual_changes(self):
        from deployment.test_isolated import address_configuration
        before=[dict(ifindex=3,ifname='test0',mtu=1500,address='aa:bb:cc:dd:ee:ff',flags=['UP'],
                     addr_info=[dict(family='inet6',local='fe80::1',prefixlen=64,scope='link',tentative=True,valid_life_time=100)])]
        after=deepcopy(before);after[0]['addr_info'][0].pop('tentative');after[0]['addr_info'][0]['valid_life_time']=90
        self.assertEqual(address_configuration(before),address_configuration(after))
        for kind in ('address','prefix','admin','mtu'):
            different=deepcopy(after)
            if kind=='address':different[0]['addr_info'][0]['local']='fe80::2'
            if kind=='prefix':different[0]['addr_info'][0]['prefixlen']=128
            if kind=='admin':different[0]['flags']=[]
            if kind=='mtu':different[0]['mtu']=9000
            self.assertNotEqual(address_configuration(before),address_configuration(different))

    def test_socket_path_limit_is_checked_before_preflight_or_loading(self):
        from argparse import Namespace
        self.assertEqual(str(control_path(Path('/run/nn-ebpf-ids'))),'/run/nn-ebpf-ids/control.sock')
        with patch('deployment.ids.preflight') as preflight:
            with self.assertRaisesRegex(RuntimeError,'path too long'):
                start(Namespace(state_dir=Path('/run')/('x'*110)))
            preflight.assert_not_called()

    def test_existing_empty_clsact_is_reusable(self):
        check_empty({'ingress':[],'egress':[],'qdisc':[{'kind':'clsact'},{'kind':'fq_codel'}]})

    def test_occupied_legacy_and_shared_block_hooks_are_refused(self):
        for s in ({'ingress':[{'kind':'flower'}],'egress':[],'qdisc':[]},
                  {'ingress':[],'egress':[],'qdisc':[{'kind':'ingress'}]},
                  {'ingress':[],'egress':[],'qdisc':[{'kind':'clsact','ingress_block':12}]}):
            with self.assertRaises(RuntimeError):check_empty(s)

    def test_exact_identity_and_direct_action_are_required(self):
        f={'kind':'bpf','pref':49152,'options':{'handle':'0x4e4e','prog':{'id':123},'direct-action':True}}
        self.assertTrue(owns_filter(f,123));self.assertFalse(owns_filter(f,12))
        for key,value in (('pref',1),('kind','flower')):
            bad=deepcopy(f);bad[key]=value;self.assertFalse(owns_filter(bad,123))
        f['options']['direct-action']=False;self.assertFalse(owns_filter(f,123))


class PublishedState(unittest.TestCase):
    def test_disconnected_corrupt_stale_and_stopped_states(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'state.json';self.assertEqual(read_state(p)['status'],'DISCONNECTED')
            p.write_text('bad');self.assertEqual(read_state(p)['status'],'ERROR')
            atomic_json(p,dict(schema=1,source='LIVE',status='CONNECTED',collected_unix=100))
            self.assertEqual(read_state(p,101)['status'],'CONNECTED');self.assertEqual(read_state(p,110)['status'],'STALE')
            atomic_json(p,dict(schema=1,source='LIVE',status='STOPPED',collected_unix=100))
            self.assertEqual(read_state(p,110)['status'],'STOPPED')

    def test_atomic_replacement_and_no_symlink_temporary_file(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'state.json';atomic_json(p,{'a':1});atomic_json(p,{'a':2})
            self.assertEqual(json.loads(p.read_text()),{'a':2})
            p.with_name('state.json.tmp').symlink_to('/etc/passwd')
            atomic_json(p,{'a':3})
            self.assertEqual(json.loads(p.read_text()),{'a':3})
            self.assertTrue(p.with_name('state.json.tmp').is_symlink())

    def test_http_server_refuses_root(self):
        with patch('dashboard.server.os.geteuid',return_value=0),patch('sys.argv',['server.py']):
            with self.assertRaises(SystemExit) as cm:server_main()
            self.assertEqual(cm.exception.code,2)


class HTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.path=Path(cls.temp.name)/'state.json'
        try:cls.http=ThreadingHTTPServer(('127.0.0.1',0),handler(cls.path))
        except PermissionError:
            cls.temp.cleanup();raise unittest.SkipTest('Sandbox forbids local sockets; run tests in normal terminal')
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):cls.http.shutdown();cls.http.server_close();cls.thread.join();cls.temp.cleanup()

    def request(self,path,method='GET',host=None):
        c=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=3)
        c.request(method,path,headers={'Host':host or '127.0.0.1'});r=c.getresponse();data=r.read();c.close();return r,data

    def test_local_assets_and_disconnected_api(self):
        r,data=self.request('/');self.assertEqual(r.status,200);self.assertIn(b'Kernel intrusion',data)
        r,data=self.request('/api/state');self.assertEqual(json.loads(data)['source'],'LIVE')

    def test_no_mutations_file_traversal_or_foreign_host(self):
        for path in ('/etc/passwd','/../etc/passwd','/%2e%2e/etc/passwd','/api/stop'):
            self.assertEqual(self.request(path)[0].status,404)
        self.assertEqual(self.request('/api/state','POST')[0].status,405)
        self.assertEqual(self.request('/api/state',host='evil.invalid')[0].status,403)


if __name__=='__main__':unittest.main()
