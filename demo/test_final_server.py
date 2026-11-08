"""Host tests; synthetic model readbacks are explicitly not kernel evidence."""
from argparse import Namespace
from copy import deepcopy
import json
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch,Mock

from deployment import model_config as models
from deployment.ids import paths
from deployment.tests.test_dashboard import fixture
from dashboard.telemetry import Collector
from demo.launch import local_configuration,main
from demo.listener import reserve,inherited


class ModelSelection(unittest.TestCase):
    def test_frozen_models_scalers_and_calibrations_are_distinct(self):
        original=models.model_spec('original');fresh=models.model_spec('fresh')
        self.assertEqual(fresh['header_sha256'],'e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391')
        self.assertEqual(fresh['parameter_sha256'],'1558c438e06600d8e3a5eeb28fe23c6aed94cb693a75dea4817497add71bd8d9')
        self.assertEqual(fresh['mean'],[572,11043024376,36,484,11935,373])
        self.assertNotEqual(original['scaler_sha256'],fresh['scaler_sha256'])
        self.assertEqual(models.model_spec('original','layer_specific')['logit_q'],18)
        self.assertEqual(models.model_spec('fresh','layer_specific')['logit_q'],16)

    def test_actual_readback_checker_rejects_wrong_model_and_scaler(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);data=models.reference('fresh').packed()
            for slot in (0,1):(d/f'model-readback-{slot}.bin').write_bytes(data)
            self.assertEqual(models.verify_loaded(d,'fresh')['kernel_readback'],'PASS')
            with self.assertRaises(ValueError):models.verify_loaded(d,'original')
            damaged=bytearray(data);damaged[5120]^=1;(d/'model-readback-1.bin').write_bytes(damaged)
            with self.assertRaisesRegex(ValueError,'slot 1'):models.verify_loaded(d,'fresh')

    def test_fresh_artifact_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'fresh';shutil.copytree(models.FRESH,target)
            (target/'mlp_params.bpf.h').write_text('invalid')
            with patch.object(models,'FRESH',target),self.assertRaisesRegex(ValueError,'artifact changed'):
                models.model_spec('fresh')

    def test_binaries_selected_independently_from_bpf_arithmetic(self):
        self.assertEqual(paths('static_q16','fresh')[0].name,'controller_fresh')
        self.assertEqual(paths('layer_specific','fresh')[0].name,'controller_fresh_layer')
        self.assertEqual(paths('static_q16','fresh')[1],paths('static_q16','original')[1])

    def test_telemetry_uses_selected_scaling_and_experiment_identity(self):
        log=Mock();info=models.model_spec('fresh','layer_specific');info['kernel_readback']='PASS'
        c=Collector('test0','layer_specific','session',log,model_identity=info,application_port=80,experiment_id='test-run')
        value=c.update(fixture('layer_specific'),{})
        self.assertEqual(value['flows'][0]['logit_q'],16)
        record=log.append.call_args.args[0]
        self.assertEqual((record['model'],record['application_port'],record['experiment_id']),('fresh',80,'test-run'))
        self.assertEqual(record['features'],fixture('layer_specific')['results'][0]['features'])


class Configuration(unittest.TestCase):
    def test_prefix_and_client_subnet_checks_do_not_configure_networking(self):
        args=Namespace(server_ip='192.168.77.3',prefix_length=24,client_ip='192.168.77.2',interface='test0')
        plan=dict(addresses=[dict(operstate='UP',addr_info=[dict(family='inet',local=args.server_ip,prefixlen=24)])])
        local_configuration(args,plan)
        wrong=deepcopy(plan);wrong['addresses'][0]['addr_info'][0]['prefixlen']=16
        with self.assertRaisesRegex(RuntimeError,'not assigned'):local_configuration(args,wrong)
        args.client_ip='10.0.0.1'
        with self.assertRaisesRegex(RuntimeError,'subnet'):local_configuration(args,plan)

    def test_cli_accepts_80_9000_and_propagates_explicit_model(self):
        for port in (80,9000):
            with patch('sys.argv',['launch','--port',str(port),'--model','fresh']),patch('demo.launch.launch',return_value=0) as launch:
                self.assertEqual(main(),0);a=launch.call_args.args[0]
                self.assertEqual((a.port,a.model),(port,'fresh'))
        with patch('sys.argv',['launch','--port','0']),self.assertRaises(SystemExit):main()

    def test_dashboard_cannot_bind_publicly(self):
        with patch('sys.argv',['launch','--dashboard-bind','0.0.0.0']),patch('demo.launch.launch') as launch:
            self.assertEqual(main(),1);launch.assert_not_called()


class OwnedListeners(unittest.TestCase):
    def setUp(self):
        try:self.listener=reserve('127.0.0.1',0,'unit fixture')
        except (PermissionError,RuntimeError):self.skipTest('Sandbox socket restriction; run as ordinary user in isolated operator suite')

    def tearDown(self):
        if hasattr(self,'listener'):self.listener.close()

    def test_inherited_listener_is_validated(self):
        import os
        address,port=self.listener.getsockname()
        with inherited(os.dup(self.listener.fileno()),address,port) as child:
            self.assertTrue(child.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN))
        with self.assertRaises(ValueError):inherited(os.dup(self.listener.fileno()),address,port+1)

    def test_conflict_does_not_terminate_existing_service(self):
        address,port=self.listener.getsockname()
        with self.assertRaisesRegex(RuntimeError,'never terminated'):reserve(address,port,'unit fixture')
        with socket.create_connection((address,port),timeout=1):
            connection,_=self.listener.accept();connection.close()


if __name__=='__main__':unittest.main()
