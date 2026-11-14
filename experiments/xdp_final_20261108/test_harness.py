"""Nonprivileged mathematical/protocol tests. Synthetic records are NOT kernel evidence."""
from pathlib import Path
import gzip,json,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import run as h

class WitnessTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.cases=[json.loads(s) for s in gzip.open(h.FRESH/'run/kernel-ready/fixtures.jsonl.gz','rt')]
 def test_all_frozen_vectors_have_completion_witness(self):
  self.assertEqual(len(self.cases),2826)
  self.assertEqual(min(min(h.certificate(c['expected']['static_q16']['tensors'])) for c in self.cases),2)
 def test_zero_identity_fixture_is_explicitly_rejected(self):
  t={s:[0]*n for s,n in zip(h.STAGES,[6,32,32,32,32,2])}
  with self.assertRaises(RuntimeError):h.certificate(t)
 def block(self,op='measure',kind=0,warm=0,samples=1):
  c=self.cases[0];v=h.states(c['expected']['static_q16']['tensors'])
  selected=v[1:] if op=='isolated' else [v[kind] if op=='failure' and kind<=5 else v[0] if op=='failure' else v[-1]]*(warm+samples)
  states=[dict(features=c['features'],model_slot=-1 if op=='failure' and kind==7 else 0,nonce=i+1,hidden1=a,hidden2=b,prediction_derived=0 if a[0]>a[1] else 1) for i,(a,b) in enumerate(selected)]
  present=not(op=='failure' and kind==6)
  return dict(event='xdp_block',mode='xdp_q16',operation=op,kind=kind,cpu=0,flags=0,kernel_repeat=1,warmup=warm,samples=samples,
   packet_dport=c['features'][3],calls=6 if op=='isolated' else warm+samples,flow_present=present,states=states if present else [],duration_ns=[2000]*samples if op=='measure' else [])
 def test_complete_workspace_mock(self):h.verify_xdp(self.block(),self.cases[0],0)
 def test_every_early_return_rejected_as_completion(self):
  for state in h.states(self.cases[0]['expected']['static_q16']['tensors'])[:-1]:
   b=self.block();b['states'][0]['hidden1'],b['states'][0]['hidden2']=state
   with self.assertRaises(RuntimeError):h.verify_xdp(b,self.cases[0],0)
 def test_actual_source_prefix_controls_are_distinguishable(self):
  for kind in range(1,8):h.verify_xdp(self.block('failure',kind),self.cases[0],0,'failure',kind)
 def test_stage_isolated_all_six_readbacks(self):h.verify_xdp(self.block('isolated'),self.cases[0],0,'isolated')
 def test_isolated_timings_cannot_be_published(self):
  b=self.block('isolated');b['duration_ns']=[1]
  with self.assertRaises(RuntimeError):h.verify_xdp(b,self.cases[0],0,'isolated')
 def test_wrong_context_destination_port_rejected(self):
  b=self.block();b['packet_dport']+=1
  with self.assertRaises(RuntimeError):h.verify_xdp(b,self.cases[0],0)
 def test_repeated_nonce_and_skipped_count_rejected(self):
  b=self.block(warm=1,samples=2);b['states'][1]['nonce']=b['states'][0]['nonce']
  with self.assertRaises(RuntimeError):h.verify_xdp(b,self.cases[0],0,warm=1,samples=2)
 def test_nonunit_kernel_repeat_rejected(self):
  b=self.block();b['kernel_repeat']=3
  with self.assertRaises(RuntimeError):h.verify_xdp(b,self.cases[0],0)
 def test_no_privileged_execution_without_root(self):
  with patch.object(h.os,'geteuid',return_value=1000):
   with self.assertRaises(RuntimeError):h.execute(Path('/none'),'pilot')
 def test_rotation_balances_first_position(self):
  for trial in range(-1,5):self.assertEqual({h.MODES[(pos+trial)%3] for pos in range(3)},set(h.MODES))
if __name__=='__main__':unittest.main(verbosity=2)
