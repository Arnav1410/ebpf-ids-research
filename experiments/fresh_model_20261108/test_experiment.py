import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parent))
import pipeline as p

class SplitTests(unittest.TestCase):
    def setUp(self):
        self.x=np.repeat(np.arange(100*6,dtype=np.int64).reshape(100,6),[1+i%4 for i in range(100)],axis=0)
        self.y=(self.x[:,0]//6%2).astype(np.int64)
    def test_group_disjoint_exhaustive_and_deterministic(self):
        a,groups=p.grouped_split(self.x,self.y);b,_=p.grouped_split(self.x,self.y)
        self.assertEqual(a,b);self.assertEqual(len(set(sum(a,[]))),len(self.x))
        vectors=[{tuple(self.x[i]) for i in ids} for ids in a]
        for i,j in ((0,1),(0,2),(1,2)):self.assertFalse(vectors[i]&vectors[j])
        for ids in a:
            self.assertEqual(set(self.y[ids]),{0,1})
        self.assertLess(abs(len(a[0])/len(self.x)-.7),.025)
    def test_conflicting_duplicate_labels_rejected(self):
        x=np.vstack((self.x,self.x[0]));y=np.append(self.y,1-self.y[0])
        with self.assertRaises(AssertionError):p.grouped_split(x,y)
    def test_different_seed_is_not_chosen_by_score(self):
        a,_=p.grouped_split(self.x,self.y,1);b,_=p.grouped_split(self.x,self.y,2)
        self.assertNotEqual(a,b)

class MetricTests(unittest.TestCase):
    def test_all_four_cells(self):
        m=p.metrics([0,0,0,1,1,1],[0,0,1,0,1,1])
        self.assertEqual(m['confusion_matrix'],[[2,1],[1,2]])
        self.assertAlmostEqual(m['f1'],2/3);self.assertAlmostEqual(m['mcc'],1/3)
    def test_missing_is_abstention(self):
        m=p.metrics([0,1,1],[0,None,1]);self.assertEqual(m['invalid_missing'],1)
        self.assertAlmostEqual(m['coverage'],2/3);self.assertEqual(m['FN'],0)
    def test_undefined_metrics(self):
        m=p.metrics([0,0],[0,0]);self.assertIsNone(m['precision']);self.assertIsNone(m['recall'])
        self.assertIsNone(m['mcc']);self.assertIsNone(m['f1'])
    def test_metrics_json_roundtrip(self):
        import json
        m=p.metrics([0,1],[0,1]);self.assertEqual(m,json.loads(json.dumps(m)))
    def test_empty_predictions(self):
        m=p.metrics([0,1],[None,None]);self.assertEqual(m['coverage'],0);self.assertIsNone(m['accuracy'])

class ArchitectureTests(unittest.TestCase):
    def test_original_net_is_bias_free_1280(self):
        import torch
        m=p.authors_net();self.assertEqual(sum(v.numel() for v in m.parameters()),1280)
        self.assertEqual([tuple(v.shape) for v in m.parameters()],[(32,6),(32,32),(2,32)])
        self.assertTrue(torch.isfinite(m(torch.zeros(3,6))).all())
        self.assertEqual(list(m.state_dict()),['model.0.weight','model.2.weight','model.4.weight'])
    def test_safe_numeric_checkpoint_rejects_pickle(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'bad.npz';np.savez(f,x=np.array([{'bad':1}],dtype=object))
            with self.assertRaises(ValueError):p.load_numeric(f)


class IntegerTests(unittest.TestCase):
    def test_new_weight_rounding_ties_even_and_range(self):
        from integer import q16
        self.assertEqual(q16([.5/65536,1.5/65536,-.5/65536,-1.5/65536]).tolist(),[0,2,0,-2])
        with self.assertRaises(ValueError):q16([np.inf])
        with self.assertRaises(ValueError):q16([65536.])
        with self.assertRaises(ValueError):q16([32768.])
    def test_negative_shift_and_rounding_are_different(self):
        from quantization.reference import round_div
        self.assertEqual(-65537>>16,-2)
        self.assertEqual(round_div(-65537,65536),-1)
        self.assertEqual(round_div(-3,2),-2)
    def test_heldout_rejection_not_clipping(self):
        from quantization.reference import normalize,ArithmeticFailure
        with self.assertRaises(ArithmeticFailure):normalize([3]*6,[0]*6,[1]*6,16,[2]*6)
    def test_q16_header_roundtrip_and_same_new_weights(self):
        from integer import emit,q16
        from validation.reference import Model
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'new.h';weights=[q16(np.zeros(s,dtype=np.float32)) for s in ((32,6),(32,32),(2,32))]
            f.write_text(emit(weights,[0]*6,[1]*6));model=Model.load(f)
            values,label=model.infer([0]*6,[])
            self.assertEqual(values['logits'],[0,0]);self.assertEqual(label,1)


class KernelProtocolTests(unittest.TestCase):
    def fixture(self):
        tensors=[[0]*n for n in (6,32,32,32,32,2)]
        return dict(mode='static_q16',kind='mlp',cpu=0,kernel_repeat=1,warmup=0,samples=1,prediction_delta=1,stage_deltas=[1]*6,duration_ns=[2000],
            record=dict(features=[0]*6,mask=63,cpu=0,model_slot=0,sequence=1,tensors=tensors,label=1))
    def call(self,b):
        from kernel import verify
        verify(b,'static_q16',[0]*6,[[0]*n for n in (6,32,32,32,32,2)],1,0)
    def test_valid_synthetic_protocol_not_kernel_claim(self):self.call(self.fixture())
    def test_skipped_tail_with_zero_tensors_rejected(self):
        b=self.fixture();b['stage_deltas'][3]=0
        with self.assertRaises(RuntimeError):self.call(b)
    def test_repeat_more_than_one_rejected(self):
        b=self.fixture();b['kernel_repeat']=2
        with self.assertRaises(RuntimeError):self.call(b)
    def test_stale_result_rejected(self):
        b=self.fixture();b['record']['sequence']=2
        with self.assertRaises(RuntimeError):self.call(b)
    def test_wrong_new_parameter_output_rejected(self):
        b=self.fixture();b['record']['tensors'][5][1]=1
        with self.assertRaises(RuntimeError):self.call(b)
    def test_unapproved_execution_refused(self):
        from unittest.mock import patch
        import kernel
        with patch.object(kernel.os,'geteuid',return_value=1000):
            with self.assertRaises(RuntimeError):kernel.execute(Path('/nonexistent'),'pilot')

if __name__=='__main__':unittest.main(verbosity=2)
