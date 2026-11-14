from fractions import Fraction
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np

from .core import choose_threshold,apply_threshold,margins,sigmoid
from .study import select
from research.cic_csv_mlp.common import write,read


def brute(y,s):
    candidates=np.r_[np.unique(s),np.nextafter(s.max(),np.inf)]
    scored=[]
    for t in candidates:
        p=s>=t;tp=int((p&(y==1)).sum());fp=int((p&(y==0)).sum());fn=int((~p&(y==1)).sum())
        scored.append((Fraction(2*tp,2*tp+fp+fn),-fp,float(t)))
    return max(scored)[2]


class ThresholdTests(unittest.TestCase):
    def test_negative_cutoff_recovers_separated_positive_scores(self):
        y=np.array([0,0,1,1]);s=np.array([-5.,-4.,-2.,-1.])
        t,_,_=choose_threshold(y,s)
        self.assertEqual(t,-2.);self.assertEqual(apply_threshold(s,t).tolist(),y.tolist())

    def test_equal_scores_must_move_as_one_block(self):
        y=np.array([1,0,1,0]);s=np.array([1.,1.,1.,1.])
        t,index,c=choose_threshold(y,s)
        self.assertEqual(t,1.);self.assertEqual(c['TP'][index],2);self.assertEqual(c['FP'][index],2)
        self.assertEqual(len(c['threshold']),2)

    def test_exact_f1_tie_prefers_fewer_false_positives(self):
        y=np.array([1,0,0,1]);s=np.array([4.,3.,2.,1.])
        self.assertEqual(choose_threshold(y,s)[0],4.)

    def test_randomized_selector_matches_independent_fraction_bruteforce(self):
        rng=np.random.default_rng(20261109)
        for _ in range(100):
            y=np.r_[0,1,rng.integers(2,size=18)];s=rng.integers(-5,6,size=20).astype(float)
            self.assertEqual(choose_threshold(y,s)[0],brute(y,s))

    def test_exact_threshold_equality_and_original_zero_tie_differ(self):
        self.assertEqual(apply_threshold(np.array([-1.,0.,1.]),0).tolist(),[0,1,1])
        self.assertEqual((np.array([-1.,0.,1.])>0).astype(int).tolist(),[0,0,1])

    def test_empty_single_class_nonbinary_and_nonfinite_inputs_reject(self):
        cases=[([],[]),([0,0],[1.,2.]),([0,.5,1],[1.,2.,3.]),([0,1],[0.,np.nan]),([0,1],[[0.,1.]])]
        for y,s in cases:
            with self.subTest(y=y),self.assertRaises(ValueError):choose_threshold(y,s)

    def test_float64_subtraction_avoids_float32_overflow(self):
        logits=np.array([[-3e38,3e38]],dtype=np.float32)
        self.assertTrue(np.isfinite(margins(logits)).all())

    def test_sigmoid_stable_and_roundtrip_threshold_exact(self):
        s=np.array([-1000.,-2.,0.,2.,1000.]);p=sigmoid(s)
        self.assertTrue(np.isfinite(p).all());self.assertEqual(float(sigmoid(0)),.5)
        self.assertTrue((np.diff(p)>=0).all())
        t=-1.23456789012345;self.assertEqual(float.fromhex(t.hex()),t)

    def test_nonfinite_test_score_is_never_a_benign_imputation(self):
        with self.assertRaises(ValueError):apply_threshold([0.,np.nan],0.)

    def test_exclusive_write_prevents_second_test_application(self):
        with tempfile.TemporaryDirectory() as d:
            marker=Path(d)/'TEST_APPLICATION_STARTED.json';write(marker,{'test':'fixture'})
            with self.assertRaises(FileExistsError):write(marker,{'test':'second'})

    def test_validation_selection_never_parses_a_test_archive(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source';source.mkdir();out=Path(d)/'analysis'
            y=np.array([0,0,1,1]);ids=np.arange(4);score=np.array([-5.,-4.,-2.,-1.])
            np.savez_compressed(source/'validation.npz',labels=y,indices=ids,source_lines=ids+2)
            (source/'test.npz').write_bytes(b'TEST ARCHIVE MUST NEVER BE PARSED')
            for mode in ('forward','bidirectional'):
                p=source/mode;p.mkdir();(p/'checkpoint.npz').write_bytes(b'frozen model, never deserialized')
                (p/'scaler.npz').write_bytes(b'frozen scaler, never fitted')
                np.savez_compressed(p/'validation_logits.npz',indices=ids,logits=np.stack([np.zeros(4),score],axis=1).astype(np.float32))
            original=np.load;opened=[]
            def guard(path,*args,**kwargs):
                self.assertNotIn('test.npz',str(path));opened.append(Path(path).name)
                return original(path,*args,**kwargs)
            with patch('research.cic_threshold_sensitivity.study.verify_source'),patch('research.cic_threshold_sensitivity.study.snapshot',return_value={}),patch('numpy.load',side_effect=guard):
                select(source,out)
            self.assertEqual(opened,['validation.npz','validation_logits.npz','validation_logits.npz'])
            selected=read(out/'thresholds.json')
            self.assertFalse(selected['test_arrays_parsed']);self.assertEqual(selected['models']['bidirectional']['threshold'],-2.)
            self.assertTrue((out/'THRESHOLDS_FROZEN.json').is_file())


if __name__=='__main__':unittest.main()
