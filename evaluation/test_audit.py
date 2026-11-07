import json
from pathlib import Path
import struct
import tempfile
import unittest
from evaluation.audit import audit
from evaluation.data import numeric_npy
from evaluation.import_cic import inspect,FEATURES


class Audit(unittest.TestCase):
    def test_shapes_scaler_and_class_counts(self):
        r=audit();self.assertEqual(r['rows'],18840);self.assertEqual(r['label_counts'],{0:5585,1:13255})
        self.assertTrue(all(x['rounded_moments_match'] for x in r['moments']))

    def test_pickle_and_malformed_npy_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.npy'
            for descr in ('|O','<i8'):
                h=repr(dict(descr=descr,fortran_order=False,shape=(1,))).encode()
                p.write_bytes(b'\x93NUMPY\x01\x00'+struct.pack('<H',len(h))+h+b'x')
                with self.assertRaises(ValueError):numeric_npy(p)

    def test_cic_named_columns_and_nonfinite_policy(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data.csv';p.write_text(','.join(' '+x for x in FEATURES+['Label'])+'\n1,2,3,80,20,1,BENIGN\nNaN,2,3,80,20,1,BENIGN\n')
            r=inspect(p,Path(d)/'out');self.assertEqual((r['valid'],r['excluded']),(1,1))
            self.assertIn('NOT RUN',r['evaluation'])

    def test_duplicate_cic_headers_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data.csv';p.write_text(','.join(FEATURES+['Label','Fwd Header Length'])+'\n')
            with self.assertRaises(ValueError):inspect(p,Path(d)/'out')


if __name__=='__main__':unittest.main()
