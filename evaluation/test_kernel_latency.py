"""Synthetic protocol/gate tests only; never evidence of actual kernel runs."""
from copy import deepcopy
from pathlib import Path
import gzip
import json
import struct
import tempfile
import unittest

from evaluation.kernel_latency import pilot_positions,check_archived,require_full_gate,audit_saved,MODES,KEYS
from evaluation.latency import summary_ns
from tc.demo import reference_for
from validation.reference import STAGES


class Sampling(unittest.TestCase):
    def test_exactly_100_unique_stable_positions_in_original_order(self):
        ids=list(range(20000,33844));a=pilot_positions(ids)
        self.assertEqual(a,pilot_positions(ids));self.assertEqual(len(a),100)
        self.assertEqual(a,sorted(set(a)));self.assertNotEqual(a,list(range(100)))
        self.assertTrue(all(0<=i<13844 for i in a))

    def test_small_or_duplicate_cohorts_rejected(self):
        for values in (list(range(99)),[1]*13844):
            with self.assertRaises(RuntimeError):pilot_positions(values)


class Evidence(unittest.TestCase):
    def block(self,mode,warm=0,samples=1):
        model=reference_for(mode);raw=list(model.mean);tensors,label=model.infer(raw)
        expected=[tensors[n] for n in STAGES]
        return raw,expected,label,dict(mode=mode,kind='mlp',cpu=0,kernel_repeat=1,warmup=warm,samples=samples,
            prediction_delta=warm+samples,stage_deltas=[warm+samples]*6,duration_ns=[100]*samples,
            record=dict(features=raw,mask=63,sequence=1,model_slot=0,cpu=0,tensors=expected,label=label))

    def test_zero_tensor_repeated_runs_require_three_full_completions(self):
        for mode in MODES:
            raw,expected,label,block=self.block(mode,1,2)
            self.assertTrue(all(v==0 for row in expected for v in row));self.assertEqual(label,1)
            check_archived(block,mode,raw,expected,label,0,1,2)
            for field,value in (('prediction_delta',1),('stage_deltas',[1]*6),('kernel_repeat',2)):
                bad=deepcopy(block);bad[field]=value
                with self.assertRaises(RuntimeError):check_archived(bad,mode,raw,expected,label,0,1,2)

    def test_correct_label_alone_cannot_hide_corrupted_hidden_stage(self):
        raw,expected,label,block=self.block('static_q16')
        bad=deepcopy(block);bad['record']['tensors'][3][17]=1
        with self.assertRaises(RuntimeError):check_archived(bad,'static_q16',raw,expected,label,0)

    def test_archive_disagreement_rejected_even_if_reference_record_looks_valid(self):
        raw,expected,label,block=self.block('layer_specific')
        archive=deepcopy(expected);archive[0][0]=1
        with self.assertRaises(RuntimeError):check_archived(block,'layer_specific',raw,archive,label,0)


class Gate(unittest.TestCase):
    def test_full_dataset_requires_clean_same_bundle_two_mode_pilot(self):
        bundle=Path('/tmp/synthetic-kernel-pilot')
        good=dict(phase='pilot',status='PASS',cleanup='PASS',input_count=100,prepared_bundle=str(bundle),
            source_manifest_sha256='synthetic',modes={m:dict(status='PASS') for m in MODES})
        require_full_gate(good,bundle,'synthetic')
        for key,value in (('phase','full'),('status','FAIL'),('cleanup','FAIL'),('input_count',99),
                          ('prepared_bundle','/tmp/another'),('source_manifest_sha256','changed')):
            bad=deepcopy(good);bad[key]=value
            with self.assertRaises(RuntimeError):require_full_gate(bad,bundle,'synthetic')
        bad=deepcopy(good);bad['modes']['layer_specific']['status']='NOT RUN'
        with self.assertRaises(RuntimeError):require_full_gate(bad,bundle,'synthetic')


class RawAudit(unittest.TestCase):
    """Everything constructed here is MOCK metadata, never kernel evidence."""
    def test_saved_record_accounting_identity_and_missing_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);n=100
            plan=dict(pilot_positions=list(range(n)),pilot_trials=2)
            raw=list(reference_for('static_q16').mean)
            contract=dict(ids=list(range(20000,20100)),raw=[raw]*n,packed={},labels={})
            result=dict(status='PASS',cleanup='PASS',phase='pilot',input_count=n,trials=2,
                        environment=dict(cpu=0),modes={},resources={})
            records=[]
            maker=Evidence()
            for mode in MODES:
                _,expected,label,block=maker.block(mode)
                padded=[0]*192
                for i,values in enumerate(expected):padded[32*i:32*i+len(values)]=values
                contract['packed'][KEYS[mode]]=struct.pack('<192i',*padded)*n
                contract['labels'][KEYS[mode]]=[label]*n
                _,_,_,guard=maker.block(mode,1,2)
                records.append(dict(phase='repetition_guard',mode=mode,status='PASS',block=guard))
                for trial in (-1,0,1):
                    for position in range(n):
                        records.append(dict(phase='warmup' if trial<0 else 'measured',trial=trial,
                            mode=mode,position=position,source_row=20000+position,status='PASS',block=block))
                result['modes'][mode]=dict(summary_ns([100]*200),total_kernel_duration_ns=20000,
                                           kernel_time_normalized_inferences_per_second=10_000_000.)
                result['resources'][mode]=[dict(event='loaded',program_ids=[11],map_ids=[12])]
                (root/mode).mkdir();(root/mode/'ids-absent.json').write_text(json.dumps(dict(
                    all_absent=True,program_ids=[11],map_ids=[12])))
            def write(values):
                with gzip.open(root/'measurements.jsonl.gz','wt') as stream:
                    for value in values:stream.write(json.dumps(value)+'\n')
            (root/'results.json').write_text(json.dumps(result));write(records)
            audited=audit_saved(root,contract,plan)
            self.assertEqual(audited['measured_kernel_calls'],400)
            self.assertEqual(audited['warmup_kernel_calls'],200)
            self.assertEqual(audited['repetition_guard_kernel_calls'],6)
            self.assertFalse((root/'audit.json').exists())  # Read-only audit default.
            write(records[:-1])
            with self.assertRaisesRegex(RuntimeError,'Missing'):audit_saved(root,contract,plan)
            corrupt=deepcopy(records);corrupt[1]['source_row']=999
            write(corrupt)
            with self.assertRaisesRegex(RuntimeError,'identity'):audit_saved(root,contract,plan)
            write(records);(root/'layer_specific/ids-absent.json').unlink()
            with self.assertRaises(FileNotFoundError):audit_saved(root,contract,plan)


if __name__=='__main__':unittest.main()
