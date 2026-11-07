"""Host tests of benchmark accounting/statistics; never BPF execution."""
from copy import deepcopy
import unittest
from quantization.benchmark import percentile,timing_summary,paired_ratios,verify_block,reference_for


class Statistics(unittest.TestCase):
    def test_percentiles_and_outlier_retention(self):
        values=[10,20,30,40,10000]
        s=timing_summary(values)
        self.assertEqual(s['median_ns'],30);self.assertEqual(s['maximum_ns'],10000)
        self.assertEqual(percentile([10,20],.5),15)

    def test_bad_timers_fail_instead_of_being_filtered(self):
        for values in ([],[0,10],[1,0xffffffff],[True],[-1],[1.5]):
            with self.assertRaises(ValueError):timing_summary(values)

    def test_paired_ratio_and_seeded_bootstrap(self):
        result=paired_ratios([(100,200)]*12)
        self.assertEqual(result['median_experimental_over_static'],2)
        self.assertEqual(result['bootstrap_95_percentile'],[2,2])
        self.assertEqual(result,paired_ratios([(100,200)]*12))
        self.assertEqual(paired_ratios([(200,100)]*12)['observation'],'faster_in_this_microbenchmark')

    def test_inconclusive_pairing(self):
        self.assertEqual(paired_ratios([(100,80),(100,120)]*6)['observation'],'inconclusive')

    def test_invalid_pairs_are_rejected(self):
        for pairs in ([],[(1,2)],[(0,1),(1,2)],[(1,-2),(1,2)]):
            with self.assertRaises(ValueError):paired_ratios(pairs)


class Accounting(unittest.TestCase):
    def block(self,mode):
        raw=list(reference_for(mode).mean)
        return raw,dict(mode=mode,kind='mlp',cpu=0,kernel_repeat=1,warmup=1,samples=2,
            prediction_delta=3,stage_deltas=[3]*6,duration_ns=[100,200],
            record=dict(features=raw,mask=63,sequence=1,model_slot=0,cpu=0,
                        tensors=[[0]*n for n in (6,32,32,32,32,2)],label=1))

    def test_each_mode_has_its_own_reference_and_zero_tie(self):
        for mode in ('static_q16','layer_specific'):
            raw,block=self.block(mode);verify_block(block,mode,'mlp',raw,1,2,0)

    def test_skipped_tail_stages_and_repeat_trap_are_rejected(self):
        raw,base=self.block('static_q16')
        for field,value in (('kernel_repeat',2),('prediction_delta',1),('stage_deltas',[1]*6)):
            b=deepcopy(base);b[field]=value
            with self.assertRaises(RuntimeError):verify_block(b,'static_q16','mlp',raw,1,2,0)

    def test_wrong_tensor_cpu_or_mode_is_rejected(self):
        raw,base=self.block('layer_specific')
        for case in ('tensor','cpu','mode'):
            b=deepcopy(base)
            if case=='tensor':b['record']['tensors'][-1][0]=1
            if case=='cpu':b['cpu']=1
            if case=='mode':b['mode']='static_q16'
            with self.assertRaises(RuntimeError):verify_block(b,'layer_specific','mlp',raw,1,2,0)


if __name__=='__main__':unittest.main()
