import tempfile
from pathlib import Path
import unittest
import numpy as np

from .dataset import features, integer, minute, positions, parse, InvalidRow
from .split import component_ids, allocate
from .metrics import classification, paired_bootstrap
from .evaluate import port_classifier
from .train import setup, network, weights_digest, reload_model


def values(**changes):
    n={'Total Fwd Packets':3,'Total Backward Packets':2,'Fwd Packet Length Max':100,'Fwd Packet Length Min':0,
       'Bwd Packet Length Max':1000,'Bwd Packet Length Min':10,'Fwd IAT Max':50,'Bwd IAT Max':70,
       'Fwd Header Length':60,'Bwd Header Length':40,'Destination Port':80,'Source Port':40000,'Flow Duration':100}
    n.update(changes);return n


class FeatureTests(unittest.TestCase):
    def test_exact_six_columns_and_units(self):
        a,b=features(values())
        self.assertEqual(a,[100,50,0,80,60,3]);self.assertEqual(b,[1000,70,0,80,100,5])

    def test_absent_backward_does_not_create_zero_minimum(self):
        n=values(**{'Total Backward Packets':0,'Fwd Packet Length Min':5,
                    'Bwd Packet Length Max':0,'Bwd Packet Length Min':0,'Bwd IAT Max':0,'Bwd Header Length':0})
        a,b=features(n);self.assertEqual(a,b);self.assertEqual(b[2],5)

    def test_measured_backward_zero_is_valid(self):
        n=values(**{'Fwd Packet Length Min':10,'Bwd Packet Length Min':0})
        self.assertEqual(features(n)[1][2],0)

    def test_unused_backward_statistics_do_not_contribute(self):
        n=values(**{'Total Backward Packets':0,'Bwd IAT Max':999,'Bwd Header Length':999})
        a,b=features(n);self.assertEqual(a,b)

    def test_zero_duration_one_packet_and_zero_payload_valid(self):
        n=values(**{'Total Fwd Packets':1,'Total Backward Packets':0,'Fwd Packet Length Max':0,
            'Fwd Packet Length Min':0,'Fwd IAT Max':0,'Fwd Header Length':20,'Flow Duration':0})
        self.assertEqual(features(n)[0],[0,0,0,80,20,1])

    def test_invalid_numeric_is_not_clipped(self):
        for s in ['NaN','Inf','-1','1.5',str(1<<63),'']:
            with self.subTest(s=s),self.assertRaises(InvalidRow):integer(s)
        self.assertEqual(integer(' 32.0 '),32)

    def test_invalid_physics_rejected(self):
        cases=[{'Total Fwd Packets':0},{'Fwd Header Length':59},{'Fwd Header Length':181},
            {'Fwd IAT Max':101},{'Fwd Packet Length Max':65536},{'Fwd Packet Length Min':101},
            {'Destination Port':65536},{'Total Backward Packets':1,'Bwd IAT Max':1}]
        for c in cases:
            with self.subTest(c=c),self.assertRaises(InvalidRow):features(values(**c))

    def test_aggregate_float64_bound_rejected(self):
        n=values(**{'Total Fwd Packets':1<<49,'Fwd Header Length':20*(1<<49)})
        with self.assertRaisesRegex(InvalidRow,'FLOAT64'):features(n)

    def test_named_duplicate_header_conflict(self):
        n=values();header=list(n)+['Fwd Header Length','Source IP','Destination IP','Flow ID','Timestamp','Label','Protocol']
        row=[str(n.get(k,{'Source IP':'192.0.2.1','Destination IP':'192.0.2.2','Flow ID':'opaque',
                        'Timestamp':'4/7/2017 10:01','Label':'BENIGN','Protocol':'6'}.get(k))) for k in header]
        p=positions(header);a,b,meta,_=parse(row,p)
        self.assertEqual(a,features(n)[0]);self.assertEqual(meta['minute'],'2017-07-04T10:01')
        row[p['Fwd Header Length'][-1]]='80'
        with self.assertRaisesRegex(InvalidRow,'DUPLICATE'):parse(row,p)

    def test_clock_is_group_token_and_invalid_date_rejected(self):
        self.assertEqual(minute('4/7/2017 3:01'),'2017-07-04T03:01')
        with self.assertRaises(InvalidRow):minute('4/7/2017 25:00')
        with self.assertRaises(InvalidRow):minute('5/7/2017 10:00')


class Splits(unittest.TestCase):
    def test_transitive_duplicate_union_across_both_representations(self):
        a=np.array([[1]*6,[1]*6,[2]*6,[3]*6]);b=np.array([[3]*6,[4]*6,[4]*6,[5]*6])
        meta=[dict(tuple_key=str(i),pair_key=str(i),minute='m') for i in range(4)]
        gid,groups=component_ids(a,b,meta,2)
        self.assertEqual(gid.tolist(),[0,0,0,3])

    def test_tuple_and_time_group_strength_is_explicit(self):
        a=np.array([[i]*6 for i in range(4)]);b=a+10
        meta=[dict(tuple_key=k,pair_key=p,minute=m) for k,p,m in [('t','p','m'),('t','q','n'),('u','p','m'),('v','r','m')]]
        strong,_=component_ids(a,b,meta,0);weak,_=component_ids(a,b,meta,1)
        self.assertEqual(strong.tolist(),[0,0,0,3]);self.assertEqual(weak.tolist(),[0,0,2,3])

    def test_split_reproducible_group_disjoint_and_supported(self):
        cats=np.tile(np.arange(3),100);groups=[list(range(i,i+3)) for i in range(0,300,3)]
        a,c=allocate(groups,cats,20261109);b,d=allocate(groups,cats,20261109)
        self.assertTrue(np.array_equal(a,b));self.assertTrue((c>0).all())
        self.assertTrue(np.allclose(c.sum(axis=1)/300,[.7,.15,.15],atol=.02))
        for g in groups:self.assertEqual(len(set(a[g])),1)


class Metrics(unittest.TestCase):
    def test_confusion_and_independent_metrics(self):
        m=classification([0,0,0,1,1,1],[0,0,1,0,1,1],[0.,1.,2.,1.,3.,4.])
        self.assertEqual(m['confusion_matrix'],[[2,1],[1,2]])
        self.assertAlmostEqual(m['f1'],2/3);self.assertAlmostEqual(m['mcc'],1/3)

    def test_missing_prediction_is_abstention(self):
        m=classification([0,1],[None,1])
        self.assertEqual(m['confusion_matrix'],[[0,0],[0,1]])
        self.assertEqual(m['missing_by_class'],{'0':1,'1':0});self.assertEqual(m['coverage'],.5)

    def test_tied_pr_scores_and_undefined_denominators(self):
        m=classification([0,1,1,0],[0,1,0,0],[0.,1.,1.,0.])
        self.assertEqual(m['average_precision'],1.)
        n=classification([0,0],[0,0]);self.assertIsNone(n['recall']);self.assertIsNone(n['precision'])

    def test_bootstrap_is_paired_by_group(self):
        y=np.array([0,1,0,1,0,1]);a=np.zeros(6,dtype=int);b=y.copy();g=np.array([0,0,1,1,2,2])
        ci=paired_bootstrap(y,a,b,g,100,7)
        self.assertEqual(ci['groups'],3);self.assertEqual(ci['f1_difference_95_percentile'],[1.,1.])

    def test_port_baseline_learns_only_training_labels(self):
        majority,p,rules=port_classifier(np.array([21,21,22,80]),np.array([1,1,0,0]),np.array([21,22,99]))
        self.assertEqual(majority,0);self.assertEqual(p.tolist(),[1,0,0])


class Model(unittest.TestCase):
    def test_authors_architecture_seed_and_numeric_reload(self):
        t=setup(20261109);net=network();h=weights_digest(net)
        self.assertEqual(sum(p.numel() for p in net.parameters()),1280)
        self.assertTrue(all('bias' not in k for k in net.state_dict()))
        setup(20261109);self.assertEqual(h,weights_digest(network()))
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'checkpoint.npz';np.savez_compressed(p,**{k:v.detach().numpy() for k,v in net.state_dict().items()})
            loaded=reload_model(p)
            x=t.tensor([[0.,1.,2.,3.,4.,5.]])
            with t.no_grad():self.assertTrue(t.equal(net(x),loaded(x)))


if __name__=='__main__':unittest.main()
