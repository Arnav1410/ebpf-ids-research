import unittest
from evaluation.metrics import binary_metrics


class Metrics(unittest.TestCase):
    def test_manual_confusion_matrix_and_missing(self):
        r=binary_metrics([1,0,0,1,1,None],[1,1,0,0,None,1])
        self.assertEqual((r['TP'],r['FP'],r['TN'],r['FN']),(1,1,1,1))
        self.assertEqual((r['accuracy'],r['precision'],r['recall'],r['f1']),(.5,.5,.5,.5))
        self.assertEqual(r['classification_coverage'],.8);self.assertEqual(r['missing_invalid_predictions'],1)

    def test_benign_only_has_no_intrusion_f1(self):
        r=binary_metrics([0,0,0],[1,0,None]);self.assertEqual(r['benign_false_positive_rate'],.5)
        self.assertIsNone(r['f1']);self.assertIsNone(r['recall']);self.assertEqual(r['classification_coverage'],2/3)

    def test_no_labels_or_predictions_not_fabricated(self):
        self.assertIsNone(binary_metrics([None],[1])['accuracy'])
        self.assertIsNone(binary_metrics([1],[None])['f1'])


if __name__=='__main__':unittest.main()
