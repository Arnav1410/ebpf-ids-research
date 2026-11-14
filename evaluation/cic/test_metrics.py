import unittest
from evaluation.cic.metrics import metrics


class Metrics(unittest.TestCase):
    def test_all_cells_missing_and_independent_sklearn(self):
        result = metrics([1, 0, 0, 1, 0], [1, 1, 0, 0, None])
        self.assertEqual(result["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(result["classification_coverage"], .8)
        for name in ("accuracy", "precision", "recall", "f1", "specificity", "false_positive_rate", "balanced_accuracy"):
            self.assertEqual(result[name], .5)
        self.assertEqual(result["mcc"], 0)
        self.assertEqual(result["sklearn_crosscheck"]["status"], "PASS")

    def test_degenerate_mcc_and_all_abstentions(self):
        result = metrics([0, 1], [1, 1])
        self.assertIsNone(result["mcc"])
        self.assertTrue(result["mcc_zero_denominator"])
        self.assertEqual(result["sklearn_crosscheck"]["values"]["mcc"], 0)
        self.assertEqual(result["false_positive_rate"], 1)
        result = metrics([0, 1], [None, None])
        self.assertEqual(result["classification_coverage"], 0)
        self.assertIsNone(result["accuracy"])
        self.assertEqual(result["missing_predictions"], 2)

    def test_invalid_codes_not_benign(self):
        for y, p in (([0], [2]), ([None], [0]), ([0], [])):
            with self.assertRaises(ValueError):
                metrics(y, p)

    def test_saved_json_keys_do_not_change_counts(self):
        from evaluation.cic.audit_results import json_value
        value = metrics([0, 0, 1], [0, None, 1])
        normalized = json_value(value)
        self.assertEqual(normalized["class_support"], {"0": 2, "1": 1})
        self.assertEqual(normalized["missing_by_class"], {"0": 1})
        self.assertEqual(normalized["confusion_matrix"], [[1, 0], [0, 1]])


if __name__ == "__main__":
    unittest.main()
