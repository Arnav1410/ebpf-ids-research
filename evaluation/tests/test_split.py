"""Behavior regressions for frozen, dataset-bound feature-group holdouts."""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
import unittest

from evaluation.dataset import load_dataset
from evaluation.split import create_split, validate_split


def dataset_from_groups(specifications):
    """Each specification lists the labels sharing one exact feature vector."""
    features, labels = [], []
    for group, group_labels in enumerate(specifications):
        for label in group_labels:
            features.append((group, group + 1, group + 2, 80, 20, 1))
            labels.append(label)
    return SimpleNamespace(
        features=tuple(features), labels=tuple(labels),
        identity={
            "data_sha256": hashlib.sha256(json.dumps(features).encode()).hexdigest(),
            "labels_sha256": hashlib.sha256(json.dumps(labels).encode()).hexdigest(),
        },
    )


class FrozenSplitTests(unittest.TestCase):
    def setUp(self):
        self.dataset = dataset_from_groups([[label] * 5 for label in (0, 1) for _ in range(30)])
        self.split = create_split(self.dataset, seed=2026, test_fraction=0.2)

    def assert_grouped_coverage(self, dataset, split):
        train, test = validate_split(dataset, split)
        self.assertEqual(set(train) | set(test), set(range(len(dataset.features))))
        self.assertFalse(set(train) & set(test))
        self.assertEqual(len(train) + len(test), len(dataset.features))
        train_features = {dataset.features[index] for index in train}
        test_features = {dataset.features[index] for index in test}
        self.assertFalse(train_features & test_features)
        for indices in (train, test):
            self.assertEqual({dataset.labels[index] for index in indices}, {0, 1})

    def test_repeatability_balance_and_duplicate_retention(self):
        self.assertEqual(self.split, create_split(self.dataset, seed=2026, test_fraction=0.2))
        self.assertNotEqual(self.split["test_indices"], create_split(self.dataset, seed=2027, test_fraction=0.2)["test_indices"])
        self.assert_grouped_coverage(self.dataset, self.split)
        self.assertEqual(self.split["class_counts"], {
            "all": {"0": 150, "1": 150},
            "train": {"0": 120, "1": 120}, "test": {"0": 30, "1": 30},
        })
        self.assertEqual(self.split["row_counts"], {"all": 300, "train": 240, "test": 60})
        self.assertEqual(self.split["actual_test_fraction"], 0.2)
        self.assertEqual(self.split["group_counts"]["all"], 60)
        self.assertEqual(self.split["group_counts"]["test"], 12)
        self.assertEqual(self.split["class_test_fractions"], {"0": 0.2, "1": 0.2})

    def test_included_dataset_has_reproducible_approximately_eighty_twenty_holdout(self):
        dataset = load_dataset()
        split = create_split(dataset, seed=2026, test_fraction=0.2)
        self.assertEqual(split, create_split(dataset, seed=2026, test_fraction=0.2))
        self.assert_grouped_coverage(dataset, split)
        self.assertLess(abs(split["actual_test_fraction"] - 0.2), 0.025)
        for fraction in split["class_test_fractions"].values():
            self.assertLess(abs(fraction - 0.2), 0.025)
        self.assertEqual(split["dataset_identity"], dataset.identity)

    def test_conflicting_label_groups_remain_intact_and_are_reported(self):
        dataset = dataset_from_groups([[0, 0, 1], [0, 1, 1], [0] * 3, [1] * 3])
        split = create_split(dataset, test_fraction=0.4)
        self.assert_grouped_coverage(dataset, split)
        counts = split["group_counts"]["conflicting_label_groups"]
        self.assertEqual(counts["all"], 2)
        self.assertEqual(counts["train"] + counts["test"], 2)

    def test_two_mixed_groups_are_sufficient_even_without_pure_groups(self):
        dataset = dataset_from_groups([[0, 1], [0, 1]])
        split = create_split(dataset, test_fraction=0.2)
        self.assert_grouped_coverage(dataset, split)
        self.assertEqual(split["actual_test_fraction"], 0.5)
        self.assertEqual(split["requested_test_fraction"], 0.2)

    def test_large_indivisible_groups_report_actual_not_requested_fraction(self):
        dataset = dataset_from_groups([[0] * 99, [0], [1] * 99, [1]])
        split = create_split(dataset, test_fraction=0.2)
        self.assert_grouped_coverage(dataset, split)
        self.assertEqual(split["actual_test_fraction"], 0.01)
        self.assertEqual(split["requested_test_fraction"], 0.2)

    def test_saved_json_roundtrip_preserves_indices_and_order(self):
        split = json.loads(json.dumps(self.split))
        split["train_indices"].reverse()
        split["test_indices"].reverse()
        train, test = validate_split(self.dataset, split)
        self.assertEqual(train, tuple(split["train_indices"]))
        self.assertEqual(test, tuple(split["test_indices"]))

    def test_wrong_dataset_hashes_are_rejected(self):
        for key in ("data_sha256", "labels_sha256"):
            with self.subTest(key=key):
                wrong = deepcopy(self.dataset)
                wrong.identity[key] = "0" * 64
                with self.assertRaisesRegex(ValueError, "identity"):
                    validate_split(wrong, self.split)

    def test_tampered_index_types_ranges_and_duplicates_are_rejected(self):
        for name in ("train_indices", "test_indices"):
            for bad in (True, False, 1.0, "1", None, -1, len(self.dataset.features)):
                with self.subTest(partition=name, bad=bad):
                    split = deepcopy(self.split)
                    split[name][0] = bad
                    with self.assertRaisesRegex(ValueError, "non-integer or out-of-range"):
                        validate_split(self.dataset, split)
            with self.subTest(partition=name, bad="duplicate"):
                split = deepcopy(self.split)
                split[name].append(split[name][0])
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    validate_split(self.dataset, split)

    def test_overlapping_missing_and_empty_partitions_are_rejected(self):
        split = deepcopy(self.split)
        split["test_indices"][0] = split["train_indices"][0]
        with self.assertRaisesRegex(ValueError, "disjoint"):
            validate_split(self.dataset, split)
        split = deepcopy(self.split)
        split["test_indices"].pop()
        with self.assertRaisesRegex(ValueError, "cover every"):
            validate_split(self.dataset, split)
        split = deepcopy(self.split)
        split["test_indices"] = []
        with self.assertRaisesRegex(ValueError, "nonempty"):
            validate_split(self.dataset, split)

    def test_complete_same_class_swap_cannot_hide_group_leakage(self):
        split = deepcopy(self.split)
        train_position = next(i for i, row in enumerate(split["train_indices"]) if self.dataset.labels[row] == 0)
        test_position = next(i for i, row in enumerate(split["test_indices"]) if self.dataset.labels[row] == 0)
        train_row = split["train_indices"][train_position]
        test_row = split["test_indices"][test_position]
        split["train_indices"][train_position] = test_row
        split["test_indices"][test_position] = train_row
        with self.assertRaisesRegex(ValueError, "group leaks"):
            validate_split(self.dataset, split)

    def test_single_class_partition_is_rejected_even_with_full_group_coverage(self):
        split = deepcopy(self.split)
        split["train_indices"] = [i for i, label in enumerate(self.dataset.labels) if label == 0]
        split["test_indices"] = [i for i, label in enumerate(self.dataset.labels) if label == 1]
        with self.assertRaisesRegex(ValueError, "must contain both"):
            validate_split(self.dataset, split)

    def test_corrupted_counts_fractions_policy_and_schema_are_rejected(self):
        mutations = {
            "class_counts": {"all": {"0": 150, "1": 150}},
            "group_counts": {},
            "row_counts": {"all": 300, "train": 240, "test": 61},
            "actual_test_fraction": 0.3,
            "actual_train_fraction": 0.7,
            "class_test_fractions": {"0": 0.2, "1": 0.3},
            "policy": {"name": "random_rows_without_groups"},
            "schema_version": True,
            "claim": "paper_reproduction",
            "requested_test_fraction": float("nan"),
            "seed": True,
        }
        for key, value in mutations.items():
            with self.subTest(field=key):
                split = deepcopy(self.split)
                split[key] = value
                with self.assertRaises(ValueError):
                    validate_split(self.dataset, split)
        split = deepcopy(self.split)
        split["class_counts"]["test"]["0"] = 30.0
        with self.assertRaisesRegex(ValueError, "class_counts"):
            validate_split(self.dataset, split)

    def test_class_edge_errors_are_explicit(self):
        fixtures = (
            ([], "nonempty"),
            ([[0], [0]], "Both numeric classes"),
            ([[1], [1]], "Both numeric classes"),
            ([[0, 0], [1], [1]], "Class 0 needs at least two"),
            ([[0], [0], [1, 1]], "Class 1 needs at least two"),
            ([[0, 1]], "Class 0 needs at least two"),
            ([[0, 1], [1]], "Class 0 needs at least two"),
        )
        for specifications, message in fixtures:
            with self.subTest(groups=specifications):
                with self.assertRaisesRegex(ValueError, message):
                    create_split(dataset_from_groups(specifications))

    def test_invalid_requested_parameters_are_rejected(self):
        for fraction in (0, 1, -0.1, 1.1, 10 ** 1000, float("nan"), float("inf"), True, "0.2", None):
            with self.subTest(fraction=fraction):
                with self.assertRaisesRegex(ValueError, "fraction"):
                    create_split(self.dataset, test_fraction=fraction)
        for seed in (True, 2026.0, "2026", None):
            with self.subTest(seed=seed):
                with self.assertRaisesRegex(ValueError, "seed"):
                    create_split(self.dataset, seed=seed)


if __name__ == "__main__":
    unittest.main()
