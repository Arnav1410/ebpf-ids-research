import struct
import tempfile
from pathlib import Path
import unittest

from evaluation.dataset import audit_dataset, load_dataset, read_npy


def npy(path, shape, dtype, values=b"", fortran=False):
    header = repr({"descr": dtype, "fortran_order": fortran, "shape": shape}).encode()
    header += b" " * ((-10 - len(header) - 1) % 64) + b"\n"
    path.write_bytes(b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + values)


class NumericDatasetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_endian_conversion_and_numeric_labels(self):
        data, labels = self.root / "data.npy", self.root / "labels.npy"
        npy(data, (2, 6), ">i8", struct.pack(">12q", *range(12)))
        npy(labels, (2,), "<f8", struct.pack("<2d", 0, 1))
        loaded = load_dataset(data, labels)
        self.assertEqual(loaded.features, (tuple(range(6)), tuple(range(6, 12))))
        self.assertEqual(loaded.labels, (0, 1))
        self.assertEqual(audit_dataset(loaded)["label_mapping"], {"0": "unverified", "1": "unverified"})

    def test_object_payload_is_rejected_without_deserialization(self):
        path = self.root / "object.npy"
        npy(path, (1,), "|O", b"not-a-pickle")
        with self.assertRaisesRegex(ValueError, "pickle"):
            read_npy(path)

    def test_truncation_and_trailing_payload_are_not_ignored(self):
        for payload in (b"", struct.pack("<2q", 1, 2)):
            with self.subTest(payload=payload):
                path = self.root / "wrong.npy"
                npy(path, (1,), "<i8", payload)
                with self.assertRaisesRegex(ValueError, "payload length"):
                    read_npy(path)

    def test_nonfinite_and_fractional_features_are_rejected(self):
        data, labels = self.root / "data.npy", self.root / "labels.npy"
        npy(labels, (1,), "<i8", struct.pack("<q", 0))
        for value in (float("nan"), float("inf"), 1.5):
            with self.subTest(value=value):
                npy(data, (1, 6), "<f8", struct.pack("<6d", value, 1, 2, 3, 4, 5))
                with self.assertRaises(ValueError):
                    load_dataset(data, labels)

    def test_label_shape_and_nonbinary_values_are_rejected(self):
        data, labels = self.root / "data.npy", self.root / "labels.npy"
        npy(data, (1, 6), "<i8", struct.pack("<6q", *range(6)))
        for shape, values in (((2,), [0, 1]), ((1,), [2])):
            npy(labels, shape, "<i8", struct.pack("<" + "q" * len(values), *values))
            with self.assertRaises(ValueError):
                load_dataset(data, labels)

    def test_audit_distinguishes_duplicate_groups_and_conflicting_labels(self):
        data, labels = self.root / "data.npy", self.root / "labels.npy"
        npy(data, (3, 6), "<i8", struct.pack("<18q", *(list(range(6)) * 2 + list(range(6, 12)))))
        npy(labels, (3,), "<i8", struct.pack("<3q", 0, 1, 1))
        groups = audit_dataset(load_dataset(data, labels))["feature_groups"]
        self.assertEqual(groups, {"unique": 2, "repeated_groups": 1,
                                  "rows_beyond_first": 1, "conflicting_label_groups": 1})


if __name__ == "__main__":
    unittest.main()
