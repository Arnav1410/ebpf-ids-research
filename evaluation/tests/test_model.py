import copy
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from evaluation.artifacts import DEFAULT_MODEL, ROOT
from evaluation.metrics import classification_metrics
from evaluation.model import FIELDS, STAGES, infer, linear, load_model, normalize, pack_model
from evaluation.reference import RECORD


class IntegerSemanticsTests(unittest.TestCase):
    def test_negative_normalization_truncates_towards_zero_before_sign(self):
        self.assertEqual(normalize([-1, 1], [0, 0], [3, 3]), [-21845, 21845])

    def test_normalization_wraps_product_and_signed_narrowing(self):
        self.assertEqual(normalize([-(1 << 63)], [0], [1]), [0])
        self.assertEqual(normalize([-32768], [0], [1]), [-(1 << 31)])
        self.assertEqual(normalize([-(1 << 63)], [(1 << 63) - 1], [1]), [65536])

    def test_accumulation_shift_and_output_cast_at_overflow_boundary(self):
        maximum = (1 << 31) - 1
        self.assertEqual(linear([maximum] * 3, [maximum] * 3, 1), [-196608])

    def test_kernel_tie_selects_class_one(self):
        model = {"fixed_point": 16, "dimensions": [6, 32, 32, 2],
                 **{name: [1 if name == "scale" else 0] * count for name, count, _ in FIELDS}}
        result = infer(model, [0] * 6)
        self.assertEqual(result["output"], [0, 0])
        self.assertEqual(result["label"], 1)

    def test_confusion_counts_and_undefined_metrics(self):
        report = classification_metrics([0, 0, 1, 1], [0, 1, 1, 1])
        self.assertEqual(report["confusion_matrix"]["counts"], [[1, 1], [0, 2]])
        self.assertEqual(report["accuracy"], 0.75)
        self.assertAlmostEqual(report["per_class"]["1"]["precision"], 2 / 3)
        self.assertAlmostEqual(report["per_class"]["1"]["f1"], 0.8)
        undefined = classification_metrics([0, 0], [0, 0])["per_class"]["1"]
        self.assertIsNone(undefined["precision"])
        self.assertIsNone(undefined["recall"])
        self.assertIsNone(undefined["f1"])
        with self.assertRaises(ValueError):
            classification_metrics([0], [])


@unittest.skipUnless(shutil.which("cc") and (ROOT / "src/.output/vmlinux.h").exists(),
                     "Native-header conformance requires cc and the generated baseline kernel header")
class ActualHeaderConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.binary = cls.root / "reference"
        subprocess.run(["cc", "-O2", "-fwrapv", "-I" + str(ROOT / "src/.output"),
                        str(ROOT / "evaluation/native_reference.c"), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def compare(self, model, vectors):
        (self.root / "model.bin").write_bytes(pack_model(model))
        (self.root / "vectors.bin").write_bytes(b"".join(struct.pack("=6q", *vector) for vector in vectors))
        output = subprocess.run([str(self.binary), str(self.root / "model.bin"), str(self.root / "vectors.bin")],
                                capture_output=True, check=True).stdout
        self.assertEqual(len(output), len(vectors) * RECORD.size)
        for index, vector in enumerate(vectors):
            values = RECORD.unpack_from(output, index * RECORD.size)
            expected, offset = infer(model, vector), 0
            for stage, count in STAGES:
                with self.subTest(vector=index, stage=stage):
                    self.assertEqual(list(values[offset:offset + count]), expected[stage])
                offset += count
            self.assertEqual(values[-1], expected["label"])

    def test_baseline_header_arithmetic_on_realistic_and_extreme_features(self):
        model = load_model(DEFAULT_MODEL)
        self.compare(model, [(572, 11161066668, 36, 496, 12145, 379), (0,) * 6,
                             ((1 << 63) - 1,) * 6, (-(1 << 63),) * 6])

    def test_large_weights_signed_wrap_and_negative_divisor_match_actual_c(self):
        model = copy.deepcopy(load_model(DEFAULT_MODEL))
        for name, count, width in FIELDS[:3]:
            model[name] = [-(1 << 31) if index % 3 else (1 << 31) - 1 for index in range(count)]
        model["mean"] = [-(1 << 63), (1 << 63) - 1, 0, 0, 1, -1]
        model["scale"] = [1, 1, -1, 3, 7, 65536]
        self.compare(model, [(0,) * 6, ((1 << 63) - 1,) * 6, (-(1 << 63),) * 6])


if __name__ == "__main__":
    unittest.main()
