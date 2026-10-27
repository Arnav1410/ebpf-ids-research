"""Behavioral regressions for portable paired holdout checkpoints."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from evaluation.artifacts import read_json, write_json
from evaluation.model import model_identity
from evaluation.split import create_split
from evaluation.training import (evaluate_experiment, fit_preprocessing, float_model_identity,
                                 quantize_model, train_experiment, validate_float_model,
                                 validate_model_pair)

ML_AVAILABLE = (importlib.util.find_spec("numpy") is not None
                and importlib.util.find_spec("torch") is not None)


def floating_model():
    return {"schema_version": 1, "dimensions": [6, 32, 32, 2], "dtype": "float32", "bias": False,
            "layer_0_weight": [0.0] * 192, "layer_1_weight": [0.0] * 1024,
            "layer_2_weight": [0.0] * 64, "mean": [0.0] * 6, "scale": [1.0] * 6}


def synthetic_dataset():
    return SimpleNamespace(
        features=tuple((i * 10, i * i * 5, 7, 80, 40, 2) for i in range(20)),
        labels=tuple(i % 2 for i in range(20)),
        identity={"data_sha256": "a" * 64, "labels_sha256": "b" * 64})


class QuantizationTests(unittest.TestCase):
    def test_nearest_even_weights_and_integer_preprocessing(self):
        floating = floating_model()
        floating["layer_0_weight"][:6] = [value / 65536 for value in (0.5, 1.5, 2.5, -0.5, -1.5, -2.5)]
        floating["mean"] = [0.5, 1.5, 2.5, -0.5, -1.5, -2.5]
        floating["scale"] = [1.5, 2.5, 3.5, 4.5, 5.5, 6.5]
        quantized = quantize_model(floating)
        self.assertEqual(quantized["layer_0_weight"][:6], [0, 2, 2, 0, -2, -2])
        self.assertEqual(quantized["mean"], [0, 2, 2, 0, -2, -2])
        self.assertEqual(quantized["scale"], [2, 2, 4, 4, 6, 6])
        self.assertEqual(quantized["provenance"]["float_model_identity"], float_model_identity(floating))

    def test_signed_int32_weight_boundaries(self):
        floating = floating_model()
        floating["layer_0_weight"][:2] = [-32768.0, 32768.0 - 1 / 512]
        quantized = quantize_model(floating)
        self.assertEqual(quantized["layer_0_weight"][:2], [-(2 ** 31), 2 ** 31 - 128])
        for invalid in (32768.0, -32768.0 - 1 / 256):
            with self.subTest(weight=invalid):
                floating["layer_0_weight"][0] = invalid
                with self.assertRaisesRegex(ValueError, "int32"):
                    quantize_model(floating)

    def test_signed_int64_preprocessing_boundaries(self):
        floating = floating_model()
        floating["mean"][0] = float(-(2 ** 63))
        floating["mean"][1] = float(2 ** 63 - 1024)
        quantized = quantize_model(floating)
        self.assertEqual(quantized["mean"][:2], [-(2 ** 63), 2 ** 63 - 1024])
        for invalid in (float(2 ** 63), float(-(2 ** 63) - 2048)):
            floating["mean"][0] = invalid
            with self.assertRaisesRegex(ValueError, "int64"):
                quantize_model(floating)

    def test_zero_rounded_scale_is_rejected_not_repaired(self):
        for invalid in (0.1, 0.5):
            floating = floating_model()
            floating["scale"][0] = invalid
            with self.assertRaisesRegex(ValueError, "zero divisor"):
                quantize_model(floating)

    def test_nonfinite_and_out_of_range_values_are_rejected(self):
        for field in ("layer_0_weight", "mean", "scale"):
            for invalid in (float("nan"), float("inf"), -float("inf")):
                with self.subTest(field=field, value=invalid):
                    floating = floating_model()
                    floating[field][0] = invalid
                    with self.assertRaises(ValueError):
                        quantize_model(floating)
        floating = floating_model()
        floating["layer_0_weight"][0] = 1e100
        with self.assertRaises(ValueError):
            quantize_model(floating)

    def test_pair_requires_linkage_and_recomputed_parameters(self):
        floating = floating_model()
        quantized = quantize_model(floating)
        validate_model_pair(floating, quantized)
        tampered = copy.deepcopy(quantized)
        tampered["layer_2_weight"][0] = 1
        with self.assertRaisesRegex(ValueError, "do not quantize"):
            validate_model_pair(floating, tampered)
        other = copy.deepcopy(floating)
        other["layer_0_weight"][0] = 1 / 65536
        with self.assertRaisesRegex(ValueError, "not linked"):
            validate_model_pair(other, quantized)
        # Even a forged linkage cannot make unrelated integer weights acceptable.
        forged = copy.deepcopy(quantized)
        forged["provenance"]["float_model_identity"] = float_model_identity(other)
        with self.assertRaisesRegex(ValueError, "do not quantize"):
            validate_model_pair(other, forged)

    def test_parameter_shapes_are_validated(self):
        floating = floating_model()
        floating["layer_1_weight"].pop()
        with self.assertRaisesRegex(ValueError, "1024"):
            validate_float_model(floating)
        floating = floating_model()
        quantized = quantize_model(floating)
        quantized["layer_2_weight"].pop()
        with self.assertRaisesRegex(ValueError, "64"):
            validate_model_pair(floating, quantized)


@unittest.skipUnless(ML_AVAILABLE, "optional NumPy/PyTorch environment is unavailable")
class TrainingTests(unittest.TestCase):
    def test_scaler_uses_training_rows_and_constant_scale_one(self):
        dataset = SimpleNamespace(features=((0, 5, 9, 0, 8, 1), (4, 5, 13, 8, 8, 1),
                                            (1000000, -9000, 7000, 40000, 99, 200)))
        mean, scale = fit_preprocessing(dataset, (0, 1))
        self.assertEqual(mean, [2.0, 5.0, 11.0, 4.0, 8.0, 1.0])
        self.assertEqual(scale, [2.0, 1.0, 2.0, 4.0, 1.0, 1.0])
        # Changing only held-out values cannot affect fitted preprocessing.
        dataset.features = dataset.features[:2] + ((-999999, 1, 2, 3, 4, 5),)
        self.assertEqual((mean, scale), fit_preprocessing(dataset, (0, 1)))

    def test_training_repeatability_and_frozen_heldout_reevaluation(self):
        dataset = synthetic_dataset()
        split = create_split(dataset, seed=2026, test_fraction=0.2)
        split["test_indices"] = list(reversed(split["test_indices"]))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second, replay = (root / name for name in ("first", "second", "replay"))
            for directory in (first, second, replay):
                directory.mkdir()
            trained = train_experiment(dataset, split, first, seed=17, epochs=2, batch_size=4)
            repeated = train_experiment(dataset, split, second, seed=17, epochs=2, batch_size=4)
            evaluated = evaluate_experiment(dataset, first, replay)
            self.assertEqual(read_json(first / "float-model.json"), read_json(second / "float-model.json"))
            self.assertEqual(read_json(first / "quantized-model.json"), read_json(second / "quantized-model.json"))
            self.assertEqual(read_json(first / "training.json")["history"],
                             read_json(second / "training.json")["history"])
            for key in ("float_metrics", "integer_metrics", "disagreement", "ties"):
                self.assertEqual(trained[key], repeated[key])
                self.assertEqual(trained[key], evaluated[key])
            self.assertEqual((first / "predictions.jsonl").read_bytes(), (replay / "predictions.jsonl").read_bytes())
            self.assertEqual((first / "traces.jsonl").read_bytes(), (replay / "traces.jsonl").read_bytes())
            with (first / "predictions.jsonl").open() as stream:
                predictions = [json.loads(line) for line in stream]
            self.assertEqual([row["index"] for row in predictions], split["test_indices"])
            self.assertTrue(set(row["index"] for row in predictions).isdisjoint(split["train_indices"]))
            self.assertEqual([row["label"] for row in predictions],
                             [dataset.labels[index] for index in split["test_indices"]])
            self.assertEqual(read_json(replay / "split.json"), split)
            floating = read_json(first / "float-model.json")
            expected_mean, expected_scale = fit_preprocessing(dataset, split["train_indices"])
            self.assertEqual(floating["mean"], expected_mean)
            self.assertEqual(floating["scale"], expected_scale)
            self.assertEqual(trained["quantized_model_identity"],
                             model_identity(read_json(first / "quantized-model.json")))

    def test_reevaluation_rejects_manifest_and_dataset_tampering(self):
        dataset = synthetic_dataset()
        split = create_split(dataset, seed=2026, test_fraction=0.2)
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / "source", Path(temporary) / "output"
            source.mkdir()
            output.mkdir()
            train_experiment(dataset, split, source, epochs=1, batch_size=4)
            altered_dataset = copy.deepcopy(dataset)
            altered_dataset.identity["data_sha256"] = "c" * 64
            with self.assertRaises(ValueError):
                evaluate_experiment(altered_dataset, source, output)
            manifest = read_json(source / "training.json")
            manifest["float_model_identity"] = "d" * 64
            # Deliberate corruption of a fixture, not an experiment overwrite API.
            (source / "training.json").unlink()
            write_json(source / "training.json", manifest)
            with self.assertRaisesRegex(ValueError, "mismatched float_model_identity"):
                evaluate_experiment(dataset, source, output)
            self.assertFalse((output / "predictions.jsonl").exists())

    def test_tie_rules_preserved_in_real_scoring(self):
        dataset = synthetic_dataset()
        split = create_split(dataset, seed=2026, test_fraction=0.2)
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / "source", Path(temporary) / "output"
            source.mkdir()
            output.mkdir()
            train_experiment(dataset, split, source, epochs=1, batch_size=4)
            floating = read_json(source / "float-model.json")
            floating["layer_2_weight"] = [0.0] * 64
            quantized = quantize_model(floating)
            manifest = read_json(source / "training.json")
            replacements = {"float-model.json": floating, "quantized-model.json": quantized}
            for name, value in replacements.items():
                (source / name).unlink()
                write_json(source / name, value)
            from evaluation.artifacts import sha256
            from evaluation.model import header_text
            (source / "mlp_params.bpf.h").write_text(header_text(quantized), encoding="utf-8")
            manifest["float_model_identity"] = float_model_identity(floating)
            manifest["quantized_model_identity"] = model_identity(quantized)
            manifest["artifact_sha256"] = {name: sha256(source / name) for name in manifest["artifact_sha256"]}
            (source / "training.json").unlink()
            write_json(source / "training.json", manifest)
            report = evaluate_experiment(dataset, source, output)
            self.assertEqual(report["disagreement"]["count"], len(split["test_indices"]))
            self.assertEqual(report["ties"], {"float": len(split["test_indices"]),
                                              "integer": len(split["test_indices"])})
            with (output / "predictions.jsonl").open() as stream:
                for line in stream:
                    row = json.loads(line)
                    self.assertEqual((row["float_prediction"], row["integer_prediction"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
