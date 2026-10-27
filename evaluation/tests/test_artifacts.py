import json
from pathlib import Path
import tempfile
import unittest

from evaluation.artifacts import new_directory, write_json


class ArtifactIsolationTests(unittest.TestCase):
    def test_existing_experiment_is_not_reused_or_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = new_directory(Path(temporary) / "run")
            write_json(root / "report.json", {"claim": "original"})
            with self.assertRaises(FileExistsError):
                new_directory(root)
            with self.assertRaises(FileExistsError):
                write_json(root / "report.json", {"claim": "replacement"})
            self.assertEqual(json.loads((root / "report.json").read_text()), {"claim": "original"})


if __name__ == "__main__":
    unittest.main()
