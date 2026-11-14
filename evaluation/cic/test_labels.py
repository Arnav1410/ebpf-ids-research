import csv
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

from evaluation.cic.labels import Labels, FIELDS, MEMBER, canonical, clock_minutes
from evaluation.cic.reconstruct import select


class Matching(unittest.TestCase):
    def labels(self, rows, header=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = Path(self.tmp.name) / "labels.zip"
        text = io.StringIO(newline="")
        writer = csv.writer(text)
        writer.writerow(header or FIELDS)
        writer.writerows(rows)
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(MEMBER, text.getvalue())
        return Labels(p)

    @staticmethod
    def row(**changes):
        value = {"Flow ID": "identity", "Source IP": "192.168.10.5", "Source Port": "49182",
                 "Destination IP": "192.168.10.3", "Destination Port": "88", "Protocol": "6",
                 "Timestamp": "4/7/2017 8:54", "Flow Duration": "640", "Total Fwd Packets": "7",
                 "Total Backward Packets": "4", "Total Length of Fwd Packets": "440",
                 "Total Length of Bwd Packets": "358", "Label": "BENIGN"}
        value.update(changes)
        return [value[field] for field in FIELDS]

    def test_exact_endpoint_minute_duration_and_counts_required(self):
        labels = self.labels([self.row()])
        r = labels.records[0]
        start = 1499169250131297000
        self.assertEqual(len(labels.at_start(canonical(r.source, r.destination), start, r.source, r.destination)), 1)
        self.assertEqual(labels.at_start(canonical(r.source, r.destination), start, r.destination, r.source), [])
        self.assertEqual(Labels.match([r], start, start + 640000, 7, 4, 440, 358), [r])
        for duration, nf, nb, pf, pb in ((641000, 7, 4, 440, 358), (640000, 6, 4, 440, 358),
                                         (640000, 7, 5, 440, 358), (640000, 7, 4, 441, 358)):
            self.assertEqual(Labels.match([r], start, start + duration, nf, nb, pf, pb), [])

    def test_duplicates_and_metadata_ambiguity_are_different(self):
        row = self.row()
        labels = self.labels([row, row])
        self.assertEqual(labels.summary["duplicate_records"], 1)
        self.assertEqual(labels.other_rows[0]["reason"], "DUPLICATE_SOURCE_RECORD")
        header = list(FIELDS) + ["Unselected Source Field"]
        labels = self.labels([row + ["a"], row + ["b"]], header)
        self.assertEqual(labels.summary["duplicate_records"], 0)
        matches = Labels.match(labels.records, 1000, 641000, 7, 4, 440, 358)
        self.assertEqual(len(matches), 2)  # Caller must reject; do not pick first.

    def test_duplicate_required_header_refused_unselected_header_allowed(self):
        labels = self.labels([self.row() + ["1", "1"]], list(FIELDS) + ["Fwd Header Length"] * 2)
        self.assertEqual(len(labels.records), 1)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.labels([self.row() + ["192.168.10.5"]], list(FIELDS) + ["Source IP"])

    def test_non_tcp_invalid_time_and_invalid_counter_are_exclusions(self):
        labels = self.labels([self.row(Protocol="17"), self.row(Timestamp="7/4/2017 8:54"),
                              self.row(**{"Total Fwd Packets": "-1"})])
        self.assertEqual(len(labels.records), 0)
        self.assertEqual([r["reason"] for r in labels.other_rows],
                         ["NON_TCP_LABEL", "INVALID_REQUIRED_LABEL_METADATA", "INVALID_REQUIRED_LABEL_METADATA"])

    def test_12_hour_candidates_and_minute_boundaries(self):
        a, b = clock_minutes("4/7/2017 1:00")
        self.assertEqual(b - a, 12 * 3600 * 10**9)
        labels = self.labels([self.row()])
        r = labels.records[0]
        m = r.minutes[0]
        self.assertTrue(r.start_matches(m, r.source, r.destination))
        self.assertTrue(r.start_matches(m + 60_000_000_000 - 1, r.source, r.destination))
        self.assertFalse(r.start_matches(m + 60_000_000_000, r.source, r.destination))

    def test_water_filling_uses_rank_not_predictions_and_never_pads(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE candidates(line INTEGER, category TEXT,label INTEGER,rank TEXT,data TEXT,eligible INTEGER)")
        for i, (category, label) in enumerate((("BENIGN", 0), ("BENIGN", 0), ("FTP-Patator", 1),
                                               ("FTP-Patator", 1), ("FTP-Patator", 1), ("SSH-Patator", 1))):
            connection.execute("INSERT INTO candidates VALUES(?,?,?,?,?,1)",
                               (i, category, label, str(i), json.dumps(dict(id=i, category=category))))
        values = select(connection, 3, 4)
        self.assertEqual([v["id"] for v in values], [0, 1, 2, 5, 3, 4])
        self.assertEqual(len({v["id"] for v in values}), 6)


if __name__ == "__main__":
    unittest.main()
