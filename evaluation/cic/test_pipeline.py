"""Synthetic end-to-end gates and independent packet-offset checks; no kernel."""
import argparse
import csv
import io
import json
import mmap
from pathlib import Path
import tempfile
import unittest
import zipfile

from evaluation.cic.capture import Reader
from evaluation.cic.labels import FIELDS, MEMBER, Labels, clock_minutes
from evaluation.cic.reconstruct import reconstruct, fingerprint
from evaluation.cic.validate_cohort import read_at
from evaluation.cic.freeze import freeze
from evaluation.cic.test_capture import section, interface, enhanced
from validation.reference import tcp_packet


class Pipeline(unittest.TestCase):
    def test_readonly_mapped_offsets_match_stream_reader(self):
        raw = section() + interface() + enhanced(tcp_packet(), 123) + enhanced(tcp_packet(flags=0x11), 456)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture"
            path.write_bytes(raw)
            reader = Reader(path)
            packets = list(reader)
            with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                for packet in packets:
                    self.assertEqual(read_at(mapped, packet.index, packet.offset, reader.metadata["interfaces"][0], "<"), packet)
                with self.assertRaisesRegex(ValueError, "enhanced-packet"):
                    read_at(mapped, 1, 0, reader.metadata["interfaces"][0], "<")
            self.assertEqual(path.read_bytes(), raw)

    def test_source_join_exclusions_and_final_gate_before_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            start_ns = clock_minutes("4/7/2017 8:54")[0] + 10_000_000
            raw = section() + interface()
            text = io.StringIO(newline="")
            writer = csv.writer(text)
            writer.writerow(FIELDS)
            for port, category, terminate, correct_duration in ((12001, "BENIGN", True, True),
                    (12002, "FTP-Patator", True, True), (12003, "SSH-Patator", False, True),
                    (12004, "BENIGN", True, False)):
                row = ["synthetic-" + str(port), "33.33.33.73", str(port), "33.33.33.1", "5001", "6",
                       "4/7/2017 8:54", "1" if correct_duration else "2", "2", "0", "2", "0", category]
                writer.writerow(row)
                if port == 12001:
                    writer.writerow(row)  # Exact source duplicate is not a new flow.
                raw += enhanced(tcp_packet(sport=port, flags=2), start_ns // 1000)
                if terminate:
                    raw += enhanced(tcp_packet(sport=port, flags=0x11, payload=b"ok"), start_ns // 1000 + 1)
                start_ns += 1_000_000
            capture = root / "capture.pcapng"
            capture.write_bytes(raw)
            labels = root / "labels.zip"
            with zipfile.ZipFile(labels, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(MEMBER, text.getvalue())
            reader = Reader(capture)
            list(reader)
            binding = root / "binding.json"
            binding.write_text(json.dumps(dict(labels_zip=dict(sha256=fingerprint(labels)),
                labels_member=dict(sha256=Labels(labels).summary["member_sha256"]),
                pcap=dict(sha256=fingerprint(capture), md5=reader.md5.hexdigest()))))
            index = root / "reconstructed"
            reconstruct(argparse.Namespace(binding=binding, labels=labels, output=index, capture=capture))
            result = json.loads((index / "reconstruction.json").read_text())
            self.assertEqual(result["eligible"], 2)
            self.assertEqual(result["eligible_categories"], {"BENIGN": 1, "FTP-Patator": 1})
            self.assertEqual(result["exclusions"], {"DUPLICATE_SOURCE_RECORD": 1,
                "NO_ELIGIBLE_INCOMING_FIN_RST": 1, "LABEL_WINDOW_DURATION_OR_COUNTER_MISMATCH": 1})
            rows = [json.loads(line) for line in (index / "pilot.jsonl").read_text().splitlines()]
            self.assertEqual([r["features"] for r in rows], [[22, 1000, 20, 5001, 40, 2]] * 2)
            self.assertEqual(capture.read_bytes(), raw)
            previous = root / "previous.json"
            previous.write_text(json.dumps(dict(status="FAIL", source_binding_sha256=fingerprint(binding), records=2)))
            args = argparse.Namespace(index=index, previous=previous, stage="final", output=root / "final")
            with self.assertRaisesRegex(ValueError, "gate did not pass"):
                freeze(args)
            previous.write_text(json.dumps(dict(status="PASS", source_binding_sha256=fingerprint(binding), records=1)))
            with self.assertRaisesRegex(ValueError, "Moderate validation"):
                freeze(args)
            previous.write_text(json.dumps(dict(status="PASS", source_binding_sha256=fingerprint(binding), records=2)))
            freeze(args)
            self.assertEqual(json.loads((args.output / "manifest.json").read_text())["input_count"], 2)


if __name__ == "__main__":
    unittest.main()
