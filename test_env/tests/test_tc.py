"""Opt-in real TC ownership regressions; existing qdiscs must survive refusal."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from test_env.commands import Recorder
from test_env.lab import CLIENT_NS, Lab, SERVER_IF, SERVER_NS
from test_env.tc import Probe


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get("NN_EBPF_RUN_LAB_TESTS") == "1",
                     "Requires explicit isolated-VM root opt-in")
class TCOwnershipTests(unittest.TestCase):
    def setUp(self):
        settings = {key: os.environ.get(key) for key in
                    ("NN_EBPF_TC_LOADER", "NN_EBPF_TC_OBJECT", "NN_EBPF_BPFTOOL")}
        if not all(settings.values()):
            self.skipTest("Explicit built probe loader/object/tool paths required")
        self.loader = Path(settings["NN_EBPF_TC_LOADER"]).resolve()
        self.obj = Path(settings["NN_EBPF_TC_OBJECT"]).resolve()
        self.bpftool = Path(settings["NN_EBPF_BPFTOOL"]).resolve()
        if not all(path.is_file() for path in (self.loader, self.obj, self.bpftool)):
            self.skipTest("Probe build products are unavailable")
        if any(os.path.lexists(Path("/run/netns") / name) for name in (CLIENT_NS, SERVER_NS)):
            self.skipTest("Existing lab namespaces must not be adopted")
        evidence = os.environ.get("NN_EBPF_LAB_EVIDENCE_ROOT")
        self.temporary = None
        if evidence is None:
            self.temporary = tempfile.TemporaryDirectory(prefix="nn-ebpf-tc-tests-")
            evidence = self.temporary.name
        self.recorder = Recorder(Path(evidence) / self._testMethodName)

    def tearDown(self):
        self.recorder.close()
        if self.temporary is not None:
            self.temporary.cleanup()

    def tc(self, *args):
        return ["ip", "netns", "exec", SERVER_NS, "tc", *args]

    def has_clsact(self):
        return any(item["kind"] == "clsact" for item in
                   self.recorder.json(self.tc("-j", "qdisc", "show", "dev", SERVER_IF)))

    def remove_fixture_clsact(self):
        if self.has_clsact():
            for direction in ("ingress", "egress"):
                filters = self.recorder.json(self.tc("-j", "filter", "show", "dev", SERVER_IF, direction))
                if filters:
                    raise RuntimeError("Foreign filters appeared on fixture qdisc; refusing removal")
            self.recorder.run(self.tc("qdisc", "del", "dev", SERVER_IF, "clsact"))

    def test_preexisting_clsact_is_preserved_when_loader_refuses(self):
        with Lab(self.recorder):
            self.recorder.run(self.tc("qdisc", "add", "dev", SERVER_IF, "clsact"))
            try:
                result = self.recorder.run([
                    "nsenter", "--net=/run/netns/" + SERVER_NS, "--", str(self.loader),
                    str(self.obj), SERVER_IF, "/run/netns/" + SERVER_NS], check=False)
                self.assertNotEqual(result.returncode, 0)
                events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
                stopped = [event for event in events if event.get("event") == "stopped"]
                self.assertEqual(len(stopped), 1)
                self.assertFalse(stopped[0]["qdisc_created"])
                self.assertTrue(self.has_clsact())
            finally:
                self.remove_fixture_clsact()

    def test_second_close_cannot_remove_a_new_foreign_clsact(self):
        with Lab(self.recorder) as lab:
            probe = Probe(self.recorder, lab, self.loader, self.obj, self.bpftool)
            try:
                probe.start()
            finally:
                first = probe.close()
            self.assertTrue(first["complete"])
            self.assertFalse(self.has_clsact())
            self.recorder.run(self.tc("qdisc", "add", "dev", SERVER_IF, "clsact"))
            try:
                second = probe.close()
                self.assertTrue(second["complete"])
                self.assertTrue(self.has_clsact())
            finally:
                self.remove_fixture_clsact()


if __name__ == "__main__":
    unittest.main()
