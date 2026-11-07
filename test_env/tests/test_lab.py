"""Real namespace tests, opt-in only; never adopt existing lab resources."""
import os
from pathlib import Path
import tempfile
import unittest

from test_env.commands import Recorder
from test_env.lab import CLIENT_IF, CLIENT_NS, Lab, SERVER_IF, SERVER_NS
from test_env.traffic import REQUEST, RESPONSE


class InjectedSetupFailure(RuntimeError):
    pass


class InterruptedSetup(Lab):
    def _configure(self, namespace, interface, argv):
        raise InjectedSetupFailure("Controlled interruption after private veth creation")


@unittest.skipUnless(os.geteuid() == 0 and os.environ.get("NN_EBPF_RUN_LAB_TESTS") == "1",
                     "Requires explicit isolated-VM root opt-in")
class NamespaceOwnershipTests(unittest.TestCase):
    def setUp(self):
        if any(os.path.lexists(Path("/run/netns") / name) for name in (CLIENT_NS, SERVER_NS)):
            self.skipTest("An existing namespace occupies a reserved lab name")
        if any((Path("/sys/class/net") / name).exists() for name in (CLIENT_IF, SERVER_IF)):
            self.skipTest("An existing interface occupies a reserved lab name")
        evidence = os.environ.get("NN_EBPF_LAB_EVIDENCE_ROOT")
        self.temporary = None
        if evidence is None:
            self.temporary = tempfile.TemporaryDirectory(prefix="nn-ebpf-lab-tests-")
            evidence = self.temporary.name
        self.recorder = Recorder(Path(evidence) / self._testMethodName)

    def tearDown(self):
        self.recorder.close()
        if self.temporary is not None:
            self.temporary.cleanup()

    def assertNoOwnedNamespace(self):
        for name in (CLIENT_NS, SERVER_NS):
            self.assertFalse(os.path.lexists(Path("/run/netns") / name))
        host_names = {link["ifname"] for link in self.recorder.json(["ip", "-j", "link", "show"])}
        self.assertTrue(host_names.isdisjoint((CLIENT_IF, SERVER_IF)))

    def test_existing_namespace_is_not_adopted_or_deleted(self):
        self.recorder.run(["ip", "netns", "add", CLIENT_NS])
        path = Path("/run/netns") / CLIENT_NS
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        original = os.fstat(fd)
        try:
            lab = Lab(self.recorder)
            with self.assertRaises(RuntimeError):
                with lab:
                    self.fail("A preexisting namespace was adopted")
            current = path.stat()
            self.assertEqual((current.st_dev, current.st_ino), (original.st_dev, original.st_ino))
            self.assertFalse(os.path.lexists(Path("/run/netns") / SERVER_NS))
        finally:
            current = path.stat()
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                os.close(fd)
                raise RuntimeError("Foreign fixture namespace identity changed; refusing deletion")
            self.recorder.run(["ip", "netns", "del", CLIENT_NS])
            os.close(fd)

    def test_interrupted_setup_cleans_both_private_endpoints(self):
        lab = InterruptedSetup(self.recorder)
        with self.assertRaises(InjectedSetupFailure):
            with lab:
                self.fail("Interrupted setup reached its body")
        self.assertTrue(lab.state["cleanup_complete"])
        self.assertNoOwnedNamespace()

    def test_repeated_private_topology_and_tcp_reset_leave_host_unchanged(self):
        for _ in range(2):
            lab = Lab(self.recorder)
            with lab:
                host_names = {link["ifname"] for link in self.recorder.json(["ip", "-j", "link", "show"])}
                self.assertTrue(host_names.isdisjoint((CLIENT_IF, SERVER_IF)))
                exchange = lab.exchange(reset=True)
                self.assertEqual(exchange["server"]["request_bytes"], len(REQUEST))
                self.assertEqual(exchange["client"]["response_bytes"], len(RESPONSE))
                self.assertTrue(exchange["server"]["expected_reset_observed"])
            self.assertTrue(lab.state["host_preserved"])
            self.assertNoOwnedNamespace()


if __name__ == "__main__":
    unittest.main()
