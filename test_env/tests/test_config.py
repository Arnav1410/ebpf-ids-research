"""Consumer/security guards using synthetic inventories, never physical proof."""
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_env.config import ConfigError, ROOT, Settings, load_config
from test_env.preflight import evaluate_guest


class ConfigParsingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nn-env-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.config = self.directory / "lab.env"

    def load(self, text):
        self.config.write_text(text, encoding="utf-8")
        return load_config(self.config)

    def test_duplicates_and_unknown_keys_identify_file_and_line(self):
        for text, reason in (("# heading\nIDS_TCP_PORT=7000\nIDS_TCP_PORT=7001\n", "duplicate"),
                             ("# heading\nIDS_TCP_PROT=7000\n", "unknown")):
            with self.subTest(reason=reason), self.assertRaises(ConfigError) as caught:
                self.load(text)
            self.assertIn(str(self.config), str(caught.exception))
            self.assertIn(":3:" if reason == "duplicate" else ":2:", str(caught.exception))
            self.assertIn(reason, str(caught.exception))

    def test_shell_payload_remains_a_literal_path_and_is_never_executed(self):
        marker = self.directory / "executed"
        payload = f"$(touch {marker});`touch {marker}`;${{HOME}}"
        settings = self.load(f'IDS_OUT="{payload}"\n')
        self.assertEqual(settings.out, ROOT / payload)
        self.assertFalse(marker.exists())

    def test_quotes_spaces_empty_optionals_and_repo_relative_paths(self):
        settings = self.load("# own-line comment\nIDS_LOADER='build with spaces/nn-loader'\n"
                             'IDS_OBJECT="build with spaces/nn.bpf.o"\n'
                             "IDS_SAMPLE=\nIDS_READER=''\nIDS_OUT=results/#literal\n")
        self.assertEqual(settings.loader, ROOT / "build with spaces/nn-loader")
        self.assertEqual(settings.bpf_object, ROOT / "build with spaces/nn.bpf.o")
        self.assertEqual(settings.out, ROOT / "results/#literal")
        self.assertIsNone(settings.sample)
        self.assertIsNone(settings.reader)
        # Provenance is safe to serialize without dropping unspecified fields.
        logged = json.loads(json.dumps(settings.as_dict()))
        self.assertEqual(logged["loader"], str(settings.loader))
        self.assertIsNone(logged["sample"])
        with self.assertRaises(FrozenInstanceError):
            settings.out = self.directory

    def test_filename_is_caller_relative_not_repo_relative(self):
        self.config.write_text("IDS_MODEL=parameters/model.h\n", encoding="utf-8")
        original = Path.cwd()
        try:
            os.chdir(self.directory)
            settings = load_config(Path("lab.env"))
        finally:
            os.chdir(original)
        self.assertEqual(settings.model, ROOT / "parameters/model.h")
        self.assertEqual(settings.config_file, self.config)

    def test_process_environment_never_overrides_file(self):
        with patch.dict(os.environ, {"IDS_TCP_PORT": "9999", "IDS_OUT": "/not-the-file"}):
            settings = self.load("IDS_TCP_PORT=6123\nIDS_OUT=file-output\n")
        self.assertEqual(settings.tcp_port, 6123)
        self.assertEqual(settings.out, ROOT / "file-output")

    def test_explicit_missing_and_non_utf8_files_are_errors(self):
        with self.assertRaises(ConfigError) as caught:
            load_config(self.directory / "absent.env")
        self.assertIn("absent.env", str(caught.exception))
        self.config.write_bytes(b"IDS_VM_NAME=\xff\n")
        with self.assertRaises(ConfigError) as caught:
            load_config(self.config)
        self.assertIn("UTF-8", str(caught.exception))

    def test_malformed_shell_style_lines_are_rejected(self):
        for line in ("export IDS_TCP_PORT=5001", "source another.env", "IDS_TCP_PORT",
                     "IDS_OUT='unclosed", 'IDS_OUT="wrong\'', "IDS_OUT='one' 'two'",
                     'IDS_OUT=word"quote', "IDS_TCP_PORT=5001 # not an inline comment"):
            with self.subTest(line=line), self.assertRaises(ConfigError) as caught:
                self.load(line + "\n")
            self.assertIn(":1:", str(caught.exception))

    def test_invalid_bounds_addresses_and_identities_are_rejected(self):
        cases = {
            "IDS_TCP_PORT": ("0", "65536", "1.0"),
            "IDS_DASHBOARD_PORT": ("1023", "65536"),
            "IDS_RUN_SECONDS": ("0", "241", "-1"),
            "IDS_REPLAY_INTERVAL": ("nan", "inf", "1e999", "0.049", "10.01"),
            "IDS_CLIENT_IPV4": ("192.0.2.999", "::1", "127.0.0.1", "0.0.0.0", "224.0.0.1"),
            "IDS_GUEST_DEMO_IPV4": ("192.0.2.4/24", "255.255.255.255"),
            "IDS_GUEST_DEMO_MAC": ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "52:54:00:aa:bb"),
            "IDS_GUEST_MANAGEMENT_MAC": ("bad-mac",),
            "IDS_GUEST_DEMO_IFACE": ("toolonginterface0", "-bad", "eth0;touch", "eth0/other"),
            "IDS_GUEST_MANAGEMENT_IFACE": ("",),
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError) as caught:
                    self.load(f"{key}={value}\n")
                self.assertIn(f":1: {key}:", str(caught.exception))


class GuestSafetyTests(unittest.TestCase):
    """All addresses/interfaces here are synthetic, not available lab targets."""

    def setUp(self):
        self.settings = Settings(management_iface="mgmt0", management_mac="52:54:00:11:22:33",
                                 demo_iface="demo0", demo_mac="52:54:00:44:55:66",
                                 demo_ipv4="192.0.2.10", client_ipv4="192.0.2.20")
        self.links = [
            {"ifname": "mgmt0", "ifindex": 2, "address": "52:54:00:11:22:33",
             "link_type": "ether", "flags": ["UP"]},
            {"ifname": "demo0", "ifindex": 3, "address": "52:54:00:44:55:66",
             "link_type": "ether", "flags": ["UP"]},
        ]
        self.addresses = [
            {"ifname": "mgmt0", "addr_info": [{"family": "inet", "local": "198.51.100.10"}]},
            {"ifname": "demo0", "addr_info": [{"family": "inet", "local": "192.0.2.10"}]},
        ]
        self.routes = [{"dst": "default", "dev": "mgmt0"}]
        self.qdiscs = [{"dev": "demo0", "kind": "fq_codel", "root": True}]
        self.filters = {"ingress": [], "egress": []}

    def evaluate(self, settings=None, **changes):
        observed = {"links": self.links, "addresses": self.addresses, "routes": self.routes,
                    "qdiscs": self.qdiscs, "filters": self.filters}
        observed.update(changes)
        return evaluate_guest(settings or self.settings, **observed)

    def assertBlockedBy(self, result, fragment):
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["guest_checks"], "BLOCKED")
        self.assertTrue(any(fragment in blocker for blocker in result["blockers"]), result)

    def test_matching_synthetic_inventory_is_never_physical_acceptance(self):
        result = self.evaluate()
        self.assertEqual(result["guest_checks"], "CLEAR")
        self.assertEqual(result["stage08"], "BLOCKED")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(any("Physical backend is not accepted" in text for text in result["blockers"]))

    def test_mislabelling_management_cannot_select_an_actual_default_route(self):
        settings = replace(self.settings, management_iface="demo0", management_mac=self.settings.demo_mac,
                           demo_iface="mgmt0", demo_mac=self.settings.management_mac,
                           demo_ipv4="198.51.100.10")
        result = self.evaluate(settings)
        self.assertBlockedBy(result, "actual default-route interface")
        self.assertIn("mgmt0", result["protected_interfaces"])

    def test_all_ipv4_ipv6_and_multipath_default_interfaces_are_protected(self):
        for route in ({"dst": "0.0.0.0/0", "dev": "demo0", "table": 123},
                      {"dst": "::/0", "dev": "demo0"},
                      {"dst": "default", "nexthops": [{"dev": "mgmt0"}, {"dev": "demo0"}]},
                      {"dst": "default", "multipath": [{"dev": "mgmt0"}, {"dev": "demo0"}]}):
            with self.subTest(route=route):
                self.assertBlockedBy(self.evaluate(routes=[route]), "actual default-route interface")

    def test_unresolved_default_nexthops_fail_closed(self):
        for route in ({"dst": "default", "nhid": 10},
                      {"dst": "default", "nexthops": [{"dev": "mgmt0"}, {"nhid": 10}]},
                      {"dst": "default", "nexthops": None}):
            with self.subTest(route=route):
                self.assertBlockedBy(self.evaluate(routes=[route]), "unresolved interface/nexthop")

    def test_same_management_interface_is_forbidden_without_any_default_route(self):
        settings = replace(self.settings, demo_iface="mgmt0", demo_mac=self.settings.management_mac,
                           demo_ipv4="198.51.100.10")
        self.assertBlockedBy(self.evaluate(settings, routes=[]), "protected: management")

    def test_management_mac_is_protected_even_on_a_differently_named_interface(self):
        links = [self.links[0], dict(self.links[1], address=self.settings.management_mac)]
        settings = replace(self.settings, demo_mac=self.settings.management_mac)
        self.assertBlockedBy(self.evaluate(settings, links=links), "protected management/default-route MAC")

    def test_identity_mismatches_and_absent_target_never_pass(self):
        cases = ((replace(self.settings, management_mac="52:54:00:aa:bb:cc"), "Management MAC mismatch"),
                 (replace(self.settings, management_iface="absent0"), "management interface"),
                 (replace(self.settings, demo_mac="52:54:00:aa:bb:cc"), "Demo MAC mismatch"),
                 (replace(self.settings, demo_ipv4="192.0.2.99"), "Demo IPv4 mismatch"),
                 (replace(self.settings, demo_iface="absent0"), "not uniquely present"))
        for settings, fragment in cases:
            with self.subTest(fragment=fragment):
                self.assertBlockedBy(self.evaluate(settings), fragment)

    def test_default_route_mac_remains_protected_after_management_is_relabelled(self):
        links = self.links + [
            {"ifname": "other0", "ifindex": 4, "address": "52:54:00:77:88:99",
             "link_type": "ether", "flags": ["UP"]},
        ]
        links[1] = dict(links[1], address=self.settings.management_mac)
        settings = replace(self.settings, management_iface="other0",
                           management_mac="52:54:00:77:88:99",
                           demo_mac=self.settings.management_mac)
        self.assertBlockedBy(self.evaluate(settings, links=links), "protected management/default-route MAC")

    def test_down_loopback_and_non_ethernet_targets_are_refused(self):
        for changes, fragment in (({"flags": []}, "not administratively UP"),
                                  ({"flags": ["UP", "LOOPBACK"]}, "not an observed Ethernet"),
                                  ({"link_type": "loopback"}, "not an observed Ethernet"),
                                  ({"ifindex": 0}, "valid interface index")):
            links = [self.links[0], dict(self.links[1], **changes)]
            with self.subTest(changes=changes):
                self.assertBlockedBy(self.evaluate(links=links), fragment)

    def test_existing_tc_attachment_or_filters_are_not_available_targets(self):
        for kind in ("clsact", "ingress"):
            with self.subTest(kind=kind):
                self.assertBlockedBy(self.evaluate(qdiscs=[{"dev": "demo0", "kind": kind}]),
                                     "occupied by an existing")
        for hook in ("ingress", "egress"):
            filters = {"ingress": [], "egress": []}
            filters[hook] = [{"kind": "bpf", "pref": 123}]
            with self.subTest(hook=hook):
                self.assertBlockedBy(self.evaluate(filters=filters), "occupied by existing filters")

    def test_missing_fields_remain_missing_instead_of_becoming_fallback_targets(self):
        for field, key in (("demo_iface", "IDS_GUEST_DEMO_IFACE"), ("demo_mac", "IDS_GUEST_DEMO_MAC"),
                           ("demo_ipv4", "IDS_GUEST_DEMO_IPV4"), ("client_ipv4", "IDS_CLIENT_IPV4")):
            with self.subTest(field=field):
                self.assertBlockedBy(self.evaluate(replace(self.settings, **{field: None})), f"Missing {key}")

    def test_guest_address_cannot_be_claimed_as_native_windows_source(self):
        for address in (self.settings.demo_ipv4, "198.51.100.10"):
            with self.subTest(address=address):
                self.assertBlockedBy(self.evaluate(replace(self.settings, client_ipv4=address)),
                                     "not a distinct external client")

    def test_missing_or_incomplete_inspection_is_not_empty_safe_state(self):
        for field in ("links", "addresses", "routes", "qdiscs", "filters"):
            with self.subTest(field=field):
                self.assertBlockedBy(self.evaluate(**{field: None}), "unavailable or malformed")
        self.assertBlockedBy(self.evaluate(filters={"ingress": []}), "unavailable or malformed")
        self.assertBlockedBy(self.evaluate(qdiscs=[{"kind": "clsact"}]), "missing device/kind")
        self.assertBlockedBy(self.evaluate(addresses=[{"ifname": "demo0", "addr_info": None}]),
                             "malformed address records")

    def test_env_file_values_feed_observed_identity_checks(self):
        with tempfile.TemporaryDirectory(prefix="nn-env-consumer-") as directory:
            filename = Path(directory) / "physical.env"
            filename.write_text("IDS_GUEST_MANAGEMENT_IFACE=mgmt0\n"
                                "IDS_GUEST_MANAGEMENT_MAC=52:54:00:11:22:33\n"
                                "IDS_GUEST_DEMO_IFACE=demo0\n"
                                "IDS_GUEST_DEMO_MAC=52:54:00:44:55:66\n"
                                "IDS_GUEST_DEMO_IPV4=192.0.2.99\n"
                                "IDS_CLIENT_IPV4=192.0.2.20\n", encoding="utf-8")
            result = self.evaluate(load_config(filename))
        self.assertBlockedBy(result, "Demo IPv4 mismatch")


if __name__ == "__main__":
    unittest.main()
