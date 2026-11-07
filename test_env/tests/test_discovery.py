"""Synthetic inventory tests cover configuration selection, not physical acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_env.config import ConfigError, Settings, load_config
from test_env.configure import DiscoveryError, derive_config, read_report, update_env


MGMT_MAC = "52:54:00:11:22:33"
DEMO_MAC = "52:54:00:44:55:66"


def envelope(role, selection, data):
    return {"schema": "nn-ebpf-lab-discovery", "schema_version": 1,
            "role": role, "collected_at": "2026-10-25T00:00:00Z", "read_only": True,
            "selection": selection, "data": data, "errors": []}


def fixtures():
    host = envelope("linux-host", {"vm_name": "lab-vm", "libvirt_uri": "qemu:///system", "wired_iface": "wire0"}, {
        "domain": {"name": "lab-vm", "interfaces": [
            {"type": "network", "mac": MGMT_MAC, "source": {"network": "default"}},
            {"type": "bridge", "mac": DEMO_MAC, "source": {"bridge": "lab-br0"}},
        ]},
        "links": [
            {"ifname": "wire0", "ifindex": 2, "link_type": "ether", "master": "lab-br0", "flags": ["UP", "LOWER_UP"]},
            {"ifname": "lab-br0", "ifindex": 3, "link_type": "ether", "linkinfo": {"info_kind": "bridge"}},
        ], "addresses": [],
    })
    windows = envelope("windows-client", {"interface_alias": "Ethernet", "interface_index": 5}, {
        "adapter": {"name": "Ethernet", "interface_index": 5, "mac": "00:e0:4c:68:01:4c",
                    "hardware_interface": True, "virtual": False, "status": "Up"},
        "addresses": [{"address": "192.168.77.2", "prefix_length": 24, "address_state": "Preferred"}],
        "routes": [{"destination_prefix": "0.0.0.0/0", "interface_index": 18, "next_hop": "10.0.0.1"}],
    })
    guest = {
        "links": [{"ifname": "mgmt0", "link_type": "ether", "address": MGMT_MAC, "flags": ["UP"]},
                  {"ifname": "demo0", "link_type": "ether", "address": DEMO_MAC, "flags": ["UP"]}],
        "addresses": [
            {"ifname": "mgmt0", "addr_info": [{"family": "inet", "local": "192.168.122.20", "prefixlen": 24}]},
            {"ifname": "demo0", "addr_info": [{"family": "inet", "local": "192.168.77.3", "prefixlen": 24}]},
        ], "ipv4_routes": [{"dst": "default", "dev": "mgmt0"}], "ipv6_routes": [],
    }
    return host, windows, guest


class DiscoverySelectionTests(unittest.TestCase):
    def setUp(self):
        self.host, self.windows, self.guest = fixtures()
        self.settings = Settings(management_iface="mgmt0", management_mac=MGMT_MAC)

    def derive(self):
        return derive_config(self.host, self.windows, self.guest, self.settings)

    def test_mac_and_wired_bridge_select_observed_peer_pair_after_address_change(self):
        self.windows["data"]["addresses"][0]["address"] = "192.168.88.42"
        self.guest["addresses"][1]["addr_info"][0]["local"] = "192.168.88.73"
        self.guest["links"][1]["ifname"] = "renamed0"
        self.guest["addresses"][1]["ifname"] = "renamed0"
        updates, blockers, _ = self.derive()
        self.assertEqual(updates["IDS_GUEST_DEMO_IFACE"], "renamed0")
        self.assertEqual(updates["IDS_CLIENT_IPV4"], "192.168.88.42")
        self.assertEqual(updates["IDS_GUEST_DEMO_IPV4"], "192.168.88.73")
        self.assertTrue(any("Stage08 is BLOCKED" in reason for reason in blockers))

    def test_apipa_and_tentative_addresses_do_not_become_demo_configuration(self):
        for state, ip in (("Preferred", "169.254.113.187"), ("Tentative", "192.168.77.2")):
            self.windows["data"]["addresses"][0].update(address=ip, address_state=state)
            with self.subTest(state=state):
                updates, _, _ = self.derive()
                self.assertEqual(updates["IDS_CLIENT_IPV4"], "")
                self.assertEqual(updates["IDS_GUEST_DEMO_IPV4"], "")

    def test_only_the_bridge_containing_the_selected_wire_can_select_a_demo_nic(self):
        self.host["data"]["domain"]["interfaces"][1]["source"]["bridge"] = "unrelated-br0"
        updates, blockers, _ = self.derive()
        self.assertEqual(updates["IDS_GUEST_DEMO_IFACE"], "")
        self.assertEqual(updates["IDS_GUEST_DEMO_MAC"], "")
        self.assertTrue(any("No unique domain demo NIC" in item for item in blockers))

    def test_actual_ipv6_and_multipath_default_routes_protect_demo_even_if_labelled_elsewhere(self):
        for route in ({"dst": "::/0", "dev": "demo0"},
                      {"dst": "default", "multipath": [{"dev": "mgmt0"}, {"dev": "demo0"}]}):
            self.guest["ipv6_routes"] = [route]
            with self.subTest(route=route):
                updates, blockers, _ = self.derive()
                self.assertEqual(updates["IDS_GUEST_DEMO_IFACE"], "")
                self.assertTrue(any("protected" in item for item in blockers))

    def test_unresolved_defaults_and_wrong_vm_fail_instead_of_overwriting_management(self):
        self.guest["ipv6_routes"] = [{"dst": "default", "nhid": 8}]
        with self.assertRaisesRegex(DiscoveryError, "unresolved"):
            self.derive()
        self.guest["ipv6_routes"] = []
        self.host["data"]["domain"]["interfaces"][0]["mac"] = "52:54:00:aa:bb:cc"
        with self.assertRaisesRegex(DiscoveryError, "wrong VM"):
            self.derive()

    def test_ambiguous_demo_mac_and_client_addresses_are_not_selected_arbitrarily(self):
        self.host["data"]["domain"]["interfaces"].append(copy.deepcopy(self.host["data"]["domain"]["interfaces"][1]))
        self.windows["data"]["addresses"].append({"address": "192.168.77.4", "prefix_length": 24, "address_state": "Preferred"})
        updates, _, _ = self.derive()
        self.assertEqual(updates["IDS_GUEST_DEMO_IFACE"], "")
        self.assertEqual(updates["IDS_CLIENT_IPV4"], "")

    def test_virtual_down_or_default_route_windows_adapter_cannot_supply_client_address(self):
        changes = ({"virtual": True}, {"hardware_interface": False}, {"status": "Disconnected"})
        for change in changes:
            original = dict(self.windows["data"]["adapter"])
            self.windows["data"]["adapter"].update(change)
            with self.subTest(change=change):
                self.assertEqual(self.derive()[0]["IDS_CLIENT_IPV4"], "")
            self.windows["data"]["adapter"] = original
        self.windows["data"]["routes"].append({"destination_prefix": "0.0.0.0/0", "interface_index": 5})
        self.assertEqual(self.derive()[0]["IDS_CLIENT_IPV4"], "")

    def test_mismatched_prefixes_and_duplicate_guest_source_cannot_produce_peer_pair(self):
        self.windows["data"]["addresses"][0]["prefix_length"] = 16
        self.assertEqual(self.derive()[0]["IDS_GUEST_DEMO_IPV4"], "")
        self.windows["data"]["addresses"][0].update(prefix_length=24, address="192.168.122.20")
        with self.assertRaisesRegex(DiscoveryError, "assigned to this guest"):
            self.derive()

    def test_missing_host_identity_and_missing_windows_routes_are_errors_not_empty_inventory(self):
        self.host["data"]["domain"] = None
        with self.assertRaisesRegex(DiscoveryError, "virtualization host"):
            self.derive()
        self.host, _, _ = fixtures()
        self.windows["data"]["routes"] = None
        with self.assertRaisesRegex(DiscoveryError, "windows.routes"):
            self.derive()


class DiscoveryFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nn-discovery-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def test_native_powershell_utf16_and_utf8_bom_reports_are_accepted(self):
        _, windows, _ = fixtures()
        path = self.directory / "windows.json"
        for encoding in ("utf-16", "utf-8-sig", "utf-8"):
            path.write_bytes(json.dumps(windows).encode(encoding))
            with self.subTest(encoding=encoding):
                self.assertEqual(read_report(path, "windows-client")["selection"]["interface_index"], 5)

    def test_duplicate_keys_console_junk_wrong_role_and_nonfinite_json_are_rejected(self):
        path = self.directory / "invalid.json"
        host, windows, _ = fixtures()
        cases = ('{"schema":1,"schema":2}', 'PS C:\\> ' + json.dumps(windows),
                 json.dumps(host), json.dumps(windows).replace('"schema_version": 1', '"schema_version": NaN'))
        for value in cases:
            path.write_text(value, encoding="utf-8")
            with self.subTest(value=value[:40]), self.assertRaises(DiscoveryError):
                read_report(path, "windows-client")

    def test_preview_preserves_file_and_apply_clears_disappeared_target_preserving_custom_settings(self):
        target = self.directory / "lab.env"
        original = ("# custom experiment\nIDS_CLIENT_IPV4=192.168.77.2\n"
                    "IDS_GUEST_DEMO_IFACE=old0\nIDS_GUEST_DEMO_MAC=52:54:00:aa:bb:cc\n"
                    "IDS_GUEST_DEMO_IPV4=192.168.77.3\nIDS_DASHBOARD_PORT=9123\n"
                    "IDS_LOADER='custom build/nn-loader'\n")
        target.write_text(original, encoding="utf-8")
        host, windows, guest = fixtures()
        host["data"]["links"][0].pop("master")
        windows["data"]["addresses"][0]["address"] = "169.254.113.187"
        updates, _, _ = derive_config(host, windows, guest, Settings(management_iface="mgmt0", management_mac=MGMT_MAC))
        update_env(target, updates)
        self.assertEqual(target.read_text(), original)
        update_env(target, updates, apply=True)
        settings = load_config(target)
        self.assertIsNone(settings.demo_iface)
        self.assertIsNone(settings.demo_mac)
        self.assertIsNone(settings.demo_ipv4)
        self.assertIsNone(settings.client_ipv4)
        self.assertEqual(settings.dashboard_port, 9123)
        self.assertTrue(str(settings.loader).endswith("custom build/nn-loader"))
        self.assertTrue(target.read_text().startswith("# custom experiment\n"))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_invalid_or_injected_updates_and_symlink_targets_do_not_modify_existing_data(self):
        target = self.directory / "lab.env"
        original = "IDS_DASHBOARD_PORT=9123\n"
        target.write_text(original)
        for value in ("bad;iface", "demo0\nIDS_LOADER=/bin/sh"):
            with self.subTest(value=value), self.assertRaises((DiscoveryError, ConfigError)):
                update_env(target, {"IDS_GUEST_DEMO_IFACE": value}, apply=True)
            self.assertEqual(target.read_text(), original)
        link = self.directory / "link.env"
        link.symlink_to(target)
        with self.assertRaisesRegex(DiscoveryError, "symlink"):
            update_env(link, {"IDS_VM_NAME": "lab-vm"}, apply=True)
        self.assertEqual(target.read_text(), original)


if __name__ == "__main__":
    unittest.main()
