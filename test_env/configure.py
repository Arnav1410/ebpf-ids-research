"""Import read-only host/Windows reports into literal configuration, never networking."""
import argparse
import codecs
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .config import ConfigError, ROOT, load_config
from .preflight import _interfaces


class DiscoveryError(ValueError):
    """An inventory is malformed, incomplete for identity, or from another VM."""


def _object(value, name):
    if not isinstance(value, dict):
        raise DiscoveryError(f"{name}: expected an object")
    return value


def _rows(value, name):
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise DiscoveryError(f"{name}: expected an array of objects, not unavailable data")
    return value


def _string(value, name):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise DiscoveryError(f"{name}: expected a nonempty string without control characters")
    return value


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _no_constant(value):
    raise DiscoveryError(f"non-finite JSON number {value}")


def read_report(path, role):
    """Accept UTF8 (including BOM) and PS5.1's BOM-marked UTF16 redirection."""
    try:
        raw = Path(path).read_bytes()
        encoding = "utf-16" if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
        report = json.loads(raw.decode(encoding), object_pairs_hook=_unique_keys,
                            parse_constant=_no_constant)
    except (OSError, UnicodeError, ValueError) as exc:
        raise DiscoveryError(f"{path}: cannot read discovery JSON: {exc}") from exc
    validate_report(report, role)
    return report


def validate_report(report, role):
    report = _object(report, role)
    if (report.get("schema") != "nn-ebpf-lab-discovery"
            or type(report.get("schema_version")) is not int or report["schema_version"] != 1
            or report.get("role") != role or report.get("read_only") is not True):
        raise DiscoveryError(f"{role}: wrong schema/version/role or not a read-only report")
    _string(report.get("collected_at"), f"{role}.collected_at")
    _object(report.get("selection"), f"{role}.selection")
    _object(report.get("data"), f"{role}.data")
    _rows(report.get("errors"), f"{role}.errors")


def inspect_guest():
    """Always observe this guest now; no imported report authorizes attachment."""
    result = {}
    for key, argv in (
        ("links", ["ip", "-j", "-d", "link", "show"]),
        ("addresses", ["ip", "-j", "address", "show"]),
        ("ipv4_routes", ["ip", "-j", "-4", "route", "show", "table", "all"]),
        ("ipv6_routes", ["ip", "-j", "-6", "route", "show", "table", "all"]),
    ):
        try:
            proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=10, check=True)
            result[key] = _rows(json.loads(proc.stdout), f"guest.{key}")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise DiscoveryError(f"guest {key} inspection failed: {exc}") from exc
    return result


def _protected(routes):
    protected = set()
    for route in routes:
        if route.get("dst", "default") in ("default", "0.0.0.0/0", "::/0"):
            names, unresolved = _interfaces(route)
            if unresolved:
                raise DiscoveryError("An actual guest default route has unresolved nexthops")
            protected.update(names)
    return protected


def _ipv4(address, prefix, name):
    if type(prefix) is not int or not 0 <= prefix <= 32:
        raise DiscoveryError(f"{name}: invalid IPv4 prefix length")
    try:
        iface = ipaddress.IPv4Interface(f"{address}/{prefix}")
    except ValueError as exc:
        raise DiscoveryError(f"{name}: invalid IPv4 address: {exc}") from exc
    ip = iface.ip
    if (ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local
            or int(ip) == 0xffffffff or (prefix < 31 and ip in (iface.network.network_address,
                                                                            iface.network.broadcast_address))):
        return None
    return iface


def _guest_ips(addresses, target):
    result = set()
    for row in addresses:
        if row.get("ifname") == target:
            for entry in _rows(row.get("addr_info"), "guest.addr_info"):
                if entry.get("family") == "inet" and "tentative" not in entry.get("flags", []):
                    value = _ipv4(entry.get("local"), entry.get("prefixlen"), "guest address")
                    if value is not None:
                        result.add(value)
    return result


def derive_config(host, windows, guest, settings):
    """Derive only unambiguous observed identities; clear missing/stale targets."""
    validate_report(host, "linux-host")
    validate_report(windows, "windows-client")
    h, w = host["data"], windows["data"]
    selection = host["selection"]
    domain = _object(h.get("domain"), "host.domain (run collector on the virtualization host)")
    vm = _string(selection.get("vm_name"), "host.selection.vm_name")
    if domain.get("name") != vm:
        raise DiscoveryError("Selected host VM does not match observed domain name")
    interfaces = _rows(domain.get("interfaces"), "host.domain.interfaces")
    host_links = _rows(h.get("links"), "host.links")
    host_addresses = _rows(h.get("addresses"), "host.addresses")
    wired = _string(selection.get("wired_iface"), "host.selection.wired_iface")
    wire_links = [row for row in host_links if row.get("ifname") == wired]
    if len(wire_links) != 1 or wire_links[0].get("link_type") != "ether":
        raise DiscoveryError("Selected host wired interface is not uniquely observed Ethernet")
    links = _rows(guest.get("links"), "guest.links")
    addresses = _rows(guest.get("addresses"), "guest.addresses")
    routes = (_rows(guest.get("ipv4_routes"), "guest.ipv4_routes")
              + _rows(guest.get("ipv6_routes"), "guest.ipv6_routes"))
    protected = _protected(routes)
    mgmt = [row for row in links if row.get("ifname") in protected and row.get("link_type") == "ether"]
    if len(mgmt) > 1:
        mgmt = [row for row in mgmt if row.get("ifname") == settings.management_iface
                and str(row.get("address", "")).lower() == settings.management_mac]
    if len(mgmt) != 1:
        raise DiscoveryError("Cannot identify one actual guest management/default-route Ethernet interface")
    management = mgmt[0]
    mgmt_mac = _string(management.get("address"), "guest management MAC").lower()
    if sum(str(row.get("mac", "")).lower() == mgmt_mac for row in interfaces) != 1:
        raise DiscoveryError("Host domain does not uniquely contain this guest's management MAC; wrong VM/report")
    updates = {
        "IDS_VM_NAME": vm,
        "IDS_LIBVIRT_URI": _string(selection.get("libvirt_uri"), "host.selection.libvirt_uri"),
        "IDS_HOST_WIRED_IFACE": wired,
        "IDS_GUEST_MANAGEMENT_IFACE": _string(management.get("ifname"), "guest management interface"),
        "IDS_GUEST_MANAGEMENT_MAC": mgmt_mac,
        "IDS_GUEST_DEMO_IFACE": "", "IDS_GUEST_DEMO_MAC": "",
        "IDS_CLIENT_IPV4": "", "IDS_GUEST_DEMO_IPV4": "",
    }
    blockers = [f"Collector {role}: {error.get('section')}: {error.get('message')}"
                for role, report in (("host", host), ("windows", windows)) for error in report["errors"]]
    master = wire_links[0].get("master")
    bridges = [row for row in host_links
               if (row.get("ifname") == master or row.get("ifindex") == master)
               and row.get("linkinfo", {}).get("info_kind") == "bridge"]
    bridge = bridges[0]["ifname"] if len(bridges) == 1 else None
    if bridge is None:
        blockers.append("Selected wired port has no observed bridge; no guest demo NIC is guessed")
    demo = [row for row in interfaces if bridge is not None and row.get("type") == "bridge"
            and _object(row.get("source"), "domain interface source").get("bridge") == bridge]
    demo_ips = set()
    if len(demo) != 1:
        blockers.append("No unique domain demo NIC is attached to the selected wired bridge")
    else:
        demo_mac = _string(demo[0].get("mac"), "domain demo MAC").lower()
        observed = [row for row in links if str(row.get("address", "")).lower() == demo_mac]
        protected_macs = {str(row.get("address", "")).lower() for row in links if row.get("ifname") in protected}
        if (demo_mac in protected_macs or len(observed) != 1
                or observed[0].get("ifname") in protected or observed[0].get("link_type") != "ether"):
            blockers.append("Domain demo NIC is protected, ambiguous or absent from this guest")
        else:
            target = _string(observed[0].get("ifname"), "guest demo interface")
            updates.update(IDS_GUEST_DEMO_IFACE=target, IDS_GUEST_DEMO_MAC=demo_mac)
            demo_ips = _guest_ips(addresses, target)
            if "UP" not in observed[0].get("flags", []):
                blockers.append("Observed guest demo NIC is not administratively UP")
    adapter = _object(w.get("adapter"), "windows.adapter")
    index = adapter.get("interface_index")
    if type(index) is not int or index <= 0 or windows["selection"].get("interface_index") != index:
        raise DiscoveryError("Windows selected adapter/index does not match observed adapter")
    if windows["selection"].get("interface_alias") != adapter.get("name"):
        raise DiscoveryError("Windows selected alias does not match observed adapter")
    win_ips = set()
    win_routes = _rows(w.get("routes"), "windows.routes")
    dedicated = (adapter.get("hardware_interface") is True and adapter.get("virtual") is False
                 and adapter.get("status") == "Up"
                 and not any(row.get("destination_prefix") == "0.0.0.0/0"
                             and row.get("interface_index") == index for row in win_routes))
    if not dedicated:
        blockers.append("Windows selected adapter is down, virtual or carries a default route; client IP not selected")
    for row in _rows(w.get("addresses"), "windows.addresses"):
        value = _ipv4(row.get("address"), row.get("prefix_length"), "Windows address")
        if dedicated and row.get("address_state") == "Preferred" and value is not None:
            win_ips.add(value)
    if len(win_ips) == 1:
        updates["IDS_CLIENT_IPV4"] = str(next(iter(win_ips)).ip)
    else:
        blockers.append("Windows wired IPv4 is absent, link-local or ambiguous; client IP cleared")
    # Select the guest address only when both peers agree on an observed subnet.
    pairs = [(client, server) for client in win_ips for server in demo_ips
             if client.network == server.network and client.ip != server.ip]
    if len(pairs) == 1:
        updates["IDS_CLIENT_IPV4"] = str(pairs[0][0].ip)
        updates["IDS_GUEST_DEMO_IPV4"] = str(pairs[0][1].ip)
    else:
        blockers.append("No unique same-subnet Windows/guest address pair; guest demo IPv4 cleared")
    all_guest_ips = {entry.get("local") for row in addresses
                     for entry in _rows(row.get("addr_info"), "guest.addr_info") if entry.get("family") == "inet"}
    if updates["IDS_CLIENT_IPV4"] in all_guest_ips:
        raise DiscoveryError("Reported Windows source IPv4 is assigned to this guest")
    if "LOWER_UP" not in wire_links[0].get("flags", []):
        blockers.append("Host wired carrier is not observed LOWER_UP")
    blockers.append("Recovery, route/capture/connectivity and separate physical-backend acceptance remain required; Stage08 is BLOCKED")
    observation = {"host_collected_at": host["collected_at"], "windows_collected_at": windows["collected_at"],
                   "wired_bridge": bridge, "windows_adapter": adapter,
                   "host_addresses": host_addresses, "protected_guest_interfaces": sorted(protected)}
    return updates, blockers, observation


def update_env(target, updates, apply=False):
    """Preserve unrelated settings/comments; validate and atomically replace only on apply."""
    target = Path(target).absolute()
    if target.is_symlink() or target.resolve() == (ROOT / ".env.example").resolve():
        raise DiscoveryError("Refusing a symlink target or the versioned .env.example")
    before = target.read_bytes() if target.exists() else None
    base = target if before is not None else ROOT / ".env.example"
    load_config(base)
    text = before.decode("utf-8") if before is not None else base.read_text(encoding="utf-8")
    for key, value in updates.items():
        if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise DiscoveryError(f"{key}: cannot insert control characters into configuration")
    lines, seen = [], set()
    for line in text.splitlines():
        key = line.strip().split("=", 1)[0] if line.strip() and not line.lstrip().startswith("#") else None
        if key in updates:
            lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            lines.append(line)
    lines.extend(f"{key}={value}" for key, value in updates.items() if key not in seen)
    rendered = "\n".join(lines) + "\n"
    # Use the same literal parser as every consumer, not a second validation convention.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".ids-config-",
                                         dir=target.parent if apply else None, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        load_config(temporary)
        if apply:
            current = target.read_bytes() if target.exists() else None
            if current != before or target.is_symlink():
                raise DiscoveryError("Configuration changed during import; rerun instead of overwriting it")
            temporary.replace(target)
            temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path, help="Linux-host collector JSON")
    parser.add_argument("--windows", required=True, type=Path, help="native Windows collector JSON")
    parser.add_argument("--env", type=Path, default=ROOT / ".env", help="local literal configuration to update")
    parser.add_argument("--apply", action="store_true", help="atomically write observed fields (default: preview)")
    args = parser.parse_args(argv)
    try:
        settings = load_config(args.env if args.env.exists() else ROOT / ".env.example")
        host = read_report(args.host, "linux-host")
        windows = read_report(args.windows, "windows-client")
        updates, blockers, observation = derive_config(host, windows, inspect_guest(), settings)
        update_env(args.env, updates, apply=args.apply)
    except (ConfigError, DiscoveryError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"status": "IMPORTED" if args.apply else "PREVIEW", "env": str(args.env.absolute()),
                      "observed_config": updates, "observations": observation, "blockers": blockers,
                      "stage08": "BLOCKED", "network_changes": False, "bpf_attached": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
