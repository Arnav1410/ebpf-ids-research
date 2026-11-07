"""Read-only guest inventory, not physical-backend or Stage08 acceptance.

Only evidence files are created. No attachment, traffic, sudo, installation,
network configuration, or host command is performed by this module.
"""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess

from .commands import Recorder
from .config import ConfigError, load_config
from .lab import CLIENT_IP, SERVER_IP


_BACKEND_BLOCKER = (
    "Physical backend is not accepted: the live service still uses only the owned "
    "private namespace/veth lab and its fixed native source filter. Read-only "
    "inspection cannot establish Stage08 PASS or authorize a physical attachment."
)


def _interfaces(route):
    """Return all default-route devices and whether any hop is unresolved."""
    result = set()
    unresolved = route.get("nhid") is not None
    if isinstance(route.get("dev"), str) and route["dev"]:
        result.add(route["dev"])
    for key in ("nexthops", "multipath"):
        hops = route.get(key, [])
        if not _records(hops):
            unresolved = True
            continue
        for hop in hops:
            devices, unknown = _interfaces(hop)
            result.update(devices)
            unresolved = unresolved or unknown
    return result, unresolved or not result


def _records(value):
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def evaluate_guest(settings, links, addresses, routes, qdiscs, filters):
    """Evaluate observed ip/tc JSON without side effects.

    links/addresses/routes/qdiscs are JSON arrays; routes combines all IPv4 and
    IPv6 route tables. filters is the configured target's ingress/egress mapping
    of JSON arrays. None means an inspection failed or could not be attempted.
    Synthetic inputs exercise guards only and can never prove physical PASS.
    """
    blockers = []
    for name, value in (("links", links), ("addresses", addresses), ("routes", routes),
                        ("qdiscs", qdiscs)):
        if not _records(value):
            blockers.append(f"Guest {name} inspection is unavailable or malformed.")
    if not blockers:
        if any(not isinstance(item.get("ifname"), str) for item in links):
            blockers.append("Guest links inspection has missing interface identities.")
        if any(not isinstance(item.get("ifname"), str)
               or not _records(item.get("addr_info")) for item in addresses):
            blockers.append("Guest addresses inspection has malformed address records.")
        if any(not isinstance(item.get("dev"), str)
               or not isinstance(item.get("kind"), str) for item in qdiscs):
            blockers.append("Guest qdiscs inspection has missing device/kind identities.")
    if blockers:
        return {"status": "BLOCKED", "stage08": "BLOCKED", "guest_checks": "BLOCKED",
                "protected_interfaces": [], "blockers": blockers + [_BACKEND_BLOCKER]}

    protected = {settings.management_iface}
    unresolved_default = False
    for route in routes:
        if route.get("dst", "default") in ("default", "0.0.0.0/0", "::/0"):
            devices, unknown = _interfaces(route)
            protected.update(devices)
            # Nexthop IDs cannot safely be treated as unprotected interfaces.
            unresolved_default = unresolved_default or unknown
    if unresolved_default:
        blockers.append("An actual default route has an unresolved interface/nexthop; no demo target is safe to select.")

    management = [link for link in links if link.get("ifname") == settings.management_iface]
    if len(management) != 1:
        blockers.append(f"Configured management interface {settings.management_iface!r} is not uniquely present.")
    elif str(management[0].get("address", "")).lower() != settings.management_mac:
        blockers.append(f"Management MAC mismatch on {settings.management_iface}: configured identity does not match the guest.")

    protected_macs = {settings.management_mac}
    for link in links:
        if link.get("ifname") in protected:
            protected_macs.add(str(link.get("address", "")).lower())
    protected_macs.discard("")

    for field, description in (("demo_iface", "IDS_GUEST_DEMO_IFACE"),
                               ("demo_mac", "IDS_GUEST_DEMO_MAC"),
                               ("demo_ipv4", "IDS_GUEST_DEMO_IPV4"),
                               ("client_ipv4", "IDS_CLIENT_IPV4 (actual native Windows source)")):
        if getattr(settings, field) is None:
            blockers.append(f"Missing {description}; no fallback target is assumed.")
    target = settings.demo_iface
    matches = [link for link in links if link.get("ifname") == target] if target else []
    if target:
        if target in protected:
            blockers.append(f"Demo interface {target} is protected: management or an actual default-route interface.")
        if len(matches) != 1:
            blockers.append(f"Demo interface {target!r} is not uniquely present in the guest.")
        else:
            link = matches[0]
            observed_mac = str(link.get("address", "")).lower()
            if (link.get("link_type") != "ether" or type(link.get("ifindex")) is not int
                    or link["ifindex"] <= 0 or "LOOPBACK" in link.get("flags", [])):
                blockers.append(f"Demo interface {target} is not an observed Ethernet target with a valid interface index.")
            if "UP" not in link.get("flags", []):
                blockers.append(f"Demo interface {target} is not administratively UP.")
            if observed_mac != settings.demo_mac:
                blockers.append(f"Demo MAC mismatch on {target}: configured identity does not match the guest.")
            if observed_mac in protected_macs:
                blockers.append(f"Demo interface {target} has a protected management/default-route MAC.")
        if settings.demo_mac in protected_macs:
            blockers.append("Configured demo MAC matches a protected management/default-route MAC.")
        target_addresses = [item for item in addresses if item.get("ifname") == target]
        observed_ips = {entry.get("local") for item in target_addresses
                        for entry in item.get("addr_info", []) if entry.get("family") == "inet"}
        if settings.demo_ipv4 is not None and settings.demo_ipv4 not in observed_ips:
            blockers.append(f"Demo IPv4 mismatch on {target}: configured address is not assigned to that guest interface.")
        if any(item.get("dev") == target and item.get("kind") in ("clsact", "ingress") for item in qdiscs):
            blockers.append(f"TC target {target} is occupied by an existing clsact/ingress qdisc; it must not be replaced.")
        if (not isinstance(filters, dict) or set(filters) != {"ingress", "egress"}
                or not all(_records(value) for value in filters.values())):
            blockers.append(f"TC filter inspection for {target} is unavailable or malformed.")
        elif any(filters.values()):
            blockers.append(f"TC target {target} is occupied by existing filters; they must not be replaced.")
    if settings.client_ipv4 is not None:
        guest_ips = {entry.get("local") for item in addresses
                     for entry in item.get("addr_info", []) if entry.get("family") == "inet"}
        if settings.client_ipv4 == settings.demo_ipv4 or settings.client_ipv4 in guest_ips:
            blockers.append("Configured Windows client IPv4 belongs to the guest, not a distinct external client.")
    return {"status": "BLOCKED", "stage08": "BLOCKED",
            "guest_checks": "BLOCKED" if blockers else "CLEAR",
            "protected_interfaces": sorted(protected), "blockers": blockers + [_BACKEND_BLOCKER]}


def _suggestions(settings):
    commands = []
    if settings.vm_name is not None and settings.host_wired_iface is not None:
        argv = ["bash", "./discover-host.sh", "--vm", settings.vm_name,
                "--wired", settings.host_wired_iface, "--uri", settings.libvirt_uri]
        commands.append({"where": "Linux virtualization host",
                         "copy_script_from": str(Path(__file__).with_name("discover-host.sh")),
                         "argv": argv, "command": shlex.join(argv)})
    argv = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
            r".\discover-windows.ps1", "-InterfaceAlias", "Ethernet"]
    commands.append({"where": "Native Windows PowerShell",
                     "copy_script_from": str(Path(__file__).with_name("discover-windows.ps1")),
                     "argv": argv, "command": shlex.join(argv)})
    return commands


def _inspect(recorder, argv, errors):
    try:
        value = recorder.json(argv, timeout=10)
        if not _records(value):
            raise ValueError("expected a JSON array of objects")
        return value
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        errors.append(f"{shlex.join(argv)}: {exc}")
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, help="literal configuration file (default: optional repository .env)")
    parser.add_argument("--out", type=Path, help="exclusive new evidence directory (overrides IDS_OUT)")
    args = parser.parse_args(argv)
    try:
        settings = load_config(args.env)
    except ConfigError as exc:
        parser.error(str(exc))
    out = args.out if args.out is not None else settings.out
    if out is None:
        parser.error("--out or IDS_OUT is required")
    try:
        recorder = Recorder(out)
    except (OSError, ValueError) as exc:
        parser.error(f"cannot create new evidence directory: {exc}")
    try:
        effective = settings.as_dict()
        effective["out"] = str(recorder.out)
        recorder.write_json("effective-config.json", effective)
        tools = {name: shutil.which(name) for name in ("ip", "tc", "python3", "virsh", "iperf3")}
        errors = []
        commands = {
            "links": ["ip", "-j", "-d", "link", "show"],
            "addresses": ["ip", "-j", "address", "show"],
            "ipv4_routes": ["ip", "-j", "-4", "route", "show", "table", "all"],
            "ipv6_routes": ["ip", "-j", "-6", "route", "show", "table", "all"],
            "qdiscs": ["tc", "-j", "qdisc", "show"],
        }
        guest = {name: _inspect(recorder, command, errors) for name, command in commands.items()}
        filters = None
        if (settings.demo_iface is not None and _records(guest["links"])
                and any(item.get("ifname") == settings.demo_iface for item in guest["links"])):
            filters = {hook: _inspect(recorder, ["tc", "-j", "filter", "show", "dev",
                                               settings.demo_iface, hook], errors)
                       for hook in ("ingress", "egress")}
        guest["filters"] = filters
        routes = (guest["ipv4_routes"] + guest["ipv6_routes"]
                  if guest["ipv4_routes"] is not None and guest["ipv6_routes"] is not None else None)
        result = evaluate_guest(settings, guest["links"], guest["addresses"], routes, guest["qdiscs"], filters)
        if errors:
            result["blockers"] = ["Guest inspection command failed: " + error for error in errors] + result["blockers"]
            result["guest_checks"] = "BLOCKED"
        result.update({"read_only": True, "tools": tools, "command_errors": errors,
                       "host_read_only_suggestions": _suggestions(settings),
                       "private_backend": {"client_ipv4": CLIENT_IP, "server_ipv4": SERVER_IP,
                                           "physical_config_applied": False},
                       "scope": "Guest observations only; host/Windows identity, physical traffic, rollback and attachment are not proven."})
        recorder.write_json("guest.json", guest)
        recorder.write_json("preflight.json", result)
        print(json.dumps({"status": result["status"], "stage08": result["stage08"],
                          "out": str(recorder.out), "blockers": result["blockers"]}, indent=2))
        return 1
    finally:
        recorder.close()


if __name__ == "__main__":
    raise SystemExit(main())
