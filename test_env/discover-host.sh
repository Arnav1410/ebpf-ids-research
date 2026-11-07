#!/usr/bin/env bash
# Standalone, read-only Stage08 inventory; JSON stdout, diagnostics stderr.
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'discover-host: python3 is required' >&2
    TZ=UTC printf -v collected_at '%(%Y-%m-%dT%H:%M:%SZ)T' -1
    printf '{"schema":"nn-ebpf-lab-discovery","schema_version":1,"role":"linux-host","collected_at":"%s","read_only":true,"selection":{},"data":{},"errors":[{"section":"runtime","message":"python3 is required"}]}\n' "$collected_at"
    exit 1
fi
exec python3 - "$@" <<'PY'
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


parser = argparse.ArgumentParser(description="Read-only Linux/libvirt lab inventory (JSON stdout)")
parser.add_argument("--vm", required=True)
parser.add_argument("--wired", required=True)
parser.add_argument("--uri", default="qemu:///system")
args = parser.parse_args()
for label, value in (("--vm", args.vm), ("--wired", args.wired)):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value):
        parser.error(label + " must be a non-option name without whitespace or shell syntax")
if len(args.wired) > 15 or ":" in args.wired:
    parser.error("--wired must be a Linux interface name of at most 15 characters")
if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s]+", args.uri):
    parser.error("--uri must be a libvirt URI without whitespace")

report = {
    "schema": "nn-ebpf-lab-discovery", "schema_version": 1,
    "role": "linux-host", "read_only": True,
    "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "selection": {"vm_name": args.vm, "libvirt_uri": args.uri, "wired_iface": args.wired},
    "data": {}, "errors": [],
}
data = report["data"]


def error(section, message, argv=None):
    entry = {"section": section, "message": str(message)}
    if argv is not None:
        entry["argv"] = argv
    report["errors"].append(entry)


def command(section, argv, allow_empty=False):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                errors="replace", timeout=15, check=False,
                                env=dict(os.environ, LC_ALL="C", LANG="C"))
    except (OSError, subprocess.TimeoutExpired) as exc:
        error(section, exc, argv)
        return None
    if result.returncode:
        error(section, "exit {}: {}".format(result.returncode,
              result.stderr.strip() or result.stdout.strip() or "no diagnostic output"), argv)
        return None
    if result.stderr.strip():
        # Retain command warnings without mixing them into the JSON stream.
        print("{}: {}".format(section, result.stderr.strip()), file=sys.stderr)
    if not result.stdout.strip() and not allow_empty:
        error(section, "command returned empty output", argv)
        return None
    return result.stdout


def json_array(section, argv):
    text = command(section, argv)
    if text is None:
        return None
    try:
        value = json.loads(text)
        if not isinstance(value, list):
            raise ValueError("expected a JSON array")
        return value
    except (ValueError, TypeError) as exc:
        error(section, "invalid command JSON: " + str(exc), argv)
        return None


def read_text(section, path):
    try:
        with open(path, encoding="utf-8") as stream:
            return stream.read().strip()
    except OSError as exc:
        error(section, exc)
        return None


def memory_element(root, tag, required=False):
    node = root.find(tag)
    if node is None:
        if required:
            raise ValueError("missing domain " + tag)
        return None
    return {"value": int(node.text), "unit": node.get("unit", "KiB")}


def normalize_domain(text):
    root = ET.fromstring(text)
    name = root.findtext("name")
    uuid = root.findtext("uuid")
    if name != args.vm:
        raise ValueError("domain name does not match selected VM")
    if not uuid:
        raise ValueError("missing domain UUID")
    interfaces = []
    for node in root.findall("./devices/interface"):
        mac = node.find("mac")
        if mac is None or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac.get("address", "")):
            raise ValueError("missing or invalid domain interface MAC")
        source, target, model = node.find("source"), node.find("target"), node.find("model")
        interfaces.append({"type": node.get("type", ""), "mac": mac.get("address").lower(),
                           "source": dict(source.attrib) if source is not None else {},
                           "target": target.get("dev") if target is not None else None,
                           "model": model.get("type") if model is not None else None})
    disks = []
    for node in root.findall("./devices/disk"):
        source, target, driver = node.find("source"), node.find("target"), node.find("driver")
        if target is None or not target.get("dev"):
            raise ValueError("missing disk target")
        disks.append({"type": node.get("type", ""), "device": node.get("device", "disk"),
                      "target": target.get("dev"),
                      "driver_type": driver.get("type") if driver is not None else None,
                      "source": dict(source.attrib) if source is not None else {},
                      "readonly": node.find("readonly") is not None, "snapshot": node.get("snapshot")})
    return {"name": name, "uuid": uuid, "memory": memory_element(root, "memory", True),
            "current_memory": memory_element(root, "currentMemory"),
            "interfaces": interfaces, "disks": disks}


for key, argv in (
    ("links", ["ip", "-j", "-d", "link", "show"]),
    ("addresses", ["ip", "-j", "address", "show"]),
    ("ipv4_routes", ["ip", "-j", "-4", "route", "show", "table", "all"]),
    ("ipv6_routes", ["ip", "-j", "-6", "route", "show", "table", "all"]),
    ("ipv4_rules", ["ip", "-j", "-4", "rule", "show"]),
):
    data[key] = json_array(key, argv)
if data["links"] is not None and not any(link.get("ifname") == args.wired for link in data["links"]):
    error("wired_iface", "selected wired interface was not found in link inventory")

virsh = ["virsh", "--readonly", "--connect", args.uri]
xml = command("domain", virsh + ["dumpxml", args.vm])
data["domain"] = None
if xml is not None:
    try:
        data["domain"] = normalize_domain(xml)
    except (ET.ParseError, ValueError, TypeError) as exc:
        error("domain", "invalid domain XML: " + str(exc))
state = command("domain_state", virsh + ["domstate", args.vm])
data["domain_state"] = state.strip() if state is not None else None
for key, operation in (("snapshot_names", "snapshot-list"), ("checkpoint_names", "checkpoint-list")):
    text = command(key, virsh + [operation, args.vm, "--name"], allow_empty=True)
    data[key] = [name for name in text.splitlines() if name.strip()] if text is not None else None
# Names are metadata inventory only; neither snapshots nor checkpoints establish recoverability.
data["snapshot_inventory_is_recovery_proof"] = False

data["disk_filesystems"] = None
if data["domain"] is not None:
    data["disk_filesystems"] = []
    for disk in data["domain"]["disks"]:
        if disk["type"] != "file" or not disk["source"].get("file"):
            continue
        path = disk["source"]["file"]
        parent = os.path.dirname(os.path.abspath(path))
        entry = {"target": disk["target"], "file": path, "parent": parent,
                 "available_bytes": None, "free_bytes": None, "total_bytes": None}
        try:
            stat = os.statvfs(parent)
            entry.update(available_bytes=stat.f_bavail * stat.f_frsize,
                         free_bytes=stat.f_bfree * stat.f_frsize,
                         total_bytes=stat.f_blocks * stat.f_frsize)
        except OSError as exc:
            error("disk_filesystems", "{}: {}".format(parent, exc))
        data["disk_filesystems"].append(entry)

meminfo = read_text("host_memory", "/proc/meminfo")
data["host_memory"] = None
if meminfo is not None:
    values = {}
    for line in meminfo.splitlines():
        match = re.fullmatch(r"(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+) kB", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    if "MemTotal" not in values or "MemAvailable" not in values:
        error("host_memory", "MemTotal or MemAvailable unavailable in /proc/meminfo")
    data["host_memory"] = {key: values.get(source) for key, source in
                           (("total_bytes", "MemTotal"), ("available_bytes", "MemAvailable"),
                            ("swap_total_bytes", "SwapTotal"), ("swap_free_bytes", "SwapFree"))}

data["wired_driver"] = None
driver_path = "/sys/class/net/{}/device/driver".format(args.wired)
try:
    driver = os.readlink(driver_path)
    module_path = driver_path + "/module"
    module = os.path.basename(os.readlink(module_path)) if os.path.islink(module_path) else None
    data["wired_driver"] = {"name": os.path.basename(driver), "module": module}
except OSError as exc:
    error("wired_driver", exc)


def nm_fields(section, fields, suffix):
    argv = ["nmcli", "--terse", "--escape", "yes", "--fields", ",".join(fields)] + suffix
    text = command(section, argv)
    if text is None:
        return None
    result = {}
    for line in text.splitlines():
        if ":" not in line:
            error(section, "invalid terse nmcli field output", argv)
            return None
        key, value = line.split(":", 1)
        # nmcli terse escaping protects colons and backslashes; no shell parsing.
        value = re.sub(r"\\([\\:])", r"\1", value)
        result[key] = value
    missing = set(fields) - set(result)
    if missing:
        error(section, "missing nmcli fields: " + ", ".join(sorted(missing)), argv)
        return None
    return result


device_fields = ["GENERAL.DEVICE", "GENERAL.TYPE", "GENERAL.STATE", "GENERAL.CONNECTION", "GENERAL.CON-UUID"]
data["network_manager"] = {"device": nm_fields("network_manager.device", device_fields,
                                                ["device", "show", args.wired]),
                           "profile": None}
device = data["network_manager"]["device"]
if device is not None:
    active_uuid = device.get("GENERAL.CON-UUID", "")
    if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", active_uuid):
        fields = ["connection.id", "connection.uuid", "connection.type", "connection.interface-name",
                  "connection.master", "connection.autoconnect", "connection.autoconnect-priority"]
        for family in ("ipv4", "ipv6"):
            fields.extend(family + "." + key for key in
                          ("method", "addresses", "gateway", "dns", "dns-search", "routes", "route-metric",
                           "ignore-auto-dns", "ignore-auto-routes", "never-default"))
        data["network_manager"]["profile"] = nm_fields("network_manager.profile", fields,
                                                       ["connection", "show", "uuid", active_uuid])
    else:
        error("network_manager.profile", "selected device has no active connection UUID; profile unavailable")

json.dump(report, sys.stdout, indent=2, ensure_ascii=True)
sys.stdout.write("\n")
sys.exit(1 if report["errors"] else 0)
PY
