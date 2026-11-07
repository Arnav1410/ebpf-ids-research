"""Disposable namespace/veth topology; no host network reconfiguration."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

CLIENT_NS = "ids_client"
SERVER_NS = "ids_server"
CLIENT_IF = "veth-idsc"
SERVER_IF = "veth-idss"
CLIENT_IP = "33.33.33.73"
SERVER_IP = "33.33.33.1"
NETWORK = ipaddress.ip_network("33.33.33.0/24")


def _stable(value):
    volatile = {"stats", "stats64", "xstats", "cacheinfo", "valid_life_time",
                "preferred_life_time", "expires", "age", "lastuse", "used",
                "bytes", "packets", "drops", "overlimits", "requeues", "backlog", "qlen"}
    if isinstance(value, dict):
        return {key: _stable(item) for key, item in value.items() if key not in volatile}
    if isinstance(value, list):
        return sorted((_stable(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


class Lab:
    def __init__(self, recorder):
        self.recorder = recorder
        self._token = "nn-ebpf-stage02-" + uuid.uuid4().hex
        self._namespaces = {}
        self._links = {}
        self._entered = False
        self._cleaned = False
        self.host_before = None
        self.host_after = None
        self.state = {"ownership_token": self._token, "namespaces": self._namespaces,
                      "links": self._links, "cleanup_complete": False}

    def _dump(self):
        self.recorder.write_json("lab-state.json", self.state)

    def _snapshot(self):
        commands = {
            "links": ["ip", "-j", "-d", "link", "show"],
            "addresses": ["ip", "-j", "address", "show"],
            "ipv4_routes": ["ip", "-j", "-4", "route", "show", "table", "all"],
            "ipv6_routes": ["ip", "-j", "-6", "route", "show", "table", "all"],
            "qdiscs": ["tc", "-j", "qdisc", "show"],
            "namespaces": ["ip", "-j", "netns", "list"],
        }
        return {key: self.recorder.json(argv) for key, argv in commands.items()}

    @staticmethod
    def _namespace_identity(name):
        entry = Path("/run/netns") / name
        if entry.is_symlink():
            raise RuntimeError(f"Refusing namespace symlink: {entry}")
        stat = entry.stat()
        return {"device": stat.st_dev, "inode": stat.st_ino}

    def _namespace_matches(self, name):
        try:
            return self._namespace_identity(name) == self._namespaces[name]
        except (OSError, RuntimeError):
            return False

    def _links_at(self, namespace=None):
        argv = ["ip"] + (["-n", namespace] if namespace else [])
        return self.recorder.json(argv + ["-j", "-d", "link", "show"])

    def _require_namespace(self, namespace):
        if not self._namespace_matches(namespace):
            raise RuntimeError(f"Refusing changed namespace identity: {namespace}")

    def _require_link(self, name, namespace):
        if namespace:
            self._require_namespace(namespace)
        identity = self._links.get(name)
        matches = [link for link in self._links_at(namespace) if link["ifname"] == name]
        if (identity is None or len(matches) != 1
                or matches[0]["ifindex"] != identity["ifindex"]
                or matches[0]["address"] != identity["address"]
                or matches[0].get("ifalias") != identity["alias"]):
            raise RuntimeError(f"Refusing changed interface identity: {name}")

    def _configure(self, namespace, interface, argv):
        self._require_link(interface, namespace)
        return self.recorder.run(["ip", "-n", namespace] + argv)

    def _remember_links(self):
        locations = [name for name in self._namespaces if self._namespace_matches(name)]
        for namespace in locations:
            for link in self._links_at(namespace):
                name = link["ifname"]
                if name in (CLIENT_IF, SERVER_IF) and link.get("ifalias") == self._token:
                    old = self._links.get(name)
                    if old is not None and (old["ifindex"] != link["ifindex"]
                                            or old["address"] != link["address"]):
                        raise RuntimeError(f"Owned interface identity changed: {name}")
                    self._links[name] = {"ifindex": link["ifindex"], "alias": self._token,
                                         "address": link["address"], "namespace": namespace}
        self._dump()

    def _record_created_pair(self):
        for name, namespace in ((CLIENT_IF, CLIENT_NS), (SERVER_IF, SERVER_NS)):
            self._require_namespace(namespace)
            matches = [link for link in self._links_at(namespace) if link["ifname"] == name]
            if len(matches) != 1 or matches[0].get("linkinfo", {}).get("info_kind") != "veth":
                raise RuntimeError("Successful creation did not identify the namespaced veth pair")
            link = matches[0]
            self._links[name] = {"ifindex": link["ifindex"], "address": link["address"],
                                 "alias": link.get("ifalias"), "namespace": namespace}
        self._dump()

    def _preflight(self):
        if os.geteuid() != 0:
            raise RuntimeError("The isolated network lab requires root")
        for tool in ("ip", "tc", "ping", "python3"):
            if shutil.which(tool) is None:
                raise RuntimeError(f"Missing required command: {tool}")
        self.host_before = self._snapshot()
        self.state["host_before"] = self.host_before
        self.recorder.write_json("host-before.json", self.host_before)
        names = {item["name"] for item in self.host_before["namespaces"]}
        for name in (CLIENT_NS, SERVER_NS):
            if name in names or os.path.lexists(Path("/run/netns") / name):
                raise RuntimeError(f"Namespace name is already occupied: {name}")
        interfaces = {item["ifname"] for item in self.host_before["links"]}
        if interfaces.intersection((CLIENT_IF, SERVER_IF)):
            raise RuntimeError("A lab interface name is already occupied")
        for route in self.host_before["ipv4_routes"]:
            destination = route.get("dst", "default")
            if destination not in ("default", "0.0.0.0/0"):
                if NETWORK.overlaps(ipaddress.ip_network(destination, strict=False)):
                    raise RuntimeError(f"Existing non-default route overlaps lab network: {route}")
        for interface in self.host_before["addresses"]:
            for address in interface.get("addr_info", []):
                if address.get("family") == "inet" and ipaddress.ip_address(address["local"]) in NETWORK:
                    raise RuntimeError("A host address already occupies the lab network")
        self.state["preflight"] = "pass"
        self._dump()

    def __enter__(self):
        if self._entered:
            raise RuntimeError("Lab contexts cannot be reused")
        self._entered = True
        try:
            self._preflight()
            for name in (CLIENT_NS, SERVER_NS):
                self.recorder.run(["ip", "netns", "add", name])
                self._namespaces[name] = self._namespace_identity(name)
                self._dump()
            # Create both endpoints privately, avoiding host-scope device-manager
            # MAC changes between creation and ownership checks.
            self.recorder.run(["ip", "-n", CLIENT_NS, "link", "add", "name", CLIENT_IF,
                               "type", "veth", "peer", "name", SERVER_IF, "netns", SERVER_NS])
            self._record_created_pair()
            for name, namespace in ((CLIENT_IF, CLIENT_NS), (SERVER_IF, SERVER_NS)):
                self._require_link(name, namespace)
                try:
                    self.recorder.run(["ip", "-n", namespace, "link", "set",
                                       "dev", name, "alias", self._token])
                finally:
                    self._remember_links()
                if self._links[name]["alias"] != self._token:
                    raise RuntimeError(f"Ownership alias was not applied: {name}")
            for name, namespace, address in ((CLIENT_IF, CLIENT_NS, CLIENT_IP),
                                             (SERVER_IF, SERVER_NS, SERVER_IP)):
                self._configure(namespace, name, ["addr", "add", address + "/24", "dev", name])
                self._configure(namespace, name, ["link", "set", "dev", "lo", "up"])
                self._configure(namespace, name, ["link", "set", "dev", name, "up"])
            self.state["setup"] = "pass"
            self.state["topology"] = {"client_namespace": CLIENT_NS, "server_namespace": SERVER_NS,
                                      "client_interface": CLIENT_IF, "server_interface": SERVER_IF,
                                      "client_ip": CLIENT_IP, "server_ip": SERVER_IP, "prefixlen": 24}
            self._dump()
            return self
        except BaseException as exc:
            self.state["setup_error"] = str(exc)
            try:
                self._cleanup()
            except BaseException as cleanup_error:
                self.state["cleanup_error"] = str(cleanup_error)
                self._dump()
                raise RuntimeError(f"Lab setup failed: {exc}; cleanup failed: {cleanup_error}") from exc
            raise

    def ping_checks(self):
        self._require_link(CLIENT_IF, CLIENT_NS)
        self._require_link(SERVER_IF, SERVER_NS)
        result = {}
        for direction, namespace, destination in (("client_to_server", CLIENT_NS, SERVER_IP),
                                                    ("server_to_client", SERVER_NS, CLIENT_IP)):
            completed = self.recorder.run(["ip", "netns", "exec", namespace, "ping", "-n", "-q",
                                           "-c", "3", "-W", "2", "-w", "10", destination], timeout=15)
            match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received,.*?"
                              r"([\d.]+)% packet loss", completed.stdout)
            if match is None or tuple(map(float, match.groups())) != (3.0, 3.0, 0.0):
                raise RuntimeError(f"Ping proof was not exactly 3/3 with zero loss: {direction}")
            result[direction] = {"transmitted": 3, "received": 3, "loss_percent": 0,
                                 "namespace": namespace, "destination": destination,
                                 "stdout": completed.stdout, "status": "pass"}
        result["status"] = "pass"
        self.state["ping"] = result
        self._dump()
        return result

    def exchange(self, reset=False):
        self._require_link(CLIENT_IF, CLIENT_NS)
        self._require_link(SERVER_IF, SERVER_NS)
        mode = "reset" if reset else "graceful"
        ready = self.recorder.out / ("tcp-ready-" + uuid.uuid4().hex + ".json")
        server_argv = ["ip", "netns", "exec", SERVER_NS, "python3", "-B", "-m", "test_env.traffic",
                       "server", "--ready", str(ready), "--seconds", "15"]
        client_argv = ["ip", "netns", "exec", CLIENT_NS, "python3", "-B", "-m", "test_env.traffic",
                       "client", "--seconds", "15"]
        if reset:
            server_argv.append("--reset")
            client_argv.append("--reset")
        proc = self.recorder.spawn("tcp-" + mode, server_argv)
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    raise RuntimeError("TCP server exited before readiness")
                try:
                    marker = json.loads(ready.read_text(encoding="utf-8"))
                except (FileNotFoundError, json.JSONDecodeError):
                    marker = None
                if marker is not None:
                    if marker != {"pid": proc.pid, "server_ip": SERVER_IP,
                                  "server_port": 5001, "reset": reset}:
                        raise RuntimeError("TCP server ready marker did not match owned fixture")
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("TCP fixture readiness deadline expired")
                time.sleep(0.02)
            client = self.recorder.json(client_argv, timeout=20)
            proc.wait(timeout=20)
            self.recorder.stop(proc)
            if proc.returncode != 0:
                raise RuntimeError(f"TCP server failed with exit {proc.returncode}")
            server = json.loads(proc.stdout_path.read_text(encoding="utf-8"))
            for field in ("client_port", "server_port", "request_bytes", "response_bytes"):
                if client[field] != server[field]:
                    raise RuntimeError(f"TCP endpoint proof disagrees on {field}")
            if client.get("status") != "pass" or server.get("status") != "pass":
                raise RuntimeError("TCP fixture did not report success on both endpoints")
            result = {"status": "pass", "reset": reset, "client": client, "server": server,
                      **{field: client[field] for field in ("client_port", "server_port",
                                                            "request_bytes", "response_bytes")}}
            self.state.setdefault("exchanges", []).append(result)
            self._dump()
            return result
        finally:
            self.recorder.stop(proc)

    def _cleanup(self):
        if self._cleaned:
            return
        errors = []
        try:
            self.recorder.stop_children()
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
        children_stopped = not errors
        # Never delete a namespace under a still-running child or a changed mount.
        if children_stopped:
            for namespace in self._namespaces:
                if not self._namespace_matches(namespace):
                    errors.append(f"Namespace identity changed or disappeared: {namespace}")
            live_links = []
            for name, identity in self._links.items():
                namespace = identity["namespace"]
                if namespace and not self._namespace_matches(namespace):
                    continue
                try:
                    matches = [link for link in self._links_at(namespace) if link["ifname"] == name]
                    if not matches:
                        continue
                    self._require_link(name, namespace)
                    live_links.append((name, namespace))
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    errors.append(f"Interface ownership check {name}: {exc}")
            if live_links and len(live_links) != len(self._links):
                errors.append("Only part of the owned veth pair can be identified; refusing deletion")
            # Removing either veth destroys its peer too. Check both directions
            # on both endpoints before deleting a link with remaining filters.
            for name, namespace in live_links:
                if errors:
                    break
                try:
                    self._require_namespace(namespace)
                    for direction in ("ingress", "egress"):
                        filters = self.recorder.json(["ip", "netns", "exec", namespace,
                            "tc", "-j", "filter", "show", "dev", name, direction])
                        if filters:
                            raise RuntimeError(f"TC filters remain on {namespace}/{name}/{direction}")
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                    errors.append(f"Refusing veth deletion: {exc}")
            # Check both endpoints first: deleting one also destroys its peer.
            if live_links and not errors:
                name, namespace = live_links[0]
                try:
                    self._require_link(name, namespace)
                    argv = ["ip"] + (["-n", namespace] if namespace else [])
                    self.recorder.run(argv + ["link", "del", "dev", name])
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    errors.append(f"Interface cleanup {name}: {exc}")
            for namespace in reversed(list(self._namespaces)):
                if not self._namespace_matches(namespace):
                    continue
                try:
                    remaining = self._links_at(namespace)
                    if any(link["ifname"] != "lo" for link in remaining):
                        raise RuntimeError("Namespace contains unremoved or foreign interfaces")
                    pids = self.recorder.run(["ip", "netns", "pids", namespace]).stdout.strip()
                    if pids:
                        raise RuntimeError("Namespace still contains processes; refusing deletion")
                    self.recorder.run(["ip", "netns", "del", namespace])
                    if os.path.lexists(Path("/run/netns") / namespace):
                        raise RuntimeError("Namespace mount remains after deletion")
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    errors.append(f"Namespace cleanup {namespace}: {exc}")
        if self.host_before is not None:
            try:
                self.host_after = self._snapshot()
                self.state["host_after"] = self.host_after
                self.recorder.write_json("host-after.json", self.host_after)
                preserved = _stable(self.host_before) == _stable(self.host_after)
                self.state["host_preserved"] = preserved
                if not preserved:
                    errors.append("Initial/final host network snapshots differ")
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                errors.append(f"Final host snapshot failed: {exc}")
        self.state["cleanup_errors"] = errors
        self.state["cleanup_complete"] = not errors
        self._cleaned = True
        self._dump()
        if errors:
            raise RuntimeError("Lab cleanup failed: " + "; ".join(errors))

    def __exit__(self, exc_type, exc, traceback):
        try:
            self._cleanup()
        except BaseException as cleanup_error:
            if exc is None:
                raise
            raise RuntimeError(f"Lab operation failed: {exc}; cleanup failed: {cleanup_error}") from exc
        return False
