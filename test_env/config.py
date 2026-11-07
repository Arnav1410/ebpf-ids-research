"""Literal, non-executable lab settings; process environment is never consulted."""
from dataclasses import asdict, dataclass
import ipaddress
import math
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent


class ConfigError(ValueError):
    """An environment file is missing, malformed, or contains an invalid setting."""


@dataclass(frozen=True)
class Settings:
    vm_name: str | None = None
    libvirt_uri: str = "qemu:///system"
    host_wired_iface: str | None = None
    management_iface: str = "enp1s0"
    management_mac: str = "52:54:00:73:34:a0"
    demo_iface: str | None = None
    demo_mac: str | None = None
    client_ipv4: str | None = None
    demo_ipv4: str | None = None
    tcp_port: int = 5001
    dashboard_port: int = 8765
    run_seconds: int = 120
    replay_interval: float = 0.5
    loader: Path = ROOT / ".output/test-env-stage-06/build/nn-loader"
    bpf_object: Path = ROOT / ".output/test-env-stage-06/build/nn.bpf.o"
    bpftool: Path = ROOT / ".output/test-env-stage-01/deps/bpftool/bpftool"
    reader: Path | None = None
    model: Path = ROOT / "src/mlp_params.bpf.h"
    sample: Path | None = None
    out: Path | None = None
    config_file: Path | None = None

    def as_dict(self):
        return {key: str(value) if isinstance(value, Path) else value
                for key, value in asdict(self).items()}


# Field names and optionality are explicit so misspelled settings never disappear.
_FIELDS = {
    "IDS_VM_NAME": ("vm_name", "name", True),
    "IDS_LIBVIRT_URI": ("libvirt_uri", "uri", False),
    "IDS_HOST_WIRED_IFACE": ("host_wired_iface", "iface", True),
    "IDS_GUEST_MANAGEMENT_IFACE": ("management_iface", "iface", False),
    "IDS_GUEST_MANAGEMENT_MAC": ("management_mac", "mac", False),
    "IDS_GUEST_DEMO_IFACE": ("demo_iface", "iface", True),
    "IDS_GUEST_DEMO_MAC": ("demo_mac", "mac", True),
    "IDS_CLIENT_IPV4": ("client_ipv4", "ipv4", True),
    "IDS_GUEST_DEMO_IPV4": ("demo_ipv4", "ipv4", True),
    "IDS_TCP_PORT": ("tcp_port", "port", False),
    "IDS_DASHBOARD_PORT": ("dashboard_port", "dashboard_port", False),
    "IDS_RUN_SECONDS": ("run_seconds", "seconds", False),
    "IDS_REPLAY_INTERVAL": ("replay_interval", "interval", False),
    "IDS_LOADER": ("loader", "path", False),
    "IDS_OBJECT": ("bpf_object", "path", False),
    "IDS_BPFTOOL": ("bpftool", "path", False),
    "IDS_READER": ("reader", "path", True),
    "IDS_MODEL": ("model", "path", False),
    "IDS_SAMPLE": ("sample", "path", True),
    "IDS_OUT": ("out", "path", True),
}


def _convert(value, kind, optional):
    if not value:
        if optional:
            return None
        raise ValueError("must not be empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("control characters are not allowed")
    if kind == "path":
        path = Path(value)
        return path if path.is_absolute() else ROOT / path
    if kind == "iface":
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", value) or value in (".", ".."):
            raise ValueError("expected an interface name of 1..15 ASCII characters")
    elif kind == "mac":
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value):
            raise ValueError("expected a six-octet colon-separated MAC address")
        if int(value[:2], 16) & 1 or value.lower() == "00:00:00:00:00:00":
            raise ValueError("expected a nonzero unicast MAC address")
        return value.lower()
    elif kind == "ipv4":
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback or int(address) == 0xffffffff:
            raise ValueError("expected a non-loopback unicast IPv4 address")
        return str(address)
    elif kind in ("port", "dashboard_port", "seconds"):
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError("expected a decimal integer")
        result = int(value)
        low, high = {"port": (1, 65535), "dashboard_port": (1024, 65535),
                     "seconds": (1, 240)}[kind]
        if not low <= result <= high:
            raise ValueError(f"must be in {low}..{high}")
        return result
    elif kind == "interval":
        if not re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value):
            raise ValueError("expected a finite decimal number")
        result = float(value)
        if not math.isfinite(result) or not 0.05 <= result <= 10:
            raise ValueError("must be finite and in 0.05..10 seconds")
        return result
    elif kind == "name":
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value):
            raise ValueError("expected a VM name, not shell syntax or options")
    elif kind == "uri":
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s]+", value):
            raise ValueError("expected a libvirt URI without whitespace")
    return value


def load_config(path=None):
    """Read only the selected UTF-8 file (or an optional repository .env).

    There is deliberately no dotenv/shell evaluation, escaping, interpolation,
    tilde expansion, inline comment handling, or process-environment override.
    Relative values for paths are repository-relative, unlike the file argument.
    """
    explicit = path is not None
    filename = Path(path).absolute() if explicit else ROOT / ".env"
    try:
        text = filename.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        if not explicit:
            return Settings()
        raise ConfigError(f"{filename}: cannot read configuration: {exc}") from exc
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"{filename}: cannot read UTF-8 configuration: {exc}") from exc
    values = {}
    seen = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        location = f"{filename}:{number}"
        if "=" not in line:
            raise ConfigError(f"{location}: expected KEY=VALUE")
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in _FIELDS:
            raise ConfigError(f"{location}: unknown configuration key {key!r}")
        if key in seen:
            raise ConfigError(f"{location}: duplicate configuration key {key}")
        seen.add(key)
        if value.startswith(("'", '"')):
            quote = value[0]
            if len(value) < 2 or value[-1] != quote or quote in value[1:-1]:
                raise ConfigError(f"{location}: {key}: malformed outer quotes")
            value = value[1:-1]
        elif "'" in value or '"' in value:
            raise ConfigError(f"{location}: {key}: quotes must enclose the entire value")
        field, kind, optional = _FIELDS[key]
        try:
            values[field] = _convert(value, kind, optional)
        except ValueError as exc:
            raise ConfigError(f"{location}: {key}: {exc}") from exc
    return Settings(**values, config_file=filename)
