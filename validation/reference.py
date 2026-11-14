"""Independent, standard-library-only reference; never imports production Python.

Explicit two's-complement bit-vector semantics model BPF integer widths. Cases
that overflow signed C are reported, not described as portable C behavior or
proof of compiler/JIT behavior. Division by zero is rejected, not silently
treated as the paper's zero-standard-deviation branch.
"""
import ast
from dataclasses import dataclass
from pathlib import Path
import re
import struct

Q = 1 << 16
I32_MIN, I32_MAX = -(1 << 31), (1 << 31) - 1
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
U64_MAX = (1 << 64) - 1
STAGES = ("normalized", "linear0", "relu0", "linear1", "relu1", "logits")
SIZES = (6, 32, 32, 32, 32, 2)


def signed(value, bits):
    value %= 1 << bits
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value


def event(events, kind, **details):
    if events is not None:
        events.append(dict(kind=kind, **details))


def normalize(x, mean, scale, events=None):
    if not len(x) == len(mean) == len(scale):
        raise ValueError("normalization dimensions differ")
    output = []
    for j, (value, mu, sigma) in enumerate(zip(x, mean, scale)):
        if any(not I64_MIN <= n <= I64_MAX for n in (value, mu, sigma)):
            raise ValueError("normalization arguments must fit int64")
        divisor = sigma & U64_MAX
        if not divisor:
            raise ZeroDivisionError("source has no zero-scale guard; native C division is undefined")
        if sigma < 0:
            event(events, "negative_scale_cast_unsigned", feature=j, scale=sigma)
        magnitude = abs(mu - value)
        numerator = magnitude * Q
        if numerator > U64_MAX:
            event(events, "normalization_uint64_multiply_wrap", feature=j, exact=numerator)
        quotient = (numerator & U64_MAX) // divisor
        narrowed = signed(quotient, 32)
        if quotient > I32_MAX:
            event(events, "normalization_int32_narrow", feature=j, quotient=quotient)
        if value < mu:
            if narrowed == I32_MIN:
                event(events, "signed_int32_negation_overflow", feature=j)
            narrowed = signed(-narrowed, 32)
        output.append(narrowed)
    return output


def linear(weights, x, rows, events=None, layer="linear"):
    if len(weights) != rows * len(x) or not x:
        raise ValueError("linear dimensions differ")
    if any(not I32_MIN <= n <= I32_MAX for n in (*weights, *x)):
        raise ValueError("linear inputs must fit int32")
    output = []
    for i in range(rows):
        total = 0
        for j, value in enumerate(x):
            # The int64 cast occurs BEFORE multiplication in production code.
            total += weights[i * len(x) + j] * value
            if not I64_MIN <= total <= I64_MAX:
                event(events, "signed_int64_accumulator_overflow", layer=layer, row=i, column=j)
                total = signed(total, 64)
        shifted = total >> 16  # Arithmetic right shift: floor, including negatives.
        if not I32_MIN <= shifted <= I32_MAX:
            event(events, "linear_int32_narrow", layer=layer, row=i, shifted=shifted)
        output.append(signed(shifted, 32))
    return output


def prediction(logits):
    return 0 if logits[0] > logits[1] else 1


def paper_prediction(logits):
    return int(logits[1] > logits[0])


@dataclass
class Model:
    weights: list
    mean: list
    scale: list

    @classmethod
    def load(cls, path):
        text = Path(path).read_text()
        macros = dict((k, int(v)) for k, v in re.findall(
            r"^#define\s+(FIX_POINT|N[0-3])\s+(\d+)\s*$", text, re.M))
        if macros != dict(FIX_POINT=16, N0=6, N1=32, N2=32, N3=2):
            raise ValueError("validation targets the current 6/32/32/2, Q16 baseline")
        arrays = {}
        for name, length in (("layer_0_weight", 192), ("layer_1_weight", 1024),
                             ("layer_2_weight", 64), ("mean", 6), ("scale", 6)):
            match = re.search(r"\b" + name + r"\[(\d+)\]\s*=\s*\{([^}]+)\}", text)
            if not match or int(match[1]) != length:
                raise ValueError(f"missing/wrong array: {name}")
            parts = [v.strip() for v in match[2].split(",") if v.strip()]
            if len(parts) != length or any(not re.fullmatch(r"-?\d+", v) for v in parts):
                raise ValueError(f"nonliteral/wrong-sized array: {name}")
            arrays[name] = list(map(int, parts))
        if any(v <= 0 for v in arrays["scale"]):
            raise ValueError("checked-in scales must be positive")
        return cls([arrays[f"layer_{i}_weight"] for i in range(3)], arrays["mean"], arrays["scale"])

    def infer(self, raw, events=None):
        stages = [normalize(raw, self.mean, self.scale, events)]
        for layer, rows in enumerate((32, 32, 2)):
            stages.append(linear(self.weights[layer], stages[-1], rows, events, f"linear{layer}"))
            if layer < 2:
                stages.append([max(0, x) for x in stages[-1]])
        return dict(zip(STAGES, stages)), prediction(stages[-1])

    def packed(self):
        return (b"".join(struct.pack("<" + "i" * len(w), *w) for w in self.weights)
                + struct.pack("<6q", *self.mean) + struct.pack("<6q", *self.scale))

    def surrogate_float(self, raw):
        """Diagnostic only: dequantized header weights, NOT original FP32 model."""
        stages = [[(x - mu) / sigma for x, mu, sigma in zip(raw, self.mean, self.scale)]]
        for weights, rows in zip(self.weights, (32, 32, 2)):
            x = stages[-1]
            stages.append([sum(weights[i * len(x) + j] / Q * v for j, v in enumerate(x))
                           for i in range(rows)])
            if rows != 2:
                stages.append([max(0.0, v) for v in stages[-1]])
        return dict(zip(STAGES, stages))


def read_npy_rows(path):
    """Read just the supplied numeric NPY format; no pickle, NumPy, or execution."""
    with Path(path).open("rb") as f:
        if f.read(8) != b"\x93NUMPY\x01\x00":
            raise ValueError("expected NPY 1.0")
        length = struct.unpack("<H", f.read(2))[0]
        header = ast.literal_eval(f.read(length).decode("latin1"))
        if (header["descr"] != "<i8" or header["fortran_order"]
                or len(header["shape"]) != 2 or header["shape"][1] != 6):
            raise ValueError("expected row-major little-endian int64 six-feature matrix")
        payload = f.read()
        if len(payload) != header["shape"][0] * 48:
            raise ValueError("truncated or trailing NPY data")
    return list(struct.iter_unpack("<6q", payload))


class FlowReference:
    """Independent byte decoder for CURRENT source, including known parser defects.

    Hand-calculated feature expectations in tests supply the separate oracle for
    intended ordinary IPv4/TCP packets. This class does not repair the parser.
    """
    def __init__(self, capacity=64):
        self.flows = {}
        self.capacity = capacity
        self.inferences = 0

    def packet(self, packet, ns):
        if (len(packet) < 54 or packet[12:14] != b"\x08\x00" or packet[23] != 6):
            return None
        source, dest = struct.unpack_from("!II", packet, 26)
        sport, dport = struct.unpack_from("!HH", packet, 34)
        if source != 555819337:
            return None
        key = source, sport, dest, dport
        if key not in self.flows:
            if len(self.flows) == self.capacity:
                return None
            self.flows[key] = [0, 0, 0x3fffffffffffffff, dport, 0, 0, ns, 0]
        state = self.flows[key]
        length = (struct.unpack_from("!H", packet, 16)[0] - (packet[14] & 15) * 4) & U64_MAX
        if length > (state[0] & U64_MAX):
            state[0] = signed(length, 64)
        if length < (state[2] & U64_MAX):
            state[2] = signed(length, 64)
        duration = (ns - state[6]) & U64_MAX
        if duration > (state[1] & U64_MAX):
            state[1] = signed(duration, 64)
        state[4] = signed(state[4] + (packet[46] >> 4) * 4, 64)
        state[5] = signed(state[5] + 1, 64)
        state[6] = ns
        if packet[47] & 5:  # FIN OR RST; current source includes closing packet.
            state[7] = ns
            self.inferences += 1
        return state


def tcp_packet(source="33.33.33.73", dest="33.33.33.1", sport=12345, dport=5001,
               flags=0x10, payload=b"", tcp_options=b"", ip_options=b"", total_length=None,
               protocol=6, ethertype=0x0800):
    """Controlled Ethernet/IPv4/TCP bytes; checksums unused by offline parser.

    These fixtures are NOT injected, and do not claim NIC/kernel acceptance.
    """
    import socket
    if len(tcp_options) % 4 or len(ip_options) % 4:
        raise ValueError("options must be padded to four bytes")
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0,
                      (5 + len(tcp_options) // 4) << 4, flags, 4096, 0, 0)
    length = 40 + len(tcp_options) + len(ip_options) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45 + len(ip_options) // 4, 0,
                     length if total_length is None else total_length, 1, 0, 64,
                     protocol, 0, socket.inet_aton(source), socket.inet_aton(dest))
    return bytes(12) + struct.pack("!H", ethertype) + ip + ip_options + tcp + tcp_options + payload
