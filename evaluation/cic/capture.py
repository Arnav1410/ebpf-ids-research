"""Bounded read-only classic PCAP/PCAPNG reader and ingress feature snapshots.

PCAPNG: IETF draft-ietf-opsawg-pcapng-06, sections 3, 4.1--4.4,
and Appendix A. Unknown metadata blocks are counted, not interpreted/executed.
This is an offline observation model, never a live kernel clock or label oracle.
"""
from dataclasses import dataclass
from array import array
import hashlib
import struct

MAX_BLOCK = 1 << 20
MAX_INTERFACES = 64
MAX_SECTIONS = 1024
I64_MAX = (1 << 63) - 1
SHB = b"\x0a\x0d\x0d\x0a"
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class CaptureError(ValueError):
    pass


class PacketError(ValueError):
    """Explicit exclusion reason; not a negative classification."""


@dataclass(frozen=True)
class Packet:
    index: int
    block_index: int
    offset: int
    section: int
    interface: int
    timestamp_ns: int | None
    wire_length: int
    linktype: int
    data: bytes

    def reference(self):
        return dict(packet_index=self.index, block_index=self.block_index,
                    file_offset=self.offset, section=self.section,
                    interface=self.interface, timestamp_ns=self.timestamp_ns,
                    captured_length=len(self.data), wire_length=self.wire_length)


@dataclass(frozen=True)
class TCP:
    source_ip: int
    source_port: int
    destination_ip: int
    destination_port: int
    segment_bytes: int
    header_bytes: int
    flags: int
    sequence: int


def options(body, order):
    pos = 0
    while pos < len(body):
        if pos + 4 > len(body):
            raise CaptureError("Truncated option header")
        code, length = struct.unpack_from(order + "HH", body, pos)
        pos += 4
        if code == 0:
            if length or any(body[pos:]):
                raise CaptureError("Invalid option terminator/padding")
            return
        padded = (length + 3) & ~3
        if pos + padded > len(body):
            raise CaptureError("Truncated option value")
        yield code, body[pos:pos + length]
        pos += padded


def timestamp(ticks, denominator, seconds_offset=0):
    ns, remainder = divmod(ticks * 1_000_000_000, denominator)
    ns += seconds_offset * 1_000_000_000
    if remainder:
        raise CaptureError("Timestamp cannot be represented as integer ns")
    if not 0 <= ns <= I64_MAX:
        raise CaptureError("Timestamp outside nonnegative int64 ns")
    return ns


class Reader:
    """Single-pass iterator. Allocations never depend on unchecked block sizes."""
    def __init__(self, path):
        self.path = path
        self.metadata = dict(format=None, sections=0, interfaces=[], blocks=0,
                             packets=0, block_types={})
        self._used = False
        self.complete = False
        self.digest = hashlib.sha256()
        self.md5 = hashlib.md5(usedforsecurity=False)  # Publisher checksum, not authentication.

    def __iter__(self):
        if self._used:
            raise CaptureError("Reader is single-pass; create a new one explicitly")
        self._used = True
        with open(self.path, "rb", buffering=1 << 20) as stream:
            magic = stream.read(4)
            stream.seek(0)
            class HashedStream:
                def read(inner, count):
                    value = stream.read(count)
                    self.digest.update(value)
                    self.md5.update(value)
                    return value

                def tell(inner):
                    return stream.tell()
            source = HashedStream()
            if magic in MAGICS:
                yield from self._classic(source, *MAGICS[magic])
            elif magic == SHB:
                yield from self._ng(source)
            else:
                raise CaptureError("Unsupported capture magic")
            self.complete = True

    @staticmethod
    def _read(stream, count):
        value = stream.read(count)
        if len(value) != count:
            raise CaptureError("Truncated capture at offset " + str(stream.tell()))
        return value

    def _classic(self, stream, order, denominator):
        header = self._read(stream, 24)
        major, minor, zone, sigfigs, snap, network = struct.unpack(order + "HHiIII", header[4:])
        if (major, minor) != (2, 4) or not 0 < snap <= MAX_BLOCK:
            raise CaptureError("Unsupported classic version/snaplen")
        # Historical 'thiszone' does not alter the stored Unix epoch timestamp.
        linktype = network & 0xffff
        self.metadata.update(format="pcap", sections=1,
                             interfaces=[dict(section=0, id=0, linktype=linktype,
                                              snaplen=snap, ticks_per_second=denominator,
                                              seconds_offset=0)])
        while True:
            offset = stream.tell()
            head = stream.read(16)
            if not head:
                return
            if len(head) != 16:
                raise CaptureError("Truncated classic packet header")
            sec, fraction, cap, wire = struct.unpack(order + "IIII", head)
            if fraction >= denominator or cap > snap or cap > wire:
                raise CaptureError("Invalid classic timestamp/packet lengths")
            data = self._read(stream, cap)
            self.metadata["packets"] += 1
            self.metadata["blocks"] += 1
            yield Packet(self.metadata["packets"], self.metadata["blocks"], offset,
                         0, 0, timestamp(sec * denominator + fraction, denominator),
                         wire, linktype, data)

    def _ng(self, stream):
        order = None
        interfaces = []
        self.metadata["format"] = "pcapng"
        while True:
            offset = stream.tell()
            head = stream.read(12)
            if not head:
                return
            if len(head) != 12:
                raise CaptureError("Truncated PCAPNG block header")
            if head[:4] == SHB:
                order = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(head[8:12])
                if order is None:
                    raise CaptureError("Invalid PCAPNG byte-order magic")
            if order is None:
                raise CaptureError("Packet before section header")
            kind, length = struct.unpack_from(order + "II", head)
            if not 12 <= length <= MAX_BLOCK or length % 4:
                raise CaptureError("Invalid/excessive PCAPNG block length")
            block = head + self._read(stream, length - 12)
            if struct.unpack_from(order + "I", block, length - 4)[0] != length:
                raise CaptureError("PCAPNG repeated block lengths disagree")
            body = memoryview(block)[8:-4]
            self.metadata["blocks"] += 1
            types = self.metadata["block_types"]
            key = str(kind)
            if key not in types and len(types) >= 256:
                key = "other"
            types[key] = types.get(key, 0) + 1
            if kind == 0x0a0d0d0a:
                if len(body) < 16 or struct.unpack_from(order + "HH", body, 4) != (1, 0):
                    raise CaptureError("Unsupported section version")
                section_length = struct.unpack_from(order + "q", body, 8)[0]
                if section_length < -1:
                    raise CaptureError("Invalid section length")
                list(options(body[16:], order))
                self.metadata["sections"] += 1
                if self.metadata["sections"] > MAX_SECTIONS:
                    raise CaptureError("Section resource limit")
                interfaces = []
                continue
            if kind == 1:
                if len(body) < 8 or len(interfaces) >= MAX_INTERFACES:
                    raise CaptureError("Invalid/excessive interface descriptions")
                linktype, reserved, snap = struct.unpack_from(order + "HHI", body)
                if snap > MAX_BLOCK:
                    raise CaptureError("Interface snaplen exceeds resource limit")
                denominator = 1_000_000
                seconds_offset = 0
                seen = set()
                for code, value in options(body[8:], order):
                    if code in (9, 14):
                        if code in seen:
                            raise CaptureError("Duplicate timestamp option")
                        seen.add(code)
                    if code == 9:
                        if len(value) != 1:
                            raise CaptureError("Invalid timestamp resolution")
                        exponent = value[0] & 127
                        if exponent > 63:
                            raise CaptureError("Timestamp resolution resource limit")
                        denominator = (2 if value[0] & 128 else 10) ** exponent
                    elif code == 14:
                        if len(value) != 8:
                            raise CaptureError("Invalid timestamp offset")
                        seconds_offset = struct.unpack(order + "q", value)[0]
                interface = dict(section=self.metadata["sections"] - 1,
                                 id=len(interfaces), linktype=linktype, snaplen=snap,
                                 ticks_per_second=denominator, seconds_offset=seconds_offset)
                interfaces.append(interface)
                self.metadata["interfaces"].append(interface)
                continue
            if kind not in (2, 3, 6):
                continue  # Metadata only; never a label or executable content.
            if kind in (2, 6):
                if len(body) < 20:
                    raise CaptureError("Short packet block")
                if kind == 6:
                    interface_id, high, low, cap, wire = struct.unpack_from(order + "IIIII", body)
                else:
                    interface_id, drops, high, low, cap, wire = struct.unpack_from(order + "HHIIII", body)
                if interface_id >= len(interfaces):
                    raise CaptureError("Unknown packet interface")
                interface = interfaces[interface_id]
                stamp = timestamp((high << 32) | low, interface["ticks_per_second"], interface["seconds_offset"])
                data_offset = 20
                padded = (cap + 3) & ~3
                if data_offset + padded > len(body):
                    raise CaptureError("Packet exceeds block")
                list(options(body[data_offset + padded:], order))
            else:
                if len(body) < 4 or not interfaces:
                    raise CaptureError("Simple packet without interface/data")
                interface_id = 0
                interface = interfaces[0]
                wire = struct.unpack_from(order + "I", body)[0]
                cap = min(wire, interface["snaplen"]) if interface["snaplen"] else wire
                data_offset = 4
                if len(body) != 4 + ((cap + 3) & ~3):
                    raise CaptureError("Invalid simple packet length")
                stamp = None  # Never invent a clock for an untimestamped packet.
            if cap > wire or cap > MAX_BLOCK or (interface["snaplen"] and cap > interface["snaplen"]):
                raise CaptureError("Invalid packet captured/wire/snap lengths")
            data = bytes(body[data_offset:data_offset + cap])
            self.metadata["packets"] += 1
            yield Packet(self.metadata["packets"], self.metadata["blocks"], offset,
                         interface["section"], interface_id, stamp, wire,
                         interface["linktype"], data)


def decode_tcp(packet):
    """Strict common supported subset; no checksum rejection absent in eBPF."""
    frame = packet.data
    if packet.linktype != 1:
        raise PacketError("UNSUPPORTED_LINKTYPE")
    if len(frame) < packet.wire_length:
        raise PacketError("TRUNCATED_PACKET")
    if len(frame) < 14:
        raise PacketError("SHORT_ETHERNET")
    if frame[12:14] != b"\x08\x00":
        raise PacketError("UNSUPPORTED_ETHERTYPE")
    if len(frame) < 34:
        raise PacketError("SHORT_IPV4")
    if frame[14] >> 4 != 4:
        raise PacketError("INVALID_IPV4_VERSION")
    ihl = (frame[14] & 15) * 4
    if ihl != 20:
        raise PacketError("IPV4_OPTIONS_OR_INVALID_IHL")
    if frame[23] != 6:
        raise PacketError("NON_TCP")
    total, fragment = struct.unpack_from("!H2xH", frame, 16)
    if fragment & 0x3fff:
        raise PacketError("IPV4_FRAGMENT")
    if total < 40 or total > len(frame) - 14 or len(frame) < 54:
        raise PacketError("INVALID_IPV4_LENGTH")
    tcp_offset = 14 + ihl
    header = (frame[tcp_offset + 12] >> 4) * 4
    if not 20 <= header <= 60 or total < ihl + header:
        raise PacketError("INVALID_TCP_HEADER_LENGTH")
    source, destination = struct.unpack_from("!II", frame, 26)
    sport, dport, sequence = struct.unpack_from("!HHI", frame, tcp_offset)
    return TCP(source, sport, destination, dport, total - ihl, header,
               frame[tcp_offset + 13], sequence)


class FeatureWindow:
    """One explicitly oriented session through its first incoming FIN/RST.

    Session start, NAT mapping, label matching and provenance are deliberately
    outside this arithmetic component and must pass separate gates.
    """
    def __init__(self, client, server, max_packets=1_000_000, compact=False):
        self.client = tuple(client)
        self.server = tuple(server)
        self.values = [0, 0, I64_MAX, self.server[1], 0, 0]
        self.last = None
        self.references = []
        self.compact = compact
        self.indices = array("Q")
        self.offsets = array("Q")
        self.snapshot = None
        self.max_packets = max_packets

    def add(self, packet, tcp):
        source = (tcp.source_ip, tcp.source_port)
        destination = (tcp.destination_ip, tcp.destination_port)
        if (source, destination) not in ((self.client, self.server), (self.server, self.client)):
            raise PacketError("ALIEN_SESSION_TUPLE")
        if self.snapshot is not None or source == self.server:
            return None
        now = packet.timestamp_ns
        if now is None:
            raise PacketError("MISSING_TIMESTAMP")
        if not 0 <= now <= I64_MAX:
            raise PacketError("TIMESTAMP_INT64_RANGE")
        if self.last is not None and now < self.last:
            raise PacketError("TIMESTAMP_REORDER")
        if self.values[5] >= self.max_packets:
            raise PacketError("FLOW_PACKET_RESOURCE_LIMIT")
        elapsed = 0 if self.last is None else now - self.last
        values = [max(self.values[0], tcp.segment_bytes), max(self.values[1], elapsed),
                  min(self.values[2], tcp.segment_bytes), self.server[1],
                  self.values[4] + tcp.header_bytes, self.values[5] + 1]
        if any(not 0 <= v <= I64_MAX for v in values):
            raise PacketError("FEATURE_INT64_OVERFLOW")
        self.values = values
        self.last = now
        if self.compact:
            self.indices.append(packet.index)
            self.offsets.append(packet.offset)
        else:
            self.references.append(packet.reference())
        if tcp.flags & 5:
            self.snapshot = dict(features=list(values), trigger=packet.reference(),
                                 trigger_flags=tcp.flags,
                                 packet_references=list(self.references))
            if self.compact:
                self.snapshot["forward_packet_indices"] = self.indices.tolist()
                self.snapshot["forward_packet_offsets"] = self.offsets.tolist()
            return self.snapshot
        return None
