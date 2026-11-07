"""Independent header oracle; clocks come only from real kernel observations.

AF_PACKET records prove headers, not wire segmentation: GRO/GSO can change the
TC/packet-socket observation granularity. IAT uses the kernel's lock-observed,
monotonically clamped clock, not AF_PACKET arrival time or an invented replay
clock. No wall-clock tolerance is applied to these exact integer reductions.
"""
from collections import Counter, defaultdict
import ipaddress
import struct


class Unsupported(ValueError):
    """A deliberately unsupported or malformed packet, with a stable reason."""


def parse_headers(raw, *, packet_length=None):
    """Parse Ethernet/IPv4/TCP independently, allowing header-only capture.

    packet_length is the original linear frame length, when known. Header-only
    ring observations omit payload intentionally, so their IP total length is
    checked against the declared headers rather than against captured payload.
    """
    raw = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw)
    if len(raw) < 14:
        raise Unsupported('truncated_ethernet')
    kind = int.from_bytes(raw[12:14], 'big')
    if kind in (0x8100, 0x88a8):
        raise Unsupported('vlan')
    if kind == 0x86dd:
        raise Unsupported('ipv6')
    if kind != 0x0800:
        raise Unsupported('non_ipv4')
    if len(raw) < 34:
        raise Unsupported('truncated_ipv4')
    version, ihl = raw[14] >> 4, (raw[14] & 15) * 4
    total = int.from_bytes(raw[16:18], 'big')
    if version != 4 or ihl < 20 or total < ihl:
        raise Unsupported('malformed_ipv4')
    if len(raw) < 14 + ihl:
        raise Unsupported('truncated_ipv4')
    if packet_length is not None and packet_length < 14 + total:
        raise Unsupported('truncated_ipv4')
    if int.from_bytes(raw[20:22], 'big') & 0x3fff:
        raise Unsupported('fragment')
    if raw[23] != 6:
        raise Unsupported('non_tcp')
    start = 14 + ihl
    if total < ihl + 20 or len(raw) < start + 20:
        raise Unsupported('truncated_tcp')
    thl = (raw[start + 12] >> 4) * 4
    if thl < 20 or total < ihl + thl:
        raise Unsupported('malformed_tcp')
    if len(raw) < start + thl:
        raise Unsupported('truncated_tcp')
    sport, dport, sequence, acknowledgement = struct.unpack_from('!HHII', raw, start)
    source = (int.from_bytes(raw[26:30], 'big'), sport)
    destination = (int.from_bytes(raw[30:34], 'big'), dport)
    a, b = sorted((source, destination))
    return {'a': a, 'b': b, 'direction': int(source != a),
            'ipv4_bytes': total, 'tcp_segment_bytes': total - ihl,
            'tcp_header_bytes': thl, 'flags': raw[start + 13],
            'sequence': sequence, 'acknowledgement': acknowledgement,
            'payload_bytes': total - ihl - thl,
            'header_hex': raw[:start + thl].hex()}


def canonical_key(packet, ifindex):
    a, b = packet['a'], packet['b']
    return {'a_addr': str(ipaddress.IPv4Address(a[0])), 'a_port': a[1],
            'b_addr': str(ipaddress.IPv4Address(b[0])), 'b_port': b[1],
            'ifindex': ifindex, 'protocol': 6}


def _direction(samples):
    sizes = [packet['tcp_segment_bytes'] for _, packet in samples]
    times = [timestamp for timestamp, _ in samples]
    return {'packets': len(samples),
            'ipv4_bytes': sum(packet['ipv4_bytes'] for _, packet in samples),
            'tcp_segment_bytes': sum(sizes),
            'tcp_header_bytes': sum(packet['tcp_header_bytes'] for _, packet in samples),
            'first_ns': times[0] if times else 0, 'last_ns': times[-1] if times else 0,
            'max_iat_ns': max((b - a for a, b in zip(times, times[1:])), default=0),
            'min_segment_bytes': min(sizes, default=0),
            'max_segment_bytes': max(sizes, default=0)}


def reference_flow(observations, ifindex):
    """Reduce one immutable generation, sorting by its real in-lock ordinal."""
    ordered = sorted(observations, key=lambda row: row['ordinal'])
    if not ordered:
        raise AssertionError('Empty generation')
    if [row['ordinal'] for row in ordered] != list(range(1, len(ordered) + 1)):
        raise AssertionError('Missing or duplicate observation ordinals')
    if len({row['flow_id'] for row in ordered}) != 1:
        raise AssertionError('Mixed generations')
    packets = [parse_headers(row['header_hex']) for row in ordered]
    keys = [canonical_key(packet, ifindex) for packet in packets]
    if any(key != keys[0] for key in keys):
        raise AssertionError('A generation contains multiple canonical keys')
    times = [row['timestamp_ns'] for row in ordered]
    if any(type(value) is not int or value < 0 for value in times) or times != sorted(times):
        raise AssertionError('Kernel lock-observed clocks are not monotonic')
    directions = defaultdict(list)
    initiator = 'unknown'
    fins, fin_acked = {}, set()
    state, closed_ns = 'open', 0
    for row, packet in zip(ordered, packets):
        direction, flags = packet['direction'], packet['flags']
        if row['direction'] != direction:
            raise AssertionError('Kernel canonical direction disagrees with independently parsed header')
        directions[direction].append((row['timestamp_ns'], packet))
        if flags & 2 and not flags & 16 and initiator == 'unknown':
            initiator = 'a' if direction == 0 else 'b'
        if flags & 16 and (1 - direction) in fins:
            # Serial arithmetic is modulo 2**32, not ordinary integer order.
            distance = (packet['acknowledgement'] - fins[1 - direction]) & 0xffffffff
            if distance < 0x80000000:
                fin_acked.add(1 - direction)
        if flags & 1:
            fins.setdefault(direction, (packet['sequence'] + packet['payload_bytes'] + bool(flags & 2) + 1) & 0xffffffff)
        if flags & 4:
            state = 'reset'
            closed_ns = closed_ns or row['timestamp_ns']
        elif state != 'reset':
            state = ('closed' if len(fins) == 2 and len(fin_acked) == 2 else
                     'closing' if len(fins) == 2 else 'half_closed' if fins else 'open')
            if state == 'closed':
                closed_ns = closed_ns or row['timestamp_ns']
    return {'id': ordered[0]['flow_id'], 'key': keys[0], 'initiator': initiator,
            'state': state, 'first_ns': times[0], 'last_ns': times[-1],
            'closed_ns': closed_ns, 'ordinal': len(ordered),
            'a_to_b': _direction(directions[0]), 'b_to_a': _direction(directions[1])}


def compare_snapshot(flows, observations, ifindex, *, require_all=True):
    """Exact expected/observed proof; no kernel-exported arithmetic is trusted."""
    grouped = defaultdict(list)
    for row in observations:
        grouped[row['flow_id']].append(row)
    actual = {flow['id']: flow for flow in flows}
    if len(actual) != len(flows):
        raise AssertionError('Duplicate flow IDs in snapshot')
    if require_all and set(actual) != set(grouped):
        raise AssertionError(f'Generation set mismatch: flows={sorted(actual)}, observations={sorted(grouped)}')
    proofs = []
    for ident in sorted(set(actual) & set(grouped)):
        expected = reference_flow(grouped[ident], ifindex)
        observed = {field: actual[ident].get(field) for field in expected}
        if expected != observed:
            raise AssertionError(f'Flow {ident} differs: expected={expected}, observed={observed}')
        proofs.append({'flow_id': ident, 'expected': expected, 'observed': observed, 'status': 'pass'})
    return proofs


def compare_capture(observations, captured, *, ports=None):
    """Require a one-to-one raw-header multiset, without comparing clock domains."""
    def selected(raw):
        try:
            packet = parse_headers(raw)
        except Unsupported:
            return None
        if ports is not None and not ({packet['a'][1], packet['b'][1]} & set(ports)):
            return None
        return packet['header_hex']
    expected = Counter(filter(None, (selected(row['header_hex']) for row in captured)))
    observed = Counter(filter(None, (selected(row['header_hex']) for row in observations)))
    if expected != observed:
        raise AssertionError(f'AF_PACKET/TC header mismatch: capture_only={dict(expected-observed)}, TC_only={dict(observed-expected)}')
    return {'status': 'pass', 'capture_packets': sum(expected.values()),
            'observation_packets': sum(observed.values()), 'capture_loss': 0,
            'clock_source': 'BPF ktime, clamped under the per-generation lock; AF_PACKET clocks are not substituted',
            'iat_tolerance_ns': 0,
            'scope': 'Header equality at TC/AF_PACKET granularity, not a wire-segmentation claim'}
