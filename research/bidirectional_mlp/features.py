"""Offline feature specification, NOT an implemented or verified kernel mode.

Packet events must already satisfy the supported parser and direction policy.
No payload is retained, and no model or existing parameter is loaded.
"""
from dataclasses import dataclass, field

I64_MAX = (1 << 63) - 1
CLOSE_GRACE_NS = 5_000_000_000


def checked_sum(a, b):
    if type(a) is not int or type(b) is not int or not 0 <= a <= I64_MAX or not 0 <= b <= I64_MAX - a:
        raise ValueError('FEATURE_INT64_OVERFLOW')
    return a + b


@dataclass(frozen=True)
class Event:
    direction: int  # 0 client -> server, 1 server -> client
    timestamp_ns: int
    segment_bytes: int
    header_bytes: int
    flags: int

    def validate(self):
        if self.direction not in (0, 1) or type(self.direction) is not int:
            raise ValueError('INVALID_DIRECTION')
        if type(self.timestamp_ns) is not int or not 0 <= self.timestamp_ns <= I64_MAX:
            raise ValueError('INVALID_TIMESTAMP')
        if type(self.header_bytes) is not int or self.header_bytes % 4 or not 20 <= self.header_bytes <= 60:
            raise ValueError('INVALID_TCP_HEADER')
        if type(self.segment_bytes) is not int or not self.header_bytes <= self.segment_bytes <= 65515:
            raise ValueError('INVALID_TCP_SEGMENT')
        if type(self.flags) is not int or not 0 <= self.flags <= 255:
            raise ValueError('INVALID_TCP_FLAGS')


@dataclass
class Direction:
    count: int = 0
    header_total: int = 0
    minimum: int | None = None
    maximum: int = 0
    last_ns: int | None = None
    iat_max: int = 0
    fin_seen: bool = False

    def update(self, e):
        e.validate()
        if self.last_ns is not None and e.timestamp_ns < self.last_ns:
            raise ValueError('TIMESTAMP_REORDER')
        count = checked_sum(self.count, 1)
        headers = checked_sum(self.header_total, e.header_bytes)
        self.iat_max = max(self.iat_max, 0 if self.last_ns is None else e.timestamp_ns - self.last_ns)
        self.count, self.header_total = count, headers
        self.maximum = max(self.maximum, e.segment_bytes)
        self.minimum = e.segment_bytes if self.minimum is None else min(self.minimum, e.segment_bytes)
        self.last_ns = e.timestamp_ns
        self.fin_seen |= bool(e.flags & 1)


@dataclass
class State:
    destination_port: int
    directions: list = field(default_factory=lambda: [Direction(), Direction()])
    last_ns: int | None = None

    def __post_init__(self):
        if type(self.destination_port) is not int or not 0 <= self.destination_port <= 65535:
            raise ValueError('INVALID_SERVICE_PORT')

    def add(self, e):
        e.validate()
        # Strict offline cohort excludes reordered records; live TC currently
        # clamps a late helper timestamp instead. Do not hide this distinction.
        if self.last_ns is not None and e.timestamp_ns < self.last_ns:
            raise ValueError('TIMESTAMP_REORDER')
        self.directions[e.direction].update(e)
        self.last_ns = e.timestamp_ns

    def vector(self, bidirectional=True):
        included = [d for d in self.directions[:2 if bidirectional else 1] if d.count]
        if not included:
            raise ValueError('EMPTY_OBSERVATION')
        headers = packets = 0
        for d in included:
            headers = checked_sum(headers, d.header_total)
            packets = checked_sum(packets, d.count)
        return [max(d.maximum for d in included), max(d.iat_max for d in included),
                min(d.minimum for d in included), self.destination_port, headers, packets]


class ClosingWindow:
    """Candidate only: first RST or both FINs, bounded after first FIN.

    The reference does not synthesize timer events or infer a missing SYN.
    A production implementation is deliberately gated on new label validation.
    """
    def __init__(self, destination_port):
        self.state = State(destination_port)
        self.first_fin = None
        self.snapshot = None
        self.reason = None
        self.started = False

    def add(self, e):
        e.validate()
        if self.snapshot is not None or self.reason is not None:
            return None
        if not self.started:
            if e.direction != 0 or not e.flags & 2 or e.flags & 16:
                self.reason = 'MISSING_INITIAL_CLIENT_SYN'
                return None
            self.started = True
        if self.first_fin is not None and e.timestamp_ns - self.first_fin > CLOSE_GRACE_NS:
            self.reason = 'CLOSING_GRACE_EXPIRED_UNSCORED'
            return None
        self.state.add(e)
        if e.flags & 1 and self.first_fin is None:
            self.first_fin = e.timestamp_ns
        if e.flags & 4 or all(d.fin_seen for d in self.state.directions):
            self.snapshot = self.state.vector()
            return list(self.snapshot)
        return None
