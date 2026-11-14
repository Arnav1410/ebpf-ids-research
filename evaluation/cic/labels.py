"""Original Tuesday identity-bearing CSVs; never substitute CIC feature columns."""
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import Counter, defaultdict
import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path, PurePosixPath
import struct
import zipfile

MEMBER = "TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv"
MAX_ZIP = 1 << 30
MAX_MEMBER = 512 << 20
CATEGORIES = {"BENIGN": 0, "FTP-Patator": 1, "SSH-Patator": 1}
FIELDS = ("Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
          "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets",
          "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label")


def canonical(a, b):
    return tuple(sorted((tuple(a), tuple(b))))


def clock_minutes(text):
    """Source binding: d/m/Y, 12-hour display, UTC-3, minute quantization.

    Both AM/PM candidates are retained; only a unique exact tuple/session
    match may disambiguate them. No nearest-label or prediction-based choice.
    """
    date, clock = text.split()
    day, month, year = map(int, date.split("/"))
    parts = list(map(int, clock.split(":")))
    if (year, month, day) != (2017, 7, 4) or len(parts) != 2:
        raise ValueError("Unexpected timestamp date/precision")
    hour, minute = parts
    if not 1 <= hour <= 12 or not 0 <= minute <= 59:
        raise ValueError("Unexpected 12-hour timestamp")
    return tuple(int(datetime(year, month, day, h, minute, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
                 + 3 * 3600 * 1_000_000_000 for h in (hour % 12, hour % 12 + 12))


@dataclass(slots=True)
class Label:
    line: int
    flow_id: str
    source: tuple
    destination: tuple
    minutes: tuple
    duration_ns: int
    forward: int
    backward: int
    forward_payload: int
    backward_payload: int
    category: str
    raw_timestamp: str
    record_hash: str
    reason: str = "NO_MATCHING_COMPLETE_SYN_SESSION"

    def start_matches(self, start_ns, client, server):
        return (self.source == client and self.destination == server
                and any(m <= start_ns < m + 60_000_000_000 for m in self.minutes))


class Labels:
    def __init__(self, path, member=MEMBER):
        self.path = Path(path)
        self.member = member
        if not 0 < self.path.stat().st_size <= MAX_ZIP:
            raise ValueError("Label ZIP size limit")
        with self.path.open("rb") as stream:
            stream.seek(max(0, self.path.stat().st_size - 65557))
            tail = stream.read(65557)
        pos = tail.rfind(b"PK\x05\x06")
        if pos < 0 or pos + 22 > len(tail):
            raise ValueError("Missing bounded ZIP directory")
        fields = struct.unpack_from("<4s4H2IH", tail, pos)
        if fields[1] or fields[2] or fields[4] > 256 or fields[5] > 1 << 20:
            raise ValueError("Unsupported ZIP directory size/disks")
        self.index = defaultdict(list)
        self.records = []
        self.other_rows = []
        self.summary = dict(raw_rows=0, labels=Counter(), protocols=Counter(), duplicate_records=0,
                            member=member, errors=Counter())
        self.member_digest = hashlib.sha256()
        seen = {}
        with zipfile.ZipFile(self.path) as archive:
            names = [i for i in archive.infolist() if i.filename == member]
            if len(names) != 1 or not 0 < names[0].file_size <= MAX_MEMBER:
                raise ValueError("Missing/duplicate/oversize Tuesday member")
            name = PurePosixPath(member)
            if name.is_absolute() or ".." in name.parts or names[0].flag_bits & 1:
                raise ValueError("Unsafe/encrypted label member")
            if (names[0].external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Symlink label member")
            with archive.open(names[0]) as raw:
                def lines():
                    total = 0
                    first = True
                    while True:
                        line = raw.readline(1 << 20)
                        if not line:
                            break
                        if len(line) >= 1 << 20:
                            raise ValueError("CSV line length bound")
                        total += len(line)
                        if total > MAX_MEMBER:
                            raise ValueError("CSV expansion limit")
                        self.member_digest.update(line)
                        yield line.decode("utf-8-sig" if first else "utf-8")
                        first = False
                reader = csv.reader(lines())
                header = [s.strip() for s in next(reader)]
                positions = {}
                for field in FIELDS:
                    found = [i for i, value in enumerate(header) if value == field]
                    if len(found) != 1:
                        raise ValueError("Missing/ambiguous identity field " + field)
                    positions[field] = found[0]
                self.summary["header"] = header
                for row in reader:
                    line_number = reader.line_num
                    self.summary["raw_rows"] += 1
                    if len(row) != len(header):
                        raise ValueError("Inconsistent CSV record width")
                    value = {field: row[i].strip() for field, i in positions.items()}
                    category = value["Label"]
                    self.summary["labels"][category] += 1
                    self.summary["protocols"][value["Protocol"]] += 1
                    if value["Protocol"] != "6":
                        self.other_rows.append(dict(csv_line=line_number, category=category, reason="NON_TCP_LABEL"))
                        continue
                    try:
                        if category not in CATEGORIES:
                            raise ValueError("Unknown source category")
                        a = (int(ipaddress.IPv4Address(value["Source IP"])), int(value["Source Port"]))
                        b = (int(ipaddress.IPv4Address(value["Destination IP"])), int(value["Destination Port"]))
                        if not all(0 <= p[1] <= 65535 for p in (a, b)) or a == b:
                            raise ValueError("Invalid endpoints")
                        duration = int(value["Flow Duration"]) * 1000
                        counters = [int(value[k]) for k in FIELDS[8:12]]
                        if not 0 <= duration <= (1 << 63) - 1 or any(v < 0 for v in counters):
                            raise ValueError("Negative/overflowing interval/counters")
                        minutes = clock_minutes(value["Timestamp"])
                    except ValueError as error:
                        self.other_rows.append(dict(csv_line=line_number, category=category, reason="INVALID_REQUIRED_LABEL_METADATA", error=str(error)))
                        self.summary["errors"][str(error)] += 1
                        continue
                    digest = hashlib.sha256(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
                    if digest in seen:
                        self.summary["duplicate_records"] += 1
                        self.other_rows.append(dict(csv_line=line_number, category=category,
                                                   reason="DUPLICATE_SOURCE_RECORD", retained_csv_line=seen[digest]))
                        continue
                    seen[digest] = line_number
                    record = Label(line_number, value["Flow ID"], a, b, minutes, duration,
                                   *counters, category, value["Timestamp"], digest)
                    self.records.append(record)
                    self.index[canonical(a, b)].append(record)
        self.summary["member_sha256"] = self.member_digest.hexdigest()
        self.summary["unique_valid_tcp_records"] = len(self.records)

    def at_start(self, key, start_ns, client, server):
        return [r for r in self.index.get(key, ()) if r.start_matches(start_ns, client, server)]

    @staticmethod
    def match(records, start_ns, trigger_ns, forward, backward, forward_payload, backward_payload):
        return [r for r in records if r.duration_ns == trigger_ns - start_ns
                and (r.forward, r.backward, r.forward_payload, r.backward_payload)
                == (forward, backward, forward_payload, backward_payload)]
