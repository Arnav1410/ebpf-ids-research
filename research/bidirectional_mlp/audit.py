#!/usr/bin/env python3
"""Predictions-blind dataset feasibility audit; never trains or loads an MLP."""
import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import asdict
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import ipaddress
import json
import mmap
from pathlib import Path, PurePosixPath
import struct
import sys
import time
import zipfile

from evaluation.cic.capture import Packet, decode_tcp, MAX_BLOCK, timestamp
from evaluation.cic.labels import Labels, CATEGORIES
from research.bidirectional_mlp.features import Event, State, ClosingWindow, I64_MAX

ROOT = Path(__file__).resolve().parents[2]
POLICY = Path(__file__).with_name('POLICY.json')
NUMERIC = ('Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Max',
           'Fwd Packet Length Min', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
           'Fwd IAT Max', 'Bwd IAT Max', 'Fwd Header Length', 'Bwd Header Length',
           'Destination Port', 'Flow Duration')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def write(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2, ensure_ascii=True, allow_nan=False)
        f.write('\n')


def prepare_output(path):
    path.mkdir(parents=True, exist_ok=False)
    write(path / 'policy.json', json.loads(POLICY.read_text()))
    return sha(POLICY)


def number(text):
    try:
        d = Decimal(text.strip())
        if not d.is_finite() or d < 0 or d > I64_MAX or d != d.to_integral_value():
            raise ValueError('INVALID_SELECTED_NUMERIC')
        return int(d)
    except InvalidOperation as error:
        raise ValueError('INVALID_SELECTED_NUMERIC') from error


def clean_csv(row, positions):
    n = {}
    for name in NUMERIC:
        values = [number(row[i]) for i in positions[name]]
        if len(set(values)) != 1:
            raise ValueError('CONFLICTING_DUPLICATE_HEADER:' + name)
        n[name] = values[0]
    for name in ('Source IP', 'Destination IP'):
        ipaddress.IPv4Address(row[positions[name][0]].strip())
    for name in ('Source Port', 'Destination Port'):
        if not 0 <= number(row[positions[name][0]]) <= 65535:
            raise ValueError('INVALID_PORT')
    if any(not row[positions[k][0]].strip() for k in ('Flow ID', 'Timestamp', 'Label')):
        raise ValueError('MISSING_IDENTITY')
    if n['Total Fwd Packets'] < 1:
        raise ValueError('ZERO_FORWARD_PACKETS')
    for prefix, count in (('Fwd', 'Total Fwd Packets'), ('Bwd', 'Total Backward Packets')):
        if n[count] and n[prefix + ' Packet Length Min'] > n[prefix + ' Packet Length Max']:
            raise ValueError('INVALID_LENGTH_EXTREMA')
    return n


def inventory(args):
    policy = prepare_output(args.output)
    binding = json.loads(args.binding.read_text())
    if sha(args.labels) != binding['labels_zip']['sha256']:
        raise ValueError('LABEL_ARCHIVE_HASH_CHANGED')
    members = []
    with zipfile.ZipFile(args.labels) as z:
        if len(z.infolist()) > 256:
            raise ValueError('ARCHIVE_MEMBER_COUNT_BOUND')
        for info in z.infolist():
            if info.is_dir():
                continue
            name = PurePosixPath(info.filename)
            if name.is_absolute() or '..' in name.parts or info.flag_bits & 1 or info.file_size > 512 << 20:
                raise ValueError('UNSAFE_OR_OVERSIZE_ARCHIVE_MEMBER')
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('SYMLINK_ARCHIVE_MEMBER')
            if not name.name.endswith('.csv'):
                continue
            start = time.monotonic()
            digest = hashlib.sha256()
            def lines(raw):
                total = 0
                while True:
                    line = raw.readline(1 << 20)
                    if not line:
                        return
                    total += len(line)
                    if len(line) >= 1 << 20 or total > info.file_size:
                        raise ValueError('CSV_EXPANSION_BOUND')
                    digest.update(line)
                    # The original archive includes a non-UTF8 dash in web
                    # attack labels. Preserve it reversibly as surrogate bytes.
                    yield line.decode('utf-8-sig', errors='surrogateescape')
            raw_counts, tcp_counts, clean_counts, exclusions = (Counter() for _ in range(4))
            raw_rows = tcp = valid = duplicates = no_reverse = 0
            seen = set()
            with z.open(info) as raw:
                reader = csv.reader(lines(raw))
                header = [s.strip() for s in next(reader)]
                positions = {name: [i for i, v in enumerate(header) if v == name] for name in
                             set(NUMERIC + ('Source IP', 'Destination IP', 'Source Port', 'Flow ID', 'Timestamp', 'Label', 'Protocol'))}
                if any(not indices for indices in positions.values()):
                    raise ValueError('MISSING_COLUMN:' + info.filename)
                for row in reader:
                    raw_rows += 1
                    if len(row) != len(header):
                        exclusions['INVALID_RECORD_WIDTH'] += 1
                        continue
                    category = row[positions['Label'][0]].strip()
                    raw_counts[category] += 1
                    if row[positions['Protocol'][0]].strip() != '6':
                        exclusions['NON_TCP'] += 1
                        continue
                    tcp += 1
                    tcp_counts[category] += 1
                    record_hash = hashlib.sha256(json.dumps(row, ensure_ascii=True, separators=(',', ':')).encode()).digest()
                    if record_hash in seen:
                        duplicates += 1
                        exclusions['DUPLICATE_SOURCE_RECORD'] += 1
                        continue
                    seen.add(record_hash)
                    try:
                        n = clean_csv(row, positions)
                    except ValueError as e:
                        exclusions[str(e)] += 1
                        continue
                    valid += 1
                    clean_counts[category] += 1
                    no_reverse += n['Total Backward Packets'] == 0
            member = dict(name=info.filename, bytes=info.file_size, sha256=digest.hexdigest(),
                          header=header, selected_column_positions_zero_based={k: positions[k] for k in NUMERIC},
                          rows=raw_rows, labels=dict(raw_counts), tcp_rows=tcp, tcp_labels=dict(tcp_counts),
                          numerically_clean_tcp=valid, clean_tcp_labels=dict(clean_counts), no_reverse_packets=no_reverse,
                          duplicate_full_tcp_rows=duplicates, exclusions=dict(exclusions),
                          status='CSV_INVENTORY_ONLY_NOT_KERNEL_COMPATIBLE', elapsed_seconds=time.monotonic()-start)
            if 'Tuesday-' in info.filename and digest.hexdigest() != binding['labels_member']['sha256']:
                raise ValueError('TUESDAY_MEMBER_HASH_CHANGED')
            members.append(member)
            print(info.filename, 'TCP', tcp, 'clean', valid, flush=True)
    write(args.output / 'inventory.json', dict(status='PASS', scope='Source CSV inventory, NOT a labeled kernel-feature training set',
          policy_sha256=policy, archive_sha256=binding['labels_zip']['sha256'], members=members,
          cleaning='Only selected bidirectional columns and identity; other CSV columns are not asserted finite or usable.',
          compatibility='Payload extrema and full-flow CSV windows cannot substitute TCP-segment extrema at the experimental trigger.'))


def read_packet(stream, index, offset, interface, order):
    if type(index) is not int or index < 1 or type(offset) is not int or offset < 0:
        raise ValueError('INVALID_PACKET_REFERENCE')
    stream.seek(offset)
    header = stream.read(8)
    if len(header) != 8:
        raise ValueError('SHORT_BLOCK_HEADER')
    kind, length = struct.unpack(order + 'II', header)
    if kind != 6 or length % 4 or not 32 <= length <= MAX_BLOCK:
        raise ValueError('INVALID_BLOCK_LENGTH_OR_TYPE')
    b = stream.read(length - 8)
    if len(b) != length - 8 or struct.unpack_from(order + 'I', b, len(b)-4)[0] != length:
        raise ValueError('INVALID_BLOCK_FOOTER')
    iid, hi, lo, cap, wire = struct.unpack_from(order+'IIIII', b)
    if iid or cap > wire or cap > interface['snaplen'] or 20 + ((cap+3)&~3) > len(b)-4:
        raise ValueError('INVALID_PACKET_LENGTHS')
    ns = timestamp((hi << 32) | lo, interface['ticks_per_second'], interface['seconds_offset'])
    return Packet(index, index+2, offset, 0, 0, ns, wire, interface['linktype'], b[20:20+cap])


def raw_event(p, direction):
    """Independent simple byte-indexed length/header derivation for the strict subset."""
    b = p.data
    if len(b) < 54 or b[12:14] != b'\x08\x00' or b[14] != 0x45 or b[23] != 6:
        raise ValueError('OUTSIDE_STRICT_PACKET_SUBSET')
    total = int.from_bytes(b[16:18], 'big')
    if int.from_bytes(b[20:22], 'big') & 0x3fff or total > len(b)-14:
        raise ValueError('FRAGMENT_OR_TRUNCATION')
    return Event(direction, p.timestamp_ns, total-20, (b[46] >> 4)*4, b[47])


def summary_vector(events, port):
    """Independent batch reduction; does not call the streaming State reference."""
    if not events:
        raise ValueError('EMPTY_OBSERVATION')
    maxima = []
    for direction in (0, 1):
        stamps = [e.timestamp_ns for e in events if e.direction == direction]
        if any(b < a for a, b in zip(stamps, stamps[1:])):
            raise ValueError('TIMESTAMP_REORDER')
        maxima.append(max((b-a for a, b in zip(stamps, stamps[1:])), default=0))
    return [max(e.segment_bytes for e in events), max(maxima), min(e.segment_bytes for e in events),
            port, sum(e.header_bytes for e in events), len(events)]


def pilot(args):
    policy = prepare_output(args.output)
    binding = json.loads(args.binding.read_text())
    before = args.capture.stat()
    if sha(args.capture) != binding['pcap']['sha256'] or sha(args.labels) != binding['labels_zip']['sha256']:
        raise ValueError('SOURCE_HASH_CHANGED')
    labels = Labels(args.labels)
    if labels.summary['member_sha256'] != binding['labels_member']['sha256']:
        raise ValueError('LABEL_MEMBER_CHANGED')
    sources = {r.line: r for r in labels.records}
    records = []
    with args.cohort.open() as f:
        for line in f:
            if len(line) > 32 << 20 or len(records) >= 500:
                raise ValueError('PILOT_RESOURCE_BOUND')
            records.append(json.loads(line))
    if not 1 <= len(records) <= 500 or len({r['source_record_id'] for r in records}) != len(records):
        raise ValueError('INVALID_PILOT_IDS')
    container = binding['container']
    if container['format'] != 'pcapng' or container['sections'] != 1 or len(container['interfaces']) != 1 or container['blocks'] != container['packets']+2:
        raise ValueError('UNSUPPORTED_RANDOM_ACCESS_SOURCE')
    stats = Counter()
    categories = Counter()
    missing_closing = Counter()
    feature_changes = [0]*6
    with args.capture.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m, (args.output/'pilot.jsonl').open('x') as out:
        order = {b'\x4d\x3c\x2b\x1a':'<', b'\x1a\x2b\x3c\x4d':'>'}.get(m[8:12])
        if order is None:
            raise ValueError('INVALID_SECTION_BYTE_ORDER')
        for r in records:
            source = sources[r['csv_line']]
            if r['source_record_id'] != labels.summary['member_sha256']+':'+str(source.line):
                raise ValueError('SOURCE_ID_MISMATCH')
            client = (int(ipaddress.IPv4Address(r['client_ip'])), r['client_port'])
            server = (int(ipaddress.IPv4Address(r['server_ip'])), r['server_port'])
            if source.source != client or source.destination != server or source.category != r['category'] or CATEGORIES[source.category] != r['label']:
                raise ValueError('SOURCE_DIRECTION_OR_LABEL_MISMATCH')
            packets = []
            for direction, prefix in ((0,'forward'), (1,'backward')):
                for i, offset in zip(r[prefix+'_packet_indices'], r[prefix+'_packet_offsets'], strict=True):
                    packets.append((read_packet(m, i, offset, container['interfaces'][0], order), direction))
            packets.sort(key=lambda item: item[0].index)
            if len({p.index for p, _ in packets}) != len(packets) or not packets:
                raise ValueError('DUPLICATE_OR_MISSING_PACKET')
            if any(b.offset <= a.offset or b.timestamp_ns < a.timestamp_ns for (a,_),(b,_) in zip(packets,packets[1:])):
                raise ValueError('PACKET_ORDER_MISMATCH')
            state, closing = State(server[1]), ClosingWindow(server[1])
            events, trace = [], []
            payload = [0,0]
            candidate_index = None
            for p, direction in packets:
                tcp = decode_tcp(p)
                expected = (client,server) if direction == 0 else (server,client)
                if ((tcp.source_ip,tcp.source_port),(tcp.destination_ip,tcp.destination_port)) != expected:
                    raise ValueError('PACKET_TUPLE_MISMATCH')
                e = raw_event(p,direction)
                if (e.segment_bytes,e.header_bytes,e.flags) != (tcp.segment_bytes,tcp.header_bytes,tcp.flags):
                    raise ValueError('PARSER_REFERENCE_DISAGREES')
                e.validate()
                events.append(e)
                payload[direction] += e.segment_bytes-e.header_bytes
                state.add(e)
                if closing.add(e) is not None and candidate_index is None:
                    candidate_index = p.index
                trace.append(dict(packet_index=p.index,file_offset=p.offset,**asdict(e)))
            first, last = events[0],events[-1]
            if first.direction or not first.flags&2 or first.flags&16 or last.direction or not last.flags&5:
                raise ValueError('INCOMPLETE_START_OR_TRIGGER')
            if any(e.direction == 0 and e.flags&5 for e in events[:-1]):
                raise ValueError('EARLIER_INGRESS_TRIGGER')
            if packets[0][0].reference() != r['start'] or packets[-1][0].reference() != r['trigger'] or last.flags != r['trigger_flags']:
                raise ValueError('START_TRIGGER_REFERENCE_MISMATCH')
            fwd = state.vector(False)
            bidir = state.vector()
            if fwd != r['features'] or fwd != summary_vector([e for e in events if e.direction==0],server[1]) or bidir != summary_vector(events,server[1]):
                raise ValueError('FEATURE_REFERENCE_MISMATCH')
            matched = labels.match([source],first.timestamp_ns,last.timestamp_ns,state.directions[0].count,state.directions[1].count,*payload)
            if len(matched) != 1 or not source.start_matches(first.timestamp_ns,client,server):
                raise ValueError('LABEL_WINDOW_COUNTERS_MISMATCH')
            exact_candidate = candidate_index == packets[-1][0].index
            stats['candidate_same_label_window' if exact_candidate else 'candidate_unvalidated_label_window'] += 1
            stats['reverse_fin_observed_before_or_at_ingress_trigger'] += state.directions[1].fin_seen
            stats['reverse_payload_present'] += payload[1]>0
            stats['packets'] += len(events)
            for i,(a,b) in enumerate(zip(fwd,bidir)):
                feature_changes[i] += a != b
            categories[r['category']] += 1
            if not exact_candidate:
                missing_closing[r['category']] += 1
            out.write(json.dumps(dict(source_record_id=r['source_record_id'],csv_line=r['csv_line'],category=r['category'],
                label=r['label'],client=[r['client_ip'],r['client_port']],server=[r['server_ip'],r['server_port']],
                forward=fwd,bidirectional_at_legacy_trigger=bidir,directions=[asdict(d) for d in state.directions],
                trigger=r['trigger'],trigger_flags=r['trigger_flags'],
                candidate_trigger_index_within_available_prefix=candidate_index,
                candidate_window_label_validated=exact_candidate,
                candidate_prefix_status=closing.reason or ('SNAPSHOT' if closing.snapshot else 'NO_CANDIDATE_TRIGGER_IN_PREFIX'),
                packet_trace=trace),separators=(',',':'))+'\n')
    after = args.capture.stat()
    if (before.st_size,before.st_mtime_ns) != (after.st_size,after.st_mtime_ns):
        raise ValueError('CAPTURE_CHANGED')
    write(args.output/'summary.json',dict(status='PASS',scope='Offline packet feature/reference audit only; NO kernel execution or MLP inference',
        records=len(records),categories=dict(categories),counts=dict(stats),
        candidate_unvalidated_by_category=dict(missing_closing),changed_features_vs_forward=feature_changes,
        source_pcap_sha256=binding['pcap']['sha256'],labels_zip_sha256=binding['labels_zip']['sha256'],
        cohort_sha256=sha(args.cohort),output_sha256=sha(args.output/'pilot.jsonl'),policy_sha256=policy,
        interpretation='Bidirectional prefix extraction validated. A changed trigger requires a newly validated label interval; current prefix labels must not be extended.'))
    print((args.output/'summary.json').read_text())


def groups(args):
    policy = prepare_output(args.output)
    counts, days, campaigns, endpoint_pairs = (Counter() for _ in range(4))
    minutes = defaultdict(Counter)
    ids = set()
    zero_reverse = 0
    with gzip.open(args.eligible,'rt') as f:
        for line in f:
            if len(line) > 32 << 20:
                raise ValueError('ELIGIBLE_RECORD_BOUND')
            r = json.loads(line)
            if r['source_record_id'] in ids:
                raise ValueError('DUPLICATE_ELIGIBLE_SOURCE_ID')
            ids.add(r['source_record_id'])
            counts[r['category']] += 1
            days[r['capture_day']] += 1
            zero_reverse += r['observed_backward_packets']==0
            if r['label']:
                campaign=(r['capture_day'],r['category'],r['client_ip'],r['server_ip'])
                campaigns[campaign] += 1
                minutes[campaign][r['source_timestamp']] += 1
                endpoint_pairs[tuple(sorted((r['client_ip'],r['server_ip'])))] += 1
    result=dict(status='PASS', scope='Predictions-blind grouping audit, NOT a train/test split',
                eligible=len(ids),categories=dict(counts),capture_days=dict(days),zero_reverse=zero_reverse,
                campaign_proxies=[dict(group=list(k),count=v,source_minutes=dict(minutes[k])) for k,v in sorted(campaigns.items())],
                attack_endpoint_pairs=[dict(pair=list(k),count=v) for k,v in endpoint_pairs.items()],
                viable_three_partition_campaign_split=len(campaigns)>=3,
                policy_sha256=policy,eligible_archive_sha256=sha(args.eligible),
                gate='FAIL' if len(campaigns)<3 else 'PENDING_FURTHER_VALIDATION',
                reason='At least three disjoint positive campaign groups are necessary to represent intrusion in train/validation/test without splitting these correlated groups. Only proxies, not independently verified session IDs, are recoverable.',
                training='NOT RUN',kernel_integration='NOT RUN')
    write(args.output/'groups.json',result)
    print(json.dumps(result,indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command',required=True)
    for name, fun in (('inventory',inventory),('pilot',pilot),('groups',groups)):
        s=sub.add_parser(name)
        s.add_argument('--output',type=Path,required=True)
        if name in ('inventory','pilot'):
            s.add_argument('--labels',type=Path,required=True)
            s.add_argument('--binding',type=Path,required=True)
        if name=='pilot':
            s.add_argument('--capture',type=Path,required=True)
            s.add_argument('--cohort',type=Path,required=True)
        if name=='groups':
            s.add_argument('--eligible',type=Path,required=True)
        s.set_defaults(run=fun)
    args=p.parse_args()
    args.run(args)


if __name__=='__main__':
    main()
