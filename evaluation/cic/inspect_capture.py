#!/usr/bin/env python3
"""Read-only streaming capture inventory. No labels, predictions or replay."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import resource
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from evaluation.cic.capture import Reader, decode_tcp, PacketError


def inspect(path, limit=0, expected_hash=None, expected_md5=None):
    before = path.stat()
    reader = Reader(path)
    reasons = Counter()
    tcp_flags = Counter()
    header_lengths = Counter()
    samples = []
    earliest = latest = first = last = previous = None
    reorders = 0
    count = 0
    segment_min = segment_max = None
    started = time.monotonic()
    for packet in reader:
        count += 1
        reference = packet.reference()
        if first is None:
            first = reference
        last = reference
        if packet.timestamp_ns is not None:
            ns = packet.timestamp_ns
            earliest = ns if earliest is None else min(earliest, ns)
            latest = ns if latest is None else max(latest, ns)
            if previous is not None and ns < previous:
                reorders += 1
            previous = ns
        try:
            tcp = decode_tcp(packet)
            reasons["SUPPORTED_TCP"] += 1
            tcp_flags[str(tcp.flags)] += 1
            header_lengths[str(tcp.header_bytes)] += 1
            segment_min = tcp.segment_bytes if segment_min is None else min(segment_min, tcp.segment_bytes)
            segment_max = tcp.segment_bytes if segment_max is None else max(segment_max, tcp.segment_bytes)
            if len(samples) < 5:
                samples.append(dict(reference=reference, source_ip=tcp.source_ip,
                                    source_port=tcp.source_port, destination_ip=tcp.destination_ip,
                                    destination_port=tcp.destination_port, flags=tcp.flags,
                                    segment_bytes=tcp.segment_bytes, header_bytes=tcp.header_bytes))
        except PacketError as error:
            reasons[str(error)] += 1
        if count % 1_000_000 == 0:
            print(json.dumps(dict(progress_packets=count, file_offset=packet.offset)), flush=True)
        if limit and count >= limit:
            break
    after = path.stat()
    unchanged = (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
    if not unchanged:
        raise RuntimeError("Source size/mtime changed during read-only inventory")
    sha = reader.digest.hexdigest() if reader.complete else None
    if expected_hash and sha != expected_hash:
        raise RuntimeError("Expected full-file SHA256 did not match; do not use this inventory")
    md5 = reader.md5.hexdigest() if reader.complete else None
    if expected_md5 and md5 != expected_md5:
        raise RuntimeError("Publisher MD5 did not match; do not use this inventory")
    def utc(ns):
        if ns is None:
            return None
        return datetime.fromtimestamp(ns // 1_000_000_000, timezone.utc).isoformat()
    return dict(status="PASS", scope="Capture/container/packet inventory only; no labeled flow pilot or model inference",
                path=str(path.resolve()), size_bytes=before.st_size, sha256=sha, md5=md5,
                full_capture_checked=reader.complete, source_size_mtime_unchanged=unchanged,
                packets=count, container=reader.metadata, packet_scope_counts=dict(reasons),
                tcp_flags=dict(tcp_flags), tcp_header_lengths=dict(header_lengths),
                supported_segment_min=segment_min, supported_segment_max=segment_max,
                first_packet=first, last_packet=last, earliest_timestamp_ns=earliest,
                latest_timestamp_ns=latest, earliest_utc=utc(earliest), latest_utc=utc(latest),
                global_packet_timestamp_reorders=reorders,
                timing_note="Capture timestamps; global reorder count is not a per-flow IAT or kernel helper-clock comparison",
                examples=samples, elapsed_seconds=round(time.monotonic() - started, 3),
                peak_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                labeled_flows_evaluated=0, classification_metrics=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-packets", type=int, default=0, help="0 scans the complete file")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-md5")
    args = parser.parse_args()
    if args.max_packets < 0 or (args.expected_sha256 or args.expected_md5) and args.max_packets:
        parser.error("Full-file expected hash requires an unlimited scan; limit must be nonnegative")
    args.output.mkdir(parents=True, exist_ok=False)
    result = inspect(args.input, args.max_packets, args.expected_sha256, args.expected_md5)
    (args.output / "inventory.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
