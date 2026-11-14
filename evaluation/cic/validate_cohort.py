#!/usr/bin/env python3
"""Independent labeled-cohort feature validation. Host C, NOT kernel execution."""
import argparse
from collections import Counter
import ctypes as C
import hashlib
import ipaddress
import json
import mmap
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from evaluation.cic.capture import Packet, MAX_BLOCK, timestamp, decode_tcp
from evaluation.cic.labels import Labels, canonical
from evaluation.cic.reconstruct import fingerprint


def read_at(stream, index, offset, interface, order):
    stream.seek(offset)
    header = stream.read(8)
    if len(header) != 8:
        raise ValueError("Invalid packet offset")
    kind, length = struct.unpack(order + "II", header)
    if kind != 6 or not 32 <= length <= MAX_BLOCK or length % 4:
        raise ValueError("Offset is not a bounded enhanced-packet block")
    body = stream.read(length - 8)
    if len(body) != length - 8 or struct.unpack_from(order + "I", body, len(body) - 4)[0] != length:
        raise ValueError("Invalid packet block footer")
    iid, high, low, cap, wire = struct.unpack_from(order + "IIIII", body)
    if iid != 0 or cap > wire or cap > interface["snaplen"] or 20 + ((cap + 3) & ~3) > len(body) - 4:
        raise ValueError("Invalid packet metadata")
    stamp = timestamp((high << 32) | low, interface["ticks_per_second"], interface["seconds_offset"])
    return Packet(index, index + 2, offset, 0, 0, stamp, wire, interface["linktype"], body[20:20 + cap])


def build_probes(out, compiler):
    directory = out / ".output"
    directory.mkdir()
    result = {}
    for mode in ("xdp", "tc"):
        path = directory / (mode + "_features.so")
        includes = ["validation/include"] if mode == "xdp" else ["tc/tests/include", "validation/include"]
        command = [compiler, "-O2", "-shared", "-fPIC", "-pthread"]
        if mode == "tc":
            command.append("-DPROBE_TC")
        command += ["-I" + str(ROOT / p) for p in includes]
        command += [str(ROOT / "evaluation/cic/feature_probe.c"), "-o", str(path)]
        p = subprocess.run(command, capture_output=True, text=True)
        (out / (mode + "-build.log")).write_text(p.stdout + p.stderr)
        with (out / "commands.jsonl").open("a") as dest:
            dest.write(json.dumps(dict(argv=command, exit_code=p.returncode)) + "\n")
        if p.returncode:
            raise RuntimeError("Host feature-probe build failed: " + mode)
        lib = C.CDLL(str(path.resolve()))
        lib.probe_packet.argtypes = [C.c_void_p, C.c_uint, C.c_uint64]
        lib.probe_features.argtypes = [C.POINTER(C.c_int64)]
        result[mode] = lib
    return result


def validate(args):
    started = time.monotonic()
    cohort_hash = fingerprint(args.cohort)
    records = []
    with args.cohort.open() as source:
        for line in source:
            if len(line) > 32 << 20 or len(records) >= 30000:
                raise ValueError("Cohort resource bound")
            records.append(json.loads(line))
    if not records or len({r["source_record_id"] for r in records}) != len(records):
        raise ValueError("Empty/duplicated cohort")
    if len(records) > 500:
        if args.previous is None or json.loads(args.previous.read_text())["status"] != "PASS":
            raise ValueError("Previous independent validation gate is required")
    binding = json.loads(args.binding.read_text())
    container = binding["container"]
    if (container["format"] != "pcapng" or container["sections"] != 1
            or len(container["interfaces"]) != 1
            or container["blocks"] != container["packets"] + 2):
        raise ValueError("Random-access validator currently requires this bound single-interface EPB source")
    if fingerprint(args.labels) != binding["labels_zip"]["sha256"]:
        raise ValueError("Label ZIP hash changed")
    labels = Labels(args.labels)
    if labels.summary["member_sha256"] != binding["labels_member"]["sha256"]:
        raise ValueError("Label member changed")
    source_records = {r.line: r for r in labels.records}
    args.output.mkdir(parents=True, exist_ok=False)
    libs = build_probes(args.output, args.compiler)
    before = args.capture.stat()
    samples = []
    category_samples = Counter()
    forward_packets = backward_packets = 0
    # Read-only mapping avoids repeatedly prefetching megabytes when validating
    # tiny packet headers from interleaved flows. Validation order never changes
    # the frozen cohort or the IDs supplied to the inference implementations.
    records.sort(key=lambda r: r["start"]["file_offset"])
    with args.capture.open("rb") as source_stream, mmap.mmap(source_stream.fileno(), 0, access=mmap.ACCESS_READ) as stream, (args.output / "comparisons.jsonl").open("w") as comparisons:
        prefix = stream.read(12)
        order = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(prefix[8:12])
        if order is None:
            raise ValueError("Section byte order changed")
        for number, record in enumerate(records, 1):
            source = source_records[record["csv_line"]]
            if record["source_record_id"] != labels.summary["member_sha256"] + ":" + str(source.line):
                raise ValueError("Source identity mismatch")
            client = (int(ipaddress.IPv4Address(record["client_ip"])), record["client_port"])
            server = (int(ipaddress.IPv4Address(record["server_ip"])), record["server_port"])
            forward = [read_at(stream, i, o, container["interfaces"][0], order) for i, o in
                       zip(record["forward_packet_indices"], record["forward_packet_offsets"], strict=True)]
            backward = [read_at(stream, i, o, container["interfaces"][0], order) for i, o in
                        zip(record["backward_packet_indices"], record["backward_packet_offsets"], strict=True)]
            if not forward:
                raise ValueError("Missing incoming packet trace")
            decoded = [decode_tcp(p) for p in forward]
            reverse = [decode_tcp(p) for p in backward]
            if any(((t.source_ip, t.source_port), (t.destination_ip, t.destination_port)) != (client, server) for t in decoded):
                raise ValueError("Incoming direction mismatch")
            if any(((t.source_ip, t.source_port), (t.destination_ip, t.destination_port)) != (server, client) for t in reverse):
                raise ValueError("Outgoing direction mismatch")
            trace = sorted(forward + backward, key=lambda p: p.index)
            if (len({p.index for p in trace}) != len(trace)
                    or any(b.offset <= a.offset or b.timestamp_ns < a.timestamp_ns for a, b in zip(trace, trace[1:]))):
                raise ValueError("Packet identity/order/time mismatch")
            if not decoded[0].flags & 2 or decoded[0].flags & 16:
                raise ValueError("No initial incoming SYN")
            if any(t.flags & 5 for t in decoded[:-1]) or not decoded[-1].flags & 5:
                raise ValueError("Snapshot is not first incoming FIN/RST")
            if forward[0].reference() != record["start"] or forward[-1].reference() != record["trigger"]:
                raise ValueError("Trigger/start packet reference mismatch")
            values = [max(t.segment_bytes for t in decoded),
                      max([0] + [b.timestamp_ns - a.timestamp_ns for a, b in zip(forward, forward[1:])]),
                      min(t.segment_bytes for t in decoded), server[1],
                      sum(t.header_bytes for t in decoded), len(forward)]
            if values != record["features"]:
                raise ValueError("Independent six-feature arithmetic disagrees")
            matches = Labels.match(labels.at_start(canonical(client, server), forward[0].timestamp_ns, client, server),
                                   forward[0].timestamp_ns, forward[-1].timestamp_ns, len(forward), len(backward),
                                   sum(t.segment_bytes - t.header_bytes for t in decoded),
                                   sum(t.segment_bytes - t.header_bytes for t in reverse))
            if len(matches) != 1 or matches[0].line != source.line or source.category != record["category"]:
                raise ValueError("Independent source-row join is ambiguous or incorrect")
            observed = {}
            for mode, lib in libs.items():
                lib.probe_reset()
                for packet in forward:
                    buf = C.create_string_buffer(packet.data)
                    if lib.probe_packet(buf, len(packet.data), packet.timestamp_ns):
                        raise ValueError("C feature helper rejected packet")
                value = (C.c_int64 * 6)()
                if lib.probe_features(value) or list(value) != values:
                    raise ValueError("C feature-helper mismatch: " + mode)
                observed[mode] = list(value)
            comparisons.write(json.dumps(dict(source_record_id=record["source_record_id"],
                                             category=record["category"], expected=values,
                                             host_C_observed=observed, status="PASS")) + "\n")
            forward_packets += len(forward)
            backward_packets += len(backward)
            if category_samples[record["category"]] < 2:
                category_samples[record["category"]] += 1
                def details(p):
                    t = decode_tcp(p)
                    return dict(reference=p.reference(), source_port=t.source_port,
                                destination_port=t.destination_port, segment=t.segment_bytes,
                                tcp_header=t.header_bytes, flags=t.flags, sequence=t.sequence)
                samples.append(dict(record=record, hand_trace=[details(p) for p in trace]))
            if number % 500 == 0:
                print("Validated feature/label records", number, flush=True)
    after = args.capture.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("Capture changed during independent validation")
    result = dict(status="PASS", records=len(records), category_counts=dict(Counter(r["category"] for r in records)),
                  forward_packets_checked=forward_packets, backward_packets_checked=backward_packets,
                  six_feature_comparisons=12 * len(records), mismatches=0,
                  scope="Independent direct packet reads plus actual host-compiled XDP/TC feature helpers; NO kernel execution or neural inference",
                  cohort_sha256=cohort_hash, source_binding_sha256=fingerprint(args.binding),
                  model_predictions="NOT RUN", elapsed_seconds=round(time.monotonic() - started, 3))
    (args.output / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    (args.output / "validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "labels", "binding", "cohort", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--compiler", default="clang-12")
    validate(parser.parse_args())
