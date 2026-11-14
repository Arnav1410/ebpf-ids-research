#!/usr/bin/env python3
"""Predictions-blind packet/label reconstruction; never loads a neural model."""
import argparse
from array import array
from collections import Counter
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import resource
import sqlite3
import struct
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from evaluation.cic.capture import Reader, decode_tcp, PacketError, FeatureWindow
from evaluation.cic.labels import Labels, canonical, CATEGORIES


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def source_key(packet):
    """Identify an unsupported TCP packet when enough tuple bytes remain.

    This does not accept that packet into feature extraction. It prevents a
    session with an identifiable unsupported packet from being silently repaired.
    """
    data = packet.data
    if packet.linktype != 1 or len(data) < 38 or data[12:14] != b"\x08\x00" or data[23] != 6:
        return None
    ihl = (data[14] & 15) * 4
    if not 20 <= ihl <= 60 or len(data) < 14 + ihl + 4:
        return None
    if int.from_bytes(data[20:22], "big") & 0x1fff:
        return None
    a, b = struct.unpack_from("!II", data, 26)
    sport, dport = struct.unpack_from("!HH", data, 14 + ihl)
    return canonical((a, sport), (b, dport))


def select(connection, target0, target1):
    """Equal water-filling across sorted source categories; rank was frozen."""
    selected = []
    for label, target in ((0, target0), (1, target1)):
        categories = [r[0] for r in connection.execute(
            "SELECT DISTINCT category FROM candidates WHERE eligible=1 AND label=? ORDER BY category", (label,))]
        cursors = [iter(connection.execute(
            "SELECT data FROM candidates WHERE eligible=1 AND label=? AND category=? ORDER BY rank,line",
            (label, category))) for category in categories]
        chosen = 0
        while chosen < target and cursors:
            available = []
            for cursor in cursors:
                try:
                    value = next(cursor)
                except StopIteration:
                    continue
                selected.append(json.loads(value[0]))
                chosen += 1
                available.append(cursor)
                if chosen == target:
                    break
            cursors = available
    return selected


def reconstruct(args):
    started = time.monotonic()
    binding = json.loads(args.binding.read_text())
    if fingerprint(args.labels) != binding["labels_zip"]["sha256"]:
        raise ValueError("Label ZIP hash changed")
    labels = Labels(args.labels)
    if labels.summary["member_sha256"] != binding["labels_member"]["sha256"]:
        raise ValueError("Label member hash changed")
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    (out / ".output").mkdir()
    database = sqlite3.connect(out / ".output/candidates.sqlite")
    database.execute("CREATE TABLE candidates(line INTEGER PRIMARY KEY,key TEXT,label INTEGER,category TEXT,rank TEXT,data TEXT,eligible INTEGER DEFAULT 0)")
    states = {}
    first_syn = {}
    prestart = set()
    reused = set()
    bad_keys = set()
    packet_reasons = Counter()
    counts = Counter()
    records_by_line = {r.line: r for r in labels.records}
    reader = Reader(args.capture)
    capture_before = args.capture.stat()
    for packet in reader:
        if packet.index % 1_000_000 == 0:
            print(json.dumps(dict(progress_packets=packet.index, active_windows=len(states),
                                  reconstructed=counts["unique_exact_matches"])), flush=True)
        try:
            tcp = decode_tcp(packet)
        except PacketError as error:
            packet_reasons[str(error)] += 1
            key = source_key(packet)
            if key is not None:
                bad_keys.add(key)
                state = states.pop(key, None)
                if state:
                    for r in state["labels"]:
                        r.reason = "UNSUPPORTED_PACKET_IN_OBSERVATION"
            continue
        client = (tcp.source_ip, tcp.source_port)
        server = (tcp.destination_ip, tcp.destination_port)
        key = canonical(client, server)
        syn = bool(tcp.flags & 2 and not tcp.flags & 16)
        if syn:
            if key in first_syn:
                if first_syn[key] != (client, tcp.sequence):
                    reused.add(key)
                    states.pop(key, None)
                    continue
            else:
                counts["syn_sessions"] += 1
                first_syn[key] = (client, tcp.sequence)
                if packet.timestamp_ns is None:
                    bad_keys.add(key)
                    continue
                matches = labels.at_start(key, packet.timestamp_ns, client, server)
                if matches and key not in prestart and key not in bad_keys:
                    for r in matches:
                        r.reason = "NO_ELIGIBLE_INCOMING_FIN_RST"
                    states[key] = dict(client=client, server=server, start=packet.reference(),
                                       labels=matches, last=packet.timestamp_ns, backward=0,
                                       backward_indices=array("Q"), backward_offsets=array("Q"),
                                       forward_payload=0, backward_payload=0,
                                       window=FeatureWindow(client, server, compact=True))
                    if len(states) > 100_000:
                        raise RuntimeError("Active-flow resource limit; no silent eviction")
        elif key not in first_syn:
            prestart.add(key)
        state = states.get(key)
        if state is None or key in reused:
            continue
        now = packet.timestamp_ns
        if now is None or now < state["last"]:
            for r in state["labels"]:
                r.reason = "TIMESTAMP_REORDER_OR_MISSING"
            states.pop(key)
            continue
        state["last"] = now
        incoming = client == state["client"]
        if incoming:
            state["forward_payload"] += tcp.segment_bytes - tcp.header_bytes
        else:
            state["backward"] += 1
            state["backward_indices"].append(packet.index)
            state["backward_offsets"].append(packet.offset)
            state["backward_payload"] += tcp.segment_bytes - tcp.header_bytes
        try:
            snapshot = state["window"].add(packet, tcp)
        except PacketError as error:
            for r in state["labels"]:
                r.reason = str(error)
            states.pop(key)
            continue
        if snapshot is None:
            continue
        counts["incoming_termination_windows"] += 1
        matching = labels.match(state["labels"], state["start"]["timestamp_ns"], now,
                                snapshot["features"][5], state["backward"],
                                state["forward_payload"], state["backward_payload"])
        if len(matching) != 1:
            reason = "AMBIGUOUS_LABEL_MATCH" if matching else "LABEL_WINDOW_DURATION_OR_COUNTER_MISMATCH"
            for r in state["labels"]:
                r.reason = reason
            states.pop(key)
            continue
        r = matching[0]
        identifier = labels.summary["member_sha256"] + ":" + str(r.line)
        rank = hashlib.sha256(("20261107\n" + identifier).encode()).hexdigest()
        value = dict(source_record_id=identifier, csv_line=r.line, original_flow_id=r.flow_id,
                     capture_day="2017-07-04", category=r.category, label=CATEGORIES[r.category],
                     protocol=6, client_ip=str(ipaddress.IPv4Address(state["client"][0])),
                     client_port=state["client"][1], server_ip=str(ipaddress.IPv4Address(state["server"][0])),
                     server_port=state["server"][1], features=snapshot["features"],
                     start=state["start"], trigger=snapshot["trigger"], trigger_flags=snapshot["trigger_flags"],
                     forward_packet_indices=snapshot["forward_packet_indices"],
                     forward_packet_offsets=snapshot["forward_packet_offsets"],
                     backward_packet_indices=state["backward_indices"].tolist(),
                     backward_packet_offsets=state["backward_offsets"].tolist(),
                     source_timestamp=r.raw_timestamp, source_duration_ns=r.duration_ns,
                     observed_backward_packets=state["backward"],
                     source_payload_bytes=[r.forward_payload, r.backward_payload],
                     matching="unique_tuple_minute_exact_duration_and_forward_backward_packet_payload_counts",
                     direction_policy="observed initial SYN initiator to responder; source-label endpoints must agree",
                     clock_policy="UTC-3 source clock, both 12-hour candidates; unique observed start minute",
                     rank=rank)
        try:
            database.execute("INSERT INTO candidates(line,key,label,category,rank,data) VALUES(?,?,?,?,?,?)",
                             (r.line, json.dumps(key), value["label"], r.category, rank, json.dumps(value, separators=(",", ":"))))
            r.reason = "EXACT_MATCH_PENDING_REUSE_AUDIT"
            counts["unique_exact_matches"] += 1
        except sqlite3.IntegrityError:
            r.reason = "AMBIGUOUS_SOURCE_RECORD_MULTIPLE_SESSIONS"
        states.pop(key)
    capture_after = args.capture.stat()
    if ((capture_before.st_size, capture_before.st_mtime_ns) != (capture_after.st_size, capture_after.st_mtime_ns)
            or reader.digest.hexdigest() != binding["pcap"]["sha256"] or not reader.complete):
        raise RuntimeError("Capture changed or full-file checksum failed")
    if reader.md5.hexdigest() != binding["pcap"]["md5"]:
        raise RuntimeError("Capture MD5 failed")
    exclusions = Counter()
    support = Counter()
    with gzip.open(out / "exclusions.jsonl.gz", "wt") as dest:
        for r in labels.records:
            key = canonical(r.source, r.destination)
            if key in reused:
                r.reason = "REUSED_TCP_TUPLE"
            elif key in prestart:
                r.reason = "PACKETS_BEFORE_COMPLETE_SESSION_START"
            elif key in bad_keys:
                r.reason = "UNSUPPORTED_PACKET_ON_TUPLE"
            if r.reason == "EXACT_MATCH_PENDING_REUSE_AUDIT":
                database.execute("UPDATE candidates SET eligible=1 WHERE line=?", (r.line,))
                r.reason = "ELIGIBLE"
                support[r.category] += 1
            else:
                exclusions[r.reason] += 1
                dest.write(json.dumps(dict(csv_line=r.line, category=r.category, reason=r.reason)) + "\n")
        for row in labels.other_rows:
            exclusions[row["reason"]] += 1
            dest.write(json.dumps(row) + "\n")
    database.commit()
    with gzip.open(out / "eligible.jsonl.gz", "wt") as dest:
        for row in database.execute("SELECT data FROM candidates WHERE eligible=1 ORDER BY rank,line"):
            dest.write(row[0] + "\n")
    pilot = select(database, 100, 100)
    with (out / "pilot.jsonl").open("w") as dest:
        for row in pilot:
            dest.write(json.dumps(row, separators=(",", ":")) + "\n")
    database.close()
    result = dict(status="RECONSTRUCTED; PILOT_VALIDATION_PENDING", capture_packets=reader.metadata["packets"],
                  labels=labels.summary, matching_counts=dict(counts), eligible_categories=dict(support),
                  eligible=sum(support.values()), exclusions=dict(exclusions),
                  packet_scope_exclusions=dict(packet_reasons), reused_tcp_tuples=len(reused),
                  pilot_selected=len(pilot), pilot_categories=dict(Counter(r["category"] for r in pilot)),
                  pilot_sha256=fingerprint(out / "pilot.jsonl"), source_binding_sha256=fingerprint(args.binding),
                  selection_policy_sha256=fingerprint(ROOT / "evaluation/cic/SELECTION_POLICY.json"),
                  model_predictions="NOT RUN", elapsed_seconds=round(time.monotonic() - started, 3),
                  peak_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    (out / "reconstruction.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    reconstruct(parser.parse_args())
