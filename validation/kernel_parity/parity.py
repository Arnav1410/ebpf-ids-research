"""Small fixture bundle and strict comparison of actual kernel-driver events."""
import hashlib
import json
from pathlib import Path
import struct

from reference import FlowReference, Model, STAGES, SIZES, tcp_packet

PROGRAMS = ("xdp_preprocessing", "xdp_input_linear", "xdp_input_relu", "xdp_hidden_linear",
            "xdp_hidden_relu", "xdp_output_linear", "xdp_prog")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def make_fixtures(root, host_path):
    host_path = Path(host_path)
    host = json.loads(host_path.read_text())
    require(host["status"] == "PASS" and not host["failures"] and not host["errors"], "host run did not pass")
    hashes = json.loads((host_path.parent / "source-hashes.json").read_text())["baseline"]
    for path, expected in hashes.items():
        require(sha(root / path) == expected, f"baseline changed since host validation: {path}")
    model = Model.load(root / "src/mlp_params.bpf.h")
    recorded = host["evidence"]["fixtures"]
    fixtures = []
    for name in ("stored_mean", "one_scale_above", "one_scale_below", "small_tcp", "packet_fixture"):
        saved = recorded[name]
        events = []
        stages, label = model.infer(saved["raw"], events)
        require(not events and stages == saved["stages"] and label == saved["prediction"], f"saved fixture mismatch: {name}")
        require(saved["raw"][5] != 0, "original final-stage trace divides by packet count")
        fixtures.append(dict(name=name, raw=saved["raw"], stages=stages, prediction=label, saved_host_fixture=True))
    neighbors = [mu + (-1 if i % 2 == 0 else 1) for i, mu in enumerate(model.mean)]
    for name, raw in (("normalization_neighbors", neighbors),
                      ("bounded_large", [1480, 827560563008, 20, 12865, 233512, 7297])):
        events = []
        stages, label = model.infer(raw, events)
        require(not events, f"unsafe synthetic vector: {name}: {events}")
        fixtures.append(dict(name=name, raw=raw, stages=stages, prediction=label, saved_host_fixture=False))
    stage_hashes = host["evidence"]["dataset"]["stage_tensor_sha256"]
    require(set(stage_hashes) == set(STAGES) and all(len(h) == 64 for h in stage_hashes.values()), "missing saved stage hashes")
    dump_path = host_path.parent / "smoke-evidence/active-model.json"
    require(dump_path.exists(), "saved successful model dump required")
    dump = json.loads(dump_path.read_text())
    require(bytes(int(x, 16) if isinstance(x, str) else x for x in dump["value"]) == model.packed(), "saved model bytes differ")
    packets = [dict(name="syn", reset=True, packet=tcp_packet(flags=2).hex()),
               dict(name="data", reset=False, packet=tcp_packet(payload=b"x" * 100, tcp_options=b"\x01" * 4).hex()),
               dict(name="fin", reset=False, packet=tcp_packet(flags=0x11).hex()),
               dict(name="rst", reset=True, packet=tcp_packet(flags=4, payload=b"123").hex()),
               dict(name="reverse_ignored", reset=True, packet=tcp_packet(source="33.33.33.1", dest="33.33.33.73",
                    sport=5001, dport=12345, flags=0x11).hex())]
    return dict(format="NNKPAR1", model_sha256=hashlib.sha256(model.packed()).hexdigest(),
                model_header_sha256=sha(root / "src/mlp_params.bpf.h"),
                host_results_sha256=sha(host_path), saved_dataset_stage_hashes=stage_hashes,
                saved_model_dump_sha256=sha(dump_path), baseline_hashes=hashes,
                arithmetic_packet=tcp_packet().hex(), fixtures=fixtures, packets=packets), model


def binary_input(bundle, model):
    packet = bytes.fromhex(bundle["arithmetic_packet"])
    parts = [b"NNKPAR1\0", struct.pack("<II", len(bundle["fixtures"]), len(bundle["packets"])),
             model.packed(), struct.pack("<I", len(packet)), packet]
    parts.extend(struct.pack("<6q", *case["raw"]) for case in bundle["fixtures"])
    for case in bundle["packets"]:
        packet = bytes.fromhex(case["packet"])
        parts.extend((struct.pack("<II", int(case["reset"]), len(packet)), packet))
    return b"".join(parts)


def compare_events(bundle, model, events):
    """Only caller executing the privileged driver may label this kernel evidence.

    Unit tests also call this parser with MOCK records, always labeled as such.
    No test-run is inferred from a changed map or a derived classification.
    """
    require(not any(x["event"] == "error" for x in events), "driver reported a kernel/load/runtime/cleanup error")
    loaded = [x for x in events if x["event"] == "loaded"]
    require(len(loaded) == 1, "missing actual object-load metadata")
    programs = {x["name"]: x for x in loaded[0]["programs"]}
    require(set(programs) == set(PROGRAMS), "missing loaded programs")
    ids = [p["id"] for p in programs.values()]
    require(all(i > 0 for i in ids) and len(set(ids)) == 7, "invalid program IDs")
    require(all(p["type"] == 6 and p["xlated_prog_len"] > 0 for p in programs.values()), "not loaded XDP bytecode")
    maps = loaded[0]["maps"]
    require(len(maps) == 5 and len({m["id"] for m in maps}) == 5, "invalid private map IDs")
    schemas = [x for x in events if x["event"] == "schema"]
    require(len(schemas) == 1 and schemas[0]["all_pin_paths_disabled"], "pinning not disabled")
    models = [x for x in events if x["event"] == "model"]
    require(sorted((m["slot"], m["bytes_verified"]) for m in models) == [(0, 5216), (1, 5216)], "parameter readback incomplete")
    tails = [x for x in events if x["event"] == "tail_call_slots"]
    require(len(tails) == 1 and tails[0]["empty"] and tails[0]["slots"] == 6, "tail-call isolation unproven")
    cleanups = [x for x in events if x["event"] == "cleanup"]
    require(len(cleanups) == 1 and cleanups[0]["private_program_ids_absent"]
            and cleanups[0]["private_map_ids_absent"] and cleanups[0]["attachments_created"] == 0
            and cleanups[0]["pins_created"] == 0, "cleanup not confirmed")
    calls = [x for x in events if x["event"] == "test_run"]
    for call in calls:
        require(call["stage"] in programs and call["program_id"] == programs[call["stage"]]["id"], "test-run program ID mismatch")
        require(call["retval"] == 2 and call["flags"] == 0 and call["repeat"] == 1, "wrong test-run mode/result")
    expected_calls = []
    comparisons = []

    def tensors(actual, expected, where):
        require(len(actual) == 6, f"missing stage tensors: {where}")
        for i, stage in enumerate(STAGES):
            require(len(actual[i]) == SIZES[i] and actual[i] == expected[stage], f"tensor mismatch: {where}/{stage}")

    records = [x for x in events if x["event"] == "fixture"]
    require(len(records) == len(bundle["fixtures"]), "missing/extra fixed fixtures")
    for i, (case, actual) in enumerate(zip(bundle["fixtures"], records)):
        require(actual["index"] == i and actual["features"] == case["raw"], f"feature seed/readback mismatch: {case['name']}")
        tensors(actual["stages"], case["stages"], case["name"])
        require(actual["prediction_derived"] == case["prediction"], "derived prediction mismatch")
        expected_calls.extend(("fixture", i, name) for name in PROGRAMS[:6])
        comparisons.append(dict(name=case["name"], feature_values="PASS", stage_tensors="PASS",
                                prediction_derived=actual["prediction_derived"]))
    records = [x for x in events if x["event"] == "packet"]
    require(len(records) == len(bundle["packets"]), "missing/extra packet cases")
    reference = FlowReference()
    packet_results = []
    for i, (case, actual) in enumerate(zip(bundle["packets"], records)):
        require(actual["index"] == i, "packet index mismatch")
        if case["reset"]:
            reference = FlowReference()
        packet = bytes.fromhex(case["packet"])
        require(actual["flow_present"] == (case["name"] != "reverse_ignored"), "packet filter/flow presence mismatch")
        expected_calls.append(("packet", i, "xdp_prog"))
        if actual["flow_present"]:
            timestamp = actual["last_packet_time"]
            require(timestamp > 0, "kernel timestamp absent")
            if reference.flows:
                require(timestamp >= next(iter(reference.flows.values()))[6], "nonmonotonic kernel sample")
            expected = reference.packet(packet, timestamp)
            require(actual["features"] == expected[:6], f"packet features mismatch: {case['name']}")
            if packet[47] & 5:
                require(actual["detection_start_time"] >= timestamp, "FIN/RST detection timestamp missing")
                arithmetic_events = []
                expected_stages, _ = model.infer(expected[:6], arithmetic_events)
                require(not arithmetic_events, "unexpected unsafe measured packet features")
                tensors(actual.get("stages", []), expected_stages, case["name"])
                expected_calls.extend(("packet", i, name) for name in PROGRAMS[:6])
            else:
                require(actual["detection_start_time"] == 0, "premature detection timestamp")
                require("stages" not in actual, "nonclosing packet stage run")
            packet_results.append(dict(name=case["name"], features=expected[:6],
                sampled_kernel_timestamp=timestamp, comparison="PASS", time_basis="stored bpf_ktime_get_ns samples"))
        else:
            require(not reference.flows and "stages" not in actual, "unexpected ignored-flow state")
            packet_results.append(dict(name=case["name"], ignored="PASS"))
    actual_calls = [(x["kind"], x["index"], x["stage"]) for x in calls]
    require(actual_calls == expected_calls, "stage invocation sequence/count mismatch")
    return dict(fixed_fixtures=comparisons, packet_fixtures=packet_results,
                test_run_invocations=len(calls), tensor_comparisons=6 * (len(comparisons) + 2),
                original_trace_prediction="NOT CAPTURED; classification derived separately from read-back logits",
                tail_call_chain="NOT TESTED; array intentionally empty and stages individually test-run",
                cleanup="PASS")
