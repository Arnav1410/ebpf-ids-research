"""Real, isolated BPF test-run validation; fixture comparison is not kernel evidence."""
import json
from pathlib import Path
import shutil
import struct
import subprocess

from .artifacts import ROOT, environment, sha256, write_json
from .model import STAGES, infer, model_identity, pack_model
from .reference import conformance_vectors

VALID_PACKETS = (("valid_1", 10, 20), ("valid_2", 40, 24), ("valid_3", 0, 20))
SKIPPED_CASES = ("source_mismatch", "non_ipv4", "non_tcp", "truncated_ethernet",
                 "truncated_ipv4", "truncated_tcp")
FEATURE_FIELDS = ("max_packet_length", "max_duration", "min_packet_length", "dst_port",
                  "header_length", "num_packet", "last_packet_time")


def _integer(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def compare_kernel_output(result, vectors, model):
    """Return detailed discrepancies; this pure function never executes eBPF."""
    errors = []

    def mismatch(where, expected, actual):
        errors.append({"location": where, "expected": expected, "actual": actual})

    def equal(where, expected, actual):
        # bool compares equal to integers in Python but is not a protocol integer.
        if type(actual) is not type(expected) or actual != expected:
            mismatch(where, expected, actual)

    if not isinstance(result, dict):
        mismatch("report", "JSON object", result)
        return errors
    equal("schema_version", 1, result.get("schema_version"))
    equal("executed", True, result.get("executed"))
    records = result.get("vectors")
    if not isinstance(records, list):
        mismatch("vectors", "array", records)
        records = []
    equal("vectors.count", len(vectors), len(records))
    seen = set()
    for position, record in enumerate(records):
        where = f"vectors[{position}]"
        if not isinstance(record, dict):
            mismatch(where, "object", record)
            continue
        index = record.get("index")
        if not _integer(index, 0, len(vectors) - 1) or index in seen:
            mismatch(where + ".index", "unique index in selected vectors", index)
            continue
        seen.add(index)
        expected = infer(model, vectors[index])
        for stage, count in STAGES:
            actual = record.get(stage)
            if (not isinstance(actual, list) or len(actual) != count
                    or any(not _integer(x, -(1 << 31), (1 << 31) - 1) for x in actual)):
                mismatch(where + "." + stage, f"{count} signed int32 values", actual)
            elif actual != expected[stage]:
                mismatch(where + "." + stage, expected[stage], actual)
        equal(where + ".label", expected["label"], record.get("label"))
        actual = record.get("chain_output")
        if (not isinstance(actual, list) or len(actual) != 2
                or any(not _integer(x, -(1 << 31), (1 << 31) - 1) for x in actual)):
            mismatch(where + ".chain_output", "2 signed int32 values", actual)
        elif actual != expected["output"]:
            mismatch(where + ".chain_output", expected["output"], actual)
        equal(where + ".chain_label", expected["label"], record.get("chain_label"))
    if seen != set(range(len(vectors))):
        mismatch("vectors.missing_indices", [], sorted(set(range(len(vectors))) - seen))

    cases = result.get("feature_cases")
    if not isinstance(cases, list):
        mismatch("feature_cases", "array", cases)
        cases = []
    names = [packet[0] for packet in VALID_PACKETS] + list(SKIPPED_CASES)
    equal("feature_cases.count", len(names), len(cases))
    previous_duration = 0
    cumulative_header = 0
    segments = []
    for index, name in enumerate(names):
        where = f"feature_cases[{name}]"
        if index >= len(cases):
            mismatch(where, "required case", None)
            continue
        case = cases[index]
        if not isinstance(case, dict):
            mismatch(where, "object", case)
            continue
        equal(where + ".name", name, case.get("name"))
        equal(where + ".retval", 2, case.get("retval"))
        if index >= len(VALID_PACKETS):
            equal(where + ".kind", "skipped", case.get("kind"))
            equal(where + ".flow_entries", 0, case.get("flow_entries"))
            if name == "truncated_ethernet":
                context = case.get("test_run_context")
                fields = ("input_bytes", "data", "data_end", "data_meta")
                if (not isinstance(context, dict) or
                        not all(_integer(context.get(field), 0, (1 << 32) - 1) for field in fields)):
                    mismatch(where + ".test_run_context", "returned XDP offsets and transport size", context)
                elif (context["input_bytes"] - context["data"] < 14 or context["data_meta"] != 0 or
                      context["data"] % 4 != 0 or context["data_end"] > context["input_bytes"] or
                      context["data_end"] - context["data"] != 13):
                    mismatch(where + ".test_run_context",
                             "at least 14 frame bytes with exactly 13 linear packet bytes", context)
            continue
        _, payload, header = VALID_PACKETS[index]
        equal(where + ".kind", "valid", case.get("kind"))
        equal(where + ".payload_bytes", payload, case.get("payload_bytes"))
        equal(where + ".tcp_header_bytes", header, case.get("tcp_header_bytes"))
        segments.append(payload + header)
        cumulative_header += header
        state = case.get("state")
        if not isinstance(state, dict):
            mismatch(where + ".state", "object", state)
            continue
        for field in FEATURE_FIELDS:
            if not _integer(state.get(field)):
                mismatch(where + ".state." + field, "unsigned int64", state.get(field))
        for field, expected in (("max_packet_length", max(segments)),
                                ("min_packet_length", min(segments)), ("dst_port", 5001),
                                ("header_length", cumulative_header), ("num_packet", index + 1)):
            equal(where + ".state." + field, expected, state.get(field))
        before, after = case.get("time_before_ns"), case.get("time_after_ns")
        seeded, prior = case.get("seeded_previous_ns"), case.get("previous_max_duration")
        duration, last = state.get("max_duration"), state.get("last_packet_time")
        equal(where + ".previous_max_duration", previous_duration, prior)
        if not (_integer(before) and _integer(after) and before <= after):
            mismatch(where + ".clock_interval", "0 <= before <= after", [before, after])
        else:
            if not _integer(last) or not before <= last <= after:
                mismatch(where + ".last_packet_time", [before, after], last)
            if index == 0:
                equal(where + ".seeded_previous_ns", None, seeded)
                equal(where + ".state.max_duration", 0, duration)
            elif not _integer(seeded) or seeded > before - (5_000_000 if index == 1 else 1_000_000):
                mismatch(where + ".seeded_previous_ns", "monotonic sample minus controlled delta", seeded)
            elif _integer(previous_duration):
                low, high = max(previous_duration, before - seeded), max(previous_duration, after - seeded)
                if not _integer(duration) or not low <= duration <= high:
                    mismatch(where + ".state.max_duration", [low, high], duration)
        previous_duration = duration
    cleanup = result.get("cleanup")
    if not isinstance(cleanup, dict):
        mismatch("cleanup", "complete private resource cleanup record", cleanup)
    else:
        equal("cleanup.complete", True, cleanup.get("complete"))
        pin_root = cleanup.get("private_pin_root")
        if (not isinstance(pin_root, str) or not pin_root.startswith("/sys/fs/bpf/nn_ebpf_eval_")
                or "/" in pin_root[len("/sys/fs/bpf/"):] or pin_root.endswith("/")):
            mismatch("cleanup.private_pin_root", "unique private bpffs root", pin_root)
    return errors


def _assess_driver_result(result, returncode, vectors, model):
    """Compare usable partial evidence even when the driver exits with an error."""
    record = result if isinstance(result, dict) else {}
    executed = record.get("executed")
    executed = executed if type(executed) is bool else None
    cleanup = record.get("cleanup")
    compared = returncode == 0 or executed is True
    mismatches = compare_kernel_output(result, vectors, model) if compared else []
    if returncode != 0:
        cleanup_failed = isinstance(cleanup, dict) and cleanup.get("complete") is not True
        status = "blocked" if returncode == 77 and not cleanup_failed else "fail"
        reason = str(record.get("reason") or f"Driver exited {returncode}; see kernel.log")
    else:
        status = "fail" if mismatches else "pass"
        reason = ("Kernel output disagrees with reference/protocol" if mismatches else
                  "All isolated stages, full chains, packet features and private cleanup agree")
    return {"status": status, "reason": reason, "executed": executed, "cleanup": cleanup,
            "comparison_performed": compared, "mismatches": mismatches}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def kernel_validation(dataset, model, directory, limit=32):
    """Build a host driver and compare actual baseline BPF execution with infer()."""
    directory = Path(directory).resolve()
    vectors = conformance_vectors(dataset, limit)
    source = ROOT / "evaluation/kernel_driver.c"
    obj = ROOT / "src/.output/xdp.bpf.o"
    lib = ROOT / ".output/libbpf/libbpf.a"
    include = ROOT / ".output/libbpf/usr/include"
    binary = directory / "kernel-driver"
    command = ["cc", "-O2", "-std=gnu11", "-fwrapv", "-fdata-sections", "-ffunction-sections",
               "-I" + str(include), "-I" + str(ROOT / "src"), str(source), str(lib),
               "-Wl,--gc-sections", "-lelf", "-lz", "-o", str(binary)]
    run_command = [str(binary), str(obj), str(directory / "model.bin"), str(directory / "vectors.bin")]
    inputs = sorted(path for path in (ROOT / "src").iterdir() if path.suffix in (".c", ".h"))
    inputs += [source, obj, lib, include / "bpf/bpf.h", include / "bpf/libbpf.h"]
    report = {"schema_version": 1, "claim": "kernel_stage_chain_and_packet_feature_validation",
              "status": "blocked", "executed": False, "reason": None,
              "dataset_identity": dataset.identity, "model_sha256": model_identity(model),
              "environment": environment(), "compiler_command": command, "command": run_command,
              "freshness_command": ["make", "-C", str(ROOT / "src"), "-q"],
              "hashes": {str(path.relative_to(ROOT)): sha256(path) if path.is_file() else None
                         for path in inputs},
              "vectors": [{"index": i, "source": "dataset" if i < len(vectors) - 4 else "boundary",
                           "features": list(vector)} for i, vector in enumerate(vectors)],
              "logs": {"build": "build.log", "kernel_stderr": "kernel.log",
                       "kernel_stdout": "kernel-output.json"}, "comparison_performed": False, "mismatches": []}
    for filename in ("build.log", "kernel.log", "kernel-output.json"):
        (directory / filename).open("x").close()
    with (directory / "model.bin").open("xb") as stream:
        stream.write(pack_model(model))
    with (directory / "vectors.bin").open("xb") as stream:
        for vector in vectors:
            stream.write(struct.pack("=6q", *vector))
    report["model_binary_sha256"] = sha256(directory / "model.bin")
    report["vectors_binary_sha256"] = sha256(directory / "vectors.bin")

    def finish(status, reason):
        report.update(status=status, reason=reason)
        write_json(directory / "report.json", report)
        return report

    missing = [str(path) for path in (source, obj, lib, include / "bpf/bpf.h", include / "bpf/libbpf.h")
               if not path.is_file()]
    missing += [name for name in ("cc", "make") if shutil.which(name) is None]
    if missing:
        return finish("blocked", "Missing build/execution prerequisites: " + ", ".join(missing))
    try:
        with (directory / "build.log").open("ab") as log:
            fresh = subprocess.run(report["freshness_command"], stdout=log, stderr=subprocess.STDOUT)
            report["freshness_returncode"] = fresh.returncode
            if fresh.returncode != 0:
                return finish("blocked", "Baseline build is stale (make -q returned 1)" if fresh.returncode == 1
                              else "Baseline freshness check failed; see build.log")
            build = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        report["build_returncode"] = build.returncode
        if build.returncode != 0:
            text = (directory / "build.log").read_text(errors="replace")
            missing_dependency = any(marker in text for marker in
                                     ("No such file or directory", "cannot find -l", "library not found"))
            return finish("blocked" if missing_dependency else "fail", "Driver build failed; see build.log")
        report["driver_binary_sha256"] = sha256(binary)
        with (directory / "kernel-output.json").open("ab") as stdout, (directory / "kernel.log").open("ab") as stderr:
            completed = subprocess.run(run_command, stdout=stdout, stderr=stderr)
        report["driver_returncode"] = completed.returncode
        # A terminated or malformed driver may have run BPF without reporting it.
        report["executed"] = None
    except OSError as exc:
        return finish("blocked", f"Cannot invoke build/execution prerequisite: {exc}")
    try:
        result = json.loads((directory / "kernel-output.json").read_text(), object_pairs_hook=_unique_object,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Invalid JSON constant: {value}")))
    except (ValueError, UnicodeError) as exc:
        return finish("blocked" if completed.returncode == 77 else "fail",
                      f"Driver returned {completed.returncode} without complete valid JSON: {exc}; see kernel.log")
    assessment = _assess_driver_result(result, completed.returncode, vectors, model)
    report.update(assessment)
    return finish(assessment["status"], assessment["reason"])
