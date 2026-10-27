#!/usr/bin/env python3
"""Prepare without privilege; --execute explicitly loads BPF after user approval."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import unittest
from zoneinfo import ZoneInfo

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "validation"))
from native import Native
from reference import Model
from parity import PROGRAMS, binary_input, compare_events, make_fixtures, require, sha
import test_parity


def timestamp():
    return datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y%m%d-%H%M%S-%f")


def command(output, name, argv):
    with (output / "commands.txt").open("a") as f:
        f.write(shlex.join(map(str, argv)) + "\n")
    result = subprocess.run(list(map(str, argv)), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (output / (name + ".log")).write_text(result.stdout)
    with (output / "commands.jsonl").open("a") as f:
        f.write(json.dumps(dict(name=name, argv=list(map(str, argv)), exit_code=result.returncode)) + "\n")
    require(result.returncode == 0, f"{name}: exit {result.returncode}; see {name}.log")
    return result.stdout


def manifest(directory):
    (directory / "SHA256SUMS").write_text("".join(sha(p) + "  " + str(p.relative_to(directory)) + "\n"
        for p in sorted(directory.rglob("*")) if p.is_file() and p.name not in ("SHA256SUMS", "kernel-SHA256SUMS")))


def environment():
    return dict(kernel=platform.release(), machine=platform.machine(), uid=os.getuid(),
                python=platform.python_version(), restrictions=[line for line in Path("/proc/self/status").read_text().splitlines()
                    if line.startswith(("Cap", "NoNewPrivs", "Seccomp"))])


def write_report(output, result):
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "REPORT.md").write_text(f'''# Minimal original-object kernel parity

Preparation: **{result.get('preparation', 'NOT RUN')}**.
Kernel execution: **{result.get('kernel_execution', 'NOT RUN')}**.

{result.get('error', '')}

The kernel driver opens an independently compiled original `src/xdp.bpf.c` ELF,
disables all pin paths before load, and uses private maps. No interface is
attached and no network configuration is changed. All six tail-call slots stay
empty: each original arithmetic program is invoked with a separate
`BPF_PROG_TEST_RUN`, flags=0, repeat=1; map readback captures every stage.
This explicitly does not test the populated tail-call chain. It uses no
host-compiled function as evidence of kernel execution.

Fixed arithmetic: seven boundary-safe fixtures, including five checked against
saved host tensors. Packet checks: SYN, data with TCP options, FIN, fresh RST,
and ignored reverse-source traffic. Time-dependent IATs are recomputed from
actual recorded kernel `last_packet_time` values, not assumed deterministic
wall-clock intervals. FIN/RST detection timestamps are checked by inequalities.
Two closing packets also get explicit six-stage arithmetic comparisons.

`events.jsonl`, if present, contains actual loaded program/map IDs, mode and
return value for every syscall, feature/tensor readbacks, parameter-byte checks,
and cleanup ID checks. `verifier-*.log` contains per-program kernel logs after
an execution attempt. Empty/not-created logs do not establish verifier success.
The original final program emits its normal trace message; this test does not
consume shared tracing. Prediction is separately derived from kernel logits
and is not represented as a captured original trace prediction.

No kernel test is run by the default preparation command. Any comparator unit
tests use explicitly MOCK events. PASS for preparation means compilation,
fixture/reference and protocol checks passed; it does not mean kernel parity.

Full results: [results.json](results.json). Exact commands: [commands.txt](commands.txt).

```json
{json.dumps(result.get('comparisons', result.get('nonprivileged', {})), indent=2)}
```

Remaining uncertainty: actual kernel parity until an approved execution passes;
after that, only these small fixtures are covered. Real hook delivery, populated
tail calls, cross-CPU/concurrent flow access, model-update races, arbitrary input
overflow, and original FP32 model parity remain outside scope.
''')
    manifest(output)


def prepare(args):
    output = (args.output or ROOT / "verification-logs" / ("kernel-parity-" + timestamp())).resolve()
    output.mkdir(parents=True, exist_ok=False)
    build = output / ".output"
    build.mkdir()
    print(f"Preparing: {output}", flush=True)
    result = dict(preparation="FAIL", kernel_execution="NOT RUN", environment=environment())
    try:
        require(platform.machine() == "x86_64" and sys.byteorder == "little", "x86-64 little-endian ABI required")
        host_path = args.host_results.resolve()
        bundle, model = make_fixtures(ROOT, host_path)
        (output / "fixtures.json").write_text(json.dumps(bundle, indent=2) + "\n")
        (output / "input.bin").write_bytes(binary_input(bundle, model))
        require(len(bundle["fixtures"]) == 7 and len(bundle["packets"]) == 5, "unexpected scope expansion")
        includes = ROOT / ".output/libbpf/usr/include"
        lib = ROOT / ".output/libbpf/libbpf.a"
        bpftool = ROOT / ".output/bpftool/bpftool"
        for p in (includes / "bpf/libbpf.h", lib, bpftool):
            require(p.exists(), f"build baseline dependencies first: missing {p}")
        result["compiler"] = command(output, "compiler", [args.compiler, "--version"])
        result["bpftool"] = command(output, "bpftool", [bpftool, "version"])
        btf = command(output, "vmlinux", [bpftool, "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
        (build / "vmlinux.h").write_text(btf)
        (output / "kernel-btf.sha256").write_text(sha(Path("/sys/kernel/btf/vmlinux")) + "\n")
        command(output, "build-bpf", [args.compiler, "-g", "-O3", "-target", "bpf", "-I" + str(build),
            "-I" + str(includes), "-I" + str(ROOT / "libbpf/include"), "-I/usr/include/x86_64-linux-gnu",
            "-c", ROOT / "src/xdp.bpf.c", "-o", build / "original.bpf.o"])
        command(output, "build-driver", [args.compiler, "-g", "-O2", "-Wall", "-Wextra", "-I" + str(includes),
            ROOT / "validation/kernel_parity/runner.c", lib, "-lelf", "-lz", "-o", build / "kernel-runner"])
        command(output, "inspect-object", [build / "kernel-runner", "--inspect", build / "original.bpf.o",
            output / "input.bin", output / "inspection.jsonl", output])
        inspection = [json.loads(line) for line in (output / "inspection.jsonl").read_text().splitlines()]
        require(len(inspection) == 1 and inspection[0]["event"] == "schema"
                and inspection[0]["all_pin_paths_disabled"], "unexpected inspect/load behavior")
        command(output, "build-host-crosscheck", [args.compiler, "-O3", "-shared", "-fPIC",
            "-I" + str(ROOT / "validation/include"), ROOT / "validation/native.c", "-o", build / "host.so"])
        native = Native(build / "host.so")
        for case in bundle["fixtures"]:
            actual, label = native.infer(case["raw"])
            require(actual == case["stages"] and label == case["prediction"], "small-fixture host cross-check failed")
        test_parity.CONTEXT = bundle, model
        with (output / "unit-tests.log").open("w") as stream:
            tests = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(test_parity))
        require(tests.wasSuccessful(), "nonprivileged protocol tests failed")
        result["nonprivileged"] = dict(tests_run=tests.testsRun, failures=len(tests.failures), errors=len(tests.errors),
            safe_fixtures_host_and_python=7, saved_host_fixtures=5, saved_dataset_hashes="INSPECTED; dataset not rerun",
            original_object_schema=inspection[0], protocol_event_tests="MOCKS ONLY")
        source_paths = list((ROOT / "src").glob("*")) + list((ROOT / "validation").rglob("*"))
        hashes = {str(p.relative_to(ROOT)): sha(p) for p in source_paths
                  if p.is_file() and ".output" not in p.parts and "__pycache__" not in p.parts}
        (output / "source-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
        for name, expected in bundle["baseline_hashes"].items():
            require(sha(ROOT / name) == expected, f"baseline modified: {name}")
        result["preparation"] = "PASS"
        result["approval_command"] = f"sudo -n {shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} --execute {shlex.quote(str(output))}"
    except Exception as exc:
        result["error"] = str(exc)
    write_report(output, result)
    print(json.dumps(result, indent=2), flush=True)
    print(f"Report: {output / 'REPORT.md'}", flush=True)
    return 0 if result["preparation"] == "PASS" else 1


def execute(bundle_dir):
    require(os.geteuid() == 0, "--execute requires an explicitly approved privileged invocation")
    bundle_dir = bundle_dir.resolve()
    for line in (bundle_dir / "SHA256SUMS").read_text().splitlines():
        expected, path = line.split("  ", 1)
        require(sha(bundle_dir / path) == expected, f"prepared file changed: {path}")
    for path, expected in json.loads((bundle_dir / "source-hashes.json").read_text()).items():
        require(sha(ROOT / path) == expected, f"source changed after preparation: {path}")
    prepared = json.loads((bundle_dir / "results.json").read_text())
    require(prepared["preparation"] == "PASS", "preparation must pass before privileged execution")
    output = bundle_dir / ("kernel-" + timestamp())
    output.mkdir()
    print(f"Kernel evidence: {output}", flush=True)
    result = dict(preparation="PASS (previous bundle)", kernel_execution="FAIL", environment=environment())
    try:
        command(output, "driver", [bundle_dir / ".output/kernel-runner", "--execute", bundle_dir / ".output/original.bpf.o",
            bundle_dir / "input.bin", output / "events.jsonl", output])
        events = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
        result["comparisons"] = compare_events(json.loads((bundle_dir / "fixtures.json").read_text()),
            Model.load(ROOT / "src/mlp_params.bpf.h"), events)
        result["kernel_execution"] = "PASS"
    except Exception as exc:
        result["error"] = str(exc)
    write_report(output, result)
    print(json.dumps(result, indent=2), flush=True)
    print(f"Report: {output / 'REPORT.md'}", flush=True)
    return 0 if result["kernel_execution"] == "PASS" else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host-results", type=Path, help="saved successful host results.json; required to prepare")
    p.add_argument("--output", type=Path, help="new preparation directory")
    p.add_argument("--compiler", default="clang-12")
    p.add_argument("--execute", type=Path, metavar="PREPARED_BUNDLE", help="privileged BPF execution; obtain user approval first")
    args = p.parse_args()
    if args.execute:
        return execute(args.execute)
    p.error("--host-results required for unprivileged preparation") if not args.host_results else None
    return prepare(args)


if __name__ == "__main__":
    raise SystemExit(main())
