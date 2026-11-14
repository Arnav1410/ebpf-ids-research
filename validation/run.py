#!/usr/bin/env python3
"""Run offline validation and preserve evidence; needs Python 3 + clang/UBSan.

Never loads BPF, changes interfaces, imports the training scripts, or invokes
sudo. Run from any cwd. The baseline source and datasets are read-only inputs.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace
import unittest
from zoneinfo import ZoneInfo

sys.dont_write_bytecode = True
from native import Native
from reference import Model
import test_validation


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Results(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append(dict(test=test.id(), status="PASS"))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.append(dict(test=test.id(), status="SKIP", reason=reason))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append(dict(test=test.id(), status="FAIL", detail=self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append(dict(test=test.id(), status="ERROR", detail=self._exc_info_to_string(err, test)))

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.records.append(dict(test=str(subtest), status="FAIL", detail=self._exc_info_to_string(err, test)))


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, value):
        for stream in self.streams:
            stream.write(value)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="NEW evidence directory (default: verification-logs/numerical-TIMESTAMP)")
    parser.add_argument("--compiler", default="clang-12")
    parser.add_argument("--smoke-log", type=Path, help="optional existing smoke logs; saved model dump checked and archived")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    timestamp = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y%m%d-%H%M%S-%f")
    output = (args.output or root / "verification-logs" / ("numerical-" + timestamp)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    build = output / ".output"
    build.mkdir()
    print(f"Evidence: {output}", flush=True)
    sources = sorted(p for p in (root / "src").iterdir() if p.is_file())
    sources += sorted((root / "dataset").glob("*.npy"))
    before = {str(p.relative_to(root)): digest(p) for p in sources}
    validation_sources = sorted(p for p in (root / "validation").rglob("*")
                                if p.is_file() and "__pycache__" not in p.parts)
    manifest = dict(baseline=before, validation={str(p.relative_to(root)): digest(p) for p in validation_sources})
    (output / "source-hashes.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def command(label, argv):
        with (output / "commands.txt").open("a") as f:
            f.write(shlex.join(argv) + "\n")
        result = subprocess.run(argv, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (output / (label + ".log")).write_text(result.stdout)
        with (output / "commands.jsonl").open("a") as f:
            f.write(json.dumps(dict(label=label, argv=argv, cwd=str(root), exit_code=result.returncode)) + "\n")
        if result.returncode:
            raise RuntimeError(f"{label} failed: {result.stdout}")
        return result.stdout

    summary = dict(status="FAIL", scope="offline host execution, not kernel/JIT validation",
                   command=shlex.join([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]),
                   environment=dict(kernel=platform.release(), machine=platform.machine(),
                                    python=platform.python_version(), uid=os.getuid()),
                   evidence={}, source_integrity="NOT CHECKED")
    try:
        if sys.byteorder != "little" or platform.machine() not in ("x86_64", "amd64"):
            raise RuntimeError("current native packet ABI characterization requires little-endian x86-64")
        compiler = shutil.which(args.compiler)
        if compiler is None:
            raise RuntimeError(f"compiler unavailable: {args.compiler}")
        summary["environment"]["compiler"] = command("compiler-version", [compiler, "--version"])
        summary["environment"]["commit"] = command("commit", ["git", "rev-parse", "HEAD"]).strip()
        native_source = str(root / "validation/native.c")
        include = "-I" + str(root / "validation/include")
        command("build-native", [compiler, "-O3", "-Wall", "-Wextra", "-Wno-unused-parameter",
                                "-fPIC", "-shared", include, native_source, "-o", str(build / "native.so")])
        command("build-ubsan", [compiler, "-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                               include, native_source, "-o", str(build / "native-ubsan")])
        smoke = args.smoke_log.resolve() if args.smoke_log else None
        if smoke:
            archive = output / "smoke-evidence"
            archive.mkdir()
            for name in ("run.log", "trace.log", "state.json", "active-model.json", "net-after.json"):
                shutil.copyfile(smoke / name, archive / name)
            smoke = archive
        context = SimpleNamespace(root=root, output=output, native=Native(build / "native.so"),
                                  sanitizer=build / "native-ubsan", model=Model.load(root / "src/mlp_params.bpf.h"),
                                  smoke=smoke, evidence=summary["evidence"])
        test_validation.CONTEXT = context
        suite = unittest.defaultTestLoader.loadTestsFromModule(test_validation)
        with (output / "test-output.log").open("w") as log:
            result = unittest.TextTestRunner(stream=Tee(sys.stdout, log), verbosity=2, resultclass=Results).run(suite)
        summary.update(status="PASS" if result.wasSuccessful() else "FAIL", tests_run=result.testsRun,
                       failures=len(result.failures), errors=len(result.errors), skips=len(result.skipped),
                       tests=result.records)
    except Exception as exc:
        summary["error"] = str(exc)
        print(f"ERROR: {exc}", file=sys.stderr)
    finally:
        after = {str(p.relative_to(root)): digest(p) for p in sources}
        summary["source_integrity"] = "PASS" if after == before else "FAIL"
        if after != before:
            summary["status"] = "FAIL"
        (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
        evidence = summary["evidence"]
        report = f'''# Numerical validation run

Status: **{summary['status']}**. Tests: {summary.get('tests_run', 0)}; failures: {summary.get('failures', 0)};
errors: {summary.get('errors', 0)}; skips: {summary.get('skips', 0)}.

This status means host comparisons/characterization assertions passed. Known
defects are deliberately characterized, not repaired. Kernel execution, JIT,
real map concurrency and real tail-call behavior were NOT tested in this run.

Command: `{summary['command']}`

Baseline source/data SHA256 integrity: **{summary['source_integrity']}**.
Complete per-test statuses and numerical evidence: [results.json](results.json).
Full output: [test-output.log](test-output.log).
Exact compile/environment commands: [commands.txt](commands.txt).
Compiler diagnostics: [build-native.log](build-native.log), [build-ubsan.log](build-ubsan.log).
Original files and framework SHA256: [source-hashes.json](source-hashes.json).

## Dataset layer comparison

```json
{json.dumps(evidence.get('dataset', 'NOT COMPLETED'), indent=2)}
```

## Observed discrepancies and boundary behavior

```json
{json.dumps({k: v for k, v in evidence.items() if k in ('equal_logit_discrepancy', 'uint64_normalization_wrap', 'real_header_iat_wrap', 'normalization_sign_change', 'linear_narrowing', 'ipv4_options_parser', 'malformed_ip_length', 'flow_lifecycle', 'original_float', 'ubsan')}, indent=2)}
```

Fixed-vector per-stage integer tensors and clearly labeled dequantized-header
floating diagnostics are in `results.json` under `evidence.fixtures`. They do not
substitute for comparison with an original FP32 checkpoint. No label-based
classification accuracy was calculated.

Next: with approval, run deterministic BPF_PROG_TEST_RUN inputs in an isolated
environment and compare captured kernel feature/per-layer values to these host
fixtures. Where clocks cannot be controlled, validate arithmetic stages with
explicit injected feature values using a separate validation-only BPF harness.
Do not change the existing detector to obtain those observations without approval.
'''
        if "error" in summary:
            report += "\nFailure: " + summary["error"] + "\n"
        (output / "REPORT.md").write_text(report)
        files = sorted(p for p in output.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
        (output / "SHA256SUMS").write_text("".join(digest(p) + "  " + str(p.relative_to(output)) + "\n" for p in files))
        print(f"Saved: {output / 'REPORT.md'}", flush=True)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
