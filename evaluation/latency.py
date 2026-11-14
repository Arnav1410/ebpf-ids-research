#!/usr/bin/env python3
"""Host C timings on the unchanged held-out partition; replay old kernel evidence.

Never loads BPF or changes networking. JSON, Python, I/O and validation are
outside the C timed regions. Existing numerical results are read-only inputs.
"""
import argparse
from array import array
from collections import Counter
import ctypes as C
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import struct
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.data import reproduction, digest
from evaluation.offline import MODES
from quantization.calibrate import split
from quantization.reference import LayerModel, ArithmeticFailure
from quantization.benchmark import percentile, paired_ratios, verify_block
from validation.reference import Model, STAGES, SIZES

SCOPES = ("resident_arithmetic", "existing_wrapper")
OLD = ROOT / "verification-logs/final-demo-20261107/offline-r2"
KERNEL = ROOT / "verification-logs/layer-specific-20261107/benchmark-ready/run-20261107-121805-782575"


def summary_ns(values):
    if not values or any(type(v) is not int or v <= 0 for v in values):
        raise ValueError("Empty/nonpositive/invalid measured durations; do not silently drop samples")
    return dict(samples=len(values), mean_ns=statistics.fmean(values), median_ns=statistics.median(values),
                p95_ns=percentile(values, .95), p99_ns=percentile(values, .99),
                minimum_ns=min(values), maximum_ns=max(values), population_stddev_ns=statistics.pstdev(values))


def stage_hash(values):
    return hashlib.sha256(struct.pack("<" + "i" * len(values), *values)).hexdigest()


def evidence_contract(directory):
    """Reconstruct the ORIGINAL scale-held-out IDs; do not make a new split."""
    baseline = json.loads((directory / "metrics.json").read_text())
    if baseline["status"] != "PASS" or baseline["input_count"] != 13844 or baseline["split"] != "scaling-heldout":
        raise ValueError("Expected successful original 13,844-row scaling-heldout evidence")
    if digest(ROOT / "src/mlp_params.bpf.h") != baseline["checkpoint_sha256"]:
        raise ValueError("Frozen header differs from saved numerical experiment")
    rows, labels = reproduction(ROOT)
    ids = split(rows)[1]
    original, layer = Model.load(ROOT / "src/mlp_params.bpf.h"), LayerModel.load()
    packed = {mode: bytearray() for mode in MODES}
    expected_labels = {mode: [] for mode in MODES}
    numerical_counts = Counter()
    with gzip.open(directory / "predictions.jsonl.gz", "rt") as source:
        count = 0
        for count, line in enumerate(source, 1):
            if count > len(ids):
                raise ValueError("Extra archived prediction record")
            record = json.loads(line)
            index = ids[count - 1]
            if (record["row_index"] != index or record["features"] != rows[index]
                    or record["encoded_label"] != labels[index]):
                raise ValueError("Archived identity/vector/partition changed")
            for mode in MODES:
                model = layer if mode == "tc_layer_specific" else original
                issues = []
                values, label = model.infer(rows[index], issues)
                if issues:
                    raise ArithmeticFailure("unsafe", str(issues))
                saved = record["configurations"][mode]
                hashes = {name: stage_hash(values[name]) for name in STAGES}
                if (saved["status"] != "PASS" or saved["label"] != label
                        or saved["logits"] != values["logits"] or hashes != saved["stage_sha256"]):
                    raise ValueError("Saved/reference logits, predictions or intermediate tensors differ: " + mode)
                tensor = [0] * 192
                for j, name in enumerate(STAGES):
                    tensor[32*j:32*j+len(values[name])] = values[name]
                packed[mode].extend(struct.pack("<192i", *tensor))
                expected_labels[mode].append(label)
                numerical_counts[mode] += 136
        if count != len(ids) or count != 13844:
            raise ValueError("Missing archived prediction record")
    return dict(ids=ids, raw=[rows[i] for i in ids], packed=packed, labels=expected_labels,
                baseline=baseline, checked_integer_values=dict(numerical_counts),
                source_hashes={str(p.relative_to(ROOT)): digest(p) for p in
                               (directory / "metrics.json", directory / "predictions.jsonl.gz", directory / "samples.json")})


class Report(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ("elapsed_ns", "successful", "failed", "first_bad", "checksum")] + [
        ("start_cpu", C.c_int32), ("end_cpu", C.c_int32)]


def build(output, compiler):
    directory = output / ".output"
    directory.mkdir()
    libraries = {}
    for mode in MODES:
        path = directory / (mode + ".so")
        includes = ("validation/include",) if mode == "xdp_q16" else ("tc/tests/include", "validation/include")
        argv = [compiler, "-O3", "-shared", "-fPIC", "-pthread", "-fno-lto"]
        argv += ["-I" + str(ROOT / p) for p in includes]
        if mode == "xdp_q16":
            argv.append("-DLATENCY_XDP")
        if mode == "tc_layer_specific":
            argv.append("-DIDS_LAYER_SPECIFIC")
        argv += [str(ROOT / "evaluation/latency_adapter.c"), "-o", str(path)]
        process = subprocess.run(argv, capture_output=True, text=True)
        (output / (mode + "-build.log")).write_text(process.stdout + process.stderr)
        with (output / "commands.jsonl").open("a") as dest:
            dest.write(json.dumps(dict(argv=argv, exit_code=process.returncode)) + "\n")
        if process.returncode:
            raise RuntimeError("Latency host build failed: " + mode)
        lib = C.CDLL(str(path))
        lib.latency_init()
        lib.latency_run.argtypes = [C.c_int, C.c_int, C.c_uint, C.POINTER(C.c_int64),
            C.POINTER(C.c_int32), C.POINTER(C.c_int32), C.POINTER(C.c_uint64),
            C.POINTER(C.c_int32), C.POINTER(C.c_int32), C.POINTER(Report)]
        lib.latency_run.restype = C.c_int
        lib.latency_clock_resolution_ns.restype = C.c_uint64
        libraries[mode] = lib
    return libraries


class Buffers:
    def __init__(self, raw, expected, labels):
        self.count = len(raw)
        self.inputs = (C.c_int64 * (6*self.count))(*(x for r in raw for x in r))
        self.expected = (C.c_int32 * (192*self.count)).from_buffer_copy(expected)
        self.expected_labels = (C.c_int32 * self.count)(*labels)
        self.durations = (C.c_uint64 * self.count)()
        self.outputs = (C.c_int32 * (192*self.count))()
        self.labels = (C.c_int32 * self.count)()

    def run(self, lib, scope, kind):
        report = Report()
        code = lib.latency_run(scope, kind, self.count, self.inputs, self.expected, self.expected_labels,
                               self.durations, self.outputs, self.labels, C.byref(report))
        result = {name: getattr(report, name) for name, _ in Report._fields_}
        result.update(exit_code=code, kind=kind)
        if kind in (1, 3):
            result["duration_ns"] = list(self.durations)
        return result


def check_block(block, n, cpu, expected_checksum=None):
    if block["exit_code"] or block["failed"] or block["successful"] != n:
        raise RuntimeError("Incomplete/incorrect benchmark: " + str({k:v for k,v in block.items() if k!="duration_ns"}))
    if block["start_cpu"] != cpu or block["end_cpu"] != cpu:
        raise RuntimeError("Benchmark ran outside selected CPU")
    if expected_checksum is not None and block["checksum"] != expected_checksum:
        raise RuntimeError("Output checksum changed across benchmark runs")
    if block["kind"] in (1, 3):
        if len(block["duration_ns"]) != n:
            raise RuntimeError("Missing timing samples")
        summary_ns(block["duration_ns"])
    if block["kind"] == 2 and block["elapsed_ns"] <= 0:
        raise RuntimeError("Invalid batch timer")


def saved_kernel(output, run=KERNEL):
    """Audit and summarize existing measured kernel blocks; never rerun BPF."""
    result = json.loads((run / "results.json").read_text())
    if result["status"] != "PASS" or result["cleanup"] != "PASS":
        raise ValueError("Historical kernel benchmark did not pass")
    checksums = 0
    for line in (run / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        path = (run / name).resolve()
        if not path.is_relative_to(run.resolve()) or digest(path) != expected:
            raise ValueError("Historical kernel evidence checksum mismatch: " + name)
        checksums += 1
    config = json.loads((run.parent / "config.json").read_text())
    workloads = {w["name"]: w for w in config["workloads"]}
    blocks = json.loads((run / "blocks.json").read_text())
    for block in blocks:
        workload = workloads[block["workload"]]
        verify_block(block, block["mode"], workload["kind"], workload["raw"],
                     config["warmup_per_block"], config["samples_per_block"], result["environment"]["benchmark_cpu"])
    summaries = {}
    for name in workloads:
        summaries[name] = {}
        for mode in ("static_q16", "layer_specific"):
            found = [b for b in blocks if b["workload"] == name and b["mode"] == mode]
            if len(found) != config["blocks"]:
                raise ValueError("Historical block count mismatch")
            summary = summary_ns([v for b in found for v in b["duration_ns"]])
            old = result["summaries"][name][mode]
            for key in ("samples", "median_ns", "minimum_ns", "maximum_ns"):
                if summary[key] != old[key]:
                    raise ValueError("Historical timing summary mismatch")
            summary["block_medians_ns"] = [statistics.median(b["duration_ns"]) for b in found]
            summaries[name][mode] = summary
    report = dict(status="PASS saved-evidence audit; NOT a new kernel run", raw_run=str(run.relative_to(ROOT)),
        recorded_environment=result["environment"], saved_file_hashes_verified=checksums,
        measured_calls=result["measured_calls"], warmup_calls=result["warmup_calls"],
        summaries=summaries, workloads=config["workloads"], cleanup=result["cleanup"],
        all_six_stages="Executing controller checks every call; stored block tensors independently replayed",
        original_xdp="NOT COMPARABLE: existing parity runner individually test-runs stages with empty tail-call map",
        new_kernel_execution="NOT RUN", network_attachments="NONE in recorded benchmark")
    (output / "kernel-saved-evidence.json").write_text(json.dumps(report, indent=2)+"\n")
    return report


def execute(args):
    if not 6 <= args.trials <= 24 or args.trials % 6:
        raise ValueError("Use 6, 12, 18 or 24 trials for balanced six-configuration ordering")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    protected = sorted({p for d in ("src", "tc", "quantization", "validation", "demo", "deployment")
                        for p in (ROOT/d).rglob("*") if p.is_file() and ".output" not in p.parts and "__pycache__" not in p.parts})
    protected += [ROOT/"evaluation/offline.py", ROOT/"evaluation/tc_vectors.c"]
    hashes = {str(p.relative_to(ROOT)): digest(p) for p in protected}
    (output / "preserved-source-hashes.json").write_text(json.dumps(hashes, indent=2)+"\n")
    print("Checking archived 13,844-row references before measuring", flush=True)
    contract = evidence_contract(args.source_evidence.resolve())
    libraries = build(output, args.compiler)
    allowed = os.sched_getaffinity(0)
    cpu = args.cpu if args.cpu is not None else min(allowed)
    if cpu not in allowed:
        raise ValueError("Requested CPU is not allowed")
    source_hashes = contract["source_hashes"]
    inputs = array("q", (x for r in contract["raw"] for x in r))
    if sys.byteorder != "little":
        raise ValueError("This verified evidence contract is little-endian")
    input_hash = hashlib.sha256(inputs.tobytes()).hexdigest()
    plan = dict(created=datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(), samples=len(contract["ids"]),
        ids=contract["ids"], input_vectors_int64le_sha256=input_hash, trials=args.trials,
        warmup="One full 13844-vector pass per configuration per trial",
        measured="One per-call-timed and one separately batch-timed pass per configuration per trial",
        configurations=[(s,m) for s in SCOPES for m in MODES],
        order="Six configurations rotate left by trial modulo six; individual/batch pass order reverses on odd trials",
        original_evidence_hashes=source_hashes, clock="C clock_gettime(CLOCK_MONOTONIC_RAW)",
        timer_control="One 13844-call empty indirect-call/timer-pair control per compiled mode; raw, no subtraction",
        cpu=cpu, execution="Sequential single host thread; no packet/kernel execution", outlier_policy="Retain all samples")
    (output/"plan.json").write_text(json.dumps(plan,indent=2)+"\n")
    environment=dict(kernel=platform.release(),machine=platform.machine(),python=platform.python_version(),
        cpu_model=next(x.split(":",1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith("model name")),
        compiler=subprocess.check_output([args.compiler,"--version"],text=True),libc=platform.libc_ver(),
        branch=subprocess.check_output(["git","branch","--show-current"],cwd=ROOT,text=True).strip(),
        baseline_commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        original_allowed_cpus=sorted(allowed),benchmark_cpu=cpu,
        restrictions=[x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith(("CapEff:","NoNewPrivs:","Seccomp:"))],
        clock_resolution_ns={m:l.latency_clock_resolution_ns() for m,l in libraries.items()})
    buffers={m:Buffers(contract['raw'],contract['packed'][m],contract['labels'][m]) for m in MODES}
    blocks=[]; controls={}; checksums={}; phase_start=time.perf_counter_ns()
    os.sched_setaffinity(0,{cpu})
    try:
        for mode in MODES:
            control=buffers[mode].run(libraries[mode],0,3);check_block(control,len(contract['ids']),cpu)
            controls[mode]=control
        configurations=[(scope,mode) for scope in SCOPES for mode in MODES]
        for trial in range(args.trials):
            offset=trial%len(configurations)
            for scope,mode in configurations[offset:]+configurations[:offset]:
                buffer,lib=buffers[mode],libraries[mode];index=SCOPES.index(scope)
                warm=buffer.run(lib,index,0);check_block(warm,buffer.count,cpu,checksums.get(mode))
                checksums[mode]=warm['checksum']
                block=dict(trial=trial,scope=scope,mode=mode,warmup={k:v for k,v in warm.items() if k!='duration_ns'})
                blocks.append(block)
                for kind in ((1,2) if trial%2==0 else (2,1)):
                    observed=buffer.run(lib,index,kind)
                    block['individual' if kind==1 else 'batch']=observed
                    check_block(observed,buffer.count,cpu,checksums[mode])
            print(f"Host paired trial {trial+1}/{args.trials} complete",flush=True)
    finally:
        os.sched_setaffinity(0,allowed)
        with gzip.open(output/"raw-timings.jsonl.gz","wt") as dest:
            for mode,control in controls.items():dest.write(json.dumps(dict(timer_control=mode,observation=control))+"\n")
            for block in blocks:dest.write(json.dumps(block,separators=(",",":"))+"\n")
    wall_ns=time.perf_counter_ns()-phase_start
    if hashlib.sha256(C.string_at(buffers[MODES[0]].inputs,C.sizeof(buffers[MODES[0]].inputs))).hexdigest()!=input_hash:
        raise RuntimeError("Input vectors mutated")
    summaries={}
    for scope in SCOPES:
        summaries[scope]={}
        for mode in MODES:
            selected=[b for b in blocks if b['scope']==scope and b['mode']==mode]
            data=summary_ns([v for b in selected for v in b['individual']['duration_ns']])
            batch_total=sum(b['batch']['elapsed_ns'] for b in selected)
            data.update(batch_total_ns=batch_total,batch_mean_per_inference_ns=batch_total/(len(selected)*len(contract['ids'])),
                sequential_host_inferences_per_second=len(selected)*len(contract['ids'])*1e9/batch_total,
                successful=sum(b[k]['successful'] for b in selected for k in ('warmup','individual','batch')),
                failed=sum(b[k]['failed'] for b in selected for k in ('warmup','individual','batch')),
                trials=[dict(trial=b['trial'],individual=summary_ns(b['individual']['duration_ns']),
                             batch_ns=b['batch']['elapsed_ns'],batch_ns_per_inference=b['batch']['elapsed_ns']/len(contract['ids'])) for b in selected])
            data['trial_mean_population_stddev_ns']=statistics.pstdev(t['individual']['mean_ns'] for t in data['trials'])
            summaries[scope][mode]=data
        baseline=summaries[scope]['tc_q16']
        for mode in MODES:
            item=summaries[scope][mode]
            item['relative_to_tc_q16_percent']={k:100*(item[k]-baseline[k])/baseline[k] for k in ('mean_ns','median_ns','batch_mean_per_inference_ns')}
        summaries[scope]['paired_tc_layer_over_tc_q16']=paired_ratios([
            (summaries[scope]['tc_q16']['trials'][i]['individual']['median_ns'],summaries[scope]['tc_layer_specific']['trials'][i]['individual']['median_ns']) for i in range(args.trials)])
    # These checks happen after timed work, not concurrently with it.
    if any(digest(ROOT/p)!=h for p,h in hashes.items()) or any(digest(ROOT/p)!=h for p,h in source_hashes.items()):
        raise RuntimeError("Preserved source or old numerical evidence changed")
    kernel=saved_kernel(output,args.kernel_evidence.resolve())
    result=dict(status="PASS",host_execution="Actual compiled C primitives and unchanged full host wrappers; not eBPF kernel execution",
        input_count=len(contract['ids']),trials=args.trials,host=summaries,
        timer_controls={m:summary_ns(c['duration_ns']) for m,c in controls.items()},
        benchmark_phase_wall_ns=wall_ns,
        wall_scope="Includes warmup, per-call/batch runs, correctness checks, Python dispatch, progress and final raw-log serialization; not a latency statistic",
        precheck_reference_integer_values=contract['checked_integer_values'],
        pre_and_post_every_pass="Every invocation checked for label and 136 integers across six stages against archived/reference expectations; checks excluded from timers",
        historical_kernel_evidence=kernel,
        original_numerical_evidence="UNCHANGED; identical archived logits, labels and stage hashes, including original calibration-held-out IDs",
        calibrated_model_sha256=digest(ROOT/'quantization/calibrated.json'),checkpoint_sha256=digest(ROOT/'src/mlp_params.bpf.h'),
        input_vectors_int64le_sha256=input_hash,environment=environment,
        source_preservation=dict(status='PASS',files=len(hashes),original_evidence_files=len(source_hashes)),
        plan_sha256=digest(output/'plan.json'),raw_timings_sha256=digest(output/'raw-timings.jsonl.gz'),
        peak_process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        network_changes='NONE',new_kernel_execution='NOT RUN; reuse independently audited recorded benchmark',
        caveats=['Wrapper scope is intentionally asymmetric: TC resets all mock tables and copies parameters each vector; XDP native_mlp does not.',
                 'Resident arithmetic excludes TC program dispatch, map access, tail-call and publication costs. It is a host arithmetic adapter, not kernel execution.',
                 'Individual timings include timer/indirect-call overhead; raw control values are reported without subtraction.',
                 'Batch timing includes loop, return-status/output stores; no per-call clocks or correctness comparisons.',
                 'Sequential host loop throughput is not NIC, packet or concurrent-flow throughput.',
                 'WSL2 scheduling/frequency/cache effects and correlated samples limit cross-environment interpretation.'])
    (output/'results.json').write_text(json.dumps(result,indent=2)+"\n")
    plot(output,result)
    print(json.dumps(dict(status='PASS',output=str(output),input_count=len(contract['ids']),trials=args.trials,
                         new_kernel_execution=result['new_kernel_execution']),indent=2))


def plot(output,result):
    os.environ.setdefault('MPLCONFIGDIR','/tmp/nn-ebpf-latency-matplotlib')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(10,4),layout='constrained')
    for ax,scope in zip(axes,SCOPES):
        for index,mode in enumerate(MODES):
            s=result['host'][scope][mode]
            ax.bar(index,s['median_ns']/1000,color=['#27648a','#4b9688','#d68532'][index],alpha=.8)
            ax.scatter([index]*result['trials'],[t['individual']['median_ns']/1000 for t in s['trials']],s=12,color='black',zorder=4)
        ax.set(xticks=range(3),xticklabels=['XDP Q16','TC Q16','TC layer'],ylabel='Host per-call p50 (µs)',
               title='Resident arithmetic' if scope==SCOPES[0] else 'Existing wrappers (asymmetric setup)')
        ax.set_ylim(bottom=0)
    fig.suptitle('13,844 fixed vectors · bars: pooled p50 · dots: trial p50 · host C, not kernel')
    fig.savefig(output/'host-latency.png',dpi=180);fig.savefig(output/'host-latency.pdf');plt.close(fig)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-evidence',type=Path,default=OLD)
    parser.add_argument('--kernel-evidence',type=Path,default=KERNEL)
    parser.add_argument('--trials',type=int,default=12)
    parser.add_argument('--cpu',type=int)
    parser.add_argument('--compiler',default='clang-12')
    execute(parser.parse_args())
