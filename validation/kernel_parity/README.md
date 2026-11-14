# Minimal kernel-side parity

This harness test-runs the **original eBPF programs in the kernel**, without
editing their source, the model header, or the training pipeline. Preparation
alone does not execute BPF. Host-compiled checks are explicitly labeled as such.

Prepare and run all nonprivileged checks:

```sh
python3 validation/kernel_parity/run.py \
  --host-results verification-logs/numerical-20261026-230113-987235/results.json
```

The command prints a new `verification-logs/kernel-parity-TIMESTAMP/` bundle
and a proposed privileged command. It requires the baseline's previously built
libbpf/bpftool, clang-12, Python standard library, readable kernel BTF, and the
same little-endian x86-64 ABI as host validation. It compiles a fresh BPF ELF
**directly from `src/xdp.bpf.c` using real libbpf headers and kernel BTF**. The
host-only `validation/include` shims are never used to compile that ELF.

Preparation checks five saved fixture tensors, the saved dataset stage hashes,
the saved 5,216-byte active model dump, and baseline source/data hashes. It adds
two safe fixtures (normalization neighbors and bounded large values), compares
all seven to a fresh host-C build and Python, and runs protocol/comparator unit
tests using explicitly MOCK kernel events. No dataset rows are rerun here.

The driver is also run in `--inspect` mode: libbpf opens ELF/BTF, disables pin
paths, and checks the seven original XDP programs and original map ABI. That
mode does not call `bpf_object__load` or `BPF_PROG_TEST_RUN`. An initial harness
build error does not constitute a verifier rejection.

## Why original stages can be observed without instrumenting them

The original programs already put normalized values and hidden tensors in
`flow_map`. They overwrite those buffers as inference proceeds. Rather than
adding snapshot maps or modifying arithmetic, the harness deliberately leaves
all six relevant `progs` entries **empty**, calls each program separately with
`BPF_PROG_TEST_RUN`, and reads the flow map between calls. The attempted tail
call therefore falls through. This executes the original arithmetic and parser
bytecode, but intentionally does **not** validate the populated tail-call chain.

All stages are explicitly called; reaching an XDP test-run return does not imply
that other stages ran. Evidence requires the exact program ID and return value
for every expected invocation, plus every tensor value and feature readback.
Seven fixed fixtures require 42 arithmetic calls. Five entry-packet calls and
12 arithmetic calls for the FIN/RST results make **59 invocations** in total.

The original final stage's classification expression is emitted through shared
kernel tracing. We preserve that program and do not consume tracing. The
report derives classification from read-back logits and clearly states that
the original trace prediction was not captured. This is sufficient for layer
parity, not a fresh observation of the printed prediction expression.

## Timestamp-dependent features

Direct arithmetic fixtures have deterministic injected feature values. Packet
fixtures use actual `bpf_ktime_get_ns()` calls: the helper clock is not replaced
or claimed to be controllable in `BPF_PROG_TEST_RUN`.

For a SYN/data/FIN sequence, the driver records the `last_packet_time` left by
each actual kernel execution. The comparator independently computes expected
maximum IAT from those samples and checks all six features after every packet.
The first-packet IAT is deterministically zero. Detection start time must be at
least the closing packet's sampled time. Absolute live IAT values and timing
metrics are not compared against invented timestamps or prior smoke timings.
This checks update arithmetic conditional on observed helper samples; it does
not independently validate the clock source. A fresh RST and ignored reverse
source are also checked. FIN/RST-derived features get all six tensor checks.

## Approval and runtime scope

**Obtain explicit user approval before running the printed command**, for example:

```sh
sudo -n /usr/bin/python3 validation/kernel_parity/run.py --execute PREPARED_BUNDLE
```

`--execute` verifies all prepared artifact and source hashes before invoking the
driver. It requires a successful preparation bundle and a privileged caller.
It never invokes sudo itself. A fresh `kernel-TIMESTAMP/` directory records
actual events, comparisons, verifier logs, command output, and checksums.

Runtime operations are limited to:

- Load one private original object: seven XDP programs and five maps. No old
  BPF object is opened/reused. Set **all map pin paths to NULL before load**,
  including the two model maps which normally use global pins. No bpffs mount
  or pinned-path cleanup is needed, and existing global model pins are untouched.
- Write/read back both private model slots, select slot zero, seed private flow
  records, and confirm six tail-call entries are empty.
- Use ordinary test-run mode with `flags=0`, `repeat=1`, no live-frame mode,
  no interface attachment, and no actual packet injection. The kernel documents
  this mode at [Running BPF programs from userspace](https://docs.kernel.org/bpf/bpf_prog_run.html).
  Original `bpf_printk` calls may append normal trace messages; no trace reader
  is started and no tracing settings are changed.
- Close private object file descriptors and check that their recorded program
  and map IDs disappear. No interface, route, namespace, firewall or sysctl
  command exists in this harness. No unrelated ID is deleted or detached.

Privilege permission alone does not establish kernel support. A denied BPF load
or unsupported test-run is preserved as a failure; there is no fallback to
host execution and no automatic production modification. An object-load error
can occur before verifier entry (for example missing capabilities); inspect
the actual driver and per-program logs before calling it a verifier rejection.

## Evidence and remaining uncertainty

Preparation's `results.json` always says kernel execution **NOT RUN**. Only an
approved `--execute` run can record kernel parity PASS, and only after program
IDs, actual test-run results, model readback, all fixed/packet tensors and cleanup
checks agree. `events.jsonl` is the raw evidence; `verifier-*.log` preserves
separate kernel logs for every program and object BTF. Partial failed output is
retained. All failures stop execution without patching production source.

This small test does not establish parity over all dataset rows, actual NIC hook
delivery, populated tail-call semantics, concurrent-map safety, hot updates,
overflow safety for arbitrary inputs, FP32 parity, or classification accuracy.
Kernel test-run mode does not measure production packet-processing latency.
