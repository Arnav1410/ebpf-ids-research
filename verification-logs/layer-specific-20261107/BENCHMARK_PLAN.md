# Planned Gate 6 measurement protocol (not executed)

Prerequisite: actual attached Gate 5 tests must pass in both modes. No benchmark
result exists yet. This plan does not add runtime-adaptive scales or change
production BPF/network processing.

Use private `BPF_PROG_TEST_RUN` calls with **repeat=1**, recording the returned
`duration` field. In upstream v6.6 the kernel timer brackets the invocation loop
and reports time per repetition. Local vendored `libbpf/src/bpf.c` passes that
field through. The WSL2-specific patched implementation was not source-audited;
these values will be labeled kernel-reported test-run durations, including its
fixed runner overhead. [Upstream timer/program invocation](https://github.com/torvalds/linux/blob/v6.6/net/bpf/test_run.c#L28-L89),
[classifier test-run setup](https://github.com/torvalds/linux/blob/v6.6/net/bpf/test_run.c#L889).

A larger repeat count would be invalid here: the first inference releases the
workspace and marks the flow DONE. Subsequent repetitions would skip inference.
Instead reset only private, quiescent flow/workspace/result maps between single
calls, outside the kernel duration. Verify each call produces a fresh completed
record, all six stages, correct forwarding return code, released workspace,
consistent mode/parameters and expected tensors/logits. State seeding is test
setup, not a host implementation substituted for kernel arithmetic.

Proposed workloads:

- Direct preprocessing through the original six-stage tail chain on a fixed
  small-TCP feature vector, and on one saved live packet-derived snapshot.
- The original TC entry on a controlled FIN packet with a fresh pre-existing
  flow: parsing, feature extraction, synchronization, MLP and result publication.
  This measures that closing-packet path, not average traffic or creation cost.

Keep both loaded modes private/unattached. Pin only their benchmark processes
to one allowed CPU; change no global scheduler, networking or offload settings.
Use 12 blocks per workload/mode, 32 warm-up calls and 64 measured calls per block.
Alternate which mode runs first across blocks. Keep every measured duration and
report sample count, median, p10/p90 and paired block-median ratios. A seeded
paired bootstrap may describe the variability of the block ratios; it cannot
remove WSL2 host scheduling, clock or frequency uncertainty. Do not trim outliers
silently. Detect zero/saturated timer results rather than manufacturing a time.

Do not change production inference to instrument per-stage clocks. Therefore
per-stage time and rescaling-only cost remain unmeasured: the modes also differ
in rounding and safety guards. The six-stage measurements include existing map
telemetry/publication and test-run overhead, not just multiply-add instructions.
No NIC throughput or end-to-end application latency claim follows from them.

Record environment, actual CPU affinity, program IDs, bytecode/JIT sizes where
reported, model/map value sizes, parameter hashes, fixture features, expected and
kernel tensors, stage/prediction count deltas, final labels and ID-only cleanup
proof. Kernel load and private-map mutation require separate approval. Ordinary
(non-live) classifier test-runs do not inject packet actions into a physical
network; actual attached traffic is a separate Gate 5 result.
[Kernel test-run scope](https://docs.kernel.org/bpf/bpf_prog_run.html).
