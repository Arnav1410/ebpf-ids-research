# Separate TC ingress IDS prototype

This is a demo of the original six-feature, 6→32→32→2, static Q16 neural network
at **TC ingress**. It preserves the XDP source, baseline runner, model arrays,
training scripts and validation framework. Work is restricted to a `feature/`
branch; this implementation was prepared on `feature/tc-ingress-prototype`.

## Phase 1 concurrency update (kernel gate passed)

The current development branch is `feature/tc-concurrency-bidirectional`, based
on verified TC commit `f06718f611a0f816048dfe254ef7a2f8edc6f788`. The modified
implementation passed its own kernel gate in
[`ready-r2/run-20261106-102343-292996`](../verification-logs/tc-phase1-20261106/ready-r2/run-20261106-102343-292996/REPORT.md).
This includes verifier acceptance, the ingress regression, CPU-pinned kernel
concurrency checks, ten live TCP flows, all-layer numerical parity and owned
resource cleanup. See [Phase 1 verification](PHASE1_VERIFICATION.md) for counts
and limits. **Phase 2 is deferred at the user's request:** no egress code or
canonical bidirectional keys have been added.

- `flow_map` is a BTF-described HASH with a top-level `bpf_spin_lock`. It stores
  directional IPv4/TCP identity, counters, timestamps, TCP flags, sequence and
  inference status; it contains **no MLP tensors**. Creation uses `BPF_NOEXIST`
  then always looks up the winner. Packet metadata, helper timestamps and all
  map lookups precede the short locked update/snapshot region. Only the unlock
  helper is called while locked; no other helper/BPF function or tail call is
  allowed there. Controller reads use `BPF_F_LOCK`.
  Per-flow `bytes` sums TCP-segment bytes (IP total length minus IP header),
  whereas the global byte counter sums `skb->len`. Neither is a wire-byte
  measurement under offloads. Global counters are individually atomic; their
  multi-field snapshots are interpreted only after controlled traffic quiesces.
- A one-entry PERCPU_ARRAY `workspace` owns the immutable feature snapshot,
  chosen model slot and all intermediate tensors across the six tail calls.
  Non-sleepable TC execution is CPU-pinned across the chain; CPU pinning does
  not imply universal non-reentrancy. A compare-and-swap busy guard prevents a
  nested entry from overwriting its owner's workspace. Rejected nested triggers
  are counted, pass traffic, leave the flow IDLE, and can retry on a later
  FIN/RST. No inference is promised for an isolated rejected trigger with no
  subsequent closing packet. Ordinary live tests require zero guard rejections.
  True interrupt/RT nesting is not forced by the tests.
- Under the flow lock, the first accepted FIN/RST changes IDLE → RUNNING and
  snapshots all six features. After unlock, every stage uses only that workspace.
  On completion, the full record is atomically published as a new HASH value in
  `results`, followed by RUNNING → DONE. No result value is modified in place.
  Missing targets/models or failed publication unwind RUNNING → IDLE, count the
  failure and release ownership. Repeated triggers during RUNNING/DONE still
  update monitoring counters, but do not run a second inference. Successful
  results persist per flow, rather than being overwritten by another flow on
  the same CPU. Maps may be deleted/reset only when traffic is quiescent.
- Model weights, scaling and the equal-logit label-1 rule are unchanged. The
  controller freezes the private parameter map against userspace updates after
  initializing both slots; this mode does not support hot model updates.
- Concurrent timestamps can reach the lock out of sampling order. A late
  sample contributes zero IAT and cannot move `last_ns` backward; reorders are
  counted. This avoids unsigned underflow and preserves ordinary ordered-flow
  feature definitions. Features describe observed processing, not wire order.
- The compare-and-swap uses BPF ISA v3 (`-mcpu=v3`) with clang-12. The current
  target is WSL2 x86_64 kernel `6.6.87.2-microsoft-standard-WSL2`, libbpf 1.3.

To reproduce, prepare a new bundle without privilege:

```bash
./run-tc-smoke.sh --prepare --phase1
```

Then run the printed `--run ... --phase1` command in an approved root terminal;
use interactive `sudo` if credentials are needed. Preparation prints the exact
new bundle path. Historical bundles retain their original source/binary hashes,
including documentation; the completion README update means the old `ready-r2`
bundle should be treated as archived evidence. A new preparation is required
for another live run. No runtime source changed after the successful test.

The privileged command first loads an unattached private TC object for actual
`BPF_PROG_TEST_RUN` checks: deterministic mean/above/below vectors, four
CPU-pinned workers updating the same flow, ten distinct flows, all six missing
tail targets, missing model, duplicate triggers, malformed frames, full flow
and result maps, and an injected busy workspace. The skb test-run API does not
support the XDP/raw-tracepoint CPU flag; pthread affinity provides CPU placement.
At least two allowed CPUs are required. The test asserts exact observed call
counts, byte totals, state transitions and owner release. It creates scheduling
opportunities, not proof of every possible interleaving. Busy-map injection is
explicitly a guard test, not an actual interrupt nesting claim.

It then runs the existing attached minimal counter/ingress smoke test and a
separate ten-connection TCP exchange, with new ports and private maps. Every
completed tensor/logit/label is compared to `validation/reference.py` for its
captured features. It checks flow totals against actual observed matching skbs,
not assumed TCP packet counts. Result records from synthetic fixed vectors are
kept separate from real attached traffic in the evidence. Any verifier, runtime,
comparison or cleanup failure fails the run. Verifier logs and ID-only release
proof are saved for each object. `--run BUNDLE` without `--phase1` remains the
ingress-only smoke test; `--minimal-only` still runs the counter alone.

Phase 1 does not add flow expiry or reset DONE on tuple reuse. The source-IP
gate, supported packet scope and inherited extreme-value arithmetic limits
remain; use fresh tuples for separate sessions. There is no bidirectional mode,
egress attachment or physical-interface command. Those require separately
authorized Phase 2 implementation and verification, which is currently deferred.

Kernel references: [spin-lock restrictions](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/include/uapi/linux/bpf.h#L3645),
[CPU-pinned BPF execution](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/include/linux/filter.h#L548),
[skb test-run flags](https://github.com/torvalds/linux/blob/v6.6/net/bpf/test_run.c#L889).

## Build, inspect and test without privilege

Build the existing baseline dependencies first if `.output/libbpf/libbpf.a` and
`.output/bpftool/bpftool` are absent. Then, from the repository root:

```bash
./run-tc-smoke.sh --prepare
```

The preparation command builds `tc/.output/tc_min.bpf.o`, `tc_ids.bpf.o`, and
`controller`, opens the objects without loading them, and runs all nonprivileged
TC tests. It prints a new `verification-logs/tc-prepare-TIMESTAMP` directory and
the exact proposed privileged command. Python 3, clang-12, kernel BTF, libelf/zlib
development files and the existing vendored libbpf/bpftool build are required.
The existing runtime dependencies additionally include iproute2 (`ip`, `tc`).

Preparation PASS means compilation and **host-only** parser/arithmetic tests.
It does not imply verifier acceptance, TC attachment, or live packet processing.
No original source/model is overwritten and no retraining runs.

## Live demonstration — obtain approval first

After explicit approval, run the printed bundle, for example:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-prepare-TIMESTAMP
```

The runner verifies the prepared source/binary hashes and feature branch before
creating anything. It performs these phases in order:

1. Refuse existing `tcids-server` or `tcids-client` namespaces; acquire a dedicated
   runner lock. Create both namespaces. Create the veth pair **inside** the server
   namespace, move its client peer into the client namespace, and configure only:

   | Namespace | Interface | Address |
   | --- | --- | --- |
   | `tcids-server` | `tcids-s0` | `33.33.33.1/24` |
   | `tcids-client` | `tcids-c0` | `33.33.33.73/24` |

   Host interfaces, addresses and routes are never configured. This avoids even
   temporarily adding the demo subnet to the host routing table.
2. Load the **minimal counter** independently, create clsact exclusively on
   `tcids-s0`, attach ingress, verify the actual filter/program ID, and complete
   a controlled TCP greeting/FIN/response. Require an increased ingress counter.
   Detach the owned filter, verify object release, and remove its empty clsact.
3. Load the **full TC pipeline**, initialize/read back both 5,216-byte model
   slots, select slot zero, populate all six tail-call slots and verify their
   program IDs and `BPF_PROG_TYPE_SCHED_CLS` type. Only then attach the entry
   program to the same isolated interface.
4. Run a fresh TCP exchange using source port 40002. Require matching-source
   packets, six executed stages, zero tail-call failures, and a completed
   per-flow prediction record with stage mask 63. Compare **every intermediate
   tensor and the kernel-computed label** with the existing Python fixed-point
   reference for the exact captured six-feature vector.
5. Detach only the filter whose current ID matches the recorded entry program,
   require the detach syscall acknowledgement, successfully dump both filter
   directions to establish absence, and remove the empty clsact. Close private
   maps/programs and check their recorded IDs disappear. Delete the owned namespace
   instances by recorded inode; veth peers and any remaining owned qdiscs are
   removed with them. Check namespace absence and protected-file hashes.

The demo uses actual attached TC ingress processing. It does not substitute
host compilation or BPF test-run output for evidence of attached packet delivery.
The controlled response also verifies that normal packets pass the classifier.

If full inference fails, the runner stops and retains all logs and any successful
minimal-counter evidence. To demonstrate the smaller counter independently:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-prepare-TIMESTAMP --minimal-only
```

Do not rerun preparation after approval without reviewing the new bundle: edits
to the prototype or binaries invalidate the prepared hashes.

Cleanup uses filter dumps rather than an exact post-detach GETTFILTER query:
on the WSL2 kernel, removing the last filter can remove its chain, making that
exact query return `EINVAL` ("Cannot find specified filter chain"). Query errors
are never accepted as absence evidence. The controller still checks the exact
program ID before detach and requires a successful detach syscall; the runner
requires successful **empty** ingress and egress dumps before deleting clsact.
Runtime logs retain those dumps and `filter-absence.json` for each phase.

Private object release is checked with `controller --list-ids prog|map`, using
only `BPF_PROG_GET_NEXT_ID` / `BPF_MAP_GET_NEXT_ID`. It does **not** open object
FDs. In contrast, repeatedly running `bpftool map show` opens and closes map FDs
and can trigger additional deferred last-user cleanup on program-array maps.
The WSL kernel's [program-array release implementation](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/kernel/bpf/arraymap.c#L1011)
and [map FD/reference implementation](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/kernel/bpf/syscall.c#L676)
explain why cleanup observation must avoid reopening objects. Each phase saves
`ids-absent.json` only after every owned program/map ID is absent; persistent
IDs, enumeration errors and timeouts still fail the run. No global map is
deleted or unpinned to make this check pass.

## Implementation and compatibility

- `tc_min.bpf.c`: one minimal TC ingress packet/byte counter, returning
  `TC_ACT_OK` for every packet.
- `tc_ids.bpf.c`: a separate `struct __sk_buff` entry program and six **TC**
  inference programs. They never tail-call into an XDP program. The controller
  checks the loaded type of every program before populating the program array.
- `src/mlp.bpf.h` and `params.bpf.h` are included directly; model arrays are
  taken unchanged from `src/mlp_params.bpf.h`. TC persistent state and locked
  feature updates now live separately in `tc/abi.h` / `tc_ids.bpf.c`.
  The original source-IP gate `33.33.33.73`, FIN **or** RST trigger, feature
  ordering, arithmetic shifts, and equal-logit label-1 rule are preserved.
- `bpf_skb_load_bytes` handles non-linear skb reads. The TC parser validates IPv4
  IHL, total length, TCP data offset and physical skb bounds, and passes fragments
  and unsupported packets unscored. IPv4/TCP header options are read at their
  correct offsets. Unlike the known original fixed-offset parser bug, IHL>5
  does not shift the interpreted ports/flags. Valid ordinary IPv4/TCP feature
  definitions remain unchanged: TCP-segment length (IP length minus IP header),
  maximum forward IAT in nanoseconds, minimum segment length, destination port,
  total TCP-header bytes and forward packet count.
- The private controller disables **all** pin paths before load. It neither
  reuses nor unlinks `/sys/fs/bpf/nn_idx` or `/sys/fs/bpf/nn_parameters`. The TC
  object may retain those map *names*, but its map *IDs* and FDs are private.
  No bpffs mount or shared trace reader is needed.
- A per-flow hash retains each completed immutable result: raw features, all
  stage tensors, model slot, completion timestamp and actual predicted label.
  Global counters use atomic increments. This telemetry adds
  overhead and is not intended as a performance result or lossless event log.

## Evidence and cleanup

Each invocation prints its evidence directory. Preparation preserves build
output, object inspection and `tests.log`. Runtime preserves exact command
arguments/exit codes, `minimal/` and `inference/` controller events, individual
verifier logs, TC filter snapshots, TCP client/server output, inference tensors,
`results.json`, `REPORT.md`, `owned.json`, and checksums.

Ctrl+C or SIGTERM invokes targeted cleanup. Do not run competing processes in
the private namespaces. SIGKILL or a crash cannot run Python cleanup; in that
case, after reviewing `owned.json` and obtaining approval, use:

```bash
sudo ./run-tc-smoke.sh --cleanup verification-logs/tc-prepare-TIMESTAMP/run-TIMESTAMP
```

Manual cleanup accepts only the two exact demo namespace names, requires matching
recorded inodes, and refuses namespaces containing live processes. It does not
kill unknown processes or touch other namespaces. The controller exits when
its input pipe closes; a leftover traffic server times out. A replaced namespace
or unexpected filter is reported rather than silently treated as ours. The
unheld `/run/tcids-demo.lock` file can remain after exit.

## Limits

This is an ingress-only IDS demonstration. **Optional egress counting is not
implemented yet**, and no bidirectional flow aggregation is claimed. There is no
packet dropping, prevention, dynamic quantization, model retraining, or new
flow-expiry policy. Flow-map exhaustion, tuple reuse and arbitrary-input
arithmetic limits remain. Phase 1 passed the recorded kernel/concurrency suite;
that is coverage of the tested cases, not a proof of all possible interleavings.

TC sees skbs later in the stack than XDP; GRO/GSO can change packet granularity.
The runner does not silently disable offloads. A small successful TCP exchange
does not establish wire-packet equivalence under aggregation, throughput,
accuracy, or full numerical correctness. VLAN/IPv6/fragments pass without
classification. Parser-rejection statistics include unsupported non-IP traffic.
IAT values come from real kernel helper clocks and are not preselected; parity
uses the identical feature vector read from the completed TC record.

Host tests exercise the TC C source with test-only helpers. Only privileged run
logs can establish verifier acceptance, filter attachment, real tail-call
execution and live packet predictions. See the actual `results.json`; do not
interpret prepared code or a proposed demo command as a runtime PASS.
