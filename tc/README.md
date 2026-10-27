# Separate TC ingress IDS prototype

This is a demo of the original six-feature, 6→32→32→2, static Q16 neural network
at **TC ingress**. It preserves the XDP source, baseline runner, model arrays,
training scripts and validation framework. Work is restricted to a `feature/`
branch; this implementation was prepared on `feature/tc-ingress-prototype`.

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
   per-CPU prediction record with stage mask 63. Compare **every intermediate
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
- `src/common.h`, `handler.bpf.h`, `mlp.bpf.h`, and `params.bpf.h` are included
  directly; model arrays are taken unchanged from `src/mlp_params.bpf.h`.
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
- A demo-only per-CPU array captures the latest completed result on each CPU:
  raw features, all stage tensors, model slot, completion timestamp and actual
  predicted label. Global counters use atomic increments. This telemetry adds
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
flow-lifecycle policy. The baseline's flow-map exhaustion, tuple reuse,
concurrency and arbitrary-input arithmetic limits remain. Snapshot records can
be overwritten by later completions on the same CPU.

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
