# TC ingress classification and bidirectional monitoring

This is a demo of the original six-feature, 6→32→32→2, static Q16 neural network
at **TC ingress**. It preserves the XDP source, baseline runner, model arrays,
training scripts and validation framework. Work is restricted to a `feature/`
branch; this implementation was prepared on `feature/tc-ingress-prototype`.

The optional [offline-calibrated arithmetic experiment](../quantization/README.md)
adds `--mode layer_specific` as a separately built inference variant.
`--mode static_q16` remains the default. Both modes passed actual attached
ingress/egress regression tests and private kernel benchmarking. The calibrated
mode improved numerical fidelity but was slower in the measured WSL2 workloads.
Neither mode changes the monitoring directions or six ingress-based MLP features.

## Phase 1 concurrency update (kernel gate passed)

Phase 1 was developed on `feature/tc-concurrency-bidirectional`, based
on verified TC commit `f06718f611a0f816048dfe254ef7a2f8edc6f788`. The modified
implementation passed its own kernel gate in
[`ready-r2/run-20261106-102343-292996`](../verification-logs/tc-phase1-20261106/ready-r2/run-20261106-102343-292996/REPORT.md).
This includes verifier acceptance, the ingress regression, CPU-pinned kernel
concurrency checks, ten live TCP flows, all-layer numerical parity and owned
resource cleanup. See [Phase 1 verification](PHASE1_VERIFICATION.md) for counts
and limits. That immutable Phase 1 checkpoint is retained as the rollback point.
Phase 2 development is on `feature/tc-egress-bidirectional`. Its runtime status
and evidence are recorded in [Phase 2 status](../verification-logs/tc-phase2-20261107/PHASE2_STATUS.md).

## Phase 2 first gate: minimal TC egress counter

`tc_min.bpf.c` now has two SCHED_CLS classifiers sharing one private counter map:
`tc_minimal` counts ingress skbs and `tc_minimal_egress` counts egress skbs. Both
return `TC_ACT_OK`. The optional egress attachment is enabled only by the new
`--egress-counter` mode; the normal ingress-only modes remain available. The
full flow/MLP program was unchanged at that first stage, and hook counters are
never supplied to the trained model.

```bash
./run-tc-smoke.sh --prepare --egress-counter --output verification-logs/tc-counter-fresh
sudo ./run-tc-smoke.sh --run verification-logs/tc-counter-fresh --egress-counter
```

Preparation builds and runs nonprivileged tests only. The privileged command
must be approved and run in a normal root-capable terminal. It creates only the
owned `tcids-server` / `tcids-client` namespaces and veth pair. It creates clsact
exclusively, attaches both minimal programs on `tcids-server/tcids-s0`, and saves
separate ingress/egress filter queries with actual IDs. A TCP greeting/FIN and
server response must complete. Both packet and byte counters must increase
relative to a saved pre-traffic snapshot; no fixed TCP packet count is assumed.
Counters include all skbs, potentially ARP/IPv6 control traffic, and are not
wire-packet/byte counts under offloads. No offloads are silently changed.

The controller verifies ID ownership before each targeted detach. The runner
requires both direction-specific acknowledgements, successful empty filter dumps,
owned program/map-ID disappearance and namespace cleanup. No primary interface,
host route, pre-existing qdisc or shared map pin is modified. Controller failure
after a successful load still triggers the recorded loaded-ID release checks.

Success is **`egress_counter_gate: PASS`**, not Phase 2 completion. Full inference
is intentionally NOT RUN in this counter-only stage. Canonical keys, shared
directional per-flow statistics, client-filter configuration and integration
followed only after this gate passed. No Phase 2 completion commit is made before
integrated kernel tests.

The first attached attempt loaded programs 80/81 and map 37 but rejected the
egress attachment with `bpf_tc_opts has non-zero extra bytes`. The controller now
uses `LIBBPF_OPTS` to zero structure padding. The failed attempt recorded ingress
detach and namespace deletion; its summary remains FAIL because owned-ID absence
checks were skipped after the controller's nonzero exit. Failure cleanup now
performs filter and owned-ID checks independently. The
[revision-2 attached run](../verification-logs/tc-phase2-20261107/egress-counter-r2/run-20261107-013339-169039/REPORT.md)
passed: program 85 observed 7 ingress skbs / 452 bytes; program 86 observed
5 egress skbs / 325 bytes. Map 38 and both program IDs disappeared, both filter
dumps were empty, and namespace cleanup passed. This is the counter-stage
checkpoint; older prepared hashes are archived, so prepare fresh bundles.

## Phase 2 architecture and integrated tests

The full object contains `tc_entry`, `tc_egress` and six SCHED_CLS inference
programs. Both attached hooks share the same loaded maps; egress never calls the
MLP. `flow_map` and `results` use a canonical key containing protocol and two
IPv4/port endpoints. Endpoints sort by unsigned numeric IPv4 address and then
numeric port. Stored address/port fields retain network byte order; the protocol
is host order. All key fields are explicit u32 slots with no implicit padding.

Three directions remain distinct:

- Canonical direction 0 is A -> B; 1 is B -> A.
- Hook indices 0/1 are ingress/egress, independent of canonical ordering.
- The first eligible ingress packet chooses the original MLP input leg. Later
  packets on that leg at ingress supply the unchanged six features. Reverse
  ingress packets are monitored separately and cannot contaminate those inputs.
  Egress-first traffic cannot choose the MLP leg, trigger inference, or change
  a completed result. Eligible ingress FIN/RST remains the inference trigger.

Each locked persistent flow contains separate hook packet/`skb->len` byte counts,
timestamp extrema, TCP flags and reorder counts, plus canonical-direction
counts. Original feature counters still measure ingress-leg TCP-segment bytes,
TCP-header bytes, min/max segment size and helper-clock maximum IAT. Per-CPU
workspace ownership, the immutable snapshot, retry state machine, static Q16
model, six-stage chain and immutable results are retained. Every map helper and
clock sample precedes the short lock region; the monitoring arithmetic is fully
inlined. Locks are never held across a tail call.

The client filter is a private, initialized/frozen configuration map. The
controller supports `--client-ip ADDRESS` or `--client-ip any` (default any).
Ingress filters on source, egress on destination. Isolated tests explicitly
select `33.33.33.73`; there is no test IP hardcoded in the BPF admission logic.

```bash
# Nonprivileged compilation and host tests:
./run-tc-smoke.sh --prepare --phase2 --output verification-logs/tc-phase2-20261107/ready
# Requires approval/root; namespaces and veth only:
sudo ./run-tc-smoke.sh --run verification-logs/tc-phase2-20261107/ready --phase2
```

Use a fresh output name on subsequent preparations. `--phase1` retains the
ingress-only regression suite, and a normal `--run BUNDLE` remains the original
minimal/ingress demonstration. Phase 2 first reruns the original kernel failure,
concurrency and fixed-vector checks; its separate two-hook kernel suite tests
same-flow and ten-flow CPU-pinned workers, egress-first termination, immutable
results, malformed packets and egress flow-map exhaustion. Deterministic model
mean/above/below fixtures run through the full kernel tail chain.

Separate attached phases cover ingress regression, ten ingress connections,
one bidirectional connection, ten simultaneous bidirectional connections and a
single connection with 128 small application writes. An independent AF_PACKET
witness records actual skbs and asserts per-flow hook/endpoint counts, byte
units, canonical keys and five non-timing features up to the first ingress
FIN/RST. It requires zero capture drops. It does not replace TC helper clocks
with capture timestamps. Every stage tensor and label is compared with the
established fixed-point reference using the actual captured kernel feature
vector. All owned attachments, IDs, empty clsact and namespaces must be removed.
Only `phase2_gate: PASS` in actual runtime evidence establishes integrated
success. Compilation/host tests alone do not.

The [2026-11-07 integrated run](../verification-logs/tc-phase2-20261107/ready/run-20261107-015636-807250/REPORT.md)
passed that gate. Single-flow TCP observations were 6 ingress / 4 egress skbs;
ten simultaneous connections were 60 / 40; the 128-write connection was 31 / 20.
Predictions were respectively 1, 10 and 1, with every tail stage executing and
zero live tail failures. AF_PACKET counts and five non-timing features matched.
Across both private kernel suites and live phases, offline replay matched
61 predictions / 366 tensors / 8,296 integers. All 58 program IDs and 57 map IDs
from that integrated run were released. See the [offline review](../verification-logs/tc-phase2-20261107/VERIFIED.json)
for actual program IDs, feature vectors, expected/observed tensors and logits.
Only completion documentation changed after that run; prepare a fresh bundle
to repeat it rather than editing the archived manifest.

## Selected-interface demonstration (manual, after integrated verification)

No automatic test uses this mode. Select the Linux server interface and client
IPv4 address explicitly, obtain approval, then run from the repository root:

```bash
read -r -p 'Server interface: ' IDS_IFACE
read -r -p 'Client IPv4 (or any): ' IDS_CLIENT_IP
IDS_LIVE_LOG=$(mktemp -d /tmp/tcids-live.XXXXXX)
sudo tc/.output/controller --serve tc/.output/tc_ids.bpf.o "$IDS_IFACE" "$IDS_LIVE_LOG" --bidirectional --client-ip "$IDS_CLIENT_IP" | tee -i "$IDS_LIVE_LOG/events.jsonl"
```

`tee -i` keeps the log reader alive while the controller handles Ctrl+C cleanup.
The controller refuses an existing clsact rather than replacing another user's
configuration. It prints actual program/map IDs (including map names), verified
tail slots and model loading. Type `snapshot` and Enter for decoded locked flow
statistics, immutable prediction tensors/logits and labels. In another server
terminal, inspect `sudo tc -s filter show dev "$IDS_IFACE" ingress` and the
corresponding `egress` command (set the variable there too). Optional
`sudo .output/bpftool/bpftool map dump id FLOW_MAP_ID` uses the printed ID, but a
raw live dump is not a substitute for the controller's locked read.

On the server, start a TCP listener on a chosen port, for example
`nc -l 5001`; on the client use `nc SERVER_IPV4 5001`, type a greeting, and close
the write side/connection. The listener's terminal can send a response before
closing. Netcat implementations differ in EOF behavior; for a deterministic
FIN/request/response exchange with installed Python 3, run the following instead:

```bash
# Server (in a second terminal):
python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",5001)); s.listen(1); c,a=s.accept(); print(a); d=b""; b=c.recv(1024)
while b: d+=b; b=c.recv(1024)
print(d); c.sendall(b"demo-ok\n"); c.close(); s.close()'
# Client: replace SERVER_IPV4 with the actual server address:
python3 -c 'import socket; s=socket.create_connection(("SERVER_IPV4",5001)); s.sendall(b"hello\n"); s.shutdown(socket.SHUT_WR); print(s.recv(1024)); s.close()'
```

Type `stop` and Enter in the controller terminal (or Ctrl+C) to detach only its
matching filters and close private maps. Manual serve mode leaves its clsact
for inspection; remove it only after **both successful filter dumps are empty**:

```bash
if grep -q '"event":"qdisc_created"' "$IDS_LIVE_LOG/events.jsonl" && [ "$(sudo tc -j filter show dev "$IDS_IFACE" ingress)" = '[]' ] && [ "$(sudo tc -j filter show dev "$IDS_IFACE" egress)" = '[]' ]; then
    sudo tc qdisc del dev "$IDS_IFACE" clsact
fi
```

There is no packet blocking. Existing host firewall/listener configuration is
not changed by this project. The selected-interface serve mode itself requires
separate user-side verification; namespace tests do not prove physical-NIC or
offload behavior.

## Timestamp reorder interpretation

The Phase 1 same-flow synthetic kernel stress test counted 26 helper samples
arriving at the flow lock older than its current `last_ns`. The saved inference
used IAT 3,862 ns at packet count 645; the final flow count was 1,033. The logs
do not retain individual samples or when each reorder occurred relative to
inference, so they cannot establish the chronological IAT error for that record.
The attached single-flow and ten-flow experiments recorded zero reorders.

The clamp prevents unsigned underflow, but **does not guarantee the exact maximum
gap between chronologically sorted samples**. For example, processing samples
`[1000,3000,2000]` retains maximum IAT 2000 although sorted adjacent gaps are 1000;
`[3000,1000,2000]` retains 0 although the sorted maximum is 1000. New host tests
characterize both cases without changing the Phase 1 algorithm. Numerical NN
parity proves computation on a snapshot, not timing-feature ground truth. Exact
chronological/wire IAT under arbitrary reordering would require a separate
ordering/timestamp design and validation; it is not claimed here.

- `flow_map` is a BTF-described HASH with a top-level `bpf_spin_lock`. It stores
  canonical IPv4/TCP identity, counters, timestamps, TCP flags, sequence and
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

Phase 1 did not add flow expiry or reset DONE on tuple reuse. Supported packet
scope and inherited extreme-value arithmetic limits remain; use fresh tuples
for separate sessions. Its historical evidence contains no egress attachment.
Phase 2 adds the configurable client filter and bidirectional monitoring above.

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

- `tc_min.bpf.c`: separate minimal TC ingress/egress packet/byte counters, returning
  `TC_ACT_OK` for every packet.
- `tc_ids.bpf.c`: separate `struct __sk_buff` ingress/egress programs and six **TC**
  inference programs. They never tail-call into an XDP program. The controller
  checks the loaded type of every program before populating the program array.
- `src/mlp.bpf.h` and `params.bpf.h` are included directly; model arrays are
  taken unchanged from `src/mlp_params.bpf.h`. TC persistent state and locked
  feature updates now live separately in `tc/abi.h` / `tc_ids.bpf.c`.
  The original source-IP gate is configurable; ingress FIN **or** RST trigger, feature
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

Classification uses the original ingress leg. Bidirectional counters are
monitoring statistics, not new trained model inputs or a claim of improved
bidirectional detection accuracy. There is no
packet dropping, prevention, dynamic quantization, model retraining, or new
flow-expiry policy. Flow-map exhaustion, tuple reuse and arbitrary-input
arithmetic limits remain. Phase 1 passed the recorded kernel/concurrency suite;
that is coverage of the tested cases, not a proof of all possible interleavings.

TC sees skbs later in the stack than XDP; GRO/GSO can change packet granularity.
The runner does not silently disable offloads. A small successful TCP exchange
does not establish wire-packet equivalence under aggregation, throughput,
accuracy, or full numerical correctness. On-wire VLAN, IPv6 and fragmented
frames are unscored. Hardware-stripped VLAN tags/metadata are not validated.
Parser-rejection statistics include unsupported non-IP traffic.
IAT values come from real kernel helper clocks and are not preselected; parity
uses the identical feature vector read from the completed TC record.

Host tests exercise the TC C source with test-only helpers. Only privileged run
logs can establish verifier acceptance, filter attachment, real tail-call
execution and live packet predictions. See the actual `results.json`; do not
interpret prepared code or a proposed demo command as a runtime PASS.
