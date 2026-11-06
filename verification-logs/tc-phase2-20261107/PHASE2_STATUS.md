# Phase 2: verified TC egress and bidirectional monitoring

**The isolated integrated Phase 2 gate passed.** The user executed the privileged
run; the agent subsequently reviewed saved artifacts without a privileged rerun.
[Runtime report](ready/run-20261107-015636-807250/REPORT.md) ·
[Full results](ready/run-20261107-015636-807250/results.json) ·
[Independent offline review](VERIFIED.json).

Phase 1 rollback commit remains `3dc5fe0f1a9ef0475cb2e198e5974c14700332dc`.
Phase 2 is on `feature/tc-egress-bidirectional`, starting at documentation commit
`d502d578fc551f5fe10fe4359ee168517cd8d15c`. The run tested that parent plus the
Phase 2 working-tree implementation, identified by the prepared manifest.
All runtime source/binary hashes matched; only completion documentation changed
after the run. The focused implementation commit can be identified with
`git log -1 --format='%H %s' -- tc/tc_ids.bpf.c`. No push was requested.

## Environment and commands

Recorded environment: WSL2 x86_64, kernel `6.6.87.2-microsoft-standard-WSL2`,
Ubuntu clang `12.0.1-19ubuntu3`, BPF ISA v3, bpftool `7.3.0`, libbpf `1.3`,
Python `3.10.12`. Runtime used the approved root-capable WSL terminal.
Dependencies: kernel BTF, iproute2 (`ip`, `tc`), Python 3 standard library,
libelf/zlib development libraries and the existing vendored libbpf/bpftool build.

Executed primary commands:

```bash
./run-tc-smoke.sh --prepare --phase2 --output verification-logs/tc-phase2-20261107/ready
sudo ./run-tc-smoke.sh --run verification-logs/tc-phase2-20261107/ready --phase2
python3 verification-logs/tc-phase2-20261107/review.py
```

Exact subprocess arguments and return codes are retained in
[preparation commands](ready/commands.jsonl) and
[runtime commands](ready/run-20261107-015636-807250/commands.jsonl).
[Earlier BPF build output](directional-host/build.log),
[final controller build output](ready/build.log),
[compiler](ready/compiler.log), [bpftool/libbpf](ready/bpftool.log),
[host tests](ready/tests.log) and [prepared hashes](ready/manifest.json) are saved.
Compilation passed without warnings in the saved successful builds.

## Implementation and observed results

The same loaded full object shares its canonical TCP flow map between ingress
and egress. A key includes protocol and numerically ordered IPv4/port endpoints,
with explicit byte-order handling. Hook direction, canonical endpoint direction
and MLP input direction remain distinct. Locked flow values store directional
skb counters/timestamps/TCP flags separately from original ingress-leg features.
The first eligible ingress leg supplies classification; egress never selects
that leg or triggers inference. The client filter is configurable or optional.

Phase 1 spin locks, creation-race handling, guarded per-CPU workspace, immutable
feature snapshots, six tail-call stages, publication and failure retries remain.
The six inference stage functions and ownership/publication helpers are
byte-identical to Phase 1; XDP, baseline runner, training, model and original
validation files are unchanged. [Source preservation hashes](source-preservation.json).

| Attached experiment | Ingress / egress program IDs | Matched TCP skbs in / out | Predictions | Result |
| --- | --- | ---: | ---: | --- |
| Original ingress regression | 118 / unattached | 6 / unmonitored | 1 | PASS |
| Ten concurrent ingress flows | 129 / unattached | 60 / unmonitored | 10 | PASS |
| One bidirectional flow | 140 / 141 | 6 / 4 | 1 | PASS |
| Ten concurrent bidirectional flows | 151 / 152 | 60 / 40 | 10 | PASS |
| One connection, 128 application writes | 162 / 163 | 31 / 20 | 1 | PASS |

All six stage counters were respectively 1, 10, 1, 10 and 1; live tail-call and
inference failures were zero. Global counters also include unsupported/control
traffic: the single bidirectional phase recorded 8 / 7 total skbs versus 6 / 4
matched TCP skbs. TCP-only counters are the appropriate flow comparison.
Each live bidirectional phase matched independent AF_PACKET observations with
zero capture drops, including 60 non-timing feature checks across 12 flows.
Application writes are not assumed to equal packets. Packet evidence:
[single](ready/run-20261107-015636-807250/bidirectional/packet-comparisons.json),
[ten](ready/run-20261107-015636-807250/bidirectional-concurrent/packet-comparisons.json),
[burst](ready/run-20261107-015636-807250/bidirectional-burst/packet-comparisons.json).

Example: flow-map ID 75 contained canonical TCP key
`33.33.33.1:5001 <-> 33.33.33.73:40004`. Its kernel feature snapshot was
`[40,35910,32,5001,136,4]`: max TCP-segment bytes, max ingress IAT ns, min segment
bytes, destination port, accumulated TCP-header bytes, packet count at trigger.
The completed record remains immutable while monitoring counters continue.
The first eight integers of the first linear layer were:

| Independently expected | Kernel observed |
| --- | --- |
| -53979, -42541, 39640, 26020, 55874, 48021, 83539, -54486 | -53979, -42541, 39640, 26020, 55874, 48021, 83539, -54486 |

Final kernel logits were `[-129096,109857]`, giving model class **1** under the
unchanged comparison rule (ties also select 1). Full tensors and provenance:
[review record](VERIFIED.json) and
[actual snapshot](ready/run-20261107-015636-807250/bidirectional/snapshot.json).

## Numerical, concurrency and failure coverage

| Scope | Actual result |
| --- | --- |
| Nonprivileged TC tests | 37 passed, 0 failures/errors |
| Preserved ingress kernel suite | 23 records, 138 tensors, 3,128 integers matched |
| Separate two-hook kernel suite | 15 records, 90 tensors, 2,040 integers matched |
| Attached packet experiments | 23 records, 138 tensors, 3,128 integers matched |
| Offline replay total | **61 records, 366 tensors, 8,296 integers; 0 mismatches** |
| Recorded verifier acceptance | All 58 loaded programs accepted across eight private object instances |

The preserved same-flow test used four CPU-pinned workers: final 1,033 ingress
packets, 20,660 TCP-segment bytes, sequence 1, eight suppressed duplicate triggers,
zero inference failures. The new two-hook same-flow test used four workers,
two per direction: **514 ingress and 514 egress packets**, 27,756 skb bytes each,
one inference sequence, one duplicate ingress trigger and zero failures.
Twenty CPU-pinned workers exercised ten distinct bidirectional flow keys, with
65 calls in each direction per flow. Every retained prediction matched the
reference for its actual feature snapshot. Exact overlap and all possible CPU
interleavings were not forced; actual interrupt nesting was not forced.

The saved kernel cases passed missing tail targets at all six slots, missing
model, full flow/result maps, immutable duplicate results, injected busy-owner
rejection/retry, malformed packets, egress-first FIN/RST and egress capacity
failure. Deliberately induced failure counters are retained; they are not live
packet-processing failures. Kernel events and verifier logs:
[ingress regression](ready/run-20261107-015636-807250/kernel-checks/events.jsonl),
[two-hook stress](ready/run-20261107-015636-807250/bidirectional-kernel-checks/events.jsonl).

## Timestamp interpretation and limits

The original Phase 1 same-flow test recorded 26 timestamp reorders at final
packet count 1,033. Its inference snapshot at packet 645 used IAT 3,862 ns.
[Extracted original values and executed host counterexamples](timestamp_review.json).
The new regression recorded 37 reorders; the new two-hook same-flow test recorded
7 ingress reorders. All live packet experiments recorded zero MLP reorders.

Helper timestamps are taken before acquiring the lock. A late sample is clamped
without moving `last_ns` backward, preventing unsigned underflow. It can still
bias chronological maximum IAT in either direction: executed host cases
`[1000,3000,2000]` give 2000 ns versus a sorted maximum of 1000; `[3000,1000,2000]`
give 0 versus 1000. Saved stress artifacts lack the individual samples/order, so
the actual timing error cannot be recovered. This Phase 1 policy is preserved.
AF_PACKET timestamps cannot substitute for TC helper timestamps; parity verifies
the model arithmetic on recorded features, not chronological/wire timing truth.

The first minimal egress attempt failed userspace libbpf option validation
(nonzero padding), not the verifier. Padding-safe initialization and independent
failure-cleanup checks fixed it; the
[revised counter gate](egress-counter-r2/run-20261107-013339-169039/REPORT.md)
passed before canonical/state work began. Counter checkpoint IDs were 85/86,
with 7 ingress / 5 egress skbs, map 38 and successful cleanup. An initial fixture
type typo and a `vmlinux.h` identifier collision were fixed during compilation;
no production XDP fix or verifier/safety check bypass was made.

No flow expiry or tuple-generation reset was added. Extreme-input overflow
limits inherited from the fixed-point model remain; the 61 recorded comparisons
reported no arithmetic overflow events. IPv6, fragments and on-wire VLAN frames
are unscored; stripped VLAN metadata is unvalidated. No offloads were changed;
AF_PACKET/TC agreement in these small isolated tests does not establish general
GRO/GSO or wire-packet equivalence. No F1, throughput, prevention or improved
bidirectional classification-accuracy claim is made.

## Cleanup, files and demonstration readiness

Cleanup passed for all eight integrated object instances: **58 recorded program
IDs and 57 map IDs absent**, both filter dumps empty for each attached phase,
owned empty clsact removed, both namespace instances deleted, veth peers removed.
The agent's read-only review also found both namespace paths absent. Every one
of the runtime's 240 saved checksums matched. No physical interface, host route,
pre-existing qdisc or shared map pin was modified. Full cleanup proofs remain
in each phase's `filter-absence.json` and `ids-absent.json`.

Modified files: `tc/Makefile`, `tc/README.md`, `tc/abi.h`, `tc/controller.c`,
`tc/demo.py`, `tc/kernel_checks.h`, `tc/safety.py`, `tc/tc_ids.bpf.c`,
`tc/tc_min.bpf.c`, `tc/tests/native.c`, `tc/tests/test_tc.py`, `tc/traffic.py`.
Added: `tc/flow_key.h`, `tc/bidirectional_checks.h`, `tc/packet_witness.py` and
selected small evidence/review files under this directory. No build binaries
are intended for the commit. Unrelated pre-existing changes remain untouched.

To repeat after the completion documentation update, run
`./run-tc-smoke.sh --prepare --phase2`, then the new printed command in an
approved root-capable terminal. Do not rewrite an archived manifest. The
[TC README](../../tc/README.md) documents explicit-interface server/client demo
commands, client filtering, locked snapshots, actual map/program IDs, predictions
and targeted cleanup. Manual serve mode, physical-NIC/offload behavior and
cross-machine reachability still require user-side verification after selecting
an interface. No native-Linux requirement was established by these WSL2 tests.
