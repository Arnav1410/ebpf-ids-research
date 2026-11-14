# READY FOR OPERATOR-CONTROLLED NATIVE LINUX DEPLOYMENT

This means implementation and isolated **WSL2** verification passed. Native
Linux compatibility, physical `enp8s0` attachment, Windows PowerShell traffic
and the two-laptop experiment are **PENDING USER EXECUTION**. No physical
interface, host route, firewall or existing Ethernet address was modified.

## Baselines and Git transfer

Branch: `feature/native-deployment-dashboard`.
Original bidirectional baseline: `791e25932e01a8e457c81237fdc8da2ea971b32e`.
Verified arithmetic checkpoint, created before deployment changes:
`a99394b3c8ab36d9be316d350c86fe031ae460f2`.
The final deployment commit is the branch HEAD reported at handoff; verify it
with `git rev-parse HEAD` and manually push that exact commit before cloning.
No automatic push occurred. The unrelated `myshell` deletion and unrelated
untracked files were excluded from commits. Build outputs were excluded.

Origin is `https://github.com/Arnav1410/ebpf-ids-research.git`.
The source-only GitHub/USB transfer, native build and exact commands are in
[SERVER_DEPLOYMENT.md](SERVER_DEPLOYMENT.md). The complete Linux/Windows demo
sequence is in [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md). No SSH or remote execution
is used or required.

## Gate A: focused architectural assessment

The existing object has TC ingress/egress plus six SCHED_CLS inference stages.
Persistent canonical IPv4/TCP flows are protected by per-entry spin locks;
the guarded per-CPU workspace carries an immutable feature snapshot through
the MLP. The immutable `results` hash retains predictions independently of
per-CPU scratch. Both model slots are read back and frozen. Default Q16 and
experimental layer-specific arithmetic are independently selectable.

No BPF source, ABI, trained model, feature definition, arithmetic, tail-call,
concurrency or trigger change was needed. The isolated addresses, interfaces
and port 5001 belong to tests; production admission already uses configurable
`--client-ip`/`any`. Eligible **ingress FIN/RST**, not every HTTP request,
triggers inference. Egress only updates monitoring statistics.

The new physical-deployment path extends the existing controller. It reads
classifier state, refuses occupied hooks/shared blocks, records interface
identity, uses exclusive handle `0x4e4e`/priority `49152`, and queries actual
IDs. It can reuse an empty clsact, and **never deletes clsact**. It refuses
coexistence with active foreign classifiers because the unchanged direct-action
`TC_ACT_OK` could otherwise bypass later classifiers. Cleanup checks exact
program IDs and preserves filters added by another operator.

## Evidence by verification level

Environment: x86_64 WSL2 kernel `6.6.87.2-microsoft-standard-WSL2`, clang
`12.0.1-19ubuntu3`, vendored libbpf 1.3, bpftool 7.3.0, Python 3.10.12.

| Check | Status | Scope / evidence |
| --- | --- | --- |
| Controllers and both BPF modes compile | PASS | Warning-free controller rebuild; existing BPF objects retained |
| Original Q16 regression | PASS | Actual WSL2 kernel, numerical, concurrency and attached namespace suite |
| Layer-specific regression | PASS | Same complete suite, selected experimental reference |
| New deployment verifier/load | PASS | Both objects loaded into actual WSL2 kernel |
| New ingress / egress attachment | PASS | Virtual interface only: Q16 IDs 628/629; experimental 639/640 |
| HTTP packet processing | PASS | One plus ten TCP connections in each mode, both directions recorded |
| New deployment numerical parity | PASS | 22 records, 132 tensors, 2,992 integers; zero mismatches |
| Existing concurrency regression | PASS | Ten-flow and same-flow CPU-pinned coverage; exact overlap not forced |
| Dashboard/retention/HTTP tests | PASS | 23 tests as UID 1000, including actual localhost endpoints; no skips |
| Live collector → HTTP API | PASS | Actual kernel snapshots, 11 independent connections per mode |
| Foreign filter preservation/refusal | PASS | Test matchall survived owned detach; occupied-hook starts refused |
| Address / IPv4 route preservation | PASS | Configured values unchanged; transient IPv6 DAD excluded |
| Owned resource cleanup | PASS | Both modes, test processes, runtime directories, namespaces and veth |
| Native Linux compiler/kernel | PENDING USER EXECUTION | Build natively; WSL outputs must not be copied |
| Physical `enp8s0` | NOT RUN | Explicit operator invocation only |
| Native browser / Windows PowerShell | PENDING USER EXECUTION | Commands prepared; actual two-machine results not claimed |

Each mode's new deployment recorded 11 predictions, with every tail stage
executing 11 times and zero inference/tail failures. Global counters included
78 ingress / 57 egress skbs in Q16 and 77 / 55 experimentally. Per-flow TCP
totals were 77 / 55 in both modes; control traffic explains the difference.
The dashboard served these real values as an unprivileged process.

[Independent saved-evidence review](verification-logs/deployment-20261107/VERIFIED.json)
checked all 54 prepared source/binary hashes, replayed all 22 retained tensor
records, matched dashboard/log values and indexed 106 raw evidence files.
[Detailed evidence report](verification-logs/deployment-20261107/REPORT.md).

## Implementation and modified files

- `tc/controller.c`, `tc/deploy_guard.h`: deployment-only conflict checks,
  empty-clsact reuse, explicit handles/priorities, targeted owned-ID detach.
  Original isolated controller modes retain their behavior.
- `tc/Makefile`: native GCC multiarch include path and guard dependencies.
- `deployment/ids.py`: read-only preflight/dry-run/status/full snapshot,
  foreground attach/collector, root-only local stop IPC, targeted cleanup.
- `dashboard/telemetry.py`: joins retained results with canonical flows,
  collection timestamps, mode/logits/features, bounded log rotation and dedup.
- `dashboard/server.py`, `dashboard/static/*`: loopback-only HTTP API/UI,
  disconnect/stale/error states, per-connection pagination and counters.
- `deployment/tests/*`, `deployment/test_isolated.py`: deterministic host tests,
  namespace HTTP integration, reference parity and cleanup/preservation checks.
- `deployment/http-root/index.html`: separate ordinary HTTP test content.
- `tc/README.md`, both runbooks and this status: operator instructions/evidence.

## Exact commands actually executed

```bash
make -C tc layer-specific
python3 -m unittest -v deployment.tests.test_dashboard
python3 deployment/test_isolated.py --prepare --output verification-logs/deployment-20261107/ready
```

The user then executed the printed privileged namespace command. Both original
regression suites passed. The first deployment attempt hit a Unix-socket path
limit; the fixed runner uses a short owned `/run/idsdep-*` directory and rejects
overlong paths before loading BPF. Revision 2 passed both deployment modes,
but its raw JSON address comparison falsely treated completion of IPv6 Duplicate
Address Detection as configuration modification. The test now compares actual
configured fields and includes a regression that detects real address/MTU/admin
changes. Prior failed results remain FAIL, preserved for diagnosis.

Final preparation and actual user-executed privileged command:

```bash
python3 deployment/test_isolated.py --prepare --reuse-regressions verification-logs/deployment-20261107/ready --output verification-logs/deployment-20261107/ready-r3
sudo /usr/bin/python3 deployment/test_isolated.py --run verification-logs/deployment-20261107/ready-r3
```

The final run reused the already-passed original suites after checking their
source hashes; it did not pretend those were new executions. It ran the complete
new deployment suite and the previously sandbox-blocked HTTP tests. The actual
HTTP tests ran without root in the isolated server namespace. No additional
privileged execution is required for the recorded WSL2 gates.

## Remaining limits and first native commands

The original parser supports untagged Ethernet IPv4/TCP; unsupported packets
pass unscored. NIC offloads affect observed packet/byte counts. Map snapshots
are not globally atomic. Helper timestamps are monotonic and timestamp reorder
clamping is not chronological IAT reconstruction. Flow/result maps are finite
(8,192), with existing retention/tuple-reuse limitations. The test covered that
maximum in host replay, not 8,192 real live connections. Long-running dedup and
collector restart semantics were host-tested; native deployment remains pending.
Per-inference log statistics reflect collection time and can precede later
response/ACK updates visible in the live table. No payloads are retained.

No attack-detection accuracy/F1, native-NIC performance, or universal concurrency
claim is made. Static Q16 remains the default; experimental arithmetic improves
fidelity to the reconstructed header network but was slower in measured WSL2
benchmarks. Do not mix egress monitoring counts into the six trained features.

On the native laptop, **start with inspection**, not attachment:

```bash
cat /etc/os-release
uname -r
uname -m
ip -4 addr show dev enp8s0
tc -j qdisc show dev enp8s0
tc -j filter show dev enp8s0 ingress
tc -j filter show dev enp8s0 egress
```

Expect the existing `192.168.77.1/24` and an UP Ethernet interface. Inspect any
foreign classifiers without changing them. Follow SERVER_DEPLOYMENT.md for the
verified source revision, native prerequisites/build, preflight and explicit
start. Stop and share errors rather than making broad network/kernel changes.
