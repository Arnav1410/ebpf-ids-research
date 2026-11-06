# TC ingress Phase 1: verified

Phase 1 is complete for the defined test scope. Phase 2 is deferred at the
user's request; no egress or bidirectional flow tracking was added.

## Actual execution evidence

Successful user-executed command, before the completion documentation update:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-phase1-20261106/ready-r2 --phase1
```

[Runtime report](../verification-logs/tc-phase1-20261106/ready-r2/run-20261106-102343-292996/REPORT.md)
and [full results](../verification-logs/tc-phase1-20261106/ready-r2/run-20261106-102343-292996/results.json).
The recorded gate is **PASS**, with protected XDP/model/validation inputs
unchanged. Runtime source and binaries matched the prepared manifest during
review. Only documentation and verification records changed after that run.

| Scope | Recorded result |
| --- | --- |
| Actual kernel load / verifier | PASS; private suite programs 33–39; separate attached object loads also accepted |
| Kernel same-flow SMP | Four workers on CPUs 0–3; 257 entry calls each, then five extra RSTs: 1,033 packets, 20,660 TCP-segment bytes, one inference sequence, eight suppressed triggers, zero inference failures |
| Cross-CPU timestamp ordering | 26 reordered samples counted in the same-flow test; no unsigned IAT underflow |
| Kernel distinct flows | Ten CPU-pinned workers on CPUs 0–9; 65 entry calls per flow; separate retained results |
| Kernel numerical parity | 23 completed records, 138 stage tensors, 3,128 integer values matched the independent reference |
| Failure/retry cases | All six missing tail targets, missing model, full flow/result maps, duplicate triggers, malformed packets and injected busy-owner guard passed their assertions |
| Minimal attached TC | Entry ID 43; 7 packets / 452 skb bytes |
| Attached ingress regression | Entry ID 47; 6 packets / 410 skb bytes; one prediction; six stage counters each 1; zero failed tail calls |
| Ten simultaneous live TCP flows | Entry ID 57; 60 packets / 4,100 skb bytes; ten predictions; six stage counters each 10; zero failed tail calls |
| Live numerical parity | Regression: 6 tensors / 136 integers. Ten-flow test: 60 tensors / 1,360 integers. Every captured logit and label matched |
| Owned resource cleanup | PASS for all four loaded objects; recorded program/map IDs disappeared, filters were empty, clsact and both owned namespaces were removed |

Independent offline review checked every runtime evidence checksum and replayed
all 34 captured predictions: **204 tensors / 4,624 integers matched**. This review
did not rerun kernel or networking tests. Full tensors, per-program verifier
summaries, IDs, commands, client/server outputs and cleanup proofs are retained
in the runtime directory. [Review record](../verification-logs/tc-phase1-20261106/VERIFIED.json).

Nonprivileged preparation: **20 TC tests passed**, zero failures/errors.
[Test log](../verification-logs/tc-phase1-20261106/ready-r2/tests.log).
The original host validation separately passed 34 tests with one expected
missing-floating-checkpoint skip, zero failures/errors, and 113,040 dataset
stage comparisons. The original detector and numerical framework were unchanged.

## Architecture and scope

Flow statistics/status use a top-level BPF spin lock; inference uses a guarded
per-CPU workspace and one immutable feature snapshot across the six tail calls.
Completed results are published as immutable per-flow hash values. Duplicate
RUNNING/DONE triggers do not reinfer; failure paths unwind to IDLE and release
workspace ownership. Model parameters and static Q16 arithmetic are unchanged.

Kernel: `6.6.87.2-microsoft-standard-WSL2`, x86_64; clang
`12.0.1-19ubuntu3`, BPF ISA v3; bpftool `7.3.0`, libbpf `1.3`, Python `3.10.12`.
Verified baseline parent: `f06718f611a0f816048dfe254ef7a2f8edc6f788`.

CPU pinning creates concurrency opportunities; exact overlap and every possible
interleaving were not forced. The busy-owner test injects contention; actual
interrupt/RT nesting was not forced. A rejected isolated trigger needs another
FIN/RST to retry. Flow expiry, DONE reset on tuple reuse, arbitrary-input overflow
limits, wire-level offload equivalence, accuracy and performance remain outside
the verified claim. The client-IP gate and ingress-only IPv4/TCP scope remain.

For another run, use `./run-tc-smoke.sh --prepare --phase1`, then the exact new
privileged command printed by preparation. Historical bundles intentionally
retain strict original hashes; do not rewrite them to accept later edits.
