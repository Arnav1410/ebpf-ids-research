# Phase 1 complete: concurrency gate verified

Phase 1 passed its actual kernel/packet/numerical/concurrency/cleanup gate in
[`ready-r2/run-20261106-102343-292996`](ready-r2/run-20261106-102343-292996/REPORT.md).
**Phase 2 is deferred at the user's request.** No egress/bidirectional code was
added, and no further privileged test was run during this completion review.

| Evidence scope | Actual result |
| --- | --- |
| Kernel verifier | PASS; 22 program acceptances across the private suite and three attached phases |
| Private kernel numerical suite | 23 records / 138 tensors / 3,128 integers matched |
| Kernel same-flow concurrency | Four CPU-pinned workers; 1,033 packets / 20,660 TCP-segment bytes after added RSTs; one sequence, eight suppressed triggers, no inference failures |
| Kernel distinct flows | Ten workers on ten CPUs; 65 calls per distinct flow, retained results verified |
| Attached ingress regression | 6 packets / 410 skb bytes; one prediction; 6 tensors / 136 integers matched |
| Ten real concurrent TCP flows | 60 packets / 4,100 skb bytes; ten predictions; all six stages counted ten; 60 tensors / 1,360 integers matched |
| Independent saved-record replay | All 204 stage tensors / 4,624 integers and labels matched; no new kernel execution |
| Cleanup | All four objects' owned program/map IDs absent; all attached filter dumps empty; clsact and namespaces removed |
| TC host suite | 20 tests passed, zero failures/errors |
| Original numerical framework | 34 tests, zero failures/errors, one expected skip; 113,040 dataset stage comparisons |

[Verification review](VERIFIED.json) records actual IDs, CPU placement,
checksums and counts. [Architecture, reproduction and limits](../../tc/PHASE1_VERIFICATION.md)
describe the verified implementation. The original XDP detector, training,
model parameters and validation sources remain unchanged.

The successful command was:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-phase1-20261106/ready-r2 --phase1
```

Runtime source and binaries matched the prepared manifest before review. Only
completion documentation/evidence changed afterward. The historical manifest
is not rewritten; to rerun after documentation changes, prepare a new bundle:

```bash
./run-tc-smoke.sh --prepare --phase1
```

Then use the exact new privileged command printed by preparation. Historical
`ready/` failed verifier acceptance; `ready-r2/` and the successful child run
retain that distinction. Earlier diagnostics remain local and are not treated
as passing evidence.

Known limits remain explicit: no exhaustive scheduling proof or forced actual
interrupt nesting; busy rejection requires a later FIN/RST to retry; no flow
expiry or DONE reset on tuple reuse; IPv4/TCP source-gated ingress only; inherited
arithmetic bounds and skb offload interpretation limits. No accuracy or
performance claim is made. These are documented limits of the verified scope,
not unexecuted checks being marked PASS.

The user-requested focused Phase 1 commit contains the TC changes, completion
documentation and small successful runtime evidence. No build objects or
executables are included. The unrelated tracked deletion and pre-existing
untracked demo evidence are left untouched. No push is performed.
