# Final demonstration verification — 7 November 2026

Status: **PASS for available WSL2 isolated verification**. New Windows-native
and Ubuntu-VM two-machine harness execution: **PENDING USER EXECUTION**.
No new physical-interface/VM attachment was performed by the agent.

Development baseline: `0ba2b2bbf9d1d24b4a98e228ff35aeb44c4e9d2d`;
branch `feature/final-demo-evaluation`. The original detector, TC programs,
models, training, validation, quantization, deployment and dashboard source
remain unchanged. The prepared manifest records 83 source/runtime hashes.

Environment: WSL2 Linux `6.6.87.2-microsoft-standard-WSL2`, x86_64,
Python 3.10.12, clang-12 12.0.1, bundled libbpf 1.3. Privileged loader/collector;
TCP server, client and dashboard run as ordinary UID 1000. No SSH is used.

## Commands and distinct evidence levels

Executed during this task:

```bash
python3 evaluation/audit.py --output verification-logs/final-demo-20261107
python3 evaluation/offline.py --output verification-logs/final-demo-20261107/offline-r2 --encoded-label-diagnostics
python3 demo/test_isolated.py --prepare --output verification-logs/final-demo-20261107/ready
```

The operator then approved and executed:

```bash
sudo /usr/bin/python3 demo/test_isolated.py --run verification-logs/final-demo-20261107/ready
```

| Check | Result and scope |
| --- | --- |
| Host compilation | PASS: three C arithmetic wrappers; original wrapper emitted 3 loop-unroll optimizer warnings; both TC wrappers had no warnings |
| TC build prerequisite | PASS: `make -C tc layer-specific` reused unchanged verified objects (`Nothing to be done`) |
| Host unit/protocol tests | PASS: 18 actual tests in ordinary-user namespace; no socket skip in privileged evidence |
| Kernel verifier/load | PASS: both unchanged TC objects loaded and ran; actual IDs below |
| TC attachment | PASS: ingress and egress on owned `idsdemo-s0` veth only |
| Real socket processing | PASS: batches 1, 10, 32 per mode; 86 completed/matched TCP connections |
| Numerical parity | PASS: 86 records, 516 tensors, 11,696 kernel-observed integers, zero mismatches |
| Concurrency | PASS within tested coverage: distinct source-port connections with up to 32 client workers; exact CPU overlap not forced; prior same-flow regression evidence preserved |
| Matching | PASS: experiment/session/full tuple/application case matching, duplicate/ambiguous/missing tests |
| Partial startup | PASS: occupied application port refused, owned IDS rolled back, existing listener preserved |
| Cleanup | PASS: owned BPF IDs and filters checked; clsact left in place; owned namespaces removed |
| New native Windows / VM two-machine harness | PENDING USER EXECUTION |
| Fresh XDP runtime comparison / independently labeled intrusion F1 | NOT RUN |

## Saved packet observations

These aggregate counters include hook-visible traffic; application writes do
not imply exact packet counts. They are not throughput or intrusion metrics.

| Mode | Ingress / egress program IDs | Ingress packets / bytes | Egress packets / bytes | Predictions | Six stage counters |
| --- | --- | --- | --- | --- | --- |
| static_q16 | 655 / 656 | 369 / 34236 | 313 / 28905 | 43 | [43, 43, 43, 43, 43, 43] |
| layer_specific | 666 / 667 | 365 / 33944 | 307 / 28457 | 43 | [43, 43, 43, 43, 43, 43] |

Both modes reported zero tail-call failures, inference failures and result
failures. Each retained one result per connection. Features remain derived
from the eligible ingress input leg; egress monitoring is separate.

**Detection outcome:** both modes classified every known-benign scenario as
raw class 1. Under the paper's intended 1=intrusion coding, the batches have
FP/TN 1/0, 9/0 and 28/0 respectively: **100% benign FPR**, 100% classification
coverage. Five cases per mode are unknown and remain unscored. No intrusion
traffic was generated; intrusion recall/F1 are unavailable. This negative
finding is separate from correct execution and numerical parity.

The offline supplied-label diagnostic covers 13,844 calibration-heldout rows;
all three host configurations agree. Its F1 0.9613857454834227 is conditional
on supplied numeric codes with unknown training overlap, **not independently
validated intrusion effectiveness or reproduction of paper Table V**.

## Underlying artifacts

- [Compatibility audit](../../DATASET_AUDIT.md), [comparison](../../THREE_WAY_COMPARISON.md), [operator runbook](../../DEMO_HARNESS.md).
- [Dataset inventory](dataset_audit.json), [offline metrics](offline-r2/metrics.json), [full representative tensors](offline-r2/samples.json), [host compiler commands](offline-r2/commands.jsonl).
- [Prepared source hashes](ready/manifest.json), [operator command journal](ready/run-20261107-201114-136504/commands.jsonl), [actual suite results](ready/run-20261107-201114-136504/results.json), [ordinary-user tests](ready/run-20261107-201114-136504/unprivileged-tests.log).
- [Q16 kernel snapshot](ready/run-20261107-201114-136504/static_q16/experiment/kernel_snapshot.json), [layer-specific kernel snapshot](ready/run-20261107-201114-136504/layer_specific/experiment/kernel_snapshot.json).
- [Q16 cleanup](ready/run-20261107-201114-136504/static_q16/experiment/cleanup.json), [layer-specific cleanup](ready/run-20261107-201114-136504/layer_specific/experiment/cleanup.json), [independent saved-evidence replay](VERIFIED.json).

Large per-row prediction archives/build artifacts stay local; the deterministic
commands regenerate them. Commit only focused source and small useful evidence.
The first offline build failed because the test include path selected the wrong
mock header; this test-framework issue was corrected before the successful
`offline-r2` run. No production code was changed to make a test pass.
