# TC ingress prototype: verified end to end

The separate TC ingress implementation is demonstrated on the WSL2 kernel,
including the original fixed-point MLP and successful cleanup of this run's
resources. This completes the requested **small TC ingress prototype** scope.
The original XDP detector, baseline runner, training, model arrays and validation
framework remain unchanged. Optional egress counting was not implemented.

## Actual evidence

Successful privileged run:
[`verification-logs/tc-prepare-20261027-171811-753128/run-20261027-172125-858078/`](verification-logs/tc-prepare-20261027-171811-753128/run-20261027-172125-858078/REPORT.md).

Final nonprivileged review:
[`verification-logs/tc-final-20261027-172434/audit.json`](verification-logs/tc-final-20261027-172434/audit.json).
The review checked 24 preparation evidence checksums, 68 runtime evidence
checksums, 32 protected-file hashes and 19 prototype source/binary hashes. It
recomputed every captured stage using the established independent reference.
It did not execute additional kernel programs or change networking.

| Check | Actual result |
| --- | --- |
| Compilation / object inspection | PASS; clang-12, both objects contain SCHED_CLS programs |
| Nonprivileged tests | PASS; 11 executed in preparation, 0 failures/errors |
| Minimal verifier / ingress attachment | PASS; program 392 |
| Minimal real packet observation | PASS; 7 packets, 452 bytes |
| Full verifier acceptance | PASS; entry 396 and stages 397–402, seven individual verifier logs |
| Full TC ingress attachment | PASS; direct-action, handle 1, priority 1, `tcids-s0` in server namespace |
| Model loading | PASS; both 5,216-byte slots written/read back; active slot 0 |
| Six TC tail-call slots | PASS; slots 0–5 read back with correct program IDs and type 3 |
| Full real packet processing | PASS; 6 packets / 410 bytes, 6 source-gate matches |
| Actual six-stage execution | PASS; counters `[1,1,1,1,1,1]`, tail-call failures 0 |
| Prediction | PASS; one completed kernel record, stage mask 63, source port 40002 |
| Intermediate tensor parity | PASS; six tensors, all 136 integer values and label match |
| TCP delivery / pass behavior | PASS; server received `hello\n` and FIN; client received `tc-demo-ok\n` |
| This run's cleanup | PASS; filters, clsact, owned program/map IDs and namespaces removed |
| Optional egress | NOT IMPLEMENTED |

All 38 logged subprocess commands exited successfully. Controller stderr logs
are empty; all eight loaded programs (minimal plus full pipeline) have successful
verifier summaries. The two controllers' exact commands are saved separately in
`minimal/command.json` and `inference/command.json`; traffic-server commands are
also retained. The runner received real attached TC traffic, rather than using
host mocks or BPF_PROG_TEST_RUN as a substitute.

The actual feature vector at inference was:

| Feature, in model order | Value | Unit |
| --- | --- | --- |
| Maximum forward TCP segment length | 40 | bytes, including TCP header |
| Maximum forward packet interval | 165398 | nanoseconds |
| Minimum forward TCP segment length | 32 | bytes, including TCP header |
| Destination port | 5001 | host-order port number |
| Accumulated forward TCP header length | 136 | bytes |
| Forward packet count at closing packet | 4 | packets |

Six ingress packets were counted by the snapshot; four had contributed when the
FIN-triggered prediction completed. They are different observation points.
The IAT comes from the kernel helper clock. Reference parity uses this exact
captured vector, not a substitute host timestamp. It yielded logits
`[-129096,109857]`, label `1`, and no arithmetic events in the reference replay.
The Q16 rounding makes this run's normalized vector identical to the preceding
successful-inference run despite different measured IATs.

## Implementation and preserved behavior

The TC port uses `struct __sk_buff` and seven `SEC("tc")` programs, all
`BPF_PROG_TYPE_SCHED_CLS`. It includes the original `common.h`, `params.bpf.h`,
`handler.bpf.h` and `mlp.bpf.h`, reusing the flow map/updates and arithmetic.
The loader uses unchanged arrays in `src/mlp_params.bpf.h`.

The architecture remains 6→32→32→2 with scale 2^16, the same feature ordering,
FIN-or-RST trigger, source-IP gate `33.33.33.73`, and classification rule
`logit0 > logit1 ? 0 : 1` (ties select 1). Only TC programs populate the TC
tail-call array. Packet paths return `TC_ACT_OK`, including unsupported frames
and parser failures. No dropping or prevention is implemented.

The TC parser reads through `bpf_skb_load_bytes`, handles IPv4 IHL/TCP options,
checks lengths, and passes fragmented or unsupported frames unscored. Supporting
IP options deliberately avoids the original XDP fixed-offset parser defect;
the ordinary IPv4/TCP feature definitions remain the same. Tests cover valid
features, FIN, RST, options, ignored sources/nonclosing traffic, truncation,
bad lengths, fragments and invalid TCP header lengths. These parser fixtures
were host-executed; the live run exercised a normal TCP FIN exchange.

## Environment and dependencies

- Branch: `feature/tc-ingress-prototype`; base commit:
  `2073fe78ee332d258511acb592b4c5003b29d82e`. New files remain uncommitted.
- Kernel: `6.6.87.2-microsoft-standard-WSL2`, x86_64.
- Compiler: Ubuntu clang `12.0.1-19ubuntu3`.
- bpftool `7.3.0`; vendored libbpf `1.3`.
- Dependencies: Python 3 with standard library, clang-12/BPF target, kernel BTF,
  existing built libbpf/bpftool, libelf/zlib development libraries, iproute2
  (`ip`, `tc`), and root privileges for the isolated live demo.
- The current controller build used `-Wall -Wextra` and emitted no warnings.

## Demo and cleanup commands

From the repository root, the **already-tested bundle** can be demonstrated with:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-prepare-20261027-171811-753128
```

No further run is required to establish the successful result above. This command
is for repeating the demo; timestamps and measured IAT can change. It creates
only `tcids-server` / `tcids-client`, their veth interfaces `tcids-s0` /
`tcids-c0`, and private TC maps/programs. Addresses `33.33.33.1/24` and
`33.33.33.73/24` are assigned only inside those namespaces. It modifies no primary
interface or host route and does not reuse pinned baseline model maps.

Before a future demo from changed sources, prepare again without privilege:

```bash
./run-tc-smoke.sh --prepare
```

Preparation prints the new exact bundle command. Existing bundles reject source
or binary hash changes. Do not substitute a different bundle when describing
the recorded successful run.

Normal cleanup is automatic. The completed run detached only owned filters,
verified empty ingress/egress dumps, removed clsact, closed unpinned maps and
programs, and verified disappearance of minimal program 392/map 58 and full
programs 396–402/maps 59–64. It deleted both exact namespace instances after
checking ownership and absence of processes. Successful empty filter dumps and
owned-ID absence are saved in both phase directories.

For a future interrupted run, review its ownership record and use the targeted
cleanup command (only after the required privileged-operation approval):

```bash
sudo ./run-tc-smoke.sh --cleanup verification-logs/tc-prepare-TIMESTAMP/run-TIMESTAMP
```

No cleanup command is needed for the successful run. The offline review could
not independently stat `/run/netns` because unprivileged access was denied; it
verified the saved successful deletes and privileged runner absence checks.

## Files created across the TC implementation

| Files | Purpose |
| --- | --- |
| `run-tc-smoke.sh` | Separate TC entry point |
| `tc/tc_min.bpf.c` | Minimal pass-through ingress counter |
| `tc/tc_ids.bpf.c`, `tc/abi.h` | TC parser, six-stage MLP, telemetry ABI |
| `tc/controller.c`, `tc/id_scan.h` | Private libbpf loader, model/tail-slot readback, TC attach/detach, ID-only release checks |
| `tc/demo.py`, `tc/safety.py`, `tc/traffic.py` | Isolated orchestration, evidence checks and controlled traffic |
| `tc/Makefile` | Separate BPF/controller build |
| `tc/tests/native.c`, `tc/tests/test_tc.py`, `tc/tests/include/` | Host parser/MLP and cleanup-check tests |
| `tc/README.md` | Detailed build, run and safety documentation |
| `verification-logs/tc-*` | Actual compilation, test, verifier, runtime and review evidence |
| `TC_INGRESS_SUMMARY.md` | This final report |

Only this summary and the final offline-review artifacts were added after the
successful run. No tested TC runtime source/binary was changed during final
review. No original tracked files were edited, and nothing was committed/pushed.

## Remaining uncertainty and next engineering action

This establishes a working ingress IDS prototype for the demonstrated flow.
It does not establish classification accuracy, throughput, all-input numerical
correctness, wire-level equivalence to XDP under GRO/GSO, or production readiness.
Inherited flow-map exhaustion, tuple reuse, concurrency and arithmetic boundary
limitations remain. The latest-per-CPU snapshot is telemetry, not a lossless
prediction stream. VLAN/IPv6/fragments are unscored, and no bidirectional flow
aggregation or egress counter is implemented. Live RST/options/multiflow stress
testing remains beyond this small demonstration.

**Historical cleanup residue:** the successful run's final global map scan
(`command-034.log`) contains `[56]`. That is the private `progs` map from the
earlier failed run, not one of this run's owned maps. Its prior cleanup failure
has not been retroactively changed to PASS. All earlier TC program IDs are
absent from the saved final program registry. The old map remains a separate
resource-release issue; its precise reference state has not been established.
No forced kernel cleanup, global unpinning or reboot was attempted. Do not
describe the global map registry as empty.

For the immediate presentation, use the verified bundle and its saved logs.
Before quantitative experiments, investigate historical map 56 release and add
a small live FIN/RST/options/multiflow validation set with packet-level feature
oracles. Keep those tasks separate from accuracy/performance claims. There is
no remaining unimplemented step in the demonstrated TC ingress inference chain.
