# Stage 03 — PASS: minimal detect-only TC ingress/egress probe

```text
STAGE: 03 — Minimal TC ingress/egress probe, no neural network
STATUS: PASS
BASE COMMIT / DIFF: 65c49c737b6791801cc98d9839b930b77ff42435; additive test_env probe/loader/adapter/tests; original src/model unchanged
CHANGES: Two all-pass TC programs, private per-CPU counters, scoped libbpf lifecycle, actual role self-tests, explicit backend CLI, TC ownership regressions and foreign-filter teardown guards
COMMANDS EXECUTED: See commands.json and live-corrected/commands.json; Make build, real isolated probe run, real opt-in namespace/TC regression suite
BUILD: PASS — clang-12 BPF object and static-libbpf loader, warnings treated as errors, empty compiler stderr
VERIFIER LOAD: PASS — both SCHED_CLS programs loaded and executed
ATTACH: PASS — ingress/egress on owned ids_server/veth-idss, direct-action filters, exclusive owned clsact, actual program IDs checked
RUNTIME PACKET TEST: PASS — live bidirectional ping/TCP counters rise and packets pass; connectivity also passes after each detach
CORRECTNESS TEST: PASS — exact per-program BPF test-run role counters and TC_ACT_OK; independent map reads; five real namespace/TC ownership regressions
EXPECTED VS OBSERVED: Two complete attach/traffic/detach cycles passed; role self-test [1,0] then [1,1]; no owned program/map IDs remain after either cleanup
EVIDENCE: evidence/stage-03/ including live-corrected/, safety/, commands.json and provenance.json
CLEANUP / ROLLBACK CHECK: PASS — owned filters/qdisc/programs/map removed, close idempotent, foreign clsact preserved, lab removed, host configuration unchanged
GATE DECISION: PASS — no new TC cleanup exception
NEXT ACTION: Stage 04 — correct bidirectional flow tracking/concurrency; do not claim TC+NN or dashboard operation yet
```

## Measured live evidence

The authoritative [top-level report](live-corrected/report.json) and [TC report](live-corrected/tc.json) both report PASS. The latter records two distinct object lifetimes:

| Cycle | Ingress program ID | Egress program ID | Map ID | Ping ingress delta | Ping egress delta | TCP ingress delta | TCP egress delta |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 450 | 451 | 82 | 7 | 7 | 6 | 4 |
| 2 | 455 | 456 | 83 | 7 | 7 | 6 | 4 |

Counters include all protocols and any background traffic, not just payload packets; these are observed deltas, not an exact wire-packet or throughput benchmark. The IPv4/TCP/ICMP fixture still completes successfully. After each detach, both ping directions and another TCP request/response pass.

Before attachment, actual `BPF_PROG_TEST_RUN` calls execute the two loaded programs on a valid small Ethernet/IPv4/TCP fixture. The observed shared map transitions are exactly `[1,0]`, then `[1,1]`, and both return `TC_ACT_OK`. This establishes which program increments which key; real TC filter metadata separately proves each program is on its intended hook. Initial live counter values therefore already include one self-test execution per role.

Actual `tc -s` text/JSON and bpftool map reads are preserved in each cycle's evidence. The loader owns no global map pins. The original XDP map-retention exception is not used for new TC objects: all new owned IDs were positively absent after both cycles. The unrelated older map is neither deleted nor counted as a new TC leak.

## Safe modular boundaries

- `test_env/probe.bpf.c`: only per-hook per-CPU counting and all-pass return. No parser, flow model, inference, payload export or packet blocking.
- `test_env/probe_loader.c`: actual BPF object and scope checks; only the named private server namespace/veth is accepted, never initial network namespace. It verifies namespace, link type/peer, ifindex, MAC and configured lab addresses. Exclusive clsact creation and non-replacing attachments prevent takeover.
- C loader statistics use versioned JSONL and signals. A single per-CPU buffer is allocated at startup and reused. Signals are consumed with `sigwait`; stderr carries diagnostics.
- C detaches only ID-matching owned filters. It does not destroy clsact. `test_env/tc.py` verifies the created qdisc/interface and empty filters before scoped qdisc removal, then verifies actual owned-object release. Terminal `close()` results are cached: a second close cannot remove a subsequently created foreign qdisc.
- `test_env/lab.py` now refuses veth/namespace teardown while filters remain on either endpoint/direction, preventing interface deletion from concealing a failed adapter cleanup or destroying a foreign filter.
- `test_env/__main__.py probe` uses the same recorder and owned topology as the unchanged original-XDP adapter, but does not import its map layout or invoke its loader/updater/model.

No TC inference, collector, flow tracker or UI is advertised by this probe. Developing an actual IDS backend remains a separate integration change with new gates.

## Retained first-run failure and correction

The initial [live result](live/report.json) failed at metadata validation, not compilation, verifier loading or attachment. This VM's iproute2 5.15 represents the actual program ID at `options.prog.id`; the initial decoder expected `options.id`. The decoder now accepts both concrete representations and rejects conflicting IDs. Actual ID/handle/priority/direct-action verification remains mandatory. The failed attempt cleaned up all its owned TC resources and is preserved; no checks were disabled to pass the corrected run.

## Real safety regressions

[namespace-tc-safety.stderr.log](namespace-tc-safety.stderr.log) records five PASS results, no skips:

1. Preexisting namespace is neither adopted nor deleted.
2. An interruption after private endpoint creation cleans both endpoints.
3. Repeated private TCP/reset topology leaves host configuration unchanged.
4. C loader refuses preexisting clsact and preserves it.
5. A second adapter close cannot delete a newly created foreign clsact using the same handle.

These use actual namespaces, sockets, TC and BPF, not mocked forwarding. They are opt-in and root-only; ordinary test discovery without isolated-VM opt-in skips privileged cases. Logs, real commands and object identities are retained under `safety/`.

## Reproduction

Build using the project's existing vendored dependencies (or supply the accepted Stage 01 dependency overrides shown in `commands.json`):

```bash
make -C test_env OUTPUT="$PWD/.output/test-env-stage-03-new"
sudo python3 -B -m test_env probe \
  --out .output/test-env-probe-new \
  --loader .output/test-env-stage-03-new/probe-loader \
  --object .output/test-env-stage-03-new/probe.bpf.o \
  --bpftool .output/bpftool/bpftool
```

Output directories must be new. The command creates and removes only its own lab namespaces/interfaces; it cannot select a real management interface. [provenance.json](provenance.json) records current source and compiled artifact hashes and exact accepted object lifetimes. No commit or push was performed.
