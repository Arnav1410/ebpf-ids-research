# Stage 06 — kernel-to-user event pipeline

```text
STAGE: 06 — Kernel-to-user event pipeline
STATUS: PASS
BASE COMMIT / DIFF: 65c49c737b6791801cc98d9839b930b77ff42435; additive test_env event implementation and evidence; no commits created
CHANGES: Versioned 256-byte ring-buffer events, FD/namespace/model-bound native reader, bounded Python queue/journal/history, cached source telemetry, separate loss counters and reader restart
COMMANDS EXECUTED: See commands.json and the reproduction commands below
BUILD: PASS — clang-12 BPF and native cc, -Wall -Wextra -Werror
VERIFIER LOAD: PASS — actual kernel load in every live session
ATTACH: PASS — both owned private TC hooks, detect-only
RUNTIME PACKET TEST: PASS — controlled FIN/RST/retransmissions, eight simultaneous TCP connections, stopped reader, reader restart and both overflow scenarios
CORRECTNESS TEST: PASS — public results match kernel ledger and exact integer oracle; coherent counts match independently parsed packet prefixes; all 48 regressions passed, zero skips
EXPECTED VS OBSERVED: 14/14 initial completions, 15/15 after restart; 64/64 burst inferences under both pressure cases; ring loss 49 of the isolated 64-event burst, Python queue loss 60 of 64 with kernel loss zero
EVIDENCE: safety/test_live_event_parity_overflows_restart_and_owned_release/events.json; root-full.stderr.log; provenance.json
CLEANUP / ROLLBACK CHECK: PASS — all native readers exit 0, owned maps/programs absent, hooks removed, namespaces released, host networking preserved; 20 original fingerprints unchanged
GATE DECISION: PASS — no new lifecycle exception
NEXT ACTION: Stage 07, independently validate the live dashboard and explicitly simulated replay
```

## Implemented boundary

- `nn.h` / `nn_bpf.h`: NN ABI 2; event schema 1. Fixed-width little-endian x64 record with size/version/endian marker, attempt sequence, immutable trigger result, actual FIN/RST flags, model identity, and a coherent locked direction-count snapshot. No payload, skb control block or intermediate NN arrays in public events.
- Every matching RX FIN/RST remains a trigger, including repeats. An event is a **classification completion**, not necessarily full bidirectional closure. Inference arithmetic and original checked-in weights are unchanged.
- A full ring increments `event_dropped`; inference completion and forwarding continue. The bounded result ledger has a separate `result_full` counter and cannot prevent event publication. Vector-only diagnostic runs do not masquerade as live events.
- `nn-collect`: opens only actual owner-held maps after private namespace/interface/metadata validation; checks the loaded model; emits typed JSONL. An abstract Unix socket permits only one consumer for that producer/ring. All metadata FDs are read-only; the ring consumer FD necessarily permits consumer-page mmap. No map updates/deletes by the reader.
- Native reader supplies actual inference/hook counters, monotonic rates input and a bounded map snapshot every second. At most 32 flow rows, with observed population and truncation explicit; each row is locked independently, not a global transaction. Routine collection never asks the producer to print its growing diagnostic result ledger.
- `Collector` drains independently of a dashboard. Queue policy: **drop newest after journaling**. Queue, history, classification cache, journal and child output have separate bounds. Journal appends are flushed, not fsync durability. Closing a collector does not stop its producer.
- Attempt sequences can arrive out of order across CPUs. Recent holes can heal; finalized holes, duplicates and too-late records are visible separately. They are never added to kernel or Python drop counts. History is bounded arrival order; producer sequence is not exposed as a reliable resume cursor.
- `event_schema.py` rejects wrong provenance, schema drift, duplicate JSON fields, private data, floating-point masquerades, incomplete labels and inconsistent count prefixes. Consumers never recompute or invent a classification.

## Authoritative observed scenarios

Source: [`safety/test_live_event_parity_overflows_restart_and_owned_release/events.json`](safety/test_live_event_parity_overflows_restart_and_owned_release/events.json).

| Scenario | Expected | Observed |
| --- | --- | --- |
| Normal controlled traffic + eight simultaneous sockets | Every matching RX FIN/RST completion exported once; all integers/counts exact | 14 events; exact result-ledger/oracle/prefix equality; 101 TC headers matched 101 independently captured headers; no capture loss |
| Competing reader | Refuse without disrupting original consumer | Exit 1, `EADDRINUSE` 98; original reader alive |
| Real pending flow | No invented score | SYN-only flow shown as unclassified |
| Reader absent and restarted | Kernel still classifies; restart preserves producer identity and counters | New completion produced without reader; 15/15 events after restart; restart count 1; no ordinary-path losses |
| 4096-byte ring, reader confirmed SIGSTOP-stopped | Bounded overflow visible, all inference continues | 64 triggers and complete results, 15 events emitted, 49 ring drops, no unfinished jobs; real 24-byte request / 25-byte response succeeds while reader remains stopped |
| Ring loss including that additional TCP exchange | Separate authoritative drop count | 50 ring drops total; zero Python queue drops |
| Four-record Python queue, aggregation paused | Reader keeps draining, drop-newest loss separate from kernel loss | 64 emitted/accepted, four queued then aggregated, 60 Python queue drops, zero kernel drops; journal retains accepted records |
| Cleanup | Close reader before producer; release every owned object | Reader exit codes all 0; no remaining owned map/program IDs; detached traffic works |

The retained live sample is [`safety/test_live_event_parity_overflows_restart_and_owned_release/sample-live-events.jsonl`](safety/test_live_event_parity_overflows_restart_and_owned_release/sample-live-events.jsonl). It contains actual native classifications, not synthetic alerts. A future replay must visibly wrap it as **SIMULATED**; replay does not establish current kernel connectivity.

## Commands actually exercised

From repository root; dependency paths refer to the already accepted Stage 01 build:

```bash
make -C test_env \
  OUTPUT="$PWD/.output/test-env-stage-06/build" \
  BPFTOOL="$PWD/.output/test-env-stage-01/deps/bpftool/bpftool" \
  LIBBPF_INCLUDE="$PWD/.output/test-env-stage-01/deps/libbpf/usr/include" \
  LIBBPF_OBJ="$PWD/.output/test-env-stage-01/deps/libbpf/libbpf.a"

.output/evaluation-venv/bin/python -B -m unittest discover -s test_env/tests -v

sudo .output/evaluation-venv/bin/python -B -m test_env events \
  --out evidence/stage-06/live-initial \
  --loader .output/test-env-stage-06/build/nn-loader \
  --object .output/test-env-stage-06/build/nn.bpf.o \
  --bpftool .output/test-env-stage-01/deps/bpftool/bpftool
```

Output directories are exclusive: choose a fresh path when reproducing. The actual commands included explicit timeouts and safe sudo stdin authentication; credentials are not stored. The authoritative final code was exercised by the full root suite with explicit `NN_EBPF_RUN_LAB_TESTS=1`, all three loader/object profiles and the existing evaluation interpreter. Exact argv and environment assignments: [`commands.json`](commands.json).

- Default suite: 48 tests, nine root-only cases skipped as intended.
- Full isolated-VM root suite: **48 tests passed, zero skips, 65.916 seconds**. This reruns the probe/flow ownership, generation-safe GC, original and paired NN arithmetic/fault/live checks, plus the event scenarios; UI absent throughout.
- Initial build failure retained: the new JSON serializer lacked the Linux BPF spin-lock type include; corrected header, successful rebuild. Initial unit import failure retained: original model constant belongs to `evaluation.artifacts`, not `evaluation.model`; corrected. Neither failure is hidden or waived.

## Limits

This is isolated VM functional/loss validation, not a physical Ethernet or wire-segmentation claim, production daemon qualification, throughput benchmark, attack demonstration or new accuracy score. Labels remain numeric **0/1 with unverified semantic names**. No original XDP cleanup waiver was applied to any new resource. No packages installed; management interface, baseline source, evaluation pipeline, weights and baseline runner unchanged.
