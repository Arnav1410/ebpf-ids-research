# Stage 05 — PASS: original RX features and TC integer inference

```text
STAGE: 05 — Bring the existing neural network inference to TC
STATUS: PASS
BASE COMMIT / DIFF: 65c49c737b6791801cc98d9839b930b77ff42435; additive private NN backend/validation and optional shared-controller hooks; original src/model/runner unchanged
CHANGES: Original arithmetic helpers, per-trigger private jobs, frozen RX feature vectors, explicit model readiness/identity, real six-tail-call chain, native vectors, context restoration, exact independent live/vector comparisons
COMMANDS EXECUTED: commands.json; native/C/BPF builds; standalone inference CLI; final complete root regression run; original counter-probe compatibility CLI
BUILD: PASS — clang-12 and static-libbpf C tools, warnings treated as errors, explicit signed-wrap semantics
VERIFIER LOAD: PASS — actual ingress/egress/GC plus vector entry and six NN stage programs
ATTACH: PASS — ID-verified private veth ingress/egress only, detect-only
RUNTIME PACKET TEST: PASS — two original-model lifetimes; each matched 101 actual TC observations to AF_PACKET headers and independently validated all 14 RX FIN/RST classifications, including repeated triggers and eight simultaneous connections
CORRECTNESS TEST: PASS — 554 vectors per original repeat and paired model, all six stages exact at tolerance zero; separate near-zero/tie/overflow probes; unready and each missing-tail fault; all five skb.cb words restored
EXPECTED VS OBSERVED: Exact integer/logit/class parity; both numeric predicted classes exercised; no partial labels on faults; ordinary profile emits real predictions without packet headers/intermediate arrays
EVIDENCE: provenance.json; root-inference-safety-accounted.stderr.log; safety-accounted/test_original_pair_packets_faults_concurrency_and_owned_release/
CLEANUP / ROLLBACK CHECK: PASS — every new owned program/map absent, expected private tail slots cleared, filters/qdisc/lab removed, host preserved, all 20 original fingerprints unchanged
GATE DECISION: PASS — TC+NN functional within this isolated tested scope; not paper reproduction, bidirectional-model accuracy improvement or production readiness
NEXT ACTION: Stage 06 — versioned completion events, independent bounded collector, visible loss/restart behavior
```

## Accuracy is distinct from implementation parity

The authoritative [current-source report](safety-accounted/test_original_pair_packets_faults_concurrency_and_owned_release/inference.json) uses a frozen, balanced 512-row subset: 256 examples of each numeric label, selected with seed 2026 from the saved local held-out membership. Its membership SHA-256 is `ccdb2270da2c124e86585f4ca78781bb8de8de6ca74ef3499b028f5075fb448c`.

| Model on the same selected rows | Accuracy | Macro F1 | Interpretation |
| --- | --- | --- | --- |
| Original checked-in Q16 weights executed by TC | 89.4531% | 0.893345 | Diagnostic only: original training overlap unknown; 54 label mismatches |
| Actual separate M3 floating checkpoint | 99.6094% | 0.996094 | Real saved FP32 weights, not reconstructed/dequantized original weights |
| Q16 version of that same M3 checkpoint executed by TC | 99.6094% | 0.996094 | Zero selected-row class disagreements with its actual floating counterpart |

Both integer models match the independent integer oracle exactly. Correct arithmetic does not imply high classification accuracy for every model. These balanced-subset scores are not interchangeable with the earlier full/prevalence-weighted M3 evaluation. Numeric label meanings, dataset provenance and feature units remain unverified. No benign/intrusion semantic mapping is invented.

The original floating checkpoint remains absent. The separate [paired evaluation artifacts](safety-accounted/test_original_pair_packets_faults_concurrency_and_owned_release/) validate the actual saved M3 float/quantized relationship without claiming that checkpoint is the paper's or the original header's source.

## Numerical and live proof

[Provenance](provenance.json) records source/build hashes, original model identity `036d6da2f963ef21c63ecb6f2d3a45a22cde4269929fc7c85c917f6e74c6c756`, actual parameter-map readback, loaded object IDs and the accepted run. Two original sessions and the paired-Q16 session each executed 512 labeled vectors plus 42 arithmetic boundaries. Separate synthetic private models executed five near-zero/tie vectors and four deliberate accumulator/narrowing-overflow vectors. They never replace repository weights.

The comparison requires every integer in normalization, first linear/ReLU, second linear/ReLU and output to match `evaluation.model.infer`, with tolerance zero. `src/mlp.bpf.h` is included unchanged rather than reimplemented. Native vectors use actual `BPF_PROG_TEST_RUN` through the same six tail calls; a stage bitmap of 63 proves the complete chain. Normalization's unsigned wrap, signed narrowing/shifts and signed accumulator wrap are explicit and exercised. Near-zero/tie decisions and both predicted numeric classes are covered.

Each original live session independently checks 14 actual classification triggers against packet headers and recorded kernel observation clocks. Eight real simultaneous TCP connections and repeated FIN/RST jobs do not share hidden scratch. All six RX features include the trigger packet and retain their original order:

1. Maximum TCP segment bytes, including the TCP header.
2. Maximum RX inter-arrival gap in ns.
3. Minimum TCP segment bytes.
4. Destination port in host order.
5. Cumulative TCP header bytes.
6. RX packet count.

Only ingress from the original `33.33.33.73` source filter updates that RX vector. Canonical bidirectional direction is not substituted for RX. Every matching FIN/RST invokes inference, including repeats; full FIN/ACK closure is separate. Each job is keyed by immutable `{flow_id, trigger_ordinal}`. New generations intentionally reset RX history on tuple reuse; the original indefinitely accumulating tuple state is not carried forward.

An explicitly unready model and all six individually missing tail slots produce observable failure statuses and `label: null`, not a fabricated prediction. Native diagnostics verify all five skb control words on success and failure, restore owned slot mutations, then successfully execute again. Parameters and initialization templates are private, validated and frozen; all six tail slots are checked against their actual owned program IDs.

## Production-style default and lifecycle

The [ordinary-profile proof](safety-accounted/test_original_pair_packets_faults_concurrency_and_owned_release/production-profile.json) runs an actual TCP request/response with header capture and intermediate tracing disabled. The prediction agrees with the integer oracle, no packet observations or intermediate trace entries are exported, and model temporary files disappear after close. Intermediate array copies/allocation are diagnostic-only; normal jobs reuse private ping-pong hidden buffers.

RX updates serialize under the existing generation lock; helpers and tail calls occur outside it. Job state is separate from mutable flow statistics and contains no other flow's scratch. Public results exclude saved skb control words. GC uses unique IDs; the native controller also prunes orphan RX state from the lookup/tombstone race. Shutdown detaches only ID-matching primaries, stops GC, clears only its expected private tail slots, then closes objects. No original-XDP cleanup exception was applied.

The final suite passed **40 tests, no skips**: 32 pure behavioral checks and eight actual privileged cases, including original Flow/Probe ownership/lifecycle cases. All new object IDs were positively absent after cleanup. All 20 original fingerprints remain unchanged. No new packages, real-interface changes, original-XDP reruns, commits or pushes occurred.

## Retained failures and their fixes

- Initial verifier rejection: clang-12's CO-RE array access formed a modified `ctx + cb` pointer. Stable UAPI byte offsets and compiler barriers now preserve direct constant-offset accesses; the verifier and actual five-word restoration tests pass.
- Subsequent verifier rejection: tail calling from a BPF subprogram below the tracker's 256-byte ancestor frame exceeded the kernel restriction. Submission is now inlined into the entry frame; checks were not disabled.
- Native `ENOSPC`: installed UAPI `__sk_buff` was 184 bytes, while the running kernel returned 192. `nn_context.c` derives size and CB offset from generated running-kernel BTF in a separate translation unit. The native utility allocates that exact output size, validates the stable prefix, and reports both measured sizes. It does not ignore the error or pretend restoration succeeded.
- A later combined suite exposed automatic IPv6 multicast traffic during the unsupported-frame test. Fixed-size, opt-in typed skip records now distinguish the exact injected-MAC fixture counts from background packets. Counter deltas must equal all diagnostic skip records; fixture counts remain exact, and background IPv6 headers must also appear in AF_PACKET capture. The accepted run actually records one injected IPv6 frame plus one independently captured background frame. IPv6 and offloads were not disabled; the failed raw run remains under `safety-final/`.

Earlier failed logs/reports remain untouched. Twenty-three generated binary serialization inputs from earlier attempts were fingerprinted in [temporary-binary-manifest.json](temporary-binary-manifest.json), then removed. Current parameter/vector inputs live only in private temporary directories and are deleted after the owned process exits; original models, complete JSON proofs, logs and hashes remain available.

## Reproduction and modular boundaries

```bash
make -C test_env OUTPUT="$PWD/.output/test-env-new"
sudo .output/evaluation-venv/bin/python -B -m test_env inference \
  --out .output/inference-validation-new \
  --loader .output/test-env-new/nn-loader \
  --object .output/test-env-new/nn.bpf.o \
  --bpftool .output/bpftool/bpftool \
  --model src/mlp_params.bpf.h \
  --paired-dir .output/evaluation/m3-train
```

Use a new output directory in the isolated VM. Exact accepted dependency overrides and executable argv are in [commands.json](commands.json). The existing evaluation interpreter supplies real NumPy/PyTorch; the runner never installs or retrains anything.

`nn.bpf.c` specializes the plain Flow source through optional hooks; ordinary Flow and Probe builds retain their own ABIs. `nn.h` defines private model/job/result types; `nn_controller.c` integrates with the shared owned lifecycle; `nn-vectors` verifies controller FD ownership before any diagnostic mutation. Python `Inference(Flow)` validates the complete backend manifest, model bytes and readiness. `inference_reference.py` reuses existing integer/model/metric helpers and independently reduces RX triggers. The next event/collector layer is deliberately not advertised as implemented by this gate.
