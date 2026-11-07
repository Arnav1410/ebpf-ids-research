# Stage 01 — PASS: original baseline rebuilt and locked

```text
STAGE: 01 — Reproduce and lock the existing baseline before modifications
STATUS: PASS
BASE COMMIT / DIFF: 65c49c737b6791801cc98d9839b930b77ff42435; test-env; evidence only, no baseline source edits
CHANGES: Built isolated vendored dependencies and original detector, proved repeatable products, ran existing regression/native/paired evaluation and actual BPF test-run validation, froze provenance
COMMANDS EXECUTED: See commands.json; corrected recursive-Make output isolation, two forced detector builds, existing unittest discovery, full native conformance, saved paired reevaluation, host driver build and four privileged kernel-driver invocations
BUILD: PASS — fresh dependency build and six byte-identical detector products across repeated builds
VERIFIER LOAD: PASS — freshly built original BPF object executed through the private-map driver for original and separate paired parameters
ATTACH: NOT TESTED — live interface checks deferred to Stage 02
RUNTIME PACKET TEST: NOT TESTED on a live interface; nine deterministic BPF test-run packet cases passed per model
CORRECTNESS TEST: PASS — 56 existing regressions; 18,844 original-model native vectors; 36 kernel vectors per model plus an explicit small-vector case; zero integer-stage/chain mismatches
EXPECTED VS OBSERVED: Exact integer intermediate values, logits/labels and packet-feature expectations agree; private cleanup complete; original artifacts preserved; float results kept separate from integer representations
EVIDENCE: evidence/stage-01/ and referenced ignored .output/test-env-stage-01/ artifacts
CLEANUP / ROLLBACK CHECK: PASS — original source/header/outputs preserved; small-case private pin roots checked absent; no networking changes
GATE DECISION: PASS
NEXT ACTION: Stage 02 — isolated namespace connectivity and original detector live execution; no TC work until that gate passes
```

## Reproduction and invocation correction

The first isolated attempt passed a root command-line `OUTPUT` override, which GNU Make propagated to the nested bpftool build. It produced `depsbpftool` instead of the expected `deps/bpftool/bpftool`, so the first detector invocation failed before compilation. That failure is retained in `dependencies-build.*` and `baseline-build-first.*`; it is not concealed or classified as a detector compiler/verifier failure.

The corrected root build clears recursive `MAKEOVERRIDES` while retaining the root output setting. The isolated source build uses the actual supported `OUTPUT`, `BPFTOOL`, `LIBBPF_INCLUDE` and `LIBBPF_OBJ` variables. Two forced builds of the unchanged sources produced identical `xdp`, `hot_updating`, `xdp.o`, `xdp.bpf.o`, `xdp.skel.h` and `vmlinux.h`. See [reproducible-build.json](reproducible-build.json). Corrected builds had empty stderr.

The original `src/.output/`, root vendored tool/library outputs and checked-in model header remain intact. The isolated products used for validation are `.output/test-env-stage-01/build/`, with vendored dependencies under its sibling `deps/`. No clean target or broad deletion was used.

## Correctness and scope

- [Behavior regression log](behavior-regressions.stderr.log): 56 tests passed. This includes existing native-header and saved training/reevaluation behavior checks; it is not a new traffic benchmark.
- `native-original` CLI: all 18,840 checked-in rows plus four boundary vectors matched the actual compiled arithmetic header at every stage.
- `paired-reevaluation` CLI: reloaded the existing portable M3 float/quantized checkpoint and frozen split without retraining. Results/artifacts remain separate from original static parameters.
- [Original-model kernel comparison](kernel-original-comparison.json) and [paired-model comparison](kernel-paired-comparison.json): 32 deterministic dataset vectors plus four boundary vectors each, including predictions of both numeric classes; six isolated stages, complete tail chain and all nine packet cases agreed exactly. Real kernel-driver stdout and libbpf stderr are retained alongside the comparison reports.
- [Small-vector record](small-vector.json): dataset row 11, features `[912,977710307,32,22,680,21]`. Original static integer logits are `[-15897,14304]`. The separate paired checkpoint gives float PyTorch logits `[1.0552306175231934,-0.7612905502319336]` and Q16 integer logits `[62175,-43084]`; the corresponding actual kernel vectors agree exactly with their own integer references. Float and Q16 logits are not interchangeable numeric representations.
- No original floating checkpoint is available. None was fabricated by dequantizing the header, and the separately trained paired model is not represented as the original baseline model.

[provenance.json](provenance.json) identifies the base revision, datasets, distinct models, driver/comparator sources and packed inputs. [original-artifact-preservation.json](original-artifact-preservation.json) records all original snapshot fingerprints unchanged.

The packet cases use `BPF_PROG_TEST_RUN`, not an attached interface. Fresh load/verifier success therefore does not establish a live baseline. Live packet delivery, safe attachment and observation are the next independent gate. No new accuracy, attack-detection, latency or throughput claim is made here.

No commit or push was made. A focused Stage 00/01 evidence and supplied-plan commit is recommended if authorized; do not add ignored binaries or datasets.
