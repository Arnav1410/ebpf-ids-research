# Layer-specific fixed-point experiment — all six gates passed

## 1. Baseline preserved

Starting commit: `791e25932e01a8e457c81237fdc8da2ea971b32e`.
Branch: `feature/layer-specific-fixed-point`. No new commit or push has been made.
The unrelated `dataset-instance/intrusion/metasploit/myshell` deletion and all
other unrelated work remain untouched. Original `src/`, training/model files,
`validation/`, TC flow ABI, canonical keys and traffic/packet-witness files are
unchanged. Only narrow mode/build/controller/inference/test hooks are added.

The original Q16 host suite ran 34 tests: **32 passed, 2 skipped** (no smoke-log
argument, and no original floating checkpoint). All 18,840 dataset rows still
matched the established reference at every stage. [Q16 regression](static-regression/REPORT.md).
Both mode-specific TC host suites passed **37 tests each**, retaining the
existing concurrency, trigger, parser, cleanup and all-stage parity assertions.
The compiled static-Q16 `tc` section is byte-identical to a fresh build of the
verified baseline: 37,240 bytes, SHA256
`34f3b8fb405ce3362398cf11b93040614f25244fa27a555e88bc610f5170fe7b`.
This is object evidence, not new kernel execution. [Bytecode comparison](q16-bytecode-comparison.json).

Modified files: `tc/Makefile`, `tc/controller.c`, `tc/demo.py`,
`tc/tc_ids.bpf.c`, `tc/tests/native.c`, `tc/tests/test_tc.py`, `tc/README.md`.
Added code/configuration/specification is under `quantization/`: independent
reference/calibration scripts, generated scale metadata, shared checked
arithmetic, host-C tests, kernel rejection fixtures and the private benchmark.
Evidence is under this directory. Generated `.so`, executables and object files
are excluded from any intended commit.

## 2. Scaling design and provenance

The network is bias-free 6 -> 32 -> 32 -> 2. Static mode retains truncating
normalization and arithmetic right-shift flooring in linear layers. Experimental
mode uses nearest-even rescaling, checked int64 accumulation, int32 bounds and
explicit prediction rejection on invalid input/configuration/arithmetic. There
is no saturation/wrapping success path and no runtime adaptation. Packets pass.

| Stage | Input q | Weight q | Bias/accumulator q | Output q | Shift |
| --- | ---: | ---: | ---: | ---: | ---: |
| Normalize | raw/scaler 0 | n/a | rational division | 22 | quotient/remainder |
| Linear 0 / ReLU 0 | 22 | 16 | 38 (zero bias) | 23 | 15 |
| Linear 1 / ReLU 1 | 23 | 16 | 39 (zero bias) | 21 | 18 |
| Output | 21 | 16 | 37 (zero bias) | 18 | 19 |

An integer at q represents integer / 2**q. Dot products start at q_input+q_weight;
shifting by q_input+q_weight-q_output yields the selected output representation.
Weights remain exactly the Q16 header values: candidate q=12..16 errors were
measured, and q16 has zero error relative to that source while meeting bounds.
Higher weight exponents cannot recover precision already lost during training
export. No original FP32 checkpoint or unrounded scaler was found in the
working tree or Git object paths. The high-precision reference is an **exact
rational reconstruction of the Q16-header network**, not original FP32.

Calibration is offline and label-free. SHA256(`b'lsfp-20261107\0' + little-endian
int64[6] row) assigns identical vectors to the same partition, using first64
unsigned big-endian < 2**62 for calibration. Actual split: **4,996 calibration,
13,844 held-out** rows; 18,561 unique feature vectors. The stored file's
collection provenance and original training partition are not established;
no detection accuracy/F1 is claimed. The selector only receives calibration
rows, fixes factor-two power-of-two bounds and then chooses maximal safe
exponents from conservative per-neuron triangle bounds. Held-out outputs do
not tune scales. [Configuration](scale_config.json), [calibration ranges](calibration_ranges.json),
[complete pre-implementation arithmetic specification](../../quantization/DESIGN.md).

Supported domain: abs(raw-mean) <= scale * `[8,128,64,16,16,16]` componentwise,
with signed int64 raw values. The strongest absolute accumulator bounds are
34,654,816,043,008; 224,214,960,404,480; 327,688,736,106,947. Every output bound
is below 2**30. Unsupported flows receive no successful experimental prediction;
the existing failure/retry state machine releases workspace ownership.

Representative stored row 0 normalizes at q22 to
`[3162003,-1742632,-310689,-1189055,-963064,-962539]`.
The first neuron's Q16 weights are `[459,25462,-44400,-20077,-17088,-21160]`.
Their integer dot product is **31,571,875,100 at q38**. Nearest-even division by
2**15 gives **963,497 at q23**, matching the host implementation.
[Saved example and logits](layer_example.json).

## 3. Numerical validation

Gate 1 (formal mathematics): PASS. Gate 2 (Python/calibration): **21 tests PASS**.
Gate 3 (shared host C): **19,004 supported fixtures, 114,024 stage tensors,
2,584,544 integers**, zero mismatches; 121 boundary comparisons and UBSan PASS.
Fixtures include all 18,840 stored rows, 64 domain corners, fixed examples and
96 seeded vectors. Additional host C tests reject zero/negative scales and
normalization-shift overflow. The final host build is warning-free; initial
host-only forced-unroll warnings were diagnosed and corrected without removing
BPF unroll directives. [Python log](python-tests.log), [host results](host_results.json),
[UBSan output](host-clean-ubsan.log), [extra guards](additional_boundaries.json).

Held-out errors after conversion to comparable real scales, relative to the
exact reconstructed network:

| Tensor | Static MAE | Layer-specific MAE | Static max error | Layer-specific max error |
| --- | ---: | ---: | ---: | ---: |
| normalized | 9.20690368e-06 | 5.06152447e-08 | 1.5258541e-05 | 1.19191523e-07 |
| linear0 | 1.17871136e-05 | 4.38373601e-08 | 3.94810318e-05 | 2.4820536e-07 |
| relu0 | 9.39894165e-06 | 2.70175319e-08 | 3.94810318e-05 | 2.00820753e-07 |
| linear1 | 2.93432471e-05 | 1.29495575e-07 | 9.89221545e-05 | 6.19329472e-07 |
| relu1 | 2.54850785e-05 | 8.57989128e-08 | 9.89221545e-05 | 6.19329472e-07 |
| logits | 0.000177595347 | 9.9137008e-07 | 0.000296741396 | 3.4770068e-06 |

All **13,844 held-out labels agreed** between modes and with the reconstructed
reference: 100% agreement, **0 flips**, no arithmetic events or saturation.
This is agreement, not an accuracy score. Weight values are unchanged and no
held-out overflow occurred, so improved fidelity comes from activation precision
and rounding policy, not recovered weights or corrected dataset overflow.
[Numerical metrics with representative stage integers](numerical_metrics.json).

A separate **Python-only ablation**, not a third deployed mode, kept every
activation at Q16 but used nearest-even rounding. On the same held-out rows its
mean absolute logit error was `4.724905078e-5`, between original Q16's
`1.775953468e-4` and calibrated scaling's `9.913700805e-7`. All labels still
agreed and no arithmetic events occurred. Thus rounding and higher activation
precision both contributed; this is not evidence about the missing original
FP32 model. [Ablation metrics](rounding_ablation.json).

## 4. eBPF execution

Kernel: `6.6.87.2-microsoft-standard-WSL2`, clang `12.0.1-19ubuntu3`, bpftool 7.3.0,
libbpf 1.3, Python 3.10.12. Both modes compile successfully as separate TC objects
and controllers. Model layouts are checked before loading: Q16 5,216 bytes,
experimental 5,304 bytes per slot; wrong mode/layout combinations are rejected.
The two private slots retain identical selected metadata, read-back comparison
and freeze-before-attachment. The per-CPU workspace/flow ABI remains unchanged;
metadata is part of the frozen selected slot. Experimental parameter SHA256:
`7238efdcabc885400037d118e99accc8a440c3fec3140be415b60d304da5347a`.

**Gate 4: PASS.** The user-executed [private kernel run](kernel-ready/run-20261107-114247-586965/REPORT.md)
passed both existing kernel suites in each mode plus eight invalid experimental
fixtures. Independent offline review verified all 88 runtime checksums and all
71 prepared source/binary hashes, replaying 38 predictions / 228 tensors / 5,168
integers per mode with no mismatch. All 40 programs and 43 private maps were
released; no interface was attached or namespace created. See [kernel review](kernel_review.json). Missing parameters, invalid metadata/domain, narrowing/overflow and
tail failures cannot publish successful experimental predictions. Invalid
metadata is rejected by the loader and shared arithmetic tests; kernel rejection
fixtures cover six out-of-domain features, missing parameters and unsafe linear
narrowing. Verifier diagnostics and owned-ID cleanup are saved in that run.

**Gate 5: PASS.** Both [static Q16](live-static/run-20261107-115920-155573/REPORT.md)
and [layer-specific](live-layer/run-20261107-115925-755703/REPORT.md) executed the
full isolated TC suite. Saved-artifact review checked 240 and 238 raw checksums,
respectively, plus prepared source/binary hashes before the later controller-only
benchmark additions. Each mode matched **61 records / 366 stage tensors / 8,296
integers**: 38 records in private kernel suites and 23 from attached TCP tests.
Total: **122 / 732 / 16,592**, zero numerical mismatches. These counts include
both regression and actual packet-processing evidence, not only live flows.

| Attached workload | TCP ingress / egress per mode | Predictions per mode | Six stage counters | Static ingress/egress IDs | Experimental ingress/egress IDs |
| --- | ---: | ---: | --- | --- | --- |
| One connection | 6 / 4 | 1 | `[1,1,1,1,1,1]` | 284 / 285 | 366 / 367 |
| Ten concurrent connections | 60 / 40 | 10 | `[10,10,10,10,10,10]` | 295 / 296 | 377 / 378 |
| One-flow burst | 31 / 20 | 1 | `[1,1,1,1,1,1]` | 306 / 307 | 388 / 389 |

The independent packet witness matched directional flow counts and 60 non-IAT
features per mode, with zero capture drops. Global counters can include control
traffic: the experimental burst counted 32 ingress skbs, of which 31 matched TCP.
All attached paths had zero tail-call failures and experimental arithmetic
diagnostics were zero. Same-flow CPU-pinned tests, duplicate triggers, immutable
results and failure/retry checks also passed. Actual overlap/interrupt nesting
is not forced; concurrent helper timestamp reorder is clamped/counted, not an
exact chronological-IAT reconstruction.

One actual experimental packet snapshot is `[40,65385,32,5001,136,4]` with
kernel logits `[-516392,439440]` at q18, class **1**. The same raw vector gives
`[-129096,109857]` at q16 / class 1 in the **offline original reference**;
that cross-mode counterfactual is not relabeled as kernel evidence. Gate 6 then
executed both kernels on this identical vector and observed these same logits
in their respective representations. All six intermediate tensors also matched
their mode-specific references.

Cleanup released 116 program IDs and 121 map IDs across both live suites;
owned filters, qdiscs and namespaces were removed. [Live audit, source records,
packet counts and identical-input comparison](live_review.json).

## 5. Comparative performance

**Gate 6: PASS.** The [actual benchmark](benchmark-ready/run-20261107-121805-782575/REPORT.md)
loaded two private objects without attaching to an interface. It retained 4,608
kernel-reported `BPF_PROG_TEST_RUN` durations plus 2,304 warmups on CPU 0 of an
Intel i7-1255U. Twelve paired blocks per workload, 32 warmups and 64 samples per
mode/block, alternate mode order; no outliers were removed. `repeat=1` and map
resets between calls avoid skipping completed flows. Each of the six stages
executed 6,912 times. The executing controller checked every fresh record for
deterministic tensors/state/forwarding; offline replay independently matched
72 stored records / 432 tensors / 9,792 integers and recomputed all timing
statistics. Eight nonprivileged benchmark tests passed before execution.

| Workload | Q16 median ns [p10, p90] | Layer-specific median ns [p10, p90] | Paired ratio [bootstrap interval] |
| --- | --- | --- | --- |
| Small TCP vector | 1560 [1483, 1814.9] | 2626 [2484.7, 2750.3] | 1.706 [1.678, 1.716] |
| Saved packet vector | 1538.5 [1482, 1746.6] | 2690.5 [2537, 3196.6] | 1.712 [1.708, 1.739] |
| Entry / FIN | 1710.5 [1626, 1976.5] | 2798 [2689.7, 3033.7] | 1.652 [1.646, 1.654] |

Each mode/workload has 768 retained samples. Ratios are medians of twelve paired
block ratios, not quotients of pooled medians. The intervals are a seeded
10,000-resample descriptive paired bootstrap; WSL2 host scheduling/frequency
is uncontrolled. Retained maxima reached 71,682 ns in experimental small-TCP
and 44,022 ns in static entry/FIN, so the distributions include scheduling noise.

The experimental mode was **slower in every measured workload**, while reducing
mean absolute held-out logit error from `1.775953468e-4` to `9.913700805e-7`
against the reconstructed header network, with 100% prediction agreement.
This is a numerical-fidelity/runtime tradeoff. Additional rounding, arithmetic
guards and activation scaling change together; their costs are not isolated.
Measured durations include kernel test-run, tail calls, telemetry and result
publication. Entry/FIN uses a fresh pre-existing flow, so it includes parsing,
feature extraction and synchronization but excludes flow creation. Per-stage
time, rescaling-only time, NIC throughput, end-to-end latency and F1 remain
**unmeasured**. These results are not a paper-performance reproduction.

| Recorded resource | Q16 | Layer-specific |
| --- | ---: | ---: |
| Compiled object instruction slots | 4,655 | 13,308 |
| Kernel-translated program bytes, summed across 8 programs | 41,752 | 111,952 |
| Kernel-reported JIT code bytes, summed across 8 programs | 24,243 | 68,058 |
| Parameter value bytes per slot, 2 slots | 5,216 | 5,304 |
| Additional arithmetic diagnostics value bytes | 0 | 32 |

Program lengths exclude allocation/page overhead; instruction slots are code
size, not executed instructions. Added logical map-value storage is 208 bytes
for two metadata slots and diagnostics, excluding kernel map overhead. Flow,
workspace and result layouts remain identical. `tc_entry`/`tc_egress` instruction
bytes also match between modes. Hidden-linear verifier analysis processed
15,685 instructions in Q16 versus 205,716 experimentally, both accepted under
the recorded 1,000,000 limit. This is verifier work, not runtime execution.
[Object resources](compiled_resources.json), [verifier analysis](verifier_resources.json).

Benchmark programs 399–406 / 410–417 and maps 260–267 / 268–276 were all released.
The offline audit checked all 36 raw checksums and all 55 prepared source/binary
hashes before the final documentation-only edits. Production inference objects
are unchanged from Gate 5. [Full benchmark audit and identical-input logits](benchmark_review.json),
[pre-execution protocol](BENCHMARK_PLAN.md).

## 6. Status and reproduction

**Fully working within the declared input domain and tested TC scope:** all six
gates passed, including attached packet inference in both modes, all-stage
numerical parity, tested concurrency/failure handling, private timing comparison
and cleanup. Preserve Q16 as the default. No original FP32 recovery, labeled
detection accuracy/F1, universal concurrency proof or physical-NIC performance
claim follows. Timestamp reorder, parser/fragmentation/offload, finite flow-map
capacity/lifecycle and dataset-provenance limits remain as documented for the
TC baseline. There is no retraining, prevention, feature change or dynamic scaling.

Executed nonprivileged commands:

```bash
python3 quantization/calibrate.py --output verification-logs/layer-specific-20261107
python3 -m unittest -v quantization.test_reference
python3 quantization/run_host.py --output verification-logs/layer-specific-20261107 --tag host-clean
python3 validation/run.py --output verification-logs/layer-specific-20261107/static-regression
./run-tc-smoke.sh --prepare --kernel-only --mode layer_specific --output verification-logs/layer-specific-20261107/kernel-ready
python3 -m unittest -v quantization.test_benchmark
python3 quantization/benchmark.py --prepare --output verification-logs/layer-specific-20261107/benchmark-ready
```

Use new output paths when repeating. Build/test command records and diagnostics
are retained in [commands.jsonl](commands.jsonl) and
[kernel bundle commands](kernel-ready/commands.jsonl).

**Completed Gate 4 command (retained as historical evidence):**

```bash
sudo ./run-tc-smoke.sh --run verification-logs/layer-specific-20261107/kernel-ready --mode layer_specific --kernel-only
```

Recorded result: `arithmetic_kernel_gate: PASS`, both modes' numerical
comparisons PASS, eight invalid cases rejected without predictions, `cleanup:
PASS`. Exact tensor values and verifier results come from the saved artifacts.
On failure inspect the printed run directory, its mode/suite `controller.log`,
verifier logs and `events.jsonl`; do not flush unrelated BPF/TC state.

## 7. Demonstration commands and next steps

Display scales: `cat quantization/calibrated.json`. Display a concrete integer
calculation and outputs: `cat verification-logs/layer-specific-20261107/layer_example.json`.
Display error comparison: `cat verification-logs/layer-specific-20261107/numerical_metrics.json`.

Static Q16 remains the default. To repeat the isolated demos, prepare fresh
bundles (nonprivileged), then obtain approval for their printed `sudo --run`
commands. Each creates owned namespaces/veth, attaches both hooks and cleans up:

```bash
./run-tc-smoke.sh --prepare --mode static_q16 --phase2 --output /tmp/tc-static-demo
./run-tc-smoke.sh --prepare --mode layer_specific --phase2 --output /tmp/tc-layer-demo
```

Mode/scale events identify the representation; per-phase `snapshot.json` holds
features, all tensors, final logits and class. Existing snapshots and the audit
JSON files can be displayed without further privileged execution. Use fresh
paths if those demo preparations already exist. The original successful frozen
bundles are historical evidence; final documentation changes require a fresh
preparation before rerunning. See the [practical README](../../quantization/README.md).


### Completed Gate 5 commands (historical evidence)

Both preparations passed 37 host tests for their selected mode. The user ran
these commands in sequence and both passed. They created only the
owned namespaces/veth interfaces, used both TC hooks, compared live tensors and
independent packet observations, and verified cleanup.

```bash
sudo ./run-tc-smoke.sh --run verification-logs/layer-specific-20261107/live-static --mode static_q16 --phase2
sudo ./run-tc-smoke.sh --run verification-logs/layer-specific-20261107/live-layer --mode layer_specific --phase2
```

`--phase2` is the existing TC integration-suite flag; these runs constitute
Gate 5 of the scaling experiment. Their frozen bundles are historical records;
later validation-only benchmark controller additions did not change either BPF object.

### Completed Gate 6 command (historical evidence)

After successful nonprivileged preparation, the user approved and executed:

```bash
sudo /usr/bin/python3 /home/arnav/research/ebpf-ids-research/quantization/benchmark.py --execute /home/arnav/research/ebpf-ids-research/verification-logs/layer-specific-20261107/benchmark-ready
```

Result: `status: PASS`, 4,608 measured and 2,304 warmup kernel calls,
`network_attachments: NONE`, `cleanup: PASS`. Only the controller processes'
CPU affinity was set; no networking configuration changed. Static Q16 was
faster in all three measured workloads. No additional privileged run is needed
to establish the recorded gates. For future benchmarking, prepare a new bundle
with `python3 quantization/benchmark.py --prepare --output FRESH_PATH` and obtain
approval for its printed execution command.
