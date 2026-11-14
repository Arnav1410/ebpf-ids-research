# Inference latency: unchanged 13,844-vector experiment

**8 November 2026 — host benchmark PASS; prior kernel timings independently
re-audited. No new privileged execution or network attachment.**

Layer-specific arithmetic was slower. Its host resident-arithmetic mean was
**1.831352 µs versus TC/Q16 0.357787 µs (+411.855%)**. The unchanged full TC
host wrapper measured **3.300557 versus 1.665878 µs (+98.127%)**. These are
different timed regions. Prior private-kernel TC results separately show the
same direction of cost, under different inputs and measurement boundaries.

Original weights, normalization, scale-calibration partition and numerical
results are unchanged. This extends the [13,844-vector comparison](THREE_WAY_COMPARISON.md),
not the later CIC external evaluation. The partition excludes scale-calibration
vectors; original model-training overlap remains unknown. No detection-accuracy
or network-throughput claim follows from these timing results.

## Host resident-arithmetic comparison

All three adapters execute the existing C arithmetic helpers, using resident
model parameters. Each call includes six-feature normalization, three linear
layers, two ReLUs, intermediate-output writes/copies and final classification.
Layer-specific metadata validation, overflow guards and rounding remain enabled.
The TC arithmetic adapter excludes program dispatch, map-like workspaces,
telemetry, synchronization and publication. **It is host code, not execution of
TC programs in the kernel.** Q16 helpers are shared by the XDP and TC sources.
The independent XDP and TC host adapters produced identical integers.

| Metric | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| Mean latency (µs) | 0.355116 | 0.357787 | 1.831352 |
| Median / p50 (µs) | 0.341000 | 0.342000 | 1.607000 |
| p95 (µs) | 0.407000 | 0.417000 | 2.892000 |
| p99 (µs) | 0.555000 | 0.614000 | 4.302730 |
| Minimum (µs) | 0.294000 | 0.295000 | 1.154000 |
| Maximum (µs) | 193.049000 | 143.943000 | 468.746000 |
| Population standard deviation (µs) | 0.912592 | 0.895431 | 2.272840 |
| Sequential host inferences/second (batch) | 3,001,846 | 2,917,338 | 539,580 |
| Total timed batch duration, 12 batches (µs) | 55,341.939 | 56,945.072 | 307,884.049 |
| Batch mean per inference (µs) | 0.333128 | 0.342778 | 1.853294 |
| Successful / failed, including warmups | 498,384 / 0 | 498,384 / 0 | 498,384 / 0 |
| Prediction/logit/tensor agreement | 100% against archived/reference outputs | 100% against archived/reference outputs | 100% against archived/reference outputs |

Each cell's per-call statistics use **166,128 timings = 13,844 vectors × 12
trials**. Each configuration additionally executes 166,128 separately batch-
timed inferences and 166,128 warmups. Thus 498,384 invocations per configuration
are correctness-checked; no failures or slow samples are discarded.

Throughput uses `166128 × 10^9 / sum(batch_duration_ns)`, excluding validation
and individual clock calls. Batch duration includes the C loop, indirect calls,
return-status stores and inference's output stores. It is **sequential host
loop throughput**, not concurrent flow, packet, NIC or end-to-end throughput.

## Unchanged existing wrappers — separate setup-inclusive scope

The actual existing exports are also timed: `native_mlp` from
`validation/native.c` and `vector_infer` from `evaluation/tc_vectors.c`.
XDP's export performs arithmetic with already-loaded parameters. TC's export
**calls `host_reset()` on every inference**, zeroing all 64 mock table slots,
reloading model parameters, seeding a mock flow/workspace, running all six TC
stages through mocked tail dispatch, checking completion, publishing and copying
the full result. These wrappers were not changed or optimized for timing.
The XDP/TC difference here cannot be interpreted as the cost of migrating hooks.

| Metric | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| Mean latency (µs) | 0.347873 | 1.665878 | 3.300557 |
| Median / p50 (µs) | 0.340000 | 1.686000 | 3.035000 |
| p95 (µs) | 0.408000 | 1.765000 | 4.578000 |
| p99 (µs) | 0.520000 | 1.993000 | 6.501730 |
| Minimum (µs) | 0.294000 | 1.352000 | 2.343000 |
| Maximum (µs) | 188.096000 | 288.871000 | 420.124000 |
| Population standard deviation (µs) | 0.843235 | 1.789499 | 2.840991 |
| Sequential host inferences/second (batch) | 2,948,790 | 587,791 | 299,577 |
| Total timed batch duration, 12 batches (µs) | 56,337.684 | 282,630.955 | 554,542.010 |
| Batch mean per inference (µs) | 0.339122 | 1.701284 | 3.338041 |
| Successful / failed, including warmups | 498,384 / 0 | 498,384 / 0 | 498,384 / 0 |
| Prediction/logit/tensor agreement | 100% against archived/reference outputs | 100% against archived/reference outputs | 100% against archived/reference outputs |

This scope quantifies the existing validation harness, including its asymmetric
setup. TC/Q16 versus TC/layer-specific within this scope shares that setup;
resident arithmetic better isolates the arithmetic comparison. Neither scope
contains packet parsing, feature extraction, kernel map operations or real
BPF tail calls. The full TC wrapper executes the actual TC stage functions under
existing mocks; the resident adapter calls their arithmetic helpers directly.

![Measured host latencies and repeated-trial p50](verification-logs/inference-latency-20261108/run/host-latency.png)

[Exportable PDF](verification-logs/inference-latency-20261108/run/host-latency.pdf).
Bars are pooled per-call p50; dots are all twelve trial p50 values. Full tails,
including unusually long samples, remain in the tables and raw archive.

## Timing protocol, controls and variability

- Same immutable 13,844 vectors in their original saved row order for every mode,
  scope, warmup and repetition. No row sampling, reordering or new calibration.
- Twelve trials rotate the six configurations through each order position twice.
  Individual/batch pass order reverses on alternating trials. Each configuration
  receives one complete warmup pass before its two measured passes.
- One host thread runs sequentially on allowed CPU 0. CPU identity is checked
  at both ends of every pass; only the benchmark process's affinity is changed
  and restored. Host/WSL scheduling, CPU frequency and thermal state are not controlled.
- `clock_gettime(CLOCK_MONOTONIC_RAW)` runs in C. Per-call boundaries surround
  the selected inference function; separate batch boundaries surround one full
  C loop, with only two clock reads. Reported clock resolution is 1 ns,
  which is not a claim of 1 ns measurement accuracy.
- No Python dispatch, JSON/CSV, allocation, file I/O, reference evaluation,
  comparisons or checksum accumulation is inside those timed regions. Python
  invokes complete C passes. Every output is consumed afterward, with compiler
  memory barriers, non-inlined call boundaries and no LTO preventing elimination.
- Empty indirect-call/timer-pair controls use 13,844 retained measurements per
  compiled mode. They characterize a lower-bound timer/call cost; they do not
  reproduce output-memory traffic. Raw latencies are reported **without noisy
  overhead subtraction**. Batch timings independently avoid per-call timer cost.
- Percentiles use linear interpolation at `(n−1) × p`; standard deviations are
  population SD (`ddof=0`). Independent NumPy recomputation agrees with saved
  summaries. Samples from repeated vectors and one WSL process are correlated;
  they are not independent measurements of production network performance.

| Compiled mode | Empty-call mean (µs) | Empty-call p50 (µs) |
| --- | ---: | ---: |
| xdp_q16 | 0.014901 | 0.015000 |
| tc_q16 | 0.014732 | 0.015000 |
| tc_layer_specific | 0.015315 | 0.015000 |

| Scope / mode | SD of 12 trial means (µs) | Minimum–maximum trial p50 (µs) |
| --- | ---: | ---: |
| resident_arithmetic / xdp_q16 | 0.020997 | 0.303000–0.349000 |
| resident_arithmetic / tc_q16 | 0.027546 | 0.300000–0.344000 |
| resident_arithmetic / tc_layer_specific | 0.114906 | 1.525000–1.749000 |
| existing_wrapper / xdp_q16 | 0.023266 | 0.302000–0.348000 |
| existing_wrapper / tc_q16 | 0.081937 | 1.489000–1.711000 |
| existing_wrapper / tc_layer_specific | 0.164105 | 2.805000–3.190000 |

Complete per-trial means, percentiles, batch totals and ranges are in
[trial-summary.csv](verification-logs/inference-latency-20261108/run/trial-summary.csv).
All observations, including the large maxima, are retained in
`run/raw-timings.jsonl.gz`. The timed benchmark phase wall time was
**7.065537 seconds**, including warmups, correctness checks, Python dispatch,
progress and raw-log serialization; it excludes initial reference checking,
compilation and later regression/audit/plotting. It is not an inference latency.

Relative differences use **TC/Q16 as denominator within the same scope**:
`100 × (configuration_latency − TC_Q16_latency) / TC_Q16_latency`.

| Scope / mode | Mean latency difference | Pooled p50 difference | Batch-per-inference difference |
| --- | ---: | ---: | ---: |
| resident_arithmetic / xdp_q16 | -0.746% | -0.292% | -2.815% |
| resident_arithmetic / tc_layer_specific | +411.855% | +369.883% | +440.668% |
| existing_wrapper / xdp_q16 | -79.118% | -79.834% | -80.067% |
| existing_wrapper / tc_layer_specific | +98.127% | +80.012% | +96.207% |

The resident-arithmetic XDP/TC Q16 mean difference is smaller than observed
trial variability and does not establish a hook overhead. A separately saved
paired-trial bootstrap describes TC/layer versus TC/Q16 median ratios:
5.032920 for resident arithmetic and 1.884019 for existing wrappers. These are
medians of paired trial ratios, not quotients of pooled medians and not claims
about native Linux/NIC performance. All twelve paired values are retained.

## Actual eBPF kernel timing — recorded experiment, not a fresh run

The existing 7 November private-kernel benchmark provides real
`BPF_PROG_TEST_RUN` measurements for TC/Q16 and TC/layer-specific. This task
verified its 36 saved-file checksums, replayed all 72 stored block records
against the numerical references, and independently recomputed the statistics
below from the 4,608 original measured durations. Its 2,304 warmups are not
included in those distributions. **No kernel call was made in this task.**

| Recorded workload / TC mode | Mean (µs) | p50 (µs) | p95 (µs) | p99 (µs) | Min / max (µs) | Population SD (µs) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mlp_small_tcp / static_q16 | 1.636344 | 1.560000 | 1.852650 | 2.007650 | 1.436000 / 35.657000 | 1.251130 |
| mlp_small_tcp / layer_specific | 2.812462 | 2.626000 | 2.860300 | 4.824780 | 2.453000 / 71.682000 | 2.631809 |
| mlp_saved_packet / static_q16 | 1.589643 | 1.538500 | 1.862650 | 1.896660 | 1.435000 / 10.452000 | 0.405283 |
| mlp_saved_packet / layer_specific | 2.883516 | 2.690500 | 3.673550 | 5.073480 | 2.449000 / 61.988000 | 2.183883 |
| entry_fin / static_q16 | 1.790891 | 1.710500 | 2.036650 | 2.117880 | 1.575000 / 44.022000 | 1.530312 |
| entry_fin / layer_specific | 2.949635 | 2.798000 | 3.349650 | 4.790250 | 2.655000 / 29.842000 | 1.372204 |

Every workload/mode cell has 768 timings from 12 blocks. Two pre-existing
feature cases were selected before that experiment: `[20,0,20,5001,20,1]`
and `[40,65385,32,5001,136,4]`. The entry/FIN workload recreates the first case
from one controlled FIN with a pre-existing fresh flow. These are **two fixed
representative vectors and one entry path**, not a sampled subset of the 13,844
rows and not a new random kernel cohort. They must not be pooled with host timings.

For `mlp_*`, execution begins at `tc_preprocessing` and proceeds through all
six stages and real tail calls to result publication and workspace release.
For `entry_fin`, it starts at `tc_entry`, additionally parsing the packet,
updating shared state and snapshotting features. Durations are the kernel's
returned test-run execution durations, not userspace syscall wall time.
They include test-run timing overhead and the program's existing stage counters,
tensor snapshots, map lookups, locks and result publication. No pure arithmetic
or instrumentation-free kernel latency is claimed. Map/flow resets and userspace
read-back validation happen between `repeat=1` calls, outside reported durations.

The executing controller checked fresh predictions, six-stage counts, release,
features and deterministic tensors on every call: **6,912 complete chains**,
including warmups. Independent saved-record replay covers 72 × 6 tensors;
the recorded cleanup released 16 program IDs and 17 map IDs. Q16 program IDs
were 399–406; experimental IDs were 410–417. Current TC inference sources,
parameters, both BPF objects and benchmark C driver match the recorded hashes.
Later controller/deployment changes are not misrepresented as the historical
benchmark build. [Hash comparison](verification-logs/inference-latency-20261108/historical-kernel-source-check.json).

| Kernel measurement availability | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | --- | --- | --- |
| Complete comparable six-stage timing | NOT RUN | Recorded PASS | Recorded PASS |
| Fresh execution in this task | NOT RUN | NOT RUN | NOT RUN |
| Physical-interface / live network timing | NOT RUN | NOT RUN | NOT RUN |

The existing original XDP parity runner leaves the tail-call map empty and
executes each stage in a separate test-run. Those stage durations cannot be
summed into a comparable complete-chain latency. A fair XDP/TC kernel comparison
requires a separate whole-chain validation driver and equivalent observation/
publication boundaries; it is **not implemented here**. No production program
or kernel instrumentation was modified to manufacture that comparison.

Kernel environment for the recorded measurements: WSL2
`6.6.87.2-microsoft-standard-WSL2`, x86_64, Intel i7-1255U, CPU 0; recorded
baseline `791e25932e01a8e457c81237fdc8da2ea971b32e` with that experiment's
layer-specific source manifest. [Recorded raw run](verification-logs/layer-specific-20261107/benchmark-ready/run-20261107-121805-782575/REPORT.md),
[recomputed kernel table](verification-logs/inference-latency-20261108/run/kernel-saved-evidence.json).
Host and kernel use different workloads, compilation targets and timing regions;
do not calculate host-to-kernel speedups from these tables.

## Numerical correctness, regression results and preservation

Before measurement, every archived source ID, input, supplied label, predicted
label, logit and all six stage hashes was matched to the unchanged deterministic
partition and independent integer references. Unsafe arithmetic aborts before
calling timed C. Each warmup and timed pass checks every label and **136 valid
intermediate integers**, including logits, after stopping its timers. Checksums
must remain identical within a mode across scopes and trials. No errors,
overflow events or changed predicted labels were observed on the benchmark inputs.

There were **2,990,304 successful inference invocations, zero failures** across
six configurations, all warmup and timed passes. Executing C checks therefore
cover 17,941,824 stage tensors / 406,681,344 integers. These are repeated checks
of 13,844 distinct stored rows, not millions of independent evaluation samples.
The independent audit verifies their accounting and all raw-derived statistics;
it does not claim to re-execute the historical kernel calls.

| Check | Result | Scope |
| --- | --- | --- |
| New adapter/statistics tests plus existing benchmark tests | PASS | 14 tests; includes corrupted intermediate-output/label rejection |
| Existing quantization reference tests | PASS | 21 tests |
| Original numerical validation | PASS | 34 tests run: 32 passed, 2 skipped; no smoke-log argument and missing original FP32 checkpoint |
| Existing TC regression suite after measurement | PASS | 37 tests per mode, including host same-flow/distinct-flow concurrency and failure paths |
| Layer-specific C/reference/UBSan regression | PASS | 19,004 fixtures; 121 boundary checks; zero mismatches |
| Independent raw timing audit | PASS | NumPy 2.2.6 checks all defined statistics, totals, throughput and relative differences |
| Saved complete-chain kernel evidence | PASS, historical | Actual execution and cleanup on unchanged BPF objects, re-audited read-only |
| Fresh kernel verifier/execution/concurrency tests | NOT RUN | Development sandbox has no effective BPF/network capabilities; no privileged rerun requested/executed |
| Old numerical results and existing sources | UNCHANGED | 83 source files plus the three original evidence files checked |

The new TC regression runner initially resolved legacy `import demo` to the
newer root demo package, causing two mocked cleanup tests per mode to error.
Only the new runner's temporary module binding was corrected; all 37 tests then
passed per mode in `tc-regressions-r2`. The original tests, detector and measured
C adapters were unchanged, so latency samples were not selectively repeated.
Known legacy overflow/parser limitations remain documented in the original
validation; passing this bounded dataset does not remove them.

The previously reported logit MAEs remain **0.0001775953468331884 for Q16** and
**0.000000991370080459385 for layer-specific**, relative to the exact rational
Q16-header network, not an unavailable FP32 checkpoint. Prediction agreement
remains 100%; the supplied-label F1 diagnostic remains 0.9613857454834227.
No training, scaler fitting, scale selection, label adjustment or threshold
change occurred. More precise arithmetic did not improve classifications here.

## Reproduce and inspect

Actual commands executed, from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v   evaluation.test_latency quantization.test_benchmark

PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR=/tmp/nn-ebpf-latency-matplotlib /tmp/nn-ebpf-cic-eval-20261108/bin/python -m evaluation.latency   --output verification-logs/inference-latency-20261108/run --trials 12

PYTHONDONTWRITEBYTECODE=1 python3 validation/run.py   --output verification-logs/inference-latency-20261108/original-regression
PYTHONDONTWRITEBYTECODE=1 python3 quantization/run_host.py   --output verification-logs/inference-latency-20261108/layer-regression
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v quantization.test_reference
PYTHONDONTWRITEBYTECODE=1 python3 -m evaluation.latency_regressions   --output verification-logs/inference-latency-20261108/tc-regressions-r2

PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-cic-eval-20261108/bin/python   -m evaluation.latency_audit --run verification-logs/inference-latency-20261108/run
```

For a repetition use a **new** output path; completed measurements are never
overwritten. Source `metrics.json`, `samples.json` and `predictions.jsonl.gz`
default to `verification-logs/final-demo-20261107/offline-r2`.
The required original 13,844 prediction archive is retained locally and is not
supplied by cloning source alone. If absent, regenerate it inside the repository
with `python3 evaluation/offline.py --output verification-logs/latency-reference --encoded-label-diagnostics`
and pass `--source-evidence verification-logs/latency-reference` to the benchmark.
Saved historical kernel files are also required by the default evidence audit;
do not fabricate replacements. Dependencies are Python 3.10, clang-12, NumPy
2.2.6 and Matplotlib 3.10.3; the actual command reused the existing isolated
`/tmp/nn-ebpf-cic-eval-20261108` environment. A fresh environment can install
NumPy/Matplotlib with pinned binary wheels without changing system packages.

All three builds use `clang-12 -O3 -shared -fPIC -pthread -fno-lto`, with original
validation includes for XDP, TC mock includes for TC, `-DLATENCY_XDP` for original
and `-DIDS_LAYER_SPECIFIC` for experimental arithmetic. Build argv and output are
saved. Original helper exports emit three existing optimizer “loop not unrolled”
warnings; both TC builds emit no warnings. No sanitizer instruments the timed
libraries; sanitizer checks run separately afterward.

Host environment: WSL2 `6.6.87.2-microsoft-standard-WSL2`, x86_64, Intel Core
i7-1255U, Python 3.10.12, glibc 2.35, Ubuntu clang 12.0.1-19ubuntu3. Current branch
`feature/cic-external-evaluation`, baseline HEAD
`73868b101d1c1f5e27c6f71eceaa78a645368445`. New benchmark sources are uncommitted
and identified by the saved source manifest; no commit/push was performed.

Optional **future** kernel timing refresh, not executed by this task:

```bash
python3 quantization/benchmark.py --prepare   --output verification-logs/inference-latency-kernel-refresh
```

Review the prepared bundle and obtain approval before its printed privileged
`--execute` command. That existing benchmark uses only private unpinned maps and
unattached programs; it supplies no comparable XDP complete-chain timing.
The previously successful bundle is historical evidence, not a mutable command
to rerun after source changes.

## Files and evidence

New code only: `evaluation/latency.py`, `evaluation/latency_adapter.c`,
`evaluation/latency_audit.py`, `evaluation/latency_regressions.py`,
`evaluation/test_latency.py`, this report and the new evidence directory.
Existing XDP/TC, training, models, calibration, demo, validation and offline
comparison files were not edited. Unrelated uncommitted work is preserved.
No physical/veth interface, qdisc, BPF object/map, route or firewall was changed.
Only temporary host libraries and process-local CPU affinity were used; no
network cleanup was required. Generated binaries/raw timings are not staged.

- [Machine-readable results](verification-logs/inference-latency-20261108/run/results.json).
- [Plan, all original row IDs and input SHA256](verification-logs/inference-latency-20261108/run/plan.json).
- [All 72 trial summaries](verification-logs/inference-latency-20261108/run/trial-summary.csv).
- [Independent raw timing audit](verification-logs/inference-latency-20261108/run/independent-audit.json).
- [TC regression results](verification-logs/inference-latency-20261108/tc-regressions-r2/results.json).
- [Original regression results](verification-logs/inference-latency-20261108/original-regression/results.json).
- [Layer-specific C/UBSan results](verification-logs/inference-latency-20261108/layer-regression/host_results.json).
- [New benchmark source hashes](verification-logs/inference-latency-20261108/SOURCE_SHA256SUMS).

The supported conclusion is a **precision-versus-cost tradeoff on the specified
host and recorded kernel workloads**. Static Q16 remains the appropriate default
for the working demonstration; no new classification benefit was measured for
the slower experimental arithmetic. New native-NIC, application end-to-end and
three-way complete-chain kernel comparisons remain unmeasured.
