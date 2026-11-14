# Kernel inference latency on the frozen 13,844-row partition

8 November 2026. **Full TC benchmark: PASS, independently audited.** The operator
executed the approved 100-vector pilot and then all 13,844 frozen vectors in
both TC modes for five measured trials. All intended calls executed the six
inference stages and matched their corresponding frozen host reference.
Original XDP timing remains **NOT RUN**: its existing pipeline lacks the required
per-run stage-completion evidence. The requested three-way kernel comparison
therefore remains incomplete; no host or modified-XDP timing fills that gap.

## Full-cohort results

These are actual kernel-returned `BPF_PROG_TEST_RUN` durations, starting at the
first inference stage. Both modes use the same vectors, CPU and measurement
protocol. Units below are microseconds; the raw records retain nanoseconds.

| Measurement | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | --- | ---: | ---: |
| Distinct stored vectors | NOT RUN | 13,844 | 13,844 |
| Measured trials | NOT RUN | 5 | 5 |
| Measured kernel calls | NOT RUN | 69,220 | 69,220 |
| Mean (µs) | NOT RUN | 4.548055 | 15.072869 |
| Median / p50 (µs) | NOT RUN | 3.637000 | 13.722000 |
| p95 (µs) | NOT RUN | 7.093000 | 20.420150 |
| p99 (µs) | NOT RUN | 11.381430 | 37.809580 |
| Population SD (µs) | NOT RUN | 31.923147 | 23.739860 |
| Minimum (µs) | NOT RUN | 1.622000 | 4.494000 |
| Maximum (µs) | NOT RUN | 6058.877000 | 3596.783000 |
| Kernel-time-normalized inferences/s | NOT RUN | 219,874.222 | 66,344.371 |
| Failed calls / numerical mismatches | NOT RUN | 0 / 0 | 0 / 0 |

Layer-specific arithmetic had **3.314× mean latency
(231.414% higher)** and
**3.773× median latency
(277.289% higher)**, with TC Q16
as the denominator. This compares the complete existing implementations,
including their validation and telemetry costs. It establishes neither pure
matrix-arithmetic cost nor detection accuracy or F1.

![Actual full-cohort kernel latency](verification-logs/kernel-13844-20261108/full-plots/kernel-latency.png)

[Exportable PDF](verification-logs/kernel-13844-20261108/full-plots/kernel-latency.pdf),
[exact machine-readable results](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/results.json),
[per-trial CSV](verification-logs/kernel-13844-20261108/full-trial-summary.csv).

### Trial variation and retained outliers

Every table entry below summarizes 13,844 timings. Trials repeat the same
vectors; they are not independent dataset samples.

| Trial | TC Q16 mean (µs) | TC Q16 p50 (µs) | Layer-specific mean (µs) | Layer-specific p50 (µs) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 4.655049 | 3.539000 | 14.804801 | 13.398000 |
| 2 | 4.227962 | 3.597500 | 14.665099 | 13.584000 |
| 3 | 4.915710 | 3.705000 | 15.426533 | 13.837000 |
| 4 | 4.613469 | 3.669000 | 15.358376 | 13.896000 |
| 5 | 4.328084 | 3.658000 | 15.109536 | 13.884000 |

All timings were retained. TC Q16 had **27 samples above 100 µs**, including
**5 above 1 ms**; layer-specific had **93 above 100 µs**, including **8 above
1 ms**. These tails explain the large pooled standard deviations. The population
SD of the five trial means was 0.245660 µs and 0.298688 µs, respectively; that
quantity differs from the pooled sample-duration SD in the main table.
The causes of individual extremes were not isolated. WSL2 scheduling, interrupts,
caches and CPU frequency were not controlled sufficiently to assign a cause or
claim production real-time bounds. No independent-sample confidence interval or
significance claim is made.

The displayed service rate is `measured_calls × 10^9 / sum(duration_ns)`.
It excludes userspace control/setup work and **is not achieved application or
network throughput**. Total experiment wall time was 380.083770 s,
including warmup, loading, resets, reference checks, read-back, compression and
cleanup; this wall time is not used as inference latency. Percentiles use linear
interpolation, and population SD uses `ddof=0`.

## Execution, correctness and cleanup evidence

The full experiment completed **166,134 kernel calls**: 138,440 measured calls,
27,688 cohort warmups and six separate zero-tensor repetition checks. Each mode
completed 83,064 cohort calls plus three repetition checks. No calls failed and
no numerical mismatches were found.

Each invocation enters **`tc_preprocessing`**, then executes all six stages
through `tc_output_linear`, with **five actual tail-call transitions**. All six
program-array slots are initialized and verified. Direct preprocessing entry
bypasses the initial parser-to-preprocessing tail call; it does not bypass any
of the six inference stages.

Before every invocation, the existing C benchmark driver removes its private
flow/result key, resets per-CPU workspaces and initializes a fresh consistent
feature snapshot. It uses `repeat=1`; it never times repeated calls against an
already-completed flow. Afterward it checks a fresh result with stage mask 63,
correct CPU/model slot/sequence/features, released workspace, DONE flow, one
prediction and exactly one increment of every stage counter. Missing stages,
failed calls and mismatched tensors stop execution rather than becoming fast
successful samples.

The two zero-intermediate-tensor guard fixtures each completed three fresh
predictions with stage increments **[3, 3, 3, 3, 3, 3]**. This specifically checks
that an unchanged all-zero tensor cannot hide a skipped repeated inference.

The executing controller checked **996,804 stage tensors / 22,594,224 integers**
over all calls. A fresh read-only replay independently checked the saved
**996,780 tensors / 22,593,680 integers** against the integer references and
archived host outputs. The smaller saved count is explicit: each three-call
guard block retains its last tensors, while the executing C driver checks every
call. Ordinary per-vector records retain all six tensors and logits. These are
repeated numerical checks on 13,844 rows, not 166,134 independent flows or a new
classification-accuracy experiment.

| Owned objects recorded during full execution | TC Q16 | TC layer-specific |
| --- | --- | --- |
| Loaded program IDs | 66–73 | 77–84 |
| Six inference target IDs, slots 0–5 | 68–73 | 79–84 |
| Private map IDs | 18–25 | 26–34 |
| Program type | 3 (`SCHED_CLS`) | 3 (`SCHED_CLS`) |
| Model bytes per slot / verified slots / active slot | 5,216 / 2 / 0 | 5,304 / 2 / 0 |
| Verifier acceptance | PASS: eight accepted logs | PASS: eight accepted logs |
| All recorded owned IDs absent after close | PASS | PASS |

The packet entry/egress programs were loaded as part of each existing object,
but no hook was attached. There were **no interfaces, tracing attachments,
map pins, namespaces, veths, qdiscs, routes or firewall changes**. Cleanup closed
owned objects and checked IDs without opening new object FDs. No network cleanup
command is needed for this experiment.

Evidence: [full saved audit](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/audit.json),
[fresh independent numerical replay](verification-logs/kernel-13844-20261108/full-independent-audit.log),
[independent NumPy statistics/accounting review](verification-logs/kernel-13844-20261108/FULL_VERIFIED.json),
[raw per-vector timings and tensors](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/measurements.jsonl.gz),
[recorded ID/model/tail-slot metadata](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/results.json),
[Q16 verifier logs](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/static_q16),
[layer-specific verifier logs](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/layer_specific),
[Q16 cleanup](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/static_q16/ids-absent.json),
[layer-specific cleanup](verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/layer_specific/ids-absent.json).
Both controller error logs are empty. Independent NumPy 2.2.6 recomputation
matched every pooled and per-trial statistic, duration sum and normalized rate.

## Timing boundary and limitations

The measured value is the kernel-returned test-run duration in ns, with
`repeat=1` and flags zero. It includes normalization, the six inference stages,
real tail calls, existing map lookups, counters, tensor retention,
synchronization, result publication and kernel test-run timing overhead.
It is **kernel model-stage-chain latency**, rather than an instrumentation-free
or pure arithmetic estimate. No estimated overhead has been subtracted.

Flow resets/insertion, workspace initialization, userspace syscall/IPC time,
reference calculations, map read-back and file I/O occur outside that duration.
The fixed synthetic packet supplies a context/key only: **it does not represent
an entire stored flow**. Packet parsing, six-feature extraction and TCP-trigger
handling are bypassed by entering at preprocessing. Stored features, including
ns-based IAT, are injected unchanged; kernel helper clocks do not reconstruct
the original flow. This measures neither full XDP/TC packet-processing latency
nor NIC latency or a live TCP exchange.

Original XDP can accept seeded private flow state and its six tail targets can
be populated. The blocker is per-run observation: the original stages have no
completion mask/counters or retained six-tensor result. Correct final logits
cannot prove that an operation ran when zero or unchanged intermediates would
produce the same values. Existing stage-isolated kernel parity does not prove
full-chain execution, and its separate stage timings cannot be summed into an
original-XDP inference time. The final trace message is not a retained per-stage
completion record.

No validated scoped observer was available for this measurement. Ordinary entry
probes were not assumed to observe every tail-call entry; no privileged tracing
probe was attempted. The smallest future alternative is a separately validated
observer or clearly labeled validation-only XDP instrumentation, with its
measurement overhead reported. Neither would automatically establish the
uninstrumented original pipeline's latency. No simulated XDP result is supplied.

## Frozen inputs and preserved implementation

The cohort is the unchanged **13,844 reproduction scaling-held-out rows**, with
the original row IDs, six features, labels, logits and stage hashes. It is held
out from layer-scale calibration, **not** a recovered original model-training
test split. It is not the external CIC cohort. Original checkpoint training
membership remains unknown. No retraining, scaler refitting, recalibration,
weight replacement or classification-rule change occurred.

New [orchestration](evaluation/kernel_latency.py) reuses the existing
`quantization.benchmark.Controller`, `quantization/benchmark.h`, `tc/controller.c`,
unmodified TC BPF objects and established independent integer references.
The [seven new host protocol tests](evaluation/test_kernel_latency.py) test
stage/repetition checks, gates and saved-record auditing. No production/BPF
inference source was edited, and no new BPF program was added.

Each mode received one complete warmup pass and five measurement trials; mode
order alternated by row and trial. CPU placement was the same for both modes.
Selection used no predictions. The prior pilot selected 100 distinct rows by
the lowest SHA256 of `kernel13844-pilot-v1` + newline + original row index,
then restored original row order. The pilot passed before the operator
separately approved the full run; the full runner re-audited that gate.

Frozen [plan](verification-logs/kernel-13844-20261108/ready-r2/plan.json),
[source/binary/data manifest](verification-logs/kernel-13844-20261108/ready-r2/source-manifest.json),
[original archived comparison](verification-logs/final-demo-20261107/offline-r2/metrics.json),
[current status](verification-logs/kernel-13844-20261108/STATUS.json).
The superseded `ready` preparation must not be used; `ready-r2` is the bundle
used by the successful pilot and full run.

## Pilot, reported separately

The earlier 100-vector pilot used two trials: 200 measured and 100 warmup
cohort calls per mode, plus three repetition guards each, totaling 606 calls.
Mean durations were **4.466775 µs** (TC Q16) and **13.887685 µs** (layer-specific);
p50 values were **3.303500 µs** and **12.962500 µs**. Numerical, verifier,
repetition and cleanup checks passed. Pilot and previous host/fixed-vector
benchmark timings are not pooled with the full experiment.

[Pilot results](verification-logs/kernel-13844-20261108/ready-r2/pilot-20261108-130715-631464/results.json),
[pilot independent review](verification-logs/kernel-13844-20261108/PILOT_VERIFIED.json),
[pilot figure](verification-logs/kernel-13844-20261108/pilot-plots-reviewed/kernel-latency.png).

## Environment and source identity

| Item | Recorded value |
| --- | --- |
| Kernel / architecture | `6.6.87.2-microsoft-standard-WSL2` / `x86_64` |
| CPU | 12th Gen Intel(R) Core(TM) i7-1255U |
| Benchmark placement | CPU 0; parent allowed CPUs 0–11 |
| Python | 3.10.12 |
| Compiler | Ubuntu clang 12.0.1-19ubuntu3 |
| bpftool / linked libbpf | 7.3.0 / 1.3 |
| Existing BPF compiler flags | `-g -O3 -target bpf -mcpu=v3` |
| Existing controller flags | `-O2 -g -Wall -Wextra -pthread` |
| Independent statistics / plotting | NumPy 2.2.6 / Matplotlib 3.10.3 |
| Branch | `feature/cic-external-evaluation` |
| Base Git commit | `73868b101d1c1f5e27c6f71eceaa78a645368445` |

Controller affinity was pinned; no system-wide CPU or networking tuning was
performed. New harness files remain uncommitted, so the base Git commit alone
does not identify them. Their exact contents and the existing BPF binaries are
bound by the source manifest. SHA256 values:

- Prepared source manifest: `28c697438abbebe2ba88129d5133d03f25c580234681893f14b90608c84a40e3`.
- Frozen plan: `2ef04e178144260996b1f60343e06ab148f0a26a1212c1fd04a0b6f7d4441fa7`.
- Model header: `f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11`.
- Calibration metadata: `f7fc2b92670d7eeb8cc9f84dcb4598392d059f407f5b0a7dd9f22878f4439856`.
- Raw full measurements: `4c46d220601ac6187a3d8135f81b6f15d3e899a735f3cdf873569631e6a095cb`.
- Full results: `d1669d6ec47acdb0a5316a10cfff3bcfd5bb9d4fba4e6ee34d42f4fc2cc28745`.

Other data, archive and binary hashes are in the manifests and
[SHA256SUMS](verification-logs/kernel-13844-20261108/SHA256SUMS). No files were committed or pushed. The unrelated
existing tracked deletion and all prior validation/evaluation evidence were
preserved. Large compressed raw/controller records remain local and ignored by
Git; the original source and model were not changed.

## Checks and exact executed commands

| Check | Status | Evidence boundary |
| --- | --- | --- |
| Build prerequisite | PASS | `make -C tc layer-specific`: targets current; no rebuild or new compiler warnings |
| Object/map/model ABI inspection | PASS | Prepared objects; distinct from kernel verification |
| Nonprivileged protocol/regression tests | PASS | 7 new tests + 8 existing benchmark tests |
| Frozen 13,844-row host archive contract | PASS | Original IDs, features, logits and all stage hashes preserved |
| Actual pilot | PASS | 606 calls; numerical, repetition and cleanup checks |
| Full kernel verifier acceptance | PASS | 16 accepted logs; no verifier failure |
| Full kernel execution and numerical parity | PASS | 166,134 calls; all stages, zero mismatches/failures |
| Full independent numerical/statistics audit | PASS | Saved-record replay and separate NumPy recomputation |
| Full cleanup | PASS | All 16 owned program / 17 map IDs absent |
| Original XDP comparable kernel latency | NOT RUN | Per-run observability unresolved |
| Physical TC/XDP attachment and live latency | NOT RUN | Outside this test; no networking changed |

The following preparation/tests were executed without privilege:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  evaluation.test_kernel_latency quantization.test_benchmark
PYTHONDONTWRITEBYTECODE=1 python3 -m evaluation.kernel_latency --prepare \
  --output verification-logs/kernel-13844-20261108/ready-r2 --trials 5
```

[Build log](verification-logs/kernel-13844-20261108/ready-r2/build.log),
[15-test output](verification-logs/kernel-13844-20261108/protocol-tests-final.log).

The operator separately approved and executed these kernel-only commands:

```bash
sudo /usr/bin/python3 /home/arnav/research/ebpf-ids-research/evaluation/kernel_latency.py \
  --execute-pilot /home/arnav/research/ebpf-ids-research/verification-logs/kernel-13844-20261108/ready-r2
sudo /usr/bin/python3 /home/arnav/research/ebpf-ids-research/evaluation/kernel_latency.py \
  --execute-full /home/arnav/research/ebpf-ids-research/verification-logs/kernel-13844-20261108/ready-r2 \
  --pilot-evidence /home/arnav/research/ebpf-ids-research/verification-logs/kernel-13844-20261108/ready-r2/pilot-20261108-130715-631464
```

Read-only audit and figure generation were then executed without privilege:

```bash
FULL_RUN='verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683'
PYTHONDONTWRITEBYTECODE=1 python3 -m evaluation.kernel_latency --audit "$FULL_RUN" \
  > verification-logs/kernel-13844-20261108/full-independent-audit.log 2>&1
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-cic-eval-20261108/bin/python \
  verification-logs/kernel-13844-20261108/plot_kernel_results.py \
  --run "$FULL_RUN" --output verification-logs/kernel-13844-20261108/full-plots
```

Audit makes no BPF calls and does not rewrite its input. The plot helper is
outside the frozen execution manifest and uses the existing Matplotlib
environment. For a new plot export, choose a fresh output directory. To prepare
a future benchmark, use a fresh preparation path; never overwrite this frozen
bundle. A future privileged execution requires explicit operator approval.
No privileged run was repeated during this independent review.

Files created for this task: `evaluation/kernel_latency.py`,
`evaluation/test_kernel_latency.py`, this report and
`verification-logs/kernel-13844-20261108/` (raw evidence, audits, CSV and plots).
Existing inference programs, weights, scaler, calibration, baseline runners,
validation framework, previous reports and networking remain unchanged.
