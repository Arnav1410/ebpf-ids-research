# Final original-XDP / TC kernel inference latency

**PASS — actual Linux-kernel execution on all 2,826 fresh-model held-out vectors,
five measured trials per mode.** The operator executed the approved pilot and
full benchmark. Two saved-record audits confirmed numerical correctness,
execution counts, timing statistics and cleanup. The full run completed
**50,877 complete-chain executions, zero numerical mismatches and zero inference
failures**. Production source, checkpoint, scaler, split, calibration, previous
measurements and the working demo remain unchanged.

## Final paired results

All columns use the **same three-mode full session**, CPU 0 and rotating order.
Times are **µs**, from inference preprocessing through complete-chain return.
Implementation tracing, parsing, synchronization and publication remain included
as explained below.

| Measurement | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| Model | Same fresh checkpoint | Same | Same + frozen calibration |
| Distinct held-out vectors | 2,826 | 2,826 | 2,826 |
| Measured executions | 14,130 | 14,130 | 14,130 |
| Warmup executions | 2,826 | 2,826 | 2,826 |
| Additional repetition checks | 3 | 3 | 3 |
| Mean | 5.141144 | 3.635677 | 12.846346 |
| Median | 4.426000 | 2.945000 | 11.694000 |
| p95 | 7.415550 | 5.318100 | 17.272100 |
| p99 | 16.871850 | 13.204550 | 32.201840 |
| Minimum | 2.691000 | 2.144000 | 6.580000 |
| Maximum | 1,004.471000 | 2,522.204000 | 647.363000 |
| Population standard deviation | 9.980570 | 21.330194 | 11.114539 |
| Kernel-time-normalized inferences/s | 194,509.256 | 275,051.958 | 77,843.146 |
| Agreement with corresponding frozen host predictions | 100% | 100% | 100% |
| Numerical mismatches / inference failures | 0 / 0 | 0 / 0 | 0 / 0 |
| Verifier / complete-chain validation / cleanup | PASS | PASS | PASS |

The rate is `measured_calls × 10^9 / sum(kernel_duration_ns)`: a normalization
of kernel time, not NIC throughput or wall-clock requests/s. The orchestrator
elapsed time, 15.016412 seconds, includes untimed seeding, syscalls, validation
and readbacks; it is not inference latency. Percentiles use NumPy linear
interpolation; population SD uses `ddof=0`. All outliers are retained.

![Paired latency statistics](experiments/xdp_final_20261108/run/full-final/latency-summary.png)

TC Q16's mean was 29.28% lower than original XDP Q16's in this session;
layer-specific's mean was 3.5334 times TC Q16's. These compare actual
**implementation pipelines**. XDP retains original trace calls and repeated
parsing; TC retains synchronization, counters and result publication. Program-type
wrapper overhead also differs. These figures do not establish a general TC
versus XDP hook speedup or isolate arithmetic cost.

## Inspected implementation and timing boundary

Original source: `src/xdp.bpf.c`, `src/mlp.bpf.h`, `src/common.h`,
`src/handler.bpf.h`, `src/params.bpf.h`. The actual six inference programs are
`xdp_preprocessing`, `xdp_input_linear`, `xdp_input_relu`, `xdp_hidden_linear`,
`xdp_hidden_relu`, `xdp_output_linear`. They use a private `flow_map` value with
two 32-int work buffers and model slot `nn_idx`, a six-target portion of `progs`,
and two `nn_parameters` slots. The original model struct is 5,216 bytes; original
flow key/value are 16/344 bytes. The entire object contains seven XDP programs
and five maps, including its internal read-only trace-format map.

Every run starts directly at preprocessing and follows five real tail
calls to output. Slot 0 is populated but parser-to-preprocessing dispatch is
outside this interval, matching the TC inference-stage boundary. Packet feature
extraction and FIN/RST triggering are not timed or claimed. Source-IP filtering
(`33.33.33.73`) occurs in `xdp_prog`, which is not invoked here. All context
packets use that source and untagged IPv4/TCP with IHL=5, respecting the original
parser's fixed 20-byte IP-header assumption.

The stored six-feature vector is written directly to the original flow fields.
A checksum-correct context frame supplies only the tuple needed for map lookup;
its destination port matches feature 3. **It does not represent an entire stored
flow, nor are six aggregate features inferred from a fake single packet.**
The existing TC test-only seeder is copied and adapted so its flow key, tuple
and context destination port match the same stored vector; owned keys are
removed between records. This changes only untimed userspace initialization and
cleanup, not any TC or XDP inference instruction. The isolated patch is saved
as `TC_SEED_ONLY.patch`.

The measured value is kernel-returned `BPF_PROG_TEST_RUN` duration in ns,
`repeat=1`, flags 0. In upstream Linux 6.6, both regular XDP and skb test paths use
a common timer around the synchronous program invocation; this encloses tail
calls until the chain returns. Frame/skb setup is outside that timer, while
some type-specific wrapper overhead remains inside. This source reading is
supporting evidence, not a substitute for actual chain verification on WSL2.
[Linux 6.6 test-run implementation](https://raw.githubusercontent.com/torvalds/linux/v6.6/net/bpf/test_run.c),
[kernel test-run documentation](https://docs.kernel.org/bpf/bpf_prog_run.html).
The exact Microsoft fork source was not independently retrieved; the running
kernel identity is recorded below; the actual pilot and full runtime checks passed.

Original XDP reparses the tuple in every stage and retains its final
`bpf_printk`, clock reads and division. TC instead includes its existing
workspace/flow synchronization, stage counters, tensor retention and result
publication. These are costs of the actual implementations. Neither duration
is pure arithmetic or an isolated measurement of hook overhead. No trace reader,
observer, trace configuration change, overhead subtraction or packet injection
is used. Ordinary original XDP trace messages are expected during execution.

## How complete original-XDP execution can be verified

Earlier experiments could not certify arbitrary zero/unchanged tensors from
final logits alone. This harness adds **no BPF counter, observer, wrapper or
modified inference program**. It uses a stricter, cohort-specific completion
witness based on the original linear tail graph:

1. Initialize all 64 workspace integers with two known signed poison patterns.
2. Compute the complete expected workspace after every possible prefix using
   the independently validated fresh-model reference. Normalization overwrites
   six entries in hidden2; input linear/ReLU overwrite hidden1; hidden
   linear/ReLU overwrite hidden2; output overwrites hidden1's first two values.
3. Require that the full expected workspace differs from *every* earlier
   prefix, including the untouched seed. **All 2,826 frozen test rows pass;
   the minimum difference is two integers. No row was removed or substituted.**
4. Audit the original source/ELF disassembly: one tail edge to slots 1–5 per
   nonfinal stage, no alternate skipped-stage path. Verify all six actual target
   IDs/types when loaded, and keep the private program array stable during each
   call. Intermediate/final exits are the only outcomes of this linear graph.
5. On every invocation require the read-back final workspace, input fields,
   model slot, fresh nonce and logit-derived label to match exactly. Given this
   private, serialized graph, every early return/tail failure would leave a
   rejected prefix, so reaching the unique final state requires all six stages.

This is a **reachability inference from a verified graph plus per-call state**,
not six independently observed program-entry counters. The actual kernel pilot validated this
method: all six stages are also explicitly test-run
separately for every pilot row with empty tail targets, with every intermediate
buffer checked. Those separate timings are discarded and never summed.
Deleting each required tail slot must produce exactly its earlier prefix and
must fail full-chain validation. Missing-flow and missing-model controls must
also be rejected as complete inference. These seven diagnostics are intentional
partial runs, not successful classifications.

A synthetic all-zero identity case is explicitly rejected by the nonprivileged
witness tests because its last two states are indistinguishable. This method
must not be generalized to arbitrary future vectors/checkpoints without the
same eligibility gate. The frozen cohort and sampling rules stay unchanged.

Original XDP shares per-flow scratch; the test owns private maps, runs serially
on one allowed CPU and reseeds/deletes the key before every call. A nonce and
poison read-back verify fresh initialization. Repetition checks use a certified
held-out vector rather than the ambiguous mean/zero fixture. No production
concurrency claim follows. Classification is derived from actual kernel logits
using original `logit0 > logit1 ? 0 : 1`; original trace-label output is not read.

## Actual 100-vector kernel pilot — PASS

The operator approved and executed the pilot on WSL2
`6.6.87.2-microsoft-standard-WSL2`, i7-1255U, CPU 0. Every mode received the same
100 frozen test IDs, a full warmup pass and two measured trials in rotating
order. These are **200 whole-chain timings per mode**, not a full-cohort result.

| Actual paired pilot measurement | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| Mean µs | 9.775775 | 6.446615 | 22.430560 |
| Median µs | 8.836000 | 6.084000 | 21.492500 |
| p95 µs | 18.457200 | 11.097200 | 35.618600 |
| p99 µs | 38.298060 | 15.243460 | 53.890720 |
| Minimum µs | 3.148000 | 2.476000 | 6.739000 |
| Maximum µs | 79.821000 | 19.182000 | 68.987000 |
| Population SD µs | 7.281624 | 2.952506 | 9.240840 |
| Measured / cohort warmup calls | 200 / 100 | 200 / 100 | 200 / 100 |
| Complete-chain mismatches / failures | 0 / 0 | 0 / 0 | 0 / 0 |

All **1,516 intended test-run calls passed their applicable checks**:
**900** cohort complete chains, **nine** complete-chain repeat checks,
**600** deliberately stage-isolated XDP calls and **seven** intentional
partial/early-stop controls. The 607 diagnostic calls are not successful
classifications and do not enter the whole-chain timing distributions.
The two TC modes each showed six stage-counter increments on every call.
Original XDP complete execution was established using the qualified final-state
witness and verified linear graph, not invented stage-entry counters.

The isolated XDP phase executed all six original programs for each pilot row:
**600 intermediate tensors / 13,600 meaningful neural integers** matched the
independent new-model reference. The **303** original-XDP complete-chain calls
(including repeat guards) each matched the entire final 64-int workspace:
**19,392** final workspace integers, containing logits, retained ReLU0 values and
ReLU1 values. Overwritten linear/normalized tensors were not claimed as
separately observed in those complete-chain calls. Each of the five missing-tail
controls stopped at exactly its predicted prefix; missing flow/model controls
also failed completion. Repetition nonces showed fresh state, not cached output.

A saved-artifact independent audit recomputed expected model tensors, checked
actual context/flow ports and IDs, checked recorded order/counts/unique nonces,
and reproduced every pooled and per-trial statistic with NumPy 2.2.6.
All outliers were retained. No new privileged execution occurred during review.

One actual saved example, original dataset row **65**:

```text
features                    [912, 1006582042, 32, 22, 680, 21]
expected normalized Q16     [49296, -26865, -4519, -18361, -14904, -14911]
kernel isolated normalized  [49296, -26865, -4519, -18361, -14904, -14911]
expected final logits       [29666, -62551]
kernel complete-chain logits[29666, -62551]
class derived by original rule: 0
```

Original trace-label messages were not consumed. Logits and buffers above were
read from the actual kernel map; the class uses the unchanged original tie-to-1
rule. No synthetic event is represented as kernel evidence.

| Actual pilot objects | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | --- | --- | --- |
| Loaded program IDs | 138; 140–145 | 149–156 | 160–167 |
| Six inference target IDs, slots 0–5 | 140–145 | 151–156 | 162–167 |
| Program type | 6 (XDP) | 3 (SCHED_CLS) | 3 (SCHED_CLS) |
| Private map IDs | 70, 71, 72, 73, 75 | 77–84 | 85–93 |
| Parameter bytes per slot / slots verified | 5,216 / 2 | 5,216 / 2 | 5,304 / 2 |
| Accepted program verifier logs | 7 | 8 | 8 |
| All recorded owned IDs absent after exit | PASS | PASS | PASS |

All 23 program verifier logs contain acceptance summaries; controller error
logs are empty. The packed model, checkpoint, calibration and prepared manifest
hashes match the frozen preparation. No interface or tracing attachment, pin,
namespace or networking configuration change occurred. Cleanup closed only owned
objects and verified absence of their 23 program and 22 map IDs.

These pilot values are not pooled with earlier TC-only measurements. In this
session both TC timings are higher than in the earlier TC-only session; trial
means also decrease from trial 1 to trial 2. This shows sensitivity to session
conditions despite warmup and CPU affinity. No causal explanation or pure
XDP-versus-TC hook speedup is inferred. The final full-cohort comparison above uses only the newly paired three-mode
measurements, not the historical TC values.

[Actual pilot results](experiments/xdp_final_20261108/run/ready-r3/pilot-20261108-154112-127986/results.json),
[raw timings and map readbacks](experiments/xdp_final_20261108/run/ready-r3/pilot-20261108-154112-127986/measurements.jsonl.gz),
[driver replay audit](experiments/xdp_final_20261108/run/ready-r3/pilot-20261108-154112-127986/audit.json),
[independent numerical/statistics/identity review](experiments/xdp_final_20261108/PILOT_VERIFIED.json),
[independent audit command output](experiments/xdp_final_20261108/pilot-independent-audit.log),
[pilot timing CSV](experiments/xdp_final_20261108/run/pilot-reviewed/per-vector-timings.csv),
[pilot per-trial CSV](experiments/xdp_final_20261108/run/pilot-reviewed/per-trial-summary.csv),
[XDP verifier logs and cleanup](experiments/xdp_final_20261108/run/ready-r3/pilot-20261108-154112-127986/xdp_q16),
[TC Q16 verifier logs and cleanup](experiments/xdp_final_20261108/run/ready-r3/pilot-20261108-154112-127986/static_q16),
[TC layer verifier logs and cleanup](experiments/xdp_final_20261108/run/ready-r3/pilot-20261108-154112-127986/layer_specific).

The pilot correctness gate was satisfied before the separately approved full run.

## Full-run protocol and numerical evidence

Every mode received exactly the same frozen test IDs and six-feature vectors.
One whole-cohort warmup pass preceded five measured trials. The first mode
rotated by `(position + trial) % 3` for each vector. All controllers ran on CPU 0.
Each invocation used `repeat=1`, flags 0; no large kernel repeat or amortization
was used. Map deletion/reseeding, poison/nonce checks, userspace validation,
IPC and syscall wall time were outside the reported kernel duration. Three
additional calls per mode verified repeated fresh execution.

The full run contains **42,390 measured + 8,478 warmup + 9 repetition calls**.
All 50,877 completed their chains. The CSV has 50,868 cohort records; three raw
guard blocks represent nine calls. No stage-isolated or partial-control timing
is included in these distributions. Pilot diagnostics remain separate.

Original XDP matched all 64 final workspace integers for **16,959 calls**:
**1,085,376 integer comparisons**. These are two logits, 30 retained input-ReLU
values and 32 hidden-ReLU values. Overwritten normalization/linear tensors were
checked in the pilot, not separately observed in the full-chain runs. Every
full-call state passed the cohort-specific completion witness described above.

TC checked all six tensors and six stage-counter increments per invocation.
Across both TC modes the C drivers checked **203,508 stage tensors / 4,612,848
integers**. Raw snapshots retain 203,484 tensors / 4,612,304 integers because
each three-call guard saves its final snapshot; the C driver checked all three.

XDP and TC Q16 logits are bit-identical for every vector and repetition. The
layer-specific results match their own reference exactly; the maximum final
logit difference from Q16 is **65 Q16 units (65/65,536)**, with **zero class
changes**. No invalid arithmetic, range rejection or inference failure was
observed. Ties use the original class-1 rule; no ties occurred in this cohort.

Unique kernel-derived predictions reproduce the previous held-out confusion
counts for all modes: **TP=1,984, FP=9, TN=829, FN=4**, accuracy 0.9953998585,
F1 0.9967344888. Independent calculations and scikit-learn agree. This counts
2,826 unique rows rather than five repetitions and remains a within-dataset
supplied-label result, not external CIC or live-network detection accuracy.

## Trial variation and historical measurements

| Trial mean, µs (2,826 measured calls per cell) | XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| 1 | 5.153634 | 4.441212 | 12.930038 |
| 2 | 4.739227 | 3.324788 | 12.540740 |
| 3 | 4.999739 | 3.282864 | 12.346987 |
| 4 | 5.659207 | 3.611412 | 13.570288 |
| 5 | 5.153910 | 3.518108 | 12.843679 |

All tails remain: XDP had eight measurements above 100 µs, including one above
1 ms; TC Q16 had one above 100 µs, also above 1 ms; layer-specific had 21 above
100 µs and none above 1 ms. TC's 2.522204 ms maximum explains its large population
SD. The evidence does not identify the cause of each outlier. Affinity controls
CPU placement but not WSL2 scheduling, CPU frequency, thermal state, interrupts
or host load. These are descriptive session measurements, not hard real-time
bounds or independent-row confidence intervals.

![All measured durations](experiments/xdp_final_20261108/run/full-final/latency-ecdf.png)

![Per-trial means](experiments/xdp_final_20261108/run/full-final/latency-trials.png)

The preserved earlier TC-only means were **2.261666 / 7.127888 µs**, medians
1.623000 / 5.536000 µs, p95 4.099000 / 13.490550 µs and p99 7.469560 /
23.271590 µs. They are historical results, **not reused in the paired table**.
Both TC modes were rerun alongside XDP to share session conditions and tuple
preparation. Cross-session differences cannot be attributed solely to a hook
or arithmetic change. [Preserved fresh-model report](FRESH_MODEL_EVALUATION.md).

The original-checkpoint 13,844-row measurements and historical XDP limitations
remain unchanged in [KERNEL_13844_LATENCY_REPORT.md](KERNEL_13844_LATENCY_REPORT.md).
This report's XDP result applies to the newly trained checkpoint and its
certified 2,826-vector cohort.

## Environment, frozen identity and cleanup

Kernel `6.6.87.2-microsoft-standard-WSL2`, x86_64, Intel Core i7-1255U;
allowed CPUs 0–11, controllers pinned to CPU 0. Python 3.10.12;
Ubuntu clang 12.0.1-19ubuntu3; BPF flags `-g -O3 -target bpf -mcpu=v3`;
userspace drivers `-O2 -g -Wall -Wextra`; linked libbpf 1.3; bpftool 7.3.0.
Independent analysis used NumPy 2.2.6, Matplotlib 3.10.3, scikit-learn 1.7.2.
No global CPU or tracing configuration was changed.

Base commit `73868b101d1c1f5e27c6f71eceaa78a645368445`, branch
`feature/cic-external-evaluation`. New experimental files remain uncommitted;
the manifest binds the actual source/object/input artifacts, rather than implying
the base commit alone contains them. No commit or push was made.

| Frozen artifact | SHA256 |
| --- | --- |
| Fresh checkpoint NPZ | `d299f964ecaa7b918eca65529371dbfa6db8797df97ee24b73a324ab52acef1b` |
| Fresh Q16 parameter header | `e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391` |
| Actual packed Q16 parameters, 5,216 bytes | `1558c438e06600d8e3a5eeb28fe23c6aed94cb693a75dea4817497add71bd8d9` |
| Frozen calibration JSON | `658d047585a57a5b52d10d71885244bb423e0040071931c7d3452ad0b92eed2a` |
| Packed layer-specific parameters, 5,304 bytes | `1db06f441987ef7eb282b5954f158fbe861a74bf59bdcbf7988c7ec5c7e2357f` |
| Reproduction features NPY | `787a3bf845a5714f79c27aafceaa6feeb59ec53a405035d2ebe64775a3dcb96e` |
| Reproduction labels NPY | `edbbc05ed553442139c0ddd7b8211aa8aa98347c7b8d3d2e3e7a0f72463d1924` |
| Prepared source/object/input manifest | `9b2b863e347cd7d4f964a64c032e5f8f7e165ede20111987f8a30544f2050847` |
| Full raw measurements JSONL.GZ | `e61092fb3606fc805c093227ff6bf72f8847956525fb656e5e5be7109bec5d4b` |
| Full results JSON | `5d013ce228b88f9fb1b8e0da0e4a15b9ca356c3a23f1a4dc72f28ba32426c9a3` |

The original fresh split (13,187 / 2,827 / 2,826), train-fitted scaler and
train-only calibration were reused unchanged. The XDP driver populated and
byte-read back both private parameter slots; active slot 0 was checked. It used
**the new experimental weights**, not the authors' old pretrained checkpoint.

| Actual full-run resources | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | --- | --- | --- |
| Loaded program IDs | 174; 176–181 | 185–192 | 196–203 |
| Inference target IDs, slots 0–5 | 176–181 | 187–192 | 198–203 |
| BPF target type | 6 (XDP) | 3 (SCHED_CLS) | 3 (SCHED_CLS) |
| Owned map IDs | 95–98; 100 | 102–109 | 110–118 |
| Verifier acceptance | PASS, seven logs | PASS, eight logs | PASS, eight logs |
| All owned IDs absent afterward | PASS | PASS | PASS |

All 23 program verifier logs contain acceptance summaries; controller error
logs are empty. All recorded 23 program and 22 map IDs were absent after object
closure. Maps were private and unpinned. No interface, TC/XDP attachment,
tracing attachment, namespace, address, route or firewall change occurred.
Normal original-XDP trace writes were retained. Hash verification confirmed
**547 pre-existing files unchanged**, including production sources, fresh-model
artifacts, earlier reports and raw results.

| Evidence level | Status |
| --- | --- |
| Twelve mathematical/protocol host tests | PASS; mock events are not kernel evidence |
| Original XDP BPF / experimental userspace compilation | PASS |
| Source/ELF linear tail graph | PASS |
| Actual kernel verifier acceptance | PASS, 23 programs |
| Pilot stage, negative-control and repetition checks | PASS |
| Full kernel execution / numerical parity / cleanup | PASS |
| Independent raw-record and NumPy statistics replay | PASS |
| TC/XDP hook attachment / live packet processing in this benchmark | NOT RUN |
| Native VM / two-laptop performance in this benchmark | NOT RUN |

## Exact commands and saved evidence

From `/home/arnav/research/ebpf-ids-research`, the host checks and preparation
were executed before the operator-approved pilot:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 experiments/xdp_final_20261108/test_harness.py
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 experiments/xdp_final_20261108/run.py \
  --prepare experiments/xdp_final_20261108/run/ready-r3
sudo /usr/bin/python3 experiments/xdp_final_20261108/run.py \
  --execute-pilot experiments/xdp_final_20261108/run/ready-r3
```

After independent pilot review and separate approval, the operator executed:

```bash
sudo /usr/bin/python3 experiments/xdp_final_20261108/run.py \
  --execute-full experiments/xdp_final_20261108/run/ready-r3 \
  --pilot-evidence experiments/xdp_final_20261108/run/ready-r3/pilot-20261108-154112-127986
```

Actual full evidence: `experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273/`.
Every execution creates a fresh output directory. Do not overwrite the existing
prepared bundle or measurements. Superseded `ready`/`ready-r2` contain preparation
diagnostics only. No further privileged run is needed to use these results.

The following saved-evidence audits and derived artifacts were then executed
without loading any BPF program:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 experiments/xdp_final_20261108/run.py \
  --audit experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-fresh-20261108/bin/python \
  experiments/xdp_final_20261108/postprocess/audit_saved.py \
  --run experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273 \
  --output experiments/xdp_final_20261108/run/full-reviewed
MPLCONFIGDIR=/tmp/nn-ebpf-final-xdp-plots PYTHONDONTWRITEBYTECODE=1 \
  /tmp/nn-ebpf-fresh-20261108/bin/python \
  experiments/xdp_final_20261108/postprocess/finalize_saved.py \
  --run experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273 \
  --review experiments/xdp_final_20261108/run/full-reviewed \
  --output experiments/xdp_final_20261108/run/full-final
```

To repeat postprocessing, use new `--output` directory names; both scripts refuse
to overwrite previous outputs. The temporary Python environment is local tooling,
not a committed dependency. Recreate Python 3.10 with the recorded library
versions if it is unavailable. The commands above describe actual executions;
rebuilding preparation requires a new bundle path.

- [Full raw timings, tensors and map states](experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273/measurements.jsonl.gz).
- [Full results, environment and resource IDs](experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273/results.json).
- [Driver audit](experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273/audit.json), [independent full review](experiments/xdp_final_20261108/FULL_VERIFIED.json).
- [Per-vector timing CSV, warmups labeled](experiments/xdp_final_20261108/run/full-reviewed/per-vector-timings.csv), [all per-trial statistics](experiments/xdp_final_20261108/run/full-reviewed/per-trial-summary.csv).
- [Ratios, tails and unique-row kernel prediction checks](experiments/xdp_final_20261108/run/full-final/summary.json).
- [Summary PDF](experiments/xdp_final_20261108/run/full-final/latency-summary.pdf), [distribution PDF](experiments/xdp_final_20261108/run/full-final/latency-ecdf.pdf), [trial PDF](experiments/xdp_final_20261108/run/full-final/latency-trials.pdf).
- [Full XDP verifier logs / cleanup](experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273/xdp_q16), [TC Q16 logs / cleanup](experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273/static_q16), [TC layer logs / cleanup](experiments/xdp_final_20261108/run/ready-r3/full-20261108-155216-966273/layer_specific).
- [Orchestrator](experiments/xdp_final_20261108/run.py), [userspace XDP driver](experiments/xdp_final_20261108/xdp_runner.c), [manifest](experiments/xdp_final_20261108/run/ready-r3/manifest.json), [graph audit](experiments/xdp_final_20261108/run/ready-r3/graph-audit.json), [preservation hashes](experiments/xdp_final_20261108/preservation-before.json), [host-test output](experiments/xdp_final_20261108/tests-final.log).

The benchmark is complete for this checkpoint and frozen cohort. It establishes
numerical agreement and the recorded cost of three actual kernel inference-stage
implementations. The working demonstration and all earlier results remain
available unchanged.
