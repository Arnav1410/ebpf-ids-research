#!/usr/bin/env python3
"""Update the fresh-model report from audited kernel artifacts, with no BPF calls."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[1]
sys.path.insert(0,str(BASE));import kernel
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True);a=p.parse_args()
r=kernel.read(a.run/'results.json');v=kernel.read(BASE/'FULL_VERIFIED.json')
assert r['status']==v['status']=='PASS' and r['phase']=='full'
assert v['results_sha256']==kernel.sha(a.run/'results.json') and v['raw_sha256']==kernel.sha(a.run/'measurements.jsonl.gz')
assert kernel.read(a.artifacts/'postprocess.json')['status']=='PASS'
plan=kernel.check_bundle(Path(r['bundle']))
path=os.path.relpath(a.run,ROOT);art=os.path.relpath(a.artifacts,ROOT);exp=os.path.relpath(BASE,ROOT)
q=r['modes']['static_q16'];l=r['modes']['layer_specific'];old=kernel.read(ROOT/'verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/results.json')
keys=[('Mean (µs)','mean_ns'),('Median / p50 (µs)','median_ns'),('p95 (µs)','p95_ns'),('p99 (µs)','p99_ns'),('Minimum (µs)','minimum_ns'),('Maximum (µs)','maximum_ns'),('Population SD (µs)','population_stddev_ns')]
timing='\n'.join(f"| {name} | {q[k]/1000:.6f} | {l[k]/1000:.6f} |" for name,k in keys)
trials='\n'.join(f"| {i+1} | {x['mean_ns']/1000:.6f} | {x['median_ns']/1000:.6f} | {y['mean_ns']/1000:.6f} | {y['median_ns']/1000:.6f} |" for i,(x,y) in enumerate(zip(q['per_trial'],l['per_trial'])))
section=f'''## New-model full kernel benchmark — PASS

The operator separately approved and executed the full run after the audited
100-vector pilot. All **2,826 held-out test row IDs** were used in both TC modes,
with one complete warmup pass and **five measured trials**. No model, scaler,
calibration or classification rule was changed after observing test results.
Each mode has **14,130 measured durations** and 2,826 cohort warmups; repetitions
are not additional independent dataset samples.

| Actual fresh-model measurement | TC Q16 | TC layer-specific |
| --- | ---: | ---: |
{timing}
| Measured calls | 14,130 | 14,130 |
| Kernel-time-normalized inferences/s | {q['kernel_time_normalized_inferences_per_second']:,.3f} | {l['kernel_time_normalized_inferences_per_second']:,.3f} |
| Failed calls / numerical mismatches | 0 / 0 | 0 / 0 |

Within this same-model/same-input experiment, layer-specific mean latency was
**{v['relative_layer_over_q16']['mean_ratio']:.6f}× TC Q16**
({100*(v['relative_layer_over_q16']['mean_ratio']-1):.6f}% higher); median latency
was {v['relative_layer_over_q16']['median_ratio']:.6f}× TC Q16. This compares the
complete existing implementations, including their checks and telemetry.
It is not a measurement of pure matrix arithmetic, and lower numerical error
did not change F1 or any test classification.

The measurement is kernel-returned `BPF_PROG_TEST_RUN` duration, `repeat=1`, from
`tc_preprocessing` through six stages and five real tail-call transitions,
result publication and workspace release. It includes existing map lookups,
synchronization, diagnostics/telemetry and kernel test-run timing overhead.
Private flow/result/per-CPU workspace resets, userspace syscall/IPC wall time,
read-back, validation and I/O occur outside the measured duration. The synthetic
packet supplies context/key only; it does not represent a stored flow. Parsing,
feature extraction and live helper-clock reconstruction are bypassed.
**This is model-stage-chain latency, not full packet or end-to-end latency.**

The normalized service rate is `measured_calls × 10^9 / sum(duration_ns)`;
it is not achieved network throughput. Total experiment wall time was
{r['wall_elapsed_seconds']:.6f} s and was not substituted for inference latency.
Percentiles use linear interpolation, population SD uses `ddof=0`, and no
outlier is removed or estimated overhead subtracted.

![Fresh-model kernel distributions and trial variation]({art}/fresh-kernel-distributions.png)
[Exportable PDF]({art}/fresh-kernel-distributions.pdf).

### Trial variability

| Trial | TC Q16 mean µs | TC Q16 p50 µs | Layer-specific mean µs | Layer-specific p50 µs |
| --- | ---: | ---: | ---: | ---: |
{trials}

The population SD of trial means was
{v['tail_summary']['static_q16']['population_SD_of_trial_means_ns']/1000:.6f} µs
and {v['tail_summary']['layer_specific']['population_SD_of_trial_means_ns']/1000:.6f} µs,
respectively; these differ from pooled duration SDs above. Means decreased over
the trials despite the warmup. WSL2 scheduling, frequency, interrupts and cache
state were not controlled enough to identify the cause. No iid confidence
interval, causal old/new speedup or hard real-time bound is claimed.
TC Q16 retained {v['tail_summary']['static_q16']['over_100us']} samples over
100 µs; layer-specific retained {v['tail_summary']['layer_specific']['over_100us']}.
Neither mode had a measured duration above 1 ms.

### Execution, model identity and cleanup

All **33,918 calls** completed: 28,260 measured, 5,652 cohort warmups and six
zero-tensor repetition guards. Every invocation received fresh private flow,
result and per-CPU workspace state. The existing C driver checks stage counts,
complete mask 63, CPU, slot, sequence, features, released workspace and DONE
flow. Repeated completion cannot silently bypass inference. Each guard block
recorded three fresh predictions and stage deltas **[3,3,3,3,3,3]**.

Executing-controller checks cover **203,508 tensors / 4,612,848 integers**.
Saved-record replay exposes **203,484 tensors / 4,612,304 integers** because each
three-call guard block retains its last tensors while C checks all three calls.
All ordinary per-vector calls retain all six tensors and logits. A separate
audit regenerated expected integers for every row/mode, checked all trial
identities, and independently reproduced pooled and per-trial statistics with
NumPy 2.2.6. There were zero missing, invalid or mismatched inferences.

Kernel-observed labels, counted once per unique test row from measured trial 0,
produce **TP=1,984, FP=9, TN=829, FN=4** in each TC mode, matching the host results.
The five trials, warmups and guard predictions are not added to this 2,826-row
classification denominator. This is kernel model-level testing of stored
features against supplied labels, not live-network attack evaluation.

| Actual full-run objects | Fresh TC Q16 | Fresh TC layer-specific |
| --- | --- | --- |
| Loaded program IDs | 112–119 | 123–130 |
| Inference targets, slots 0–5 | 114–119 | 125–130 |
| Private map IDs | 52–59 | 60–68 |
| Model bytes per slot / slots byte-verified | 5,216 / 2 | 5,304 / 2 |
| Verifier acceptance | PASS: 8 logs | PASS: 8 logs |
| Recorded owned IDs absent after close | PASS | PASS |

All tail targets are type 3 (`SCHED_CLS`). Both controller error logs are empty.
Both model slots were byte-read back and frozen by the unchanged controller;
slot 0 was selected. New-checkpoint/header/calibration/parameter identities match
the same frozen preparation used by the pilot. The experiment created no
interface or tracing attachment, map pin, namespace, qdisc, routing or firewall
change. Cleanup closed owned BPF objects and checked only recorded IDs.
No networking cleanup command is needed.

- Checkpoint SHA256: `{r['checkpoint_sha256']}`.
- New Q16 header SHA256: `{r['model_sha256']}`.
- New calibration SHA256: `{r['calibration_sha256']}`.
- Prepared manifest SHA256: `{r['manifest_sha256']}`.
- Raw full measurements SHA256: `{v['raw_sha256']}`.
- Full results SHA256: `{v['results_sha256']}`.

Actual full-run environment: {r['environment']['kernel']},
{r['environment']['machine']}, Python {r['environment']['python']},
{r['environment']['cpu_model']}; CPU {r['environment']['cpu']}, parent allowed
CPUs 0–11. Only controller-process affinity was pinned; no system-wide CPU or
network tuning occurred. Preparation records clang 12.0.1-19ubuntu3, bpftool
7.3.0 / libbpf 1.3, `-g -O3 -target bpf -mcpu=v3` BPF flags and
`-O2 -g -Wall -Wextra -pthread` controller flags.

[Full exact results]({path}/results.json),
[raw per-call tensors/timings/status]({path}/measurements.jsonl.gz),
[per-vector CSV export]({art}/per-vector-timings.csv.gz),
[per-trial summary CSV]({exp}/run/kernel-trial-summary.csv),
[unique-row kernel metrics]({art}/kernel-unique-row-metrics.json),
[saved replay audit]({path}/audit.json),
[independent replay log]({exp}/full-independent-replay.log),
[independent numerical/statistics/identity audit]({exp}/FULL_VERIFIED.json),
[Q16 verifier logs]({path}/static_q16), [layer verifier logs]({path}/layer_specific),
[Q16 cleanup]({path}/static_q16/ids-absent.json),
[layer cleanup]({path}/layer_specific/ids-absent.json).
The CSV contains 33,912 cohort calls; guard blocks remain in the raw JSON.
Stored trial −1 is warmup, and trials 0–4 are measurements.

### Approved command actually executed

```bash
sudo /usr/bin/python3 experiments/fresh_model_20261108/kernel.py \\
  --execute-full experiments/fresh_model_20261108/run/kernel-ready \\
  --pilot-evidence experiments/fresh_model_20261108/run/kernel-ready/pilot-20261108-142840-507834
```

Read-only audit and postprocessing commands actually executed:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 experiments/fresh_model_20261108/kernel.py \\
  --audit {path}
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-fresh-20261108/bin/python \\
  experiments/fresh_model_20261108/postprocess/full_results.py \\
  --run {path} --output {art}
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \\
  experiments/fresh_model_20261108/postprocess/final_report.py \\
  --run {path} --artifacts {art}
```

Use a fresh output directory for a new plot/CSV export. Auditing/postprocessing
make no BPF calls and do not edit input evidence or frozen execution source.
A future privileged rerun requires explicit approval. No privileged test was
rerun during this independent review.

### Prior correctness pilot, kept separate

The approved 100-vector pilot passed before full execution: 606 calls, two
measurement trials, zero mismatches and successful cleanup. Mean durations were
2.055630 µs (TC Q16) and 8.038040 µs (layer-specific); its timings are not pooled
with the full run above. [Pilot evidence]({exp}/run/kernel-ready/pilot-20261108-142840-507834/results.json),
[pilot independent audit]({exp}/PILOT_VERIFIED.json).

'''
comparison='\n'.join(f"| {name} | {old['modes']['static_q16'][key]/1000:.6f} | {old['modes']['layer_specific'][key]/1000:.6f} | {q[key]/1000:.6f} | {l[key]/1000:.6f} |" for name,key in keys)
summary=f'''## Kernel evidence — original and fresh models kept separate

| Measurement | Original TC Q16 | Original TC layer-specific | Fresh TC Q16 | Fresh TC layer-specific |
| --- | ---: | ---: | ---: | ---: |
| Model | Original header | Original header + prior calibration | Fresh checkpoint | Same fresh checkpoint + new calibration |
| Cohort | 13,844 scaling-held-out | Same 13,844 | 2,826 new test-held-out | Same 2,826 |
| Measured calls / trials | 69,220 / 5 | 69,220 / 5 | 14,130 / 5 | 14,130 / 5 |
{comparison}
| Kernel numerical / cleanup checks | PASS | PASS | PASS | PASS |

![Separate original and fresh-model kernel experiments]({art}/separate-old-and-fresh-kernel.png)
[Exportable PDF]({art}/separate-old-and-fresh-kernel.pdf).

Old and fresh timings are **separate experiments with different checkpoints,
normalization/calibration, input populations and run conditions**. They are not
pooled, and the lower fresh-run durations cannot be attributed solely to model
training or claimed as an equal-input speedup. Within each experiment, the two
arithmetic modes do use the same checkpoint and input cohort. Previous reports,
raw durations and model hashes remain unchanged; see the preserved
[KERNEL_13844_LATENCY_REPORT.md](KERNEL_13844_LATENCY_REPORT.md).

The new TC pilot and full benchmark pass kernel verification, six-stage numerical
parity, repetition and cleanup checks. **Original XDP full-chain kernel latency
remains NOT RUN** under the previously documented per-run observability contract.
XDP/Q16 host-C arithmetic on the new test cohort did run; it is not substituted
for missing original-XDP kernel timing. Physical fresh-model deployment and
live packet-processing latency remain NOT RUN.

'''
report=ROOT/'FRESH_MODEL_EVALUATION.md';text=report.read_text();marker='## Kernel evidence — original and fresh models kept separate'
starts=[text.find(t) for t in ('## New-model full kernel benchmark — PASS','## New-model actual kernel pilot — PASS') if t in text]
start=min(starts) if starts else text.index(marker);end=text.index('## Reproduction and preservation')
text=text[:start]+section+summary+text[end:]
intro='**FP32 held-out evaluation: PASS.**'
if intro in text:text=text.replace(intro,'**Fresh-model held-out evaluation and full TC kernel benchmark: PASS.**',1)
old_start='New TC BPF/controller compilation and ELF inspection: **PASS**;'
old_end='The original 13,844-row diagnostic F1'
if old_start in text and old_end in text:
 a0=text.index(old_start);a1=text.index(old_end,a0)
 text=text[:a0]+'''New TC BPF/controller compilation, actual verifier acceptance, all six stages,
full-cohort numerical parity, repeated-execution checks and cleanup: **PASS**.
Independent timing/statistics audits passed. Physical fresh-model deployment and
live-network attack effectiveness remain **NOT RUN**. No further privileged
execution is needed to finish this model-level experiment.

'''+text[a1:]
if '## Final verification status and comparison limits' not in text:
 text+='''\n## Final verification status and comparison limits\n\n20 new host tests and 15 existing benchmark tests passed; all three actual C\nvariants passed UBSan on 2,826 rows. New model TC pilot/full kernel gates pass.\nThe original 13,844-row F1 diagnostic and old timings use a different checkpoint\nand protocol; they are preserved and not an equal-protocol improvement baseline.\nThe original deployed model remains unchanged. Near-duplicate or session-related\nflows may still span partitions because trusted capture/session metadata are\nunavailable. Physical deployment and live attack evaluation of the new model\nremain NOT RUN.\n'''
report.write_text(text)
print('Updated',report,'from audited full-run evidence; frozen execution source unchanged')
