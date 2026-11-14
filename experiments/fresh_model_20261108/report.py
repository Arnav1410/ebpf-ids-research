"""Render only measured fresh-model evidence; never performs training or inference."""
from pathlib import Path
import json
import sys
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pipeline import ROOT,HERE,read,write,sha,preservation


def generate(out):
    frozen=read(out/'freeze.json');fp=read(out/'fp32-metrics.json');split=read(out/'split.json');history=read(out/'history.json')
    configs={'fp32':fp['metrics']}
    comparison=read(out/'comparison.json') if (out/'comparison.json').exists() else None
    if comparison:configs.update({m:s['metrics'] for m,s in comparison['modes'].items()})
    figs=out/'figures';figs.mkdir(exist_ok=True)
    fig,ax=plt.subplots(figsize=(7,4),layout='constrained')
    ax.plot([h['epoch'] for h in history],[h['training_loss'] for h in history],label='Training')
    ax.plot([h['epoch'] for h in history],[h['validation_loss'] for h in history],label='Validation')
    ax.axvline(frozen['selected_epoch'],linestyle=':',color='gray',label='Selected epoch')
    ax.set(xlabel='Epoch',ylabel='Cross-entropy',title='Fresh model: train/validation only');ax.legend()
    fig.savefig(figs/'loss.png',dpi=160);fig.savefig(figs/'loss.pdf');plt.close(fig)
    fig,axes=plt.subplots(1,len(configs),figsize=(4*len(configs),3.8),layout='constrained',squeeze=False)
    for ax,(name,m) in zip(axes[0],configs.items()):
        cm=m['confusion_matrix'];ax.imshow(cm,cmap='Blues');ax.set(xticks=[0,1],yticks=[0,1],xlabel='Predicted',ylabel='Supplied truth',title=name)
        for i in range(2):
            for j in range(2):ax.text(j,i,str(cm[i][j]),ha='center',va='center',color='white' if cm[i][j]>np.max(cm)/2 else 'black')
    fig.savefig(figs/'confusion-matrices.png',dpi=160);fig.savefig(figs/'confusion-matrices.pdf');plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,4),layout='constrained');keys=['accuracy','precision','recall','f1'];xx=np.arange(4)
    for i,(mode,m) in enumerate(configs.items()):ax.bar(xx+(i-(len(configs)-1)/2)*.18,[m[k] for k in keys],width=.17,label=mode)
    ax.set(xticks=xx,xticklabels=keys,ylim=(0,1.07),title='Fresh held-out test: supplied labels');ax.legend(loc='lower right')
    fig.savefig(figs/'classification.png',dpi=160);fig.savefig(figs/'classification.pdf');plt.close(fig)
    if comparison:
        fig,ax=plt.subplots(figsize=(7,4),layout='constrained')
        names=list(comparison['modes']);ax.bar(names,[comparison['modes'][n]['errors_vs_fp32']['logits']['mean_abs'] for n in names])
        ax.set(ylabel='Mean absolute logit error (real units)',title='New integer modes versus frozen FP32 model')
        fig.savefig(figs/'numerical-error.png',dpi=160);fig.savefig(figs/'numerical-error.pdf');plt.close(fig)
    modes=['fp32','xdp_q16','tc_q16','tc_layer_specific']
    keys=['TP','FP','TN','FN','accuracy','precision','recall','f1','specificity','false_positive_rate','balanced_accuracy','mcc','macro_f1','weighted_f1','coverage','invalid_missing']
    fmt=lambda x:'undefined' if x is None else str(x) if isinstance(x,int) else f'{x:.9f}'
    table='\n'.join('| '+k+' | '+' | '.join(fmt(configs[m][k]) if m in configs else 'NOT RUN' for m in modes)+' |' for k in keys)
    split_table='\n'.join(f"| {n} | {v['count']} | {v['support']['0']} | {v['support']['1']} |" for n,v in split['partitions'].items())
    old=read(ROOT/'verification-logs/kernel-13844-20261108/ready-r2/full-20261108-131502-522683/results.json')
    oldrows='\n'.join(f"| {label} | {old['modes']['static_q16'][k]/1000:.6f} | {old['modes']['layer_specific'][k]/1000:.6f} | NOT RUN | NOT RUN |" for label,k in [('Mean µs','mean_ns'),('p50 µs','median_ns'),('p95 µs','p95_ns'),('p99 µs','p99_ns'),('Min µs','minimum_ns'),('Max µs','maximum_ns'),('Population SD µs','population_stddev_ns')])
    relative=os.path.relpath(out,ROOT);fp_m=fp['metrics']
    doc=f'''# Fresh experimental NN-eBPF model — held-out evaluation

**FP32 held-out evaluation: PASS.** This is a newly initialized model, separate
from the deployed checkpoint. The previous model, scaler, calibration, source,
dashboard and original latency experiment remain unchanged. No physical deployment
or network configuration change occurred.

## Dataset and leakage controls

Authors' numeric eBPF-Reproduction arrays: 18,840 rows; 18,561 distinct complete
six-feature vectors; 279 duplicate excess rows. Supplied codes: 0=benign,
1=intrusion. Collection labels are used as given; no trusted capture-day/session
metadata or independently audited attack identities accompany these arrays.

| Partition | Rows | Benign (0) | Intrusion (1) |
| --- | ---: | ---: | ---: |
{split_table}

Seed **20261108**. Exact duplicate vectors are grouped, shuffled separately within
each label, then assigned at nearest cumulative 70%/85% row boundaries. Every row
occurs once; no feature group crosses a partition. This is a group-separated
random within-dataset split, not a held-out capture-day experiment. Seed/split
were frozen before training or observing predictions. The scaler fits training
rows only. Test rows do not select the checkpoint or quantization scales.

[Split manifest]({relative}/split.json), [split gate]({relative}/gate1.json),
[training-only scaler]({relative}/scaler.json), [frozen configuration]({relative}/config.json).
Dataset SHA256: features `{split['dataset']['dataset/reproduction-xdp-data.npy']}`;
labels `{split['dataset']['dataset/reproduction-xdp-label.npy']}`.

## Training and checkpoint

Reuses the authors' `Net` class: bias-free 6→32→32→2, ReLU after each hidden
linear layer, 1,280 parameters, two logits and cross-entropy. CPU Adam, learning
rate 0.001, batch size 512, 32 epochs; no hyperparameter search or test-based
tuning. One CPU thread and deterministic PyTorch algorithms; seed 20261108.
Selected epoch **{frozen['selected_epoch']}**, minimum validation cross-entropy
**{frozen['validation_loss']:.9f}**, earliest exact tie. DataLoader workers=0
is a reproducibility adaptation of the original script. The original script's
full-dataset scaler fit is corrected only in this separate experiment.

Checkpoint is a numeric-only NPZ, loaded with `allow_pickle=False`; neither
untrusted pickle nor the authors' unrestricted `torch.load` path is executed.
All selected weights and FP32 test logits are finite.
Checkpoint SHA256: `{frozen['checkpoint_sha256']}`.
Scaler SHA256: `{frozen['scaler_sha256']}`.
[Training history]({relative}/history.json), [freeze gate]({relative}/freeze.json).

![Training and validation losses]({relative}/figures/loss.png)

## Untouched test results

Every prediction retains its original row ID, six raw values, normalized FP32
values, logits, supplied truth and checkpoint/scaler identifiers. Intrusion is
the positive class. Confusion matrices use `[[TN, FP], [FN, TP]]`. Independent
integer counts/formulas are cross-checked with scikit-learn; saved prediction
records reproduce the metrics. Missing/invalid predictions are abstentions,
never benign. Undefined metrics are null; eligible metrics are conditional on
valid predictions and coverage is reported separately.

| Measurement | FP32 host | XDP Q16 host C | TC Q16 host C | TC layer-specific host C |
| --- | ---: | ---: | ---: | ---: |
{table}

**FP32 accuracy {fp_m['accuracy']:.9f}; precision {fp_m['precision']:.9f};
recall {fp_m['recall']:.9f}; F1 {fp_m['f1']:.9f}.**
These measure the fresh model against supplied labels on rows excluded from our
training/scaler fit/checkpoint selection. They do not establish generalization
to independently captured days, external CIC traffic or live demo connections.

![Held-out confusion matrices]({relative}/figures/confusion-matrices.png)
![Held-out classification metrics]({relative}/figures/classification.png)

[FP32 prediction archive]({relative}/fp32-predictions.jsonl.gz),
[FP32 exact metrics and per-class report]({relative}/fp32-metrics.json).
FP32 retains authors' `argmax` tie→0; integer modes retain kernel tie→1. No
threshold or label mapping was chosen from test results.

## Integer conversion and numerical evidence

'''
    if comparison:
        error_rows='\n'.join(f"| {m} | {v['errors_vs_fp32']['logits']['mean_abs']:.12g} | {v['errors_vs_fp32']['logits']['max_abs']:.12g} | {v['errors_vs_exact_rational_header']['logits']['mean_abs']:.12g} | {v['errors_vs_exact_rational_header']['logits']['max_abs']:.12g} |" for m,v in comparison['modes'].items())
        scaled_rows='\n'.join(f"| {stage} | {v['different_values']} | {v['values']} |" for stage,v in comparison['q16_layer_scaled_tensor_differences'].items())
        doc+=f'''**Host conversion/comparison: PASS**, using the new weights and the same
2,826 test IDs. Actual original XDP arithmetic and TC stages are host-compiled
with existing mocks in an isolated copied source tree; this is not kernel
execution. Only copied model/calibration headers differ; deployed files stay
unchanged. Q16 uses nearest-even weight quantization, rounded int64 scaler,
unsigned-magnitude normalization, int64 products/accumulators, arithmetic >>16
flooring and checked int32 narrowing. No clipping or saturation is added.

Layer-specific scale selection uses training rows only and the existing
conservative selector. Weights remain Q16 representations of this same fresh
FP32 checkpoint; layer-specific mode improves activation precision/rounding,
not weight precision. Unsupported inputs are retained as rejected records.
Every successful C stage is checked against its corresponding independent
Python integer reference. Stage errors versus FP32 use each layer's exponent;
weights/scaler quantization contribute to those errors. Exact-rational Q16
header-network errors are reported separately, rather than calling that model
identical to FP32.

- XDP Q16 ↔ TC Q16 tensor mismatches: **{comparison['q16_tensor_mismatch_rows']}**.
- FP32 ↔ Q16 prediction changes (both valid): **{comparison['fp32_q16_changes']}**.
- Q16 ↔ layer-specific prediction changes (both valid): **{comparison['q16_layer_changes']}**.
- Common-valid test rows: **{comparison['common_valid_count']}** of 2,826.

| Integer mode | Logit MAE vs FP32 | Max abs vs FP32 | MAE vs exact Q16 header | Max abs vs exact Q16 header |
| --- | ---: | ---: | ---: | ---: |
{error_rows}

Errors are in real logit units, over 5,652 test logits. The rounded scaler and
Q16 weights also differ from the FP32 model: layer-specific activation precision
does not recover those discarded values. Its lower mean error does not imply
lower maximum error or improved F1. No test example was removed based on error.
All modes had zero equal-logit ties in this cohort.

| Stage | Q16/layer-specific unequal values at common binary scale | Compared values |
| --- | ---: | ---: |
{scaled_rows}

These cross-scale differences are expected quantization/rounding differences,
not failures of the corresponding C/Python parity checks. Each mode matched
its own integer reference on all {comparison['numerical_comparisons']['stage_tensors']:,}
stage tensors / {comparison['numerical_comparisons']['integers']:,} integers.
The complete per-layer mean/max errors and both-mode rejection reasons are
in the machine-readable comparison. No overflow/narrowing/rejection occurred
on the training calibration rows or test cohort. The UBSan result is recorded
separately as host execution, with no kernel implication.

[Per-row integer predictions/tensors]({relative}/integer-predictions.jsonl.gz),
[comparison, all metrics, errors, failures and common-valid subset]({relative}/comparison.json),
[quantization/calibration gate]({relative}/quantization.json).

![Numerical logit error versus new FP32]({relative}/figures/numerical-error.png)

'''
    else:doc+='Integer conversion and host-C comparisons: **NOT RUN** at this milestone. The completed FP32 result is preserved independently.\n\n'
    doc+=f'''## Kernel evidence — original and fresh models kept separate

| Measurement | Original TC Q16 | Original TC layer-specific | Fresh TC Q16 | Fresh TC layer-specific |
| --- | ---: | ---: | --- | --- |
| Model | Original header | Original header + prior calibration | Fresh checkpoint | Fresh checkpoint + new calibration |
| Cohort | 13,844 scaling-held-out | Same 13,844 | 2,826 new held-out | Same 2,826 |
| Measured calls / trials | 69,220 / 5 | 69,220 / 5 | NOT RUN | NOT RUN |
{oldrows}
| Kernel numerical checks | PASS | PASS | NOT RUN | NOT RUN |

The original results are preserved historical measurements, not fresh-model
timings or an equal-input old-versus-new comparison. Original kernel mean is
4.548055 µs / 15.072869 µs. All long outliers were retained. The existing
[KERNEL_13844_LATENCY_REPORT.md](KERNEL_13844_LATENCY_REPORT.md) remains unchanged.

Fresh-model kernel correctness/latency: **PENDING OPERATOR APPROVAL/EXECUTION**.
No new model kernel load, verifier acceptance, attachment or kernel timing is
claimed. Comparable original XDP full-chain kernel latency remains **NOT RUN**;
no fabricated or interpolated XDP value is supplied. The proposed TC methodology
enters at preprocessing, includes six stages/five tails, existing telemetry and
kernel test-run overhead, and excludes parsing/feature extraction and userspace
syscall wall time. No claim about full packet or network latency follows.

## Reproduction and preservation

From repository root, with CPU PyTorch 2.5.1+cpu, NumPy 2.2.6, scikit-learn 1.7.2
and Matplotlib 3.10.3 in `/tmp/nn-ebpf-fresh-20261108`:

```bash
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-fresh-20261108/bin/python experiments/fresh_model_20261108/test_experiment.py
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-fresh-20261108/bin/python experiments/fresh_model_20261108/pipeline.py prepare --output /tmp/fresh-reproduction
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-fresh-20261108/bin/python experiments/fresh_model_20261108/pipeline.py train --output /tmp/fresh-reproduction
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-fresh-20261108/bin/python experiments/fresh_model_20261108/pipeline.py fp32 --output /tmp/fresh-reproduction
```

The actual executed run uses `{relative}`. Choose a fresh path for reruns;
selected checkpoints and prediction archives are never overwritten. The
[experiment README](experiments/fresh_model_20261108/README.md) records dependency,
integer-conversion, audit and approval-gated kernel commands. Pipeline stages
stop at failed assertions. See retained logs in the experiment directory.

Base commit `{frozen['git_head']}`, branch `feature/cic-external-evaluation`;
new experimental source/artifacts are uncommitted. Isolation uses a separate
directory, preserving all pre-existing uncommitted/untracked work.
Training environment: {frozen['kernel']}, {frozen['machine']}, Python {frozen['python']},
PyTorch {frozen['packages']['torch']}, NumPy {frozen['packages']['numpy']},
scikit-learn {frozen['packages']['sklearn']}; CPU, one thread.
Preservation check: **{preservation()['unchanged_files']} prior files unchanged**,
including original model/normalization/calibration, source/objects/dashboard,
previous reports and raw benchmark measurements. No commit, push or physical
network operation occurred.

## Explanation for the presentation

“We trained a fresh bias-free 6→32→32→2 MLP on 13,187 reproduction samples and
selected its checkpoint using 2,827 validation samples. The scaler used only
training data. We grouped identical six-feature vectors before splitting, so
none crosses into the 2,826-row test partition. The fresh model's held-out F1
against supplied labels is {fp_m['f1']:.6f}. This is a controlled within-dataset
result; unknown capture/session provenance limits claims about new-day attacks.
The original deployed model and its previous kernel measurements were preserved.”
'''
    (ROOT/'FRESH_MODEL_EVALUATION.md').write_text(doc)
    print('Wrote FRESH_MODEL_EVALUATION.md and measured-result figures',flush=True)
