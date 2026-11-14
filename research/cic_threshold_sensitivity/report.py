"""Audit saved decisions and report a separately labeled sensitivity study."""
import csv
import gzip
import json
import os
from pathlib import Path
import numpy as np

from research.cic_csv_mlp.common import ROOT,read,write,sha,verify_hashes,archive
from research.cic_csv_mlp.metrics import classification
from .study import MODES,HERE,selector_code
from .core import sigmoid


def audit(out):
    verify_hashes(out,'THRESHOLDS_FROZEN.json');verify_hashes(out,'RESULTS_FROZEN.json')
    assert read(out/'selector_code.json')==selector_code()
    thresholds=read(out/'thresholds.json');result=read(out/'results.json')
    assert result['threshold_freeze_sha256']==sha(out/'THRESHOLDS_FROZEN.json')
    assert result['threshold_application_count_per_model']==1 and not result['threshold_selection_used_test_labels']
    for name,expected in read(out/'source_snapshot.json').items():assert sha(ROOT/name)==expected,name
    for phase in ('validation','test'):
        d=archive(out/(phase+'_decisions.npz'))
        for mode in MODES:
            t=float.fromhex(thresholds['models'][mode]['threshold_hex']);score=d[mode+'_margin']
            # Check saved decisions and counts, not another search/application
            # on the original test predictions.
            assert np.all((d[mode+'_selected']==1)==(score>=t))
            assert np.all((d[mode+'_argmax']==1)==(score>0))
            assert len(set(d['indices'].tolist()))==len(d['indices'])
            for rule,key in [('argmax','validation_argmax'),('selected','validation_selected')]:
                actual=classification(d['truth'],d[mode+'_'+rule],score)
                expected=thresholds['models'][mode][key] if phase=='validation' else result['models'][mode]['argmax' if rule=='argmax' else 'validation_selected_threshold']
                assert actual==expected,(phase,mode,rule)
    d=archive(out/'test_decisions.npz')
    with gzip.open(out/'test_decisions.csv.gz','rt',newline='') as f:
        n=0
        for i,row in enumerate(csv.DictReader(f)):
            assert int(row['array_index'])==d['indices'][i] and int(row['source_line'])==d['source_lines'][i]
            assert int(row['truth'])==d['truth'][i] and int(row['group_id'])==d['group_id'][i]
            for mode in MODES:
                assert float(row[mode+'_margin'])==d[mode+'_margin'][i]
                for rule in ('argmax','selected'):assert int(row[mode+'_'+rule])==d[mode+'_'+rule][i]
            n+=1
        assert n==len(d['truth'])
    # Independently retain the earlier demo preservation contract too.
    old=read(ROOT/'research/bidirectional_mlp/evidence/preservation-before.json');base=Path(old['root'])
    for name,h in old['files'].items():assert sha(base/name)==h,name
    outcome=dict(status='PASS',validation_rows=thresholds['validation_count'],test_rows=n,
        original_study_files_unchanged=len(read(out/'source_snapshot.json')),main_checkout_files_unchanged=len(old['files']),
        selected_thresholds_still_frozen=True,saved_decisions_counts_csv_and_sklearn_metrics='PASS',
        threshold_search_used_test_labels=False,selected_threshold_test_applications_per_model=1,
        models_retrained=0,new_neural_inference_executions=0,kernel_or_network_operations='NONE')
    target=out/'audit.json'
    if target.exists():assert read(target)==outcome
    else:write(target,outcome)
    print(json.dumps(outcome,indent=2))


def figures(out,thresholds,result):
    os.environ.setdefault('MPLCONFIGDIR','/tmp/nn-ebpf-cic-bidir-mpl')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':11,'axes.spines.top':False,'axes.spines.right':False,'savefig.bbox':'tight'})
    dest=out/'figures';dest.mkdir(exist_ok=True)
    def save(fig,name):
        for ext in ('png','pdf'):fig.savefig(dest/(name+'.'+ext),dpi=250)
        plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(11,4.2),sharey=True,layout='constrained')
    for ax,mode in zip(axes,MODES):
        c=archive(out/(mode+'-validation-curve.npz'));chosen=thresholds['models'][mode]
        ax.plot(sigmoid(c['threshold']),c['f1'],color='#087F8C',label='Validation F1')
        ax.axvline(.5,color='#596579',linestyle='--',label='Argmax boundary')
        ax.axvline(chosen['softmax_threshold_display'],color='#CB6726',linestyle=':',label='Validation-selected')
        ax.scatter([chosen['softmax_threshold_display']],[chosen['validation_selected']['f1']],color='#CB6726',zorder=3)
        ax.set(title=mode.capitalize(),xlabel='Softmax intrusion score cutoff (display)',ylabel='Validation binary F1',xlim=(0,1),ylim=(0,1.04))
        ax.grid(alpha=.15);ax.legend(fontsize=9,loc='lower right')
    fig.suptitle('Threshold search uses validation labels only');save(fig,'validation_f1_threshold')
    fig,axes=plt.subplots(2,2,figsize=(11,7),sharey=True,layout='constrained')
    for i,phase in enumerate(('validation','test')):
        d=archive(out/(phase+'_decisions.npz'))
        for j,mode in enumerate(MODES):
            ax=axes[i,j];score=d[mode+'_margin'];y=d['truth']
            for label,color,name in [(0,'#356DA8','Benign'),(1,'#BC463B','Intrusion')]:
                values=np.sort(score[y==label]);ax.step(values,np.arange(1,len(values)+1)/len(values),where='post',color=color,label=name)
            ax.axvline(0,color='#596579',linestyle='--',label='Argmax = 0')
            ax.axvline(thresholds['models'][mode]['threshold'],color='#28834F',linestyle=':',label='Selected cutoff')
            ax.set(xscale='symlog',xlabel='Logit margin (symmetric log scale)',ylabel='Class cumulative fraction',title=phase.capitalize()+' / '+mode)
            ax.grid(alpha=.15)
            if i==0 and j==0:ax.legend(fontsize=8,loc='lower right')
    fig.suptitle('Frozen class-score distributions · no test cutoff search');save(fig,'margin_distributions')


def report(out):
    assert read(out/'audit.json')['status']=='PASS'
    selected=read(out/'thresholds.json');result=read(out/'results.json')
    figures(out,selected,result)
    rows=[];validation=[];distribution=[]
    def pct(v):return f'{100*v:.4f}%' if v is not None else 'undefined'
    for mode in MODES:
        q=selected['models'][mode];v=q['validation_selected'];before=q['validation_argmax']
        validation.append(f"| {mode} | `{q['threshold']:.17g}` | {q['softmax_threshold_display']:.9f} | {pct(before['f1'])} | {pct(v['precision'])} | {pct(v['recall'])} | {pct(v['f1'])} | {v['TP']}/{v['FP']}/{v['TN']}/{v['FN']} |")
        r=result['models'][mode]
        for rule in ('argmax','validation_selected_threshold'):
            m=r[rule];rows.append(f"| {mode} | {'Original argmax' if rule=='argmax' else 'Validation F1 cutoff'} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['f1'])} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} |")
        for phase,stats in [('Validation',q['validation_score_distribution']),('Test',r['test_score_distribution'])]:
            for label in ('0','1'):
                p=stats[label]['margin_percentiles']
                distribution.append(f"| {phase} | {mode} | {'Benign' if label=='0' else 'Intrusion'} | {stats[label]['count']} | {p['5']:.6g} | {p['50']:.6g} | {p['95']:.6g} | {stats[label]['softmax_percentiles']['50']:.6g} |")
    a=result['models']['forward'];b=result['models']['bidirectional']
    am=a['validation_selected_threshold'];bm=b['validation_selected_threshold'];oldb=b['argmax']
    gap=result['paired_selected_thresholds']['f1_B_minus_A_percentage_points']
    interval=result['paired_selected_thresholds']['bootstrap']['percentage_point_95_percentile']
    interval_statement=('This conditional interval includes zero; it does not resolve a clear F1 advantage.'
        if interval[0]<=0<=interval[1] else 'This conditional interval excludes zero, subject to the grouping and post-hoc limitations below.')
    ranking=[]
    for mode in MODES:
        for phase,stats,metrics in [('Validation',selected['models'][mode]['validation_score_distribution'],selected['models'][mode]['validation_selected']),
                                    ('Test',result['models'][mode]['test_score_distribution'],result['models'][mode]['validation_selected_threshold'])]:
            ranking.append(f"| {phase} | {mode} | {stats['roc_auc']:.8f} | {metrics['average_precision']:.8f} |")
    categories=[]
    for category in ('FTP-Patator','SSH-Patator'):
        parts=[]
        for mode in MODES:
            stats=result['per_category'][mode][category]
            parts.extend([str(stats['argmax']['support']['1']),pct(stats['argmax']['recall']),pct(stats['selected']['recall'])])
        categories.append('| '+category+' | '+' | '.join(parts)+' |')
    recovery=b['changes']['fraction_original_FN_recovered']
    operational=(f"Changing only the cutoff recovers **{b['changes']['original_false_negatives_recovered']} / {oldb['FN']}** "
                 f"({100*recovery:.2f}%) original bidirectional false negatives. "
                 f"It introduces {b['changes']['additional_false_positives']} additional false positives and loses "
                 f"{b['changes']['original_true_positives_lost']} original true positives.")
    cause=('The default decision boundary explains most of the original low recall on this cohort: most missed positives are recoverable without changing weights or ranking.'
           if recovery>.5 else 'Threshold adjustment explains part of the low recall, but does not recover most original missed positives.')
    prefix=out.relative_to(ROOT).as_posix()
    text=f'''# Validation-threshold sensitivity: frozen CICFlowMeter MLPs

9 November 2026. **Separate, post-hoc analysis; the original argmax comparison
is preserved unchanged.** This is offline analysis of saved FP32 logits.
No model, scaler, split, test record, eBPF program or live demonstration changed.

## Main finding

Bidirectional recall changes from **{pct(oldb['recall'])} to {pct(bm['recall'])}**;
F1 changes from **{pct(oldb['f1'])} to {pct(bm['f1'])}**, or
**{b['f1_change_percentage_points']:+.4f} percentage points**.
{operational}

{cause}
This identifies an operating-point effect, not why training placed the boundary
there, nor proof that all remaining errors have the same cause.

The fair comparison also tunes the forward model by the same validation-only
objective: its F1 becomes **{pct(am['f1'])}**, versus **{pct(bm['f1'])}** for
bidirectional. Thus B−A is **{gap:+.4f} percentage points** after both cutoffs
are selected. The conditional group-bootstrap 95% interval is
**[{interval[0]:+.4f}, {interval[1]:+.4f}] pp**. These exact values, together with
the precision/recall trade-off below, define how competitive the two models are
on this reused cohort; they do not establish campaign-level generalization.
{interval_statement}
Compared with its original operating point, B is much more competitive, but
its adjusted test precision is **{pct(bm['precision'])}** versus
**{pct(am['precision'])}** for A, and false positives are **{bm['FP']} versus
{am['FP']}**. Its recall is **{pct(bm['recall'])}** versus **{pct(am['recall'])}**.
The smaller F1 gap is not evidence of bidirectional superiority.

## Predeclared validation-only objective and tie handling

Use margin **m = float64(logit1) − float64(logit0)** from saved FP32 logits.
The original argmax predicts intrusion iff **m > 0**; equal logits select benign.
The new rule predicts intrusion iff **m >= t**. For each model separately,
maximize ordinary binary intrusion **validation F1 = 2TP/(2TP+FP+FN)**.

Candidate cutoffs are every distinct validation margin, moving all equal-score
rows together, plus a finite cutoff just above the maximum (all-negative rule).
Compare F1 ratios using integer cross-products. On exact F1 ties prefer fewer
FP, then the largest cutoff. No subgroup-specific cutoffs, class balancing,
test-score candidates or test-label optimization are used. Sigmoid(m) is shown
as a softmax-score cutoff for interpretation only; scores are not claimed to
be calibrated attack probabilities. Optimization and application use margins
to avoid softmax saturation or rounding changing tied-score groups.
Argmax remains the valid original decision rule; changing the operating
criterion is not an arithmetic bug fix or a fitted probability calibrator.

Selection reads **{selected['validation_count']:,} validation labels**:
{selected['validation_support']['0']:,} benign and {selected['validation_support']['1']:,}
intrusion. Original checkpoint selection already used this validation set;
threshold selection adds another validation-dependent decision.
Both thresholds, their hexadecimal float64 representations, protocol, source
preservation hashes, full validation curves and decisions were frozen in
`THRESHOLDS_FROZEN.json` before test predictions were parsed. Its SHA256 is
`{result['threshold_freeze_sha256']}`.

| Model | Margin cutoff t | Softmax cutoff (display) | Validation argmax F1 | Selected precision | Selected recall | Selected F1 | TP/FP/TN/FN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
{chr(10).join(validation)}

![Validation-only F1 search]({prefix}/figures/validation_f1_threshold.png)

## Frozen test application

Apply the stored cutoffs once to the same **{result['test_count']:,}** saved test
rows: {result['test_support']['0']:,} benign / {result['test_support']['1']:,} intrusion.
An exclusive application marker prevents a second evaluation in this output
directory. No neural inference was reexecuted. Original argmax decisions and
metrics match the earlier frozen records exactly. Both rules have 100% coverage;
all saved margins are finite. Auditing the resulting saved decisions does not
constitute a new cutoff search or operating-point evaluation.

| Model | Rule | Precision | Recall | F1 | TP | FP | TN | FN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(rows)}

The original matrices and results remain in the original experiment. Every new
decision is separately exported to `test_decisions.csv.gz` and numeric NPZ,
including stable source-member/line IDs, class, group, margin and both decisions.
All metrics can be recomputed from those records. No row is omitted or relabeled.

| Attack | A support | A argmax recall | A selected recall | B support | B argmax recall | B selected recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(categories)}

## Score separation and boundary position

Threshold changes leave every logit, score ordering, ROC-AUC and average precision
unchanged. A high ranking score can coexist with poor recall at a zero-margin
decision. The following quantiles show whether intrusion scores lie below that
boundary despite being separated from many benign scores. Complete min/max,
mean, SD, 1/5/25/50/75/95/99 percentiles and boundary counts are saved in JSON.

| Phase | Model | Class | Count | Margin p5 | Margin median | Margin p95 | Softmax median |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(distribution)}

| Phase | Model | ROC-AUC | Average precision |
| --- | --- | ---: | ---: |
{chr(10).join(ranking)}

![Frozen margin distributions]({prefix}/figures/margin_distributions.png)

Plots retain the complete margin range using a symmetric-log x-axis. Test
distributions are descriptive after the cutoffs are fixed. **There is no test
F1-versus-threshold sweep.** Score separation is not independent validation of
the source labels or evidence of live-network detection effectiveness.

## Limitations and interpretation

- This study was requested **after the original test results were known**.
  Cutoffs use validation labels only, but the test set is being reused for a
  post-hoc question. It is not a new confirmatory or independently untouched test.
- Both thresholds optimize the particular validation prevalence and F1 cost
  trade-off. Recall improvements can increase false positives; another traffic
  prevalence or operating cost need not favor these cutoffs.
- The same within-Tuesday split limitations apply: correlated campaigns, service-
  port shortcuts, proxy grouping, a large training component, only 60 validation
  and 61 test SSH-Patator rows, and one training seed. The original port-only
  baseline remains relevant.
- The optional interval resamples whole original test union-components, with
  paired draws for both selected-threshold models (2,000 draws, seed 20261111).
  It is conditional on fixed fitted models/cutoffs; residual campaign correlation,
  training variance and validation-threshold selection uncertainty are not
  captured. It is not an attack-campaign-independent significance claim.
- This does not establish that aggregating egress features improves the deployed
  model. CICFlowMeter feature/window semantics still differ from the kernel.
  No threshold was installed in the live IDS, and the original comparison is
  not replaced by the more favorable operating point.

## Reproducibility and preservation

Artifacts are under `{prefix}/`. `thresholds.json` records validation outcomes
and exact cutoffs; `results.json` records both original and adjusted test metrics,
score summaries and category counts. Saved decisions, curves, source hashes,
threshold/result freezes and `audit.json` provide the evidence chain.
The selection process is separate from test application; its input list and
`test_arrays_parsed: false` are saved. Tests include a guard that fails if the
selector attempts to parse any test archive, exact-rational brute-force checks,
equal-score blocks, equality rules, nonfinite input rejection and the one-time
application marker. No optimizer, checkpoint loader or training routine is used.

From the existing `feature/bidirectional-mlp` worktree:

```bash
PY=/tmp/nn-ebpf-cic-bidir-20261109/bin/python
export PYTHONDONTWRITEBYTECODE=1
export MPLCONFIGDIR=/tmp/nn-ebpf-cic-bidir-mpl
"$PY" -B -m unittest -v research.cic_threshold_sensitivity.test_sensitivity

# Use a NEW directory for a deliberate reproduction; do not rerun evaluate
# in the completed measured directory.
OUT=research/cic_threshold_sensitivity/run-reproduction
"$PY" -B -m research.cic_threshold_sensitivity.study select \\
  --source research/cic_csv_mlp/run --output "$OUT"
"$PY" -B -m research.cic_threshold_sensitivity.study evaluate --output "$OUT"
"$PY" -B -m research.cic_threshold_sensitivity.study audit --output "$OUT"
"$PY" -B -m research.cic_threshold_sensitivity.study report --output "$OUT"
```

The measured run used `OUT={prefix}`. Audit/report commands read saved decisions
and may be rerun without applying thresholds again. The existing experiment's
dependency versions are reused; no new package or dataset download was required.
New files are confined to `research/cic_threshold_sensitivity/` and this report.
Original sources, weights, scalers, split, predictions, reports and live demo
remain unchanged. No Git commit or push was performed.
'''
    root=ROOT/'CIC_VALIDATION_THRESHOLD_SENSITIVITY.md';local=out/'REPORT.md'
    if not root.exists():root.write_text(text)
    elif root.read_text()!=text:print('Preserving existing root report; new run report is saved locally.')
    local_text=text.replace(']('+prefix+'/','](')
    if local.exists():assert local.read_text()==local_text
    else:local.write_text(local_text)
    print('Report:',root)
