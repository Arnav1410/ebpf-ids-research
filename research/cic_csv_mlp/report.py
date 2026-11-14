"""Read-only saved-result checks, presentation figures and research report."""
from collections import Counter
import csv
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import numpy as np

from .common import ROOT, HERE, archive, read, write, sha, verify_hashes
from .metrics import classification


def audit(out):
    from .pipeline import check_implementation
    from .train import setup,reload_model
    check_implementation(out)
    for name in ('data-freeze.json','split-freeze.json','models-freeze.json'):verify_hashes(out,name)
    verify_hashes(out/'evaluation','freeze.json')
    for mode in ('forward','bidirectional'):verify_hashes(out/mode,'freeze.json')
    full=archive(out/'data.npz');split=archive(out/'split.npz');test=archive(out/'test.npz')
    pred=archive(out/'evaluation/predictions.npz');metrics=read(out/'evaluation/metrics.json')
    with gzip.open(out/'records.jsonl.gz','rt') as f:meta=[json.loads(s) for s in f]
    assert len(meta)==len(full['labels']) and len({r['source_record_id'] for r in meta})==len(meta)
    assert len({r['complete_row_sha256'] for r in meta})==len(meta)
    assert np.array_equal(pred['indices'],split['test']) and np.array_equal(pred['truth'],test['labels'])
    assert np.array_equal(pred['source_lines'],test['source_lines'])
    partition_sets=[set(split[k].tolist()) for k in ('train','validation','test')]
    assert sum(map(len,partition_sets))==len(set.union(*partition_sets))==len(meta)
    group_sets=[set(split['group_id'][split[k]].tolist()) for k in ('train','validation','test')]
    assert all(not group_sets[i]&group_sets[j] for i,j in ((0,1),(0,2),(1,2)))
    for name in ('forward','bidirectional'):
        sets=[{row.tobytes() for row in full[name][split[k]]} for k in ('train','validation','test')]
        assert all(not sets[i]&sets[j] for i,j in ((0,1),(0,2),(1,2)))
    t=setup(read(out/'protocol.json')['seed']);reloads={}
    for mode in ('forward','bidirectional'):
        train=archive(out/'train.npz');val=archive(out/'validation.npz');scaler=archive(out/mode/'scaler.npz')
        assert np.allclose(scaler['mean'],train[mode].astype(np.float64).mean(0),rtol=1e-14,atol=1e-10)
        assert np.allclose(scaler['variance'],train[mode].astype(np.float64).var(0),rtol=1e-13,atol=1e-9)
        history=read(out/mode/'history.json');chosen=min(history,key=lambda x:x['validation_loss'])
        training=read(out/mode/'training.json')
        assert chosen['epoch']==training['best_epoch'] and chosen['validation_loss']==training['best_validation_loss']
        assert len(history)==32 and training['test_used'] is False and training['weights']==1280
        model=reload_model(out/mode/'checkpoint.npz')
        for kind,raw,expected in [('validation',val,archive(out/mode/'validation_logits.npz')['logits']),
                                  ('test',test,pred[mode+'_logits'])]:
            x=((raw[mode].astype(np.float64)-scaler['mean'])/scaler['scale']).astype(np.float32)
            assert np.isfinite(x).all()
            with t.no_grad():actual=model(t.from_numpy(x)).numpy()
            assert np.array_equal(actual,expected),(mode,kind)
            reloads[mode+'_'+kind]=len(x)
        logits=pred[mode+'_logits'];p=logits.argmax(1)
        assert np.array_equal(p,pred[mode+'_prediction'])
        assert np.array_equal(logits[:,1].astype(np.float64)-logits[:,0].astype(np.float64),pred[mode+'_margin'])
        assert classification(pred['truth'],p,pred[mode+'_margin'])==metrics['models'][mode]['metrics']
    with gzip.open(out/'evaluation/predictions.csv.gz','rt',newline='') as f:
        rows=0
        for j,r in enumerate(csv.DictReader(f)):
            i=int(pred['indices'][j]);original=meta[i]
            assert r['source_record_id']==original['source_record_id'] and int(r['source_line'])==original['source_line']
            assert int(r['array_index'])==i and int(r['truth'])==int(full['labels'][i])
            for mode in ('forward','bidirectional'):
                assert [int(r[mode+'_feature_'+str(k)]) for k in range(6)]==full[mode][i].tolist()
                assert [float(r[mode+'_logit'+str(k)]) for k in range(2)]==pred[mode+'_logits'][j].tolist()
                assert r[mode+'_status']=='PASS' and int(r[mode+'_prediction'])==int(pred[mode+'_prediction'][j])
            rows+=1
        assert rows==len(test['indices'])
    a,b=pred['forward_prediction'],pred['bidirectional_prediction'];y=pred['truth']
    assert int((a!=b).sum())==metrics['paired']['disagreements']
    assert int(((a!=y)&(b==y)).sum())==metrics['paired']['corrected']
    assert int(((a==y)&(b!=y)).sum())==metrics['paired']['made_incorrect']
    preservation=read(HERE/'preservation-before.json')
    old=read(ROOT/preservation['main_checkout_manifest']);base=Path(old['root'])
    for name,h in old['files'].items():assert sha(base/name)==h,name
    for name,h in preservation['prior_experiment_files'].items():assert sha(ROOT/name)==h,name
    result=dict(status='PASS',records_recomputed=rows,checkpoint_reload_logits_bitwise_equal=reloads,
        training_only_scaler_recalculation='PASS',checkpoint_selection_from_validation_only='PASS',
        metrics_and_prediction_csv_recomputed='PASS',row_and_component_and_both_feature_overlap=0,
        original_main_checkout_files_preserved=len(old['files']),prior_worktree_study_files_preserved=len(preservation['prior_experiment_files']),
        scope='Host offline checks only; no BPF/kernel or live-network execution')
    path=out/'evaluation/audit.json'
    if path.exists():assert read(path)==result
    else:write(path,result)
    print(json.dumps(result,indent=2),flush=True)


def summary(out):
    m=read(out/'evaluation/metrics.json');s=read(out/'split.json')
    lines=['OFFLINE CICFlowMeter CSV EXPERIMENT — NOT LIVE IDS ACCURACY',
           'Tuesday TCP rows: '+str(sum(p['rows'] for p in s['partitions'].values())),
           'Split train/validation/test: '+' / '.join(str(s['partitions'][k]['rows']) for k in ('train','validation','test')),
           'Model             Accuracy  Precision  Recall      F1      FP    FN',
           '-'*72]
    for name,label in [('forward','Forward-only'),('bidirectional','Bidirectional')]:
        q=m['models'][name]['metrics']
        lines.append(f"{label:16s} {q['accuracy']*100:8.3f}% {q['precision']*100:8.3f}% {q['recall']*100:8.3f}% {q['f1']*100:8.3f}% {q['FP']:5d} {q['FN']:5d}")
        lines.append('  Confusion [[TN,FP],[FN,TP]] = '+str(q['confusion_matrix']))
    lines += [f"F1 difference B−A: {m['paired']['f1_difference_percentage_points']:+.4f} percentage points",
              f"Disagreements {m['paired']['disagreements']}; corrected {m['paired']['corrected']}; made incorrect {m['paired']['made_incorrect']}",
              'Campaign independence: NO. Both models/scalers newly fitted on training rows only.']
    text='\n'.join(lines)+'\n';print(text)
    target=out/'TERMINAL_SUMMARY.txt'
    if target.exists():assert target.read_text()==text
    else:target.write_text(text)


def figures(out,m):
    os.environ.setdefault('MPLCONFIGDIR','/tmp/nn-ebpf-cic-bidir-mpl')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size':11,'axes.spines.top':False,'axes.spines.right':False,'savefig.bbox':'tight'})
    directory=out/'figures';directory.mkdir(exist_ok=True)
    labels=['Forward-only','Bidirectional'];modes=['forward','bidirectional'];colors=['#6B5CA5','#007C91']
    def save(fig,name):
        for ext in ('png','pdf'):fig.savefig(directory/(name+'.'+ext),dpi=250)
        plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(11,4.6),layout='constrained')
    maximum=max(max(row) for mode in modes for row in m['models'][mode]['metrics']['confusion_matrix'])
    for ax,mode,label in zip(axes,modes,labels):
        matrix=np.array(m['models'][mode]['metrics']['confusion_matrix'])
        ax.imshow(matrix,cmap='Blues',vmin=0,vmax=maximum)
        for (i,j),v in np.ndenumerate(matrix):ax.text(j,i,f'{v:,}',ha='center',va='center',fontsize=15,color='white' if v>maximum*.5 else '#17233B')
        ax.set(xticks=[0,1],yticks=[0,1],xticklabels=['Benign','Intrusion'],yticklabels=['Benign','Intrusion'],
               xlabel='Predicted',ylabel='Source label',title=label)
    fig.suptitle('Tuesday held-out CSV flows · confusion counts');save(fig,'confusion_matrices')
    fig,axes=plt.subplots(1,2,figsize=(11,4.2),sharey=True,layout='constrained')
    for ax,mode,label,color in zip(axes,modes,labels,colors):
        h=read(out/mode/'history.json');epochs=[r['epoch'] for r in h]
        ax.plot(epochs,[r['training_loss'] for r in h],label='Training',color=color)
        ax.plot(epochs,[r['validation_loss'] for r in h],label='Validation',color='#DB8B24',linestyle='--')
        best=read(out/mode/'training.json')['best_epoch'];ax.axvline(best,color='#667085',alpha=.5,linestyle=':')
        ax.set(xlabel='Epoch',ylabel='Cross-entropy (log scale)',title=label,yscale='log');ax.legend();ax.grid(alpha=.15)
    save(fig,'loss_curves')
    fig,ax=plt.subplots(figsize=(8,4.6),layout='constrained');x=np.arange(3)
    for j,(mode,label,color) in enumerate(zip(modes,labels,colors)):
        vals=[100*m['models'][mode]['metrics'][k] for k in ('precision','recall','f1')]
        bars=ax.bar(x+(j-.5)*.36,vals,.36,label=label,color=color)
        ax.bar_label(bars,fmt='%.2f%%',fontsize=9,padding=4)
    ax.set(xticks=x,xticklabels=['Precision','Recall','F1'],ylim=(0,112),ylabel='Percent',title='Same held-out Tuesday flows');ax.legend(loc='lower right')
    save(fig,'classification_metrics')
    fig,ax=plt.subplots(figsize=(6.5,4.6),layout='constrained')
    vals=[m['models'][mode]['metrics']['FP'] for mode in modes]
    bars=ax.bar(labels,vals,color=colors,width=.55);ax.bar_label(bars,padding=4)
    ax.set(ylabel='Benign flows predicted intrusion',title='False positives on the same benign test rows',ylim=(0,max(1,max(vals))*1.18))
    save(fig,'false_positives')


def report(out):
    m=read(out/'evaluation/metrics.json');d=read(out/'dataset_audit.json');s=read(out/'split.json');env=read(out/'environment.json')
    raw_source=read(out/'raw_source_audit.json')
    verified=read(out/'evaluation/audit.json');assert verified['status']=='PASS'
    figures(out,m)
    summary(out)
    a=m['models']['forward']['metrics'];b=m['models']['bidirectional']['metrics'];paired=m['paired']
    pct=lambda x:f'{100*x:.4f}%' if x is not None else 'undefined'
    num=lambda x:f'{x:.6f}' if x is not None else 'undefined'
    rows=[]
    for label,key,is_count in [('Accuracy','accuracy',False),('Precision','precision',False),('Recall','recall',False),('F1','f1',False),
        ('TP','TP',True),('FP','FP',True),('TN','TN',True),('FN','FN',True),('Specificity','specificity',False),
        ('False-positive rate','false_positive_rate',False),('Balanced accuracy','balanced_accuracy',False),('MCC','mcc',False),
        ('Average precision (step PR-AUC)','average_precision',False),('Trapezoidal PR-AUC','pr_auc_trapezoidal',False)]:
        if is_count:va,vb,delta=str(a[key]),str(b[key]),f'{b[key]-a[key]:+d}'
        elif key=='mcc':va,vb,delta=num(a[key]),num(b[key]),f'{b[key]-a[key]:+.6f}'
        else:va,vb,delta=pct(a[key]),pct(b[key]),f'{100*(b[key]-a[key]):+.4f} pp'
        rows.append(f'| {label} | {va} | {vb} | {delta} |')
    partitions='\n'.join(f"| {name} | {p['rows']:,} | {p['binary_support']['0']:,} | {p['binary_support']['1']:,} | {p['categories'].get('FTP-Patator',0):,} | {p['categories'].get('SSH-Patator',0):,} | {p['groups']:,} |" for name,p in s['partitions'].items())
    training=[]
    for mode in ('forward','bidirectional'):
        tr=read(out/mode/'training.json');training.append(f"| {mode} | {tr['best_epoch']} | {tr['best_validation_loss']:.9f} | `{tr['checkpoint_sha256']}` | `{tr['scaler_sha256']}` |")
    category_rows=[]
    for cat in ('FTP-Patator','SSH-Patator'):
        u=m['per_category']['forward'][cat];v=m['per_category']['bidirectional'][cat]
        category_rows.append(f"| {cat} | {u['support']:,} | {pct(u['intrusion_detection_recall'])} | {pct(v['intrusion_detection_recall'])} |")
    exclusions='\n'.join(f'| {k} | {v:,} |' for k,v in d['exclusions'].items())
    anomalies=[x for x in d['column_profile'] if any(x[k] for k in ('missing','nan','positive_infinity','negative_infinity','negative','non_numeric'))]
    anomaly_rows='\n'.join(f"| {x['name']} [{x['position']}] | {x['missing']} | {x['nan']} | {x['positive_infinity']+x['negative_infinity']} | {x['negative']} | {x['non_numeric']} |" for x in anomalies)
    feature_stats=[]
    for mode in ('forward','bidirectional'):
        for name,q in d['feature_statistics'][mode].items():
            feature_stats.append(f"| {mode} / {name} | {q['minimum']:,} | {q['maximum']:,} | {q['mean']:.5g} | {q['population_std']:.5g} |")
    baseline=m['baselines'];ci=paired['bootstrap']['percentage_point_95_percentile']
    direction='increased' if paired['f1_difference']>0 else 'decreased' if paired['f1_difference']<0 else 'was unchanged'
    fp_statement=f"False positives changed from **{a['FP']} to {b['FP']}** ({b['FP']-a['FP']:+d}); benign test support is {a['support']['0']:,}."
    prefix=out.relative_to(ROOT).as_posix()
    plot_prefix=f'{prefix}/figures'
    if out==HERE/'run':
        import shutil
        presentation=HERE/'presentation';presentation.mkdir(exist_ok=True)
        for path in (out/'figures').iterdir():shutil.copyfile(path,presentation/path.name)
        plot_prefix='research/cic_csv_mlp/presentation'
    plot=lambda name:f'{plot_prefix}/{name}.png'
    test_evidence=read(HERE/'tests.json') if (HERE/'tests.json').exists() else {'passed':'See saved test log'}
    text=f'''# Forward-only vs bidirectional six-input MLP on CIC-IDS-2017 Tuesday

9 November 2026 · **Completed offline CICFlowMeter CSV experiment**.
All results below are host FP32 classification on stored labeled CSV flows.
No model was quantized, loaded into eBPF, deployed, or tested on live traffic.

The bidirectional model's test F1 **{direction}** relative to the forward control:
**{pct(a['f1'])} → {pct(b['f1'])}**, a **{paired['f1_difference_percentage_points']:+.4f}
percentage-point** difference in this fixed split/training run.
{fp_statement}

## Dataset and audit

Read only `{d['source_zip']}::{d['source_member']}`. No download or PCAP join
was needed. Source-member SHA256: `{d['csv_sha256']}`; archive SHA256:
`{d['archive_sha256']}`. The streamed CSV contains {d['raw_rows']:,} physical
data records and {len(d['column_profile'])} columns, after trimming header whitespace.
Protocol counts: `{d['protocol_counts']}`. Original labels: `{d['raw_labels']}`.
The whole-source re-audit found **{raw_source['exact_duplicate_complete_records']}**
complete duplicate rows, all TCP, and {raw_source['flow_id_unique']:,} distinct
Flow ID strings ({raw_source['repeated_flow_id_excess']:,} repeated-ID excess).
Repeated IDs alone are not treated as duplicate records: reverse/timeout/FIN
appendices can share an ID. Every timestamp is minute-quantized on 4 July 2017,
without AM/PM or timezone. Original download provenance was operator-supplied,
not independently authenticated; hashes bind the actual analyzed files.
The [official UNB dataset description](https://www.unb.ca/cic/datasets/ids-2017.html)
and the existing dataset audit document the capture context. No release or
corrected label set was silently substituted.

The exact eligible population is **{d['retained']:,} TCP rows**:
**{d['binary_support']['0']:,} BENIGN** and **{d['binary_support']['1']:,} intrusion**,
with source categories `{d['retained_categories']}`. These are source annotations,
not independent confirmation that every labeled attack succeeded. No balancing,
oversampling, class weighting or attack-category removal was performed.

| First exclusion reason (deterministic rule order) | Rows |
| --- | ---: |
{exclusions}

Every excluded source row has its member-hash/physical-line identity, label,
protocol and reason in `{prefix}/excluded.jsonl.gz`. Counts reconcile exactly
to the full input denominator. Additional anomalies in all columns are recorded
even when the first exclusion reason already applies. Only complete identical
TCP source rows are deduplicated; feature-equal rows and conflicting labels
are retained and grouped. The diagnostic from the previous PCAP study is not
merged into this dataset.

Selected numeric fields must be finite, integral, nonnegative int64. Require
at least one forward packet, valid ports, payload extrema in 0..65535, TCP-header
totals in 20..60 bytes per observed packet, directional IAT no greater than
flow duration, and zero IAT for fewer than two directional packets. Aggregate
features must fit int64 and the exact float64 integer range. No imputation or
clipping is applied. IPv4 identity and 4 July 2017 minute timestamps are checked.
The two named `Fwd Header Length` columns must agree. These are declared CSV
sanity rules, not a claim that CIC counts exactly reproduce kernel packets.

All column names, positions, observed numeric ranges/types, missing, NaN,
infinity, negative and malformed-numeric counts are in
`{prefix}/dataset_audit.json`. Anomalous columns (positions are zero-based):

| Column [position] | Missing | NaN | Infinity | Negative | Non-numeric |
| --- | ---: | ---: | ---: | ---: | ---: |
{anomaly_rows or '| None | 0 | 0 | 0 | 0 | 0 |'}

Unused rate-column NaN/infinity does not enter either model and is not a reason
to drop an otherwise eligible row. Cleaning is stricter than the earlier
selected-column-only inventory; any changed row count is explained by the
explicit exclusions above, without consulting predictions.

## Exact feature definitions

Both representations use the same retained source rows, original CSV orientation
and source IAT **microseconds**. Packet lengths follow CICFlowMeter payload
conventions; TCP/IP/Ethernet headers are not added to those length columns.

| Input | Forward-only A | Bidirectional B |
| --- | --- | --- |
| 0 | Fwd Packet Length Max | Max of forward and observed backward maxima |
| 1 | Fwd IAT Max | Max of separate forward/backward IAT maxima; not Flow IAT Max |
| 2 | Fwd Packet Length Min | Min of observed-direction minima; measured zero is valid |
| 3 | Destination Port | Same original CSV destination port |
| 4 | Fwd Header Length | Forward + observed backward header totals |
| 5 | Total Fwd Packets | Total Fwd + Total Backward Packets |

For the **{d['no_backward_packets']:,}** rows without backward packets, all
backward contributions are omitted. Nonzero unused backward fields occurred
in {d['nonzero_ignored_backward_fields']} retained rows and are diagnosed, not used.
No IPs, timestamps, flow IDs, labels or source-row indices enter the neural
inputs. Those identifiers are used only for grouping and audit.

| Representation / feature | Min | Max | Mean | Population SD |
| --- | ---: | ---: | ---: | ---: |
{chr(10).join(feature_stats)}

## Frozen split and leakage limits

Shared train/validation/test split SHA256: `{sha(out/'split.npz')}`.
Seed **20261109**. The protocol and three allowed grouping alternatives were
written before preparing the cohort or fitting either model. The first feasible
scheme was **{s['selected_scheme']}**: {s['grouping']}. See `split_attempts.json`
for every attempted component size and support count. Feasibility requires all
three source categories in every partition and row fractions within five
percentage points of 70/15/15. Selection does not use predictions.

| Partition | Rows | Benign | Intrusion | FTP-Patator | SSH-Patator | Union groups |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
{partitions}

There are {s['group_count']:,} union components; the largest has
{s['largest_group']:,} rows. Exact six-vector repetitions are grouped for **both**
representations, including transitive links and conflicting-label vectors.
Overlap of source rows, union components and exact A/B vectors across partitions
is **zero**. Repetition diagnostics: `{s['repetition']}`. The complete source-ID,
row-index, group and partition mapping is saved in `split_rows.csv.gz` and
numeric `split.npz`; both models use exactly those IDs.

**This is not campaign-independent testing.** Tuesday has only FTP/SSH campaigns,
so the earlier three-campaign requirement was explicitly relaxed for this new
CSV-only task. Time is minute-quantized without AM/PM or offset; proxies are not
validated independent sessions. Related attack activity, hosts, ports and
near-duplicate behavior can still correlate across partitions. Grouping is
stronger than an unqualified random-row split, but does not establish new-day,
new-host, new-attack or external generalization.

Group preservation also changes class prevalence between partitions: the
training/validation/test category counts above are not perfectly stratified.
Only {s['partitions']['test']['categories'].get('SSH-Patator',0)} SSH-Patator rows
remain in test, so its subgroup estimate is especially narrow. The large
component and failed stronger scheme are reported instead of silently breaking
duplicate/session groups to improve balance or scores.

## Training and checkpoint identity

Both models instantiate the authors' `src/mlp.py` **Net(6,2)** from scratch:
bias-free **6→32→32→2**, ReLU hidden layers, exactly **1,280 weights**. Same seed,
same initial weight hash, same shuffled training IDs, Adam defaults with
lr=0.001, unweighted cross-entropy, batch size 512, **32 epochs**, CPU, one Torch
thread and deterministic algorithms. No prior model/checkpoint is loaded.

Each representation has a separate StandardScaler fitted on training IDs only.
Scaling is float64 `(x-mean)/scale`, then float32 input. Validation/test never
fit scaler statistics. Independent training-mean/variance recalculations passed.
The minimum validation cross-entropy selects each checkpoint; earliest exact
ties win. Test outputs were computed only after both checkpoints were frozen.
Argmax over two logits is unchanged; exact FP32 ties select class 0.

| Model | Best epoch | Validation CE | Checkpoint SHA256 | Numeric scaler SHA256 |
| --- | ---: | ---: | --- | --- |
{chr(10).join(training)}

Numeric-only NPZ checkpoints/scalers use `allow_pickle=False`. Reloaded
validation and test logits match saved outputs **bit for bit**. Epoch train/val
losses, normalized ranges, checkpoint-selection evidence, initialization,
dataset/split hashes and environment are saved beside each checkpoint.

![Training and validation loss]({plot('loss_curves')})

## Held-out results

Positive class = intrusion. Confusion order is **[[TN, FP], [FN, TP]]**.
Both models classify the same **{m['input_count']:,}** test rows with **100% coverage**,
zero rejected/missing predictions, finite normalized inputs and finite logits.
The test support is **{a['support']['0']:,} benign / {a['support']['1']:,} intrusion**.

| Metric | Forward-only A | Bidirectional B | B − A |
| --- | ---: | ---: | ---: |
{chr(10).join(rows)}

Forward confusion: **{a['confusion_matrix']}**. Bidirectional confusion:
**{b['confusion_matrix']}**. All counts independently reconcile to the same
test denominator. Manual confusion formulas and tied-score PR calculations
agree with scikit-learn. Average precision is step-integrated PR-AUC;
trapezoidal PR-AUC is separately named. Both rank by logit1−logit0, without
test-fitted thresholds.

![Confusion matrices]({plot('confusion_matrices')})
![Precision, recall and F1]({plot('classification_metrics')})
![False-positive counts]({plot('false_positives')})

| Attack source category | Test support | Forward recall | Bidirectional recall |
| --- | ---: | ---: | ---: |
{chr(10).join(category_rows)}

Per-port results (including 21/22 and other ports with at least 100 test rows)
and benign false-positive rates are retained in `evaluation/metrics.json`.
No subgroup result was used to tune or retrain a model.

## Paired comparison, baselines and interpretation

Predictions disagree on **{paired['disagreements']:,}** test rows. B corrects
**{paired['corrected']:,}** A errors and makes **{paired['made_incorrect']:,}** A-correct
rows incorrect. Class-wise counts: `{paired['by_class']}`.

Paired percentile bootstrap: 2,000 draws of whole frozen test union components,
same sampled components for both models, seed 20261110. The 95% interval for
F1(B)−F1(A) is **[{ci[0]:+.4f}, {ci[1]:+.4f}] percentage points**.
This interval is conditional on the fixed trained models and imperfect proxy
groups. Residual campaign dependence and training-seed variability are not
captured; it is not a campaign-level significance or generalization claim.

Training-majority baseline class = {baseline['training_majority_class']}:
accuracy **{pct(baseline['majority']['accuracy'])}**, F1
**{pct(baseline['majority']['f1'])}**. A training-only destination-port lookup
achieves accuracy **{pct(baseline['destination_port_only']['accuracy'])}**, F1
**{pct(baseline['destination_port_only']['f1'])}**, FP
**{baseline['destination_port_only']['FP']}**, FN
**{baseline['destination_port_only']['FN']}**. It learns the majority source
label per training port, with class-0 ties and training-majority fallback for
unseen ports. This diagnostic measures how much service-port correlation alone
can explain; it does not establish what either MLP internally relies on.

The port-only lookup has higher F1 than either MLP in this split, which is a
strong warning about service-port shortcuts in Tuesday's source labels.
The bidirectional model's average precision remains
{num(b['average_precision'])} despite its lower recall at the fixed argmax
decision. Ranking quality and the chosen operating point are different
measurements; no test-derived threshold adjustment was made.

Aggregating max/min/sums also loses directional identity. This result does
not show that all uses of bidirectional information are harmful, or isolate
which aggregate caused the decrease. It establishes the measured trade-off for
these two representations, fixed architecture, budget and split. A future
multi-seed or alternative-representation study needs its own declared protocol;
this test set was not used to redesign the features or training.

These results describe one naturally imbalanced, cleaned Tuesday population,
one frozen split and one paired initialization/training seed. Source labels and
CICFlowMeter flow construction have known limitations. High F1 can reflect
service ports or capture conditions rather than attack behavior. No improvement
over the separately evaluated reproduction model, paper benchmark, deployed
extractor, kernel arithmetic or live IDS is inferred.

## Validation, reproduction and files

Saved-record/model/scaler/split audit: **PASS**. Host tests:
`{test_evidence}`. The audit rereads every saved prediction CSV row, checks
identities/features/logits/labels against numeric archives, reexecutes both
checkpoints, verifies scaler fits and selected validation epochs, and checks
all freeze hashes. Production preservation: {verified['original_main_checkout_files_preserved']:,}
existing main-checkout file hashes and {verified['prior_worktree_study_files_preserved']}
prior-study files remain unchanged. No kernel, namespace or physical-network
operation was run in this task.

Environment: Python {env['python']}, `{env['packages']}`, kernel
`{env['kernel']}`, {env['machine']}. Base Git commit `{env['git_head']}`;
branch `{env['branch']}`. Work is uncommitted; no commit or push was performed.
Pinned package list is saved in `requirements.txt`. Existing temporary packages
were unavailable, so dependencies were installed only in a new `/tmp` venv.

From this isolated worktree root, actual stages were run in order:

```bash
PY=/tmp/nn-ebpf-cic-bidir-20261109/bin/python
export PYTHONDONTWRITEBYTECODE=1
export MPLCONFIGDIR=/tmp/nn-ebpf-cic-bidir-mpl

"$PY" -B -m unittest -v research.cic_csv_mlp.test_study

# For reproduction choose a NEW output directory; frozen outputs refuse overwrite.
OUT=research/cic_csv_mlp/run-reproduction
"$PY" -B -m research.cic_csv_mlp.pipeline prepare --output "$OUT" \\
  --source '/mnt/c/Study Materials/Semester 7/USAP/Term Project/GeneratedLabelledFlows.zip'
"$PY" -B -m research.cic_csv_mlp.forensics --output "$OUT" \\
  --source '/mnt/c/Study Materials/Semester 7/USAP/Term Project/GeneratedLabelledFlows.zip'
"$PY" -B -m research.cic_csv_mlp.pipeline split --output "$OUT"
"$PY" -B -m research.cic_csv_mlp.pipeline train --output "$OUT"
"$PY" -B -m research.cic_csv_mlp.pipeline evaluate --output "$OUT"
"$PY" -B -m research.cic_csv_mlp.pipeline audit --output "$OUT"
"$PY" -B -m research.cic_csv_mlp.pipeline report --output "$OUT"

# Screenshot-friendly summary of the existing completed run; does not retrain:
"$PY" -B -m research.cic_csv_mlp.pipeline summary --output {prefix}
```

The measured run used `OUT={prefix}`. The previous PCAP study and all its
evidence remain unchanged. New code is exclusively under `research/cic_csv_mlp/`:
protocol, dataset/feature audit, union split, trainer, metric/evaluation code,
saved-result auditor/report/plots, CLI, tests and README. This report is the only
new root document. Numeric data/checkpoints/raw predictions are under ignored
`{prefix}/`; no large archive, raw CSV or executable is added to Git.
Suggested review boundaries: (1) protocol/data/split and tests; (2) training,
evaluation, audit/report and small summary/figures. Stage explicit paths after
review; do not use `git add .`, merge the demo branch or commit large run archives.

## What remains before TC integration

The model is **not deployable as-is**. CIC payload extrema differ from kernel
TCP-segment extrema, timestamps use microseconds rather than helper ns, CSV
forward direction can differ from monitored ingress, and completed CSV windows
can contain packets arriving after the demo's first-ingress-FIN decision.
Unit conversion alone does not repair direction/window or length conventions.

A separate integration study must either collect faithfully labeled kernel-
equivalent bidirectional training windows or deliberately implement and verify
compatible feature semantics. Current egress state lacks segment min/max,
directional maximum IAT and TCP-header totals. Add separate versioned
experimental state and consistent locked snapshots; specify termination and
bounded expiration, tuple reuse, duplicate prevention and per-CPU ownership.
Fit a compatible training-only scaler and separate model parameters, quantize
to Q16 with range/overflow checks, verify loaded map bytes, all six stages,
intermediate tensors/logits and reference predictions. Run verifier/concurrency
and one/ten/32/asymmetric/missing-direction namespace tests. Hold ingress fixed,
vary egress, and prove the actual MLP input changes. Only subsequent operator-
controlled live testing can measure live detection performance. No production
model/default or working demonstration was modified here.

## Direct answers

- **Q1:** {d['retained']:,} eligible TCP rows; train
  {s['partitions']['train']['rows']:,}, validation {s['partitions']['validation']['rows']:,},
  test {s['partitions']['test']['rows']:,}, shared by both models.
- **Q2:** Forward: F1 {pct(a['f1'])}, precision {pct(a['precision'])}, recall
  {pct(a['recall'])}, accuracy {pct(a['accuracy'])}; matrix {a['confusion_matrix']}.
- **Q3:** Bidirectional: F1 {pct(b['f1'])}, precision {pct(b['precision'])}, recall
  {pct(b['recall'])}, accuracy {pct(b['accuracy'])}; matrix {b['confusion_matrix']}.
- **Q4:** F1 {direction}; B−A = {paired['f1_difference_percentage_points']:+.4f} pp.
- **Q5:** {fp_statement}
- **Q6:** Within-Tuesday proxy-group evaluation, source-label/capture correlation,
  port shortcuts, one training seed and no new-day/campaign independence.
- **Q7:** Compatible kernel training windows/features, missing egress state and
  trigger/lifecycle design, new scaler/quantization, map/tensor/kernel/network
  validation, then separately measured live effectiveness remain outstanding.
'''
    # A reproduction can have a different output prefix/environment. Preserve
    # the first study report; always save a report beside its own new run.
    target=ROOT/'CIC_FORWARD_VS_BIDIRECTIONAL_MLP.md'
    if not target.exists():target.write_text(text)
    elif target.read_text()!=text:
        existing=target.read_text()
        if existing.replace(']('+prefix+'/figures/',']('+plot_prefix+'/')==text:
            # Link-only portability correction to this run's own report.
            target.write_text(text)
        else:print('Preserving the existing root report; this run report is saved under',out)
    local=out/'CIC_FORWARD_VS_BIDIRECTIONAL_MLP.md'
    local_text=text.replace(']('+plot_prefix+'/','](figures/')
    if local.exists():
        if local.read_text()!=local_text:raise ValueError('This run already has a different report')
    else:local.write_text(local_text)
    print('Report:',target,flush=True)
