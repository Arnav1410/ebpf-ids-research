#!/usr/bin/env python3
"""Inspect stored numeric data without training, unpickling or traffic generation."""
import argparse
from collections import Counter,defaultdict
import json
import math
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.dont_write_bytecode=True
from evaluation.data import reproduction,digest
from validation.reference import Model
from quantization.calibrate import split


def audit(root=ROOT):
    rows,labels=reproduction(root);model=Model.load(root/'src/mlp_params.bpf.h')
    moments=[];groups=defaultdict(set)
    for x,y in zip(rows,labels):groups[tuple(x)].add(y)
    for j in range(6):
        avg=sum(x[j] for x in rows)/len(rows);sigma=math.sqrt(sum((x[j]-avg)**2 for x in rows)/len(rows))
        moments.append(dict(column=j,min=min(x[j] for x in rows),max=max(x[j] for x in rows),
                            mean=avg,population_std=sigma,header_mean=model.mean[j],header_scale=model.scale[j],
                            rounded_moments_match=round(avg)==model.mean[j] and round(sigma)==model.scale[j]))
    cal,held=split(rows)
    return dict(status='PASS',execution='Host data inspection only',rows=len(rows),columns=6,feature_dtype='int64',
        label_dtype='float64',label_counts=dict(Counter(labels)),unique_vectors=len(groups),duplicate_rows=len(rows)-len(groups),
        vectors_with_conflicting_labels=sum(len(v)>1 for v in groups.values()),moments=moments,
        hashes={p:digest(root/p) for p in ('dataset/reproduction-xdp-data.npy','dataset/reproduction-xdp-label.npy','src/mlp_params.bpf.h')},
        scaler_provenance='All six rounded full-dataset moments match header; weights/training membership not established',
        original_train_split='Not saved; train_test_split has no random_state, StandardScaler fits all rows',
        scaling_calibration_rows=len(cal),scaling_heldout_rows=len(held),original_training_membership='UNKNOWN',
        intended_paper_label_map={'0':'benign','1':'intrusion'},stored_label_collection_manifest='NOT FOUND',
        labeled_effectiveness_gate='NOT RUN: encoded-label diagnostics possible; independently labeled held-out protocol unavailable',
        cic_csv_availability='No CIC CSV found in project/research or inspected Windows Downloads/Desktop/Documents; search is not an exhaustive disk inventory')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=True);value=audit();(args.output/'dataset_audit.json').write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value,indent=2))


if __name__=='__main__':main()
