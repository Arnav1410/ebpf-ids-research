"""One predictions-blind union-group split shared by both representations."""
from collections import Counter
import csv
import gzip
import hashlib
import json
import numpy as np

from .common import archive, read, write, freeze, verify_hashes, protocol


class Union:
    def __init__(self,n):self.parent=list(range(n));self.size=[1]*n
    def find(self,i):
        while i!=self.parent[i]:
            self.parent[i]=self.parent[self.parent[i]];i=self.parent[i]
        return i
    def join(self,a,b):
        a,b=self.find(a),self.find(b)
        if a==b:return
        if self.size[a]<self.size[b]:a,b=b,a
        self.parent[b]=a;self.size[a]+=self.size[b]


def component_ids(a,b,metadata,scheme):
    n=len(a);u=Union(n)
    for x in (a,b):
        seen={}
        for i,row in enumerate(x):
            key=row.astype('<i8',copy=False).tobytes()
            if key in seen:u.join(i,seen[key])
            else:seen[key]=i
    for kind in (('tuple_key','minute_pair') if scheme==0 else ('tuple_key',) if scheme==1 else ()):
        seen={}
        for i,r in enumerate(metadata):
            key=r['tuple_key'] if kind=='tuple_key' else (r['pair_key'],r['minute'])
            if key in seen:u.join(i,seen[key])
            else:seen[key]=i
    groups={}
    for i in range(n):groups.setdefault(u.find(i),[]).append(i)
    # Stable ID: lowest retained source-array index in each union component.
    gid=np.empty(n,dtype='<i8')
    for members in groups.values():gid[members]=min(members)
    return gid,list(groups.values())


def allocate(groups,categories,seed):
    rng=np.random.default_rng(seed);fractions=np.array([.7,.15,.15])
    total=np.bincount(categories,minlength=3)
    targets=fractions[:,None]*total[None,:]
    counts=np.zeros((3,3),dtype=np.int64);row_counts=np.zeros(3,dtype=np.int64)
    out=np.full(len(categories),-1,dtype=np.int64)
    # No prediction or learned feature weighting enters the split objective.
    ordered=sorted(groups,key=lambda ids:(-len(ids),hashlib.sha256(f'{seed}:{min(ids)}'.encode()).hexdigest()))
    for ids in ordered:
        c=np.bincount(categories[ids],minlength=3)
        delta=(((counts-targets+c)**2-(counts-targets)**2)/np.maximum(targets,1)).sum(axis=1)
        desired=fractions*len(categories)
        delta+=.1*((row_counts-desired+len(ids))**2-(row_counts-desired)**2)/np.maximum(desired,1)
        tied=np.flatnonzero(np.isclose(delta,delta.min(),rtol=0,atol=1e-10))
        part=int(rng.choice(tied));out[ids]=part;counts[part]+=c;row_counts[part]+=len(ids)
    assert (out>=0).all()
    return out,counts


def repetition_stats(x,y):
    masks={};counts=Counter()
    for row,label in zip(x,y):
        k=row.astype('<i8',copy=False).tobytes();counts[k]+=1;masks[k]=masks.get(k,0)|(1<<int(label))
    return dict(unique_vectors=len(counts),duplicate_excess=len(x)-len(counts),
                conflicting_label_vectors=sum(m==3 for m in masks.values()),
                rows_in_conflicting_vectors=sum(counts[k] for k,m in masks.items() if m==3))


def make_split(out):
    verify_hashes(out,'data-freeze.json');spec=read(out/'protocol.json')
    data=archive(out/'data.npz')
    with gzip.open(out/'records.jsonl.gz','rt') as f:metadata=[json.loads(line) for line in f]
    assert len(metadata)==len(data['labels'])
    cats=np.array([('BENIGN','FTP-Patator','SSH-Patator').index(r['category']) for r in metadata],dtype=np.int64)
    attempts=[];selected=None
    for scheme in range(3):
        gid,groups=component_ids(data['forward'],data['bidirectional'],metadata,scheme)
        assignment,counts=allocate(groups,cats,spec['seed'])
        ratios=counts.sum(axis=1)/len(cats)
        feasible=bool((counts>0).all() and (np.abs(ratios-np.array([.7,.15,.15]))<=.05).all())
        item=dict(scheme=scheme,description=spec['grouping_attempts_in_order'][scheme],components=len(groups),
                  largest_component=max(map(len,groups)),counts=counts.tolist(),fractions=ratios.tolist(),feasible=feasible)
        attempts.append(item);print('Split candidate',json.dumps(item),flush=True)
        if feasible:selected=scheme;break
    write(out/'split_attempts.json',attempts)
    if selected is None:raise RuntimeError('Declared grouped splitting alternatives exhausted; no model was trained')
    parts={name:np.flatnonzero(assignment==i) for i,name in enumerate(('train','validation','test'))}
    assert sum(map(len,parts.values()))==len(cats)
    for members in groups:assert len(set(assignment[members]))==1
    for x in (data['forward'],data['bidirectional']):
        sets=[{row.tobytes() for row in x[ids]} for ids in parts.values()]
        assert all(not sets[i]&sets[j] for i,j in ((0,1),(0,2),(1,2)))
    arrays=dict(parts,group_id=gid,assignment=assignment)
    np.savez_compressed(out/'split.npz',**arrays)
    summary=dict(status='PASS',seed=spec['seed'],selected_scheme=selected,grouping=attempts[-1]['description'],
        campaign_independent=False,partitions={},group_count=len(groups),largest_group=max(map(len,groups)),
        exact_vector_overlap=0,union_component_overlap=0,source_row_overlap=0,
        repetition={k:repetition_stats(data[k],data['labels']) for k in ('forward','bidirectional')},
        interpretation='Within-Tuesday group-disjoint split under the recorded proxy, not independent campaigns or days.')
    with gzip.open(out/'split_rows.csv.gz','wt',newline='') as f:
        writer=csv.writer(f);writer.writerow(['array_index','source_record_id','source_line','category','label','group_id','partition'])
        for i,r in enumerate(metadata):writer.writerow([i,r['source_record_id'],r['source_line'],r['category'],r['label'],int(gid[i]),('train','validation','test')[assignment[i]]])
    for name,ids in parts.items():
        summary['partitions'][name]=dict(rows=len(ids),binary_support={str(k):int((data['labels'][ids]==k).sum()) for k in (0,1)},
            categories=dict(Counter(metadata[i]['category'] for i in ids)),groups=len(set(gid[ids].tolist())))
        # Trainer can open just train/validation files; no need to open test.
        np.savez_compressed(out/(name+'.npz'),indices=ids,source_lines=data['source_lines'][ids],
                            forward=data['forward'][ids],bidirectional=data['bidirectional'][ids],labels=data['labels'][ids])
    write(out/'split.json',summary)
    freeze(out,'split-freeze.json',['split.json','split.npz','split_rows.csv.gz','split_attempts.json',
           'train.npz','validation.npz','test.npz','protocol.json'],model_predictions_consulted=False)
    print(json.dumps(summary['partitions'],indent=2),flush=True)
