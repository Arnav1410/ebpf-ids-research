"""Bounded Tuesday CSV audit and two six-input CICFlowMeter representations."""
from collections import Counter
import csv
from datetime import datetime
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import zipfile

from .common import HERE, sha, write, protocol, freeze

I64_MAX = (1 << 63)-1
EXACT_FLOAT64_MAX = (1 << 53)-1
NUMERIC = ('Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Max',
           'Fwd Packet Length Min', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
           'Fwd IAT Max', 'Bwd IAT Max', 'Fwd Header Length', 'Bwd Header Length',
           'Destination Port', 'Source Port', 'Flow Duration')
TEXT = ('Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label')


class InvalidRow(ValueError):
    pass


def integer(s):
    try: d = Decimal(s.strip())
    except InvalidOperation as ex: raise InvalidRow('NON_NUMERIC_SELECTED') from ex
    if not d.is_finite(): raise InvalidRow('NONFINITE_SELECTED')
    if d < 0: raise InvalidRow('NEGATIVE_SELECTED')
    if d > I64_MAX or d != d.to_integral_value(): raise InvalidRow('NONINTEGRAL_OR_INT64_RANGE')
    return int(d)


def features(n):
    """Use source microseconds/payload conventions; never kernel conversions."""
    for k in NUMERIC:
        if type(n[k]) is not int or not 0 <= n[k] <= I64_MAX: raise InvalidRow('SELECTED_INT64_RANGE')
    if not 0 <= n['Source Port'] <= 65535 or not 0 <= n['Destination Port'] <= 65535: raise InvalidRow('INVALID_PORT')
    if n['Total Fwd Packets'] < 1: raise InvalidRow('ZERO_FORWARD_PACKETS')
    observed = []
    for prefix, count_name in (('Fwd','Total Fwd Packets'),('Bwd','Total Backward Packets')):
        count = n[count_name]
        if not count: continue
        small, large = n[prefix+' Packet Length Min'], n[prefix+' Packet Length Max']
        header, iat = n[prefix+' Header Length'], n[prefix+' IAT Max']
        if not small <= large <= 65535: raise InvalidRow('INVALID_PAYLOAD_EXTREMA')
        if not 20*count <= header <= 60*count: raise InvalidRow('INVALID_TCP_HEADER_TOTAL')
        if iat > n['Flow Duration'] or count < 2 and iat != 0: raise InvalidRow('INVALID_DIRECTIONAL_IAT')
        observed.append((large,iat,small,header,count))
    fwd=observed[0]
    a=[fwd[0],fwd[1],fwd[2],n['Destination Port'],fwd[3],fwd[4]]
    b=[max(d[0] for d in observed),max(d[1] for d in observed),min(d[2] for d in observed),
       n['Destination Port'],sum(d[3] for d in observed),sum(d[4] for d in observed)]
    if any(v > I64_MAX for v in a+b): raise InvalidRow('AGGREGATE_INT64_OVERFLOW')
    if any(v > EXACT_FLOAT64_MAX for v in a+b): raise InvalidRow('FLOAT64_EXACT_INTEGER_RANGE')
    return a,b


def minute(text):
    try: d=datetime.strptime(text.strip(),'%d/%m/%Y %H:%M')
    except ValueError as ex: raise InvalidRow('INVALID_TIMESTAMP') from ex
    if (d.year,d.month,d.day)!=(2017,7,4): raise InvalidRow('UNEXPECTED_CAPTURE_DATE')
    # Source has no AM/PM or offset; this is a grouping token, NOT UTC time.
    return d.strftime('%Y-%m-%dT%H:%M')


def positions(header):
    p={k:[i for i,x in enumerate(header) if x==k] for k in NUMERIC+TEXT+('Protocol',)}
    if any(not v for v in p.values()): raise ValueError('Required CSV column missing')
    if any(len(v)!=1 for k,v in p.items() if k!='Fwd Header Length'): raise ValueError('Ambiguous CSV column')
    return p


def parse(row, pos):
    n={}
    for k in NUMERIC:
        v=[integer(row[i]) for i in pos[k]]
        if len(set(v))!=1: raise InvalidRow('CONFLICTING_DUPLICATE_HEADER')
        n[k]=v[0]
    a,b=features(n)
    get=lambda k:row[pos[k][0]].strip()
    if any(not get(k) for k in TEXT): raise InvalidRow('MISSING_IDENTITY_OR_LABEL')
    try: src=int(ipaddress.IPv4Address(get('Source IP')));dst=int(ipaddress.IPv4Address(get('Destination IP')))
    except ValueError as ex: raise InvalidRow('INVALID_IPV4') from ex
    endpoints=sorted(((src,n['Source Port']),(dst,n['Destination Port'])))
    if endpoints[0]==endpoints[1]: raise InvalidRow('IDENTICAL_ENDPOINTS')
    meta=dict(flow_id=get('Flow ID'),source_ip=get('Source IP'),source_port=n['Source Port'],
              destination_ip=get('Destination IP'),destination_port=n['Destination Port'],
              timestamp=get('Timestamp'),minute=minute(get('Timestamp')),category=get('Label'),
              tuple_key=','.join(map(str,(*endpoints[0],*endpoints[1],6))),
              pair_key=','.join(map(str,sorted((src,dst)))),backward_packets=n['Total Backward Packets'])
    unused=not n['Total Backward Packets'] and any(n[k] for k in
             ('Bwd Packet Length Max','Bwd Packet Length Min','Bwd IAT Max','Bwd Header Length'))
    return a,b,meta,bool(unused)


def prepare(source, out):
    import math
    import numpy as np
    spec=protocol()
    if sha(source)!=spec['source_zip_sha256']: raise ValueError('Source archive changed')
    out.mkdir(parents=True,exist_ok=False)
    write(out/'protocol.json',spec)
    raw_labels, protocols, exclusions, retained_categories = (Counter() for _ in range(4))
    rows=0;xs=[];bs=[];ys=[];lines_kept=[];seen={};no_reverse=unused=0;date_counts=Counter()
    digest=hashlib.sha256()
    with zipfile.ZipFile(source) as z:
        matches=[i for i in z.infolist() if i.filename==spec['source_member']]
        if len(z.infolist())>256 or len(matches)!=1: raise ValueError('Archive directory/member bound')
        info=matches[0]
        if info.file_size>512<<20 or info.flag_bits&1: raise ValueError('Member size/encryption bound')
        def text_lines(raw):
            total=0;first=True
            while True:
                line=raw.readline(1<<20)
                if not line:break
                total+=len(line)
                if len(line)>=1<<20 or total>info.file_size: raise ValueError('CSV expansion bound')
                digest.update(line)
                yield line.decode('utf-8-sig' if first else 'utf-8');first=False
        with z.open(info) as raw, gzip.open(out/'excluded.jsonl.gz','wt') as rejected, gzip.open(out/'records.jsonl.gz','wt') as kept:
            reader=csv.reader(text_lines(raw));header=[s.strip() for s in next(reader)];pos=positions(header)
            profile=[dict(name=name,position=i,type='text' if name in TEXT else 'numeric',missing=0,nan=0,
                          positive_infinity=0,negative_infinity=0,negative=0,non_numeric=0,integral=0,fractional=0,
                          minimum=None,maximum=None) for i,name in enumerate(header)]
            for row in reader:
                rows+=1;line=reader.line_num
                if len(row)!=len(header):
                    raise ValueError('Unexpected CSV width at source row '+str(line))
                category=row[pos['Label'][0]].strip();proto=row[pos['Protocol'][0]].strip()
                raw_labels[category]+=1;protocols[proto]+=1
                for value,stats in zip(row,profile):
                    value=value.strip()
                    if not value: stats['missing']+=1;continue
                    if stats['type']=='text':continue
                    try:v=float(value)
                    except ValueError:stats['non_numeric']+=1;continue
                    if math.isnan(v):stats['nan']+=1;continue
                    if math.isinf(v):stats['positive_infinity' if v>0 else 'negative_infinity']+=1;continue
                    stats['negative']+=v<0
                    stats['integral' if v.is_integer() else 'fractional']+=1
                    stats['minimum']=v if stats['minimum'] is None else min(v,stats['minimum'])
                    stats['maximum']=v if stats['maximum'] is None else max(v,stats['maximum'])
                reason=None;duplicate_of=None
                if proto!='6':reason='NON_TCP'
                else:
                    h=hashlib.sha256(json.dumps(row,separators=(',',':')).encode()).digest()
                    if h in seen:reason='DUPLICATE_COMPLETE_TCP_ROW';duplicate_of=seen[h]
                    else:
                        seen[h]=line
                        try:a,b,meta,ignored=parse(row,pos)
                        except InvalidRow as ex:reason=str(ex)
                        if reason is None:
                            if category not in spec['source_labels']:raise ValueError('Undeclared source label '+category)
                            y=spec['source_labels'][category]
                            xs.append(a);bs.append(b);ys.append(y);lines_kept.append(line)
                            retained_categories[category]+=1;no_reverse+=not meta['backward_packets'];unused+=ignored
                            date_counts[meta['timestamp'].split()[0]]+=1
                            meta.update(index=len(xs)-1,source_line=line,source_record_id=spec['source_member_sha256']+':'+str(line),
                                        label=y,complete_row_sha256=h.hex())
                            kept.write(json.dumps(meta,separators=(',',':'))+'\n')
                if reason:
                    exclusions[reason]+=1
                    rejected.write(json.dumps(dict(source_record_id=spec['source_member_sha256']+':'+str(line),
                        source_line=line,category=category,protocol=proto,reason=reason,duplicate_of=duplicate_of),separators=(',',':'))+'\n')
                if rows%100000==0:print('Audited CSV rows',rows,'retained TCP',len(xs),flush=True)
    if digest.hexdigest()!=spec['source_member_sha256']:raise ValueError('Source CSV member changed')
    a=np.asarray(xs,dtype='<i8');b=np.asarray(bs,dtype='<i8');y=np.asarray(ys,dtype='<i8')
    assert a.shape==b.shape==(len(y),6) and set(y)=={0,1}
    np.savez_compressed(out/'data.npz',forward=a,bidirectional=b,labels=y,source_lines=np.asarray(lines_kept,dtype='<i8'))
    fields=('max_packet_length','max_directional_iat_us','min_packet_length','destination_port','header_total','packet_count')
    summaries={name:{k:dict(minimum=int(x[:,i].min()),maximum=int(x[:,i].max()),mean=float(x[:,i].mean()),
                 population_std=float(x[:,i].std())) for i,k in enumerate(fields)} for name,x in [('forward',a),('bidirectional',b)]}
    audit=dict(status='PASS',scope='Offline Tuesday CICFlowMeter CSV classification inputs, not eBPF vectors',
        source_zip=str(Path(source).resolve()),source_member=spec['source_member'],archive_sha256=sha(source),
        csv_sha256=digest.hexdigest(),csv_bytes=info.file_size,raw_rows=rows,protocol_counts=dict(protocols),
        raw_labels=dict(raw_labels),tcp_rows=protocols['6'],retained=len(y),retained_categories=dict(retained_categories),
        binary_support={str(k):int((y==k).sum()) for k in (0,1)},exclusions=dict(exclusions),
        no_backward_packets=no_reverse,nonzero_ignored_backward_fields=unused,timestamp_dates=dict(date_counts),
        timestamp_precision='Minute; no AM/PM/offset. Retained only as grouping metadata.',column_profile=profile,
        selected_positions_zero_based=pos,feature_statistics=summaries,features_changed_counts=(a!=b).sum(axis=0).tolist(),
        input_dtype='int64; StandardScaler receives float64, MLP receives normalized float32; source IAT remains microseconds',
        deduplication='Complete identical TCP CSV rows only. Repeated/conflicting feature vectors retained and grouped at split.')
    assert rows==len(y)+sum(exclusions.values())
    write(out/'dataset_audit.json',audit)
    freeze(out,'data-freeze.json',['protocol.json','data.npz','records.jsonl.gz','excluded.jsonl.gz','dataset_audit.json'],
           source_csv_sha256=digest.hexdigest(),model_predictions_consulted=False)
    print(json.dumps({k:audit[k] for k in ('raw_rows','protocol_counts','retained','binary_support','retained_categories','exclusions')},indent=2),flush=True)
