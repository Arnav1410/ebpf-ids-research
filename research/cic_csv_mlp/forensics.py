"""Supplementary whole-source duplicate/clock audit; no selection or model fit."""
import argparse
from collections import Counter
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

from .common import protocol,sha,write


def source_audit(source,out):
    spec=protocol()
    if sha(source)!=spec['source_zip_sha256']:raise ValueError('Source archive changed')
    duplicates=Counter();categories=Counter();protocols=Counter();dates=Counter();clocks=Counter();seen={};flow_ids=Counter()
    with zipfile.ZipFile(source) as z, z.open(spec['source_member']) as raw, gzip.open(out/'raw_duplicates.jsonl.gz','xt') as log:
        reader=csv.reader(io.TextIOWrapper(raw,encoding='utf-8-sig'))
        header=[s.strip() for s in next(reader)];p={k:header.index(k) for k in ['Protocol','Label','Flow ID','Timestamp']}
        n=0
        for row in reader:
            n+=1;category=row[p['Label']].strip();proto=row[p['Protocol']].strip()
            categories[category]+=1;protocols[proto]+=1;flow_ids[row[p['Flow ID']].strip()]+=1
            stamp=row[p['Timestamp']].strip();parts=stamp.split();dates[parts[0] if parts else 'MISSING']+=1
            clocks['minute_without_AM_PM' if re.fullmatch(r'\d+/\d+/\d+ \d+:\d+',stamp) else 'other']+=1
            h=hashlib.sha256(json.dumps(row,separators=(',',':')).encode()).digest()
            if h in seen:
                duplicates[proto]+=1
                log.write(json.dumps(dict(source_line=reader.line_num,retained_first_line=seen[h],protocol=proto,category=category))+'\n')
            else:seen[h]=reader.line_num
    result=dict(status='PASS',rows=n,protocol_counts=dict(protocols),raw_labels=dict(categories),
        exact_duplicate_complete_records=sum(duplicates.values()),duplicates_by_protocol=dict(duplicates),
        unique_complete_records=len(seen),flow_id_unique=len(flow_ids),repeated_flow_id_excess=sum(v-1 for v in flow_ids.values()),
        timestamp_date_counts=dict(dates),clock_formats=dict(clocks),
        caveat='Repeated Flow ID may describe reverse/timeout/termination appendices; not automatically a duplicate source row. Clock has no AM/PM or offset.',
        source_csv_sha256=spec['source_member_sha256'],source_zip_sha256=spec['source_zip_sha256'])
    write(out/'raw_source_audit.json',result);print(json.dumps(result,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();source_audit(a.source,a.output)
