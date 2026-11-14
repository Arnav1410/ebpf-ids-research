#!/usr/bin/env python3
"""Inspect a caller-supplied numeric CSV; never download/replay or silently adapt it."""
import argparse
import csv
from decimal import Decimal,InvalidOperation
import hashlib
import json
from pathlib import Path

FEATURES=['Fwd Packet Length Max','Fwd IAT Max','Fwd Packet Length Min','Destination Port','Fwd Header Length','Total Fwd Packets']


def inspect(source,output):
    output.mkdir(parents=True,exist_ok=False);valid=invalid=0
    with source.open(encoding='utf-8-sig',newline='') as f,(output/'selected.jsonl').open('w') as dest,(output/'excluded.jsonl').open('w') as excluded:
        reader=csv.reader(f);headers=[h.strip() for h in next(reader)]
        positions={name:[i for i,h in enumerate(headers) if h==name] for name in FEATURES+['Label']}
        if any(len(v)!=1 for v in positions.values()):raise ValueError('Missing/ambiguous selected headers: '+str(positions))
        for number,row in enumerate(reader,2):
            try:
                if len(row)!=len(headers):raise ValueError('Column count differs')
                values=[row[positions[n][0]].strip() for n in FEATURES]
                if any(not Decimal(v).is_finite() for v in values):raise ValueError('Non-finite selected value')
                dest.write(json.dumps(dict(csv_line=number,raw_cic_values=values,label=row[positions['Label'][0]].strip()))+'\n');valid+=1
            except (ValueError,InvalidOperation) as error:
                excluded.write(json.dumps(dict(csv_line=number,error=str(error)))+'\n');invalid+=1
    # Streaming hash avoids loading a potentially large numeric CSV into RAM.
    h=hashlib.sha256()
    with source.open('rb') as f:
        for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
    result=dict(status='PASS',source=str(source),sha256=h.hexdigest(),positions=positions,valid=valid,excluded=invalid,
                units='Original CIC values preserved; IAT normally microseconds; payload/segment definitions require producer audit',
                evaluation='NOT RUN: feature/checkpoint compatibility unresolved')
    (output/'inspection.json').write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(inspect(a.input,a.output),indent=2))
