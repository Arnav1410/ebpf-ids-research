"""Portable protocol/scenario validation shared by Windows client and TCP server."""
import csv
import ipaddress
import json
from pathlib import Path
import re

MAX_CASES=128;MAX_CONCURRENCY=32;MAX_PAYLOAD=65536;MAX_TOTAL=8*1024*1024
TOKEN=re.compile(r'^[A-Za-z0-9_-]{1,64}$')


def token(value):
    if not TOKEN.fullmatch(value):raise ValueError('Invalid case/experiment identifier')
    return value


def ipv4(value):return str(ipaddress.IPv4Address(value))


def scenarios(path,count=None):
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        reader=csv.DictReader(f);rows=[];seen=set()
        for source in reader:
            if count is not None and len(rows)>=count:break
            if len(rows)>=MAX_CASES:raise ValueError('At most 128 scenarios per run')
            case=token(source['case_id'])
            if case in seen:raise ValueError('Duplicate case ID')
            seen.add(case);label=source.get('ground_truth','').strip().lower() or 'unknown'
            if label not in ('benign','unknown'):raise ValueError('This client generates ordinary benign TCP only; do not manufacture intrusion labels')
            provenance=source.get('ground_truth_provenance','').strip()
            if label!='unknown' and not provenance:raise ValueError('Known truth requires independent provenance')
            length=int(source['payload_length']);chunks=int(source['chunks']);delay=int(source['delay_ms'])
            if not 0<=length<=MAX_PAYLOAD or not 1<=chunks<=64 or not 0<=delay<=50:raise ValueError('Scenario exceeds safe bounds')
            expect=source.get('response_expectation','ack')
            if expect!='ack':raise ValueError('Only deterministic acknowledgement is supported')
            rows.append(dict(case_id=case,ground_truth=label,ground_truth_provenance=provenance,payload_length=length,
                             chunks=chunks,delay_ms=delay,response_expectation=expect,notes=source.get('notes','')))
    if not rows or count is not None and len(rows)!=count:raise ValueError('--count must select an available nonempty prefix')
    if sum(r['payload_length'] for r in rows)>MAX_TOTAL:raise ValueError('Aggregate payload exceeds 8 MiB')
    return rows


def header(experiment,case):
    return ('IDSDEMO1 '+json.dumps(dict(experiment_id=token(experiment),case_id=token(case)),separators=(',',':'))+'\n').encode('ascii')


def canonical(client_ip,client_port,server_ip,server_port):
    a,b=sorted(((ipv4(client_ip),int(client_port)),(ipv4(server_ip),int(server_port))),key=lambda p:(int(ipaddress.IPv4Address(p[0])),p[1]))
    return f'6|{a[0]}:{a[1]}|{b[0]}:{b[1]}'


CLIENT_FIELDS=('experiment_id','case_id','protocol','ground_truth','ground_truth_provenance','client_ip','client_port','server_ip','server_port',
               'start_unix','end_unix','bytes_sent','payload_bytes_sent','bytes_received','completion','error','notes')


def write_csv(path,rows,fields):
    with Path(path).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
