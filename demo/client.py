#!/usr/bin/env python3
"""Windows-native Python 3 client. No WSL, administrator rights or third-party modules."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import platform
import socket
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import scenarios,header,ipv4,token,write_csv,CLIENT_FIELDS,MAX_CONCURRENCY


def connection(row,args):
    result=dict(experiment_id=args.experiment_id,case_id=row['case_id'],protocol=6,ground_truth=row['ground_truth'],
        ground_truth_provenance=row['ground_truth_provenance'],client_ip='',client_port='',server_ip=args.server_ip,server_port=args.port,
        start_unix=time.time(),end_unix=None,bytes_sent=0,payload_bytes_sent=0,bytes_received=0,
        completion='FAIL',error='',notes=row['notes'])
    deadline=time.monotonic()+15
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(5);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            s.bind((args.source_ip,0));result['client_ip'],result['client_port']=s.getsockname()
            s.connect((args.server_ip,args.port))
            result['client_ip'],result['client_port']=s.getsockname();result['server_ip'],result['server_port']=s.getpeername()
            def send(data,payload=False):
                remaining=memoryview(data)
                while remaining:
                    if time.monotonic()>deadline:raise TimeoutError('Connection deadline')
                    n=s.send(remaining)
                    if n==0:raise ConnectionError('Socket closed during send')
                    remaining=remaining[n:];result['bytes_sent']+=n
                    if payload:result['payload_bytes_sent']+=n
            send(header(args.experiment_id,row['case_id']))
            payload=b'A'*row['payload_length'];offset=0
            for i in range(row['chunks']):
                end=(i+1)*len(payload)//row['chunks'];send(payload[offset:end],True);offset=end
                if row['delay_ms'] and i+1<row['chunks']:time.sleep(row['delay_ms']/1000)
            s.shutdown(socket.SHUT_WR) # Ordered FIN; keep reading the server leg.
            data=b''
            while True:
                if time.monotonic()>deadline:raise TimeoutError('Response deadline')
                part=s.recv(4096)
                if not part:break
                result['bytes_received']+=len(part);data+=part
                if len(data)>4096:raise ValueError('Oversized acknowledgement')
            reply=json.loads(data)
            expected=dict(experiment_id=args.experiment_id,case_id=row['case_id'],payload_bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),status='ok')
            if reply!=expected:raise ValueError('Wrong server acknowledgement/run identity')
            result['completion']='PASS'
    except (OSError,ValueError,TimeoutError) as error:result['error']=str(error)[:500]
    result['end_unix']=time.time();return result


def run(args):
    rows=scenarios(args.input,args.count)
    if not 1<=args.concurrency<=MAX_CONCURRENCY:raise ValueError('Concurrency must be 1..32')
    args.output.mkdir(parents=True,exist_ok=False)
    # executor.map retains CSV order; ordering is never used to join predictions.
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:results=list(pool.map(lambda r:connection(r,args),rows))
    write_csv(args.output/'client_results.csv',results,CLIENT_FIELDS)
    report=dict(experiment_id=args.experiment_id,source='Actual ordinary TCP sockets',platform=platform.platform(),
        input_count=len(rows),requested_concurrency=args.concurrency,completed=sum(r['completion']=='PASS' for r in results),
        failed=sum(r['completion']!='PASS' for r in results),bytes_sent=sum(r['bytes_sent'] for r in results),
        bytes_received=sum(r['bytes_received'] for r in results),input_sha256=hashlib.sha256(args.input.read_bytes()).hexdigest())
    (args.output/'client_summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    return int(report['failed']>0)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--count',type=int)
    p.add_argument('--concurrency',type=int,default=10);p.add_argument('--server-ip',type=ipv4,default='192.168.77.3')
    p.add_argument('--source-ip',type=ipv4,default='192.168.77.2');p.add_argument('--port',type=int,default=9000)
    p.add_argument('--experiment-id',type=token,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not 1<=a.port<=65535 or a.count is not None and not 1<=a.count<=128:p.error('Invalid bounded count/port')
    return run(a)


if __name__=='__main__':raise SystemExit(main())
