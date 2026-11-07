#!/usr/bin/env python3
"""Concurrent bounded benign TCP sink; records identities and hashes, never payloads."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import sys
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import token,ipv4,MAX_CASES,MAX_PAYLOAD


def serve(args):
    if os.geteuid()==0:raise RuntimeError('Run the TCP application server as an ordinary user')
    done=threading.Event();lock=threading.Lock();slots=threading.BoundedSemaphore(32)
    signal.signal(signal.SIGTERM,lambda *_:done.set());signal.signal(signal.SIGINT,lambda *_:done.set())
    def worker(conn):
        event=dict(experiment_id=args.experiment_id,accepted_unix=time.time(),accepted_monotonic_ns=time.monotonic_ns(),case_id=None,
                   client_ip=None,client_port=None,server_ip=None,server_port=None,payload_bytes=0,status='FAIL',error='')
        try:
            with conn:
                conn.settimeout(5);event['client_ip'],event['client_port']=conn.getpeername();event['server_ip'],event['server_port']=conn.getsockname()
                start=time.monotonic();buffer=b''
                while b'\n' not in buffer:
                    part=conn.recv(1)
                    if not part:raise ValueError('Missing experiment header')
                    buffer+=part
                    if len(buffer)>512 or time.monotonic()-start>10:raise ValueError('Header bounds exceeded')
                if not buffer.startswith(b'IDSDEMO1 '):raise ValueError('Wrong protocol')
                metadata=json.loads(buffer[9:]);case=token(metadata['case_id']);event['case_id']=case
                if metadata['experiment_id']!=args.experiment_id:raise ValueError('Wrong experiment ID')
                h=hashlib.sha256()
                while True:
                    if time.monotonic()-start>10:raise TimeoutError('Application deadline')
                    part=conn.recv(4096)
                    if not part:break
                    event['payload_bytes']+=len(part)
                    if event['payload_bytes']>MAX_PAYLOAD:raise ValueError('Payload exceeds 64 KiB')
                    h.update(part)
                reply=dict(experiment_id=args.experiment_id,case_id=case,payload_bytes=event['payload_bytes'],sha256=h.hexdigest(),status='ok')
                conn.sendall((json.dumps(reply,separators=(',',':'))+'\n').encode());event['status']='PASS'
        except (OSError,ValueError,KeyError,TimeoutError) as error:event['error']=str(error)[:500]
        finally:
            event['closed_unix']=time.time();event['closed_monotonic_ns']=time.monotonic_ns()
            with lock:
                with args.events.open('a') as f:f.write(json.dumps(event,separators=(',',':'))+'\n')
            slots.release()
    with socket.socket() as listener,ThreadPoolExecutor(max_workers=32) as pool:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind((args.server_ip,args.port));listener.listen(64);listener.settimeout(.2)
        args.ready.write_text(json.dumps(dict(experiment_id=args.experiment_id,address=listener.getsockname(),uid=os.geteuid()))+'\n')
        accepted=0
        while not done.is_set() and accepted<MAX_CASES:
            if not slots.acquire(timeout=.2):continue
            try:conn,_=listener.accept()
            except socket.timeout:slots.release();continue
            except OSError:slots.release();raise
            accepted+=1;pool.submit(worker,conn)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--server-ip',type=ipv4,default='192.168.77.3');p.add_argument('--port',type=int,default=9000)
    p.add_argument('--experiment-id',type=token,required=True);p.add_argument('--events',type=Path,required=True);p.add_argument('--ready',type=Path,required=True)
    a=p.parse_args()
    if not 1024<=a.port<=65535:p.error('Use an unprivileged TCP port')
    serve(a)
