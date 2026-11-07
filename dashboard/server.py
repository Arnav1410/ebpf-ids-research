#!/usr/bin/env python3
"""Unprivileged, loopback-only HTTP views of one fixed collector file."""
import argparse
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

ASSETS=Path(__file__).resolve().parent/'static'
LIMIT=32*1024*1024


def read_state(path,now=None):
    now=time.time() if now is None else now
    try:
        with path.open('rb') as f:data=f.read(LIMIT+1)
        if len(data)>LIMIT:raise ValueError('Telemetry exceeds bounded snapshot size')
        value=json.loads(data)
        if not isinstance(value,dict):raise ValueError('Telemetry must be an object')
        if value.get('schema')!=1 or value.get('source')!='LIVE':raise ValueError('Not a live collector snapshot')
        age=now-value.get('collected_unix',0)
        value['age_seconds']=max(0,age)
        if value.get('status')=='CONNECTED' and (age>5 or age< -5):
            value['status']='STALE';value['errors']=value.get('errors',[])+['Collector update is stale or wall clock changed']
        return value
    except FileNotFoundError:
        return dict(schema=1,source='LIVE',status='DISCONNECTED',errors=['No IDS collector snapshot'],flows=[])
    except (OSError,ValueError,TypeError) as error:
        return dict(schema=1,source='LIVE',status='ERROR',errors=[str(error)],flows=[])


def handler(state_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass

        def respond(self,code,data,content_type='text/plain; charset=utf-8'):
            self.send_response(code);self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY')
            self.send_header('Content-Security-Policy',"default-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'")
            self.end_headers()
            if self.command!='HEAD':
                try:self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError):pass

        def do_GET(self):
            host=self.headers.get('Host','').split(':',1)[0]
            if host not in ('localhost','127.0.0.1'):self.respond(403,b'Loopback Host required\n');return
            path=urlsplit(self.path).path
            if path=='/api/state':
                data=json.dumps(read_state(state_path),separators=(',',':')).encode()
                self.respond(200,data,'application/json; charset=utf-8');return
            assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),
                    '/style.css':('style.css','text/css; charset=utf-8')}
            if path not in assets:self.respond(404,b'Not found\n');return
            name,kind=assets[path];self.respond(200,(ASSETS/name).read_bytes(),kind)

        do_HEAD=do_GET
        def do_POST(self):self.respond(405,b'Read-only dashboard\n')
        do_PUT=do_DELETE=do_PATCH=do_OPTIONS=do_POST
    return Handler


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state',type=Path,default=Path('/run/nn-ebpf-ids/telemetry.json'))
    p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port',type=int,default=8080)
    args=p.parse_args()
    if os.geteuid()==0:p.error('Run the HTTP dashboard without sudo; the collector is a separate privileged process')
    if args.bind!='127.0.0.1' or not 1<=args.port<=65535:p.error('Use 127.0.0.1 and port 1..65535')
    server=ThreadingHTTPServer((args.bind,args.port),handler(args.state))
    server.daemon_threads=True
    print(f'Read-only dashboard: http://{args.bind}:{args.port}/ ; source LIVE collector {args.state}',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()


if __name__=='__main__':main()
