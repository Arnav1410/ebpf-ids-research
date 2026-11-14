"""Controlled TCP exchanges, only inside the demo namespaces."""
import json
from pathlib import Path
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
import threading


def serve_connection(conn,repeat=1):
    with conn:
        conn.settimeout(15)
        assert conn.getpeername()[0] == '33.33.33.73'
        data = b''
        while True:
            block = conn.recv(1024)
            if not block: break
            data += block
            assert len(data) <= 1024
        assert data == b'hello\n'*repeat
        conn.sendall(b'tc-demo-ok\n')
        return dict(greeting_repetitions=repeat,greeting_bytes=len(data),client_fin=True,source_port=conn.getpeername()[1])


def client(port, barrier=None, repeat=1):
    with socket.socket() as s:
        s.settimeout(15)
        s.bind(('33.33.33.73', port))
        if barrier: barrier.wait(timeout=15)
        s.connect(('33.33.33.1', 5001))
        if repeat>1:s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        for _ in range(repeat):s.sendall(b'hello\n')
        s.shutdown(socket.SHUT_WR)
        reply = b''
        while True:
            block = s.recv(1024)
            if not block: break
            reply += block
            assert len(reply) <= 1024
        assert reply == b'tc-demo-ok\n'
        return dict(response=reply.decode(), source_port=port)


if __name__ == '__main__':
    if sys.argv[1] == 'server':
        count = int(sys.argv[3]) if len(sys.argv)>3 else 1
        repeat=int(sys.argv[4]) if len(sys.argv)>4 else 1
        with socket.socket() as s, ThreadPoolExecutor(max_workers=count) as pool:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(15); s.bind(('33.33.33.1', 5001)); s.listen(max(16,count))
            Path(sys.argv[2]).write_text('ready\n')
            jobs = [pool.submit(serve_connection, s.accept()[0],repeat) for _ in range(count)]
            for job in jobs: print(json.dumps(job.result()), flush=True)
    else:
        count = int(sys.argv[3]) if len(sys.argv)>3 else 1
        repeat=int(sys.argv[4]) if len(sys.argv)>4 else 1
        barrier = threading.Barrier(count) if count>1 else None
        with ThreadPoolExecutor(max_workers=count) as pool:
            jobs = [pool.submit(client,int(sys.argv[2])+i,barrier,repeat) for i in range(count)]
            for job in jobs: print(json.dumps(job.result()), flush=True)
