"""Controlled TCP exchange, only run inside the demo network namespaces."""
import json
from pathlib import Path
import socket
import sys

if sys.argv[1] == 'server':
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(15)
        s.bind(('33.33.33.1', 5001)); s.listen(1)
        Path(sys.argv[2]).write_text('ready\n')
        with s.accept()[0] as conn:
            conn.settimeout(15)
            assert conn.getpeername()[0] == '33.33.33.73'
            data = b''
            while True:
                block = conn.recv(1024)
                if not block: break
                data += block
                assert len(data) <= 1024
            assert data == b'hello\n'
            conn.sendall(b'tc-demo-ok\n')
            print(json.dumps(dict(greeting=data.decode(), client_fin=True)), flush=True)
else:
    with socket.socket() as s:
        s.settimeout(15)
        s.bind(('33.33.33.73', int(sys.argv[2])))
        s.connect(('33.33.33.1', 5001))
        s.sendall(b'hello\n'); s.shutdown(socket.SHUT_WR)
        reply = b''
        while True:
            block = s.recv(1024)
            if not block: break
            reply += block
            assert len(reply) <= 1024
        assert reply == b'tc-demo-ok\n'
        print(json.dumps(dict(response=reply.decode(), source_port=int(sys.argv[2]))))
