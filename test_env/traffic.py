"""One bounded, harmless TCP request/response inside the owned namespaces."""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

from .lab import CLIENT_IP, SERVER_IP

PORT = 5001
REQUEST = b"nn-ebpf-stage02-request\n"
RESPONSE = b"nn-ebpf-stage02-response\n"


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("TCP fixture deadline expired")
    return remaining


def _receive(conn, expected, deadline):
    data = bytearray()
    while len(data) < len(expected):
        conn.settimeout(_remaining(deadline))
        chunk = conn.recv(len(expected) - len(data))
        if not chunk:
            raise RuntimeError("TCP peer closed before the complete fixed payload")
        data.extend(chunk)
    if data != expected:
        raise RuntimeError("TCP payload differs from the fixed harmless fixture")
    return len(data)


def serve(ready, reset=False, seconds=15):
    deadline = time.monotonic() + seconds
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((SERVER_IP, PORT))
        listener.listen(1)
        with Path(ready).open("x", encoding="utf-8") as stream:
            json.dump({"pid": os.getpid(), "server_ip": SERVER_IP, "server_port": PORT,
                       "reset": reset}, stream)
            stream.write("\n")
        listener.settimeout(_remaining(deadline))
        conn, peer = listener.accept()
        with conn:
            if peer[0] != CLIENT_IP:
                raise RuntimeError("Unexpected client source address")
            received = _receive(conn, REQUEST, deadline)
            conn.settimeout(_remaining(deadline))
            conn.sendall(RESPONSE)
            conn.settimeout(_remaining(deadline))
            try:
                extra = conn.recv(1)
            except ConnectionResetError:
                if not reset:
                    raise RuntimeError("Unexpected reset in graceful fixture") from None
                close_kind = "reset"
            else:
                if extra:
                    raise RuntimeError("Unexpected extra client payload")
                if reset:
                    raise RuntimeError("Expected client RST, observed graceful close")
                close_kind = "fin"
            return {"status": "pass", "role": "server", "server_ip": SERVER_IP,
                    "server_port": PORT, "client_ip": peer[0], "client_port": peer[1],
                    "request_bytes": received, "response_bytes": len(RESPONSE),
                    "peer_close": close_kind, "expected_reset_observed": reset}


def client(reset=False, seconds=15):
    deadline = time.monotonic() + seconds
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(_remaining(deadline))
        conn.bind((CLIENT_IP, 0))
        conn.connect((SERVER_IP, PORT))
        client_port = conn.getsockname()[1]
        conn.settimeout(_remaining(deadline))
        conn.sendall(REQUEST)
        received = _receive(conn, RESPONSE, deadline)
        if reset:
            # Do not enable abortive close until the real response was received.
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        else:
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(_remaining(deadline))
            if conn.recv(1):
                raise RuntimeError("Unexpected extra server payload")
    return {"status": "pass", "role": "client", "client_ip": CLIENT_IP,
            "client_port": client_port, "server_ip": SERVER_IP, "server_port": PORT,
            "request_bytes": len(REQUEST), "response_bytes": received,
            "close": "reset" if reset else "fin", "response_verified_before_close": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("server", "client"):
        command = commands.add_parser(name)
        command.add_argument("--reset", action="store_true")
        command.add_argument("--seconds", type=int, default=15, choices=range(1, 31))
        if name == "server":
            command.add_argument("--ready", required=True)
    args = parser.parse_args(argv)
    try:
        result = (serve(args.ready, args.reset, args.seconds) if args.command == "server"
                  else client(args.reset, args.seconds))
    except (OSError, RuntimeError) as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}), file=sys.stderr, flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
