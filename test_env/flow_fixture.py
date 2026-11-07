"""Bounded real packet/TCP fixtures, restricted to the private Stage02 lab.

Raw frames use a nonlocal unicast destination MAC. TC still observes them, but
PACKET_OTHERHOST prevents the IPv4 stack from generating unsolicited TCP RSTs.
The capture socket's promiscuous membership is scoped to its FD and released
on close. Logs retain only headers/lengths, never application payloads.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import threading
import time

from .lab import CLIENT_IF, CLIENT_IP, CLIENT_NS, SERVER_IF, SERVER_IP, SERVER_NS

DESTINATION_MAC = bytes.fromhex('020000f10401')
SOURCE_MAC = bytes.fromhex('020000f10402')
MAX_CAPTURE = 4096
TCP_PORT = 15041
REQUEST = b'stage04-request'
RESPONSE = b'stage04-response'


def checksum(raw):
    raw += b'\0' * (len(raw) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(raw) // 2), raw))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def tcp_frame(*, reverse=False, sport=41001, dport=15001, flags=16,
              sequence=100, acknowledgement=0, payload=b'', ip_options=b'', tcp_options=b''):
    """Construct genuine IPv4/TCP checksums, including variable header lengths."""
    if len(ip_options) % 4 or len(tcp_options) % 4 or len(ip_options) > 40 or len(tcp_options) > 40:
        raise ValueError('Options must be aligned and at most 40 bytes')
    source, destination = socket.inet_aton(CLIENT_IP), socket.inet_aton(SERVER_IP)
    if reverse:
        source, destination, sport, dport = destination, source, dport, sport
    thl, ihl = 20 + len(tcp_options), 20 + len(ip_options)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, sequence, acknowledgement,
                      (thl // 4) << 4, flags, 4096, 0, 0) + tcp_options
    pseudo = source + destination + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x40 | (ihl // 4), 0, ihl + thl + len(payload),
                     0x404, 0, 64, 6, 0, source, destination) + ip_options
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return DESTINATION_MAC + SOURCE_MAC + b'\x08\x00' + ip + tcp + payload


def controlled_phases():
    """Ordered state boundaries; exact same SYN is an observed retransmission."""
    def frame(**kw):
        return tcp_frame(**kw).hex()
    syn = frame(flags=2, sequence=100)
    return [
        ('syn', [(False, syn), (False, syn),
                 (True, frame(reverse=True, flags=18, sequence=500, acknowledgement=101)),
                 (False, frame(flags=16, sequence=101, acknowledgement=501))]),
        ('options_and_unknown', [
            (False, frame(flags=24, sequence=101, acknowledgement=501, payload=b'abcdefg',
                          ip_options=b'\x01\x01\x01\x00', tcp_options=b'\x01\x01\x01\x00')),
            (True, frame(reverse=True, flags=16, sequence=501, acknowledgement=108)),
            (True, frame(reverse=True, sport=41002, dport=15002, flags=24,
                         sequence=700, payload=b'abc')),
            (False, frame(sport=41002, dport=15002, sequence=800, acknowledgement=703))]),
        ('half_close', [(False, frame(flags=17, sequence=108, acknowledgement=501)),
                        (True, frame(reverse=True, sequence=501, acknowledgement=109))]),
        ('both_fin', [(True, frame(reverse=True, flags=17, sequence=501, acknowledgement=109))]),
        ('full_close', [(False, frame(sequence=109, acknowledgement=502))]),
        ('reuse', [(False, frame(flags=2, sequence=900)),
                   (True, frame(reverse=True, flags=18, sequence=1000, acknowledgement=901)),
                   (False, frame(flags=4, sequence=901, acknowledgement=1001))]),
    ]


def unsupported_frames():
    base = tcp_frame(sport=41003, dport=15003)
    vlan = base[:12] + b'\x81\x00\x00\x01\x08\x00' + base[14:]
    ipv6 = base[:12] + b'\x86\xdd' + bytes(40)
    fragment = bytearray(base)
    fragment[20:22] = b'\x20\x00'
    udp = bytearray(base)
    udp[23] = 17
    bad_ip = bytearray(base)
    bad_ip[14] = 0x44
    bad_tcp = bytearray(base)
    bad_tcp[46] = 0x40
    other_l2 = base[:12] + b'\x88\xb5' + base[14:]
    return {'non_ipv4': other_l2.hex(), 'vlan': vlan.hex(), 'ipv6': ipv6.hex(),
            'fragment': bytes(fragment).hex(),
            'non_tcp': bytes(udp).hex(), 'malformed_ipv4': bytes(bad_ip).hex(),
            'malformed_tcp': bytes(bad_tcp).hex(), 'truncated_tcp': base[:44].hex()}


def _headers(raw):
    # Capture extraction intentionally does not depend on the oracle parser.
    if len(raw) >= 34 and raw[12:14] == b'\x08\x00':
        ihl = (raw[14] & 15) * 4
        start = 14 + ihl
        if ihl >= 20 and raw[23] == 6 and len(raw) >= start + 20:
            return raw[:min(len(raw), start + max(20, (raw[start + 12] >> 4) * 4))]
        return raw[:min(len(raw), 14 + max(20, ihl))]
    if raw[12:14] == b'\x86\xdd':
        return raw[:54]
    if raw[12:14] in (b'\x81\x00', b'\x88\xa8'):
        return raw[:18]
    return raw[:14]


def capture(interface, ready):
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    records, overflow = [], 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.bind((interface, 0))
        membership = struct.pack('IHH8s', socket.if_nametoindex(interface), 1, 0, b'')
        sock.setsockopt(263, 1, membership)  # SOL_PACKET/PACKET_ADD_MEMBERSHIP/PROMISC
        Path(ready).write_text(json.dumps({'status': 'ready', 'interface': interface}), encoding='utf-8')
        deadline = time.monotonic() + 120
        quiet_until = None
        while time.monotonic() < deadline:
            if stopped.is_set() and quiet_until is None:
                quiet_until = time.monotonic() + 0.15
            if quiet_until is not None and time.monotonic() >= quiet_until:
                break
            if not select.select([sock], [], [], 0.05)[0]:
                continue
            raw, address = sock.recvfrom(65535)
            if raw[12:14] not in (b'\x08\x00', b'\x86\xdd', b'\x81\x00', b'\x88\xa8'):
                continue
            if len(records) >= MAX_CAPTURE:
                overflow += 1
            else:
                records.append({'header_hex': _headers(raw).hex(), 'packet_length': len(raw),
                                'packet_type': address[2]})
        received, dropped = struct.unpack('II', sock.getsockopt(263, 6, 8))
    return {'status': 'pass' if stopped.is_set() and not overflow and not dropped else 'fail',
            'records': records, 'socket_packets': received, 'socket_drops': dropped,
            'overflow': overflow, 'promiscuous_membership_released': True}


def send_frames(interface, manifest):
    frames = json.loads(Path(manifest).read_text(encoding='utf-8'))
    if not isinstance(frames, list) or not 1 <= len(frames) <= 256:
        raise ValueError('Raw fixture requires 1..256 frames')
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((interface, 0))
        for raw in frames:
            frame = bytes.fromhex(raw)
            if not 14 <= len(frame) <= 2048 or frame[:6] != DESTINATION_MAC:
                raise ValueError('Refusing a frame outside the controlled nonlocal-MAC fixture')
            if sock.send(frame) != len(frame):
                raise RuntimeError('Short AF_PACKET send')
    return {'status': 'pass', 'sent': len(frames)}


def _receive(conn, expected):
    data = bytearray()
    while len(data) < len(expected):
        part = conn.recv(len(expected) - len(data))
        if not part:
            raise RuntimeError('Early TCP fixture EOF')
        data.extend(part)
    if data != expected:
        raise RuntimeError('TCP fixture content mismatch')
    return len(data)


def tcp_server(ready, count):
    def handle(conn):
        with conn:
            conn.settimeout(10)
            received = _receive(conn, REQUEST)
            conn.sendall(RESPONSE)
            if conn.recv(1):
                raise RuntimeError('Extra TCP fixture data')
            return {'request_bytes': received, 'response_bytes': len(RESPONSE)}
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=count) as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((SERVER_IP, TCP_PORT))
        listener.listen(count)
        listener.settimeout(15)
        Path(ready).write_text(json.dumps({'status': 'ready', 'count': count}), encoding='utf-8')
        work = [pool.submit(handle, listener.accept()[0]) for _ in range(count)]
        results = [future.result() for future in work]
    return {'status': 'pass', 'connections': results}


def tcp_clients(count):
    barrier = threading.Barrier(count)
    def client(_):
        with socket.socket() as conn:
            conn.settimeout(10)
            conn.bind((CLIENT_IP, 0))
            barrier.wait(timeout=10)
            conn.connect((SERVER_IP, TCP_PORT))
            port = conn.getsockname()[1]
            conn.sendall(REQUEST)
            received = _receive(conn, RESPONSE)
            conn.shutdown(socket.SHUT_WR)
            if conn.recv(1):
                raise RuntimeError('Extra TCP response')
        return {'client_port': port, 'server_port': TCP_PORT,
                'request_bytes': len(REQUEST), 'response_bytes': received}
    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(pool.map(client, range(count)))
    return {'status': 'pass', 'connections': results}


class Fixture:
    """Recorder-owned helpers; the caller already owns and guards the lab."""
    def __init__(self, recorder, lab, label):
        self.recorder, self.lab, self.label = recorder, lab, label
        self.capture_process = None
        self.serial = 0

    def _argv(self, namespace, *args):
        interface = SERVER_IF if namespace == SERVER_NS else CLIENT_IF
        self.lab._require_link(interface, namespace)
        return ['nsenter', '--net=/run/netns/' + namespace, '--', sys.executable,
                '-m', 'test_env.flow_fixture', *map(str, args)]

    def _ready(self, proc, path):
        deadline = time.monotonic() + 5
        while True:
            if proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('Flow fixture did not become ready')
            try:
                ready = json.loads(path.read_text(encoding='utf-8'))
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.01)
                continue
            if ready.get('status') != 'ready':
                raise RuntimeError('Flow fixture emitted invalid readiness')
            return ready

    def start_capture(self):
        path = self.recorder.out / (self.label + '-capture-ready.json')
        self.capture_process = self.recorder.spawn(self.label + '-capture',
            self._argv(SERVER_NS, 'capture', '--interface', SERVER_IF, '--ready', path))
        self._ready(self.capture_process, path)

    def send(self, frames):
        # Preserve requested order even when ingress/egress alternate.
        results = []
        groups = []
        for reverse, raw in frames:
            if not groups or groups[-1][0] != reverse:
                groups.append((reverse, []))
            groups[-1][1].append(raw)
        for reverse, batch in groups:
            self.serial += 1
            name = f'{self.label}-frames-{self.serial}.json'
            self.recorder.write_json(name, batch)
            namespace, interface = ((SERVER_NS, SERVER_IF) if reverse else (CLIENT_NS, CLIENT_IF))
            results.append(self.recorder.json(self._argv(namespace, 'send', '--interface', interface,
                                                        '--manifest', self.recorder.out / name)))
        return {'status': 'pass', 'batches': results, 'frames': len(frames)}

    def concurrent_tcp(self, count=8):
        path = self.recorder.out / (self.label + '-tcp-ready.json')
        proc = self.recorder.spawn(self.label + '-tcp-server',
            self._argv(SERVER_NS, 'server', '--ready', path, '--count', count))
        try:
            self._ready(proc, path)
            clients = self.recorder.json(self._argv(CLIENT_NS, 'clients', '--count', count))
            proc.wait(timeout=20)
            self.recorder.stop(proc)
            if proc.returncode != 0:
                raise RuntimeError('Concurrent TCP server failed')
            server = json.loads(proc.stdout_path.read_text(encoding='utf-8'))
            if clients['status'] != 'pass' or server['status'] != 'pass' or len(server['connections']) != count:
                raise RuntimeError('Concurrent TCP endpoint proof failed')
            return {'status': 'pass', 'client': clients, 'server': server, 'count': count}
        finally:
            self.recorder.stop(proc)

    def stop_capture(self):
        if self.capture_process is None:
            return None
        proc, self.capture_process = self.capture_process, None
        code = self.recorder.stop(proc)
        result = json.loads(proc.stdout_path.read_text(encoding='utf-8'))
        if code != 0 or result['status'] != 'pass':
            raise RuntimeError('AF_PACKET capture failed or dropped packets')
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('capture', 'send', 'server', 'clients'))
    parser.add_argument('--interface', choices=(CLIENT_IF, SERVER_IF))
    parser.add_argument('--manifest')
    parser.add_argument('--ready')
    parser.add_argument('--count', type=int, choices=range(1, 17), default=8)
    args = parser.parse_args(argv)
    try:
        if args.command == 'capture':
            result = capture(args.interface, args.ready)
        elif args.command == 'send':
            result = send_frames(args.interface, args.manifest)
        elif args.command == 'server':
            result = tcp_server(args.ready, args.count)
        else:
            result = tcp_clients(args.count)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({'status': 'fail', 'error': str(exc)}), file=sys.stderr, flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
