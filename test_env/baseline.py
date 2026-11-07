"""Original XDP ABI adapter and private, metadata-only packet observer.

This is deliberately the only test-environment module that knows the original
program names, global pins, map layout, or model feature order. No trace_pipe
reader is used: the final logits are read from this run's directional flow.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from evaluation.model import infer, load_model, pack_model
from .lab import CLIENT_IP, SERVER_IP, SERVER_IF, SERVER_NS


PINS = {name: Path('/sys/fs/bpf') / name for name in ('nn_idx', 'nn_parameters')}
STAGES = ('xdp_preprocessing', 'xdp_input_linear', 'xdp_input_relu',
          'xdp_hidden_linear', 'xdp_hidden_relu', 'xdp_output_linear')
ROOT = Path(__file__).resolve().parents[1]


class _Flow(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int32) for name in ('saddr', 'sport', 'daddr', 'dport')]


class _Attribute(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int64) for name in (
        'num_packet', 'min_packet_length', 'max_packet_length', 'max_duration',
        'dst_port', 'header_length', 'last_packet_time', 'status')]
    _fields_ += [('total_feature_extraction_time', ctypes.c_uint64),
                 ('detection_start_time', ctypes.c_uint64), ('nn_idx', ctypes.c_int32),
                 ('hidden1', ctypes.c_int32 * 32), ('hidden2', ctypes.c_int32 * 32)]


def _need(condition, message):
    if not condition:
        raise RuntimeError(message)


def _object(value):
    # Some bpftool versions wrap individual objects in singleton arrays.
    if isinstance(value, list):
        _need(len(value) == 1, 'Expected a singleton BPF object')
        value = value[0]
    _need(isinstance(value, dict), 'Expected a BPF object')
    return value


def _raw(value):
    _need(isinstance(value, list), 'Expected default bpftool raw byte array')
    return bytes(int(item, 16) if isinstance(item, str) else item for item in value)


def _loader_ids(proc):
    """Prove ownership using the actual loader's still-open BPF descriptors."""
    result = {'map': set(), 'prog': set()}
    if proc is None or proc.poll() is not None:
        return result
    try:
        paths = list(Path(f'/proc/{proc.pid}/fdinfo').iterdir())
    except FileNotFoundError:
        return result
    for path in paths:
        try:
            text = path.read_text()
        except FileNotFoundError:
            continue
        for line in text.splitlines():
            for kind in result:
                if line.startswith(kind + '_id:'):
                    result[kind].add(int(line.split(':', 1)[1]))
    return result


class _Baseline:
    def __init__(self, recorder, bpftool):
        self.recorder = recorder
        self.tool = str(bpftool.resolve())
        self.loader = None
        self.capture = None
        self.owned = {'map': set(), 'prog': set()}
        self.pins = {}

    def bpf(self, *args, network=False):
        argv = [self.tool, '-j', *map(str, args)]
        if network:
            argv = ['ip', 'netns', 'exec', SERVER_NS, *argv]
        return self.recorder.json(argv)

    def lookup(self, map_id, key):
        entry = _object(self.bpf('map', 'lookup', 'id', map_id, 'key', 'hex',
                                 *[f'{byte:02x}' for byte in key]))
        return _raw(entry['value'])

    def remember(self):
        ids = _loader_ids(self.loader)
        for kind in ids:
            self.owned[kind].update(ids[kind])
        for name, path in PINS.items():
            if os.path.lexists(path):
                info = _object(self.bpf('map', 'show', 'pinned', path))
                if info['id'] in self.owned['map']:
                    previous = self.pins.get(name)
                    _need(previous in (None, info['id']), f'Owned pin changed: {path}')
                    self.pins[name] = info['id']

    def ready(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.remember()
            _need(self.loader.poll() is None, 'Original loader exited before readiness')
            net = _object(self.bpf('net', 'show', 'dev', SERVER_IF, network=True))
            entries = net.get('xdp', [])
            if len(self.pins) == 2 and entries:
                _need(len(entries) == 1, 'Expected exactly one lab XDP attachment')
                entry = entries[0]
                program = _object(self.bpf('prog', 'show', 'id', entry['id']))
                _need(program['name'] == 'xdp_prog' and program['type'] == 'xdp',
                      'Attachment is not the original XDP entry program')
                _need(program['id'] in self.owned['prog'], 'Entry program is not loader-owned')
                maps = {}

                def collect(prog):
                    for map_id in prog.get('map_ids', []):
                        info = _object(self.bpf('map', 'show', 'id', map_id))
                        _need(map_id in self.owned['map'], 'Program references a non-owned map')
                        previous = maps.get(info['name'])
                        _need(previous is None or previous['id'] == map_id,
                              f'Inference chain disagrees on map {info["name"]}')
                        maps[info['name']] = info

                collect(program)
                _need('progs' in maps, 'Entry program lacks its tail-call map')
                stages = []
                for slot, name in enumerate(STAGES):
                    value = self.lookup(maps['progs']['id'], struct.pack('=I', slot))
                    _need(len(value) == 4, 'Unexpected tail-call slot ABI')
                    stage_id = struct.unpack('=I', value)[0]
                    stage = _object(self.bpf('prog', 'show', 'id', stage_id))
                    _need(stage['type'] == 'xdp' and stage['name'] in (name, name[:15]),
                          f'Tail-call slot {slot} is not {name}')
                    _need(stage_id in self.owned['prog'], 'Tail-call program is not loader-owned')
                    collect(stage)
                    stages.append({'slot': slot, 'expected_name': name, 'program': stage})
                expected = {'progs': ('prog_array', 4, 4, 1024),
                            'flow_map': ('hash', 16, 344, 8192),
                            'nn_idx': ('array', 4, 4, 1),
                            'nn_parameters': ('array', 4, 5216, 2)}
                for name, dimensions in expected.items():
                    info = maps[name]
                    actual = tuple(info.get(key) for key in
                                   ('type', 'bytes_key', 'bytes_value', 'max_entries'))
                    _need(actual == dimensions, f'Unexpected original map ABI for {name}: {actual}')
                for name, map_id in self.pins.items():
                    _need(maps[name]['id'] == map_id, 'Global pin is not shared by this chain')
                initial = struct.unpack('=i', self.lookup(maps['nn_idx']['id'], bytes(4)))[0]
                _need(initial == 1, f'Original loader initial index is not 1: {initial}')
                state = {'network': net, 'program': program, 'stages': stages,
                         'maps': maps, 'pins': self.pins.copy(), 'initial_index': initial}
                self.recorder.write_json('baseline-ready.json', state)
                return state
            time.sleep(0.1)
        raise RuntimeError('Timed out waiting for loader-owned pins and actual XDP attachment')

    def cleanup(self):
        errors = []
        if self.capture is not None:
            try:
                self.recorder.stop(self.capture)
            except Exception as exc:
                errors.append(f'Capture cleanup: {exc}')
        if self.loader is not None:
            try:
                self.remember()
            except Exception as exc:
                errors.append(f'Ownership snapshot: {exc}')
            if self.loader.poll() is None:
                # SIGINT invokes the original unconditional unlink logic. Never
                # invoke that handler when either global name is no longer ours.
                safe = True
                for name, path in PINS.items():
                    try:
                        current = _object(self.bpf('map', 'show', 'pinned', path))['id']
                        _need(current == self.pins.get(name), f'Pin identity changed: {path}')
                    except Exception as exc:
                        safe = False
                        errors.append(f'Refusing loader unlink handler: {exc}')
                try:
                    self.recorder.stop(self.loader, sig=signal.SIGINT if safe else signal.SIGTERM)
                except Exception as exc:
                    errors.append(f'Loader cleanup: {exc}')
        for name, path in PINS.items():
            try:
                if os.path.lexists(path):
                    current = _object(self.bpf('map', 'show', 'pinned', path))['id']
                    _need(current == self.pins.get(name), f'Refusing to remove foreign pin {path}')
                    path.unlink()
                _need(not os.path.lexists(path), f'Owned pin remains: {path}')
            except Exception as exc:
                errors.append(str(exc))
        network = None
        remaining = {}
        try:
            network = self.bpf('net', 'show', 'dev', SERVER_IF, network=True)
            _need(not _object(network).get('xdp'), 'XDP remains attached to owned lab interface')
            # A positive global enumeration is stronger than interpreting a
            # failed individual lookup as proof that an object disappeared.
            deadline = time.monotonic() + 5
            while True:
                remaining = {}
                for kind in ('prog', 'map'):
                    objects = self.bpf(kind, 'show')
                    if isinstance(objects, dict):
                        objects = [objects]
                    remaining[kind] = sorted(self.owned[kind].intersection(
                        obj['id'] for obj in objects))
                if not any(remaining.values()) or time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            _need(not any(remaining.values()), f'Owned BPF objects remain: {remaining}')
        except Exception as exc:
            errors.append(f'Detachment verification: {exc}')
        result = {'complete': not errors, 'errors': errors, 'network_after': network,
                  'remaining_owned_ids': remaining,
                  'owned_ids': {kind: sorted(ids) for kind, ids in self.owned.items()},
                  'pins': self.pins.copy()}
        self.recorder.write_json('baseline-cleanup.json', result)
        return result


def _packet_metadata(frame, timestamp):
    """Decode Ethernet/IPv4/TCP independently; retain no packet payload bytes."""
    if len(frame) < 34 or struct.unpack_from('!H', frame, 12)[0] != 0x0800:
        return None
    start = 14
    version, ihl = frame[start] >> 4, (frame[start] & 15) * 4
    if version != 4 or ihl < 20 or len(frame) < start + ihl + 20:
        return None
    total = struct.unpack_from('!H', frame, start + 2)[0]
    fragment = struct.unpack_from('!H', frame, start + 6)[0]
    if frame[start + 9] != socket.IPPROTO_TCP or fragment & 0x3fff:
        return None
    src = socket.inet_ntoa(frame[start + 12:start + 16])
    dst = socket.inet_ntoa(frame[start + 16:start + 20])
    tcp = start + ihl
    sport, dport = struct.unpack_from('!HH', frame, tcp)
    if (src, dst, dport) != (CLIENT_IP, SERVER_IP, 5001):
        return None
    doff = (frame[tcp + 12] >> 4) * 4
    _need(total >= ihl + doff and doff >= 20 and len(frame) >= start + total,
          'Malformed or truncated controlled TCP packet')
    _need(ihl == 20, 'Original XDP parser does not support IPv4 options')
    return {'monotonic_ns': timestamp, 'source': src, 'destination': dst,
            'source_port': sport, 'destination_port': dport, 'ipv4_header_bytes': ihl,
            'ipv4_total_bytes': total, 'tcp_segment_bytes': total - ihl,
            'tcp_header_bytes': doff, 'tcp_flags': frame[tcp + 13]}


def _capture(interface, ready, output, seconds):
    records = []
    started = time.monotonic_ns()
    deadline = time.monotonic() + seconds
    result = {'complete': False, 'packets': records, 'started_monotonic_ns': started,
              'payload_recorded': False}
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
            sock.bind((interface, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.settimeout(0.2)
            with Path(ready).open('x') as stream:
                json.dump({'ready_monotonic_ns': time.monotonic_ns()}, stream)
            while time.monotonic() < deadline:
                try:
                    frame, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                # Only server ingress, not copies of server outgoing packets.
                if address[2] == socket.PACKET_OUTGOING:
                    continue
                metadata = _packet_metadata(frame, time.monotonic_ns())
                if metadata is None:
                    continue
                records.append(metadata)
                _need(len(records) <= 1024, 'Controlled capture exceeded packet bound')
                if metadata['tcp_flags'] & 0x04:
                    result['complete'] = True
                    break
            statistics = sock.getsockopt(263, 6, 12)  # SOL_PACKET / PACKET_STATISTICS
            received, dropped = struct.unpack_from('=II', statistics)
            result.update({'socket_received_packets': received, 'socket_dropped_packets': dropped})
            _need(result['complete'], 'Capture deadline expired without client RST')
            _need(dropped == 0, 'Packet socket dropped packets')
    except Exception as exc:
        result['error'] = str(exc)
        raise
    finally:
        result['finished_monotonic_ns'] = time.monotonic_ns()
        with Path(output).open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')


def _live(adapter, lab, state, model, active):
    recorder = adapter.recorder
    ready = recorder.out / 'baseline-capture-ready.json'
    output = recorder.out / 'baseline-capture.json'
    adapter.capture = recorder.spawn('baseline-capture', [
        'ip', 'netns', 'exec', SERVER_NS, sys.executable, '-B', '-m', 'test_env.baseline',
        'capture', '--interface', SERVER_IF, '--ready', str(ready.resolve()),
        '--output', str(output.resolve()), '--seconds', '15'])
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        _need(adapter.capture.poll() is None, 'Metadata observer exited before readiness')
        time.sleep(0.02)
    _need(ready.exists(), 'Metadata observer readiness deadline expired')
    # This window bounds BPF monotonic clocks, not exact wire timing. AF_PACKET
    # userspace arrival timestamps cannot reproduce bpf_ktime_get_ns exactly.
    operation_start = time.monotonic_ns()
    exchange = lab.exchange(reset=True)
    try:
        returncode = adapter.capture.wait(timeout=18)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Metadata observer did not finish after TCP exchange') from exc
    recorder.stop(adapter.capture)
    _need(returncode == 0, 'Metadata observer failed; see its stderr and capture JSON')
    capture = json.loads(output.read_text())
    _need(capture.get('complete') and capture.get('socket_dropped_packets') == 0,
          'Incomplete or lossy controlled capture')
    packets = capture['packets']
    _need(bool(packets), 'No controlled client packets observed')
    _need(all(packet['source_port'] == exchange['client_port'] and
              packet['destination_port'] == exchange['server_port'] for packet in packets),
          'Capture includes a different controlled-address flow')
    _need(packets[-1]['tcp_flags'] & 0x04, 'Final client packet is not RST')
    _need(not any(packet['tcp_flags'] & 0x05 for packet in packets[:-1]),
          'An earlier FIN/RST would make final inference ambiguous')
    source_ip = int.from_bytes(socket.inet_aton(CLIENT_IP), sys.byteorder)
    destination_ip = int.from_bytes(socket.inet_aton(SERVER_IP), sys.byteorder)
    key = struct.pack('=IIII', source_ip, socket.htons(exchange['client_port']),
                      destination_ip, socket.htons(exchange['server_port']))
    value = adapter.lookup(state['maps']['flow_map']['id'], key)
    operation_end = time.monotonic_ns()
    _need(len(value) == ctypes.sizeof(_Attribute), 'Unexpected flow value length')
    attr = _Attribute.from_buffer_copy(value)
    actual = {name: int(getattr(attr, name)) for name, kind in _Attribute._fields_
              if name not in ('hidden1', 'hidden2')}
    independently_expected = {
        'num_packet': len(packets),
        'max_packet_length': max(packet['tcp_segment_bytes'] for packet in packets),
        'min_packet_length': min(packet['tcp_segment_bytes'] for packet in packets),
        'dst_port': exchange['server_port'],
        'header_length': sum(packet['tcp_header_bytes'] for packet in packets)}
    checks = {name: {'expected': expected, 'actual': actual[name],
                     'pass': actual[name] == expected}
              for name, expected in independently_expected.items()}
    _need(all(check['pass'] for check in checks.values()), f'Independent feature mismatch: {checks}')
    span = operation_end - operation_start
    timing = {'operation_start_monotonic_ns': operation_start,
              'operation_end_monotonic_ns': operation_end,
              'max_duration_within_operation': 0 <= attr.max_duration <= span,
              'last_packet_within_operation': operation_start <= attr.last_packet_time <= operation_end,
              'detection_within_operation': attr.last_packet_time <= attr.detection_start_time <= operation_end,
              'extraction_within_operation': 0 <= attr.total_feature_extraction_time <= span,
              'comparison': 'bounds only; packet-socket receive times are not exact BPF wire times'}
    _need(all(timing[name] for name in ('max_duration_within_operation',
          'last_packet_within_operation', 'detection_within_operation',
          'extraction_within_operation')), f'Kernel timestamps out of measured window: {timing}')
    _need(attr.nn_idx == active, 'Flow used an unexpected model slot')
    features = [attr.max_packet_length, attr.max_duration, attr.min_packet_length,
                attr.dst_port, attr.header_length, attr.num_packet]
    oracle = infer(model, features)
    logits = list(attr.hidden1[:2])
    _need(any(oracle['output']), 'Oracle logits are all zero; scratch cannot prove tail-chain execution')
    _need(logits == oracle['output'], f'Kernel logits {logits} differ from oracle {oracle["output"]}')
    result = {'exchange': exchange, 'directional_key_hex': key.hex(),
              'flow_value_hex': value.hex(), 'flow': actual, 'features': features,
              'independent_feature_checks': checks, 'timing': timing,
              'kernel_logits': logits, 'oracle_logits': oracle['output'],
              'derived_logit_label': oracle['label'], 'label_semantics': 'unknown',
              'bpf_printk_observed': False,
              'label_evidence': 'derived from map logits; not a directly observed BPF printk',
              'capture_file': output.name, 'tail_chain_live_match': True}
    recorder.write_json('baseline-live.json', result)
    return result


def run_baseline(recorder, lab, loader: Path, updater: Path, bpftool: Path):
    """Validate and clean one original XDP run inside the caller's owned lab."""
    _need(ctypes.sizeof(_Flow) == 16 and ctypes.sizeof(_Attribute) == 344 and
          _Attribute.nn_idx.offset == 80 and _Attribute.hidden1.offset == 84,
          'Host ctypes layout differs from original BPF ABI')
    model = load_model(ROOT / 'src/mlp_params.bpf.h')
    expected = pack_model(model)
    _need(len(expected) == 5216, 'Original model ABI is not 5216 bytes')
    adapter = _Baseline(recorder, Path(bpftool))
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    lock = os.open('/run/nn-ebpf-baseline.lock', flags, 0o600)
    result = {}
    cleanup = None
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for path in PINS.values():
            _need(not os.path.lexists(path), f'Refusing preexisting original global pin: {path}')
        # Empty attachment precondition avoids attributing another process's
        # attachment to this loader or detaching a foreign attachment later.
        before = adapter.bpf('net', 'show', 'dev', SERVER_IF, network=True)
        _need(not _object(before).get('xdp'), 'Lab interface already has XDP attached')
        try:
            adapter.loader = recorder.spawn('baseline-loader', [
                'nsenter', '--net=/run/netns/' + SERVER_NS, '--',
                str(Path(loader).resolve()), SERVER_IF])
            state = adapter.ready()
            # Pinned maps are a global control-plane resource, not a netns socket.
            # `ip netns exec` remounts sysfs and can hide the existing bpffs mount.
            recorder.run([str(Path(updater).resolve())])
            adapter.remember()
            for name, path in PINS.items():
                _need(_object(adapter.bpf('map', 'show', 'pinned', path))['id'] == state['pins'][name],
                      f'Global pin replaced during model update: {path}')
            active = struct.unpack('=i', adapter.lookup(state['maps']['nn_idx']['id'], bytes(4)))[0]
            _need(active == (state['initial_index'] + 1) % 2, 'Updater did not switch model slot')
            actual = adapter.lookup(state['maps']['nn_parameters']['id'], struct.pack('=i', active))
            _need(actual == expected, 'Not all 5216 active parameter bytes match original header')
            initialized = {'initial_slot': state['initial_index'], 'active_slot': active,
                           'parameter_bytes': len(actual), 'all_parameter_bytes_match': True,
                           'sha256': hashlib.sha256(actual).hexdigest(),
                           'header': model['provenance'], 'actual_parameter_hex': actual.hex()}
            recorder.write_json('baseline-model.json', initialized)
            result = {'attachment': state, 'model': initialized,
                      'live': _live(adapter, lab, state, model, active)}
        finally:
            cleanup = adapter.cleanup()
            result['cleanup'] = cleanup
        _need(cleanup['complete'], 'Original baseline cleanup failed: ' + '; '.join(cleanup['errors']))
        result.update({'status': 'pass', 'cleanup_complete': True})
        recorder.write_json('baseline.json', result)
        return result
    finally:
        os.close(lock)


def _main():
    parser = argparse.ArgumentParser(description='Internal baseline metadata observer')
    actions = parser.add_subparsers(dest='action', required=True)
    capture = actions.add_parser('capture')
    capture.add_argument('--interface', required=True, choices=[SERVER_IF])
    capture.add_argument('--ready', required=True, type=Path)
    capture.add_argument('--output', required=True, type=Path)
    capture.add_argument('--seconds', type=float, default=15)
    args = parser.parse_args()
    _need(0 < args.seconds <= 30, 'Capture deadline must be within 30 seconds')
    _capture(args.interface, args.ready, args.output, args.seconds)


if __name__ == '__main__':
    _main()
