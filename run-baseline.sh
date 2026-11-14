#!/usr/bin/env bash
# Baseline smoke test only: no source edits, builds, training, package installs,
# mounts, sysctl changes, or numerical-correctness claims. See --help.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'HELP'
Usage: sudo ./run-baseline.sh [--log-dir NEW_DIRECTORY] [--timeout SECONDS]
       ./run-baseline.sh --check [--log-dir NEW_DIRECTORY]

Run only in an isolated Linux VM. Requires current binaries from `make -C src`,
plus iproute2, Python 3, GNU coreutils, util-linux, mounted bpffs and tracefs.
The detector must already accept an interface argument (this checkout does).

Creates ids-client, ids-server and ids-client0, using 33.33.33.1/24 and
33.33.33.73/24 to match the checked-in source-IP filter. Refuses existing names,
model pins and overlapping non-default routes. Does not touch other interfaces.
Loads XDP, checks all six tail-call slots, runs hot_updating, compares the active
model bytes with mlp_params.bpf.h, then sends one TCP greeting/FIN on port 5001.
Success requires a timing/prediction line from the final inference stage.
Stage-name checks accept full BTF names and the kernel's 15-character names.

Automatically stops its children, removes its network and checks model-pin/XDP
cleanup on success, failure and Ctrl+C. Residual pins are removed only if their
recorded map IDs still match. The original loader itself uses global pin paths:
do not run another loader/updater concurrently. Also, do not run another reader
of the shared trace_pipe. Records are consumed, but tracing is not reconfigured.
No automatic generic-XDP fallback if this kernel rejects the original loader.

--check       Check prerequisites without loading BPF or changing networking.
              Non-root checks cannot validate root-only BPF/trace permissions.
--log-dir DIR Create a NEW directory for run.log, detector.log, updater.log,
              trace.log and JSON evidence. Default: /tmp/nn-ebpf-baseline.XXXXXX.
--timeout N   Per-stage deadline in seconds, 1..300 (default: 20).
--help        Show this help. No root required.

Logs are retained, including on failure; under sudo their ownership is returned
to the invoking user. Exit 0 means smoke success (or --check passed), not model
accuracy, feature/fixed-point correctness, flow-map hygiene or concurrency safety.
Those need separate experiments. Training is intentionally not automated because
mlp_quant.py overwrites the checked-in parameter header.
HELP
}

check_only=0
log_dir=''
stage_timeout=20
while (($#)); do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --check) check_only=1; shift ;;
        --log-dir|--timeout)
            (($# >= 2)) || { printf 'Missing value for %s\n' "$1" >&2; exit 2; }
            if [[ $1 == --log-dir ]]; then log_dir=$2; else stage_timeout=$2; fi
            shift 2 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ $stage_timeout =~ ^[1-9][0-9]{0,2}$ ]] && ((stage_timeout <= 300)) || {
    printf '%s\n' '--timeout must be an integer from 1 to 300.' >&2; exit 2;
}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bpftool=$root/.output/bpftool/bpftool
for tool in python3 ip make stdbuf flock tee mktemp findmnt; do
    command -v "$tool" >/dev/null || { printf 'Missing command: %s\n' "$tool" >&2; exit 1; }
done
if [[ -z $log_dir ]]; then
    log_dir=$(mktemp -d -t nn-ebpf-baseline.XXXXXX)
else
    mkdir -m 700 -- "$log_dir" || { printf 'Log directory must be new.\n' >&2; exit 1; }
    log_dir=$(cd -- "$log_dir" && pwd)
fi
exec 3>&1 4>&2
exec > >(tee "$log_dir/run.log") 2>&1
logger_pid=$!
log() { printf '[%(%Y-%m-%dT%H:%M:%S%z)T] %s\n' -1 "$*"; }
fail() { log "ERROR: $*"; exit 1; }
run() { printf '[command]'; printf ' %q' "$@"; printf '\n'; "$@"; }
loader_pid='' trace_pid='' server_pid=''
netns_owned=0 link_owned=0
helper=$log_dir/helper.py

stop_child() {
    local pid=$1 signal=$2 n
    [[ -n $pid ]] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill -s "$signal" "$pid" 2>/dev/null || true
        for ((n=0; n<50; n++)); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            log "WARNING: process $pid required SIGKILL after SIG$signal."
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    wait "$pid" 2>/dev/null || true
}
cleanup() {
    local result=$?
    trap - EXIT INT TERM ERR
    set +e
    log 'Cleaning up lab resources.'
    stop_child "$server_pid" TERM
    # The original loader handles SIGINT, not SIGTERM.
    stop_child "$loader_pid" INT
    stop_child "$trace_pid" TERM
    if [[ -n $loader_pid ]]; then
        python3 "$helper" clean-pins "$bpftool" "$log_dir" || result=1
        if ((link_owned)); then
            # Save actual post-loader attachment state before deleting the veth.
            "$bpftool" -j net show dev ids-server > "$log_dir/net-after.json"
            if (($? != 0)); then
                log 'ERROR: could not verify XDP detachment.'; result=1
            elif ! python3 "$helper" detached "$log_dir/net-after.json"; then
                result=1
            fi
        fi
    fi
    if ((link_owned)); then
        run ip link del ids-server || result=1
        if ip link show dev ids-server >/dev/null 2>&1; then
            log 'ERROR: ids-server still exists.'; result=1
        fi
    fi
    if ((netns_owned)); then
        run ip netns del ids-client || result=1
        if [[ -e /run/netns/ids-client ]]; then
            log 'ERROR: ids-client still exists.'; result=1
        fi
    fi
    rm -f -- "$helper" "$log_dir/trace.ready" "$log_dir/server.ready"
    # Report final status after artifact ownership and cleanup have been checked.
    # Only this newly created, root-owned artifact directory is handed back.
    if [[ ${SUDO_UID:-} =~ ^[0-9]+$ && ${SUDO_GID:-} =~ ^[0-9]+$ ]]; then
        chown -- "$SUDO_UID:$SUDO_GID" "$log_dir" "$log_dir"/* || result=1
    fi
    if ((result == 0)); then log 'RESULT: PASS'; else log "RESULT: FAIL (exit $result)"; fi
    log "Logs: $log_dir"
    exec 1>&3 2>&4
    if ! wait "$logger_pid"; then
        printf 'ERROR: log writer failed; logs may be incomplete.\n' >&2
        result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'log "Interrupted (SIGINT)."; exit 130' INT
trap 'log "Interrupted (SIGTERM)."; exit 143' TERM
trap 'log "ERROR: line $LINENO: $BASH_COMMAND (exit $?)"' ERR

# Keep structured BPF/JSON checks and portable TCP traffic in Python's stdlib;
# no nc implementation-specific flags, Python packages or persistent helpers.
cat > "$helper" <<'PY'
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import sys
import time


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def cmd(*args):
    return subprocess.check_output(args, text=True)


def obj(value):
    # bpftool show returns a singleton array on some versions.
    if isinstance(value, list):
        need(len(value) == 1, 'Expected one BPF object')
        return value[0]
    return value


def bpf(tool, *args):
    return json.loads(cmd(tool, '-j', *args))


def raw(value):
    return bytes(int(x, 16) if isinstance(x, str) else x for x in value)


def lookup(tool, selector, key):
    encoded = [f'{x:02x}' for x in struct.pack('=i', key)]
    return raw(bpf(tool, 'map', 'lookup', *selector, 'key', 'hex', *encoded)['value'])


def check_stage(stage, key, expected):
    # bpftool restores full BTF names when available; the kernel name is shorter.
    name, kind = stage.get('name'), stage.get('type')
    need(kind == 'xdp' and name in (expected, expected[:15]),
         f'Tail-call slot {key}: expected XDP program {expected!r} '
         f'(or kernel name {expected[:15]!r}); got name={name!r}, '
         f'type={kind!r}, program ID={stage.get("id")}')


def alive(pid):
    os.kill(int(pid), 0)


def preflight():
    names = {'ids-server', 'ids-client0'}
    links = json.loads(cmd('ip', '-j', 'link', 'show'))
    need(not names.intersection(x['ifname'] for x in links), 'Lab interface name already in use')
    need('ids-client' not in [x.split()[0] for x in cmd('ip', 'netns', 'list').splitlines()],
         'Namespace ids-client already exists')
    network = ipaddress.ip_network('33.33.33.0/24')
    for route in json.loads(cmd('ip', '-j', '-4', 'route', 'show', 'table', 'all')):
        dst = route.get('dst', 'default')
        if dst not in ('default', '0.0.0.0/0'):
            need(not network.overlaps(ipaddress.ip_network(dst, strict=False)),
                 f'Existing route overlaps lab addresses: {route}')
    if os.geteuid() == 0:
        for name in ('nn_idx', 'nn_parameters'):
            need(not os.path.lexists('/sys/fs/bpf/' + name), f'Existing pinned map: {name}')
    print('Lab names and routes available; existing resources will not be reused.')


def ready(tool, directory, pid, seconds):
    directory = Path(directory)
    deadline = time.monotonic() + int(seconds)
    while time.monotonic() < deadline:
        pins = {}
        for name in ('nn_idx', 'nn_parameters'):
            path = '/sys/fs/bpf/' + name
            if os.path.exists(path):
                pins[name] = obj(bpf(tool, 'map', 'show', 'pinned', path))['id']
        # Record pins even if attachment subsequently fails, for safe cleanup.
        if pins:
            (directory / 'pins.json').write_text(json.dumps(pins))
        alive(pid)
        net = bpf(tool, 'net', 'show', 'dev', 'ids-server')
        xdp = obj(net)['xdp']
        if xdp and len(pins) == 2:
            need(len(xdp) == 1, 'Expected one XDP attachment')
            program = obj(bpf(tool, 'prog', 'show', 'id', str(xdp[0]['id'])))
            need(program['name'] == 'xdp_prog', 'Unexpected XDP entry program')
            maps = {}
            for map_id in program['map_ids']:
                info = obj(bpf(tool, 'map', 'show', 'id', str(map_id)))
                maps[info['name']] = info
            stages = ('xdp_preprocessing', 'xdp_input_linear', 'xdp_input_relu',
                      'xdp_hidden_linear', 'xdp_hidden_relu', 'xdp_output_linear')
            for key, name in enumerate(stages):
                prog_id = int.from_bytes(lookup(tool, ['id', str(maps['progs']['id'])], key), sys.byteorder)
                stage = obj(bpf(tool, 'prog', 'show', 'id', str(prog_id)))
                check_stage(stage, key, name)
                for map_id in stage.get('map_ids', []):
                    info = obj(bpf(tool, 'map', 'show', 'id', str(map_id)))
                    previous = maps.get(info['name'])
                    need(previous is None or previous['id'] == map_id,
                         f"Stages disagree on map {info['name']}")
                    maps[info['name']] = info
            # nn_parameters is referenced by tail-call stages, not xdp_prog.
            for name, map_id in pins.items():
                need(maps[name]['id'] == map_id, f'{name} pin does not belong to the inference chain')
            index = struct.unpack('=i', lookup(tool, ['pinned', '/sys/fs/bpf/nn_idx'], 0))[0]
            need(index in (0, 1), f'Invalid initial model index: {index}')
            state = {'initial_index': index, 'program': program, 'maps': maps, 'network': net}
            (directory / 'state.json').write_text(json.dumps(state, indent=2))
            print(f'XDP attached to ids-server; all six tail-call slots verified; initial slot={index}.')
            return
        time.sleep(0.1)
    raise RuntimeError('Timed out waiting for XDP attachment and both model pins; see detector.log')


def model(tool, directory, header):
    directory = Path(directory)
    state = json.loads((directory / 'state.json').read_text())
    index = struct.unpack('=i', lookup(tool, ['pinned', '/sys/fs/bpf/nn_idx'], 0))[0]
    need(index == (state['initial_index'] + 1) % 2, 'Updater did not switch to the inactive model slot')
    expected = b''
    text = Path(header).read_text()
    fields = [('layer_0_weight', 192, 'i'), ('layer_1_weight', 1024, 'i'),
              ('layer_2_weight', 64, 'i'), ('mean', 6, 'q'), ('scale', 6, 'q')]
    for name, count, fmt in fields:
        match = re.search(r'\b' + name + r'\s*\[\d+\]\s*=\s*\{([^}]+)\}', text)
        need(match is not None, f'Cannot read checked-in array {name}')
        values = [int(x.strip()) for x in match[1].split(',') if x.strip()]
        need(len(values) == count, f'Unexpected array size: {name}')
        if name == 'scale':
            need(all(x != 0 for x in values), 'Model contains zero scale divisor')
        expected += struct.pack('=' + fmt * count, *values)
    entry = bpf(tool, 'map', 'lookup', 'pinned', '/sys/fs/bpf/nn_parameters',
                'key', 'hex', *[f'{x:02x}' for x in struct.pack('=i', index)])
    (directory / 'active-model.json').write_text(json.dumps(entry, indent=2))
    need(raw(entry['value']) == expected, 'Active model bytes differ from mlp_params.bpf.h')
    print(f'Active model slot={index}: all {len(expected)} parameter bytes match the checked-in header.')


def clean_pins(tool, directory):
    path = Path(directory) / 'pins.json'
    owned = json.loads(path.read_text()) if path.exists() else {}
    errors = []
    for name in ('nn_idx', 'nn_parameters'):
        pin = '/sys/fs/bpf/' + name
        try:
            if os.path.lexists(pin):
                current = obj(bpf(tool, 'map', 'show', 'pinned', pin))['id']
                need(owned.get(name) == current, f'Refusing to delete unknown/replaced pin: {pin}')
                os.unlink(pin)
                print(f'Removed residual owned pin {pin} (map {current}).')
            need(not os.path.lexists(pin), f'Pin remains: {pin}')
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
    need(not errors, '; '.join(errors))
    print('Both model pins absent after cleanup.')


def trace(path, ready_file):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    # Drain historical records into the log before announcing readiness.
    while True:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            break
        need(data, 'trace_pipe closed unexpectedly')
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    Path(ready_file).touch()
    while True:
        if select.select([fd], [], [], 1)[0]:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                continue
            need(data, 'trace_pipe closed unexpectedly')
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()


def serve(host, source, port, ready_file, seconds):
    with socket.socket() as server:
        server.settimeout(int(seconds))
        server.bind((host, int(port)))
        server.listen(1)
        Path(ready_file).touch()
        with server.accept()[0] as conn:
            conn.settimeout(int(seconds))
            need(conn.getpeername()[0] == source, 'Unexpected TCP client source')
            data = b''
            while True:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
                need(len(data) <= 1024, 'Unexpected TCP payload size')
            need(data == b'hello\n', f'Unexpected greeting: {data!r}')
            conn.sendall(b'baseline-ok\n')
            print(f'TCP server received {data!r} and client FIN from {source}.')


def client(source, host, port, seconds):
    with socket.socket() as conn:
        conn.settimeout(int(seconds))
        conn.bind((source, 0))
        conn.connect((host, int(port)))
        conn.sendall(b'hello\n')
        conn.shutdown(socket.SHUT_WR)  # Explicit FIN triggers the original detector.
        reply = b''
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            reply += chunk
            need(len(reply) <= 1024, 'Unexpected TCP response size')
        need(reply == b'baseline-ok\n', f'Unexpected TCP reply: {reply!r}')
        print(f'TCP greeting/FIN and response verified: {source} -> {host}:{port}.')


def prediction(path, offset, pid, seconds):
    deadline = time.monotonic() + int(seconds)
    pattern = re.compile(r'avg feature extraction time: (-?\d+), detection time: (-?\d+), label: ([01])\b')
    while time.monotonic() < deadline:
        alive(pid)
        with open(path, 'rb') as stream:
            stream.seek(int(offset))
            match = pattern.search(stream.read().decode('utf-8', errors='replace'))
        if match:
            print('Final inference stage observed: ' + match[0])
            return
        time.sleep(0.1)
    raise RuntimeError('No final inference line before deadline; inspect trace.log, state.json and active-model.json')


def detached(path):
    need(not obj(json.loads(Path(path).read_text()))['xdp'], 'XDP remained attached after loader exit')
    print('XDP attachment absent after loader exit.')


if __name__ == '__main__':
    actions = {'preflight': preflight, 'ready': ready, 'model': model,
               'clean-pins': clean_pins, 'trace': trace, 'serve': serve,
               'client': client, 'prediction': prediction, 'detached': detached}
    try:
        actions[sys.argv[1]](*sys.argv[2:])
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, struct.error) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
PY

log "Baseline log directory: $log_dir"
log "Kernel: $(uname -r); repository: $root"
for binary in "$root/src/.output/xdp" "$root/src/.output/hot_updating" "$bpftool"; do
    [[ -x $binary ]] || fail "Missing executable: $binary. Build dependencies with make, then make -C src."
done
run make -C "$root/src" -q || fail 'Build is stale or incomplete. Run make -C src before this runner.'
run "$bpftool" version
run python3 "$helper" preflight
[[ $(findmnt -n -o FSTYPE --target /sys/fs/bpf) == bpf ]] || fail 'Mount bpffs at /sys/fs/bpf before running.'
trace_pipe=''
for candidate in /sys/kernel/tracing/trace_pipe /sys/kernel/debug/tracing/trace_pipe; do
    if [[ -r $candidate ]]; then trace_pipe=$candidate; break; fi
done
if ((EUID != 0)); then
    ((check_only)) || fail 'Run with sudo in your isolated VM (or use --check for unprivileged checks).'
    log 'CHECK: root-only pin, BPF, and trace access not verified. Repeat --check with sudo for those checks.'
else
    [[ -n $trace_pipe ]] || fail 'No readable trace_pipe; mount/enable tracefs before running.'
    [[ $(< "${trace_pipe%/*}/tracing_on") == 1 ]] || fail 'Kernel tracing is disabled; enable it before running.'
    # Check BPF access before creating any networking resources.
    "$bpftool" -j prog show > "$log_dir/programs-before.json"
fi
if ((check_only)); then
    log 'CHECK: prerequisites passed; no networking or BPF objects changed.'
    exit 0
fi

# One runner at a time: both original executables use fixed global pin paths.
exec 9>/run/nn-ebpf-baseline.lock
flock -n 9 || fail 'Another baseline runner is active.'
# Recheck names/pins after taking the lock.
run python3 "$helper" preflight
run ip netns add ids-client
netns_owned=1
run ip link add ids-server type veth peer name ids-client0
link_owned=1
run ip link set ids-client0 netns ids-client
run ip addr add 33.33.33.1/24 dev ids-server
run ip link set ids-server up
run ip netns exec ids-client ip addr add 33.33.33.73/24 dev ids-client0
run ip netns exec ids-client ip link set lo up
run ip netns exec ids-client ip link set ids-client0 up
ip -j addr show dev ids-server > "$log_dir/server-address.json"
ip netns exec ids-client ip -j addr show > "$log_dir/client-addresses.json"

wait_ready_file() {
    local marker=$1 pid=$2
    for ((n=0; n<stage_timeout*10; n++)); do
        kill -0 "$pid" 2>/dev/null || fail "Child $pid exited before readiness; inspect its log."
        [[ -e $marker ]] && return 0
        sleep 0.1
    done
    fail "Timed out waiting for $marker."
}
log "Reading $trace_pipe into trace.log (do not run a competing trace reader)."
python3 -u "$helper" trace "$trace_pipe" "$log_dir/trace.ready" > "$log_dir/trace.log" 2> "$log_dir/trace-reader.log" &
trace_pid=$!
wait_ready_file "$log_dir/trace.ready" "$trace_pid"
log 'Starting detector on ids-server; output: detector.log.'
stdbuf -oL -eL "$root/src/.output/xdp" ids-server > "$log_dir/detector.log" 2>&1 &
loader_pid=$!
run python3 "$helper" ready "$bpftool" "$log_dir" "$loader_pid" "$stage_timeout"
log 'Initializing neural-network parameters; output: updater.log.'
if ! "$root/src/.output/hot_updating" > "$log_dir/updater.log" 2>&1; then
    fail 'Updater exited unsuccessfully; see updater.log.'
fi
run python3 "$helper" model "$bpftool" "$log_dir" "$root/src/mlp_params.bpf.h"

log 'Starting TCP listener on 33.33.33.1:5001; output: server.log.'
python3 -u "$helper" serve 33.33.33.1 33.33.33.73 5001 "$log_dir/server.ready" "$stage_timeout" > "$log_dir/server.log" 2>&1 &
server_pid=$!
wait_ready_file "$log_dir/server.ready" "$server_pid"
trace_offset=$(stat -c %s "$log_dir/trace.log")
run ip netns exec ids-client python3 "$helper" client 33.33.33.73 33.33.33.1 5001 "$stage_timeout"
wait "$server_pid" || fail 'TCP listener failed; see server.log.'
server_pid=''
kill -0 "$trace_pid" 2>/dev/null || fail 'Trace reader exited; see trace-reader.log.'
run python3 "$helper" prediction "$log_dir/trace.log" "$trace_offset" "$loader_pid" "$stage_timeout"
log 'Smoke test succeeded. This is not numerical/model correctness validation.'
