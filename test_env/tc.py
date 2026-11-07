"""Owned, all-pass TC probe lifecycle and evidence in the private lab only."""
import json
from pathlib import Path
import signal
import sys
import struct
import time

from .lab import SERVER_IF, SERVER_NS


HOOKS = ('ingress', 'egress')
HANDLE = 1
PRIORITY = 49152
NS_PATH = Path('/run/netns') / SERVER_NS
WAIT_SECONDS = 10
RELEASE_SECONDS = 5
MAX_EVENT_BYTES = 64 * 1024


def _need(condition, message):
    if not condition:
        raise RuntimeError(message)


def _uint(value, bits=64):
    return type(value) is int and 0 <= value < (1 << bits)


def _object(value):
    if isinstance(value, list):
        _need(len(value) == 1, 'Expected a singleton BPF object')
        value = value[0]
    _need(isinstance(value, dict), 'Expected a BPF object')
    return value


def _objects(value):
    if isinstance(value, dict):
        value = [value]
    _need(isinstance(value, list) and all(isinstance(item, dict) for item in value),
          'Expected a BPF object enumeration')
    _need(all(_uint(item.get('id'), 32) and item['id'] > 0 for item in value),
          'BPF enumeration contains an invalid ID')
    return value


def _number(value):
    if isinstance(value, str):
        return int(value, 16) if value.startswith('0x') else int(value)
    _need(type(value) is int, 'Expected an integer TC identifier')
    return value


def _raw(value, size):
    _need(isinstance(value, list) and len(value) == size, 'Unexpected map byte-array ABI')
    result = []
    for item in value:
        byte = int(item, 16) if isinstance(item, str) else item
        _need(_uint(byte, 8), 'Invalid raw map byte')
        result.append(byte)
    return bytes(result)


class Probe:
    """One loader-owned attachment; close never deletes an unowned filter/qdisc."""

    program_keys = HOOKS
    map_keys = ('hook_counts',)
    max_event_bytes = MAX_EVENT_BYTES

    def _loader_args(self):
        return []

    def __init__(self, recorder, lab, loader, obj, bpftool, *, label='tc-probe'):
        self.recorder = recorder
        self.lab = lab
        self.loader_path = Path(loader).resolve()
        self.object_path = Path(obj).resolve()
        self.bpftool = str(Path(bpftool).resolve())
        self.label = label
        self.proc = None
        self.ready = None
        self.stopped = None
        self.owned = {'prog': set(), 'map': set()}
        self._offset = 0
        self._pending = b''
        self._events = []
        self._last_seq = 0
        self._closed = None
        self._started = False
        self._preflight_complete = False
        self._qdisc_identity = None
        self._cpu_ids = None
        self._before_ids = {'prog': set(), 'map': set()}
        self._namespace = None
        self._link = None
        self.evidence = {'schema_version': 1, 'events': self._events, 'snapshots': []}

    def _save(self):
        self.recorder.write_json(self.label + '.json', self.evidence)

    def _guard(self):
        _need(self._namespace is not None and self._link is not None,
              'Probe has no established lab ownership')
        _need(not NS_PATH.is_symlink(), 'Refusing a namespace symlink')
        stat = NS_PATH.stat()
        _need({'device': stat.st_dev, 'inode': stat.st_ino} == self._namespace,
              'Refusing changed TC namespace identity')
        links = self.recorder.json(['ip', '-n', SERVER_NS, '-j', '-d',
                                    'link', 'show', 'dev', SERVER_IF], timeout=5)
        _need(isinstance(links, list) and len(links) == 1, 'Lab TC interface is missing')
        link = links[0]
        _need(link.get('ifname') == SERVER_IF and
              link.get('ifindex') == self._link['ifindex'] and
              link.get('address') == self._link['address'] and
              link.get('ifalias') == self._link['alias'] and
              link.get('linkinfo', {}).get('info_kind') == 'veth',
              'Refusing changed TC interface identity')
        return link

    def _tc(self, *args, stats=False, text=False):
        self._guard()
        argv = ['nsenter', '--net=' + str(NS_PATH), '--', 'tc']
        if not text:
            argv.append('-j')
        if stats:
            argv.append('-s')
        argv.extend(map(str, args))
        if text:
            return self.recorder.run(argv, timeout=5).stdout
        return self.recorder.json(argv, timeout=5)

    def _bpf(self, *args, timeout=5):
        return self.recorder.json([self.bpftool, '-j', *map(str, args)], timeout=timeout)

    def _qdiscs(self):
        value = self._tc('qdisc', 'show', 'dev', SERVER_IF)
        _need(isinstance(value, list) and all(isinstance(item, dict) for item in value),
              'Invalid TC qdisc enumeration')
        return value

    @staticmethod
    def _clsact(qdiscs):
        matches = [item for item in qdiscs if item.get('kind') == 'clsact']
        _need(len(matches) <= 1, 'Multiple clsact qdiscs on the lab interface')
        if not matches:
            return None
        item = matches[0]
        _need(item.get('handle') == 'ffff:' and item.get('parent') == 'ffff:fff1',
              'Unexpected clsact identity')
        return {key: item[key] for key in ('kind', 'handle', 'parent')}

    def _filters(self, *, stats=False):
        return {hook: self._tc('filter', 'show', 'dev', SERVER_IF, hook, stats=stats)
                for hook in HOOKS}

    def _remember_fds(self):
        """Independently identify all BPF objects held by our live child."""
        result = {'prog': set(), 'map': set()}
        if self.proc is None or self.proc.poll() is not None:
            return result
        try:
            paths = list(Path(f'/proc/{self.proc.pid}/fdinfo').iterdir())
        except FileNotFoundError:
            return result
        for path in paths:
            try:
                lines = path.read_text(encoding='ascii').splitlines()
            except FileNotFoundError:
                continue
            for line in lines:
                for kind in result:
                    if line.startswith(kind + '_id:'):
                        ident = int(line.split(':', 1)[1])
                        _need(_uint(ident, 32) and ident > 0, 'Invalid loader fdinfo ID')
                        result[kind].add(ident)
        for kind in result:
            self.owned[kind].update(result[kind])
        return result

    def _reported_ids(self, event):
        result = {'prog': set(), 'map': set()}
        for field, keys, kind in (('program_ids', self.program_keys, 'prog'),
                                  ('map_ids', self.map_keys, 'map')):
            values = event.get(field)
            _need(isinstance(values, dict) and set(values) == set(keys),
                  'Loader event has invalid ' + field)
            for ident in values.values():
                _need(_uint(ident, 32), 'Loader reported an invalid BPF object ID')
                if ident:
                    result[kind].add(ident)
        return result

    def _read_events(self):
        if self.proc is None:
            return
        with self.proc.stdout_path.open('rb') as stream:
            stream.seek(self._offset)
            chunk = stream.read(self.max_event_bytes)
        self._offset += len(chunk)
        self._pending += chunk
        while b'\n' in self._pending:
            line, self._pending = self._pending.split(b'\n', 1)
            _need(0 < len(line) <= self.max_event_bytes, 'Invalid loader JSONL record length')
            event = json.loads(line.decode('utf-8'))
            _need(isinstance(event, dict) and type(event.get('schema_version')) is int and
                  event['schema_version'] == 1, 'Unsupported loader event schema')
            name = event.get('event')
            _need(name in ('ready', 'stats', 'stopped', 'error'), 'Unknown loader event')
            self._events.append(event)
            if name in ('ready', 'stopped'):
                _need(type(event.get('qdisc_created')) is bool,
                      'Loader omitted qdisc ownership evidence')
                reported = self._reported_ids(event)
                for kind in reported:
                    self.owned[kind].update(reported[kind])
            if name == 'ready':
                _need(self.ready is None and self.stopped is None, 'Duplicate or late ready event')
                self.ready = event
            elif name == 'stopped':
                _need(self.stopped is None, 'Duplicate stopped event')
                self.stopped = event
            elif name == 'stats':
                _need(self.ready is not None and self.stopped is None, 'Out-of-lifecycle stats event')
                _need(_uint(event.get('seq')) and event['seq'] > self._last_seq,
                      'Loader stats sequence did not increase')
                _need(all(_uint(event.get(hook)) for hook in HOOKS), 'Invalid loader counter')
                self._last_seq = event['seq']
        _need(len(self._pending) <= self.max_event_bytes, 'Loader JSONL record exceeded its bound')
        if chunk:
            self._save()

    def _wait(self, predicate, description):
        deadline = time.monotonic() + WAIT_SECONDS
        exited_at = None
        while True:
            self._read_events()
            errors = [event for event in self._events if event['event'] == 'error']
            _need(not errors and self.stopped is None, f'Loader failed during {description}: {errors}')
            if predicate():
                return
            if self.proc.poll() is not None:
                # Recorder's output pump can lag the owned child's exit briefly.
                exited_at = exited_at or time.monotonic()
                _need(time.monotonic() - exited_at < 0.5,
                      f'Loader exited before {description}: {self.proc.returncode}')
            _need(time.monotonic() < deadline, f'Timed out waiting for TC {description}')
            time.sleep(0.02)

    def _validate_filters(self, filters):
        expected = self.ready['program_ids']
        for hook in HOOKS:
            entries = filters[hook]
            _need(isinstance(entries, list), 'Invalid TC filter enumeration')
            concrete = []
            for entry in entries:
                _need(isinstance(entry, dict) and entry.get('kind') == 'bpf' and
                      _number(entry.get('pref')) == PRIORITY and entry.get('protocol') == 'all' and
                      entry.get('chain', 0) == 0, 'Foreign TC filter or classifier chain')
                options = entry.get('options')
                if options is None:
                    # iproute2 emits a classifier summary before its concrete filters.
                    continue
                _need(isinstance(options, dict), 'Invalid TC BPF filter options')
                concrete.append(options)
            _need(len(concrete) == 1, 'Expected exactly one TC BPF filter per hook')
            options = concrete[0]
            program = options.get('prog')
            if program is not None:
                _need(isinstance(program, dict), 'Invalid nested TC program metadata')
                program_id = program.get('id')
                _need('id' not in options or options['id'] == program_id,
                      'Conflicting TC program identities')
            else:
                program_id = options.get('id')
            _need(_number(options.get('handle')) == HANDLE and
                  program_id == expected[hook] and
                  options.get('direct-action') is True,
                  'Actual TC role/ID/handle/direct-action does not match the loader')

    def _visibility(self):
        filters = self._filters(stats=True)
        self._validate_filters(filters)
        text = {hook: self._tc('filter', 'show', 'dev', SERVER_IF, hook, stats=True, text=True)
                for hook in HOOKS}
        return {'filters_json': filters, 'tc_s_text': text}

    def start(self):
        _need(not self._started and self._closed is None, 'Probe instances cannot be restarted')
        self._started = True
        state = self.lab.state
        _need(state.get('setup') == 'pass' and not state.get('cleanup_complete'),
              'TC probe requires an active owned lab')
        self._namespace = dict(state['namespaces'][SERVER_NS])
        self._link = dict(state['links'][SERVER_IF])
        _need(self._link.get('namespace') == SERVER_NS and
              self._link.get('alias') == state['ownership_token'],
              'TC interface is not owned by this lab')
        self._guard()
        before = self._qdiscs()
        _need(self._clsact(before) is None, 'Refusing preexisting clsact qdisc')
        self.evidence['qdiscs_before'] = before
        self.evidence['identity'] = {'namespace': self._namespace, 'link': self._link}
        for kind in self._before_ids:
            objects = _objects(self._bpf(kind, 'show'))
            self._before_ids[kind] = {item['id'] for item in objects}
        self.evidence['preexisting_ids'] = {kind: sorted(ids)
                                            for kind, ids in self._before_ids.items()}
        self._preflight_complete = True
        self._save()
        # Unlike ip netns exec, nsenter preserves the mount namespace and bpffs view.
        self.proc = self.recorder.spawn(self.label + '-loader', [
            'nsenter', '--net=' + str(NS_PATH), '--', str(self.loader_path),
            str(self.object_path), SERVER_IF, str(NS_PATH), *self._loader_args()])
        self._wait(lambda: self.ready is not None, 'readiness')
        ready = self.ready
        _need(self.proc.poll() is None, 'TC loader exited immediately after readiness')
        _need(ready['qdisc_created'] is True and ready.get('ifindex') == self._link['ifindex'],
              'Loader readiness does not identify its owned lab qdisc/interface')
        _need(ready.get('filter') == {'handle': HANDLE, 'priority': PRIORITY},
              'Unexpected loader filter ABI')
        selftest = ready.get('counter_selftest')
        _need(isinstance(selftest, dict) and selftest.get('pass') is True and
              selftest.get('after_ingress') == [1, 0] and
              selftest.get('after_egress') == [1, 1] and
              all(_uint(value) for field in ('after_ingress', 'after_egress')
                  for value in selftest[field]),
              'Real per-program counter role self-test did not pass')
        reported = self._reported_ids(ready)
        _need(len(reported['prog']) == len(self.program_keys) and
              len(reported['map']) == len(self.map_keys),
              'TC backend did not report every distinct owned program/map')
        held = self._remember_fds()
        _need(held == reported, 'Ready IDs do not match the owned loader BPF descriptors')
        for kind in reported:
            _need(not (reported[kind] & self._before_ids[kind]), 'Loader reused a preexisting BPF object')
        programs, counts = self._validate_objects(ready)
        qdiscs = self._qdiscs()
        self._qdisc_identity = self._clsact(qdiscs)
        _need(self._qdisc_identity is not None, 'Ready loader has no clsact qdisc')
        self.evidence['attachment'] = {'ready': ready, 'programs': programs, 'map': counts,
                                       'qdiscs': qdiscs, **self._visibility()}
        self._save()
        return ready

    def _validate_objects(self, ready):
        """Probe ABI stays exact; other backends must validate their own full ABI."""
        programs = {}
        map_id = ready['map_ids']['hook_counts']
        for hook in HOOKS:
            ident = ready['program_ids'][hook]
            program = _object(self._bpf('prog', 'show', 'id', ident))
            _need(program.get('id') == ident and program.get('name') == 'probe_' + hook and
                  program.get('type') == 'sched_cls' and program.get('map_ids') == [map_id],
                  'Wrong TC program type/name/map binding for ' + hook)
            programs[hook] = program
        counts = _object(self._bpf('map', 'show', 'id', map_id))
        actual = tuple(counts.get(key) for key in
                       ('id', 'name', 'type', 'bytes_key', 'bytes_value', 'max_entries'))
        _need(actual == (map_id, 'hook_counts', 'percpu_array', 4, 8, 2),
              'Unexpected TC hook_counts ABI: ' + str(actual))
        _need(not counts.get('pinned') and not any(p.get('pinned') for p in programs.values()),
              'Probe objects must be unpinned')
        return programs, counts

    def _map_read(self):
        result = {'entries': {}, 'sums': {}}
        for key, hook in enumerate(HOOKS):
            entry = _object(self._bpf('map', 'lookup', 'id', self.ready['map_ids']['hook_counts'],
                                      'key', 'hex', *[f'{byte:02x}' for byte in struct.pack('=I', key)]))
            _need(_raw(entry.get('key'), 4) == struct.pack('=I', key), 'Map lookup returned the wrong key')
            values = entry.get('values')
            _need(isinstance(values, list) and values, 'Missing per-CPU map values')
            cpus = []
            total = 0
            for item in values:
                _need(isinstance(item, dict) and _uint(item.get('cpu'), 32), 'Invalid per-CPU entry')
                cpus.append(item['cpu'])
                total += int.from_bytes(_raw(item.get('value'), 8), byteorder=sys.byteorder)
            _need(cpus == list(range(len(cpus))), 'Per-CPU map values are missing or duplicated')
            if self._cpu_ids is None:
                self._cpu_ids = cpus
            _need(cpus == self._cpu_ids, 'Per-CPU map topology changed')
            _need(_uint(total), 'Per-CPU counter sum exceeds the loader u64 ABI')
            result['entries'][hook] = entry
            result['sums'][hook] = total
        return result

    def snapshot(self):
        _need(self.ready is not None and self._closed is None and self.proc.poll() is None,
              'Cannot snapshot an inactive TC probe')
        self._guard()
        self._read_events()
        previous = self._last_seq
        before = self._map_read()
        # Only this recorder-owned Popen is signalled; no process-name/PID search.
        self.proc.send_signal(signal.SIGUSR1)
        self._wait(lambda: self._last_seq > previous, 'counter snapshot')
        matches = [event for event in self._events
                   if event['event'] == 'stats' and event['seq'] > previous]
        _need(len(matches) == 1, 'Unexpected unsolicited TC stats events')
        stats = matches[0]
        after = self._map_read()
        for hook in HOOKS:
            _need(before['sums'][hook] <= stats[hook] <= after['sums'][hook],
                  'Loader stats disagree with independent per-CPU map reads: ' + hook)
            _need(stats[hook] >= 1, 'Counter lost its actual self-test increment')
        self.evidence['snapshots'].append({'stats': stats, 'map_before': before, 'map_after': after})
        self._save()
        return stats

    def close(self):
        if self._closed is not None:
            return self._closed
        result = {'complete': False, 'cleanup_complete': False, 'errors': [],
                  'qdisc_removed': False, 'owned_ids': {}, 'remaining_owned_ids': {},
                  'enumerations': []}
        errors = result['errors']
        if self.proc is not None:
            try:
                self._remember_fds()
            except Exception as exc:
                errors.append('Final fd ownership snapshot: ' + str(exc))
            try:
                result['loader_exit_code'] = self.recorder.stop(self.proc, sig=signal.SIGTERM, timeout=5)
                _need(result['loader_exit_code'] == 0, 'TC loader exited unsuccessfully')
            except Exception as exc:
                errors.append('Loader shutdown: ' + str(exc))
            try:
                # stop joins the recorder pumps, so final records are now available.
                while self._offset < self.proc.stdout_path.stat().st_size:
                    self._read_events()
                _need(not self._pending, 'Truncated final loader JSONL record')
                _need(self.stopped is not None, 'Loader omitted its final stopped event')
                stopped = self.stopped
                result['stopped'] = stopped
                _need(stopped.get('filters_detached') is True,
                      'Loader did not confirm ID-matching filter detachment')
                _need(isinstance(stopped.get('errors'), list) and not stopped['errors'],
                      'Loader reported cleanup/load errors: ' + str(stopped.get('errors')))
                _need(not [event for event in self._events if event['event'] == 'error'],
                      'Loader emitted an error event')
                if self.ready is not None:
                    for field in ('program_ids', 'map_ids', 'qdisc_created'):
                        _need(stopped[field] == self.ready[field], 'Loader final ownership changed: ' + field)
            except Exception as exc:
                errors.append('Final loader evidence: ' + str(exc))
        owns_qdisc = any(event.get('qdisc_created') is True
                         for event in (self.ready, self.stopped) if event is not None)
        if owns_qdisc:
            try:
                _need(self._preflight_complete, 'No exclusive-create precondition evidence')
                _need(self.proc is not None and self.proc.poll() is not None,
                      'Refusing qdisc removal while the loader is alive')
                self._guard()
                qdiscs = self._qdiscs()
                identity = self._clsact(qdiscs)
                result['qdiscs_before_removal'] = qdiscs
                # Partial startup can fail before ready; the final event still proves
                # exclusive creation, and the canonical clsact identity is checked.
                _need(identity is not None, 'Owned clsact vanished before controlled cleanup')
                _need(self._qdisc_identity is None or identity == self._qdisc_identity,
                      'Refusing a changed clsact identity')
                filters = self._filters(stats=True)
                result['filters_before_removal'] = filters
                _need(all(isinstance(value, list) and not value for value in filters.values()),
                      'Refusing clsact deletion with foreign or remaining filters')
                _need(self._clsact(self._qdiscs()) == identity, 'Clsact changed during cleanup')
                self._tc('qdisc', 'del', 'dev', SERVER_IF, 'handle', identity['handle'], 'clsact', text=True)
                result['qdiscs_after_removal'] = self._qdiscs()
                _need(self._clsact(result['qdiscs_after_removal']) is None, 'Owned clsact remains')
                result['qdisc_removed'] = True
            except Exception as exc:
                errors.append('Owned qdisc cleanup: ' + str(exc))
        elif self.proc is not None and self.stopped is None:
            errors.append('No final evidence proving whether the loader created a qdisc')
        try:
            deadline = time.monotonic() + RELEASE_SECONDS
            while True:
                current = {}
                for kind in ('prog', 'map'):
                    timeout = max(0.1, min(3, deadline - time.monotonic()))
                    current[kind] = sorted(item['id'] for item in _objects(
                        self._bpf(kind, 'show', timeout=timeout)))
                remaining = {kind: sorted(self.owned[kind].intersection(current[kind]))
                             for kind in current}
                result['enumerations'].append({'live_ids': current, 'remaining_owned_ids': remaining})
                result['remaining_owned_ids'] = remaining
                if not any(remaining.values()):
                    break
                _need(time.monotonic() < deadline, 'Owned TC BPF objects remain: ' + str(remaining))
                time.sleep(0.1)
        except Exception as exc:
            errors.append('Positive BPF release verification: ' + str(exc))
        result['owned_ids'] = {kind: sorted(ids) for kind, ids in self.owned.items()}
        result['complete'] = result['cleanup_complete'] = not errors
        self._closed = result
        self.evidence['cleanup'] = result
        self._save()
        return result


def _window(probe, action, name):
    before = probe.snapshot()
    traffic = action()
    after = probe.snapshot()
    delta = {hook: after[hook] - before[hook] for hook in HOOKS}
    result = {'before': before, 'after': after, 'delta': delta, 'traffic': traffic,
              'counter_semantics': 'All protocols and background traffic; positive deltas, not exact wire counts',
              'visibility_after': probe._visibility()}
    probe.evidence.setdefault('windows', {})[name] = result
    probe._save()
    _need(all(value > 0 for value in delta.values()),
          f'{name} did not increase both TC hook counters: {delta}')
    result['status'] = 'pass'
    probe._save()
    return result


def run_probe(recorder, lab, loader: Path, obj: Path, bpftool: Path):
    """Prove two real TC attach/traffic/detach/release cycles in the owned lab."""
    result = {'schema_version': 1, 'status': 'fail', 'cleanup_complete': False, 'cycles': []}
    try:
        for index in (1, 2):
            probe = Probe(recorder, lab, loader, obj, bpftool, label=f'tc-cycle-{index}')
            cycle = {'cycle': index, 'evidence_file': probe.label + '.json'}
            result['cycles'].append(cycle)
            try:
                cycle['ready'] = probe.start()
                cycle['ping'] = _window(probe, lab.ping_checks, 'ping')
                cycle['tcp'] = _window(probe, lab.exchange, 'tcp')
            finally:
                cycle['cleanup'] = probe.close()
            _need(cycle['cleanup']['complete'],
                  'TC cleanup failed: ' + '; '.join(cycle['cleanup']['errors']))
            # Passing traffic after detach demonstrates that removal did not leave
            # a classifier/qdisc dependency or disrupt the original private link.
            cycle['connectivity_after_detach'] = {'ping': lab.ping_checks(), 'tcp': lab.exchange()}
            cycle['status'] = 'pass'
            recorder.write_json('tc.json', result)
        result.update(status='pass', cleanup_complete=True)
        return result
    except BaseException as exc:
        result['error'] = str(exc)
        result['cleanup_complete'] = bool(result['cycles']) and all(
            cycle.get('cleanup', {}).get('complete', False) for cycle in result['cycles'])
        raise
    finally:
        recorder.write_json('tc.json', result)
