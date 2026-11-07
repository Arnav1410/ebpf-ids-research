"""UI-independent ingestion of the private native classifier stream.

The reader, queue, aggregation, journal and flow inspection have independent
bounds. Queue policy is drop-newest: a validated record is journaled before
queue admission, so durable delivery and unprocessed consumer loss are distinct.
History/state evictions are retention, not missing kernel completions. Native
reader restarts keep source identity and sequence/counter history intact.

Source counters, rates and bounded flow snapshots come from the independent
native reader; neither the UI nor collector polls producer.snapshot(). No UI
is needed to drain events. Only diagnostic pause methods suspend draining.
"""
from collections import OrderedDict, deque
import copy
import json
from pathlib import Path
import signal
import threading
import time

from .commands import MAX_LOG_BYTES
from .event_schema import (MAX_RECORD_BYTES, SchemaError, decode_record,
                           source_for, uint, validate_record, validate_source)
from .lab import SERVER_IF
from .tc import NS_PATH, _need


def _capacity(value, name, maximum=1 << 20):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(name + ' must be a positive bounded integer')
    return value


class SequenceWindow:
    """Bounded reorder-aware missing-sequence accounting, not a loss total.

    Sequence assignment precedes reserve, so concurrent CPUs can deliver out of
    numerical order. Holes in the recent window can heal. Older unresolved holes
    are finalized; a late record beyond that window is reported separately and
    cannot be reliably deduplicated. Neither measure is added to ring drops.
    """
    def __init__(self, capacity=8192):
        self.capacity = _capacity(capacity, 'sequence capacity')
        self.high = 0
        self.bits = 0
        self.finalized = 0
        self.duplicates = 0
        self.late_outside_window = 0

    def observe(self, sequence):
        if not uint(sequence) or sequence == 0:
            raise ValueError('Sequence must be a positive u64')
        width = min(self.high, self.capacity)
        if sequence > self.high:
            shift = sequence - self.high
            if shift >= self.capacity:
                self.finalized += width - self.bits.bit_count()
                self.finalized += max(0, sequence - self.capacity - self.high)
                self.bits = 1
            else:
                old_low = max(1, self.high - self.capacity + 1)
                new_low = max(1, sequence - self.capacity + 1)
                exiting = max(0, new_low - old_low)
                seen_exiting = (self.bits >> (self.capacity - shift)).bit_count()
                self.finalized += exiting - seen_exiting
                self.bits = ((self.bits << shift) | 1) & ((1 << self.capacity) - 1)
            self.high = sequence
            return True
        distance = self.high - sequence
        if distance >= self.capacity:
            self.late_outside_window += 1
            return False
        bit = 1 << distance
        if self.bits & bit:
            self.duplicates += 1
            return False
        self.bits |= bit
        return True

    def snapshot(self):
        pending = min(self.high, self.capacity) - self.bits.bit_count()
        return {'highest_received': self.high, 'sequence_gaps': self.finalized + pending,
                'recent_unresolved_gaps': pending, 'finalized_gaps': self.finalized,
                'duplicates': self.duplicates, 'late_outside_window': self.late_outside_window,
                'window_capacity': self.capacity,
                'meaning': 'unobserved sequence holes, not added to kernel or Python drops; recent holes can heal'}


class EventJournal:
    """Append-only accepted native records; at capacity stop, never overwrite."""
    def __init__(self, path, max_bytes=MAX_LOG_BYTES):
        self.path = Path(path)
        self.max_bytes = _capacity(max_bytes, 'journal bytes', MAX_LOG_BYTES)
        self.stream = self.path.open('xb')
        self.bytes_written = 0
        self.records_written = 0
        self.dropped_records = 0
        self.closed = False

    def append(self, record):
        encoded = (json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if self.closed:
            raise RuntimeError('Journal is closed')
        if self.bytes_written + len(encoded) > self.max_bytes:
            self.dropped_records += 1
            return False
        self.stream.write(encoded)
        self.stream.flush()
        self.bytes_written += len(encoded)
        self.records_written += 1
        return True

    def snapshot(self):
        return {'filename': self.path.name, 'bytes': self.bytes_written,
                'capacity_bytes': self.max_bytes, 'records': self.records_written,
                'journal_dropped_records': self.dropped_records,
                'policy': 'stop-writing-at-capacity; no overwrite; flushed, not fsync durability'}

    def close(self):
        if not self.closed:
            self.stream.close()
            self.closed = True


class EventBuffer:
    """Thread-safe pure consumer boundary, useful independently of a UI/process.

    ingest() accepts ONLY schema-validated native records bound to expected_source.
    This API does not establish kernel provenance; Collector's FD-proven child
    does. Tests may feed unit records here without claiming live execution.
    """
    def __init__(self, expected_source, *, queue_capacity=1024, history_capacity=1024,
                 flow_capacity=8192, journal=None, sequence_capacity=8192):
        self.source = copy.deepcopy(validate_source(expected_source))
        self.queue_capacity = _capacity(queue_capacity, 'queue capacity')
        self.history_capacity = _capacity(history_capacity, 'history capacity')
        self.flow_capacity = _capacity(flow_capacity, 'flow capacity', 8192)
        self.journal = journal
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.queue = deque()
        self.history = deque()
        self.flow_state = OrderedDict()
        self.classified = OrderedDict()
        self.sequence = SequenceWindow(sequence_capacity)
        self.counts = {'accepted_classifications': 0, 'aggregated_classifications': 0,
                       'python_queue_drops': 0, 'history_retention_evictions': 0,
                       'classification_retention_evictions': 0, 'flow_retention_evictions': 0,
                       'schema_errors': 0, 'reader_restarts': 0, 'reader_disconnects': 0,
                       'reader_decode_errors_previous': 0, 'error_retention_evictions': 0}
        self.status = 'disconnected'
        self.reader_generation = 0
        self.ready = None
        self.native_stopped = None
        self.native_decode_errors = 0
        self.native_counters = None
        self.source_sequence = 0
        self.source_timestamp_ns = None
        self.hook_counts = None
        self.rates = None
        self.errors = deque()
        self.error_count = 0
        self.aggregation_paused = False
        self.reader_paused = False
        self.flow_inspection = None
        self._rate_previous = None
        self._reader_received_ns = None
        self._labels = {0: 0, 1: 0}
        self._failed = 0

    def reader_starting(self):
        with self.changed:
            if self.reader_generation:
                self.counts['reader_restarts'] += 1
                self.counts['reader_decode_errors_previous'] += self.native_decode_errors
            self.native_decode_errors = 0
            self.reader_generation += 1
            self.status = 'connecting'
            self.ready = None
            self.native_stopped = None
            self.reader_paused = False
            self.changed.notify_all()

    def disconnected(self):
        with self.changed:
            if self.status != 'disconnected':
                self.counts['reader_disconnects'] += 1
            self.status = 'disconnected'
            self.reader_paused = False
            self.changed.notify_all()

    def fail(self, message, *, schema=False):
        with self.changed:
            self.error_count += 1
            if len(self.errors) == 32:
                self.errors.popleft()
                self.counts['error_retention_evictions'] += 1
            self.errors.append(str(message)[:4096])
            if schema:
                self.counts['schema_errors'] += 1
            self.changed.notify_all()

    def ingest(self, record):
        validate_record(record, self.source)
        with self.changed:
            name = record['event']
            if name == 'ready':
                if self.status != 'connecting' or self.ready is not None:
                    raise SchemaError('Duplicate or out-of-lifecycle reader ready')
                self.ready = copy.deepcopy(record)
                self.status = 'connected'
            elif name in ('classification', 'source_counters', 'stopped'):
                if self.status != 'connected' or self.native_stopped is not None:
                    raise SchemaError('Native record outside a ready reader lifecycle')
            if name == 'classification':
                if not self.sequence.observe(record['sequence']):
                    return False
                self.counts['accepted_classifications'] += 1
            elif name in ('source_counters', 'stopped'):
                self._source_counters(record)
                if name == 'stopped':
                    self.native_stopped = copy.deepcopy(record)
                    if record['errors']:
                        self.fail('Native reader shutdown errors: ' + str(record['errors']))
            elif name == 'error':
                self.fail(record['stage'] + ': ' + record['message'])
            if self.journal is not None:
                self.journal.append(record)
            self._reader_received_ns = time.monotonic_ns()
            if name == 'classification':
                if len(self.queue) == self.queue_capacity:
                    self.counts['python_queue_drops'] += 1
                else:
                    self.queue.append(copy.deepcopy(record))
            self.changed.notify_all()
            return True

    def _source_counters(self, record):
        counters = record['inference_counters']
        hooks = record['hook_counts']
        if self.native_counters is not None:
            if (record['timestamp_ns'] < self.source_timestamp_ns or
                    record['sequence'] < self.source_sequence or
                    any(counters[name] < value for name, value in self.native_counters.items()) or
                    any(hooks[name] < value for name, value in self.hook_counts.items())):
                raise SchemaError('Same producer counters/clock regressed across reader lifetimes')
        if record['reader_decode_errors'] < self.native_decode_errors:
            raise SchemaError('Native decode-error count regressed within a reader lifetime')
        previous = self._rate_previous
        if previous is not None and record['timestamp_ns'] > previous[0]:
            seconds = (record['timestamp_ns'] - previous[0]) / 1_000_000_000
            self.rates = {'interval_ns': record['timestamp_ns'] - previous[0],
                          'timestamp_ns': record['timestamp_ns'],
                          'hook_packets_per_second': {name: (value - previous[1][name]) / seconds
                                                      for name, value in hooks.items()},
                          'inference_per_second': {name: (value - previous[2][name]) / seconds
                                                   for name, value in counters.items()},
                          'source': 'actual producer counters / actual monotonic source delta'}
        self._rate_previous = (record['timestamp_ns'], dict(hooks), dict(counters))
        self.native_counters = dict(counters)
        self.hook_counts = dict(hooks)
        self.source_sequence = record['sequence']
        self.source_timestamp_ns = record['timestamp_ns']
        self.native_decode_errors = record['reader_decode_errors']
        self.update_flows(record)

    def aggregate(self, limit=None):
        """Drain accepted queue records without computing logits or class decisions."""
        if limit is not None:
            _capacity(limit, 'aggregate limit')
        with self.changed:
            if self.aggregation_paused:
                return 0
            count = 0
            while self.queue and (limit is None or count < limit):
                event = self.queue.popleft()
                if len(self.history) == self.history_capacity:
                    self.history.popleft()
                    self.counts['history_retention_evictions'] += 1
                self.history.append(event)
                ident = event['flow_id']
                previous = self.classified.get(ident)
                # Ring delivery across CPUs need not follow per-flow ordinal order.
                if previous is None or event['trigger_ordinal'] > previous['trigger_ordinal']:
                    self.classified[ident] = event
                    self.classified.move_to_end(ident)
                    if len(self.classified) > self.flow_capacity:
                        self.classified.popitem(last=False)
                        self.counts['classification_retention_evictions'] += 1
                self.counts['aggregated_classifications'] += 1
                if event['status'] == 0:
                    self._labels[event['label']] += 1
                else:
                    self._failed += 1
                count += 1
            self.changed.notify_all()
            return count

    def update_flows(self, inspection):
        """Cache the native reader's bounded, per-generation locked map rows."""
        rows = inspection['flows']
        with self.changed:
            selected = sorted(rows, key=lambda row: (row['last_ns'], row['id']))[-self.flow_capacity:]
            ids = {row['id'] for row in rows}
            old = set(self.flow_state)
            self.flow_state = OrderedDict((row['id'], copy.deepcopy(row)) for row in selected)
            self.counts['flow_retention_evictions'] += len((old - set(self.flow_state)) & ids)
            self.flow_inspection = {'snapshot_ns': inspection['snapshot_ns'],
                                    'snapshot_end_ns': inspection['snapshot_end_ns'],
                                    'flows_total': inspection['flows_total'],
                                    'flows_retained': len(selected),
                                    'source_row_limit': inspection['flow_limit'],
                                    'flows_truncated': inspection['flows_truncated'] or len(selected) < len(rows),
                                    'scope': 'bounded FD-proven per-generation locked map rows, not a global transaction'}
            self.changed.notify_all()

    def health(self):
        with self.lock:
            return copy.deepcopy({'source': self.source, 'mode': 'live',
                'reader_status': self.status, 'connected': self.status == 'connected' and not self.reader_paused,
                'reader_generation': self.reader_generation, 'reader_paused': self.reader_paused,
                'aggregation_paused': self.aggregation_paused,
                'source_timestamp_ns': self.source_timestamp_ns,
                'last_native_received_monotonic_ns': self._reader_received_ns,
                'queue_size': len(self.queue), 'queue_capacity': self.queue_capacity,
                'queue_policy': 'drop-newest-after-journal', **self.counts,
                'reader_decode_errors': self.counts['reader_decode_errors_previous'] + self.native_decode_errors,
                'kernel_ring_drops': None if self.native_counters is None else self.native_counters['event_dropped'],
                'sequence': self.sequence.snapshot(), 'source_sequence': self.source_sequence,
                'errors': list(self.errors), 'error_count': self.error_count,
                'journal': None if self.journal is None else self.journal.snapshot(),
                'loss_accounting': 'kernel drops, unobserved sequence holes and Python queue drops are separate; never summed'})

    def summary(self):
        with self.lock:
            return copy.deepcopy({'source': self.source, 'mode': 'live',
                'numeric_labels': self._labels, 'failed_classifications': self._failed,
                'label_semantics': {'0': 'unverified', '1': 'unverified'},
                'scope': 'aggregated consumer records only, not whole producer population',
                'inference_counters': self.native_counters, 'hook_counts': self.hook_counts,
                'rates': self.rates, 'flow_inspection': self.flow_inspection,
                'retained_classifications': len(self.history), 'history_capacity': self.history_capacity,
                'retained_classified_flows': len(self.classified), 'flow_capacity': self.flow_capacity})

    def flows(self):
        with self.lock:
            result = []
            for ident, row in self.flow_state.items():
                classification = self.classified.get(ident)
                result.append({'flow': copy.deepcopy(row),
                               'classification': copy.deepcopy(classification),
                               'classification_state': 'unclassified' if classification is None else
                                   'classified' if classification['status'] == 0 else 'failed',
                               'active': row['state'] in ('open', 'half_closed', 'closing')})
            return result

    def events(self, *, limit=None):
        """Bounded arrival history; producer sequences are not delivery cursors."""
        if limit is not None:
            _capacity(limit, 'event limit')
        with self.lock:
            rows = list(self.history)
            return copy.deepcopy(rows if limit is None else rows[-limit:])

    def snapshot(self):
        with self.lock:
            return {'health': self.health(), 'summary': self.summary(),
                    'flows': self.flows(), 'events': self.events()}


class Collector:
    """Own native readers, never the detector; close readers before producer.close."""
    def __init__(self, recorder, producer, reader, *, label='events', queue_capacity=1024,
                 history_capacity=1024, flow_capacity=8192, journal_bytes=MAX_LOG_BYTES):
        self.recorder, self.producer = recorder, producer
        self.reader_path = Path(reader).resolve()
        self.label = label
        if not isinstance(label, str) or not label or any(c not in
                'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in label):
            raise ValueError('Invalid collector label')
        self.source = source_for(producer)
        self.journal = EventJournal(recorder.out / (label + '-live.jsonl'), journal_bytes)
        self.state = EventBuffer(self.source, queue_capacity=queue_capacity,
                                 history_capacity=history_capacity, flow_capacity=flow_capacity,
                                 journal=self.journal)
        self.proc = None
        self._ingest_thread = None
        self._aggregator = None
        self._closing = threading.Event()
        self._reader_stop = threading.Event()
        self._started = False
        self._closed = False
        self.reader_exits = []

    def reader_argv(self):
        self.producer._guard()
        _need(source_for(self.producer) == self.source, 'Owned producer identity changed')
        source = self.source
        return ['nsenter', '--net=' + str(NS_PATH), '--', str(self.reader_path),
                str(source['ring_map_id']), SERVER_IF, str(NS_PATH),
                '--owner-pid', str(source['owner_pid']), '--model-id', source['model_id'],
                '--counters', str(source['counters_map_id']),
                '--sequence', str(source['sequence_map_id']),
                '--slots', str(source['slots_map_id']), '--control', str(source['control_map_id']),
                '--hook-counts', str(source['hook_counts_map_id']),
                '--flow-stats', str(source['flow_stats_map_id'])]

    def start(self):
        _need(not self._started and not self._closed, 'Collector cannot be started twice')
        self._started = True
        self._aggregator = threading.Thread(target=self._aggregate_loop, daemon=True)
        self._aggregator.start()
        return self._start_reader()

    def _start_reader(self):
        _need(self.proc is None and not self._closed, 'A collector reader is already present')
        argv = self.reader_argv()
        self.state.reader_starting()
        self._reader_stop.clear()
        self.proc = self.recorder.spawn(self.label + '-reader', argv)
        self._ingest_thread = threading.Thread(target=self._ingest_loop, args=(self.proc,), daemon=True)
        self._ingest_thread.start()
        self.wait_for(lambda: self.state.ready is not None, 'native reader readiness')
        ready = copy.deepcopy(self.state.ready)
        _need(ready['ifindex'] == self.producer.ready['ifindex'] and
              ready['event_ring_bytes'] == self.producer.ready['event_ring_bytes'],
              'Native reader interface/ring capacity differs from actual producer')
        return ready

    def _ingest_loop(self, proc):
        offset, pending, exited_at = 0, b'', None
        try:
            while True:
                with proc.stdout_path.open('rb') as stream:
                    stream.seek(offset)
                    chunk = stream.read(65536)
                offset += len(chunk)
                pending += chunk
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    record = decode_record(line, self.source)
                    self.state.ingest(record)
                if len(pending) > MAX_RECORD_BYTES:
                    raise SchemaError('Native partial JSONL record exceeded its byte bound')
                if proc.poll() is not None:
                    exited_at = exited_at or time.monotonic()
                    if not chunk and (self._reader_stop.is_set() or time.monotonic() - exited_at >= 0.5):
                        if pending:
                            raise SchemaError('Native reader exited with an incomplete JSONL record')
                        break
                if not chunk:
                    self._reader_stop.wait(0.01)
        except Exception as exc:
            self.state.fail(str(exc), schema=isinstance(exc, SchemaError))
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)  # Only this recorder-owned Popen.
        finally:
            self.state.disconnected()

    def _aggregate_loop(self):
        while True:
            with self.state.changed:
                self.state.changed.wait_for(lambda: self._closing.is_set() or
                    (self.state.queue and not self.state.aggregation_paused), timeout=0.1)
                if self._closing.is_set() and not self.state.queue:
                    return
            self.state.aggregate()

    def wait_for(self, predicate, description='collector condition', timeout=10):
        deadline = time.monotonic() + timeout
        with self.state.changed:
            while not predicate():
                _need(not self.state.error_count, 'Collector failed: ' + '; '.join(self.state.errors))
                _need(time.monotonic() < deadline, 'Timed out waiting for ' + description)
                self.state.changed.wait(min(0.05, max(0, deadline - time.monotonic())))
            _need(not self.state.error_count, 'Collector failed: ' + '; '.join(self.state.errors))

    def refresh_source(self):
        """Return independent native counter/rate cache; never signal producer."""
        return self.state.summary()

    def refresh_flows(self):
        """Read cached native flow telemetry without spawning or polling producer."""
        return self.flows()

    def pause_aggregation(self):
        """Diagnostic-only deterministic queue-pressure control; ingestion continues."""
        with self.state.changed:
            self.state.aggregation_paused = True

    def resume_aggregation(self):
        with self.state.changed:
            self.state.aggregation_paused = False
            self.state.changed.notify_all()

    def pause_reader(self):
        _need(self.proc is not None and self.proc.poll() is None, 'No owned live reader to pause')
        self.proc.send_signal(signal.SIGSTOP)
        with self.state.lock:
            self.state.reader_paused = True
        deadline = time.monotonic() + 5
        while True:
            _need(self.proc.poll() is None, 'Owned reader exited while pausing')
            status = Path('/proc', str(self.proc.pid), 'status').read_text()
            if any(line.startswith('State:') and line.split()[1] in ('T', 't')
                   for line in status.splitlines()):
                break
            _need(time.monotonic() < deadline, 'Owned reader did not enter stopped state')
            time.sleep(0.01)

    def resume_reader(self):
        _need(self.proc is not None and self.proc.poll() is None, 'No owned live reader to resume')
        self.proc.send_signal(signal.SIGCONT)
        with self.state.lock:
            self.state.reader_paused = False

    def stop_reader(self):
        if self.proc is None:
            return None
        proc = self.proc
        if self.state.reader_paused and proc.poll() is None:
            self.resume_reader()
        code = self.recorder.stop(proc)
        self._reader_stop.set()
        if self._ingest_thread is not None:
            self._ingest_thread.join(timeout=5)
            _need(not self._ingest_thread.is_alive(), 'Native ingest thread failed to stop')
        stopped = copy.deepcopy(self.state.native_stopped)
        self.reader_exits.append({'pid': proc.pid, 'exit_code': code, 'stopped': stopped})
        self.proc = None
        self.state.disconnected()
        _need(code == 0 and stopped is not None and stopped['errors'] == 0,
              'Native reader did not exit with clean FD/socket release evidence')
        return self.reader_exits[-1]

    def restart_reader(self):
        self.stop_reader()
        return self._start_reader()

    def health(self):
        return self.state.health()

    def summary(self):
        return self.state.summary()

    def flows(self):
        return self.state.flows()

    def events(self, **kwargs):
        return self.state.events(**kwargs)

    def snapshot(self):
        return self.state.snapshot()

    def close(self):
        if self._closed:
            return self.health()
        error = None
        try:
            self.stop_reader()
        except Exception as exc:
            self.state.fail(str(exc))
            error = exc
        finally:
            self.resume_aggregation()
            self._closing.set()
            with self.state.changed:
                self.state.changed.notify_all()
            if self._aggregator is not None:
                self._aggregator.join(timeout=5)
                if self._aggregator.is_alive():
                    self.state.fail('Aggregation thread failed to stop')
            self.journal.close()
            self._closed = True
        if error is not None:
            raise error
        return self.health()
