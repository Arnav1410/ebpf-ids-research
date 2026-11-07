"""Read-only local dashboard and bounded playback of recorded classifications.

Replay validates the native transport schema, not the origin or correctness of a
capture. Historical native ``mode=live`` fields remain intact; the surrounding
replay state and HTTP envelope always mark them as simulated.
"""
import copy
import json
from pathlib import Path
import threading

from .event_schema import FLOW_STATES, SchemaError, decode_record, validate_source

MAX_REPLAY_BYTES = 1 << 20
MAX_REPLAY_RECORDS = 256
_DIRECTION_UNAVAILABLE = ('first_ns', 'last_ns', 'max_iat_ns',
                          'min_segment_bytes', 'max_segment_bytes')


class ReplayState:
    """Deterministic, bounded recorded data; no reader, inference, or BPF owner."""

    def __init__(self, sample_path):
        with Path(sample_path).open('rb') as sample:
            payload = sample.read(MAX_REPLAY_BYTES + 1)
        if len(payload) > MAX_REPLAY_BYTES:
            raise SchemaError('Replay sample exceeds the 1 MiB byte bound')
        records = []
        sequences = set()
        source = None
        for line_number, line in enumerate(payload.split(b'\n'), 1):
            if not line.strip():
                continue
            if len(records) == MAX_REPLAY_RECORDS:
                raise SchemaError('Replay sample exceeds 256 classification records')
            try:
                if source is None:
                    # Bootstrap only the expected identity. decode_record below
                    # still validates every byte, including duplicate JSON keys.
                    first = json.loads(line)
                    if not isinstance(first, dict):
                        raise SchemaError('First replay record must be an object')
                    source = copy.deepcopy(validate_source(first.get('source')))
                record = decode_record(line, source)
                if record['event'] != 'classification':
                    raise SchemaError('Replay accepts classification records only')
                if record['sequence'] in sequences:
                    raise SchemaError('Duplicate replay sequence: ' + str(record['sequence']))
            except (SchemaError, UnicodeDecodeError, json.JSONDecodeError,
                    RecursionError) as exc:
                raise SchemaError('Replay line ' + str(line_number) + ': ' + str(exc)) from exc
            records.append(record)
            sequences.add(record['sequence'])
        if not records:
            raise SchemaError('Replay sample contains no classification records')
        self._records = records
        self._source = source
        self._lock = threading.RLock()
        self.reset()

    def reset(self):
        """Hide every record and restore the exact initial replay state."""
        with self._lock:
            self._visible = 0
            self._labels = {0: 0, 1: 0}
            self._failed = 0
            self._classified = {}
            self._counts = {}

    def advance(self, count=1):
        """Reveal at most count records in capture order; return number revealed."""
        if type(count) is not int or count < 0:
            raise ValueError('Replay advance count must be a nonnegative integer')
        with self._lock:
            end = min(self._visible + count, len(self._records))
            for record in self._records[self._visible:end]:
                ident = record['flow_id']
                previous = self._classified.get(ident)
                if previous is None or record['trigger_ordinal'] > previous['trigger_ordinal']:
                    self._classified[ident] = record
                previous_counts = self._counts.get(ident)
                if record['counts_valid'] and (previous_counts is None or
                        (record['counts_ordinal'], record['counts_timestamp_ns']) >
                        (previous_counts['counts_ordinal'], previous_counts['counts_timestamp_ns'])):
                    self._counts[ident] = record
                if record['status'] == 0:
                    self._labels[record['label']] += 1
                else:
                    self._failed += 1
            revealed = end - self._visible
            self._visible = end
            return revealed

    def health(self):
        with self._lock:
            return copy.deepcopy({
                'mode': 'replay', 'simulated': True, 'source': self._source,
                'reader_status': 'simulated', 'connected': False,
                'reader_generation': None, 'source_timestamp_ns': None,
                'last_native_received_monotonic_ns': None,
                'queue_size': None, 'queue_capacity': None,
                'python_queue_drops': None, 'kernel_ring_drops': None,
                'reader_decode_errors': None, 'schema_errors': None,
                'error_count': 0, 'errors': [], 'journal': None, 'sequence': None,
                'replay_progress': {'visible': self._visible, 'total': len(self._records),
                                    'complete': self._visible == len(self._records)},
                'loss_accounting': 'Recorded classifications do not establish live connectivity or capture loss totals',
            })

    def summary(self):
        with self._lock:
            return copy.deepcopy({
                'mode': 'replay', 'simulated': True, 'source': self._source,
                'numeric_labels': self._labels, 'failed_classifications': self._failed,
                'label_semantics': {'0': 'unverified', '1': 'unverified'},
                'scope': 'Revealed recorded classifications only; simulated playback, not current accuracy or map occupancy',
                'inference_counters': None, 'hook_counts': None, 'rates': None,
                'flow_inspection': None, 'retained_classifications': self._visible,
                'history_capacity': MAX_REPLAY_RECORDS,
                'retained_classified_flows': len(self._classified),
                'flow_capacity': MAX_REPLAY_RECORDS,
            })

    def flows(self):
        with self._lock:
            result = []
            for ident, classification in self._classified.items():
                counts = self._counts.get(ident)
                row = {'id': ident, 'key': classification['key'], 'initiator': None,
                       'state': None if counts is None else FLOW_STATES[counts['flow_state']],
                       'first_ns': None,
                       'last_ns': None if counts is None else counts['counts_timestamp_ns'],
                       'closed_ns': None,
                       'ordinal': None if counts is None else counts['counts_ordinal']}
                for direction in ('a_to_b', 'b_to_a'):
                    row[direction] = None if counts is None else {
                        **counts['direction_counts'][direction],
                        **dict.fromkeys(_DIRECTION_UNAVAILABLE)}
                result.append({'flow': row, 'classification': classification,
                               'classification_state': 'classified' if classification['status'] == 0 else 'failed',
                               'active': None})
            return copy.deepcopy(result)

    def events(self):
        """Return complete revealed arrival history, never a sequence cursor."""
        with self._lock:
            return copy.deepcopy(self._records[:self._visible])


def create_app(state, *, mode):
    """Build only read-only API and exact allowlisted local asset routes."""
    if mode not in ('live', 'replay'):
        raise ValueError('Dashboard mode must be live or replay')
    health = state.health()
    if health.get('mode') != mode:
        raise ValueError('Dashboard mode differs from the supplied state')
    if mode == 'replay' and (health.get('connected') is not False or
                             health.get('reader_status') != 'simulated'):
        raise ValueError('Replay state must be simulated and disconnected')

    from fastapi import FastAPI
    from fastapi.responses import FileResponse
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1'])
    web = Path(__file__).resolve().parent / 'web'

    @app.middleware('http')
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'")
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        return response

    def endpoint(method):
        async def read_state():
            return {'schema_version': 1, 'mode': mode, 'simulated': mode == 'replay',
                    'data': method()}
        return read_state

    for name in ('health', 'summary', 'flows', 'events'):
        app.add_api_route('/' + name, endpoint(getattr(state, name)),
                          methods=['GET'], name=name)

    @app.get('/', include_in_schema=False)
    async def index():
        return FileResponse(web / 'index.html', media_type='text/html')

    @app.get('/app.js', include_in_schema=False)
    async def javascript():
        return FileResponse(web / 'app.js', media_type='text/javascript')

    @app.get('/style.css', include_in_schema=False)
    async def stylesheet():
        return FileResponse(web / 'style.css', media_type='text/css')

    return app
