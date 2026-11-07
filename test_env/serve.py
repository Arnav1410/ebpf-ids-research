"""Localhost lab dashboard; independent live collector or explicitly simulated replay.

No HTTP mutation endpoints. Live mode owns only the accepted private lab and
expires within Recorder's child lifetime bound. SIGHUP explicitly restarts its
native reader; unexpected reader failure remains visible until operator action.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import threading
import time

from .commands import Recorder
from .dashboard import ReplayState, create_app
from .lab import Lab, SERVER_IF, SERVER_NS
from .tc import _need

ROOT = Path(__file__).resolve().parents[1]


class LiveView:
    """Presentation adapter; no BPF calls, inference or packet-path ownership."""
    def __init__(self, collector, producer):
        self.collector, self.producer = collector, producer

    def health(self):
        result = self.collector.health()
        received = result['last_native_received_monotonic_ns']
        age = None if received is None else max(0, time.monotonic_ns() - received)
        alive = self.producer.proc is not None and self.producer.proc.poll() is None
        result.update({'producer_alive': alive, 'interface': SERVER_IF, 'namespace': SERVER_NS,
                       'reader_pid': None if self.collector.proc is None else self.collector.proc.pid,
                       'telemetry_age_ns': age, 'stale': age is None or age > 3_000_000_000,
                       'hooks': {name: {'program_id': self.producer.ready['program_ids'][name],
                                        'verified_at_start': True}
                                 for name in ('ingress', 'egress')},
                       'hook_status_scope': 'IDs and attachment verified at start; current activity is measured counters'})
        result['connected'] = result['connected'] and alive and not result['stale']
        return result

    def summary(self):
        return self.collector.summary()

    def flows(self):
        return self.collector.flows()

    def events(self):
        return self.collector.events()


def _serve(recorder, args, state, mode, errors, collector=None):
    import uvicorn
    log_config = {'version': 1, 'disable_existing_loggers': False,
        'formatters': {'plain': {'format': '%(asctime)s %(levelname)s %(message)s'}},
        'handlers': {'file': {'class': 'logging.FileHandler', 'filename': str(recorder.out / 'http.log'),
                             'formatter': 'plain'},
                     'console': {'class': 'logging.StreamHandler', 'stream': 'ext://sys.stderr',
                                 'formatter': 'plain'}},
        'loggers': {'uvicorn': {'handlers': ['file', 'console'], 'level': 'INFO', 'propagate': False},
                    'uvicorn.error': {'level': 'INFO'},
                    'uvicorn.access': {'handlers': ['file'], 'level': 'INFO', 'propagate': False}}}
    server = uvicorn.Server(uvicorn.Config(create_app(state, mode=mode), host='127.0.0.1',
        port=args.port, log_config=log_config, access_log=False, workers=1,
        timeout_keep_alive=3, limit_concurrency=16))
    stopping, restart = threading.Event(), threading.Event()
    previous_hup = signal.signal(signal.SIGHUP, lambda *_: restart.set())

    def monitor():
        deadline, tick, announced = time.monotonic() + args.seconds, time.monotonic(), False
        try:
            while not stopping.wait(0.1):
                if server.started and not announced:
                    ready = {'event': 'dashboard_ready', 'mode': mode, 'simulated': mode == 'replay',
                             'url': f'http://127.0.0.1:{args.port}', 'pid': os.getpid(),
                             'seconds': args.seconds}
                    recorder.write_json('ready.json', ready)
                    print(json.dumps(ready), flush=True)
                    announced = True
                if collector is not None and restart.is_set():
                    restart.clear()
                    collector.restart_reader()
                    recorder.write_json('reader-restart.json', {'mode': mode, 'health': state.health()})
                if mode == 'replay' and server.started and time.monotonic() >= tick:
                    state.advance()
                    tick = time.monotonic() + args.interval
                if time.monotonic() >= deadline:
                    server.should_exit = True
                    return
        except Exception as exc:
            errors.append('Service monitor: ' + str(exc))
            server.should_exit = True

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    try:
        server.run()
        _need(server.started, 'HTTP server never reached actual readiness')
    finally:
        stopping.set()
        thread.join(timeout=10)
        signal.signal(signal.SIGHUP, previous_hup)
        _need(not thread.is_alive(), 'Dashboard monitor failed to stop')


def _interrupt(signum, _frame):
    # Uvicorn replays captured signals after graceful shutdown. A Python handler
    # preserves finally cleanup instead of default SIGTERM killing owned maps.
    raise InterruptedError('Operator signal ' + str(signum))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    for mode in ('live', 'replay'):
        command = commands.add_parser(mode)
        command.add_argument('--out', type=Path, required=True, help='New log directory; never reused')
        command.add_argument('--port', type=int, default=8765, choices=range(1024, 65536), metavar='1024..65535')
        command.add_argument('--seconds', type=int, default=120, choices=range(1, 241), metavar='1..240')
        if mode == 'live':
            command.add_argument('--loader', type=Path, required=True)
            command.add_argument('--object', type=Path, required=True)
            command.add_argument('--bpftool', type=Path, required=True)
            command.add_argument('--reader', type=Path)
            command.add_argument('--model', type=Path, default=ROOT / 'src/mlp_params.bpf.h')
        else:
            command.add_argument('--sample', type=Path, required=True)
            command.add_argument('--interval', type=float, default=0.5, help='Replay step seconds (0.05..10)')
    args = parser.parse_args(argv)
    if args.mode == 'live' and os.geteuid() != 0:
        parser.error('Live mode requires sudo in the isolated VM; replay needs no root')
    if args.mode == 'replay' and not 0.05 <= args.interval <= 10:
        parser.error('Replay interval must be finite and within 0.05..10 seconds')
    recorder = Recorder(args.out.resolve())
    report = {'schema_version': 1, 'stage': '07', 'mode': args.mode,
              'simulated': args.mode == 'replay', 'status': 'fail', 'errors': []}
    errors = report['errors']
    previous_term = signal.signal(signal.SIGTERM, _interrupt)
    try:
        if args.mode == 'replay':
            state = ReplayState(args.sample.resolve())
            try:
                _serve(recorder, args, state, 'replay', errors)
            except (KeyboardInterrupt, InterruptedError) as exc:
                report['operator_stop'] = str(exc)
            report['final_health'] = state.health()
            report['final_summary'] = state.summary()
        else:
            from .collector import Collector
            from .inference import Inference
            lab = Lab(recorder)
            try:
                with lab:
                    producer = Inference(recorder, lab, args.loader, args.object, args.bpftool,
                                         args.model, label='dashboard-producer')
                    collector = None
                    try:
                        report['producer_ready'] = producer.start()
                        reader = args.reader or args.loader.parent / 'nn-collect'
                        collector = Collector(recorder, producer, reader, label='dashboard-collector')
                        report['reader_ready'] = collector.start()
                        state = LiveView(collector, producer)
                        try:
                            _serve(recorder, args, state, 'live', errors, collector)
                        except (KeyboardInterrupt, InterruptedError) as exc:
                            report['operator_stop'] = str(exc)
                    finally:
                        try:
                            if collector is not None:
                                recorder.write_json('final-collector.json', collector.snapshot())
                                try:
                                    recorder.write_json('final-map-snapshot.json', producer.inspect())
                                finally:
                                    report['collector_close'] = collector.close()
                                    report['reader_exits'] = collector.reader_exits
                                    _need(report['collector_close']['error_count'] == 0,
                                          'Collector reported an ingestion/lifecycle failure')
                        finally:
                            report['producer_close'] = producer.close()
                            _need(report['producer_close']['complete'], 'Owned producer objects remain')
            finally:
                report['lab'] = lab.state
            _need(lab.state.get('cleanup_complete') is True, 'Lab namespace cleanup not confirmed')
    except (Exception, SystemExit) as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        try:
            recorder.close()
        except Exception as exc:
            errors.append('Recorder cleanup: ' + str(exc))
        report['status'] = 'pass' if not errors else 'fail'
        recorder.write_json('service-report.json', report)
    print(json.dumps({'status': report['status'], 'mode': args.mode,
                      'report': str(recorder.out / 'service-report.json'), 'errors': errors}), flush=True)
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
