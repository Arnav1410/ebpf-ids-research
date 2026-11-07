"""Run isolated live validation, never attach to a real management interface."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys

from .commands import Recorder
from .lab import Lab

ROOT = Path(__file__).resolve().parent.parent


def interrupted(signum, _frame):
    raise InterruptedError(f"Signal {signum}: stopping owned lab resources")


def host_snapshot(recorder):
    """Capture configuration, not packet counters or changing address lifetimes."""
    return {
        "links": recorder.json(["ip", "-j", "-d", "link", "show"]),
        "ipv4_routes": recorder.json(["ip", "-j", "-4", "route", "show", "table", "all"]),
        "ipv6_routes": recorder.json(["ip", "-j", "-6", "route", "show", "table", "all"]),
        "qdiscs": recorder.json(["tc", "-j", "qdisc", "show"]),
        "namespaces": recorder.run(["ip", "netns", "list"]).stdout.splitlines(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    baseline = commands.add_parser("baseline", help="Validate the unchanged XDP detector in owned namespaces")
    baseline.add_argument("--out", type=Path, required=True, help="New evidence directory; never reused")
    baseline.add_argument("--loader", type=Path, required=True)
    baseline.add_argument("--updater", type=Path, required=True)
    baseline.add_argument("--bpftool", type=Path, default=ROOT / ".output/bpftool/bpftool")
    for name, help_text in (
        ("probe", "Validate detect-only TC ingress/egress counters in owned namespaces"),
        ("flows", "Validate bidirectional TC flow tracking and expiration in owned namespaces"),
        ("inference", "Validate original RX features and six-stage integer TC inference"),
        ("events", "Validate bounded kernel classification events and independent collection"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--out", type=Path, required=True, help="New evidence directory; never reused")
        command.add_argument("--loader", type=Path, required=True)
        command.add_argument("--object", type=Path, required=True)
        command.add_argument("--bpftool", type=Path, default=ROOT / ".output/bpftool/bpftool")
        if name in ("inference", "events"):
            command.add_argument("--model", type=Path, default=ROOT / "src/mlp_params.bpf.h")
        if name == "events":
            command.add_argument("--reader", type=Path, help="Native nn-collect; defaults beside loader")
        if name == "inference":
            command.add_argument("--paired-dir", type=Path, default=ROOT / ".output/evaluation/m3-train",
                                 help="Existing portable float/quantized pair and frozen split; never retrained")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("Run this isolated lab command with sudo; no password is accepted by the program")
    for name in ("loader", "bpftool", "updater" if args.command == "baseline" else "object"):
        path = getattr(args, name).resolve()
        if not path.is_file() or (name != "object" and not os.access(path, os.X_OK)):
            parser.error(f"Missing input {name}: {path}")
        setattr(args, name, path)
    siblings = {"flows": ("flow-inspect",), "inference": ("nn-vectors", "flow-inspect"),
                "events": ("flow-inspect",)}
    for name in siblings.get(args.command, ()):
        executable = args.loader.parent / name
        if not executable.is_file() or not os.access(executable, os.X_OK):
            parser.error(f"Missing sibling backend utility: {executable}")
    if args.command == "events":
        args.reader = (args.reader or args.loader.parent / "nn-collect").resolve()
        if not args.reader.is_file() or not os.access(args.reader, os.X_OK):
            parser.error(f"Missing event reader: {args.reader}")
        args.model = args.model.resolve()
        if not args.model.is_file():
            parser.error(f"Missing model input: {args.model}")
    if args.command == "inference":
        args.model = args.model.resolve()
        args.paired_dir = args.paired_dir.resolve()
        for path in (args.model, *(args.paired_dir / name for name in
                                  ("float-model.json", "quantized-model.json", "split.json"))):
            if not path.is_file():
                parser.error(f"Missing model input: {path}")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        recorder = Recorder(args.out.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    report = {"schema_version": 1,
              "stage": {"baseline": "02", "probe": "03", "flows": "04",
                        "inference": "05", "events": "06"}[args.command],
              "status": "fail", "mode": "detect_only", "command": args.command,
              "label_semantics": "unverified" if args.command in ("baseline", "inference", "events") else "not_applicable",
              "errors": []}
    validated = False
    lab = Lab(recorder)
    before = None
    try:
        before = host_snapshot(recorder)
        recorder.write_json("command-host-before.json", before)
        with lab:
            report["ping"] = lab.ping_checks()
            report["tcp_connectivity"] = lab.exchange()
            if args.command == "baseline":
                from .baseline import run_baseline
                backend = run_baseline(recorder, lab, args.loader, args.updater, args.bpftool)
                report["detector"] = backend
            elif args.command == "probe":
                from .tc import run_probe
                backend = run_probe(recorder, lab, args.loader, args.object, args.bpftool)
                report["probe"] = backend
            elif args.command == "flows":
                from .flows import run_flows
                backend = run_flows(recorder, lab, args.loader, args.object, args.bpftool)
                report["flows"] = backend
            elif args.command == "inference":
                from .inference import run_inference
                backend = run_inference(recorder, lab, args.loader, args.object, args.bpftool,
                                        args.model, args.paired_dir)
                report["inference"] = backend
            else:
                from .event_validation import run_events
                backend = run_events(recorder, lab, args.loader, args.object, args.bpftool,
                                     args.reader, args.model)
                report["events"] = backend
            if backend.get("status") != "pass" or backend.get("cleanup_complete") is not True:
                raise RuntimeError("Backend did not validate execution and owned cleanup")
        if lab.state.get("cleanup_complete") is not True:
            raise RuntimeError("Owned namespace cleanup was not confirmed")
        validated = True
    except (Exception, KeyboardInterrupt) as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        report["lab"] = lab.state
        try:
            after = host_snapshot(recorder)
            recorder.write_json("command-host-after.json", after)
            report["host_configuration_unchanged"] = before is not None and before == after
            if not report["host_configuration_unchanged"]:
                report["errors"].append("Root namespace configuration differs from its pre-run snapshot")
        except (Exception, KeyboardInterrupt) as exc:
            report["errors"].append("Post-run host snapshot failed: " + str(exc))
        try:
            recorder.close()
        except (Exception, KeyboardInterrupt) as exc:
            report["errors"].append("Owned child cleanup failed: " + str(exc))
        if validated and not report["errors"]:
            report["status"] = "pass"
        recorder.write_json("report.json", report)
    print(json.dumps({"status": report["status"], "stage": report["stage"],
                      "report": str(recorder.out / "report.json"), "errors": report["errors"]}, indent=2))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
