"""Run with python3 -m evaluation; outputs are immutable experiment directories."""
import argparse
import json
import sys
import subprocess

from .artifacts import DEFAULT_DATA, DEFAULT_LABELS, DEFAULT_MODEL, new_directory, read_json, write_json
from .dataset import audit_dataset, load_dataset
from .model import load_model
from .reference import diagnostic, native_conformance


def main(argv=None):
    parser = argparse.ArgumentParser(description="Baseline correctness and accuracy evaluation")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, description in (
            ("audit", "Audit numeric dataset contents without loading pickles"),
            ("reference", "Evaluate existing integer parameters; diagnostic, not held-out"),
            ("native", "Compare reference stages with the actual host-compiled baseline header"),
            ("split", "Freeze a deterministic exact-feature-group holdout"),
            ("train", "Train and compare one paired floating/quantized checkpoint on a frozen split"),
            ("evaluate", "Re-evaluate saved models and split without retraining"),
            ("kernel", "Compare actual isolated BPF stages, complete chain and packet features")):
        command = commands.add_parser(name, help=description)
        command.add_argument("--data", default=str(DEFAULT_DATA))
        command.add_argument("--labels", default=str(DEFAULT_LABELS))
        command.add_argument("--out", required=True, help="New experiment directory")
        if name in ("reference", "native", "kernel"):
            command.add_argument("--model", default=str(DEFAULT_MODEL), help="Parameter header or quantized-model JSON")
        if name == "reference":
            command.add_argument("--trace-limit", type=int, default=16)
        if name in ("native", "kernel"):
            command.add_argument("--limit", type=int, default=32 if name == "kernel" else 128)
        if name == "split":
            command.add_argument("--seed", type=int, default=2026)
            command.add_argument("--test-fraction", type=float, default=0.2)
        if name == "train":
            command.add_argument("--split", required=True, help="Saved split.json from the split command")
            command.add_argument("--seed", type=int, default=2026)
            command.add_argument("--epochs", type=int, default=32)
            command.add_argument("--batch-size", type=int, default=512)
            command.add_argument("--learning-rate", type=float, default=0.001)
        if name == "evaluate":
            command.add_argument("--experiment", required=True, help="Existing train output directory")
    args = parser.parse_args(argv)
    try:
        dataset = load_dataset(args.data, args.labels)
        model = load_model(args.model) if args.command in ("reference", "native", "kernel") else None
        if args.command == "reference" and args.trace_limit < 0:
            raise ValueError("--trace-limit must not be negative")
        if args.command in ("native", "kernel") and args.limit <= 0:
            raise ValueError("--limit must be positive")
        directory = new_directory(args.out)
        if args.command == "audit":
            report = audit_dataset(dataset)
            write_json(directory / "manifest.json", report)
        elif args.command == "reference":
            report = diagnostic(dataset, model, directory, args.trace_limit)
        elif args.command == "native":
            report = native_conformance(dataset, model, directory, args.limit)
        elif args.command == "split":
            from .split import create_split
            report = create_split(dataset, args.seed, args.test_fraction)
            write_json(directory / "split.json", report)
        elif args.command == "train":
            from .training import train_experiment
            report = train_experiment(dataset, read_json(args.split), directory, seed=args.seed,
                                      epochs=args.epochs, batch_size=args.batch_size,
                                      learning_rate=args.learning_rate)
        elif args.command == "kernel":
            from .kernel import kernel_validation
            report = kernel_validation(dataset, model, directory, args.limit)
        else:
            from .training import evaluate_experiment
            report = evaluate_experiment(dataset, args.experiment, directory)
        print(json.dumps({"status": report.get("status", "complete"), "command": args.command,
                          "claim": report.get("claim", "frozen_local_grouped_split"), "rows": len(dataset.features),
                          "metrics": report.get("metrics") if "float_metrics" not in report else
                                     {"float": report["float_metrics"], "integer": report["integer_metrics"]},
                          "report": str(directory)}, indent=2))
        return 77 if report.get("status") == "blocked" else 1 if report.get("status") == "fail" else 0
    except (ImportError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
