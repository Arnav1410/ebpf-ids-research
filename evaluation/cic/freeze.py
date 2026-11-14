#!/usr/bin/env python3
"""Freeze predictions-blind moderate/final cohorts after the preceding gate."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sqlite3

from evaluation.cic.reconstruct import select, fingerprint


def freeze(args):
    reconstructed = json.loads((args.index / "reconstruction.json").read_text())
    previous = json.loads(args.previous.read_text())
    if previous["status"] != "PASS" or previous["source_binding_sha256"] != reconstructed["source_binding_sha256"]:
        raise ValueError("Previous matching/source validation gate did not pass")
    if args.stage == "final" and previous["records"] < min(2000, reconstructed["eligible"]):
        raise ValueError("Moderate validation required before final cohort")
    target = 1250 if args.stage == "moderate" else 15000
    database = sqlite3.connect("file:" + str((args.index / ".output/candidates.sqlite").resolve()) + "?mode=ro", uri=True)
    try:
        if args.stage == "resource":
            chosen = [json.loads(row[0]) for row in database.execute(
                "SELECT data FROM candidates WHERE eligible=1 ORDER BY rank,line LIMIT 2500")]
        else:
            chosen = select(database, target, target)
    finally:
        database.close()
    args.output.mkdir(parents=True, exist_ok=False)
    path = args.output / "cohort.jsonl"
    with path.open("w") as dest:
        for record in chosen:
            dest.write(json.dumps(record, separators=(",", ":")) + "\n")
    result = dict(status="FROZEN; INFERENCE NOT RUN", stage=args.stage,
                  input_count=len(chosen), target_each_class=None if args.stage == "resource" else target,
                  categories=dict(Counter(r["category"] for r in chosen)),
                  support=dict(Counter(r["label"] for r in chosen)),
                  cohort_sha256=fingerprint(path),
                  source_binding_sha256=reconstructed["source_binding_sha256"],
                  selection_policy_sha256=reconstructed["selection_policy_sha256"],
                  previous_validation_sha256=fingerprint(args.previous),
                  resource_batch_only=args.stage == "resource",
                  note="Shortfalls retained; no duplicates or prediction-dependent replacement")
    (args.output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--stage", choices=("moderate", "resource", "final"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    freeze(parser.parse_args())
