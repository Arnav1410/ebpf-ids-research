#!/usr/bin/env python3
"""Summarize and plot audited saved kernel measurements, without loading BPF."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import sklearn
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score

MODES = ("xdp_q16", "static_q16", "layer_specific")
NAMES = ("Original XDP Q16", "TC Q16", "TC layer-specific")
COLORS = ("#0072B2", "#009E73", "#D55E00")
BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[1]


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def statistics(values):
    x = np.asarray(values, dtype=np.float64)
    return dict(samples=len(x), mean_ns=float(x.mean()),
                median_ns=float(np.median(x)),
                p95_ns=float(np.percentile(x, 95)),
                p99_ns=float(np.percentile(x, 99)),
                minimum_ns=int(x.min()), maximum_ns=int(x.max()),
                population_stddev_ns=float(x.std(ddof=0)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = read(args.run / "results.json")
    review = read(args.review / "audit.json")
    assert results["status"] == review["status"] == "PASS"
    assert results["phase"] == review["phase"] == "full"
    assert review["raw_sha256"] == sha(args.run / "measurements.jsonl.gz")
    assert review["results_sha256"] == sha(args.run / "results.json")
    with (args.review / "per-vector-timings.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 50868
    assert sum(r["phase"] == "measured" for r in rows) == 42390
    assert sum(r["phase"] == "warmup" for r in rows) == 8478
    assert all(r["status"] == "PASS" and int(r["cpu"]) == 0 for r in rows)
    assert len({(r["mode"], r["trial"], r["position"]) for r in rows}) == len(rows)
    split = read(ROOT / "experiments/fresh_model_20261108/run/split.json")
    test_ids = split["partitions"]["test"]["indices"]
    truth_all = np.load(ROOT / "dataset/reproduction-xdp-label.npy", allow_pickle=False).reshape(-1)
    truth = truth_all[test_ids].astype(np.int64)
    assert len(test_ids) == 2826 and set(truth) == {0, 1}
    times, trials, labels, logits, metrics, tails = {}, {}, {}, {}, {}, {}
    for mode in MODES:
        selected = [r for r in rows if r["mode"] == mode]
        times[mode] = np.array([int(r["duration_ns"]) for r in selected
                                if r["phase"] == "measured"], dtype=np.int64)
        assert len(times[mode]) == 14130
        for key, value in statistics(times[mode]).items():
            assert np.isclose(value, results["modes"][mode][key], rtol=1e-12, atol=1e-9)
        trials[mode] = []
        for trial in range(-1, 5):
            part = [r for r in selected if int(r["trial"]) == trial]
            assert [int(r["row_index"]) for r in part] == test_ids
            if trial >= 0:
                trials[mode].append(statistics([int(r["duration_ns"]) for r in part]))
        unique = [r for r in selected if int(r["trial"]) == 0]
        logits[mode] = np.array([[int(r["logit0"]), int(r["logit1"])] for r in unique], dtype=np.int64)
        labels[mode] = np.array([int(r["label"]) for r in unique], dtype=np.int64)
        assert np.array_equal(labels[mode], (logits[mode][:, 0] <= logits[mode][:, 1]).astype(np.int64))
        for trial in (-1, 1, 2, 3, 4):
            part = [r for r in selected if int(r["trial"]) == trial]
            assert np.array_equal(labels[mode], [int(r["label"]) for r in part])
            assert np.array_equal(logits[mode], [[int(r["logit0"]), int(r["logit1"])] for r in part])
        tn, fp, fn, tp = confusion_matrix(truth, labels[mode], labels=[0, 1]).ravel().tolist()
        independent_accuracy = (tp + tn) / len(truth)
        independent_f1 = 2 * tp / (2 * tp + fp + fn)
        assert np.isclose(independent_accuracy, accuracy_score(truth, labels[mode]))
        assert np.isclose(independent_f1, f1_score(truth, labels[mode]))
        metrics[mode] = dict(unique_rows=len(truth), TP=tp, FP=fp, TN=tn, FN=fn,
                             accuracy=independent_accuracy, f1=independent_f1,
                             label_ties=int(np.sum(logits[mode][:, 0] == logits[mode][:, 1])),
                             scope="Stored-vector model evaluation against supplied reproduction labels; no live-network or external-data claim")
        tails[mode] = dict(above_100_us=int(np.sum(times[mode] > 100000)),
                           above_1_ms=int(np.sum(times[mode] > 1000000)),
                           outliers_removed=0)
    assert all(np.array_equal(labels[MODES[0]], labels[m]) for m in MODES)
    assert np.array_equal(logits["xdp_q16"], logits["static_q16"])
    args.output.mkdir(parents=True, exist_ok=False)
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False,
                         "axes.spines.right": False, "pdf.fonttype": 42})

    def save(fig, name):
        fig.savefig(args.output / (name + ".png"), dpi=170, bbox_inches="tight")
        fig.savefig(args.output / (name + ".pdf"), bbox_inches="tight")
        plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 4.5), layout="constrained")
    keys = ("mean_ns", "median_ns", "p95_ns", "p99_ns")
    x = np.arange(len(keys))
    for i, mode in enumerate(MODES):
        values = [results["modes"][mode][k] / 1000 for k in keys]
        bars = ax.bar(x + (i - 1) * .25, values, .25, color=COLORS[i], label=NAMES[i])
        ax.bar_label(bars, fmt="%.2f", padding=3, fontsize=8)
    ax.set(xticks=x, xticklabels=("Mean", "Median", "p95", "p99"),
           ylabel="Kernel test-run duration (µs)", ylim=(0, 38),
           title="Fresh model: paired six-stage kernel inference pipelines")
    ax.legend(loc="upper left")
    ax.text(0, -.19, "2,826 vectors × 5 trials per mode; all outliers retained; original XDP trace calls enabled.",
            transform=ax.transAxes, fontsize=9)
    save(fig, "latency-summary")

    fig, ax = plt.subplots(figsize=(9, 4.5), layout="constrained")
    for i, mode in enumerate(MODES):
        ordered = np.sort(times[mode]) / 1000
        ax.step(ordered, np.arange(1, len(ordered) + 1) / len(ordered),
                where="post", color=COLORS[i], label=NAMES[i])
    ax.set(xscale="log", ylabel="Fraction of measured executions", ylim=(0, 1.01),
           xlabel="Kernel test-run duration (µs, logarithmic axis)",
           title="Full measured distributions, including every tail sample")
    ax.legend(loc="lower right")
    ax.grid(which="both", alpha=.2)
    save(fig, "latency-ecdf")

    fig, ax = plt.subplots(figsize=(9, 4.5), layout="constrained")
    for i, mode in enumerate(MODES):
        ax.plot(range(1, 6), [t["mean_ns"] / 1000 for t in trials[mode]],
                "o-", color=COLORS[i], label=NAMES[i])
    ax.set(xticks=range(1, 6), xlabel="Measured trial (2,826 vectors per mode)",
           ylabel="Mean kernel test-run duration (µs)",
           title="Per-trial variation in the same rotating-order session")
    ax.legend()
    ax.grid(alpha=.2)
    save(fig, "latency-trials")

    ratios = {key: {f"{a}_over_{b}": results["modes"][a][key] / results["modes"][b][key]
                    for a, b in (("static_q16", "xdp_q16"), ("layer_specific", "xdp_q16"),
                                 ("layer_specific", "static_q16"))}
              for key in ("mean_ns", "median_ns", "p95_ns", "p99_ns")}
    output = dict(status="PASS", source_run=str(args.run.resolve()),
                  raw_sha256=review["raw_sha256"], results_sha256=review["results_sha256"],
                  reviewed_csv_sha256=sha(args.review / "per-vector-timings.csv"),
                  measured_rows=42390, warmup_rows=8478, guard_calls=9,
                  tails=tails, observed_pipeline_ratios=ratios,
                  unique_kernel_prediction_metrics=metrics,
                  prediction_disagreements=dict(xdp_vs_tc_q16=0, xdp_vs_tc_layer=0),
                  xdp_vs_tc_q16_logits="Bit-identical for every held-out vector and repetition",
                  layer_vs_q16_logit_max_abs_Q16_units=int(np.max(np.abs(logits["layer_specific"] - logits["xdp_q16"]))),
                  scope="Same-session implementation-pipeline comparison; trace/parsing/telemetry differ. No generic XDP-versus-TC hook speedup claim.",
                  versions=dict(numpy=np.__version__, matplotlib=matplotlib.__version__, sklearn=sklearn.__version__),
                  plots=[p.name for p in sorted(args.output.iterdir())])
    (args.output / "summary.json").write_text(json.dumps(output, indent=2, allow_nan=False) + "\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
