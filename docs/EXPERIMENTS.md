# Reproduce models, arithmetic and benchmarks

Read [command status definitions](GETTING_STARTED.md). Outputs below are new paths. No command requires physical attachment. Do not overwrite archived result directories or calibrate from test data.

## Frozen models and data

The included `dataset/reproduction-xdp-data.npy` is an 18,840 × 6 int64 matrix; `reproduction-xdp-label.npy` contains 18,840 numeric binary labels. They originate from the authors' repository. Exact original collection/sample membership and checkpoint training split are unknown. Paper Table III counts cannot be assigned to these files. Original model-training overlap remains unknown.

`src/mlp_params.bpf.h` is the original Q16 model/scaler, SHA256 `f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11`. No original float checkpoint is available; the old scripts fit StandardScaler before splitting and have leakage limitations.

The separate fresh model uses identical architecture, 1,280 weights, exact-feature groups and fixed seed 20261108: 13,187 training / 2,827 validation / 2,826 test rows. Scaler fit and arithmetic calibration use training rows only; validation CE selects the checkpoint. This is not a capture/session-independent split.

| Frozen fresh artifact | SHA256 |
| --- | --- |
| Numeric checkpoint | `d299f964ecaa7b918eca65529371dbfa6db8797df97ee24b73a324ab52acef1b` |
| Runtime Q16 header | `e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391` |
| Packed Q16 parameters | `1558c438e06600d8e3a5eeb28fe23c6aed94cb693a75dea4817497add71bd8d9` |
| Kernel-facing scaler bytes | `f900a854d88a1eb6a346da7e102c97f70a2481e4332345b2a28b2d5ce91ef650` |

Exact split IDs, train/validation/test NPZs, checkpoint, scaler, model headers, checkpoint-selection history and compact host predictions are selected artifacts under `experiments/fresh_model_20261108/run/`. Numeric NPZ loading always uses `allow_pickle=False`. Runtime copies live separately at `deployment/models/fresh/`. `--model original|fresh` is independent of `--mode static_q16|layer_specific`; original remains the rollback default. Runtime readbacks verify both parameter-map slots and scaler bytes, not just source hashes.

## Reproduce fresh predictions without retraining

After installing [analysis dependencies](GETTING_STARTED.md), these commands are **E** (with the audit's temporary Python path instead of `.venv`):

```bash
mkdir -p artifacts/fresh-reproduction
cp experiments/fresh_model_20261108/run/{checkpoint.npz,scaler.json,split.json,config.json,history.json,freeze.json,gate1.json,train.npz,validation.npz,test.npz,fp32-predictions.jsonl.gz,fp32-metrics.json} artifacts/fresh-reproduction/
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python experiments/fresh_model_20261108/pipeline.py quantize --output artifacts/fresh-reproduction
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python experiments/fresh_model_20261108/pipeline.py compare --output artifacts/fresh-reproduction
```

This rebuilds host wrappers in a copied source tree, overlays frozen fresh parameters and recreates training-only calibration deterministically. It never edits production headers. `compare` checks all three integer implementations/tensors against their references and the saved FP32 outputs on the same test IDs. Inspect `comparison.json`; numerical differences between scales are not classification disagreement. Integer equal logits choose class 1, while FP32 argmax chooses class 0; no ties occurred in the saved test cohort.

For an intentional **new training reproduction** (**V**, source checked; not retrained in this audit), use a different output and run all stages in order:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python experiments/fresh_model_20261108/pipeline.py prepare --output artifacts/new-training
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python experiments/fresh_model_20261108/pipeline.py train --output artifacts/new-training
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python experiments/fresh_model_20261108/pipeline.py fp32 --output artifacts/new-training
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python experiments/fresh_model_20261108/pipeline.py quantize --output artifacts/new-training
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python experiments/fresh_model_20261108/pipeline.py compare --output artifacts/new-training
```

Adam 0.001, unweighted CE, batch 512, max 32 epochs, deterministic CPU/one thread; earliest minimum validation CE. Production never selects this new output automatically. Generated hashes may differ with library/CPU versions; don't overwrite the frozen deployed model to chase identical scores.

## Static and layer-specific arithmetic

Static Q16 uses unchanged original helpers with Q16 weights/activations, sign restoration and truncating shifts; boundary tests document legacy wrapping/narrowing and signed-C limitations. Layer-specific uses the same quantized weights, offline activation exponents, nearest rounding and explicit domain/overflow/narrowing rejection. It is not per-packet dynamic quantization and does not recover discarded FP32 weights.

| Metadata | Original header experiment | Fresh checkpoint |
| --- | --- | --- |
| Normalized input exponent | 22 | 22 |
| Weight exponents | 16, 16, 16 | 16, 16, 16 |
| Linear output exponents | 23, 21, 18 | 22, 19, 16 |

See `quantization/calibrated.{h,json}` and `deployment/models/fresh/calibrated.{h,json}`. Conservative bounds include all declared calibration inputs. Unsupported live values are reported invalid, never silently clipped into a benign classification.

Original-model numerical reproduction (**E**):

```bash
python3 quantization/run_host.py --output artifacts/layer-numerical
python3 evaluation/offline.py --output artifacts/original-three-way
```

`evaluation/offline.py` excludes the fixed scale-calibration partition, uses exact rational arithmetic of the rounded header, and compares 13,844 identical vectors. It does not claim independent unseen detection F1. Original activation calibration can be regenerated into a new file (**V**) using `python3 quantization/calibrate.py --output artifacts/original-calibration`; do not replace checked-in metadata.

## Actual kernel latency: original XDP and both TC modes

Historical matched session: 2,826 vectors × 5 measured trials × 3 modes; 42,390 measurements, 8,478 warmups and nine fresh-state repeat guards. CPU 0, rotating order, WSL2 6.6.87.2, clang-12, Intel i7-1255U. Kernel `BPF_PROG_TEST_RUN` duration uses `repeat=1`, preprocessing through chain return; untimed state resets/readbacks/syscall wall time are outside. Five actual tails execute after preprocessing. XDP retains trace calls/repeated parsing; TC retains synchronization/counters/publication. These are implementation-pipeline timings, not arithmetic-only, NIC throughput, whole-flow or end-to-end latency.

New nonprivileged preparation (**E**):

```bash
python3 experiments/fresh_model_20261108/kernel.py --experiment artifacts/fresh-reproduction --prepare experiments/fresh_model_20261108/run/kernel-ready
python3 experiments/xdp_final_20261108/test_harness.py
python3 experiments/xdp_final_20261108/run.py --prepare artifacts/xdp-ready
```

The intermediate fresh preparation creates the fixtures and copied build state the XDP runner needs. A clean clone contains no compiled benchmark bundle. Original XDP source is compiled unchanged; test-only userspace seeding injects the stored vector directly, not fictitious flow statistics reconstructed from one packet. Fresh model bytes are read back in private unpinned maps. Six stage-isolated pilot checks, seven negative controls, graph audit and a cohort-specific final-workspace witness certify completion; ambiguous all-zero witnesses are rejected.

Privileged pilot/full (**X**, operator approval required; not rerun in this submission audit):

```bash
sudo /usr/bin/python3 experiments/xdp_final_20261108/run.py --execute-pilot artifacts/xdp-ready
# Review PASS, six stages/negative controls, correctness and cleanup first.
sudo /usr/bin/python3 experiments/xdp_final_20261108/run.py --execute-full artifacts/xdp-ready --pilot-evidence /absolute/path/to/the/new/pilot-directory
```

The full result must include every frozen ID, 14,130 measurements/mode, zero mismatches, cleanup PASS and retained raw `measurements.jsonl.gz`. Repeat guards reseed state; a large kernel `repeat` cannot substitute for fresh inference. No network/tracing attachment or physical interface is used. Older TC-only means 2.262/7.128 µs come from another session; do not mix them into the matched three-mode comparison.

Historical raw kernel archives remain in original development storage and are excluded from the submission; [selected full-session summary](evidence/fresh-kernel-latency.json) and harness source are included. Auditing old raw measurements requires those original archives and prepared manifests. Fresh reruns generate new complete evidence. Do not claim historical logs have been re-created merely by reading their summaries.

## Separate CIC CSV research

[Original comparison](../CIC_FORWARD_VS_BIDIRECTIONAL_MLP.md) and [threshold sensitivity](../CIC_VALIDATION_THRESHOLD_SENSITIVITY.md) remain distinct from deployed TC inference. Tuesday ZIP is external; no PCAP is required for CSV research. Obtain official identity-bearing `GeneratedLabelledFlows.zip` through [UNB](https://www.unb.ca/cic/datasets/ids-2017.html), subject to its terms. Required member: `TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv`; ZIP SHA256 `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`, member SHA256 `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815`. A reissued ZIP may differ: inspect and record provenance, don't bypass checks silently.

CSV source and full run arrays are not included. Complete raw-data reproduction is **X**; no download/retraining was performed in the submission audit. With the approved matching ZIP at your own path:

```bash
.venv/bin/python -B -m research.cic_csv_mlp.pipeline prepare --source /path/to/GeneratedLabelledFlows.zip --output artifacts/cic-csv
.venv/bin/python -B -m research.cic_csv_mlp.pipeline split --output artifacts/cic-csv
.venv/bin/python -B -m research.cic_csv_mlp.pipeline train --output artifacts/cic-csv
.venv/bin/python -B -m research.cic_csv_mlp.pipeline evaluate --output artifacts/cic-csv
.venv/bin/python -B -m research.cic_csv_mlp.pipeline audit --output artifacts/cic-csv
.venv/bin/python -B -m research.cic_csv_mlp.pipeline report --output artifacts/cic-csv
```

Threshold sensitivity (**V**, original experiment complete; not re-evaluated here) selects on validation only, freezes thresholds, applies once to saved test logits:

```bash
.venv/bin/python -B -m research.cic_threshold_sensitivity.study select --source artifacts/cic-csv --output artifacts/cic-threshold
.venv/bin/python -B -m research.cic_threshold_sensitivity.study evaluate --output artifacts/cic-threshold
.venv/bin/python -B -m research.cic_threshold_sensitivity.study audit --output artifacts/cic-threshold
.venv/bin/python -B -m research.cic_threshold_sensitivity.study report --output artifacts/cic-threshold
```

Never repeat `evaluate` in an existing output. This was post-hoc sensitivity motivated by known test results, not a fresh confirmatory experiment or a threshold deployed into eBPF. Reports preserve service-port shortcuts, grouped-split limitations and single-day class imbalance. PCAP feature/label matching research under `evaluation/cic` is separate and does not justify a 30,000-row matched attack cohort.
