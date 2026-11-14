# Frozen-model external CIC evaluation

This is an offline, read-only PCAP/label study. It does not attach BPF programs,
replay packets, train a model, fit a scaler, or calibrate arithmetic. C feature
and MLP functions run under the project's existing **host mocks**, not in the
kernel. Read [the measured report](../../CIC_EXTERNAL_EVALUATION_REPORT.md)
before interpreting any score.

The preregistered [policy](SELECTION_POLICY.json) is immutable historical input;
its initial `PENDING` fields describe its creation time. Current progress is in
[STATUS.json](STATUS.json). The separately hashed source binding fixes the
actual files, timestamp interpretation and conservative join before predictions.

## Dependencies and tests

Run from the repository root with Python 3.10+, clang-12 and the existing host
wrapper include files. No root permissions or packet-analysis library is needed.
Install evaluation-only dependencies in a virtual environment:

```bash
python3 -m venv /tmp/nn-ebpf-cic-eval-20261108
/tmp/nn-ebpf-cic-eval-20261108/bin/python -m pip install --only-binary=:all: \
  numpy==2.2.6 scipy==1.15.3 scikit-learn==1.7.2 matplotlib==3.10.3
PYTHONDONTWRITEBYTECODE=1 /tmp/nn-ebpf-cic-eval-20261108/bin/python -m unittest -v \
  evaluation.cic.test_capture evaluation.cic.test_labels \
  evaluation.cic.test_pipeline evaluation.cic.test_metrics
```

## Reproduce the Tuesday experiment

These are the actual processing commands. Output directories must be new;
choose another `OUT` for a repeat. Source files remain on the Windows drive.
Only the Tuesday member is streamed from the label archive, including its
literal space in `TrafficLabelling /`. No archive extraction is required.

```bash
PCAP='/mnt/c/Study Materials/Semester 7/USAP/Term Project/Tuesday-WorkingHours.pcap'
LABELS='/mnt/c/Study Materials/Semester 7/USAP/Term Project/GeneratedLabelledFlows.zip'
BINDING='verification-logs/cic-external-20261108/source-binding.json'
OUT='verification-logs/cic-external-repeat'
mkdir -p "$OUT"

python3 -m evaluation.cic.inspect_capture --input "$PCAP" \
  --expected-sha256 080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57 \
  --expected-md5 2d976fec5b8b3676c1c4152a9195bba7 \
  --output "$OUT/capture-inventory"

python3 -m evaluation.cic.reconstruct --capture "$PCAP" --labels "$LABELS" \
  --binding "$BINDING" --output "$OUT/reconstructed"

python3 -m evaluation.cic.validate_cohort --capture "$PCAP" --labels "$LABELS" \
  --binding "$BINDING" --cohort "$OUT/reconstructed/pilot.jsonl" \
  --output "$OUT/pilot-validation"

python3 -m evaluation.cic.freeze --index "$OUT/reconstructed" \
  --previous "$OUT/pilot-validation/validation.json" --stage resource \
  --output "$OUT/resource-cohort"
python3 -m evaluation.cic.validate_cohort --capture "$PCAP" --labels "$LABELS" \
  --binding "$BINDING" --cohort "$OUT/resource-cohort/cohort.jsonl" \
  --previous "$OUT/pilot-validation/validation.json" --output "$OUT/resource-validation"

python3 -m evaluation.cic.freeze --index "$OUT/reconstructed" \
  --previous "$OUT/resource-validation/validation.json" --stage final \
  --output "$OUT/final-cohort"
python3 -m evaluation.cic.validate_cohort --capture "$PCAP" --labels "$LABELS" \
  --binding "$BINDING" --cohort "$OUT/final-cohort/cohort.jsonl" \
  --previous "$OUT/resource-validation/validation.json" --output "$OUT/final-validation"

MPLCONFIGDIR=/tmp/nn-ebpf-cic-matplotlib \
/tmp/nn-ebpf-cic-eval-20261108/bin/python -m evaluation.cic.evaluate \
  --cohort "$OUT/final-cohort/cohort.jsonl" \
  --validation "$OUT/final-validation/validation.json" \
  --binding "$BINDING" --output "$OUT/evaluation"

/tmp/nn-ebpf-cic-eval-20261108/bin/python -m evaluation.cic.audit_results \
  --results "$OUT/evaluation" --cohort "$OUT/final-cohort/cohort.jsonl" \
  --output "$OUT/results-audit"
```

The 2,500-record resource batch measures extraction/validation at scale; it is
not a balanced scoring cohort. Final selection still caps each class at 15,000
and never fills an intrusion shortfall with repeated records or extra benign
records. Source hashes are checked during the complete reconstruction pass.
The independent validator re-reads every selected packet, joins the original
CSV again, and compares all six features with both original host-C helpers.

## Outputs and interpretation

- `source-binding.json`: exact source hashes and matching contract.
- `reconstruction.json`, `exclusions.jsonl.gz`: all source-row eligibility counts
  and explicit exclusions, including source rows that never reach inference.
- Each cohort has packet indices/offsets, endpoints, label provenance, trigger,
  features and its SHA256. IDs use the CSV member hash plus physical CSV row.
- Validation directories contain independently observed features and hand traces.
- `metrics.json`: mode-specific valid/missing counts, metrics, confusion matrices,
  per-category/day support, common-success metrics, numerical errors and overlap.
- `predictions.jsonl.gz`: one row per frozen source ID, all three results and
  actual/reference six-stage hashes. This is the aggregate audit trail.
- `tensor_samples.json`: complete representative intermediate integer tensors.
- `results-audit/audit.json`: independently rebuilt counts, intermediate hashes
  and same-subset logit errors; per-flow numerical diagnostics are retained in
  `prediction-diagnostics.jsonl.gz` without rewriting the original predictions.
- `confusion-matrices.png` / `.pdf`: conditional on valid predictions.

Ordinary packet retransmissions and duplicated capture frames are counted as
observed. Exact repeated CSV records are excluded; six-vector collisions are
reported, never equated with training overlap. Tuple reuse, unsupported formats,
ambiguous or differently segmented label windows, and per-session timestamp
reversals are rejected conservatively. CSV scientific-notation/negative required
identity-window metadata is not guessed or rounded. Capture microsecond deltas
are converted to integer ns; they cannot reproduce a live helper's clock.

The current join requires initial SYN direction, source-minute agreement,
**exact duration through first incoming FIN/RST and all four packet/payload
counters**. This rejects many source attack records whose CSV window ends at a
server FIN. It establishes a narrow auditable subset, not representative attack
coverage. Broadening this join needs a separately frozen, predictions-blind
protocol and renewed packet/label validation; never tune it to improve F1.

Unsafe Q16 arithmetic is detected before invoking host C. Layer-specific range
rejections remain missing predictions; its original calibrated domain is not
expanded. Errors are relative to the exact rational network encoded by the Q16
header, **not** an unavailable original FP32 checkpoint. Undefined ratios are
null, not zero; sklearn's different undefined conventions are recorded.

Keep PCAPs, archives, generated libraries, caches, full cohorts and prediction
archives outside commits. See the small evidence manifests and report instead.
