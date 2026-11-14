# Three-way comparison: numerical agreement, supplied labels and live traffic

These are different experiments. The deployed model/feature definitions are
unchanged. [Dataset audit](DATASET_AUDIT.md) establishes compatibility limits.

## Host model-level experiment — PASS

Executed command:

```bash
python3 evaluation/offline.py --output verification-logs/final-demo-20261107/offline-r2 --encoded-label-diagnostics
```

Inputs: **13,844** stored reproduction vectors held out from *scale calibration*,
with supplied code labels 0: **4,152**, 1: **9,692**. This is **not** a recovered
original model test split. The original scaler was fitted on all stored rows;
original training overlap and collection labels are unverified. The explicit
diagnostic flag scores those supplied numeric labels using the intended
published coding. It does not establish independently labeled intrusion F1.

The original XDP C arithmetic, actual TC Q16 C stages and actual experimental
TC C stages were compiled for the host with their existing validation mocks.
They received identical precomputed vectors, bypassing packet extraction.
Every intermediate tensor matched its independent integer reference.
**This is host execution, not XDP/TC kernel packet-processing evaluation.**

| Measured supplied-code-label diagnostic | XDP/Q16 host C | TC/Q16 host C | TC/layer-specific host C |
| --- | ---: | ---: | ---: |
| Eligible / invalid predictions | 13,844 / 0 | 13,844 / 0 | 13,844 / 0 |
| TP / FP / TN / FN under intended coding | 9,685 / 771 / 3,381 / 7 | same | same |
| Accuracy against supplied codes | 0.943802 | 0.943802 | 0.943802 |
| Precision | 0.926262 | 0.926262 | 0.926262 |
| Recall | 0.999278 | 0.999278 | 0.999278 |
| F1 against supplied codes | 0.961386 | 0.961386 | 0.961386 |
| Classification coverage | 100% | 100% | 100% |
| Mean absolute logit error | 1.775953468e-4 | 1.775953468e-4 | 9.913700805e-7 |
| Maximum absolute logit error | 2.967413958e-4 | 2.967413958e-4 | 3.477006804e-6 |

Error reference: exact rational reconstruction of the Q16 header network, **not
the missing FP32 model**. There were zero Q16 tensor differences and zero
prediction changes in the experimental mode. Activation precision/rounding
improved fidelity; there is **no measured F1 improvement**. Kernel-scaled logits
at q18 and Q16 logits at q16 must be divided by their respective powers of two
before comparing real magnitudes. Per-layer errors are in the metrics JSON.

[Machine-readable metrics](verification-logs/final-demo-20261107/offline-r2/metrics.json),
[representative full intermediate tensors](verification-logs/final-demo-20261107/offline-r2/samples.json).
`predictions.jsonl.gz` alongside them stores every row index, input, supplied
label, prediction/logits/error status and all stage hashes. That bounded raw
prediction archive is retained locally; regenerate it with the same command
and a fresh output path instead of committing large logs.

Published reference figures are listed in DATASET_AUDIT.md. Our diagnostic is
not an equal-protocol comparison to them. No CIC CSV was imported or scored.
The independently labeled intrusion metrics remain **NOT RUN**.

## Actual TC kernel/network harness — PASS in isolated WSL2

Approved user execution:

```bash
sudo /usr/bin/python3 demo/test_isolated.py --run verification-logs/final-demo-20261107/ready
```

Both modes attached the unchanged TC object to an owned veth. Batches of 1, 10
and 32 ordinary TCP connections completed per mode, with orderly client FIN,
server acknowledgement and real retained kernel predictions. The application
server and dashboard ran as UID 1000. Final map snapshots matched **86 records,
516 tensors, 11,696 integers**, with zero mismatches and 100% matching coverage.
Each mode retained 43 predictions, every stage executed 43 times, and cleanup
passed. An occupied application port caused expected startup failure, with
successful owned rollback and the unrelated listener preserved.

Q16 ingress/egress IDs: **655/656**; layer-specific: **666/667**.
[Independent evidence replay](verification-logs/final-demo-20261107/VERIFIED.json).

**Detection finding:** all known-benign cases received raw class 1 in both
modes. With the intended 1=intrusion interpretation, each mode produced:

| Batch | Known benign | Unknown truth | False positives / true negatives | Benign FPR | Coverage |
| --- | ---: | ---: | --- | ---: | ---: |
| 1 connection | 1 | 0 | 1 / 0 | 100% | 100% |
| 10 connections | 9 | 1 | 9 / 0 | 100% | 100% |
| 32 connections | 28 | 4 | 28 / 0 | 100% | 100% |

Unknown cases were not relabeled benign. No intrusions were generated, so
intrusion recall and F1 are **unavailable**, not zero or a synthetic success.
These false positives demonstrate poor behavior on this small controlled
traffic sample under the intended coding. Domain shift (including a new
application/port) and model/collection provenance deserve investigation; no
single cause has been established. **Do not flip the class mapping to make the
demo look successful.** Correct execution and numerical parity do not prove
good intrusion detection.

Modes ran in separate clean sessions. Identical payload scenarios do not create
identical helper-clock features; the live experiment is not a controlled
identical-vector quantization study. Actual Windows execution and this new
two-machine Ubuntu-VM harness are **PENDING USER EXECUTION**. Earlier deployment
success on the VM is user-reported context, not new harness evidence.

## Next scientific step

Obtain the original capture/split/label manifest and checkpoint provenance,
then evaluate independently labeled, extraction-compatible flows on held-out
capture days. A genuine CIC reproduction needs its matching model/scaler and
feature protocol. Do not retrain or change the deployed six features during
this demonstration task. Optional same-VM XDP-versus-TC runtime comparison is
**NOT RUN / future work**; old WSL XDP and new VM TC results must not be presented
as equal-environment measurements.
