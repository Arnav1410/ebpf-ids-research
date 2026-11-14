# External CIC evaluation of the frozen NN-eBPF model

8 November 2026 — branch `feature/cic-external-evaluation`.

**A smaller, qualified offline evaluation is complete: 15,026 flows, not the
requested 30,000.** The original XDP/Q16 and TC/Q16 arithmetic match exactly.
The frozen model has a high benign false-positive rate on this subset.
Layer-specific arithmetic reduces numerical error but changes no valid class
prediction and rejects 198 inputs. This is **host-executed model evaluation on
reconstructed historical flows**, not new kernel execution or live traffic.

## Measured results

Positive class is intrusion = 1; benign = 0. Confusion-matrix order is
`[[TN, FP], [FN, TP]]`. Metrics below are conditional on valid predictions;
all selected records remain in the coverage denominator.

| Measurement | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| Identical frozen inputs | 15,026 | 15,026 | 15,026 |
| Valid predictions | 15,026 | 15,026 | 14,828 |
| Missing / invalid predictions | 0 | 0 | 198 |
| Coverage | 1.000000 | 1.000000 | 0.986823 |
| Accuracy | 0.136829 | 0.136829 | 0.132722 |
| Precision | 0.001924 | 0.001924 | 0.001940 |
| Recall (intrusion) | 0.961538 | 0.961538 | 0.961538 |
| F1 (intrusion) | 0.003840 | 0.003840 | 0.003873 |
| Specificity (benign recall) | 0.135400 | 0.135400 | 0.131266 |
| False-positive rate | 0.864600 | 0.864600 | 0.868734 |
| Balanced accuracy | 0.548469 | 0.548469 | 0.546402 |
| MCC | 0.011781 | 0.011781 | 0.011504 |
| TP / FP / TN / FN | 25 / 12969 / 2031 / 1 | 25 / 12969 / 2031 / 1 | 25 / 12859 / 1943 / 1 |
| Prediction changes vs XDP | Baseline | 0 / 15,026 comparable | 0 / 14,828 comparable |

Layer-specific's slightly different conditional F1 is **not an improvement in
classification**: it abstains on 198 benign inputs. All three consume precisely
the same frozen IDs/vectors, and all valid paired predictions agree. For an
equal-denominator comparison:

| Measurement on identical common-success subset | All three modes |
| --- | ---: |
| Flows | 14828 |
| TP | 25 |
| FP | 12859 |
| TN | 1943 |
| FN | 1 |
| Accuracy | 0.132722 |
| Precision | 0.001940 |
| Recall | 0.961538 |
| F1 | 0.003873 |
| False-positive rate | 0.868734 |

The missing 198 records are separately retained, never predicted benign or
silently removed. All are frozen-domain range rejections: 88 exceed the
maximum-segment feature's domain and 110 the destination-port domain. No
int32/int64 overflow event was reported by the references on selected inputs.
This is a bounded-cohort finding, not a general removal of documented legacy
arithmetic limitations. No scaler limits were expanded.

![Actual conditional confusion matrices](verification-logs/cic-external-20261108/evaluation/confusion-matrices.png)

[Machine-readable metrics](verification-logs/cic-external-20261108/evaluation/metrics.json),
[saved-prediction re-audit](verification-logs/cic-external-20261108/results-audit-r2/audit.json),
[PDF figure](verification-logs/cic-external-20261108/evaluation/confusion-matrices.pdf).

## Sources, independence and selected population

Operator-supplied Tuesday CIC-IDS-2017 artifacts were read at
`/mnt/c/Study Materials/Semester 7/USAP/Term Project/`. No dataset download or
packet replay was performed. Only Tuesday's identity-bearing CSV was streamed
from `GeneratedLabelledFlows.zip`, without extracting other members.
The capture is **PCAPNG despite its `.pcap` extension**: one Ethernet interface,
microsecond timestamp resolution, 11,551,954 packets, 11,048,283,608 bytes.
Its MD5 `2d976fec5b8b3676c1c4152a9195bba7` matches the supplied sidecar.
This binds the files; the download transaction was not independently authenticated.

The CSV contains 445,909 rows: 432,074 BENIGN, 7,938 FTP-Patator and 5,897
SSH-Patator. There are 245,781 TCP rows before metadata/duplicate checks;
245,722 unique TCP rows have usable required identity/window metadata.
Strict reconstruction accepts 62,615 source rows: 62,589 BENIGN, 5 FTP-Patator,
21 SSH-Patator. Final sampling selects 15,000 benign and all 26 eligible
intrusion records from **4 July 2017 only**. No DoS, web-attack or scan evaluation
is claimed. The benign sample is largely HTTPS/HTTP, as recorded in the
[feature/port summary](verification-logs/cic-external-20261108/feature-summary.json).

The paper describes CIC and eBPF-Reproduction as separate traffic collections.
However, the exact header's historical training membership and number of training
flows are **unknown**. We cannot certify that it never encountered CIC.
The header and reproduction NPY files match the authors' inspected repository;
this establishes artifact identity, not training lineage. No original saved
split IDs or FP32 checkpoint were recovered. Training's complete-dataset scaler
fit and unknown overlap remain limitations; no new fitting occurred.
See [CIC_OVERLAP_AUDIT.md](evaluation/CIC_OVERLAP_AUDIT.md).

Measured duplicate/overlap counts: 4 identical full TCP CSV records were excluded;
543 repeated six-vectors occur in the eligible pool and 42 in the selected
cohort. **Zero** eligible/selected six-vectors exactly collide with supplied
reproduction vectors. Vector equality is not flow identity; zero collisions
cannot prove unseen training history. Numeric collisions/repeats were not used
as exclusions. [Counts](verification-logs/cic-external-20261108/overlap-counts.json).

The 30,000 balanced target is **NOT ACHIEVED**. Tuesday has only 13,835 intrusion
source rows even before eligibility checks, and the strict observation-window
join leaves 26. The locally saved prospective policy was not a public study registration.
Its 15,000-per-class cap was preserved: no padding,
relabeled rows, prediction-based replacements, or extra benign records were used.
These 26 correlated, narrowly selected attack annotations cannot support a
representative intrusion-recall claim. The cohort is not balanced and does not
reflect natural source or deployment prevalence. Whole-source natural-prevalence
model evaluation and statistical confidence intervals are **NOT RUN**; independent
row bootstrapping would obscure both selection bias and session correlation.

## Packet reconstruction and reliable label matching

Each observed initial SYN initiator is the input direction; its SYN responder
is treated as that connection's **virtual monitored server**. Source label
endpoints must agree. This is an explicit offline direction policy, not a
physical-interface experiment. No NAT rewriting or row-number matching between
unrelated files is used.

| MLP input order | Reconstructed definition | Why CSV column substitution is invalid |
| --- | --- | --- |
| 1 | Maximum `IPv4 total_length − IHL`, bytes | Includes TCP header/options, rather than payload only |
| 2 | Maximum consecutive incoming timestamp delta, integer ns | Capture microseconds are multiplied by 1,000; not live helper timestamps |
| 3 | Minimum TCP-segment bytes | Same length convention as feature 1 |
| 4 | Observed responder TCP port, host-order integer | Direction must match the SYN and original source label |
| 5 | Sum of incoming TCP `doff × 4`, bytes | Includes each observed packet's TCP options and termination packet |
| 6 | Number of observed incoming packets | Includes retransmissions/capture duplicates and first incoming FIN/RST |

Input state stops at the **first incoming FIN/RST, including that packet**;
no later packet contributes features. Reverse traffic supplies label-join
cross-checks, not MLP inputs. Only complete untagged Ethernet/IPv4 IHL=20,
unfragmented TCP frames are admitted into the common XDP/TC subset. Checksums
are not used as a new acceptance rule. Tuple reuse, missing session starts,
unsupported identifiable packets, and pre-trigger timestamp reversal are rejected.
The 3,721 globally reordered capture timestamps are not automatically 3,721
incorrect flow IATs: per-session checks exclude affected observation windows.
A captured segment reaches 24,840 bytes; offloading/coalescing is a plausible
capture limitation, not independently proven NIC behavior.

Source label timestamps have minute precision and a 12-hour display without
AM/PM. The source binding retains both candidates and adds an empirical effective
three-hour offset to align with capture epoch timestamps. The join requires a
**unique oriented tuple/minute match, exact initial-SYN-to-trigger duration,
and all four forward/backward packet/payload counters**. No nearest timestamp
or attack schedule is used. This exact equality rule was frozen before CIC
predictions; it is intentionally narrower than a general CIC session matcher.

A hand-checkable benign anchor is CSV row 2, `192.168.10.5:49182 →
192.168.10.3:88`: original packet 83 SYN through packet 93 incoming FIN,
640 microseconds, 7 forward / 4 backward packets, 440 / 358 payload bytes.
Its reconstructed vector is `[240,497000,20,88,164,7]`. This prefix is a parser
anchor only: row 2 was **excluded from metrics because its tuple is reused
later in the capture**, as recorded in [manual-anchor.json](verification-logs/cic-external-20261108/manual-anchor.json).
All final selected records were additionally re-read from original packet offsets and checked
against both actual host-compiled XDP/TC feature helpers. The XDP feature probe
invokes the original tuple/update helpers after offline direction selection;
it does not demonstrate that the original hardcoded source-IP entry filter
would admit CIC addresses. The independent packet decoder enforces the common
supported parser subset before these helper comparisons.

Why many attack labels fail the strict window rule is demonstrated by two
[exact-tuple traces](verification-logs/cic-external-20261108/window-mismatch-examples.json):

| Original CSV row/category | CSV duration / packet counts at server FIN | First incoming FIN duration / counts |
| --- | --- | --- |
| 11585 / FTP-Patator | 9,715,978 µs; 9 forward, 15 backward | 9,716,584 µs; 10 forward, 15 backward |
| 162282 / SSH-Patator | 11,191,994 µs; 21 forward, 32 backward | 11,192,695 µs; 22 forward, 32 backward |

These demonstrate two specific mismatches; they do not prove the cause of every
excluded row. Keeping later incoming-FIN input while borrowing an earlier CSV
label requires separately validated session/appendix linkage, not silent merging.
The [Engelen/Rimmer/Joosen analysis](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html)
documents original CIC FIN and labeling issues. No corrected release was mixed
in. Original annotations are retained: for example row 11349 says FTP-Patator
with destination port 80. A port alone neither proves that label wrong nor
validates attack behavior. [Selected attack identities](verification-logs/cic-external-20261108/selected-attack-identities.json).

## Exclusions and classification coverage

All 445,909 source rows are accounted for as 62,615 eligible and **383,294 excluded**:

| Source-row exclusion | Count |
| --- | ---: |
| REUSED_TCP_TUPLE | 16 |
| NO_MATCHING_COMPLETE_SYN_SESSION | 105,427 |
| NO_ELIGIBLE_INCOMING_FIN_RST | 11,352 |
| LABEL_WINDOW_DURATION_OR_COUNTER_MISMATCH | 65,722 |
| PACKETS_BEFORE_COMPLETE_SESSION_START | 89 |
| TIMESTAMP_REORDER_OR_MISSING | 501 |
| NON_TCP_LABEL | 200,128 |
| INVALID_REQUIRED_LABEL_METADATA | 55 |
| DUPLICATE_SOURCE_RECORD | 4 |

The 55 metadata exclusions include negative counters/intervals and scientific-
notation duration text that does not establish exact integer microseconds;
none was guessed or rounded. These are explicit conservative policy exclusions,
not necessarily proof that the underlying capture is corrupt.
The 47,589 eligible rows outside final class caps remain unselected, rather than
being called parser failures. Every source-row exclusion is retained in
`reconstructed/exclusions.jsonl.gz`. The 198 layer-specific failures are
**additional model abstentions within the selected cohort**, not source exclusions.

Per-category performance, all on the same selected source labels:

| Source category | Selected support | Q16 valid / detected intrusion | Layer-specific valid / detected intrusion |
| --- | ---: | ---: | ---: |
| BENIGN | 15,000 | 15,000 / 12,969 false positives | 14,802 / 12,859 false positives; 198 missing |
| FTP-Patator | 5 | 5 / 5 (recall 1.000000) | 5 / 5 (recall 1.000000) |
| SSH-Patator | 21 | 21 / 20 (recall 0.952381) | 21 / 20 (recall 0.952381) |

Both Q16 implementations are identical. The only capture day is 2017-07-04;
its metrics are the overall table, also saved explicitly under `per_capture_day`.
Coverage and missing counts accompany every category and paired metric.

## Frozen arithmetic and numerical evidence

**Retrained: No.** No model replacement, scaler fitting or calibration was run.
The original bias-free 6→32→32→2 model is loaded from `src/mlp_params.bpf.h`.
Rounded mean is `[572,11161066668,36,496,12145,379]`; rounded scale is
`[451,24027934608,54,1672,49932,1560]`.
Static arithmetic remains Q16. Experimental six-stage exponents are
`[22,23,23,21,21,18]`, with unchanged Q16 weights and recorded calibration.
Classification remains `0 if logit0 > logit1 else 1`, including class 1 for a
tie. There were **zero equal-logit predictions** here; the documented difference
from the paper's equal-logit rule cannot explain these measured scores.

The existing `validation/native.c` and `evaluation/tc_vectors.c` compile the
actual original XDP and current TC arithmetic under host mocks. Every valid
`normalized → linear0 → relu0 → linear1 → relu1 → logits` tensor was compared
with the independent integer reference. Original and TC Q16 match on all
15,026 inputs: **zero intermediate or prediction differences**. Layer-specific
matches its own reference on all 14,828 valid inputs. Combined comparisons:
**269,280 tensors / 6,103,680 integers, zero mismatches**.

| Same 14,828 common-success flows: scaled-logit error | XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| Mean absolute error | 0.000143164927136 | 0.000143164927136 | 1.01169165891e-06 |
| Maximum absolute error | 0.000289952447012 | 0.000289952447012 | 3.27400459549e-06 |

Errors use real-valued scales and the **exact rational network represented by
the unchanged Q16 header**, not an unavailable original FP32 checkpoint.
Lower arithmetic error did not improve classification on common valid inputs.
The smallest Q16 raw logit gap was 68 (`[-1726,-1658]`, class 1); ties were not
observed. Full representative integer tensors, final logits and independent
stage hashes are saved in [tensor_samples.json](verification-logs/cic-external-20261108/evaluation/tensor_samples.json).

For example, a selected benign vector `[2076,76108057000,20,80,552,27]`
produces Q16 logits `[-123092,96621]` and class 1 in both Q16 implementations;
layer-specific logits `[-492397,386515]` also give class 1 at Q18. This is an
observed false positive under the source label, not a claimed attack detection.

## Gates, commands and reproducibility

| Check | Status | Actual scope |
| --- | --- | --- |
| Provenance and source checksum audit | PASS, with stated uncertainty | Full PCAP SHA256/MD5; ZIP/member SHA256; no guaranteed-unseen claim |
| Parser, matching, arithmetic-metric framework tests | PASS | 26 nonprivileged tests, including synthetic end-to-end exclusion/gate checks |
| Independent real-capture decoder cross-check | PASS | 651 supported prefix packets versus existing host-C/parser fields |
| Pilot | PASS | 126 flows: 100 benign, 5 FTP, 21 SSH; 1,512 feature comparisons |
| Resource batch | PASS | 2,500 flows; 30,000 feature comparisons; validation-only, not balanced scoring |
| Final cohort reconstruction | PASS | 15,026 flows; 269,637 forward + 287,323 backward packet checks; 180,312 feature comparisons |
| Balanced 30,000-flow target | NOT ACHIEVED | Strict Tuesday eligible intrusion count is 26 |
| Host C builds / all-layer arithmetic | PASS | Three original/TC wrappers; 3 existing XDP optimizer “loop not unrolled” warnings, no TC build warnings |
| Independent counts and sklearn metrics | PASS | Raw-archive re-audit; confusion matrices and all defined metrics agree |
| New kernel verifier / program test run | NOT RUN | Prior kernel evidence remains separate |
| Live XDP/TC processing, NIC or two-machine test | NOT RUN | No attachment, replay or networking configuration changes |
| Production-source preservation | PASS | 83 verified runtime/demo/model source hashes unchanged |

The resource batch was 2,499 benign / 1 FTP by frozen rank. It tested processing
scale after the both-class pilot; it was never presented as balanced evaluation.
Peak reconstruction RSS was 426,628 KiB. Full reconstruction took 324.156 s,
resource validation 39.101 s, final validation 67.755 s and host evaluation
38.380 s on this environment; these are tool runtimes, not kernel/NIC latency.

[Exact copy-and-paste commands](evaluation/cic/README.md) cover inventory,
reconstruction, pilot/resource/final gates, inference and independent re-audit.
The actual run used output root `verification-logs/cic-external-20261108`;
build argv/exit codes are saved in each validation/evaluation `commands.jsonl`.
Unit output is in `all-tests-final.log`; inference in `evaluation.log`.
The initial secondary audit failed only because JSON stringifies integer map
keys; the new audit normalized that representation, added a regression test,
and passed as `results-audit-r2`. Original predictions and model results were
not changed. Source arrays are loaded with a bounded numeric reader, without
pickle. No packets or payload content are included in classification logs.

Environment: WSL2 `6.6.87.2-microsoft-standard-WSL2`, x86_64, Python 3.10.12,
clang 12.0.1-19ubuntu3, NumPy 2.2.6, SciPy 1.15.3, scikit-learn 1.7.2 and
Matplotlib 3.10.3. Evaluation packages were installed in an isolated `/tmp`
virtual environment. Starting/current baseline commit:
`73868b101d1c1f5e27c6f71eceaa78a645368445`; new offline files are uncommitted.
The [source checksum manifest](verification-logs/cic-external-20261108/SOURCE_SHA256SUMS)
identifies the additional evaluator code. No commit or push was performed.

| Frozen artifact | SHA256 |
| --- | --- |
| Tuesday PCAP | `080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57` |
| Original label ZIP | `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a` |
| Tuesday CSV member | `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815` |
| Model/scaler header | `f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11` |
| Frozen layer calibration | `f7fc2b92670d7eeb8cc9f84dcb4598392d059f407f5b0a7dd9f22878f4439856` |
| Preregistered policy | `9aa537d42ba297e94cc09da80a8719dd5255dede978ccc6330b362bebbdcd39e` |
| Source binding | `ea2f5c0b01fe1e653ea8cb09bf31563be8f504a560d046b805d64f79267915fa` |
| Final cohort | `c675d42cb3b3dc30ca70a534081d3cfdec33cd787c0059306cc2b9e656da93f7` |
| Original saved prediction archive | `fd3a5376abc595ddfbeea12f356ae7548f541b63b3c811e6e707b6510fd15f62` |

Local audit trail: [source binding](verification-logs/cic-external-20261108/source-binding.json),
[capture inventory](verification-logs/cic-external-20261108/capture-inventory/inventory.json),
[all-source exclusions/counts](verification-logs/cic-external-20261108/reconstructed/reconstruction.json),
[final sample manifest](verification-logs/cic-external-20261108/final-cohort/manifest.json),
[final packet validation](verification-logs/cic-external-20261108/final-validation/validation.json),
[manual trace examples](verification-logs/cic-external-20261108/final-validation/samples.json),
[prediction rows](verification-logs/cic-external-20261108/evaluation/predictions.jsonl.gz),
[per-flow numerical errors](verification-logs/cic-external-20261108/results-audit-r2/prediction-diagnostics.jsonl.gz).
Large captures, source archives, caches, raw cohorts, predictions and binaries
are retained locally and excluded from commits.

## Comparison with published and earlier results

| DSN 2024 Table V reference, authors' measurements | Accuracy | F1 |
| --- | ---: | ---: |
| CIC-IDS-2017 offline, NN-int32 Q+Top 6 | 0.974 | 0.933 |
| eBPF-Reproduction real-time, NN-int32 Q+Top 6 | 0.994 | 0.992 |

[DSN 2024 paper](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf).
Our frozen checkpoint, subset, prevalence, input direction, capture-time
approximation and termination window differ or have unresolved lineage. These
scores are **not an equal-protocol reproduction** of Table V. The earlier
13,844-row reproduction diagnostic F1 0.961386 has unknown training overlap;
it is not pooled with this external test. The separate known-benign live
harness result is also a different experiment.

**Professor-ready explanation:** “We kept the original weights, scaler and
arithmetic configuration frozen. We reconstructed the six ingress features from
Tuesday CIC packet traces at the first incoming FIN or RST and accepted only
uniquely matched original label records. That conservative protocol yielded
15,026 flows, including only 26 intrusion annotations. The XDP and TC Q16
implementations match numerically, while layer-specific scaling reduces
quantization error without changing valid predictions. The high false-positive
rate shows that numerical parity does not establish useful external intrusion
detection. Unknown checkpoint history, source-label issues and narrow selection
prevent claiming an identical reproduction of the paper's F1.”

## Recommended next research step

Preserve this cohort and report. Before another score, separately validate
session-to-CIC-FIN-appendix linkage on hand-audited server-first-FIN cases, or
obtain a documented corrected label release bound to the same captures. Freeze
that broader protocol without consulting its future predictions, then expand
capture days under separate acquisition approval. Do not change the deployed
model or demonstration harness to improve this score. A later kernel subset
would check execution parity, not fix label quality or model generalization.
