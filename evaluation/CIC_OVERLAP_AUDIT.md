# CIC external evaluation: independence and checkpoint audit

Date: 8 November 2026. **PASS: qualified provenance audit and measured overlap
checks.** The operator-provided Tuesday PCAP/label pair has been inspected;
[external offline results](../CIC_EXTERNAL_EVALUATION_REPORT.md) use a conservative
15,026-record cohort. This is not a guarantee of unseen evaluation data.

Work is isolated on `feature/cic-external-evaluation`, based on verified commit
`73868b101d1c1f5e27c6f71eceaa78a645368445`. Existing uncommitted work, including
the unrelated tracked deletion and the live false-positive report, is preserved.
No inference, training, calibration, model or demonstration source was changed.

## Conclusions by evidence strength

| Question | Conclusion | Classification |
| --- | --- | --- |
| Are CIC and eBPF-Reproduction separate collection protocols? | DSN §V-A describes generating new reproduction traffic using XDP extraction; reproduction train/test captures are on different dates. They are not described as subsets or packet replays of CIC. | **Confirmed by source**, as the authors' account; captures not independently compared |
| Are equal attack names proof of duplicated traffic? | No. Category names describe behavior, not packet/flow identity. | **Confirmed methodological limitation** |
| Did the paper train for both dataset experiments? | §V-B1 describes CIC training; §V-B2 describes reproduction training parameters subsequently loaded into eBPF. This supports dataset-specific training rather than assuming one frozen model covers both experiments. | **Confirmed protocol description**; separate serialized checkpoint identities **not recoverable** |
| Which experiment produced our exact weights? | The available script trains on the reproduction NPY files; all rounded file means/SDs match the header scaler. A reproduction association is strong, but those facts do not establish weight-training membership. | **Supported by evidence, not independently verified** |
| Can our exact checkpoint be traced to original training flows? | No saved split, flow IDs, capture hashes/dates, training seed or checkpoint lineage links the weights to individual flows. | **Unknown / not recoverable from inspected artifacts** |
| Are 16,257 training / 27,103 test samples the sizes for this checkpoint? | Those are paper Table III reproduction counts; the bundled files contain 18,840 rows. They cannot be assigned to this header. | Paper counts **confirmed by source**; checkpoint training count **unknown** |
| Is CIC guaranteed unseen by this checkpoint? | No. Separate collection provenance supports an external-data study, but unknown checkpoint history prevents proving that it never used CIC or related data. | **Unknown** |

Primary paper source: [DSN 2024, §V-A, §V-B1–2, Tables III/V](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf).

## Local artifact forensics

The separate authors' clone was inspected read-only at
`/home/arnav/research/NN-eBPF`, commit
`4fe55dd6f4172f8aec4ad00cbd5dd6750d2f886d`, origin
`https://github.com/IntelligentDDS/NN-eBPF.git`.
Its tracked dataset has only the two numeric reproduction arrays. Relevant
local history lists commit `58bbbb5` for the dataset/header/training artifacts;
that history provides no additional flow/split manifest.

The current project header and both NPY files are **byte-for-byte identical**
to the corresponding files in that clone. No `mlp.th`, original FP32 checkpoint,
separate CIC checkpoint or recoverable original test-ID manifest was found in
the inspected project/research locations. No pickle/checkpoint was deserialized.

| Artifact | SHA256 |
| --- | --- |
| `src/mlp_params.bpf.h` | `f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11` |
| `dataset/reproduction-xdp-data.npy` | `787a3bf845a5714f79c27aafceaa6feeb59ec53a405035d2ebe64775a3dcb96e` |
| `dataset/reproduction-xdp-label.npy` | `edbbc05ed553442139c0ddd7b8211aa8aa98347c7b8d3d2e3e7a0f72463d1924` |
| `quantization/calibrated.json` | `f7fc2b92670d7eeb8cc9f84dcb4598392d059f407f5b0a7dd9f22878f4439856` |

The numeric arrays contain 18,840 six-feature rows, codes 0: 5,585 and
1: 13,255. There are 18,561 unique vectors and 279 repeated rows, without
conflicting numeric labels among identical vectors. They have no associated
timestamps or connection identifiers. These are repeated feature vectors,
**not proven duplicate source flows**. See [existing audit](../DATASET_AUDIT.md)
and [saved numeric inventory](../verification-logs/final-demo-20261107/dataset_audit.json).

The inspected [training script](../src/mlp_train.py) requests a stratified random
80/20 split without a fixed seed and fits `StandardScaler` on the complete
dataset. A new split is not a reconstruction of its historical split, and its
scaler is not independently held out. [Quantization](../src/mlp_quant.py) exports
rounded weights/scaler from a supplied checkpoint; no lineage metadata is
exported in the header. Neither script was executed.

## Actual external sources and overlap measurements

The operator supplied `Tuesday-WorkingHours.pcap`, `Tuesday-WorkingHours.md5`
and `GeneratedLabelledFlows.zip` under
`/mnt/c/Study Materials/Semester 7/USAP/Term Project/`.
No dataset was downloaded by this investigation. Only Tuesday's CSV member was
read from the ZIP, without filesystem extraction. Its identity-bearing fields
include both endpoint addresses/ports, protocol, timestamp and duration.
`MachineLearningCSV` was not used. These original-style files were not
independently authenticated against an official server download; the supplied
sidecar MD5 agrees with the complete PCAP and SHA256 binds every source.
See [source binding](../verification-logs/cic-external-20261108/source-binding.json).

The [official UNB dataset account](https://www.unb.ca/cic/datasets/ids-2017.html)
places this capture on 4 July 2017. Actual container timestamps fall on that UTC
date. Reproduction capture dates/identities remain unavailable locally, so no
packet-level cross-collection identity comparison is possible. Equal attack
category names are not evidence of duplicated flows.

| Check | Measured result / interpretation |
| --- | --- |
| Original Tuesday CSV rows | 445,909: 432,074 BENIGN; 7,938 FTP-Patator; 5,897 SSH-Patator |
| TCP source rows | 245,781 before metadata and duplicate exclusions |
| Exact duplicate full TCP CSV records | 4; deterministic first representative retained; remaining source records are distinct CSV observations |
| Eligible packet/label records | 62,615 after strict complete-session/first-incoming-termination matching |
| Final frozen selected records | 15,026: 15,000 BENIGN; 5 FTP-Patator; 21 SSH-Patator |
| Repeated selected six-vectors | 42 repeated vectors; not proven duplicated source flows and not removed |
| Selected six-vectors colliding with reproduction vectors | 0 rows / 0 unique vectors; this does **not** establish unseen training history |
| Confirmed historical checkpoint-training overlaps | **UNKNOWN**, not a measured zero |

[All-eligible and selected overlap counts](../verification-logs/cic-external-20261108/overlap-counts.json)
record repeats/collisions separately. Exact whole-row duplicates are stronger
source-record evidence than the 149 repeated identity/time/counter metadata
signatures seen during the preliminary inventory: differing unselected fields
are not silently discarded as duplicates. Packet retransmissions and duplicate
capture frames remain counted as observed.

The eligibility join requires source SYN direction, exact source-minute
membership, duration through the first incoming FIN/RST, and all four forward/
backward packet/payload counters. This is deliberately narrower than joining a
whole session to several CIC FIN appendices. Most attack rows do not satisfy
it; the selected 26 attack records cannot represent the original attack pool.
No labels, thresholds or selected records were changed after predictions.

## Label-quality and observation-window risks

Engelen, Rimmer and Joosen's 2021 study documents flow-construction and labeling
errors; its corrected release changes FIN/RST handling and labeling semantics.
Corrections have dated revisions, and later work revises them further. A
corrected CSV is not interchangeable with the original release or a different
repaired/reordered PCAP. No corrected dataset is silently substituted here.
[Primary study and version history](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html).

Original flow directions and timeout-generated TCP appendices can be misleading;
the published attack timetable alone cannot supply exact per-flow labels.
[Authors' detailed analysis](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html).
Our join must establish unique packet-session/label-interval correspondence and
the monitored server direction, not infer intrusion from ports or schedules.
Even an unambiguous join inherits the source release's label-quality limits.

The model takes ingress TCP-segment lengths, ns-based IAT and statistics through
the first eligible incoming FIN/RST. CIC full-flow payload lengths and time
features cannot replace them. A timeout label segment or reverse FIN appendix
may not contain the complete modeled observation window; reject unresolved
cases rather than silently combine labels or include later packets.

## Gate decision

The provenance audit permits a **qualified external offline study**, not an
“independent, guaranteed unseen” claim or identical-protocol Table V reproduction.
The 126-record pilot, 2,500-record resource batch and all 15,026 final selected
records passed independent packet/label/feature validation. Final source IDs
and vectors were hashed before model inference; the unchanged preregistered
policy is linked in the [evaluation guide](cic/README.md).

The target of approximately 30,000 balanced flows was **not achieved**. Tuesday
contains only 13,835 intrusion-labeled source rows in total, and the strict
observation-window policy yields only 26 eligible attack rows. Broadening
matching or adding capture days requires a separately justified protocol and
renewed validation; it cannot be justified by a desired F1. Source-label defects,
unknown checkpoint membership, narrow selection and capture-clock approximation
remain explicit limitations after the successful numerical comparisons.
