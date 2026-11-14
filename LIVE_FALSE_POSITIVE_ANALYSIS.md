# Live benign false-positive investigation

7 November 2026. Read-only analysis of saved artifacts from commit
`73868b101d1c1f5e27c6f71eceaa78a645368445`, branch
`feature/final-demo-evaluation`. Only this report was added. No model, labels,
inference code, demonstration harness or networking was changed; no kernel
programs were loaded and no traffic tests were rerun.

## Findings

The evidence supports a **model/input-distribution problem worth investigating**,
with strong destination-port sensitivity and unusually short flows relative to
the stored benign-coded population. It does **not establish TC as the cause**.
The saved kernel tensors agree with the appropriate integer reference, and the
original Q16 reference also predicts class 1 for these exact live vectors.
Equal-logit handling, overflow and timestamp reordering do not explain this run.

The strongest observed distribution discrepancy is destination port **9000**:
it never occurs in the supplied dataset and exceeds every benign-coded row's
port. Other features remain within the dataset's marginal minimum/maximum,
although packet counts and cumulative headers occupy a region much more common
among intrusion-coded rows. Minimum segment length and header accounting show
substantial agreement with the stored data. There is no demonstrated ns/µs bug.

## Population and method

- Reference file: [reproduction-xdp-data.npy](dataset/reproduction-xdp-data.npy),
  **18,840 × 6 int64** values, read with the existing bounded numeric reader;
  no pickle or training/checkpoint loading. Labels are read separately from
  [reproduction-xdp-label.npy](dataset/reproduction-xdp-label.npy).
- **“Training” statistics below mean the complete supplied reproduction file.**
  The actual historical training subset is unavailable. The training script
  requests an unsaved random split and fits its scaler on the entire file
  ([mlp_train.py](src/mlp_train.py), lines 20–33). These are reference-distribution
  statistics, not measurements of a recovered independent train/test split.
- Live source: [successful isolated WSL2 run](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/results.json).
  The 1/10/32 batches contain **38 explicitly benign connections per mode**:
  1 + 9 + 28. Five unknown cases per mode are excluded. Thus this analysis covers
  **76 benign observations**, not all 86 connections and not 76 independent
  traffic scenarios; scenarios repeat across batches and modes.
- Connections were matched by experiment/session and full TCP tuple to retained
  kernel results. Features came from immutable inference records, not later
  flow counters. All 76 labels, logits and six intermediate tensors matched
  the corresponding Python reference with no arithmetic events. The original
  Q16 reference and exact rational header-network reference were also evaluated
  on each same vector using host calculations only.
- Standard deviations use population SD (`ddof=0`). Tables round displayed
  moments; quantiles below use linear interpolation at `(n−1)p`. Stored code 0
  is interpreted as benign only under the paper's intended coding; a manifest
  proving individual stored labels is still missing. See [DATASET_AUDIT.md](DATASET_AUDIT.md).

## Per-feature comparison

Input order is identical in XDP and TC:
`[maximum TCP-segment bytes, maximum forward IAT, minimum TCP-segment bytes,
destination port, cumulative forward TCP-header bytes, forward packet count]`.

| Feature / units | Reference minimum | Reference maximum | Reference mean | Reference population SD | Benign live Q16 range | Benign live layer-specific range |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| Maximum TCP-segment length / bytes | 20 | 1,480 | 571.545648 | 451.430511 | 114–192 | 114–192 |
| Maximum forward IAT / source-defined ns | 0 | 827,560,563,008 | 11,161,066,668.226486 | 24,027,934,608.299084 | 2,123,332–5,515,539 | 493,208–6,133,095 |
| Minimum TCP-segment length / bytes | 20 | 984 | 35.611359 | 54.303186 | 32 | 32 |
| Destination port / integer | 20 | 12,865 | 496.486412 | 1,671.753375 | 9,000 | 9,000 |
| Cumulative forward TCP-header length / bytes | 20 | 233,512 | 12,145.089597 | 49,931.984280 | 168–264 | 168–264 |
| Forward packet count / packets | 1 | 7,297 | 379.281210 | 1,560.374886 | 5–8 | 5–8 |

The NPY array itself has no unit metadata. “ns” follows the available original
XDP extraction source, the linked scaler and the live TC implementation; the
original collection/conversion script was not found. It is not proof that every
historical row was collected exactly as the present source describes.

Representative **recorded** `demo001` connections from each single-client batch:

| Mode / client source port → server port | Actual feature vector |
| --- | --- |
| Q16 / 36379 → 9000 | `[114, 2281047, 32, 9000, 200, 6]` |
| Layer-specific / 39375 → 9000 | `[114, 2442872, 32, 9000, 200, 6]` |

Sources: [Q16 client identity](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/static_q16/client-1/client_results.csv),
[Q16 immutable kernel tensors](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/static_q16/experiment/kernel_snapshot.json),
[layer-specific client identity](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/layer_specific/client-1/client_results.csv),
[layer-specific kernel tensors](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/layer_specific/experiment/kernel_snapshot.json).

### Destination port: confirmed novel value and model sensitivity

Port 9000 is inside the full numeric range but **outside observed discrete
support**. Every stored code-0 port is at most 5001. Port is represented as a
standardized scalar, so numeric distance can affect the MLP; it is not a
categorical service identifier or a statement that high ports are malicious.

| Stored destination port | All rows | Code 0 rows | Code 1 rows |
| --- | ---: | ---: | ---: |
| 20 | 2,532 | 2,532 | 0 |
| 21 | 1,109 | 26 | 1,083 |
| 22 | 3,128 | 1,080 | 2,048 |
| 80 | 10,636 | 1,024 | 9,612 |
| 3306 | 128 | 0 | 128 |
| 5001 | 1,051 | 923 | 128 |
| 8080 | 128 | 0 | 128 |
| 12865 | 128 | 0 | 128 |
| **9000, actual live port** | **0** | **0** | **0** |

An analysis-only host Q16 calculation held each live vector's other five
features fixed. Changing only its port to **80** produced class 0 for **66/76**
vectors and class 1 for **10/76**. Ports 20/21/22 gave the same class counts;
ports 3306/5001/8080/12865 left all 76 at class 1. For the recorded Q16 example:

| Host-only input-port diagnostic | Q16 output logits | Predicted class |
| --- | --- | ---: |
| Actual 9000 | `[-215448, 186484]` | 1 |
| Hypothetical 80 | `[14424, -10149]` | 0 |
| Hypothetical 5001 | `[-129174, 110604]` | 1 |

These hypothetical vectors are **not new kernel observations or measured FPRs**.
No saved vector, label, application port or network configuration was edited.
This isolates model sensitivity to an input coordinate, not the causal effect
of switching a real service: live packetization and timing can change too.
It also shows that an unseen port alone is not a complete explanation.

### Packet counts, header totals and segment lengths

Global means are misleading for this skewed population. The class-conditioned
distributions give a clearer comparison:

| Feature | Stored code 0, Q25 / median / Q75 | Stored code 1, Q25 / median / Q75 | Benign live observations |
| --- | --- | --- | --- |
| Maximum segment bytes | 107 / 912 / 1480 | 296 / 434 / 579 | 114–192; median 114 in both modes |
| Maximum IAT, ns | 306192 / 432807 / 3561249 | 3028479369 / 10398377933 / 22944746232 | Q16 median 3391352; layer median 3045052.5 |
| Minimum segment bytes | 32 / 32 / 40 | 32 / 32 / 32 | All 32 |
| Cumulative TCP-header bytes | 584 / 872 / 4768 | 200 / 236 / 360 | 168–264; median 232 in both modes |
| Forward packet count | 18 / 27 / 149 | 6 / 7 / 11 | 5–8; median 7 in both modes |

Only **160/5585** code-0 rows have 5–8 packets, versus **6026/13255** code-1
rows. Header totals 168–264 occur in **159/5585** code-0 rows and
**5278/13255** code-1 rows. This supports a distribution shift toward short
flows; it does not make these ordinary connections intrusions. Header totals
and packet counts are strongly related, not two independent causes.

Both [original XDP](src/xdp.bpf.c) (lines 94–98) and
[TC parsing/update](tc/tc_ids.bpf.c) (lines 98–119, 247–274) calculate segment
length as `IPv4 total_length − IPv4 IHL`, **including TCP headers/options**.
This is neither application payload length nor Ethernet frame length.
TC's aggregate byte counters use `skb->len`, a separate monitoring quantity;
they are not substituted into the MLP inputs.

All live minimum lengths are 32, also the stored value in **16,137/18,840** rows
(including **4,048/5,585** code-0 rows). Every analyzed live vector obeys
`header_total = 32 × packet_count + 8`, as do **14,799/18,840** stored rows,
including **5,380/5,585** code-0 rows. This is consistent with a 40-byte TCP
header on one packet and 32-byte headers on the others; individual packet
headers were not retained, so that allocation is an interpretation, not a
packet-by-packet proof. There is no evidence here of a new TC header-length
convention causing the false positives.

The demonstration also sends an experiment/case protocol header before its
ASCII payload ([client.py](demo/client.py), lines 37–42). The representative
connection sent **146 application bytes: 64 scenario payload + 82 protocol
bytes**. A separate 82-byte TCP payload with a 32-byte TCP header would yield
the observed maximum 114; the saved aggregates do not prove that exact
packetization. Comparing “64 payload bytes” directly with feature 114 would
therefore misdiagnose a parser error.

The inspected CICFlowMeter code instead records TCP payload length and IPv4
capture timestamps in microseconds. This is a genuine **CIC versus eBPF
representation concern**, not evidence that this NPY file uses CIC conventions.
No CIC CSV was fed into this live test. The exact historical CIC producer
revision is unknown. [Primary PacketReader source](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java).

### IAT: small live intervals, no demonstrated unit mismatch

Both extraction implementations use `bpf_ktime_get_ns()` differences; TC keeps
the maximum interval on the original ingress input leg, excluding egress.
Live maxima span **0.493208–6.133095 ms**. The scenario deliberately inserts
2-ms gaps for multi-chunk cases; helper-clock observations also include
scheduling and network-stack delays. Chunk boundaries need not be packets.

The whole-file IAT median is **3.336474919 s** and mean **11.161066668 s**,
but the code-0 median is only **0.432807 ms**, with Q75 **3.561249 ms**.
Thus “live IAT is much smaller than the overall mean” does not establish an
out-of-range value or an incorrect 1000-fold conversion. It overlaps the
benign-coded distribution. No unit rescaling is justified from these aggregates.

Both saved runs report **zero timestamp reorders**, and all analyzed final flow
records also report zero. The earlier concurrency-test reorders are not events
in this harness run. TC's clamp can affect chronological IAT semantics when
samples arrive out of timestamp order, but that path supplies no explanation
for the present result. Offloads and the XDP/TC observation points can change
packet sizes, counts and timing; no matched packet capture or simultaneous
hook measurement here establishes their actual effect. No offload was changed.

## Normalization and arithmetic

The checked-in scaler is:

```text
mean  [572,11161066668,36,496,12145,379]
scale [451,24027934608,54,1672,49932,1560]
```

Each value is the rounded corresponding full-file mean or population SD. This
supports linkage to the supplied data, but does not establish weight-training
membership. Full-file scaler fitting leaks information across an evaluation
split; that limitation does not by itself explain these live false positives.

Q16 normalizes using signed magnitude with truncation toward zero at scale
65536; layer-specific normalization uses nearest-even at scale 4194304. For
the recorded Q16 example, the kernel actually stored:

```text
features     [114,2281047,32,9000,200,6]
normalized   [-66553,-30435,-4854,333324,-15677,-15669]
real values  [-1.015518,-0.464401,-0.074066,5.086121,-0.239212,-0.239090]
```

Port is approximately **+5.086** standardized units; the other coordinates are
approximately −1.016, −0.464, −0.074, −0.239 and −0.239. This is a descriptive
scalar distance, not a Gaussian tail probability or a calibrated attack score.
All 76 vectors fit every full-file marginal min/max; port is the only coordinate
outside code-0 marginal min/max. In-range coordinates do not guarantee a
representative joint distribution.

All six saved kernel stages matched the mode-specific reference for these 76
benign observations: **456 tensors / 10,336 integers**, zero mismatches and no
reported overflow/narrowing events. These are host rechecks of saved kernel
evidence, not new kernel executions. Layer-specific saved numerical diagnostics
are all zero. Using the original Q16 arithmetic on *all 76 same live vectors*
still gives class 1. An exact rational reconstruction of the header-weight /
rounded-scaler network also gives class 1 for all 76. The original FP32
checkpoint is unavailable; the rational model is not a recovered FP32 model.
The modes ran in separate sessions with different clock-derived inputs; their
raw output differences are not an identical-vector comparison. Each reference
check above uses the exact feature vector of its own saved kernel record.

## FIN-triggered window and flow lifetime

Current TC updates the input statistics **before** testing the closing packet;
the triggering FIN/RST is included. It snapshots at the first eligible ingress
FIN/RST, then preserves the completed result. The ordinary client performs a
write-half-close before waiting for the application reply. Thus its inference
is not a summary of the eventual complete bidirectional exchange.

For **all 76** benign connections, final ingress monitoring counts exceed the
immutable inference packet count by **two**. The Q16 example uses count **6**
and cumulative header **200** for inference; its final ingress count is **8**.
The extra packets are observed after the result's input snapshot; the artifacts
do not retain per-packet flags/times to identify each one independently. Later
flow/JSONL directional counters must not be substituted for the saved inputs.
Egress counts remain separate from all six model features.

The original XDP source also updates statistics before FIN/RST inference, so
the trigger convention was **not introduced by the TC migration**. The paper
describes FIN/RST termination-based inference. [Paper §IV-A5](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf).
However, the available XDP code can retrigger and keeps the tuple's counters;
TC retains the first successful result. No capture, extraction/export manifest,
per-row tuple or termination marker establishes which snapshot became each
stored training row. Whether the NPY rows match this first-client-FIN window
is therefore **UNKNOWN**, not a demonstrated mismatch. Tuple reuse or repeated
termination could matter in other runs; the analyzed client tuples are distinct
within each session and provide no evidence of that failure here.

## Labels, logits and ties

The paper explicitly specifies **0=benign, 1=intrusion**. Its equality case
selects 0; original XDP and current TC select 1 when the two logits are equal.
That known discrepancy is inactive here: **zero equal-logit benign predictions**.
[Paper §IV-B3, equation (5)](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf),
[XDP decision](src/xdp.bpf.c) (line 318),
[TC decision](tc/tc_ids.bpf.c) (line 397).

| Actual benign kernel output | Q16, 38 connections | Layer-specific, 38 connections |
| --- | --- | --- |
| Stored logit scale | 2^16 | 2^18 |
| Logit 0 integer range | −215454 … −207542 | −861840 … −830152 |
| Logit 1 integer range | 180147 … 186489 | 720576 … 745978 |
| Smallest / largest observed integer gap, logit1−logit0 | 387689 / 401943 | 1550728 / 1607818 |
| Gap after dividing by the actual scale | 5.915665 … 6.133163 | 5.915558 … 6.133339 |
| Class 1 / class 0 / ties | 38 / 0 / 0 | 38 / 0 / 0 |

Representative Q16 logits `[-215448,186484]` equal
`[-3.287475586,2.845520020]` after dividing by 65536. The representative
layer-specific logits `[-861808,745951]` equal
`[-3.287536621,2.845577240]` after dividing by 262144. These are clearly
separated raw scores, **not calibrated probabilities**. The maximum absolute
per-logit error versus the exact header-network reference on the respective
live vectors is **0.000074532324** for Q16 and **0.000001928123** for
layer-specific. These errors are much smaller than the observed decision gaps;
both exact and fixed-point decisions agree. Rounding/near-tie behavior is not
supported as the explanation for these cases.

Each mode therefore has **38 false positives / 0 true negatives** under the
paper's intended coding, with all 38 benign predictions present. Five unknown
connections per mode remain unscored. The supplied class labels' provenance
remains a separate dataset limitation; flipping the class interpretation to
make this live experiment look successful would contradict the stated contract.
No intrusion recall or F1 can be inferred from these benign-only observations.

## Recommended future experiments — not executed here

1. **Recover collection and model provenance.** Obtain safe numeric exports and
   the label/split/capture manifest, particularly timestamp units and whether
   rows are first-FIN, later-FIN or reused-tuple snapshots. Resolve compatibility
   before attributing findings to the paper's model performance.
2. **Independently reconstruct feature windows.** In a separately approved
   isolated test, retain packet metadata only: tuple, direction, IPv4 length/IHL,
   TCP doff/flags and timestamps. Reconstruct first-FIN and full-close windows,
   checking all six inputs. Capture timestamps and helper clocks require an
   explicit timing protocol; they are not automatically interchangeable.
3. **Test port sensitivity with real benign traffic.** Use identical bounded
   application scenarios on separately approved isolated listeners at observed
   dataset ports and at 9000, in randomized repeated runs. Keep benign truth
   fixed and report actual extracted vectors/margins. Port 80 requires a
   suitable approved listener setup; the working launcher deliberately requires
   unprivileged ports. The host-only port calculation above is not this test.
4. **Vary flow size and timing independently where feasible.** Compare short
   and longer benign flows, chunk counts and delays, with protocol-header effects
   explicitly measured. Assert observed packet counts, not application-write
   counts. Keep the working demonstration unchanged and use a separate study.
5. **Compare hooks under controlled observation.** Apply original XDP and TC
   extraction to identical packet fixtures first; use separate clean live runs
   on the same kernel/topology if needed. Account for offloads and helper-clock
   timing, without changing physical network settings. Existing same-vector
   parity does not prove packet-extraction equivalence or hook-independent IAT.
6. **Then evaluate independently labeled held-out captures.** Report benign
   FPR and coverage now; intrusion metrics need genuine intrusion labels and a
   compatible observation protocol. Investigate model generalization only after
   representation/window checks. No retraining, relabeling, threshold tuning or
   demonstration “fix” is justified by this report alone.

## Evidence and preservation

- [Prior dataset moments and hashes](verification-logs/final-demo-20261107/dataset_audit.json).
- [Q16 classifications](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/static_q16/experiment/server_classifications.jsonl)
  and [layer-specific classifications](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/layer_specific/experiment/server_classifications.jsonl).
- [Q16 batch-32 joined rows](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/static_q16/join-32/joined_results.csv)
  and [layer-specific batch-32 joined rows](verification-logs/final-demo-20261107/ready/run-20261107-201114-136504/layer_specific/join-32/joined_results.csv);
  the neighboring batch-1/10 files establish the remaining observations.
- [Original scaler/arithmetic](src/mlp.bpf.h),
  [independent Q16 reference](validation/reference.py),
  [layer-specific/exact references](quantization/reference.py).
- [Prior full-run verification](verification-logs/final-demo-20261107/VERIFIED.json)
  covers all 86 predictions, including unknown-truth cases. This report's
  numerical count deliberately covers only its 76 known-benign observations.

All **83** prepared source/runtime hashes were rechecked against
[the existing manifest](verification-logs/final-demo-20261107/ready/manifest.json)
and were unchanged. Analysis used ordinary-user file reads and in-memory host
calculations only. Temporary analysis scripts/results were kept under `/tmp`;
the only project addition is this report. No commit or push was performed.
