# Dataset/model compatibility audit — 7 November 2026

Baseline deployment commit: `0ba2b2bbf9d1d24b4a98e228ff35aeb44c4e9d2d`.
Arithmetic checkpoint: `a99394b3c8ab36d9be316d350c86fe031ae460f2`.
This is source/data inspection, not a new kernel or two-machine result.

## Published references and label contract

The paper selects indices `[6,23,7,0,34,2]`, matching both implementations'
input order below. Table III reports reproduction train/test counts
16,257 / 27,103. Table V's NN-int32 Q+Top K reference values are:

| Published experiment | Accuracy | F1 |
| --- | ---: | ---: |
| CIC-IDS-2017 offline | 0.974 | 0.933 |
| eBPF-Reproduction real-time | 0.994 | 0.992 |

These are **published values, never our measurements**. Section IV-B3 assigns
0=benign, 1=intrusion. Its equation assigns equal logits to 0; the checked-in
XDP code and both TC modes assign equal logits to **1**. We preserve the code.
[Paper, Tables III–V and §IV-B3](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf).

The paper establishes the intended class coding. It does not establish the
row-by-row provenance or original split of these particular NPY files. The
offline evaluator therefore separates optional **supplied-code-label
diagnostics** from independently validated intrusion-detection effectiveness.
It does not infer coding from whichever mapping produces a better score.

## Actual stored artifacts

Safe numeric parsing measured:

- `dataset/reproduction-xdp-data.npy`: **(18,840, 6), little-endian int64**.
- `dataset/reproduction-xdp-label.npy`: **(18,840,), float64**, integral codes
  only: 0 → **5,585**, 1 → **13,255**. No label-generation manifest was found.
- **18,561** distinct vectors, **279** duplicate rows, no conflicting encoded
  labels among identical vectors. No timestamps, flow IDs, capture dates or
  original training-membership records accompany the arrays.

Every rounded full-file population mean and standard deviation equals the
header's mean/scale:

```text
mean  [572,11161066668,36,496,12145,379]
scale [451,24027934608,54,1672,49932,1560]
```

This strongly links the scaler to the supplied reproduction file; it does
**not prove the provenance of the weights**. The training script reads these
two filenames, constructs the bias-free 6→32→32→2 network and fits StandardScaler
on **all rows**, after requesting a random 80/20 split without `random_state`.
Such a split would contain 15,072 / 3,768 rows, not the published counts. Scaler
statistics include test rows, creating preprocessing leakage. Original model
training membership cannot be recovered; do not call a new split independent
held-out effectiveness testing.

No original `mlp.th`, FP32 checkpoint or CIC-trained checkpoint was found in
the project/research checkpoint search. The quantization script uses unsafe
`torch.load` and the training script unnecessarily allows pickle for labels;
neither script is executed here. Our numeric NPY reader permits only bounded
int64/float64 arrays, rejects objects/non-finite values and never unpickles.

Model source is `src/mlp_params.bpf.h`, SHA256
`f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11`.
All modes use those weights and rounded scaler. Layer-specific scaling changes
activation exponents/rounding and uses the recorded calibration metadata; it
does not recover missing FP32 weight precision. The exact rational comparison
represents this header network, not the missing original floating model.
[Machine-readable shapes, ranges, moments and hashes](verification-logs/final-demo-20261107/dataset_audit.json).

## Six-feature compatibility matrix

Indices refer to the paper's feature table, **not arbitrary physical CSV offsets**.

| Input / CIC index | CIC feature | Original XDP calculation | Current TC calculation | CIC compatibility |
| --- | --- | --- | --- | --- |
| 0 / 6 | Fwd Packet Length Max | max(IP total length − IPv4 IHL), TCP header included | Same feature formula, validated IPv4/TCP parser | Inspected CICFlowMeter uses TCP payload length; max(payload+header) cannot be reconstructed from max(payload) alone |
| 1 / 23 | Fwd IAT Max | max difference of ingress helper timestamps, **ns** | Same helper-clock ns; cross-CPU reorders clamped/counted | CIC capture timestamps use **µs**; ×1000 fixes units only, not observation timing/direction/window |
| 2 / 7 | Fwd Packet Length Min | min TCP-segment bytes, including TCP header | Same formula | CIC payload minimum differs; pure ACK is payload 0 versus segment at least 20 bytes |
| 3 / 0 | Destination Port | first observed forward destination port | destination port on eligible ingress input leg | Same numeric port only when forward direction matches; parse exact named column |
| 4 / 34 | Fwd Header Length | cumulative TCP doff×4 | Same TCP header-byte sum on input leg | Inspected meter also sums TCP header bytes, but direction, closure and inclusion window must match |
| 5 / 2 | Total Fwd Packets | count accepted source-filtered TCP packets, including FIN/RST | count eligible ingress-leg packets, including first triggering FIN/RST | Meter forward packet count depends on first-seen orientation, flow timeout and termination implementation |

The inspected primary [PacketReader](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java)
sets timestamps from `timestampInMicros`, lengths from TCP payload and header
length APIs. [BasicFlow](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)
builds forward statistics relative to the first flow source. This is not
automatically the monitored server's ingress. [FlowGenerator](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java)
has timeout/FIN/RST termination rules that vary across versions; the exact
CIC-2017 producer revision was not established. We do not claim that current
master defines every released CSV's semantics.

The original XDP parser assumes a 20-byte IP header when locating TCP and lacks
the TC parser's malformed/fragment checks. It hardcodes source `33.33.33.73`,
stores shared inference arrays in flow entries and can retrigger on subsequent
FIN/RST. TC fixes concurrency/parsing and retains one completed result per
canonical connection; egress counters are **not** input features. Identical
precomputed vectors avoid those extraction differences, but do not test them.
Offloads/GRO/GSO can change hook-visible packet sizes/counts; no offload setting
is changed. Neither hook captures CIC's offline timing exactly.

Both Q16 variants use unsigned-magnitude normalization, int64 accumulation,
arithmetic right-shift flooring and int32 narrowing. Overflow/narrowing events
must be exclusions reported explicitly. Experimental arithmetic rounds nearest
even and rejects unsupported ranges; no missing prediction becomes benign.

## CIC availability and optional safe import

No labeled CIC CSV was found in the project/research directories or inspected
Windows Downloads/Desktop/Documents. This is not an exhaustive disk inventory.
No large CSV/PCAP download was performed. Start with the
[official UNB dataset page](https://www.unb.ca/cic/datasets/ids-2017.html), which
describes labeled flow CSVs, capture conditions and days. Obtain a small
documented CSV input manually, record its official download provenance/SHA256,
and inspect headers before importing. Do not execute attack tools or binaries.

```bash
python3 evaluation/import_cic.py --input /path/to/selected-day.csv --output /tmp/cic-inspection
```

The importer reads named columns, trims header whitespace/BOM, rejects ambiguous
duplicate selected headers and reports original positions. Invalid/non-finite
selected values are excluded with row numbers/reasons; raw units are preserved.
Its output is **diagnostic CIC data, not an eBPF-equivalent vector dataset**.
There is no automatic unit/packet-length conversion or F1 evaluation. A CIC
checkpoint and extraction-equivalence/split protocol would be needed for a
faithful reproduction. Scoring this reproduction-linked model on CIC, if later
justified, would be cross-dataset/domain-shift testing with explicit caveats.

## Evaluation gates and interpretation

Gate A passes for a **model-level numerical comparison on the stored vectors**:
order, integer units, fixed scaler and code-label values are known. Genuine
held-out intrusion F1 remains **NOT RUN**: collection labels/training membership
are unverified, and no compatible CIC evaluation input/checkpoint is available.
Optional code-label metrics must say they score the bundled encoded labels,
with unknown training overlap, not independent attack truth or Table V parity.

The existing offline calibration split (4,996 / 13,844) keeps duplicate feature
groups together. Its held-out portion is held out from **scale selection only**;
the original model/scaler may have seen those rows. A held-out-day evaluation
requires capture/day metadata and a faithful feature protocol, neither present.
No retraining, scaler refit, model replacement or malicious replay is authorized
or performed. Live benign/unknown TCP scenarios are a separate experiment;
arbitrary socket payloads do not reproduce CIC rows.
