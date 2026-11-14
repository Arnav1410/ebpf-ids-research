# Bidirectional six-input MLP: feasibility experiment

9 November 2026. **Dataset Gate 3 FAIL: training and TC integration stopped.**
The audit and offline feature-reference pilot passed. There is no new trained
model, F1 result, experimental TC program, or kernel/network execution in this
experiment. The existing fresh-model demonstration remains unchanged.

## Preservation and scope

The demo checkout remains on `feature/final-demo-evaluation`, commit
`711b909261e352cfb87ce3c34d598f5615e04661`. Its tracked working-tree change is
still the pre-existing unrelated dataset-file deletion; it was not restored,
read, executed, staged or manipulated. No existing untracked work was moved.

New branch: **`feature/bidirectional-mlp`**, based on that same commit.
Sparse worktree:

```text
/home/arnav/research/ebpf-ids-research/experiments/bidirectional_mlp_20261109/worktree
```

The sparse checkout includes source/model directories and excludes
`dataset-instance` entirely. The original demonstration, fresh-model package,
deployment defaults, XDP baseline and all existing experimental results were
left untouched. SHA256 preservation checks cover **5,067 existing files**;
five unreadable root-owned evidence files were compared by metadata only.
[Preservation check](research/bidirectional_mlp/evidence/preservation-after.json).
No privileged operation, network change, data download, malicious replay,
new commit or push was performed. Creating the worktree changes only Git's
branch/worktree metadata and adds files under this experiment directory.

The CIC packet parser and research scripts were untracked in the main checkout.
Seven exact source/test dependencies were copied into this worktree; hashes
and rationale are in [DEPENDENCIES.json](research/bidirectional_mlp/DEPENDENCIES.json).
No earlier training checkpoint or benchmark binary was copied or executed.

The protected models remain:

| Artifact | SHA256 |
| --- | --- |
| Original parameter header | `f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11` |
| Demo fresh Q16 header | `e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391` |
| Existing fresh checkpoint | `d299f964ecaa7b918eca65529371dbfa6db8797df97ee24b73a324ab52acef1b` |

## Gate 1: what the existing TC code actually collects

Inspected sources: `tc/tc_ids.bpf.c`, `tc/abi.h`, `tc/flow_key.h`,
`tc/controller.c`, `src/mlp.bpf.h`, `src/mlp.py`, `src/mlp_train.py`,
`src/mlp_quant.py`, `quantization/arithmetic.h`, `quantization/reference.py`,
`deployment/model_config.py`, and the existing fresh-model `pipeline.py` and
`integer.py` in the main checkout. Existing numerical, concurrency and
packet-label validation reports were inspected rather than rerunning privileged
tests of unchanged programs.

| Measurement/state | Ingress input leg | Egress | Reuse for proposed inputs |
| --- | --- | --- | --- |
| Accepted packet count | `tc_flow.packets` | `hooks[1].packets`; canonical endpoint counters too | Counts exist, but require validated client/server direction and decision-time snapshot |
| Byte totals | Ingress segment-byte sum plus hook `skb->len` | Hook/endpoint `skb->len` | Egress byte counters are frame/skb bytes, not segment extrema or TCP-header bytes |
| Segment min/max | `min_length`, `max_length` | **Not retained**; parser computes a length then discards it | New directional egress extrema required |
| Cumulative TCP-header bytes | `header_length`, sums `doff*4` | **Not retained** | New egress header accumulator required |
| Directional maximum IAT | `max_duration` in ns | **Not retained** | New egress IAT maximum required |
| Timestamp bounds | Input first/last; hook first/last | Hook first/last extrema and reorder counter | First/last alone cannot recover maximum inter-arrival gap |
| TCP flags | OR of SYN/FIN/RST bits | OR of SYN/FIN/RST bits | No ACK/PSH history or ordered termination state is retained |
| Endpoint identity | Canonical sorted address/port key, plus remembered ingress input tuple | Same map/key | Preserve key; canonical endpoint B is not necessarily the server |

The original six inputs are `[ingress_segment_max, ingress_iat_max_ns,
ingress_segment_min, ingress_destination_port, ingress_tcp_header_sum,
ingress_packet_count]`. Valid SYN, ACK, FIN and RST packets contribute;
the first eligible incoming FIN/RST is included before inference starts.
Egress cannot currently trigger inference or supply these inputs. Hook counters
can continue increasing after the immutable inference result is published.

`flow_map` has capacity 8,192 and a top-level spin lock. Input initialization,
flow statistics, inference-state transitions and six-feature snapshot occur
under that lock. A per-CPU `workspace` busy guard owns temporary tensors across
all six tail-call stages. The stage chain is normalization, 6→32 linear, ReLU,
32→32 linear, ReLU, 32→2 linear. Results are retained by canonical key with a
stage mask and snapshots. Existing duplicate/state guards prevent a completed
connection from simply being classified again. They do not establish a general
flow-expiry or TCP tuple-generation policy for a new feature mode.

The bias-free architecture has 1,280 weights. Q16 uses the established integer
normalization/linear semantics; equal integer logits select class 1. The fresh
model's scaler was fitted only on its reproduction training partition. Its
old six-input weights/scaler cannot be reused for the different aggregate
representation. The authors' original training script's whole-file scaler fit
must not be copied into a future experiment. No training script was run here.

## Gate 2: exact proposed feature contract

This is an **offline specification/reference**, not an installed kernel mode.
For a validated client→server flow, let `P_in(t*)` and `P_out(t*)` be accepted
packets visible at or before the inference decision. For each direction `d`:

```text
L(p) = IPv4 total_length(p) - IPv4_header_bytes(p)
H(p) = TCP doff(p) * 4
N_d = number of accepted packets in that direction
H_d = sum H(p)
M_d = max L(p), m_d = min L(p), only when N_d > 0
I_d = max consecutive same-direction timestamp difference; 0 if N_d < 2
```

| Input | Definition | Unit |
| --- | --- | --- |
| `segment_len_max` | max `M_d` over directions with packets | TCP-segment bytes, TCP header/options included |
| `iat_max` | max(`I_in`, `I_out`) | Integer nanoseconds |
| `segment_len_min` | min `m_d` over directions with packets | TCP-segment bytes; an absent direction contributes no zero |
| `destination_port` | Observed SYN responder's service port, fixed throughout flow | Host-order integer port |
| `tcp_header_total` | `H_in + H_out` | TCP-header bytes including options |
| `packet_count` | `N_in + N_out` | Accepted packets |

Do not compute IAT between interleaved directions. The first packet in a
direction contributes zero IAT. Count observed retransmissions; do not
deduplicate them. SYN/ACK/FIN/RST packets contribute their actual segment and
header lengths. Ethernet padding, IP headers and application payload alone
are not the length feature.

The current TC parser accepts untagged Ethernet IPv4/TCP with variable valid
IPv4 IHL, and rejects fragments/malformed lengths unscored. The audited CIC
pilot uses the stricter common subset with IPv4 IHL=20. Neither VLAN nor IPv6
support is claimed. Capture deltas in ns approximate helper-clock timing;
they do not reproduce host scheduling or offload-dependent skb segmentation.

The reference rejects timestamp reordering and nonnegative-int64 feature
overflow; it never silently wraps or saturates. Existing live TC clamps late
same-direction helper timestamps and counts reorders. That difference must be
tested explicitly in any future kernel implementation. A future experimental
ABI needs checked fixed-width counters, a sticky invalid-state diagnostic,
and signed-int64 bounds before taking its snapshot.

### Inference observation point

Two distinct windows are kept separate:

1. **Legacy prefix:** first eligible incoming FIN/RST, including that packet.
   The 126 packet/label windows below validate aggregate features for this
   prefix only. They do not include later server responses.
2. **Candidate response-inclusive window:** require a known initial client SYN;
   trigger on the first observed RST in either direction, or the packet that
   completes observed FINs in both directions. Include the triggering packet.
   Allow at most **5 seconds after the first FIN**. If the next observed packet
   is later, expire unscored before including it. Do not invent a timer-driven
   inference if no further packet arrives. Final ACKs after the decision are
   excluded. A reset or missing reverse direction can still produce only a
   partial response observation; completeness is not guaranteed.

Five seconds is a **provisional bounded engineering parameter**, not a learned
threshold or validated CIC producer rule. The candidate reference is tested,
but its dataset window and kernel lifecycle are not validated. Production
retention/expiry must be bounded separately; a packet-triggered deadline alone
does not reclaim idle map entries.

The demo client half-closes its write side, and the server sends its application
reply after `recv()` returns EOF. Thus the current incoming-FIN decision
precedes that reply. This is directly supported by `demo/client.py` and
`demo/server.py`; mere egress packet counters do not prove response data reached
the MLP. The candidate later window addresses this ordering in a reference,
without changing the working demo.

A future TC mode would update both validated endpoint directions under the
existing flow lock, copy the aggregate vector while holding that lock, then
release it before tail calls. Ingress and egress would share an exactly-once
state transition and per-CPU workspace guard. Helpers must stay outside the
locked arithmetic section. Tuple reuse, missing SYN, stale entries, deadline
expiration, result retention and changed ABI readouts require their own tests.
None of those kernel changes were made after the dataset gate failed.

## Gate 3: actual local data and compatibility

The 18,840-row reproduction array has only the original forward six-vector
and supplied binary labels, without backward packets/features or capture/session
IDs. Egress values cannot be recovered from it. Its existing trained model and
held-out evaluation are separate and preserved.

Operator-provided sources under
`/mnt/c/Study Materials/Semester 7/USAP/Term Project/`:

| Source | SHA256 |
| --- | --- |
| `Tuesday-WorkingHours.pcap` (PCAPNG, 11,048,283,608 bytes) | `080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57` |
| `GeneratedLabelledFlows.zip` | `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a` |
| Tuesday identity-bearing CSV member | `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815` |

Both source files were rehashed read-only. Archive members were streamed,
not extracted. They include endpoints, protocol, timestamp, duration, class,
and forward/backward length, IAT, header and count columns. Only Tuesday's
PCAP was located in the supplied source directory; other capture days were
not downloaded. Matching a checksum binds the supplied files, not their
unobserved original download provenance.

The [official CIC source](https://www.unb.ca/cic/datasets/ids-2017.html) describes
five capture days and Tuesday FTP/SSH brute-force campaigns. The known flow
construction/labeling defects and changed FIN/RST behavior documented by
[Engelen, Rimmer and Joosen](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html)
remain relevant; no corrected release or replacement labels were substituted.

### Full local CSV inventory

These are **source-column cleaning counts**, not a semantically validated
kernel-feature dataset. Counts describe the actual supplied archive, without
assuming a different MachineLearningCSV release has the same population.

| Member shorthand | Raw rows | TCP rows | Clean TCP benign | Clean TCP intrusion | Matching local PCAP |
| --- | ---: | ---: | ---: | ---: | --- |
| Monday | 529,918 | 305,423 | 305,374 | 0 | Not located |
| Tuesday | 445,909 | 245,781 | 231,925 | 13,835 | Yes |
| Wednesday | 692,703 | 489,450 | 236,741 | 252,671 | Not located |
| Thursday morning WebAttacks | 458,968 | 88,455 | 86,263 | 2,180 | Not located |
| Thursday afternoon Infilteration | 288,602 | 186,169 | 185,987 | 36 | Not located |
| Friday morning | 191,033 | 95,199 | 93,222 | 1,966 | Not located |
| Friday afternoon DDos | 225,745 | 192,820 | 64,789 | 128,027 | Not located |
| Friday afternoon PortScan | 286,467 | 226,257 | 67,297 | 158,923 | Not located |
| **Total** | **3,119,345** | **1,829,554** | **1,271,598** | **557,638** | Tuesday only |

The cleaning policy checks the selected numeric columns for finite,
nonnegative integral int64 values, valid nonempty identities, IPv4/port bounds,
positive forward count and valid observed-direction extrema. Duplicate
`Fwd Header Length` columns must agree. Exclusions: 1,289,791 non-TCP rows,
115 invalid selected-numeric TCP rows, and 203 exact duplicate TCP source rows
within members. Duplicate removal is not proof of cross-file/session
independence. Unselected columns and timestamps for other capture days are
not certified usable. Tuesday's earlier strict identity/clock validator has
additional requirements, so its usable-row count differs from this inventory.

Among clean TCP rows, **440,163 have zero backward packets**. They remain
explicitly identified; zero backward minima must not enter aggregate minima.
The source inventory preserves all label categories and raw non-UTF8 label
bytes reversibly. DoS, Heartbleed, web attacks, infiltration, bot, DDoS and scan
annotations are available in CSVs, but their packet-level compatibility was
not established without the corresponding capture.

[Exact filenames, per-class counts, duplicate-column positions, member hashes
and exclusions](research/bidirectional_mlp/evidence/inventory/inventory.json).

### Compatibility matrix

| Proposed kernel input | CIC columns available | Can they be substituted directly? |
| --- | --- | --- |
| Segment maximum/minimum across directions | Fwd/Bwd Packet Length Max/Min | No: inspected CICFlowMeter uses payload bytes. Header lengths vary per packet; extrema of payload plus a header constant are not justified |
| Maximum directional IAT | Fwd/Bwd IAT Max | Microseconds can be converted to ns, but clock, direction and inference window still need packet validation; do not use `Flow IAT Max` |
| Service destination port | Source/Destination IP/Port, Flow ID | Only after SYN/client-server orientation is established; canonical sort order is not service identity |
| Combined header sum | Fwd/Bwd Header Length | Potentially compatible TCP-header accounting, but only for exactly the same accepted packets/window; duplicated forward column needs checking |
| Combined packet count | Total Fwd/Backward Packets | Potentially compatible on a uniquely matched observation window, not automatically the completed CSV flow |

Primary implementation evidence:
[CICFlowMeter PacketReader](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java)
uses microsecond timestamps and TCP payload/header APIs;
[BasicFlow](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)
maintains direction-relative payload, header and IAT statistics. The exact
producer revision of the supplied 2017 files remains unknown. These inspected
sources explain incompatibility; they do not certify every released CSV.

### Packet pilot: what passed

Reused the prior predictions-blind frozen pilot IDs: **100 BENIGN, 5
FTP-Patator, 21 SSH-Patator**, including all 26 eligible attack annotations.
Read **5,050 packet records** from the bound PCAPNG using saved offsets.
Validated tuple direction, initial SYN, first incoming FIN/RST, timestamps,
duration and all four forward/backward packet/payload label counters again.
No labels were inferred from ports or model predictions.

Each packet's lengths/header/flags were independently derived from raw bytes
and compared with the existing decoder. Streaming aggregate features were
cross-checked against a separate batch calculation. Original forward vectors
also matched the frozen six-vectors. Existing host-compiled XDP/TC feature
helper tests passed; the previous packet-to-C validation report is retained
in the main checkout. These are **host/offline checks, not kernel execution**.

At the **legacy** trigger, feature changes caused by incorporating observed
reverse packets were:

| Feature | Changed pilot flows / 126 |
| --- | ---: |
| Segment maximum | 92 |
| Maximum directional IAT | 49 |
| Segment minimum | 0 |
| Service port | 0 |
| Header sum | 126 |
| Packet count | 126 |

All 126 had reverse packets, and 110 had reverse payload before that legacy
decision. This demonstrates real historical reverse packets affecting the
offline proposed vector, **not egress influencing a currently installed MLP**.

Representative actual vectors, in the specified six-input order:

| Source annotation | Forward control | Aggregate at the same legacy trigger |
| --- | --- | --- |
| BENIGN | `[2076,76108057000,20,80,552,27]` | `[2076,76108057000,20,80,1004,49]` |
| FTP-Patator | `[54,3314868000,32,21,264,8]` | `[66,3314868000,32,21,592,18]` |
| SSH-Patator | `[672,2609673000,32,22,744,23]` | `[1008,2609673000,32,22,1616,50]` |

[Pilot summary](research/bidirectional_mlp/evidence/pilot/summary.json),
[all derived vectors and header-only packet traces](research/bidirectional_mlp/evidence/pilot/pilot.jsonl),
[traceable example records](research/bidirectional_mlp/evidence/pilot/examples.json).
No packet payloads were saved in the new evidence.

### Why the training gate fails

**Window mismatch:** no pilot prefix contains a reverse FIN. Only **4** records,
all benign RST terminations, have the candidate response-inclusive decision at
the already validated label endpoint. The other **122** include **all 26 attack
records**: 121 have no candidate trigger in the retained prefix, and one has
an earlier reverse RST. Later termination needs additional packet references;
the earlier RST needs its shorter label window validated too. Neither is
covered by blindly reusing the old interval. This does not prove valid labels
for those windows are impossible; they have not been established with the
available join.

**Grouping limitation:** the complete prior strict eligible pool has **62,615**
flows: **62,589 BENIGN, 5 FTP-Patator, 21 SSH-Patator**. All are from one capture
day. The 26 attack records occupy only two `(day, category, client IP, server
IP)` campaign proxies, and share endpoint pair `172.16.0.1 ↔ 192.168.10.50`.
These are conservative grouping proxies, not recovered independent session
IDs. They are supported by the source campaign account and observed metadata.
With two such positive groups, three disjoint train/validation/test partitions
cannot each contain intrusion examples. Arbitrary minute/connection splits
would weaken the specified campaign-separation policy and would not establish
independent generalization. No stricter independence claim is made.

[Full eligible-pool grouping audit](research/bidirectional_mlp/evidence/groups/groups.json).
The prospective [policy](research/bidirectional_mlp/POLICY.json) was saved before
feature pilot/model evaluation; no neural predictions were consulted in this
experiment. A pilot/preparation subset is not called a frozen final test set.

An **early-decision aggregate-prefix model** is a possible separately named
protocol: its packet features are reconstructible here, but it omits later
responses and still has the same campaign-split limitation. A **CIC CSV-only
payload-feature model** would be another offline experiment with different
semantics. Neither was silently substituted for the requested kernel-feature
comparison or trained after the failed gate.

## Results and status

| Check / deliverable | Status | Evidence or scope |
| --- | --- | --- |
| Gate 0: demo preservation and separate branch | PASS | 5,067 hashes; five metadata-only files unchanged |
| Gate 1: ingress/egress state audit | PASS | Source audit above |
| Gate 2: formulas and bounded candidate-window reference | PASS | Offline specification and unit tests only; deployment timing not validated |
| Source archive inventory | PASS | Eight streamed members; selected-column cleaning only |
| Offline aggregate-prefix packet pilot | PASS | 126 label/feature windows, 5,050 packets |
| Gate 3: candidate-window labeled dataset and grouped split | **FAIL** | 122 unvalidated new windows; two positive campaign proxies |
| Gate 4: train control/aggregate MLPs | NOT RUN | Required dataset gate failed |
| Gate 5: held-out metrics/disagreements/confusion matrices | NOT RUN | No trained experimental models or predictions |
| Gate 6: new BPF compilation/verifier acceptance | NOT RUN | No experimental BPF changes |
| Gate 7: quantization, map readback, six-stage kernel execution | NOT RUN | Gated on model/data validation |
| Gate 8: one/ten/32/asymmetric/one-direction namespace tests | NOT RUN | No experimental kernel mode to test |
| Physical two-laptop experimental test | NOT RUN | No physical interface operations |

**39 host tests passed**, including 19 new feature/input-bound tests and 20
reused capture, original-C-helper and label tests. They cover one missing
direction, directional IAT, changed reverse traffic with identical forward
events, TCP control/retransmission inclusion, byte/port/time bounds, overflow,
RST, both FIN orders, missing SYN, inclusive deadline, expired unscored windows,
immutable decisions, duplicate headers and malformed PCAPNG blocks.
The first test run exposed two omitted untracked dependencies; copying those
exact helper files resolved both setup errors. No assertion was disabled.
Host Clang helper compilation produced the existing three XDP unroll warnings;
this is not BPF verifier evidence.

| Requested comparison | Forward-only control | Bidirectional model |
| --- | --- | --- |
| Architecture if trained | Bias-free 6→32→32→2 | Same |
| Frozen train/validation/test partition | NOT RUN | NOT RUN |
| Test predictions / all classification metrics | NOT RUN | NOT RUN |
| F1 / FPR improvement | Unmeasured | Unmeasured |
| Kernel egress-to-MLP evidence | No new test | NOT IMPLEMENTED |

There are no experimental confusion-matrix figures or invented zero errors.
[Machine-readable gate/metric status](research/bidirectional_mlp/evidence/status.json)
uses null metrics and explicit NOT RUN entries. The reproduction model's prior
99.67% F1 is not reused as a control on these CIC records.

## Exact commands and rerunning the audit

Worktree setup actually executed, before any research source changes:

```bash
git worktree add --no-checkout -b feature/bidirectional-mlp \
  /home/arnav/research/ebpf-ids-research/experiments/bidirectional_mlp_20261109/worktree HEAD
cd /home/arnav/research/ebpf-ids-research/experiments/bidirectional_mlp_20261109/worktree
git sparse-checkout set --no-cone '/*.md' '/.gitignore' '/Makefile' \
  '/tc/' '/src/' '/dataset/' '/quantization/' '/validation/' '/evaluation/' \
  '/deployment/' '/demo/' '/dashboard/'
git checkout --
```

The worktree already exists; do not rerun its creation. From it, the following
commands reproduce the checks using new output directories. All are ordinary
user, read-only source operations; **no sudo is needed**:

```bash
python3 -B -m unittest -v research.bidirectional_mlp.test_features \
  evaluation.cic.test_capture evaluation.cic.test_labels

SOURCE='/mnt/c/Study Materials/Semester 7/USAP/Term Project'
PRIOR=/home/arnav/research/ebpf-ids-research/verification-logs/cic-external-20261108
OUT="research/bidirectional_mlp/evidence/recheck-$(date +%Y%m%d-%H%M%S)"

python3 -B -m research.bidirectional_mlp.audit inventory \
  --labels "$SOURCE/GeneratedLabelledFlows.zip" \
  --binding "$PRIOR/source-binding.json" --output "$OUT/inventory"

python3 -B -m research.bidirectional_mlp.audit pilot \
  --capture "$SOURCE/Tuesday-WorkingHours.pcap" \
  --labels "$SOURCE/GeneratedLabelledFlows.zip" \
  --binding "$PRIOR/source-binding.json" \
  --cohort "$PRIOR/reconstructed/pilot.jsonl" --output "$OUT/pilot"

python3 -B -m research.bidirectional_mlp.audit groups \
  --eligible "$PRIOR/reconstructed/eligible.jsonl.gz" --output "$OUT/groups"
```

Original commands used `research/bidirectional_mlp/evidence/inventory`,
`.../pilot`, and `.../groups`. Outputs refuse overwrite. The pilot reads the
complete PCAP once for its checksum, then bounded referenced packet blocks;
the inventory streams about 1.2 GB of decompressed CSV data without writing
it to disk. The source archive/capture remain external and are not committed.
Python 3.10.12, Clang 12.0.1 and WSL2 kernel 6.6.87.2 are recorded in
[environment.json](research/bidirectional_mlp/evidence/environment.json).
No NumPy, PyTorch or pickle loading is used by the new audit.

## Changed files, commit boundaries and next work

**No tracked demo or inference source changed in either worktree.** New research
files are this report, `research/bidirectional_mlp/{__init__.py,POLICY.json,
DEPENDENCIES.json,features.py,audit.py,test_features.py,README.md}`, the evidence
directory, and the seven copied `evaluation/cic/` dependencies listed in the
manifest. Existing tracked files in the sparse worktree match the base commit.
No new deployment commit exists; both branches still reference the stated
baseline, with new work uncommitted only in the experimental worktree.

Suggested review boundaries, with explicit-path staging by the operator:

1. Source/data/trigger audit, frozen policy and necessary copied parser/test
   dependencies.
2. Offline reference, audit CLI, tests and small status/summary/hash evidence.

Keep raw traces, large preservation lists, PCAPs, CSV archives, generated
binaries and unrelated experiments out of commits. Review staged paths; do
not use `git add .`. Do not merge the experiment into the demonstration branch.
No push was attempted.

To resume training honestly, first obtain/reconstruct **packet-level labeled
windows covering the chosen trigger**, and enough disjoint attack campaigns
for the agreed split. Additional existing capture days with their bound labels
may help, but need separate validation/acquisition approval before large
downloads. Tuesday could be reprocessed with a justified complete-session label
policy; adjacent CIC FIN appendices must not simply inherit a convenient label.

Once that gate passes, freeze common source IDs and union groups for duplicate
forward or aggregate vectors and known correlated captures/campaigns. Train two
new bias-free 6→32→32→2 models with separate training-only scalers, identical
partitions/seeds/hyperparameters and validation-only checkpoint selection.
Evaluate the untouched common test IDs; retain all predictions/failures and
all requested confusion metrics. Only then add a separate feature-mode ABI,
Q16 export and kernel tests. The critical future kernel control holds ingress
events fixed, varies reverse response length/timing, and verifies the **recorded
MLP feature vector and logits**, not just egress counters. No improvement or
kernel egress contribution is claimed before that evidence exists.
