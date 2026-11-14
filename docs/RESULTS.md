# Results and interpretation

These tables are traced to selected saved artifacts. This submission audit does not recreate privileged historical measurements by reading their summaries. Current checks and command outcomes are in [submission validation](SUBMISSION_VALIDATION.md).

## Fresh reproduction model — held-out host classification

[Recorded metrics](evidence/fresh-heldout.json), [checkpoint and split artifacts](../experiments/fresh_model_20261108/run/), [full historical report](../FRESH_MODEL_EVALUATION.md).

Training/validation/testing: 13,187 / 2,827 / 2,826 exact-feature-group-separated rows from the authors' 18,840-row arrays. Train-only scaler/calibration; validation-only checkpoint choice. All four FP32/XDP-Q16/TC-Q16/TC-layer-specific configurations classified the held-out rows identically.

| TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,984 | 9 | 829 | 4 | 99.5400% | 99.5484% | 99.7988% | 99.6734% |

Confusion order `[[829,9],[4,1984]]`. Supplied labels: 0 benign, 1 intrusion. Unknown capture/session provenance prevents claims of new-campaign independence. These are not live-network metrics.

## Original-model arithmetic fidelity

[Recorded three-way summary](evidence/original-model-offline.json), [arithmetic report](../THREE_WAY_COMPARISON.md).

13,844 identical vectors held out from offline scale calibration; old checkpoint training membership unknown. Mean absolute final-logit error against exact rational inference of the **rounded Q16 header**:

| Static Q16 | Layer-specific | Ratio |
| ---: | ---: | ---: |
| 0.0001775953468331884 | 0.000000991370080459385 | 179.14× lower mean error |

No Q16 XDP/TC integer-tensor differences and no layer-specific prediction changes. This reference is not the authors' missing original FP32 checkpoint. Lower numerical error alone does not establish higher F1. The original supplied-label diagnostic F1 0.961386 has unknown training overlap; it remains separate from fresh held-out testing and CIC evaluation.

## Paired actual kernel inference-stage timing

[Saved full-session result](evidence/fresh-kernel-latency.json), [detailed methodology](../FINAL_XDP_TC_KERNEL_LATENCY.md).

| µs | Original XDP Q16 | TC Q16 | TC layer-specific |
| --- | ---: | ---: | ---: |
| Mean | 5.141144 | 3.635677 | 12.846346 |
| Median | 4.426000 | 2.945000 | 11.694000 |
| p95 | 7.415550 | 5.318100 | 17.272100 |
| p99 | 16.871850 | 13.204550 | 32.201840 |
| Measured executions | 14,130 | 14,130 | 14,130 |

Same fresh checkpoint, same 2,826 held-out vectors, five rotating-order trials and one full warmup per mode on CPU 0. 50,877 complete-chain calls including repeats; zero reported numerical mismatches/inference failures; owned-ID cleanup PASS. WSL2 6.6.87.2, x86-64 Intel i7-1255U, clang-12. All outliers retained.

The timed region is the kernel-returned test-run duration around preprocessing through synchronous tail-chain return. Untimed seed/reset/readback/syscall wall time is excluded. XDP keeps original trace calls and repeated tuple parsing; TC keeps guards, counters and result publication; program-type wrappers differ. **Do not call the difference a pure TC-vs-XDP hook speedup, pure arithmetic benchmark, network RTT or NIC throughput.** The older unpaired TC 2.262/7.128 µs session is not substituted into this table.

## Live monitoring and demonstration

[Historical isolated summary](evidence/fresh-live-isolated.json), [network verification](evidence/fresh-live-network-verified.json). Five runs cover fresh/static and fresh/layer-specific on ports 80/9000, plus original/static/9000 rollback: 55 connections, actual ordinary-user listeners/dashboard, both TC hooks, complete tensors and cleanup.

The isolated benign-intent cases still produced false positives. For example the fresh/static port-80 one-plus-ten cohort recorded 3 class-1 predictions among 11 benign-intent flows; the port-9000 cohort recorded 5/11. These are small artificial-scenario observations, not general deployment FPR estimates. The classifier frequently predicts class 1 on synthetic benign-intent traffic because its actual features/distribution differ from stored data; no unsupported causal attribution to TC is made.

The students report a successful physical presentation. Locally retained machine-readable evidence does not establish a new physical run of this candidate, Windows Python 3.13 validation or current Ubuntu VM compatibility. Those remain **NOT RUN for this submission audit**. No physical attachment occurred during the audit.

## Offline CIC research, deliberately separate

[Forward/bidirectional comparison](../CIC_FORWARD_VS_BIDIRECTIONAL_MLP.md), [validation-only threshold sensitivity](../CIC_VALIDATION_THRESHOLD_SENSITIVITY.md), [CSV summary](../research/cic_csv_mlp/RESULTS.json), [threshold summary](../research/cic_threshold_sensitivity/RESULTS.json).

244,610 eligible Tuesday TCP rows: 172,715 train / 35,947 validation / 35,948 test. Grouping prevents exact A/B vectors and canonical tuples crossing partitions but is not campaign independent. Original argmax F1: forward 97.0409%, bidirectional 65.0320%. Validation-selected thresholds recover bidirectional recall, raising F1 to 96.6919%, while forward becomes 97.2380%; bidirectional has 34 FP versus forward 3. Post-hoc reuse, port shortcuts and single-day/campaign correlations limit inference. No threshold or CIC-trained model is deployed.

PCAP feature/label matching has separate coverage/ambiguity limitations; no claim of 30,000 faithfully matched attack/benign packet flows is made. CIC payload lengths, microsecond IAT, direction and full-flow timing differ from kernel segment lengths, ns IAT and ingress FIN/RST snapshots.

## Published reference, not our measurement

| Authors' Table V NN-int32 Q+Top6 experiment | Accuracy | F1 |
| --- | ---: | ---: |
| CIC-IDS-2017 offline | 0.974 | 0.933 |
| eBPF-Reproduction real-time | 0.994 | 0.992 |

Source: [DSN 2024 paper](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf). Different checkpoints, cohorts, features and environments prevent equal-protocol performance rankings.

## Practical limitations

Monitoring-only TC; ingress-derived MLP even with egress counters; finite non-evicting flow/result maps; tuple reuse/lifetime and collection-capacity limits; timestamp ordering/offload effects; restricted IPv4/TCP parser coverage; original XDP concurrency/parser/arithmetic issues characterized by tests; original floating checkpoint and original training membership unavailable; no independently labeled live attack campaign evaluation. Actual verifier/concurrency coverage is evidence-bounded, not a guarantee for every kernel or schedule.
