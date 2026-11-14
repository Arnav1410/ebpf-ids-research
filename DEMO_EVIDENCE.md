# Demonstration evidence: XDP → TC ingress

## Slide 1 — Attached programs and real packets

**Recorded environment:** `6.6.87.2-microsoft-standard-WSL2`, `x86_64`; clang `12.0.1-19ubuntu3`, Python `3.10.12`, bpftool `7.3.0`, libbpf `1.3`. [Environment][env] · [Tool versions][tools]

**Recorded commits:** [XDP build / host][basecommit] `18f855b1ea41500be31a4bd5e2507d17a75dee9b`; [TC][tcprep] `2073fe78ee332d258511acb592b4c5003b29d82e`. Kernel parity records [source hashes][hashes], without a commit field.

| Real attached experiment | Recorded attachment | Recorded observations |
|---|---|---|
| Original XDP | **339**, driver mode, `ids-server` | TCP greeting/FIN/response; label **1**; **5,216** model bytes matched; no retained packet counter. [Attachment][xstate] · [Run][xrun] |
| Minimal TC ingress | **392**, `tcids-server/tcids-s0`, direct-action | **7 packets / 452 bytes**. [Filter][minfilter] · [Counters][tcresult] |
| Full TC ingress | Entry **396**; TC tail-call slots **397, 398, 399, 400, 401, 402** | **6 packets / 410 bytes**, **6** source matches; stage counters **[1,1,1,1,1,1]**; **0** tail-call failures; **1** prediction. [Filter][tcfilter] · [Events][tcevents] |

**Live TC features:** `[40,165398,32,5001,136,4]` = max TCP-segment bytes, max forward IAT (kernel ns), min TCP-segment bytes, destination port, TCP-header byte sum, forward packet count. Features precede final packet counters. [Snapshot][tcsnapshot]

**Live kernel logits:** `[-129096,109857]` → **class 1**, matching reference. Traffic passed; XDP and current TC cleanup succeeded. [TC result][tcresult] · [Review][review] · [XDP run][xrun]

---

## Slide 2 — Numerical parity, with execution scopes separated

**Dense layer `linear0`:** isolated-kernel `packet_fixture`, input `[124,5000,20,5001,64,3]`—separate from the TC flow. Complete tensor in consecutive blocks: independent expected integers saved before execution beside kernel read-back integers. [Expected][fixtures] · [Observed][kevents]

| Independently expected integers | Kernel-observed integers |
|---|---|
| `-43988,-51349,34745,28397,65130,54939,87895,-61232` | `-43988,-51349,34745,28397,65130,54939,87895,-61232` |
| `-29954,-38511,31429,-45320,86427,-84626,-40524,31309` | `-29954,-38511,31429,-45320,86427,-84626,-40524,31309` |
| `-102367,-47047,-10066,20056,-9988,99622,44233,-22567` | `-102367,-47047,-10066,20056,-9988,99622,44233,-22567` |
| `-98332,-63716,-109477,-42021,1322,-12551,33580,-70247` | `-98332,-63716,-109477,-42021,1322,-12551,33580,-70247` |

| Execution scope | Recorded comparison totals and outcomes |
|---|---|
| **Host-compiled C vs Python; no kernel execution** | **18,840 rows; 113,040 stage-tensor comparisons**, PASS. **34 tests, 0 failures, 0 errors, 1 skip** (missing original floating-point checkpoint). [Results][host] |
| **Isolated kernel `BPF_PROG_TEST_RUN`; no attachment** | **59 invocations; 54 stage-tensor comparisons**, PASS. Stages run individually; tail-call chain **NOT TESTED**; class derived from read-back logits. [Results][kernel] |
| **Real attached TC ingress** | **6 stage-tensor comparisons / 136 integer values**, all matched; kernel label matched. Cleanup of this run's owned objects: PASS. [TC result][tcresult] · [Saved review][review] |

Totals have distinct scopes. **Accuracy and general-input correctness remain unverified**; arithmetic/parser/flow limits persist. Historical map **56** remains outside this TC run's owned objects. [Limitations][host] · [Review][review]

*Prepared solely from saved artifacts; no source changes or privileged test reruns.*

[env]: /home/arnav/research/ebpf-ids-research/verification-logs/numerical-20261026-230113-987235/results.json
[tools]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128/bpftool.log
[basecommit]: /home/arnav/research/ebpf-ids-research/verification-logs/baseline-20261026-221001-uyw17nvv/results.json
[tcprep]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128/results.json
[hashes]: /home/arnav/research/ebpf-ids-research/verification-logs/kernel-parity-20261026-235825-083044/source-hashes.json
[xstate]: /home/arnav/research/ebpf-ids-research/verification-logs/numerical-20261026-230113-987235/smoke-evidence/state.json
[xrun]: /home/arnav/research/ebpf-ids-research/verification-logs/numerical-20261026-230113-987235/smoke-evidence/run.log
[minfilter]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128/run-20261027-172125-858078/minimal-attachment.log
[tcfilter]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128/run-20261027-172125-858078/inference-attachment.log
[tcresult]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128/run-20261027-172125-858078/results.json
[tcevents]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128/run-20261027-172125-858078/inference/events.jsonl
[tcsnapshot]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128/run-20261027-172125-858078/inference/snapshot.json
[review]: /home/arnav/research/ebpf-ids-research/verification-logs/tc-final-20261027-172434/audit.json
[fixtures]: /home/arnav/research/ebpf-ids-research/verification-logs/kernel-parity-20261026-235825-083044/fixtures.json
[kevents]: /home/arnav/research/ebpf-ids-research/verification-logs/kernel-parity-20261026-235825-083044/kernel-20261027-000513-505560/events.jsonl
[host]: /home/arnav/research/ebpf-ids-research/verification-logs/numerical-20261026-230113-987235/results.json
[kernel]: /home/arnav/research/ebpf-ids-research/verification-logs/kernel-parity-20261026-235825-083044/kernel-20261027-000513-505560/results.json
