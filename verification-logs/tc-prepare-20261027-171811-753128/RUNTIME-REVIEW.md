# Actual TC execution and remaining cleanup issue

Evidence reviewed:
`../tc-prepare-20261027-171300-980021/run-20261027-171502-764429/`.
The original evidence and FAIL status have not been rewritten.

| Check | Actual result |
| --- | --- |
| Minimal TC ingress | PASS: 7 packets, 452 bytes |
| Full TC verifier/load | PASS: entry + 6 SCHED_CLS stages, individual verifier logs retained |
| Full TC attachment | PASS: direct-action ingress entry program 382 |
| Model loading | PASS: both 5,216-byte slots read back, slot 0 active |
| Tail-call population | PASS: slots 0–5 contain program IDs 383–388, type 3 |
| Live controlled TCP | PASS: 6 matched packets, 410 bytes; greeting/FIN and response logged |
| Tail-call execution | PASS: stage counters [1,1,1,1,1,1], failures 0 |
| Prediction | PASS: 1 completed record, stage mask 63, source port 40002 |
| Tensor parity | PASS: all 6 tensors / 136 scalar values and actual kernel label match reference |
| Filter/qdisc cleanup | PASS: empty ingress/egress dumps, clsact deletion success in both phases |
| Namespace cleanup | PASS: both namespaces deleted, no live PIDs recorded |
| Private program release | PASS: all recorded owned program IDs absent in final scan |
| Private map release | FAIL: map ID 56 (`progs`) remained in last saved scan |
| Protected baseline files | UNCHANGED |
| Optional egress | NOT IMPLEMENTED |

The completed inference record has features `[40,55783,32,5001,136,4]`, logits
`[-129096,109857]` and label `1`. These were independently recomputed from the
saved record during this review; every intermediate tensor matched, with no
arithmetic events reported by the established reference. Results are in
`saved-run-review.json`, including the hash of the original results file.
The real timestamp-derived feature is compared as captured, not replaced with
a host clock. This is evidence for one controlled live flow, not an accuracy,
performance, bidirectional IDS, or arbitrary-input correctness claim.

## Cleanup observation fix

The runner previously used repeated `bpftool -j map show`. That command opens
and closes map FDs, affecting the objects it is trying to observe. In this WSL
kernel, the program-array last-user release increments the map reference and
schedules deferred clear work. Reopening it for inspection can cause additional
last-user release operations. Relevant primary sources:

- [WSL 6.6.87.2 program-array deferred release](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/kernel/bpf/arraymap.c#L1011)
- [Map last-user release and FD lookup](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/kernel/bpf/syscall.c#L676)

This supports observer interference as a plausible cause. The saved evidence
does not establish the precise reference history or whether map 56 has since
disappeared. It must not be labelled successfully released without a later
check. No attempt has been made to mutate, unpin or forcibly delete it.

The TC controller now provides `--list-ids prog|map`, which walks the registry
using GET_NEXT_ID only. The runner uses that instead of opening object FDs,
still requires every owned ID to disappear, reports exact remaining IDs, and
saves `ids-absent.json` only on success. The bounded wait is 50 attempts, 100 ms
apart, plus command time. Errors and malformed output fail the check.

Changed TC-only files: `controller.c`, `id_scan.h` (new), `demo.py`, `Makefile`,
`tests/native.c`, `tests/test_tc.py`, `README.md`. Original BPF inference source
and model parameters were not changed. No new networking scope was added.

Executed nonprivileged preparation:

```bash
./run-tc-smoke.sh --prepare
```

Compilation PASS, no compiler warnings; 11 tests PASS. Two additional tests
exercise the exact C registry walker with a synthetic callback: sparse IDs,
empty registry, permission and mid-scan errors, and non-increasing IDs. These
are host tests, not evidence of kernel release. Exact preparation commands and
outputs are in `commands.jsonl`, `build.log` and `tests.log`.

Attempted under the existing isolated-demo approval:

```bash
sudo -n /usr/bin/python3 /home/arnav/research/ebpf-ids-research/tc/demo.py --run /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171811-753128
```

Exit 1; actual output:

```text
sudo: a password is required
```

No runner started; no privileged resources were changed during this attempt.
The revised ID-only cleanup check therefore remains NOT RUN in the kernel.

## Next run

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-prepare-20261027-171811-753128
```

This repeats the approved isolated demo and targeted automatic cleanup. Its
ID-only command logs will also show whether the previously observed map 56
remains; only IDs owned by the new run determine that run's cleanup status.
For an explicit read-only check of the old map, use:

```bash
sudo tc/.output/controller --list-ids map
```

An absent 56 establishes that the old map is no longer in the registry. A
remaining 56 needs further diagnosis; do not delete unrelated maps or rewrite
the old cleanup result. No commit or push was made.
