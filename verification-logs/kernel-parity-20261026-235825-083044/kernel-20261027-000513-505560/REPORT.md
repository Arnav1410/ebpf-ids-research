# Minimal original-object kernel parity

Preparation: **PASS (previous bundle)**.
Kernel execution: **PASS**.



The kernel driver opens an independently compiled original `src/xdp.bpf.c` ELF,
disables all pin paths before load, and uses private maps. No interface is
attached and no network configuration is changed. All six tail-call slots stay
empty: each original arithmetic program is invoked with a separate
`BPF_PROG_TEST_RUN`, flags=0, repeat=1; map readback captures every stage.
This explicitly does not test the populated tail-call chain. It uses no
host-compiled function as evidence of kernel execution.

Fixed arithmetic: seven boundary-safe fixtures, including five checked against
saved host tensors. Packet checks: SYN, data with TCP options, FIN, fresh RST,
and ignored reverse-source traffic. Time-dependent IATs are recomputed from
actual recorded kernel `last_packet_time` values, not assumed deterministic
wall-clock intervals. FIN/RST detection timestamps are checked by inequalities.
Two closing packets also get explicit six-stage arithmetic comparisons.

`events.jsonl`, if present, contains actual loaded program/map IDs, mode and
return value for every syscall, feature/tensor readbacks, parameter-byte checks,
and cleanup ID checks. `verifier-*.log` contains per-program kernel logs after
an execution attempt. Empty/not-created logs do not establish verifier success.
The original final program emits its normal trace message; this test does not
consume shared tracing. Prediction is separately derived from kernel logits
and is not represented as a captured original trace prediction.

No kernel test is run by the default preparation command. Any comparator unit
tests use explicitly MOCK events. PASS for preparation means compilation,
fixture/reference and protocol checks passed; it does not mean kernel parity.

Full results: [results.json](results.json). Exact commands: [commands.txt](commands.txt).

```json
{
  "fixed_fixtures": [
    {
      "name": "stored_mean",
      "feature_values": "PASS",
      "stage_tensors": "PASS",
      "prediction_derived": 1
    },
    {
      "name": "one_scale_above",
      "feature_values": "PASS",
      "stage_tensors": "PASS",
      "prediction_derived": 0
    },
    {
      "name": "one_scale_below",
      "feature_values": "PASS",
      "stage_tensors": "PASS",
      "prediction_derived": 1
    },
    {
      "name": "small_tcp",
      "feature_values": "PASS",
      "stage_tensors": "PASS",
      "prediction_derived": 1
    },
    {
      "name": "packet_fixture",
      "feature_values": "PASS",
      "stage_tensors": "PASS",
      "prediction_derived": 1
    },
    {
      "name": "normalization_neighbors",
      "feature_values": "PASS",
      "stage_tensors": "PASS",
      "prediction_derived": 1
    },
    {
      "name": "bounded_large",
      "feature_values": "PASS",
      "stage_tensors": "PASS",
      "prediction_derived": 1
    }
  ],
  "packet_fixtures": [
    {
      "name": "syn",
      "features": [
        20,
        0,
        20,
        5001,
        20,
        1
      ],
      "sampled_kernel_timestamp": 8989022392403,
      "comparison": "PASS",
      "time_basis": "stored bpf_ktime_get_ns samples"
    },
    {
      "name": "data",
      "features": [
        124,
        3340,
        20,
        5001,
        44,
        2
      ],
      "sampled_kernel_timestamp": 8989022395743,
      "comparison": "PASS",
      "time_basis": "stored bpf_ktime_get_ns samples"
    },
    {
      "name": "fin",
      "features": [
        124,
        3340,
        20,
        5001,
        64,
        3
      ],
      "sampled_kernel_timestamp": 8989022398483,
      "comparison": "PASS",
      "time_basis": "stored bpf_ktime_get_ns samples"
    },
    {
      "name": "rst",
      "features": [
        23,
        0,
        23,
        5001,
        20,
        1
      ],
      "sampled_kernel_timestamp": 8989022419344,
      "comparison": "PASS",
      "time_basis": "stored bpf_ktime_get_ns samples"
    },
    {
      "name": "reverse_ignored",
      "ignored": "PASS"
    }
  ],
  "test_run_invocations": 59,
  "tensor_comparisons": 54,
  "original_trace_prediction": "NOT CAPTURED; classification derived separately from read-back logits",
  "tail_call_chain": "NOT TESTED; array intentionally empty and stages individually test-run",
  "cleanup": "PASS"
}
```

Remaining uncertainty: actual kernel parity until an approved execution passes;
after that, only these small fixtures are covered. Real hook delivery, populated
tail calls, cross-CPU/concurrent flow access, model-update races, arbitrary input
overflow, and original FP32 model parity remain outside scope.
