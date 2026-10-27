# Numerical validation run

Status: **PASS**. Tests: 33; failures: 0;
errors: 0; skips: 1.

This status means host comparisons/characterization assertions passed. Known
defects are deliberately characterized, not repaired. Kernel execution, JIT,
real map concurrency and real tail-call behavior were NOT tested in this run.

Command: `/usr/bin/python3 /home/arnav/research/ebpf-ids-research/validation/run.py --smoke-log /tmp/nn-ebpf-baseline.dhp5S5`

Baseline source/data SHA256 integrity: **PASS**.
Complete per-test statuses and numerical evidence: [results.json](results.json).
Full output: [test-output.log](test-output.log).
Exact compile/environment commands: [commands.txt](commands.txt).
Compiler diagnostics: [build-native.log](build-native.log), [build-ubsan.log](build-ubsan.log).
Original files and framework SHA256: [source-hashes.json](source-hashes.json).

## Dataset layer comparison

```json
{
  "rows": 18840,
  "stage_comparisons": 113040,
  "arithmetic_events": {},
  "stage_min_max": {
    "normalized": [
      -80212,
      2226723
    ],
    "linear0": [
      -1156330,
      1219071
    ],
    "relu0": [
      0,
      1219071
    ],
    "linear1": [
      -1928884,
      1514626
    ],
    "relu1": [
      0,
      1514626
    ],
    "logits": [
      -2886753,
      2700748
    ]
  },
  "equal_logits": 0,
  "classification_accuracy": "NOT EVALUATED; labels are not used"
}
```

## Observed discrepancies and boundary behavior

```json
{
  "uint64_normalization_wrap": {
    "input": 281474976710656,
    "mean": 0,
    "scale": 1099511627776,
    "source_output": 0,
    "unbounded_formula": 16777216
  },
  "normalization_sign_change": {
    "input": 32769,
    "mean": 0,
    "scale": 1,
    "exact_scaled_value": 2147549184,
    "source_output": -2147418112
  },
  "linear_narrowing": {
    "output": -2147450882,
    "events": [
      {
        "kind": "linear_int32_narrow",
        "layer": "linear",
        "row": 0,
        "shifted": 2147516414
      }
    ]
  },
  "ubsan": {
    "accumulator-overflow": {
      "exit_code": 1,
      "diagnostic": "/home/arnav/research/ebpf-ids-research/validation/../src/mlp.bpf.h:21:17: runtime error: signed integer overflow: 4611686018427387904 + 4611686018427387904 cannot be represented in type 'long'\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /home/arnav/research/ebpf-ids-research/validation/../src/mlp.bpf.h:21:17 in"
    },
    "negation-overflow": {
      "exit_code": 1,
      "diagnostic": "/home/arnav/research/ebpf-ids-research/validation/../src/mlp.bpf.h:40:20: runtime error: negation of -2147483648 cannot be represented in type 'int32_t' (aka 'int'); cast to an unsigned type to negate this value to itself\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /home/arnav/research/ebpf-ids-research/validation/../src/mlp.bpf.h:40:20 in"
    },
    "zero-divisor": {
      "exit_code": 1,
      "diagnostic": "/home/arnav/research/ebpf-ids-research/validation/../src/mlp.bpf.h:42:79: runtime error: division by zero\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /home/arnav/research/ebpf-ids-research/validation/../src/mlp.bpf.h:42:79 in"
    },
    "flow-counter-overflow": {
      "exit_code": 1,
      "diagnostic": "/home/arnav/research/ebpf-ids-research/validation/../src/handler.bpf.h:41:26: runtime error: signed integer overflow: 9223372036854775807 + 1 cannot be represented in type 'long'\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /home/arnav/research/ebpf-ids-research/validation/../src/handler.bpf.h:41:26 in"
    }
  },
  "equal_logit_discrepancy": {
    "raw": [
      572,
      11161066668,
      36,
      496,
      12145,
      379
    ],
    "logits": [
      0,
      0
    ],
    "source_label": 1,
    "paper_equation_5_label": 0
  },
  "original_float": {
    "status": "NOT VERIFIED",
    "candidates": [],
    "reason": "No original floating-point checkpoint available"
  },
  "flow_lifecycle": "Repeated FIN re-infers; new SYN on same tuple retains old counters and IAT",
  "ipv4_options_parser": {
    "actual": [
      20,
      0,
      20,
      257,
      0,
      1
    ],
    "correctly_offset_features": [
      20,
      0,
      20,
      5001,
      20,
      1
    ],
    "actual_inferences": 0,
    "expected_fin_inferences": 1
  },
  "malformed_ip_length": {
    "actual": [
      -10,
      0,
      4611686018427387903,
      5001,
      20,
      1
    ],
    "reason": "tot_len - IHL is negative, converted to u64 then narrowed to signed feature; minimum sentinel persists"
  }
}
```

Fixed-vector per-stage integer tensors and clearly labeled dequantized-header
floating diagnostics are in `results.json` under `evidence.fixtures`. They do not
substitute for comparison with an original FP32 checkpoint. No label-based
classification accuracy was calculated.

Next: with approval, run deterministic BPF_PROG_TEST_RUN inputs in an isolated
environment and compare captured kernel feature/per-layer values to these host
fixtures. Where clocks cannot be controlled, validate arithmetic stages with
explicit injected feature values using a separate validation-only BPF harness.
Do not change the existing detector to obtain those observations without approval.
