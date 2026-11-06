# TC ingress prototype run

```json
{
  "minimal_ingress": "PASS",
  "full_inference": "PASS",
  "cleanup": "PASS",
  "optional_egress": "NOT IMPLEMENTED",
  "kernel_checks": {
    "status": "PASS",
    "cases": [
      "all_missing_tail_slots_retry",
      "distinct_flows",
      "duplicate_result_immutable",
      "fixed_mean_above_below_full_chain",
      "flow_capacity_pass",
      "injected_reentrancy_guard",
      "malformed_pass_unscored",
      "missing_model_retry",
      "result_capacity_retry",
      "same_flow"
    ],
    "numerical": {
      "records": 23,
      "stage_tensors": 138,
      "integers": 3128
    },
    "same_flow": {
      "source_port": 41000,
      "packets": 1033,
      "bytes": 20660,
      "state": 2,
      "sequence": 1,
      "duplicates": 8,
      "failures": 0,
      "timestamp_reorders": 26
    },
    "scheduling": "CPU-pinned workers; exact overlap not forced",
    "reentrancy": "Injected busy guard tested; actual interrupt nesting not forced",
    "cleanup": "PASS"
  },
  "inference_numerical": {
    "records": 1,
    "stage_tensors": 6,
    "integers": 136
  },
  "reference_comparisons": 66,
  "concurrent_numerical": {
    "records": 10,
    "stage_tensors": 60,
    "integers": 1360
  },
  "concurrent_flows": "PASS",
  "protected_files": "UNCHANGED",
  "phase1_gate": "PASS",
  "packet_observations": {
    "minimal": {
      "packets": 7,
      "bytes": 452,
      "matched": 0,
      "predictions": 0,
      "stages": [
        0,
        0,
        0,
        0,
        0,
        0
      ],
      "tail_failures": 0
    },
    "inference": {
      "packets": 6,
      "bytes": 410,
      "matched": 6,
      "predictions": 1,
      "stages": [
        1,
        1,
        1,
        1,
        1,
        1
      ],
      "tail_failures": 0
    },
    "concurrent": {
      "packets": 60,
      "bytes": 4100,
      "matched": 60,
      "predictions": 10,
      "stages": [
        10,
        10,
        10,
        10,
        10,
        10
      ],
      "tail_failures": 0
    }
  },
  "tensor_evidence": "Full records in results.json and each phase/snapshot.json"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. Egress is NOT IMPLEMENTED in this iteration.
