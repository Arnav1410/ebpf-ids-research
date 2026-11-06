# TC ingress prototype run

```json
{
  "minimal_ingress": "PASS",
  "full_inference": "PASS",
  "cleanup": "PASS",
  "optional_egress": "PASS: shared bidirectional monitoring; ingress-leg classification",
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
      "timestamp_reorders": 37,
      "key": {
        "a_ip": "33.33.33.1",
        "a_port": 5001,
        "b_ip": "33.33.33.73",
        "b_port": 41000,
        "protocol": 6
      },
      "input_initialized": true,
      "mlp_input_direction": 1,
      "hooks": {
        "ingress": {
          "packets": 1033,
          "bytes": 55782,
          "first_ns": 33604475946105,
          "last_ns": 33604569758275,
          "timestamp_reorders": 37,
          "tcp_flags": 5
        },
        "egress": {
          "packets": 0,
          "bytes": 0,
          "first_ns": 0,
          "last_ns": 0,
          "timestamp_reorders": 0,
          "tcp_flags": 0
        }
      },
      "endpoint_packets": [
        0,
        1033
      ],
      "endpoint_bytes": [
        0,
        55782
      ]
    },
    "scheduling": "CPU-pinned workers; exact overlap not forced",
    "reentrancy": "Injected busy guard tested; actual interrupt nesting not forced",
    "cleanup": "PASS"
  },
  "bidirectional_kernel_checks": {
    "status": "PASS",
    "cases": [
      "bidirectional_distinct_flows",
      "bidirectional_same_flow",
      "egress_first_and_duplicate_result_immutable",
      "egress_flow_capacity_pass",
      "fixed_mean_above_below_full_chain",
      "malformed_egress_pass_unscored"
    ],
    "numerical": {
      "records": 15,
      "stage_tensors": 90,
      "integers": 2040
    },
    "same_flow": {
      "source_port": 47000,
      "packets": 514,
      "bytes": 10280,
      "state": 2,
      "sequence": 1,
      "duplicates": 1,
      "failures": 0,
      "timestamp_reorders": 7,
      "key": {
        "a_ip": "33.33.33.1",
        "a_port": 5001,
        "b_ip": "33.33.33.73",
        "b_port": 47000,
        "protocol": 6
      },
      "input_initialized": true,
      "mlp_input_direction": 1,
      "hooks": {
        "ingress": {
          "packets": 514,
          "bytes": 27756,
          "first_ns": 33604853765639,
          "last_ns": 33604854146086,
          "timestamp_reorders": 7,
          "tcp_flags": 1
        },
        "egress": {
          "packets": 514,
          "bytes": 27756,
          "first_ns": 33604853769077,
          "last_ns": 33604854200682,
          "timestamp_reorders": 0,
          "tcp_flags": 4
        }
      },
      "endpoint_packets": [
        514,
        514
      ],
      "endpoint_bytes": [
        27756,
        27756
      ]
    },
    "scheduling": "CPU-pinned workers on both programs; exact overlap not forced",
    "cleanup": "PASS"
  },
  "inference_numerical": {
    "records": 1,
    "stage_tensors": 6,
    "integers": 136
  },
  "reference_comparisons": 138,
  "concurrent_numerical": {
    "records": 10,
    "stage_tensors": 60,
    "integers": 1360
  },
  "concurrent_flows": "PASS",
  "bidirectional_packets": {
    "status": "PASS",
    "flows": 1,
    "non_timing_features_checked": 5
  },
  "bidirectional_numerical": {
    "records": 1,
    "stage_tensors": 6,
    "integers": 136
  },
  "bidirectional": "PASS",
  "bidirectional-concurrent_packets": {
    "status": "PASS",
    "flows": 10,
    "non_timing_features_checked": 50
  },
  "bidirectional-concurrent_numerical": {
    "records": 10,
    "stage_tensors": 60,
    "integers": 1360
  },
  "bidirectional-concurrent": "PASS",
  "bidirectional-burst_packets": {
    "status": "PASS",
    "flows": 1,
    "non_timing_features_checked": 5
  },
  "bidirectional-burst_numerical": {
    "records": 1,
    "stage_tensors": 6,
    "integers": 136
  },
  "bidirectional-burst": "PASS",
  "protected_files": "UNCHANGED",
  "phase2_gate": "PASS",
  "packet_observations": {
    "minimal": {
      "packets": 7,
      "bytes": 452,
      "egress_packets": 0,
      "egress_bytes": 0,
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
      "egress_packets": 0,
      "egress_bytes": 0,
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
      "egress_packets": 0,
      "egress_bytes": 0,
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
    },
    "bidirectional": {
      "packets": 8,
      "bytes": 570,
      "egress_packets": 7,
      "egress_bytes": 533,
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
    "bidirectional-concurrent": {
      "packets": 61,
      "bytes": 4190,
      "egress_packets": 40,
      "egress_bytes": 2830,
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
    },
    "bidirectional-burst": {
      "packets": 31,
      "bytes": 2822,
      "egress_packets": 20,
      "egress_bytes": 1339,
      "matched": 31,
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
    }
  },
  "tensor_evidence": "Full records in results.json and each phase/snapshot.json"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. Egress monitoring statistics are separate from ingress-leg MLP features.
