# TC ingress prototype run

```json
{
  "minimal_ingress": "PASS",
  "full_inference": "NOT RUN",
  "cleanup": "PASS",
  "optional_egress": "COUNTER ONLY; no bidirectional IDS claim",
  "phase2_stage": "EGRESS COUNTER ONLY; canonical keys and directional flow state not implemented",
  "egress_counter": "PASS",
  "counter_deltas": {
    "packets": 7,
    "bytes": 452,
    "egress_packets": 5,
    "egress_bytes": 325
  },
  "egress-counter_snapshot": {
    "event": "snapshot",
    "packets": 7,
    "bytes": 452,
    "matched": 0,
    "rejected": 0,
    "predictions": 0,
    "tail_failures": 0,
    "stages": [
      0,
      0,
      0,
      0,
      0,
      0
    ],
    "flow_full": 0,
    "workspace_busy": 0,
    "duplicate_triggers": 0,
    "inference_failures": 0,
    "timestamp_reorders": 0,
    "result_failures": 0,
    "egress_packets": 5,
    "egress_bytes": 325,
    "results": [],
    "flows": []
  },
  "protected_files": "UNCHANGED",
  "egress_counter_gate": "PASS"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. The separate egress counter stage does not implement bidirectional flow tracking.
