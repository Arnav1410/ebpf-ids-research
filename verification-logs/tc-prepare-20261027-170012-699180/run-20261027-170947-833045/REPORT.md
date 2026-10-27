# TC ingress prototype run

```json
{
  "minimal_ingress": "PASS",
  "full_inference": "NOT RUN",
  "cleanup": "PASS",
  "optional_egress": "NOT IMPLEMENTED",
  "minimal_snapshot": {
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
    "results": []
  },
  "error": "Controller cleanup failed",
  "protected_files": "UNCHANGED"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. Egress is NOT IMPLEMENTED in this iteration.
