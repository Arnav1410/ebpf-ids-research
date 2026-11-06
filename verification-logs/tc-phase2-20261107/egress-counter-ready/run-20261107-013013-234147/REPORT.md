# TC ingress prototype run

```json
{
  "minimal_ingress": "NOT RUN",
  "full_inference": "NOT RUN",
  "cleanup": "FAIL",
  "optional_egress": "NOT IMPLEMENTED",
  "phase2_stage": "EGRESS COUNTER ONLY; canonical keys and directional flow state not implemented",
  "error": "controller exited before ready; see /home/arnav/research/ebpf-ids-research/verification-logs/tc-phase2-20261107/egress-counter-ready/run-20261107-013013-234147/egress-counter/controller.log",
  "cleanup_errors": [
    "Controller cleanup failed"
  ],
  "protected_files": "UNCHANGED",
  "egress_counter_gate": "FAIL"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. The separate egress counter stage does not implement bidirectional flow tracking.
