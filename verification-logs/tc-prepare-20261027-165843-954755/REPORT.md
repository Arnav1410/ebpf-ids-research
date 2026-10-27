# TC ingress prototype run

```json
{
  "preparation": "FAIL",
  "runtime": "NOT RUN",
  "optional_egress": "NOT IMPLEMENTED",
  "branch": "feature/tc-ingress-prototype",
  "commit": "2073fe78ee332d258511acb592b4c5003b29d82e",
  "kernel": "6.6.87.2-microsoft-standard-WSL2",
  "error": "build-host-tests failed (1); see build-host-tests.log"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. Egress is NOT IMPLEMENTED in this iteration.
