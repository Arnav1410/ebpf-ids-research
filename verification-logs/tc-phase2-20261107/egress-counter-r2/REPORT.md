# TC ingress prototype run

```json
{
  "preparation": "PASS",
  "runtime": "NOT RUN",
  "optional_egress": "NOT IMPLEMENTED",
  "branch": "feature/tc-egress-bidirectional",
  "commit": "d502d578fc551f5fe10fe4359ee168517cd8d15c",
  "kernel": "6.6.87.2-microsoft-standard-WSL2",
  "nonprivileged_tests": {
    "run": 27,
    "failures": 0,
    "errors": 0
  },
  "protected_files": "UNCHANGED",
  "approval_command": "sudo -n /usr/bin/python3 /home/arnav/research/ebpf-ids-research/tc/demo.py --run /home/arnav/research/ebpf-ids-research/verification-logs/tc-phase2-20261107/egress-counter-r2 --egress-counter",
  "phase2_stage": "EGRESS COUNTER ONLY; flow tracking not started",
  "egress_counter_gate": "PENDING: actual attached ingress/egress packet observation required"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. The separate egress counter stage does not implement bidirectional flow tracking.
