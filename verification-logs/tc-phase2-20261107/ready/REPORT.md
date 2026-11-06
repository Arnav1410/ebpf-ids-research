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
    "run": 37,
    "failures": 0,
    "errors": 0
  },
  "protected_files": "UNCHANGED",
  "approval_command": "sudo -n /usr/bin/python3 /home/arnav/research/ebpf-ids-research/tc/demo.py --run /home/arnav/research/ebpf-ids-research/verification-logs/tc-phase2-20261107/ready --phase2",
  "phase2_gate": "PENDING: attached bidirectional traffic and all regressions required"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. Egress monitoring statistics are separate from ingress-leg MLP features.
