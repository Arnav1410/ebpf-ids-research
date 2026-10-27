# TC ingress prototype run

```json
{
  "preparation": "PASS",
  "runtime": "NOT RUN",
  "optional_egress": "NOT IMPLEMENTED",
  "branch": "feature/tc-ingress-prototype",
  "commit": "2073fe78ee332d258511acb592b4c5003b29d82e",
  "kernel": "6.6.87.2-microsoft-standard-WSL2",
  "nonprivileged_tests": {
    "run": 6,
    "failures": 0,
    "errors": 0
  },
  "protected_files": "UNCHANGED",
  "approval_command": "sudo -n /usr/bin/python3 /home/arnav/research/ebpf-ids-research/tc/demo.py --run /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-170012-699180"
}
```

PASS in preparation means compilation and host tests only. Runtime evidence requires --run.
TCP exchange, TC filter queries, per-stage counters and kernel snapshots establish the live demo.
Reported snapshot parity uses the same captured features as the fixed-point reference; it is not an accuracy evaluation.
Original XDP/validation/model files are unchanged. Egress is NOT IMPLEMENTED in this iteration.
