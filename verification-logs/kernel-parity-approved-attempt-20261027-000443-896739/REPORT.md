# Approved kernel-only parity attempt

The approved command exited 1 before the Python runner started:

```text
sudo: a password is required
```

No BPF program/map was loaded, no verifier/test-run was reached, and no interface,
pin, route or networking configuration was changed. Kernel fixture comparisons
remain NOT RUN. No runtime cleanup was needed. This is an authentication blocker,
not a verifier rejection or numerical mismatch.

The prepared bundle's artifact and source hashes were checked again and match.
Tracked production files remain unchanged.

Exact invocation: [command.txt](command.txt).
Actual captured stderr: [command-output.log](command-output.log).
Structured result: [results.json](results.json).

To continue, run the already-approved test in a local terminal with interactive
sudo authentication (omit `-n`):

```bash
sudo /usr/bin/python3 /home/arnav/research/ebpf-ids-research/validation/kernel_parity/run.py --execute /home/arnav/research/ebpf-ids-research/verification-logs/kernel-parity-20261026-235825-083044
```

The runner prints the fresh `kernel-TIMESTAMP` evidence directory. Its actual
verifier/test-run logs and per-layer comparisons are needed to finish validation.
Do not share the sudo password in chat.
