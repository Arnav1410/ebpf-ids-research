# Approved isolated TC demo attempt

The exact approved sudo command exited 1 before the Python runner started:

```text
sudo: a password is required
```

Minimal ingress, full TC inference, verifier acceptance, live packet processing
and runtime reference comparisons remain NOT RUN. No namespaces, interfaces,
qdiscs, filters, BPF programs or maps were created; no cleanup was necessary.
Prepared prototype/binary and protected baseline hashes still match.

Use a local terminal for interactive sudo authentication; approval already exists:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-prepare-20261027-170012-699180
```

The runner prints the actual evidence directory. Review those results before
claiming runtime success. No source fix is indicated by this authentication failure.
