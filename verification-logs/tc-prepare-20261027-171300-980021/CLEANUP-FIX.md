# TC cleanup diagnosis and retest

The actual preceding runtime evidence is in
`../tc-prepare-20261027-170012-699180/run-20261027-170947-833045/`.
It established minimal TC ingress verifier acceptance, attachment, a successful
TCP exchange, 7 observed packets / 452 bytes, private object release, namespace
deletion, and unchanged protected files. Full inference did not run.

Its minimal controller log reads:

```text
libbpf: Kernel error message: Cannot find specified filter chain
Filter absence not established: -22
```

The controller reached that check only after `bpf_tc_detach` returned success.
The exact post-detach query was incorrectly required to return only `-ENOENT`.
Here the kernel returned `-EINVAL` after the last filter chain disappeared.
This was a cleanup verification failure, not a verifier rejection.

The TC-only fix retains the exact program-ID ownership query before detach and
requires successful detach acknowledgement. The runner now establishes absence
with successful empty ingress and egress filter dumps, preserves both in
`filter-absence.json`, and only then removes clsact. Query errors alone are never
accepted as evidence of absence. Attachment verification now parses the exact
program ID, handle, priority and direct-action flag. Repeated controller-stop
calls retain failure rather than bypassing the failed status.

Executed without privilege:

```bash
./run-tc-smoke.sh --prepare
git diff --stat
git branch --show-current
```

Preparation compiled the changed controller without warnings and inspected both
TC objects. All nine tests passed: six existing host parser/arithmetic tests and
three cleanup/attachment evidence regression tests. See `commands.jsonl`,
`build.log`, `tests.log`, and `results.json`. Branch:
`feature/tc-ingress-prototype`; tracked baseline changes: none. Protected source,
model and validation hashes remained unchanged.

The already-approved isolated privileged rerun was attempted:

```bash
sudo -n /usr/bin/python3 /home/arnav/research/ebpf-ids-research/tc/demo.py --run /home/arnav/research/ebpf-ids-research/verification-logs/tc-prepare-20261027-171300-980021
```

Actual output (exit 1):

```text
sudo: a password is required
```

No runner started and no networking changed during this attempt. A new live run
is still required to establish that the cleanup transition works and to test
the full TC MLP. Run the new prepared bundle with interactive sudo:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-prepare-20261027-171300-980021
```

This uses the same approved isolated namespace/interface scope. The prior run
already removed its namespaces, so no additional cleanup was required. Optional
egress remains unimplemented. No commit or push was made.
