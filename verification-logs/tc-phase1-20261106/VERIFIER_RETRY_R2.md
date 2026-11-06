# Phase 1 verifier rejection: targeted retry

Actual failed run:
`ready/run-20261106-101748-963620/`. The original logs remain unchanged.

The verifier stopped in `tc_entry`, before model initialization, test-run calls,
TC attachment or namespace creation. The final diagnostic is:

```text
388: (db) lock *(u64 *)(r7 +104) += r1
R7 invalid mem access 'scalar'
processed 425 insns (limit 1000000) max_states_per_insn 1 total_states 32 peak_states 32 mark_read 17
```

Offset 104 is the global `workspace_busy` counter. The verifier reached that
instruction with R7 zero after the compiler lowered the compound optional-stats
conditions. The syscall's `Permission denied` / `-13` is the load rejection;
it does not call for changing sudo permissions or disabling verifier checks.

`tc_entry` now checks the statistics lookup once at entry and immediately returns
`TC_ACT_OK` on NULL. All continuation paths therefore have a non-null stats
pointer. With the existing fixed-size array/key zero, the ordinary packet path
is unchanged. The model arithmetic, lock critical sections, flow state machine
and six tail-call stages are unchanged by this repair.

Additional TC host-shim/test changes inject a missing stats value and verify
pass-through, no inference or leaked workspace owner, and successful inference
after restoring the value. Original XDP/model/training/validation files were
not edited.

Executed:

```bash
./run-tc-smoke.sh --prepare --phase1 --output verification-logs/tc-phase1-20261106/ready-r2
git diff --check
```

Results: BPF rebuild PASS, no warnings; object ABI inspection PASS; **20 host
tests PASS**, zero failures/errors. These tests do not establish kernel verifier
acceptance. See `ready-r2/build.log`, `ready-r2/inspect-tc_ids.log`,
`ready-r2/tests.log` and its prepared manifest.

An approved-scope retry was attempted from the agent:

```bash
sudo -n /usr/bin/python3 /home/arnav/research/ebpf-ids-research/tc/demo.py --run /home/arnav/research/ebpf-ids-research/verification-logs/tc-phase1-20261106/ready-r2 --phase1
```

Actual output, exit 1:

```text
sudo: a password is required
```

No runner or privileged operation started during that attempt. Run the revised
bundle interactively in the normal WSL2 terminal:

```bash
sudo ./run-tc-smoke.sh --run verification-logs/tc-phase1-20261106/ready-r2 --phase1
```

**Use `ready-r2`, not `ready`:** source/binary changes invalidate the old bundle.
No additional build, mount or networking setup command is required before this
retry. The gate remains pending until the revised code actually loads and all
kernel, packet, numerical, concurrency and cleanup assertions pass. Phase 2 is
untouched, and no phase-completion commit has been created.

The failed run created no test namespaces or attachments. Its cleanup PASS does
not establish numerical/concurrency success or provide a recorded owned-ID
absence check for partially loaded objects: no `loaded` event was emitted.
The controller closes the object on this error path; no manual global cleanup
or changes to BPF security settings have been made.
