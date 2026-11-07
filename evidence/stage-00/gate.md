# Stage 00 gate — PASS with approved legacy-metadata exception

```text
STAGE: 00 — Environment and repository audit
STATUS: PASS — explicit legacy-metadata exception
BASE COMMIT / DIFF: 65c49c737b6791801cc98d9839b930b77ff42435; new test-env branch; evidence/ additions only; pre-existing user plan preserved
CHANGES: Saved audit/capability/preservation evidence and modular integration constraints; recorded user-approved exception for legacy gitlink metadata; no detector, model, package or networking changes
COMMANDS EXECUTED: git switch -c test-env; recorded diagnostics including the successful authenticated vendored kernel feature probe in commands.json; input credentials excluded
BUILD: NOT APPLICABLE — audit only; fresh baseline build is Stage 01
VERIFIER LOAD: NOT TESTED for the baseline — minimal kernel capability probes succeeded; historical detector M4 evidence not rerun
ATTACH: NOT TESTED — no interface attachment attempted
RUNTIME PACKET TEST: NOT TESTED — no traffic generated
CORRECTNESS TEST: NOT TESTED — numerical/packet tests deferred; artifact integrity inspection performed
EXPECTED VS OBSERVED: 26 checksum and three model checks agree; privileged kernel feature probe exits 0 with XDP/SCHED_CLS/maps available; submodule exit 128 remains recorded under a specific user-approved exception
EVIDENCE: evidence/stage-00/ inventory, fingerprints, preservation records, privileged-feature-probe logs and legacy-metadata-exception.json
CLEANUP / ROLLBACK CHECK: PASS — no lab resources created; tracked files/index, user plan, artifact snapshots and network state preserved; baseline-reproduction still points to the base commit
GATE DECISION: PASS — only the legacy metadata diagnostic is explicitly excepted
NEXT ACTION: Stage 01 — reproduce and lock the unchanged baseline; all build, verifier, attachment, packet and correctness gates remain in force
```

## Completed capability probe and approved exception

### Privileged compatibility evidence — PASS

Initial `sudo -n` attempts required a password, and the vendored unprivileged fallback lacked libcap support. The subsequent operator-authorized authenticated probe succeeded with exit code 0 and empty stderr, without recording credentials or changing sudo policy.

The actual vendored command and its output are recorded in `commands.json`. Raw results:

- [Standard output](privileged-feature-probe.stdout.log): BPF syscall, `sched_cls` and `xdp` program types, and hash/array/program-array/ring/perf-event map types are available.
- [Standard error](privileged-feature-probe.stderr.log): empty.
- [Exit code](privileged-feature-probe.exit-code): zero.

This is current kernel capability evidence. Minimal feature-probe programs are not the IDS: successful baseline rebuilding, detector verifier loading, hook attachment and packet execution remain separate later checks. No package installation, permanent capability grant, interface attachment or BPF restriction change was made.

### Repository metadata diagnostic

`git submodule status` failed on the unmapped `dataset-instance/intrusion/DVMA/brute-force` gitlink. The index contains a second gitlink at `dataset-instance/intrusion/GoldenEye`. Neither has a root `.gitmodules` mapping; the inspected original local commit also lacks these mappings. Both are unrelated to the detector build, whose libbpf/bpftool trees are populated normal tracked files.

The user explicitly selected **Record a narrow exception**. [legacy-metadata-exception.json](legacy-metadata-exception.json) records the authorization, exact scope, preserved commit references and unchanged later gates. Only this known diagnostic is nonblocking for the IDS baseline Stage 00 gate. The raw failure remains recorded: repository-wide submodule integrity and working legacy attack scripts are not claimed. No references were deleted, URLs guessed or external tools downloaded/executed.

## Modular integration and rollback

[The inventory](inventory.md#modular-ebpf-integration-boundary--design-constraints-not-implementation) records the required separation between the unchanged reference, hook/resource lifecycle, feature/model contract, flow/inference state and future event consumers. There is no new adapter, TC program, collector or dashboard yet.

`baseline-snapshot.json` anchors the existing sources and ignored binary/model configuration artifacts. `preservation-checks.json` confirms the audit's non-mutation checks. Returning to the reference branch requires only `git switch baseline-reproduction`; untracked plan/evidence files remain present. Do not run a hard reset, broad network teardown or map deletion.

## Commit status

No commit or push was performed. The new files are Stage 00 evidence; the initial user plan remains untracked. A focused audit-evidence/plan commit can be made if authorized. Stage 01 remains unstarted; the exception does not waive any subsequent build, load, attachment or correctness check.
