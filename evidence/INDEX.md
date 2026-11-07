# IDS execution evidence

Execution plan: [UBUNTU_VM_IDS_AGENT_PLAN.md](../UBUNTU_VM_IDS_AGENT_PLAN.md).

Reference commit: `65c49c737b6791801cc98d9839b930b77ff42435` on preserved `baseline-reproduction`. Work branch: `test-env`. Initial mode: **DETECT ONLY**.

| Stage | Latest status | Evidence | Gate reason |
| --- | --- | --- | --- |
| 00 — Environment and repository audit | PASS — approved legacy-metadata exception | [Gate report](stage-00/gate.md), [inventory and modular boundaries](stage-00/inventory.md) | Inventory, privileged kernel capabilities and preservation checked; only known legacy attack-tool gitlink metadata is explicitly excepted |
| 01 — Reproduce and lock baseline | PASS | [Gate report](stage-01/gate.md), [provenance](stage-01/provenance.json) | Original sources rebuilt twice with identical products; 56 regressions, full native arithmetic and fresh kernel stage/packet checks passed; live attachment deferred |
| 02 — Isolated live original baseline | PASS — approved original-XDP lifecycle exception | [Gate report](stage-02/gate.md), [exception](stage-02/lifecycle-exception.json), [raw live result](stage-02/live-private/report.json) | Live checks passed; original map 76 retention remains recorded and assigned to teammate; new TC cleanup checks are not waived |
| 03 — Minimal TC ingress/egress probe | PASS | [Gate report](stage-03/gate.md), [live result](stage-03/live-corrected/report.json) | Both all-pass TC hooks verified; live counters and two complete lifecycles passed; five real ownership regressions passed; no new owned objects remain |
| 04 — Bidirectional flow tracking | PASS | [Gate report](stage-04/gate.md), [provenance](stage-04/provenance.json) | Exact independent header/statistics parity, simultaneous TCP flows, same-key generation-safe GC, inspector and all 17 regressions passed; new resources released |
| 05 — Original RX features and TC inference | PASS | [Gate report](stage-05/gate.md), [provenance](stage-05/provenance.json) | Exact six-stage integer parity; live repeated FIN/RST and concurrent flows; readiness/tail faults; all 40 regressions passed; new objects released |
| 06 — Kernel-to-user event pipeline | PASS | [Gate report](stage-06/gate.md), [provenance](stage-06/provenance.json) | Versioned native events match kernel/oracle/packet prefixes; actual ring and queue overflow are visible; restart and all 48 regressions passed; new objects released |
| 07 — Live dashboard and simulated replay | PASS | [Gate report](stage-07/gate.md), [provenance](stage-07/provenance.json), [browser proof](stage-07/live-browser-proof.json) | Actual Chromium live/map/result parity, reader and browser reconnect, explicit replay, responsive layout and UI-stopped kernel checks passed; new resources released |

Stages 00–07 are accepted, with only the explicitly recorded original-baseline exceptions. Stage 08 is blocked on separate physical-network approval and host/WSL/bridge configuration; later stages retain their gates. Stage 10 remains optional and requires separate approval after Stage 09. Original raw failure evidence is not rewritten by gate acceptance.

## Stage 00 evidence files

- [commands.json](stage-00/commands.json): diagnostic argv, timestamps, stdout, stderr and exit codes; branch-creation transcript.
- [environment.json](stage-00/environment.json): OS/kernel, guest DMI and selected kernel configuration, with inspection sources and host-configuration limits.
- [baseline-snapshot.json](stage-00/baseline-snapshot.json): baseline commit, initial user work, gitlinks and 20 source/configuration/tool/build-product fingerprints.
- [artifact-checks.json](stage-00/artifact-checks.json): fresh checksum/identity checks against retained historical model/kernel/native records; no numerical inference rerun.
- [preservation-checks.json](stage-00/preservation-checks.json): tracked-source/index, baseline/artifact/user-plan and before/after networking preservation.
- [Privileged feature-probe stdout](stage-00/privileged-feature-probe.stdout.log), [stderr](stage-00/privileged-feature-probe.stderr.log) and [exit code](stage-00/privileged-feature-probe.exit-code): successful current kernel capability probe, not a baseline detector attachment.
- [legacy-metadata-exception.json](stage-00/legacy-metadata-exception.json): explicit user approval, retained failure/reference details and limits; no unrelated check is waived.

Raw binaries, datasets, model copies, secrets and private traffic payloads are not added here. Existing large experiment artifacts remain under ignored `.output/` paths; their hashes are references, not archival copies. The metadata exception preserves the known failure rather than claiming to fix it; every later stage still requires its own evidence and gate decision.

## Source control and local raw artifacts

Stages 00–06 are saved as one validated checkpoint, not retroactively invented
per-stage commits. Following operator authorization, each subsequent PASS gate
is committed before advancing; incomplete stages are excluded.

Compact gate reports, provenance and command manifests are versioned. Bulky
raw runtime traces remain at their recorded local paths and are excluded by
`evidence/.gitignore`; they are not deleted. A fresh clone does not include those
local raw paths. [Stage 06 checkpoint metadata](stage-06/checkpoint.json) records
hashes of authoritative raw results, the regression log and the genuine live sample.

