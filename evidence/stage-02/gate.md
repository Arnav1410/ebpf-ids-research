# Stage 02 — PASS with approved original-XDP lifecycle exception

```text
STAGE: 02 — Isolated single-VM networking and live original baseline
STATUS: PASS — explicitly approved original-XDP lifecycle exception
BASE COMMIT / DIFF: 65c49c737b6791801cc98d9839b930b77ff42435; test-env; new test_env/ validation modules/tests and evidence; original detector/model unchanged
CHANGES: Implemented owned namespace/veth lifecycle, bounded command evidence, controlled TCP fixtures, and a detector-specific original-XDP adapter; fixed setup/namespace invocation issues without changing the IDS
COMMANDS EXECUTED: Recorded invocations and live-private/commands.json; opt-in real namespace regression suite; scoped retained-map/FD/pin/program/link diagnostics
BUILD: PASS — original detector artifacts from accepted Stage 01; no TC program built
VERIFIER LOAD: PASS — original XDP skeleton loaded in the owned server network namespace
ATTACH: PASS — driver-mode XDP on veth-idss inside ids_server; all six tail-call slots and shared map IDs verified
RUNTIME PACKET TEST: PASS — 3/3 ping each direction, controlled TCP request/response, RST-triggered original inference, metadata-only capture
CORRECTNESS TEST: PASS for exercised flow — five independently captured non-timing features, bounded kernel timing, all 5216 active model bytes, and exact kernel/oracle logits; three real namespace safety regressions passed
EXPECTED VS OBSERVED: Live features [56,199660,32,5001,168,5]; observed and expected logits [-129530,110395]; all owned program IDs gone but owned empty prog_array map 76 remains
EVIDENCE: evidence/stage-02/ including live-private/, safety/, invocation and retained-map diagnostics
CLEANUP / ROLLBACK CHECK: FAIL for full owned BPF object release; PASS for namespaces/veths/global pins/XDP attachment/host configuration and spawned child cleanup
GATE DECISION: PASS with user-approved exception for the original retained map; raw cleanup failure remains unresolved
NEXT ACTION: Stage 03 — minimal detect-only TC probe; its own load, attachment, execution and cleanup gates are unchanged
```

## Explicitly approved continuation

The user requested progression while assigning resolution of the original
eBPF lifecycle problem to their teammate. [lifecycle-exception.json](lifecycle-exception.json)
records that decision. It is a scoped acceptance exception, not a verified fix.
Original live-run and cleanup reports, provenance, and the strict original
adapter remain unchanged. The exception does not apply to the new TC backend or
waive any later validation or real-interface approval gate.

## Actual successes

The final [live report](live-private/report.json) deliberately reports `fail`, even though traffic and inference succeeded. Its independently saved component evidence establishes:

- [Readiness](live-private/baseline-ready.json): original entry attached in driver mode, expected map ABIs, loader-owned map/program IDs, six verified stages and shared parameter pins.
- [Model initialization](live-private/baseline-model.json): original inactive slot initialized, index switched, every parameter byte compared to `src/mlp_params.bpf.h`. The independently trained M3 model was not substituted.
- [Packet/NN observation](live-private/baseline-live.json): five client packets observed with a final RST, zero capture drops, five exact non-timing feature comparisons, timing bounds and nonzero final logits matching the integer reference. The sixth feature's exact nanosecond value is read from the kernel and bounded, not claimed to match a userspace wire timestamp.
- [Capture](live-private/baseline-capture.json): header metadata only, no arbitrary packet payload. The fixture sends a fixed harmless 24-byte request and 25-byte response.
- [Lab state](live-private/lab-state.json): all owned namespaces/interfaces removed and host configuration restored. The top-level report also confirms unchanged root-namespace configuration.

A label derived from logits is explicitly not represented as a directly observed `bpf_printk` record. No competing `trace_pipe` reader was started. Numeric label meanings remain unverified; this is not proof of benign/attack classification accuracy.

## Remaining failed check

[baseline-cleanup.json](live-private/baseline-cleanup.json) records the exact failed condition: original loader-owned map ID `76`, name `progs`, type `prog_array`, still exists after loader exit and the bounded cleanup wait. All seven owned program IDs disappeared, global model pins were absent, and XDP was detached.

Follow-up inspection confirms:

- [Map metadata and pins](map76-pins.json): the map remains, has no pins, and uses 8,576 bytes of reported memlock.
- [Map contents](retained-prog-array-76.json): empty.
- [Userspace FD search](retained-map-fd-holders.json): no process FD with this map ID found at inspection time; no command lines or credentials captured.
- [Programs](remaining-programs.json): no remaining enumerated program references map 76. These global diagnostics are read-only; unrelated system BPF programs/maps were not modified.
- [Links](remaining-links.json): the remaining link is unrelated HID tracing, not the original XDP instance.
- [Kernel notice search](kernel-rcu-notices.json): no matching RCU-stall/BPF-warning entries found. This does not prove the absence of a kernel reference or a permanent leak.

The cause is **unresolved**. Retention is observed; a permanent kernel leak is not asserted. No unverified kernel patch, forced map manipulation, policy change, package install or broad BPF deletion was attempted. Further detector runs are suspended rather than accumulating additional retained objects.

## Setup failures retained, not concealed

1. `live/`: aliases supplied during veth creation were not reported; the original guard could not establish identities. Root-created evidence also initially needed an ownership correction. The recorded pair was removed only after matching creation ifindices, recorded MACs, reciprocal peer names and veth type. See [scoped recovery](failed-attempt-cleanup.json).
2. `live-corrected/`: topology, ping and TCP succeeded, but `ip netns exec` hid the existing bpffs submount through its sysfs/mount-namespace handling. The original loader returned EINVAL while auto-pinning, before attachment. Its actual stderr is retained. Using `nsenter --net` preserves the mount namespace; updater control-plane access stays outside the temporary namespace.
3. `live-netns/`: a new host-scope veth's MAC changed between creation and ownership checks. The mismatch was refused rather than accepted; only the exact recorded pair was subsequently removed. [Recovery](failed-netns-attempt-cleanup.json) and scoped [device-manager journal](owned-veth-manager.stdout.log) remain. The final topology creates both endpoints directly in their owned namespaces, never exposing them to host device management.
4. `live-private/`: corrected private topology and original inference passed; the remaining owned-map release check failed as described above. This remains the authoritative raw run result; acceptance for progression is separately qualified by the approved lifecycle exception.

The original C detector, loader, updater, weights and existing runner were not edited to bypass these failures.

## New modular validation surface

- `test_env/commands.py`: shell-free, bounded command/child evidence, deadlines, new output directories and sudo-invoker ownership restoration for owned evidence only.
- `test_env/lab.py`: namespace mount identities, interface ifindex/MAC/alias guards, entirely private veth creation, conflict checks and scoped teardown.
- `test_env/traffic.py`: deterministic harmless TCP fixtures with explicit graceful versus post-response reset closure.
- `test_env/baseline.py`: only module coupled to the current XDP program/map names, layout, pins and inference state. It verifies the real ABI and model instead of assuming the developing BPF implementation remains compatible.
- `test_env/__main__.py`: orchestration and honest top-level failure reporting. It cannot report PASS after an exception/interrupt or failed cleanup.

There is no TC backend, collector or UI scaffold. Those stages remain unstarted behind this gate.

### CLI, after the retained-map blocker is resolved

From the repository root, use explicit loader/updater/tool paths and a new output directory:

```bash
sudo python3 -B -m test_env baseline \
  --out .output/test-env-live-new \
  --loader .output/test-env-stage-01/build/xdp \
  --updater .output/test-env-stage-01/build/hot_updating \
  --bpftool .output/test-env-stage-01/deps/bpftool/bpftool
```

Do not repeat the detector run merely to bypass the current failure. The command refuses preexisting lab names, overlapping non-default routes, model pins and output-directory reuse. It never accepts an arbitrary real interface.

### Exercised safety regressions

[safety-tests.stderr.log](safety-tests.stderr.log) records three passing, real privileged tests: preexisting namespace preservation, interruption after private endpoint creation, and repeated private TCP/reset lifecycle with host configuration unchanged. They use no mocked network commands and load no detector. Source is `test_env/tests/test_lab.py`; tests are skipped unless isolated-VM root opt-in is explicit.

```bash
sudo env NN_EBPF_RUN_LAB_TESTS=1 python3 -B -m unittest discover -s test_env/tests -v
```

No commit or push was performed. New source/tests and evidence are available for a focused review/commit if authorized; ignored build products and datasets should remain uncommitted.

[provenance.json](provenance.json) records current module/test hashes, unchanged
original snapshot fingerprints, executed CLI/help checks and validation scope.
[final-resource-state.json](final-resource-state.json) positively enumerates the
remaining owned map after the safety regressions and confirms that both lab
namespace names and host interface names are absent. Stages 03–10 remain unstarted.
