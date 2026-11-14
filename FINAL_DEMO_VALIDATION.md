# Fresh-model live demo validation

**PASS — all available WSL2 isolated gates completed and independently audited.**
The implementation is ready for operator-controlled transfer/build on the Ubuntu
VM. Native VM compatibility, Windows Python 3.13 and the physical two-laptop
experiment remain NOT RUN for this revision.
No new native VM or physical two-laptop success is claimed. Earlier successful
original-model demo evidence and both fresh-model stored-vector benchmarks are
preserved, and are now supplemented by actual fresh-model operational integration in WSL2.

## Gate 1: inventory and frozen model — PASS

Inspected current Git status/branches, loader, Makefile, launcher, application,
collector, dashboard, CLI parsers, existing isolated tests, runbooks and fresh
artifacts before editing. Current branch is `feature/final-demo-evaluation` at
`73868b101d1c1f5e27c6f71eceaa78a645368445`; evaluation and demo branch tips share
that baseline. Fresh artifacts generated on `feature/cic-external-evaluation`
exist as untracked local files, not in either branch's committed tree. No branch
merge, reset, discard, broad staging, commit or push occurred. The unrelated
tracked dataset deletion remains untouched.

Fresh source: `experiments/fresh_model_20261108/run/checkpoint.npz` and
`run/model/{mlp_params.bpf.h,normalization.json,calibrated.h,calibrated.json}`.
Checkpoint SHA256: `d299f964ecaa7b918eca65529371dbfa6db8797df97ee24b73a324ab52acef1b`.
Runtime copies are in `deployment/models/fresh/`, with a source/hash manifest and
the same 100 deterministic held-out pilot vectors. No checkpoint deserialization,
training, scaler fitting or calibration took place. Transfer only the focused
runtime package and source, not the whole experiments tree.

| Identity | Expected SHA256 |
| --- | --- |
| Original header, preserved | `f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11` |
| Fresh header | `e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391` |
| Fresh packed Q16, 5,216 bytes | `1558c438e06600d8e3a5eeb28fe23c6aed94cb693a75dea4817497add71bd8d9` |
| Fresh packed layer-specific, 5,304 bytes | `1db06f441987ef7eb282b5954f158fbe861a74bf59bdcbf7988c7ec5c7e2357f` |
| Fresh kernel-facing scaler, 96 bytes | `f900a854d88a1eb6a346da7e102c97f70a2481e4332345b2a28b2d5ce91ef650` |
| Frozen normalization JSON | `32c01e51e8b4d4179afc7a45d828d9b8df12bcc5827c7910dea770ea73c3d9f8` |

The scaler digest covers six little-endian int64 means followed by six int64
scales. Means are `[572,11043024376,36,484,11935,373]`; scales are
`[452,24483430907,58,1649,49489,1547]`. These are the frozen quantized train-only
scaler, not a refit or the original model's normalization.

## Focused changes

| Existing file changed | Purpose |
| --- | --- |
| `tc/controller.c` | Optional compile-time parameter/calibration header selection; save actual map readbacks and verify active slot |
| `tc/Makefile` | Separate fresh controllers, reusing unchanged BPF code; `demo-models` build target |
| `tc/tests/test_tc.py` | Two explicit `tc.demo` imports fix a host-test name collision with the newer `demo/` package; assertions unchanged |
| `deployment/ids.py` | Select model separately from arithmetic; validate map readbacks; carry experiment/port/model metadata |
| `demo/launch.py` | Configurable port/prefix/bind/model; reserved sockets, readiness checks, identity output and supervised cleanup |
| `demo/server.py` | Accept selected port and verified inherited listener as an ordinary user |
| `dashboard/server.py` | Supervised inherited listener, configurable IPv4 loopback bind |
| `dashboard/telemetry.py` | Model identity, experiment and port in telemetry/JSONL; selected model's actual logit exponent |
| `dashboard/static/index.html` | Model/port status field |
| `dashboard/static/app.js` | Display selected model/port and readback identity |

New source: `deployment/model_config.py`, `demo/listener.py`,
`demo/start_server.sh`, `demo/test_final_server.py`, `demo/validate_server.py`,
`demo/scenarios-reproduction-informed.csv`, and these two runbooks.
New frozen package files: `deployment/models/fresh/mlp_params.bpf.h`,
`calibrated.h`, `calibrated.json`, `normalization.json`, `pilot.jsonl`,
`manifest.json`.

Original XDP sources/parameters, TC BPF source, flow keys, spin locks, per-CPU
workspace, feature definitions, trained artifacts and old benchmark records are
not modified. All existing test assertions remain; two TC test imports were
made unambiguous so those tests actually exercise the intended module. Initial hashes cover 584 protected files;
pre-edit copies of changed source are in
`verification-logs/fresh-live-demo-20261108/baseline-source/`.

## Port-80 failure and fix

In this exact baseline, both `demo/launch.py` and `demo/server.py` accepted a
`--port` argument but **explicitly rejected every value below 1024**. Thus port
80 could not reach a listener. The deployment CLI also had no application-port
metadata option. Those are confirmed code defects relevant to this request.

The historical literal "unsupported option" stderr from the VM is not present
locally; it cannot be attributed to a particular remote file/version without
that log. This checkout's `--port 80` range rejection is confirmed. No missing
listener is explained away as a model prediction issue.

The fix uses a root supervisor to reserve the selected sockets before any BPF
load, then passes descriptors to ordinary-user application/dashboard children.
No proxy, redirection, root web server, setcap or system-wide privileged-port
change is used. Port selection propagates to the listener, deployment
`--app-port` metadata, experiment, JSONL, dashboard, actual tuple matching and
printed Windows command. The existing kernel IP filter remains client-scoped;
no new kernel port filter or MLP input definition is introduced. Conflicts fail
without killing pre-existing services. Actual port-80 and port-9000 socket exchanges passed in the isolated runtime
suite; this result is supported by listener records and real client responses.

## Actual commands and evidence to date

```bash
make -C tc demo-models
PYTHONDONTWRITEBYTECODE=1 python3 -m deployment.model_config --model fresh --mode static_q16
PYTHONDONTWRITEBYTECODE=1 python3 -m deployment.model_config --model fresh --mode layer_specific
bash -n demo/start_server.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v demo.test_demo deployment.tests.test_dashboard
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v demo.test_final_server
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 demo/validate_server.py \
  --prepare verification-logs/fresh-live-demo-20261108/ready
```

Preparation actually ran `make -C tc -B demo-models`, compiling the unchanged
BPF programs and all four controllers, then the combined host suite and four
read-only ELF/schema inspections. Build output has no compiler warning/error.
The initial sandbox unittest output reported **42 tests run, four skips** for
socket restrictions. The operator subsequently ran the full suite inside the
owned namespace as UID 1000: **44 tests passed, zero skips**, including the
previously unavailable real-socket/HTTP tests. Mock model readbacks in unit tests are not
kernel evidence.

Evidence: `verification-logs/fresh-live-demo-20261108/prepare.log`,
`ready/build.log`, `ready/host-tests.log`, four inspect subdirectories and
`ready/manifest.json`. Frozen parameter identities are independently checked by
the standard-library numerical references.

| Check | Current status |
| --- | --- |
| Fresh artifact discovery, origin and hash identity | PASS |
| Native-source BPF/controller compilation in WSL | PASS |
| Shell syntax / CLI / host tests | PASS; 44 ordinary-user namespace tests, zero skips |
| Existing original-model regression tests in this revision | PASS, both modes including kernel/concurrency/network checks |
| Actual kernel verifier acceptance of this revision | PASS, 16 program logs |
| Fresh map parameter/scaler readback in this revision | PASS, both slots in both modes |
| Fresh 100-vector actual six-stage correctness pilot | PASS, 206 complete chains, zero mismatches |
| Port 80/9000 genuine listener and response | PASS, fresh Q16 and layer-specific |
| One-command lifecycle and LIVE dashboard telemetry | PASS, five supervised runs with actual HTTP API |
| One/ten connections, features, tuples and kernel tensors | PASS, 55 direct connections, zero numerical mismatches |
| Occupied-port/foreign-filter/owned-ID cleanup checks | PASS, plus address/route and namespace cleanup |
| Ubuntu VM new-model deployment | NOT RUN |
| Windows Python 3.13 and physical two-laptop test | NOT RUN |

## Ordered runtime gates

The operator approved and executed the following command:

```bash
sudo /usr/bin/python3 /home/arnav/research/ebpf-ids-research/demo/validate_server.py \
  --pilot /home/arnav/research/ebpf-ids-research/verification-logs/fresh-live-demo-20261108/ready
```

It used the new selected deployment binaries and two private TC objects
(16 programs, 17 unpinned maps). Each mode runs the same 100 vectors plus three
fresh repetition checks: 206 complete chains total. Both actual kernel slots
matched expected packed parameters and scaler bytes. All six stage counters,
tensors and labels agreed with the frozen reference. No attachment or
networking change occurred. Cleanup passed for all 16 programs and 17 maps.

Actual evidence: `ready/pilot-20261108-221759-464762/` under the verification
directory. The independent read-only audit is `audit_pilot.py`, its output is
`pilot-audit.log`, and its machine-readable summary is `PILOT_VERIFIED.json`.
It checked 202 retained snapshots, 1,212 stage tensors and 27,472 integers. The
C driver checked all 206 calls (1,236 tensors / 28,016 integers); each three-call
guard retains only its last snapshot. All 16 verifier logs have acceptance
summaries and both controller error logs are empty. The checks use stored
feature vectors, not full-flow statistics invented from a single packet.
Actual program IDs: Q16 252–259; layer-specific 263–270. Map IDs: 144–151 and
152–160. Recorded ID-absence checks passed for every owned ID.

The saved parameter/scaler files were compared byte-for-byte with the frozen
references, not accepted from a header hash alone. Both modes use the same
96-byte scaler and final Q16 logit exponent 16. The original model remains
separate and unchanged.

The actual pilot and separately approved network phase have passed independent
review. The network run checked existing regressions,
then fresh static/LS at ports 80 and 9000, and original/static/9000 rollback.
Each run performed one connection before ten concurrent connections. Real
responses, LIVE HTTP snapshots, source-port identities, real six features,
retained classifications, all-stage parity and kernel diagnostics passed.
It refused occupied app/dashboard ports, preserved a foreign test filter added
after attachment, and verified address/route and owned-resource cleanup. No
physical or VM interface is automatically selected.

Model validation failure leaves original parameters and binaries available;
there is no silent fallback to original weights. Port-80 success is established in isolated WSL2 only; native VM and physical
verification remain pending. The operator
commands and safe rollback are in FINAL_TWO_LAPTOP_DEMO.md.

## Git review and remaining work

No new commit yet. Recommended boundaries: model package/selection/readback;
listener/lifecycle/dashboard; tests/scenarios/runbooks plus small successful
summaries after the gates pass. The exact explicit staging list is in the
runbook. Exclude all unrelated untracked work, generated outputs, old raw
measurements and the longstanding unrelated dataset deletion. Do not push
automatically. A committed-and-manually-pushed runtime package is required
before GitHub transfer can deliver the fresh model to the VM.

The remaining critical evidence is operator-only VM/two-laptop execution. Held-out F1 and previous benchmark success remain separate evidence.

## Network preparation correction, before privileged execution

The initial new network driver attempted the existing smoke runner's `--run`
without first preparing its required evidence bundle. This was caught during
review before requesting a privileged network run. The driver now has a
nonprivileged `--prepare-network` phase that builds both regression bundles;
`--network` consumes them rather than nonexistent per-run paths.

That preparation exposed a pre-existing import collision: two TC host tests
used `import demo`, which resolved to the newer top-level application package
instead of `tc/demo.py`. Only those imports changed to `from tc import demo`;
no assertions were removed or skipped. Both original TC host suites now pass
all **37 tests each**. No inference, loader, listener, model or BPF binary changed
after the successful fresh-model kernel pilot.

`network-ready/` preserves the failed nonprivileged preparation diagnostics;
the successful network run used **`network-ready-r2/`**. Its compatibility record confirms
98 other manifest entries unchanged, including every runtime source, binary,
parameter and fixture. The two differing files are only the network test driver
and those TC unit-test imports. The original pilot driver/test files are
archived with their original verified hashes, so the old pilot manifest and
raw outputs were not rewritten. A new kernel pilot is unnecessary for these
test-only changes. The current network manifest is
`e6e46fd719f93ac0ec7fbbfb5859e8c5b3755fb6248c8f4b5b74903edeb5154a`.

Actual nonprivileged commands:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 verification-logs/fresh-live-demo-20261108/audit_pilot.py
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 demo/validate_server.py \
  --prepare-network verification-logs/fresh-live-demo-20261108/network-ready-r2 \
  --pilot-evidence verification-logs/fresh-live-demo-20261108/ready/pilot-20261108-221759-464762
```

Actual separately approved operator networking command:

```bash
sudo /usr/bin/python3 demo/validate_server.py \
  --network verification-logs/fresh-live-demo-20261108/network-ready-r2 \
  --pilot-evidence verification-logs/fresh-live-demo-20261108/ready/pilot-20261108-221759-464762
```

The old `ready/` manifest documents the actual pilot-time test driver. Do not
reuse it to start a new pilot with the revised driver; use a fresh `--prepare`
output path when independently reproducing the pilot. The network gate verifies
the current manifest and permits only the two explicitly recorded test-only
changes relative to the passing pilot. All runtime/model changes invalidate it.

The additional saved-manifest guard checks in NETWORK_GATE_REVIEW.json passed:
a changed model, changed loader, changed listener or extra input is rejected.
These four synthetic metadata tests do not represent kernel or packet evidence.


## Actual isolated networking results — PASS

Actual execution: network-ready-r2/network-20261108-222936-086955/.
Independent replay: audit_network.py, network-audit.log and NETWORK_VERIFIED.json.
The saved-data audit created no sockets, loaded no BPF and changed no networking.
It rechecked the frozen manifest, both original regression reports, actual
listener readiness, the HTTP response, tuple joins, every retained feature/tensor,
model identity, log records and cleanup evidence.

| Model / mode / port | Connections | Ingress total / matched | Egress matched | Predictions | Each stage | Benign false positives |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| fresh / static_q16 / 80 | 11 | 169 / 169 | 146 | 11 | 11 | 3 / 11 |
| fresh / static_q16 / 9000 | 11 | 170 / 169 | 146 | 11 | 11 | 5 / 11 |
| fresh / layer_specific / 80 | 11 | 169 / 169 | 146 | 11 | 11 | 3 / 11 |
| fresh / layer_specific / 9000 | 11 | 169 / 169 | 146 | 11 | 11 | 5 / 11 |
| original / static_q16 / 9000 | 11 | 170 / 169 | 147 | 11 | 11 | 10 / 11 |

Each row contains one connection followed by ten concurrent connections. All
55 completed with validated acknowledgements, unique source ports and one
canonical record/prediction each. Coverage was 100% for these cases. **330
stage tensors / 7,480 integers** matched the corresponding frozen host reference,
with zero numerical mismatches. Tail-call failures, inference failures,
workspace-busy events, flow/result capacity errors and arithmetic diagnostics
were zero. Incoming/outgoing byte counters and per-flow directional counters
were positive; complete observed values are in NETWORK_VERIFIED.json.

Fresh Q16/80 observed 169 matched ingress packets and 146 egress packets,
11 predictions and stages [11,11,11,11,11,11]. These are observed skb counts,
not promised counts for the physical demo. The extra unmatched ingress packet
in two rows is included in total traffic and not silently counted as an
eligible TCP-model packet.

The application and dashboard ran as ordinary UID 1000. Kernel-owned listener
evidence confirms actual selected ports 80 and 9000. A live HTTP API response
was fetched after client traffic and matched the logged tuples, predictions,
features, model identity and hook IDs. Browser rendering in the actual VM is
still an operator visual check; no browser session on that VM was simulated.

Both original-model integrated regression suites passed, including ingress,
single/ten-flow/burst bidirectional traffic and numerical comparisons. Existing
SMP tests observed 1,033 ingress packets in one shared flow and 514 packets per
hook in a two-hook shared flow. Exact CPU interleavings were not forced. The
new ten-connection runs demonstrate tested concurrency, not all possible races.

Occupied application and dashboard ports were refused before any IDS process
started; existing listeners remained alive. Every run preserved the deliberately
added foreign TC filter, detached only its owned filters and left clsact in
place. Saved stop/cleanup evidence reports private-ID release. Address/route
snapshots match, both namespace PID lists were empty, and namespace deletion
commands succeeded.

Pilot raw verifier logs and binary parameter readbacks remain retained. For
the five live runs, the collector verified byte readbacks before readiness;
their verified identities, owner records, real kernel tensors, snapshots and
cleanup results are retained. Per-live-run raw verifier/readback files were
removed with the owned temporary runtime; they are not claimed to have been
independently re-hashed after deletion.

**Detection-effectiveness limitation:** benign false positives above remain
visible. There are no labeled intrusion cases in this suite, so intrusion
recall/F1 is unavailable. These separate runs differ in port and actual packet
timing/features; their false-positive counts are not a controlled model-effect
or arithmetic-effect comparison. The 99.67% held-out dataset F1 remains separate.

## Operator handoff

All available isolated gates passed. Use FINAL_TWO_LAPTOP_DEMO.md to explicitly
commit/push the focused runtime package, fetch/build natively and launch with
model fresh, mode static_q16, port 80. No physical interface operation was
performed here. The source remains uncommitted at this handoff; do not assume
the fresh artifacts are already on GitHub. No automatic push or broad Git
cleanup is authorized or performed.

Recommended reviewable boundaries: (1) frozen model package, loader/readbacks,
collector metadata and the two TC test-import fixes; (2) supervised listeners,
launcher/dashboard, scenario/test harness, runbooks and small PASS summaries.
No model/BPF/runtime source changed after the successful pilot/network gates.
584 protected model, original-source and prior-benchmark files remain unchanged.
