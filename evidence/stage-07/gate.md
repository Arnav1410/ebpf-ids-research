# Stage 07 — live dashboard and explicitly simulated replay

```text
STAGE: 07 — Live dashboard
STATUS: PASS
BASE COMMIT / DIFF: b6c5b48; additive test_env/dashboard.py, serve.py, web assets, replay regressions, pinned isolated requirements and evidence
CHANGES: Read-only localhost FastAPI surface, dependency-free browser UI, collector-only live adapter, bounded deterministic simulated replay, scoped service lifecycle and explicit reader restart
COMMANDS EXECUTED: commands.json; live/replay service argv and controlled private traffic helpers; actual Chromium navigation, selection, offline/recovery and screenshots
BUILD: NOT APPLICABLE — no frontend bundler; actual Python/ASGI startup and static assets exercised
VERIFIER LOAD: PASS — actual accepted Stage06 NN object loaded by the live service
ATTACH: PASS — both owned detect-only private TC hooks
RUNTIME PACKET TEST: PASS — eight real simultaneous TCP exchanges; real SYN-only pending flow; reader stop/restart and browser network loss
CORRECTNESS TEST: PASS — all eight rendered events match API and final kernel ledger; active map row matches read-only independent inspector; exact 16-record replay; pure suite and UI-stopped kernel event checks pass
EXPECTED VS OBSERVED: eight scored flows plus one pending flow displayed; reader generation 1 -> 2 with unchanged producer identity; offline/disconnected state visible then recovered; 16/16 recorded replay events unchanged
EVIDENCE: live-browser-proof.json, replay-browser-proof.json, mobile-api-proof.json, provenance.json and hashed local raw artifacts
CLEANUP / ROLLBACK CHECK: PASS — all services/readers exit 0, owned maps/programs/filters/namespaces released, browser tab closed; 20 original fingerprints unchanged
GATE DECISION: PASS
NEXT ACTION: Commit this accepted stage, then stop at Stage08's separate physical-network approval/configuration gate
```

## Surface and modular boundary

- `dashboard.create_app(state, mode=...)` accepts only collector-shaped read-only state. `GET /health`, `/summary`, `/flows`, `/events` have versioned envelopes with explicit `mode` and `simulated`. The browser never computes a model output, reads BPF maps or controls networking.
- `serve.LiveView` adds actual producer liveness, telemetry age and startup-verified hook IDs. Startup attachment verification is **not** claimed to prove current attachment. Rates use measured native counters and monotonic source intervals.
- Static HTML/JS/CSS poll complete bounded arrival histories, preserving cross-CPU reordering. Flow detail selection, latest arrival, model identity, direction counts, pending/unclassified state, numeric-label counts, truncation and separate losses are visible. Fetch failure, missing reader and stale source data show **DISCONNECTED / STALE**, not a healthy cached view.
- Numeric label meanings are still **UNVERIFIED**. The UI does not rename 0/1 to benign/intrusion, invent accuracy/F1, convert kernel monotonic clocks to wall time or claim a greeting is correctly classified. JavaScript-unsafe integers are marked unavailable rather than displayed as exact rounded values.
- `ReplayState` validates a maximum 1 MiB / 256-record capture before revealing any prefix. Mixed source, duplicate sequence, private/unknown fields and malformed records fail. Advance/reset are deterministic; actual recorded labels/logits/timestamps are preserved. Replay rates, current map occupancy and connectivity are unavailable. A persistent **SIMULATED REPLAY** banner applies even to historical native records originally marked `live`.
- FastAPI is imported lazily: replay boundary tests and the existing evaluation environment remain usable without installing web dependencies there. Inspected [FastAPI](https://pypi.org/project/fastapi/) 0.162.0 and [Uvicorn](https://pypi.org/project/uvicorn/) 0.54.0 were installed only in `.output/test-env-stage-07/venv`. All resolved runtime dependencies are pinned in `test_env/requirements-dashboard.txt`; no system or evaluation packages changed.
- Localhost-only binding, allowed Host names, no CORS or HTTP mutations, exact static-file routes, self-only CSP, `nosniff` and no-store responses. Actual observed rejections: POST 405, foreign Host 400, repository source path 404.

## Actual verification

| Check | Observed evidence |
| --- | --- |
| Real controlled traffic | Eight concurrent namespace TCP connections; UI showed nine flows: eight scored, one actual SYN-only pending/unclassified |
| Rendered event fields | All eight sequence/flow/trigger/timestamp/label rows match API; full model identity displayed; every public result integer matches the final owned kernel result ledger |
| Active flow statistics | Independent FD/namespace-proven read-only inspector matched the collector's remaining active row exactly; completed flows had legitimately expired before this later snapshot, not silently disappeared from the event ledger |
| Reader failure/restart | SIGTERM to the actual owned reader produced visible stale/disconnected status; SIGHUP explicitly restarted it; new reader PID, generation 2, same producer/source identity; no automatic hidden replacement |
| Browser network loss | Actual Chromium offline emulation produced visible stale/disconnected state; restoring network recovered without inventing new data |
| Replay | Exact equality of all 16 actual saved native events through replay API; no live connectivity claim; flow selection/details inspected in Chromium |
| Responsive surface | Actual Chromium 1440-pixel desktop and 390 × 844 viewport; mobile body width equals viewport, no page-level horizontal overflow |
| Pure regressions | 55 discovered: 46 passed, nine privileged cases skipped intentionally; all seven new replay boundary/transition tests passed without web dependencies in evaluation venv |
| UI service stopped | All eight event tests passed as root in 11.467 seconds, including real kernel parity, overflow, restart and strict release; no HTTP UI service running |
| Final release | All three owned service processes exit 0; both live reader lifetimes exit 0; no owned BPF IDs left; lab cleanup complete; original 20 fingerprints unchanged |

Raw screenshots (`live-render.webp`, `replay-render.webp`, `reader-disconnected.webp`, `mobile-render.webp`), native logs, final map/collector snapshots and service reports are retained locally and hashed in `provenance.json`; they are excluded from Git. Compact browser proofs and provenance are versioned. Two parent-driver mistakes (root-private readiness path and caption word order) are recorded in `validation-driver-notes.json`; neither was an application failure suppressed to pass the gate.

## Reproduction and operation

From repository root. Dependency installation uses a separate ignored environment:

```bash
python3 -m venv .output/test-env-stage-07/venv
.output/test-env-stage-07/venv/bin/python -m pip install \
  -r test_env/requirements-dashboard.txt
```

Replay needs no root or live kernel attachment. The sample is generated by the accepted Stage06 event command and retained locally; a fresh clone does not contain bulky local raw evidence. Select a fresh log directory:

```bash
.output/test-env-stage-07/venv/bin/python -B -m test_env.serve replay \
  --sample evidence/stage-06/safety/test_live_event_parity_overflows_restart_and_owned_release/sample-live-events.jsonl \
  --out .output/dashboard-replay --seconds 120
```

Live mode creates only the accepted owned private lab, loads the original checked-in model and exposes the same localhost page. Build paths below are the actual accepted artifacts:

```bash
sudo .output/test-env-stage-07/venv/bin/python -B -m test_env.serve live \
  --loader .output/test-env-stage-06/build/nn-loader \
  --object .output/test-env-stage-06/build/nn.bpf.o \
  --bpftool .output/test-env-stage-01/deps/bpftool/bpftool \
  --out .output/dashboard-live --seconds 120
```

Open `http://127.0.0.1:8765`. Both modes default to 120 seconds and have a maximum 240-second lab lifetime; `--port` selects a nonprivileged localhost port. These are bounded lab services, not production daemons. Ctrl+C/SIGTERM performs graceful owned cleanup. Live `SIGHUP` explicitly requests a native-reader restart; the HTTP API never offers a mutation endpoint. Root live logs stay private while running; cleanup restores invoking-user ownership. No passwords are accepted by or stored in the program.

`http.log`, native reader/producer logs, live JSONL journal and `service-report.json` are in the chosen exclusive output directory. Final live collector/map snapshots are saved before reader-then-producer release. Existing namespace names/resources are never adopted or deleted as cleanup.

## Next gate

Stage08 is **not authorized or validated**. The VM evidence does not establish the physical Ethernet wiring, Windows/WSL configuration, host bridge/NIC ownership or a safe non-management real-interface target. No default route, firewall, physical/bridged interface or working model was changed. Obtain explicit operator approval and actual host/WSL/bridge details before physical integration. Stage09 remains gated on those prerequisites; optional Stage10 remains unapproved and detect-only behaviour unchanged.
