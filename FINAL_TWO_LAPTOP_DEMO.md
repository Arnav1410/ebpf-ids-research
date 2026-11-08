# Fresh-model two-laptop demonstration

**READY FOR OPERATOR-CONTROLLED UBUNTU VM DEPLOYMENT.** The fresh-model pilot
and all available WSL2 isolated network gates passed. Native VM compatibility,
Windows Python 3.13 and the physical two-laptop run remain NOT RUN for this
revision. Commit/push the focused source below before fetching it on the VM;
the fresh runtime package is not yet on GitHub.

Only the existing six ingress-derived features enter the MLP. Egress counters
remain monitoring statistics. No training, new calibration or network
reconfiguration is part of startup. The application on port 80 is the bounded
`IDSDEMO1` TCP protocol, **not an HTTP server**. The dashboard is HTTP on 8080.

## Development gates in WSL

Preparation already ran without privilege:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 demo/validate_server.py \
  --prepare verification-logs/fresh-live-demo-20261108/ready
```

The operator ran this private, unattached fresh-model kernel pilot before
network-driver-only corrections:

```bash
sudo /usr/bin/python3 demo/validate_server.py \
  --pilot verification-logs/fresh-live-demo-20261108/ready
```

Actual independent review: PASS for both modes, 100 vectors and 103 fresh
six-stage executions per mode (206 total), zero mismatches, correct actual
parameter/scaler readbacks and owned-ID cleanup. No attachment occurred.
The evidence is `ready/pilot-20261108-221759-464762/` under the verification
directory. The old `ready/` manifest is the pilot-time snapshot; do not rerun it
with the revised test driver. For a full independent pilot reproduction, prepare
a fresh output path first.

The actual pilot has passed review. Nonprivileged network preparation also
passed, including both original-model TC host suites (37 tests each):

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 demo/validate_server.py \
  --prepare-network verification-logs/fresh-live-demo-20261108/network-ready-r2 \
  --pilot-evidence verification-logs/fresh-live-demo-20261108/ready/pilot-20261108-221759-464762
```

That directory already exists; do not rerun preparation over it. The two
post-pilot test-only changes are the corrected regression-preparation sequence
and unambiguous TC test imports. All runtime/model/binary bytes match the passed
pilot. The compatibility gate rejects other changes.

The operator separately approved and executed this network command:

```bash
sudo /usr/bin/python3 demo/validate_server.py \
  --network verification-logs/fresh-live-demo-20261108/network-ready-r2 \
  --pilot-evidence verification-logs/fresh-live-demo-20261108/ready/pilot-20261108-221759-464762
```

The second phase passed both original-model regression suites, fresh Q16 and
layer-specific one/ten-connection tests on ports 80 and 9000, and the
original/Q16/9000 rollback. All 55 direct connections completed and produced
matching real kernel classifications; 330 tensors / 7,480 integers matched the
references. The actual LIVE API, port conflicts, foreign-filter preservation,
address/route preservation and cleanup passed. All 44 ordinary-user tests passed,
with zero skips. No physical interface was touched.

Actual evidence: `network-ready-r2/network-20261108-222936-086955/` under the
verification directory. See FINAL_DEMO_VALIDATION.md and its compact SUMMARY.json.
No further privileged WSL rerun is needed. Separate benign false positives remain
recorded; these passes do not prove live detection accuracy.

## Transfer the focused source through GitHub

The fresh artifacts were generated on `feature/cic-external-evaluation` and were
untracked in the development working tree. They were **not** present in the
committed demo baseline. The verified copies for runtime are now explicitly in
`deployment/models/fresh/`; do not merge the experimental branches or copy all
training/benchmark output. The VM does not need PyTorch, NumPy, the full dataset
or the checkpoint NPZ to run this demo.

Current development branch: `feature/final-demo-evaluation`, baseline
`73868b101d1c1f5e27c6f71eceaa78a645368445`. No new commit or push has been made.
The isolated gates passed. Review this exact list; the unrelated tracked dataset
deletion and all experimental work must remain outside it. Make two focused
commits as your ordinary WSL account:

```bash
git status --short
git diff --cached --name-only
git diff -- demo deployment dashboard tc
```

If anything is already staged, review it first; do not commit unrelated changes
or automatically unstage someone else's work. First stage model integration:

```bash
git add -- tc/controller.c tc/Makefile tc/tests/test_tc.py deployment/ids.py \
  deployment/model_config.py deployment/models/fresh/ dashboard/telemetry.py
git diff --cached --stat
git diff --cached --name-only
git commit -m "Add frozen fresh-model selection and kernel parameter readback"
```

Then stage the verified operational harness and compact evidence:

```bash
git add -- demo/launch.py demo/server.py demo/listener.py demo/start_server.sh \
  demo/test_final_server.py demo/validate_server.py \
  demo/scenarios-reproduction-informed.csv dashboard/server.py \
  dashboard/static/index.html dashboard/static/app.js \
  FINAL_TWO_LAPTOP_DEMO.md FINAL_DEMO_VALIDATION.md \
  verification-logs/fresh-live-demo-20261108/SUMMARY.json \
  verification-logs/fresh-live-demo-20261108/PILOT_VERIFIED.json \
  verification-logs/fresh-live-demo-20261108/NETWORK_VERIFIED.json
git diff --cached --stat
git diff --cached --name-only
git commit -m "Add verified port-80 fresh-model demonstration launcher"
git rev-parse HEAD
git push origin HEAD:feature/final-demo-evaluation
```

These are manual operator commands; Codex did not stage, commit or push. The
full hash printed after the second commit is the deployment revision to
transfer. Compare that exact hash on the VM. If push is rejected, stop and
inspect remote changes; do not force-push. Full raw test evidence stays in WSL;
only the small summaries above are recommended for Git.

Confirm the list contains no unrelated dataset deletion/executable, generated
binary, PCAP, old experiment or raw benchmark archive. The two boundaries above
keep model integration separate from the operational harness. Uncommitted files do not
transfer. No `git add .`, reset, clean or automatic push is used.

On the VM, inspect local changes before fetching. For a clean existing checkout:

```bash
git status --short
git remote get-url origin
git fetch origin feature/final-demo-evaluation
git switch --detach origin/feature/final-demo-evaluation
git rev-parse HEAD
```

Compare the full hash with the exact validated commit you pushed. If there are
local edits, preserve them and use a separate checkout instead of forcing a
switch. The actual origin is `https://github.com/Arnav1410/ebpf-ids-research.git`.
For a new clone use HTTPS authentication:

```bash
git clone --branch feature/final-demo-evaluation \
  https://github.com/Arnav1410/ebpf-ids-research.git
cd ebpf-ids-research
git submodule update --init -- libbpf bpftool
```

For an existing sparse checkout, retain existing dependency paths and add:

```bash
git sparse-checkout add --no-cone '/demo/' '/deployment/' '/dashboard/' '/tc/' \
  '/src/' '/validation/' '/quantization/' '/evaluation/' \
  '/FINAL_TWO_LAPTOP_DEMO.md' '/FINAL_DEMO_VALIDATION.md'
```

Only the source/dependency paths above are needed. Do not execute unrelated
dataset files. Do not copy WSL `.output` executables onto the VM.

## Inspect and build in the Ubuntu VM

```bash
cat /etc/os-release
uname -r
ip -4 addr show dev enp7s0
ip -details link show dev enp7s0
ip route show
tc -j qdisc show dev enp7s0
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
test -r /sys/kernel/btf/vmlinux
```

Expect the already configured, operational **enp7s0 = 192.168.77.3/24**.
`enp8s0` belongs to the physical host; `enp1s0` is the VM's separate NAT adapter.
Do not select or reconfigure either. If the address/link is missing, stop and
restore the intended network manually with your teammates; startup never adds
or flushes addresses or changes routes, DNS, firewall or NetworkManager.

Install only missing prerequisites after confirming Ubuntu; the dependency
list and rationale are in SERVER_DEPLOYMENT.md. The actual native commands are:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends build-essential gcc make clang llvm \
  libelf-dev zlib1g-dev pkg-config iproute2 util-linux python3 git ca-certificates curl
git submodule update --init -- libbpf bpftool
make -j2 CLANG=clang
make -C tc demo-models CLANG=clang
test -f deployment/models/fresh/manifest.json
test -x demo/start_server.sh
sha256sum src/mlp_params.bpf.h deployment/models/fresh/mlp_params.bpf.h
python3 -m deployment.model_config --model fresh --mode static_q16
python3 -B -m unittest -v demo.test_demo demo.test_final_server deployment.tests.test_dashboard
```

The two header hashes must remain respectively:

```text
original f8fbc19b2aaf2e18d2163f378722ce336217eb9299a51a12218369333d473f11
fresh    e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391
```

Read-only dry-run, without attachment or listeners:

```bash
./demo/start_server.sh --interface enp7s0 --server-ip 192.168.77.3 \
  --prefix-length 24 --client-ip 192.168.77.2 --port 80 \
  --dashboard-bind 127.0.0.1 --dashboard-port 8080 --model fresh \
  --mode static_q16 --dry-run
```

An unprivileged preflight can report unavailable effective attachment
capabilities; actual startup uses explicit sudo. The dry-run prints expected
model identity with kernel readback NOT RUN, existing filters and planned hooks.
It does not prove verifier acceptance. Existing classifiers are refused.

## One startup command

Run as your ordinary VM account. The thin shell wrapper requests local sudo;
the application and dashboard drop back to that ordinary UID.

```bash
IDS_RUN="$HOME/ids-runs/$(date +%Y%m%d-%H%M%S)"
./demo/start_server.sh --interface enp7s0 --server-ip 192.168.77.3 \
  --prefix-length 24 --client-ip 192.168.77.2 --port 80 \
  --dashboard-bind 127.0.0.1 --dashboard-port 8080 \
  --model fresh --mode static_q16 --output "$IDS_RUN"
```

Review preflight and type **`ATTACH enp7s0`**. Keep the terminal open. The parent
reserves the selected application/dashboard ports before IDS load. It passes
owned listening descriptors to unprivileged children, so port 80 needs neither
a root application server nor a system-wide port/capability change. Occupied
ports fail without terminating the other listener. Port 9000 uses the identical
path; change only `--port` and the client argument.

Expected readiness lines, **only after actual successful startup**:

```text
MODEL: fresh
ARITHMETIC: static_q16
HEADER SHA256: e896b31f40fd3cfd6bf78db3c64651f882c7bd8a206438c30361e276f6da8391
PARAMETER SHA256: 1558c438e06600d8e3a5eeb28fe23c6aed94cb693a75dea4817497add71bd8d9
SCALER SHA256: f900a854d88a1eb6a346da7e102c97f70a2481e4332345b2a28b2d5ce91ef650
KERNEL MODEL READBACK: PASS (slots 0 and 1)
TCP LISTENING: 192.168.77.3:80
DASHBOARD: http://127.0.0.1:8080/
```

The following JSON `experiment_ready` line contains the actual experiment ID,
output path and first Windows command. An ICMP warning is nonfatal: Windows may
block ping or not yet have its Ethernet address. No client IP is assumed to be
currently assigned merely because it appears in configuration.

Open `http://127.0.0.1:8080/` in the **VM browser**. Use another ordinary VM
terminal for the printed `tail -f '.../dashboard.log'` command. No GUI terminal
is launched as root. Dashboard binds are restricted to IPv4 loopback; there is
no public dashboard or remote-control endpoint and no SSH requirement.

## Windows Python 3.13: one connection, then ten

Copy `demo/client.py`, `demo/common.py`, `demo/scenarios.csv` and
`demo/scenarios-reproduction-informed.csv` to one Windows folder. No WSL,
administrator privilege or pip installation is required for the client.

In Windows PowerShell 5.1 or later:

```powershell
Set-Location "$env:USERPROFILE\Documents\ids-client"
py -3.13 --version
Get-NetAdapter -Name Ethernet
Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4
Test-Connection 192.168.77.3 -Count 2
$Server = '192.168.77.3'
$Source = '192.168.77.2'
$Port = 80
$RunId = Read-Host 'Paste experiment_id printed by the VM launcher'
$Stamp = Get-Date -Format yyyyMMdd-HHmmss
py -3.13 client.py --input scenarios-reproduction-informed.csv --count 1 --concurrency 1 --server-ip $Server --source-ip $Source --port $Port --experiment-id $RunId --output "client-$Stamp-one"
Get-Content "client-$Stamp-one\client_summary.json"
```

Confirm the Ethernet adapter actually has `192.168.77.2/24`. If it is currently
using DHCP for another connection, stop and restore the intended isolated demo
network manually; do not blindly reconfigure an Internet adapter. ICMP failure
alone does not prove TCP failure. The first Python call performs the real
connection/half-close/response check and must report completed=1, failed=0.

Only then:

```powershell
py -3.13 client.py --input scenarios-reproduction-informed.csv --count 10 --concurrency 10 --server-ip $Server --source-ip $Source --port $Port --experiment-id $RunId --output "client-$Stamp-ten"
Get-Content "client-$Stamp-ten\client_summary.json"
```

Expect ten completed acknowledgements and no errors, with ten actual source
ports recorded. `Test-NetConnection $Server -Port $Port` is an optional diagnostic
if connection setup fails; it creates an extra TCP flow without a demo header.
Do not count that diagnostic as a labeled application case. Do not use curl to
test the `IDSDEMO1` application protocol.

These scenarios are bounded ordinary TCP traffic informed by approximate size
and chunk ranges. They do **not** reproduce stored dataset feature vectors.
Segmentation/offloads, real nanosecond timing, header bytes and the FIN window
determine actual features. The held-out 99.67% F1 does not imply equivalent live
accuracy. A predicted intrusion on benign-intent traffic is recorded, not hidden
or used as a startup failure condition.

## Inspect actual evidence

In a second VM terminal, use the actual printed output directory:

```bash
IDS_RUN='/actual/printed/experiment/output/path'
cat "$IDS_RUN/experiment.json"
ss -lntp 'sport = :80'
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
curl --fail --silent http://127.0.0.1:8080/api/state
```

The dashboard must show CONNECTED, both actual hook IDs, fresh/static_q16,
application port 80 and increasing ingress/egress statistics. Connections are
identified by the full canonical address/port tuple, not by client IP alone.
Inference runs on the first eligible ingress FIN/RST; requests/packets are not
one-to-one classifications. Packet counts are observations, not fixed targets.

`experiment.json` records the short, owned `/run/idsdemo-*` runtime directory.
While running, inspect full kernel features and all six tensors with:

```bash
IDS_RUNTIME=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state_dir"])' "$IDS_RUN/experiment.json")
sudo python3 deployment/ids.py snapshot --interface enp7s0 --state-dir "$IDS_RUNTIME"
sudo cat "$IDS_RUNTIME/classifications.jsonl"
```

Completed JSONL records include experiment ID, model identity, raw six features,
canonical tuple, final logits/scale, label and directional statistics. The UI
shows raw predictions, not proven attack detection. The kernel still monitors
client-scoped TCP on all ports; `--app-port` is collector/experiment metadata,
not a new packet filter or a change to model inputs. Tuple matching uses actual
server ports.

## Shutdown, matching and rollback

Press **Ctrl+C in the launcher terminal**. It drains application work, polls
retained results, saves `kernel_snapshot.json` and `server_classifications.jsonl`,
stops the collector and detaches only its own program IDs. It checks cleanup
and leaves shared clsact in place. It never flushes filters or changes addresses.

```bash
cat "$IDS_RUN/cleanup.json"
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
ip -4 addr show dev enp7s0
ip route show
```

Expect cleanup status PASS, no owned IDS filters and any unrelated filters
preserved. The application listener is owned by this run and stops with it.
No generic qdisc deletion command is needed. Do not use `killall` or kill an
unrelated port owner.

If the launcher terminal died but the recorded collector remains, inspect the
same boot/interface and use the ownership-aware recovery command:

```bash
sudo python3 deployment/ids.py stop --interface enp7s0 --state-dir "$IDS_RUNTIME"
```

Retain failure logs/runtime paths for diagnosis. Never remove a stale runtime
directory merely to bypass a conflict. The controller rejects changed ownership.

Transfer the small Windows `client-...` result folders back by USB or an approved
file-copy workflow, without SSH. After shutdown, match the exact tuple/run:

```bash
python3 demo/evaluate.py --experiment "$IDS_RUN" \
  --client '/path/to/client-ten/client_results.csv' \
  --output "$IDS_RUN/join-ten" --attack-class 1 \
  --label-provenance 'Controlled ordinary benign TCP; no intrusion recall/F1 claim'
```

The exporter preserves missing/invalid predictions as abstentions and reports
coverage separately from benign false positives. No intrusion F1 is invented.

Rollback after targeted stop: launch the same configuration with
`--model original --mode static_q16 --port 9000` and a **new** output directory;
use port 9000 in the Windows command. The original header and weights remain
untouched. If the new lifecycle itself fails, the last committed original-model
launcher is at `73868b101d1c1f5e27c6f71eceaa78a645368445`; inspect it in a separate
checkout/worktree and build there. Preserve current changes; do not reset or
overwrite this working tree. Existing DEMO_HARNESS.md describes that old
original-model/9000 procedure.

For connection refusal, inspect `application.log`, `collector.log`, `ss`, both
TC hooks, selected IP/port and the exact VM revision. For an argument error,
compare `./demo/start_server.sh --help`, `python3 demo/server.py --help` and
`python3 deployment/ids.py --help`; do not forward `--port` directly to the
deployment subcommand, which uses `--app-port` metadata. For model mismatch,
stop; rebuild the selected controller with `make -C tc demo-models CLANG=clang`
and verify the frozen hashes. Never substitute original weights silently.

## Current measured readiness and remaining limits

The isolated fresh/Q16/80 run observed 169 matched ingress packets, 146 egress
packets, 11 retained predictions, stages `[11,11,11,11,11,11]`, and zero
tail/inference/workspace errors. Every configuration completed a single
connection before ten concurrent connections. These counts are WSL2 evidence,
not target counts for the physical network.

The fresh port-80 runs each recorded 3 benign false positives among 11
connections; fresh port-9000 runs each recorded 5/11. The original/Q16/9000
rollback recorded 10/11. These are small separate benign-only observations with
different actual timing/features, not a controlled effectiveness comparison or
intrusion F1 measurement. Do not modify labels or hide these predictions.

This revision has not been tested on the VM's previously observed
6.8.0-138-generic kernel or with Windows Python 3.13. Build from source and run
the one-connection check first. The inference trigger, ingress feature meaning,
offload-dependent packet observations and bounded result retention remain as
documented in tc/README.md. Reusing the same TCP tuple within a retained flow's
lifetime is not a new connection generation; start a new experiment for a clean
map/model session. No hot model replacement is performed.

The five live test runs retained owner/identity records, actual tensors,
classification logs and cleanup evidence. Their temporary raw verifier/model
dump directories were cleaned with the runtime; the separate pilot retains raw
verifier and model-readback files. Inspect those files on the VM while its
collector is running under the recorded `state_dir` if additional archival
evidence is needed. Native visual browser rendering and the full Windows-to-VM
path remain operator verification steps.
