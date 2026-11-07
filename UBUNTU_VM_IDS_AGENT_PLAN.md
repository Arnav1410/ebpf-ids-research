# Agent Execution Plan — eBPF TC-Based IDS Live Demo and Research Validation

**Execution environment:** Ubuntu 22.04 VM (all implementation and local tests run here).  
**Starting point:** The team's actual local project repository, adapting the DSN 2024 `IntelligentDDS/NN-eBPF` baseline.  
**Initial operating mode:** DETECT ONLY. No kernel-side blocking until explicitly approved after validation.  
**Target demo:** Native Windows client on Laptop A → physical Ethernet → bridged Ubuntu VM on Laptop B → TC ingress/egress + in-kernel inference → event collector → live dashboard. WSL is optional, not a Stage 08 prerequisite (operator-approved client-scope change).

## Non-negotiable agent operating rules

1. **Inspect before editing.** Inspect the actual local repository, current branch, uncommitted changes, build scripts, kernel compatibility, model artifacts and test assets. Do **not** invent source filenames, executable names, API signatures, commands, datasets, or existing capabilities. The upstream repository may differ from the team's working copy.
2. **Do not rewrite the existing IDS.** Prefer the smallest reversible changes to the working reference. Keep a reproducible XDP/static-fixed-point baseline, and isolate TC and quantization variants.
3. **Hard gate:** Complete only ONE stage at a time. Run all required checks, capture evidence, and record **PASS** before beginning the next. If a check fails or cannot be performed, mark **BLOCKED**, explain the evidence, and stop progression. Do not silently skip a gate, change the success criterion, or call an untested feature complete.
4. **Distinguish** source compilation, ELF generation, successful BPF verifier loading, successful TC/XDP attachment, packet execution, correct flow statistics, valid NN inference, and end-to-end demo operation. They are different checks.
5. **Safety and reversibility:** Use dedicated test namespaces and veth interfaces first. Never alter default routes, host firewalls, SSH/network-management interfaces, or machine-wide qdiscs as an experiment. Never run attacks on public or unauthorized targets. Do not issue broad `tc qdisc del`, map deletion, `pkill`, or firewall-flush commands. Ask for approval before changing a real/bridged interface, enabling drops, or replacing working model files.
6. **Source control:** Save a baseline commit or snapshot reference. Keep source and tests under version control; avoid committing large binaries, datasets, keys, or machine-specific environment files. Commit after each PASS gate if authorized, otherwise provide a clear diff and commit recommendation. Never overwrite uncommitted user work.
7. **Evidence:** For each stage, create `evidence/stage-NN/` (or a compatible existing structure) with commands, relevant stdout/stderr, exit codes, environment details, test inputs, expected versus observed results, and a concise `gate.md`. Avoid storing secrets or private traffic payloads. Keep an `evidence/INDEX.md` of the latest validated stages.
8. **No fabricated measurements.** Numerical benchmarks, F1, classifier labels, latency and throughput must be measured; if unknown, report `NOT MEASURED`.
9. **Dependency changes:** Inspect and explain package/toolchain changes before installing. Prefer the project's existing pinned libbpf/bpftool and supported Clang combination when feasible; verify versions rather than assuming the VM has a particular kernel or LLVM version.
10. **Mandatory milestone report** at the end of every stage (template at bottom). If blocked, include the smallest safe next diagnostic step, and stop.

## Stage 00 — Environment and repository audit

**Goal:** Learn precisely what exists, which Linux kernel is running, and what is already functioning.

**Work:**
- Inspect repository state, upstream fork relationship, README, Makefiles, git submodules, scripts, source tree, actual model and training assets, generated BPF objects, loader and attach mechanism, maps, hook types, test scripts, and documentation.
- Map the architecture: program entry points; XDP/TC hooks; map definitions and pinning; flow key/value structures; feature extraction; NN tail-call chain; scratch space; weight/scaler generation; inference trigger; user-space control plane.
- Record the current status of *each*: baseline build, verifier, attach, packet processing, training, inference parity, and known issues. An old success statement without evidence is not an automatic PASS.
- Capture the VM network adapters and hypervisor configuration without changing them.

**Diagnostic commands** (run from the *actual* repository root; capture failures too):
```bash
pwd
git status --short --branch
git log -1 --oneline
git submodule status
uname -a
cat /etc/os-release
ip -br address
ip route
clang --version | head -n 1
llvm-config --version
bpftool version
ip -V
tc -V
ls -l /sys/kernel/btf/vmlinux
sudo bpftool feature probe kernel
```
Missing commands are documented as missing, not concealed; use `command -v` and investigate installation requirements.

**PASS gate:** Environment inventory is saved; repository entry points and current build method are identified by actual paths; kernel/BTF/BPF tool compatibility and permissions are known; active user changes are preserved; a reversible implementation/rollback approach is written.

## Stage 01 — Reproduce and lock the existing baseline *before modifications*

**Goal:** Establish reference implementation behavior on the VM without pretending compilation equals real runtime reproduction.

**Work:**
- Build the project's existing baseline using the *actual* build instructions/toolchain. Record warnings and exact commands. Do not substitute unverified generic `make` targets.
- Run existing unit/offline tests or create a small independent oracle if tests are absent. Preserve baseline artifacts, model parameters, scaler and known-good inputs/outputs.
- Where supported, perform BPF loading/verifier and attach checks on a safe test interface. If live packet testing requires the namespace topology from Stage 02, explicitly defer that portion to Stage 02 and do not claim the live baseline has been reproduced.
- Record architecture and expected offline/in-kernel outputs for a documented small input vector. Separate float PyTorch output, reference integer output, and actual kernel output.

**PASS gate:** Baseline source builds reproducibly; any offline reference tests used pass; BPF load/verifier evidence is captured where possible; reference commit hash, test vectors and artifact provenance are documented. Unresolved critical baseline build/verifier errors = BLOCKED. **Full live baseline reproduction remains pending until Stage 02.**

## Stage 02 — Build isolated single-VM networking and finish live baseline check

**Goal:** Make two isolated Linux endpoints using namespaces and a veth pair; verify real packets cross the protected interface, without touching VM management networking.

**Example topology:** `ids_client` (`10.203.0.1/24`, `veth-idsc`) ↔ `ids_server` (`10.203.0.2/24`, `veth-idss`). The server namespace models the protected Ubuntu host. These names/addresses are dedicated examples; check for conflicts before running.

**Example setup commands** (run once, after checking namespaces/interfaces do not exist):
```bash
sudo ip netns add ids_client
sudo ip netns add ids_server
sudo ip link add veth-idsc type veth peer name veth-idss
sudo ip link set veth-idsc netns ids_client
sudo ip link set veth-idss netns ids_server
sudo ip -n ids_client addr add 10.203.0.1/24 dev veth-idsc
sudo ip -n ids_server addr add 10.203.0.2/24 dev veth-idss
sudo ip -n ids_client link set lo up
sudo ip -n ids_server link set lo up
sudo ip -n ids_client link set veth-idsc up
sudo ip -n ids_server link set veth-idss up
sudo ip netns exec ids_client ping -c 3 -W 2 10.203.0.2
sudo ip netns exec ids_server ping -c 3 -W 2 10.203.0.1
```
Optionally verify controlled TCP using `iperf3` or a simple HTTP service: bind the server to `10.203.0.2`; run a client in `ids_client`. Inspect packet traces on both namespaces if needed; keep capture sizes bounded.

**Finish the baseline runtime check:** Attach the original program to the safe veth interface *if its hook type is supported there*, run known test flows, inspect actual per-flow state and inference evidence, then detach. If the baseline is incompatible with the VM/veth test hook, report the precise technical blocker and seek a safe supported alternative; no fabricated results or silent skipped reproduction.

**PASS gate:** Both ping directions work (zero packet loss in short controlled smoke tests or fully explained loss); a TCP request/response traverses veth; the original baseline has demonstrably loaded/attached/processed representative traffic and produced expected recorded state, or a previously verified equivalent baseline runtime result exists with reproducible evidence. No changes to the VM's management interface.

**Safe teardown of owned test topology:** `sudo ip netns del ids_client` and `sudo ip netns del ids_server` after stopping only the processes started for these tests. Deleting namespaces removes their owned veth endpoints. Do not delete unrelated namespaces.

## Stage 03 — Minimal TC ingress/egress probe (no NN yet)

**Goal:** Validate the selected TC hook itself before adapting complex inference code.

**Work:**
- Create a minimal `BPF_PROG_TYPE_SCHED_CLS` implementation that safely returns `TC_ACT_OK` and increments **separate ingress and egress counters**. Use one object with two entry points or another explicit arrangement consistent with the project's loader.
- Attach both hooks to `veth-idss` **inside `ids_server`** using `clsact` and the confirmed loader/TC tool syntax. Keep detection-only/pass behavior.
- Use `tc -s` and `bpftool`/map reads to confirm load, verifier acceptance, attach and actual execution. Run ping/controlled TCP in both directions. Inspect per-hook counters before and after a known activity window.
- Write an idempotent scoped detach/cleanup script that removes only the filters/qdisc created for `veth-idss`; avoid deleting unrelated TC configuration.

**Useful observations** (only after actual attachment):
```bash
sudo ip netns exec ids_server tc -s filter show dev veth-idss ingress
sudo ip netns exec ids_server tc -s filter show dev veth-idss egress
sudo bpftool prog show
```

**PASS gate:** Both TC programs compile, pass the verifier, attach and are visible; each direction's own counter rises when expected; packets still pass; repeated attach/detach does not leak owned programs/maps or damage connectivity.

## Stage 04 — Correct bidirectional flow tracking and concurrency

**Goal:** Have ingress and egress events update **one logical bidirectional flow**, safely under concurrent execution.

**Work:**
- Inventory the reference's RX-only six features. Define a shared, canonical key (protocol + endpoint IP/port pair, with interface/namespace context as needed) so reversed endpoints match the same connection; retain an explicit client/server or initiator orientation so `fwd` and `bwd` remain meaningful.
- **Do not mistake TC ingress/egress for universally equivalent dataset `fwd`/`bwd`:** document the protected host's perspective and whether a SYN was observed. If no SYN was observed, mark orientation as unknown rather than guess.
- Initially support and test IPv4 TCP (and UDP only if separately implemented); handle bounds checks, variable IPv4/TCP header sizes, truncated packets, VLAN, fragments, IPv6 and unsupported protocols explicitly: either implement or reject/skip safely with counted reasons. Never read past `data_end`.
- Maintain direction-specific packet/byte/header/timing fields, per-flow timestamps, flow lifecycle state and cleanup/expiration. Handle duplicate/retransmitted packets under a documented counting policy.
- Handle SYN, FIN half-close, RST, idle timeout, UDP termination policy, and the case of no observed close. Do not claim FIN from one side means both directions are completely closed.
- Prevent data races: atomic counters where adequate; short guarded critical sections for compound updates if suitable; review map value locking and lock restrictions. Never hold a BPF spin lock across helper calls or tail calls. Ensure each flow's temporary NN inference state cannot be overwritten by another flow/CPU.
- Implement a small user-space inspection or dump utility.

**PASS gate:** For controlled traces, both directions resolve to one flow ID, packet direction is correct, counts/bytes/timestamps match a separately captured reference at the defined skb or packet granularity, independent concurrent connections never share statistics, and repeated multi-flow tests do not show missing updates, stale entries, data races, unexpected map growth or kernel errors. Document GRO/GSO/TSO/offload differences rather than claiming wire-packet exactness if not established.

## Stage 05 — Bring the existing neural network inference to TC

**Goal:** Reuse the working integer model and inference chain rather than introducing a new ML design prematurely.

**Work:**
- Use the original six RX-only features and existing trained/scaled model **first**, preserving their exact definition and order. Do not silently feed new bidirectional features into weights trained for the RX-only feature vector.
- Port the existing NN invocation/flow-end trigger to the verified TC flow path. Preserve tail-call sequence and carefully validate scratch storage, parameter maps, scaling, signed shifts, accumulation width and return behavior.
- Build a deterministic reference harness: compare float model → host-side fixed-point implementation → in-kernel outputs for the same feature vectors. Include negative values, near-zero weights, overflow-boundary inputs, and both classification classes.
- Capture model hash/version, feature schema version and quantization factors alongside every test run.

**PASS gate:** Model programs compile, load, pass verifier and execute on observed flows; final logits or a documented equivalent intermediate representation agree with the fixed-point oracle under a predeclared tolerance; classification parity is measured on a nontrivial labeled set; all mismatches are explained; no unexplained overflows, map races or stale state. **Only then** call TC+NN functional. Note: matching the original trained model does not prove bidirectional accuracy gains.

## Stage 06 — Kernel-to-user event pipeline

**Goal:** Export inference events without putting the dashboard into the packet-processing path.

**Work:**
- Inspect any existing output mechanism first. If an event channel is needed, choose a kernel-supported BPF ring buffer or existing perf event pipeline; use fixed, versioned event structures with explicit endian and integer-width conventions.
- Emit small records (timestamp, flow ID/endpoints, direction counts, prediction, optional logits and timing, model version, termination reason); **do not** stream every packet or copy arbitrary payloads to the UI.
- Implement a user-space collector and a bounded event queue; track event submission failures, consumer drops and collector restarts. Keep packet forwarding/detection alive if user-space stops consuming events.
- Store a small local replayable JSONL sample for frontend testing. Never let frontend or collector decide the model's inference result.

**PASS gate:** For known completed flows, each classification is emitted and decoded correctly; expected fields match BPF map state; burst/restart tests do not crash the kernel program or block packets; events have stable schema, and measured losses (if any) are visible rather than hidden.

## Stage 07 — Live dashboard (after kernel pipeline is independently verified)

**Goal:** Deliver a simple, honest presentation UI.

**Work:**
- Backend: minimal FastAPI or existing framework; provide `/health`, `/summary`, `/flows`, `/events` endpoints and WebSocket/SSE only if useful. Pull flow snapshots from collector-side state and push classification events. Bind to localhost initially; configurable network exposure later.
- Frontend: React or simplest maintainable equivalent. Show network/hook status, RX/TX rates, active flows, flow details, last prediction and model version, benign/intrusion count, event table and collector event-loss status.
- Clearly label **pending / unclassified active flows** versus completed flows with model inference. No invented predictions, F1 or timestamps. Do not mistake a UI-level synthetic alert for a kernel-generated inference.
- Add a **demo replay mode** consuming known fixture events, visibly marked simulated. Keep separate from live mode.

**PASS gate:** UI opens, updates under controlled real traffic, agrees with saved collector events/map snapshots, survives collector restart or network loss with a visible disconnected status, and can replay fixture data reproducibly. With UI stopped, eBPF tests still pass.

## Stage 08 — Two-laptop Ethernet integration (separate approval gate)

**Goal:** Use physical traffic from a native Windows client to the Ubuntu VM without risking connectivity during the demo. Packet generation does not require WSL; inference remains in the Ubuntu kernel.

**Prerequisite:** Confirm with the operator that the VM hypervisor supports bridging to the **wired** Ethernet adapter; ensure adequate permissions and a working snapshot/rollback. Configure static *demo-only* addresses or predictable DHCP reservations on the Ethernet segment; determine actual adapter names/IPs by inspection. Avoid using the VM management NIC until the route and remote-access impact are understood.

**Work:**
- Discovery/configuration milestone: run standalone `test_env/discover-host.sh` on the Linux virtualization host and `test_env/discover-windows.ps1` on native Windows; import their versioned reports with `python -m test_env.configure`. Use actual changing identities/IPs, clear stale targets, and preserve management/default-route guards. These are read-only discovery plus local `.env` updates, not network setup or attachment permission.
- Recovery/setup milestone: inspect actual disk driver/memory/free space and snapshot/checkpoint inventory; establish VM/console recovery plus exact host/Windows undo steps. Preserve the observed host `.77.1` address and operator-retained `.77/24` intent unless a later explicit change is approved. Do not treat proposed peer addresses as observed values.
- Start with native Windows client ↔ VM basic ICMP and TCP connectivity, then controlled native TCP exchanges. Verify the actual packets and source address on the VM interface before any eBPF attachment. WSL-origin traffic is optional and outside the required acceptance path.
- Attach TC ingress and egress to the VM's verified **bridged guest interface**, not to a guessed port/IP; document ifindex, addresses, tool commands and rollback.
- Generate only authorized, contained traffic: `iperf3`, `curl`, an SSH login to a lab account, short controlled connection bursts and locally owned negative-case fixtures if available. Prefer scripted labeled demo traffic to uncontrolled attacks.
- Check both directions: source client→VM and VM→client; compare what VM TC observes to guest tcpdump and namespace tests, accounting for VM NIC offloading.
- Use the dashboard on the VM or via a deliberately opened authorized port; keep backend authentication/network exposure minimal and documented.

**PASS gate:** The native Windows client can reach the VM service as expected; real packets reach the correct TC hooks; at least one known benign flow produces an **actual** in-kernel inference event and correct UI record; labeled negative-case traffic is demonstrated only if a matching trained model/ground truth exists; rollback restores original networking. No claim of demonstrated attack detection without genuine labeled evidence. WSL execution is not required.

## Stage 09 — Research evaluation and reproducible benchmark

**Goal:** Produce defensible comparisons, not just a polished demo.

**Work:**
- Freeze a common test dataset, traffic scripts, ground-truth labels, VM resource allocation, model artifacts, kernel, NIC/offload settings and software versions. Distinguish CIC-IDS-2017 offline evaluation from newly generated real-time traffic and guard against train/test leakage.
- Compare: (A) original XDP + static `2^16` fixed-point inference; (B) TC + same RX feature/model definition; (C) TC with properly retrained bidirectional features; (D) TC with layer-specific fixed-point factors, keeping model/features otherwise identical to the intended comparator. Label infeasible cells explicitly; do not pretend an RX-only XDP model receives TX features.
- For layer-specific scaling, choose factors using offline calibration and documented range/overflow analysis; define exact inter-layer rescale/rounding semantics. Check multiply/accumulate maximums, signed shift behavior and quantization-error distribution. Compare against host float and integer oracles before any F1 claim.
- Measure, rather than assume: accuracy, precision, recall, F1, confusion matrix, classifier parity, feature correctness, inference latency distribution (median, p95, p99), CPU cost, map memory, throughput, event loss and performance across concurrency levels. Repeat trials and report dispersion/environment.
- Compare warm versus cold paths and explicitly report whether the benchmark includes packet feature extraction, model execution, user-space event collection and dashboard. Do not mix these durations.

**PASS gate:** There is a re-runnable experiment script/config, immutable variant identifiers, raw data, analysis code and a result table with transparent methods; all computed metrics are backed by logs/labels. A perceived improvement without controlled evidence is recorded only as a hypothesis.

## Stage 10 — Optional only: mid-flow classification and prevention

**Do not start automatically.** Requires approval after Stage 09. For mid-flow detection, define a measurable window/packet threshold, retrain on partial-flow features and measure detection lead time and overhead. For prevention, use an explicit operator opt-in, protected management-network exceptions, rollback and false-positive tests. Never turn on blocking by default.

## Mandatory report format after every stage

```text
STAGE: NN — <name>
STATUS: PASS | BLOCKED
BASE COMMIT / DIFF: <hash or paths>
CHANGES: <brief, exact>
COMMANDS EXECUTED: <actual commands, not suggestions>
BUILD: PASS | FAIL | NOT APPLICABLE
VERIFIER LOAD: PASS | FAIL | NOT TESTED
ATTACH: PASS | FAIL | NOT TESTED
RUNTIME PACKET TEST: PASS | FAIL | NOT TESTED
CORRECTNESS TEST: PASS | FAIL | NOT TESTED
EXPECTED VS OBSERVED: <short quantified details>
EVIDENCE: evidence/stage-NN/<actual paths>
CLEANUP / ROLLBACK CHECK: PASS | FAIL
GATE DECISION: PASS | BLOCKED
NEXT ACTION: <next stage only if PASS; otherwise specific remediation>
```

## First instruction to execute NOW

**Begin at Stage 00 only.** Produce the audit and baseline compatibility report; do not modify the code or networking until the repository and VM have been inspected. Report the Stage 00 gate with evidence. Move to Stage 01 only if Stage 00 passes.

## Reference material (verify against the machine and code)

- DSN 2024 baseline: https://github.com/IntelligentDDS/NN-eBPF
- TC eBPF classifier manual: https://man7.org/linux/man-pages/man8/tc-bpf.8.html
- Linux veth namespaces: https://man7.org/linux/man-pages/man4/veth.4.html
- libbpf BPF app lifecycle: https://docs.kernel.org/bpf/libbpf/libbpf_overview.html
- Kernel BPF ring buffer: https://docs.kernel.org/bpf/ringbuf.html
- Optional WSL networking reference (not required for Stage 08): https://learn.microsoft.com/en-us/windows/wsl/networking
