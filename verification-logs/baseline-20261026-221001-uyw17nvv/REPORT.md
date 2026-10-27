# Existing-baseline execution verification — 26 October 2026

The original checkout builds successfully. Its unprivileged smoke-test preflight fails because the session cannot open a netlink socket. No BPF program was loaded or attached and no test networking was created. Runtime baseline execution remains unverified. No claim about numerical correctness, classification accuracy, or performance follows from this verification.

## Environment

| Item | Observed value |
| --- | --- |
| Commit | `18f855b1ea41500be31a4bd5e2507d17a75dee9b` |
| Initial tracked working tree | Clean; final tracked and staged diffs also empty |
| OS | Ubuntu 22.04.5 LTS, x86-64 |
| Running kernel | `6.6.87.2-microsoft-standard-WSL2` |
| Virtualization identification | `systemd-detect-virt`: `wsl` |
| User | `uid=1000(arnav)`, non-root |
| Detector compiler | Ubuntu clang `12.0.1-19ubuntu3`; BPF backend listed |
| Dependency C compiler | GCC executable `11.4.0` |
| GNU Make | 4.3 |
| Built bpftool | `v7.3.0`, `using libbpf v1.3`, `features: libbfd` |
| Vendored detector and bpftool libbpf | 1.3.0, from both source Makefiles; detector linked with locally built static archive |
| libelf / zlib | 0.186 / 1.2.11, development packages installed |
| Python / Bash / iproute2 | 3.10.12 / 5.1.16 / 5.15.0 |
| Kernel BTF | `/sys/kernel/btf/vmlinux` readable; dumped successfully during build |
| Effective/permitted/bounding capabilities | All zero in this session |
| Restriction indicators | `NoNewPrivs: 1`, `Seccomp: 2` |
| bpffs target | `/sys/fs/bpf` resolves to read-only `sysfs`, not a mounted `bpf` filesystem |
| tracefs | Read-only mount; trace directory/pipe inaccessible to this user |
| Isolation | Session shares network namespace with PID 1; a separate suitable runtime test environment was not established |

`ip -Version` reports its own libbpf 0.5.0, which is distinct from the detector/bpftool build's libbpf 1.3.0. A system `libbpf-dev` package and system bpftool were not needed because vendored sources built successfully.

Required build facilities are Make, a host C compiler/binutils, clang-12 with the BPF target, libelf/zlib development files, the vendored libbpf/bpftool trees, x86-64 headers, and readable kernel BTF. The runner additionally uses Bash, Python standard library, iproute2, GNU coreutils, and util-linux (`flock`, `findmnt`). Runtime needs permitted BPF and network-namespace operations, mounted bpffs, and enabled/readable tracing inside an isolated Linux test environment. Optional bpftool libcap/libbfd development support was installed; optional LLVM and clang-BPF-CO-RE feature probes reported OFF without preventing the build. No packages were installed during this verification.

## Inspection and commands

No repository-root README, README.md, or README.rst exists. Inspected both project Makefiles, BASELINE_SUMMARY.md, the complete runner, loader, BPF inference code, model maps/header, updater, feature handler, arithmetic helpers, and training/quantization sources. Also inspected dependency build rules and their READMEs. `inspection.log` preserves file contents and source hashes.

The following were executed as the ordinary user from the repository root, in this order for the build/test workflow:

```sh
bash -n run-baseline.sh
./run-baseline.sh --help
make
.output/bpftool/bpftool version
make -C src
./run-baseline.sh --check --log-dir /home/arnav/research/ebpf-ids-research/verification-logs/baseline-20261026-221001-uyw17nvv/preflight
```

Each operation was wrapped by `python3 /tmp/ebpf-baseline-record-command.py LOG_DIRECTORY LABEL COMMAND [ARGUMENTS...]` to save combined stdout/stderr and exit status. A copy of the wrapper is `record-command.py`. `commands.txt` gives the exact recorded invocations, including complete environment/inspection/diagnostic shell scripts. `commands.jsonl` records argv, cwd, timestamps in Asia/Kolkata, and exit status. The runner's own nested commands are also present in `preflight/run.log`.

Initial read-only reconnaissance preceded the recorder; environment/source inspection was repeated into the saved logs. No sudo, package installation, mount, sysctl change, BPF load/unload, interface mutation, commit, or push was executed.

## Privileged/destructive operations in the existing runner — inspected, NOT executed

The runner starts with collision/route/pin checks and takes `/run/nn-ebpf-baseline.lock` before lab creation. Its mutation scope is:

| Resource | Planned action |
| --- | --- |
| Namespace `ids-client` | Create with `ip netns add`; delete on cleanup |
| Veth `ids-server` | Create in the host namespace, assign `33.33.33.1/24`, bring up, attach XDP ingress, delete on cleanup |
| Veth peer `ids-client0` | Move into `ids-client`, assign `33.33.33.73/24`, bring up; deletion of the veth pair removes it |
| Loopback in `ids-client` | Bring up; host loopback is not configured |
| Connected/local routes | Added implicitly by those addresses; host gains the `33.33.33.0/24` connected route; no explicit route replacement |
| `xdp_prog` | Load and attach to `ids-server` only using `bpf_program__attach_xdp` |
| Six XDP tail-call programs | Load `xdp_preprocessing`, `xdp_input_linear`, `xdp_input_relu`, `xdp_hidden_linear`, `xdp_hidden_relu`, `xdp_output_linear`; populate `progs` slots 0–5 |
| Map `progs` | New program array, up to 1,024 entries; six populated |
| Map `flow_map` | New hash map, up to 8,192 flow records; controlled test updates this map |
| Map `nn_parameters` | New two-slot parameter array pinned at `/sys/fs/bpf/nn_parameters`; updater fills inactive slot |
| Map `nn_idx` | New one-entry index array pinned at `/sys/fs/bpf/nn_idx`; loader selects 1 and first successful updater selects 0 |
| Map `xdp_bpf.rodata` | New internal read-only map for trace format strings, identified in the generated skeleton |
| TCP socket | Listener `33.33.33.1:5001`; client binds `33.33.33.73`, sends `hello\n`, sends FIN, and expects `baseline-ok\n` |
| Trace stream | Opens and consumes shared kernel `trace_pipe`, including draining historical records; does not clear/reconfigure tracing |
| Processes | Sends SIGINT to its loader, SIGTERM to its trace/server children; may SIGKILL those recorded children after timeout |
| Pins on cleanup | Original loader unconditionally attempts removal of its two fixed pin paths; runner only removes residual pins with matching recorded IDs |
| Other files | Creates log directory/helper/readiness markers and lock file; deletes its helper/markers; may chown newly created logs to the sudo invoking user |

Generated skeleton inspection confirms exactly seven BPF programs and five maps. Only the entry program attaches to an interface; the other six are reached through tail calls. No existing BPF object is intentionally reused: preflight rejects existing model pin paths. Existing names and non-default overlapping IPv4 routes are rejected. The loader defaults to `ens3` if invoked without arguments, but the runner explicitly supplies `ids-server`; the bare loader was not run.

The script does not configure physical/production interfaces, change default routes, flush firewall rules, modify sysctls, or use a generic-XDP fallback. Nevertheless, its connected route, globally pinned map names, and shared trace consumption require an isolated host without a concurrent detector/updater/trace reader. Its lock only coordinates this runner. This is a source-level scope assessment, not confirmation of live host isolation.

## SSH / production-interface safety

Live links, addresses, namespaces and routes could not be inspected: every netlink query was denied. No SSH environment variables were present, which does not prove that production connectivity is absent. Accordingly, noninterference with live SSH/production traffic could not be certified. The privileged test was not attempted and no privilege escalation was requested. There is no basis for claiming a dedicated isolated VM merely from the WSL identification.

No command executed during this verification changed network configuration or attached/detached BPF. No runtime action awaits blanket approval on the current unsuitable environment. Before a future privileged invocation, confirm a suitable isolated Linux VM, inspect its live state, and obtain the user's approval for the exact runner command.

## Results

| Check | Result | Evidence / limitation |
| --- | --- | --- |
| Runner syntax and help | PASS | `script-syntax.log` (empty output, exit 0), `runner-help.log` |
| Vendored dependency build (`make`) | PASS | `build-dependencies.log`, exit 0 |
| Detector/updater build (`make -C src`) | PASS | `build-detector.log`, exit 0; fresh build from absent output directories |
| Compiler warnings | PASS | No compiler warning/error/fatal diagnostics in either build log |
| Build freshness | PASS | Runner advanced beyond `make -C .../src -q` |
| BPF object/skeleton generation | PASS | `xdp.bpf.o` is an eBPF ELF; skeleton lists seven programs/five maps; offline evidence only |
| Unprivileged preflight | FAIL | Exit 1 on `ip -j link show`; denied netlink socket |
| Suitable isolated runtime / live SSH safety | NOT RUN | Could not establish/inspect with available access |
| Kernel verifier acceptance | NOT RUN | No BPF load performed; compilation is not kernel verification |
| XDP attachment and actual hook/mode | NOT RUN | No loader execution |
| Parameter loading / active-slot switch / 5,216-byte comparison | NOT RUN | Updater never executed |
| Tail-call map population and actual execution | NOT RUN | No BPF load or controlled traffic |
| Controlled TCP exchange | NOT RUN | No lab network or listener |
| Prediction/timing output | NOT RUN | No inference was executed |
| Runtime detach/map/network cleanup verification | NOT RUN | No runtime resources created |
| Preflight temporary-file cleanup | PASS | Trap completed, generated helper removed; `preflight/` retains only `run.log` |
| Tracked/staged source integrity | PASS | Both `git diff --exit-code` and `git diff --cached --exit-code` returned 0 |

The stop condition was the preflight failure. No workaround, source modification, alternate attachment mode, or privileged runtime attempt followed it. Subsequent commands only inspected artifacts and recorded the diagnosis.

## Relevant actual output

Build version output:

```text
bpftool v7.3.0
using libbpf v1.3
features: libbfd
```

The detector build emitted and completed the original commands:

```text
make: Entering directory '/home/arnav/research/ebpf-ids-research/src'
mkdir -p "/home/arnav/research/ebpf-ids-research/src/.output"
/home/arnav/research/ebpf-ids-research/.output/bpftool/bpftool btf dump file /sys/kernel/btf/vmlinux format c > /home/arnav/research/ebpf-ids-research/src/.output/vmlinux.h
clang-12 -g -O3 -target bpf -I/home/arnav/research/ebpf-ids-research/src/.output -I/home/arnav/research/ebpf-ids-research/.output/libbpf/usr/include -I/home/arnav/research/ebpf-ids-research/libbpf/include -I/usr/include/x86_64-linux-gnu/ -c xdp.bpf.c -o /home/arnav/research/ebpf-ids-research/src/.output/xdp.bpf.o
/home/arnav/research/ebpf-ids-research/.output/bpftool/bpftool gen skeleton /home/arnav/research/ebpf-ids-research/src/.output/xdp.bpf.o > /home/arnav/research/ebpf-ids-research/src/.output/xdp.skel.h
clang-12 -O3 -g -Wall -I/home/arnav/research/ebpf-ids-research/src/.output -I/home/arnav/research/ebpf-ids-research/.output/libbpf/usr/include -I/home/arnav/research/ebpf-ids-research/libbpf/include -I/usr/include/x86_64-linux-gnu/ -c xdp.c -o /home/arnav/research/ebpf-ids-research/src/.output/xdp.o
clang-12 -O3 -g -Wall -lelf -lz /home/arnav/research/ebpf-ids-research/src/.output/xdp.o /home/arnav/research/ebpf-ids-research/.output/libbpf/libbpf.a -o /home/arnav/research/ebpf-ids-research/src/.output/xdp
clang-12 -g -Wall -lelf -lz -I/home/arnav/research/ebpf-ids-research/src/.output -I/home/arnav/research/ebpf-ids-research/.output/libbpf/usr/include -I/home/arnav/research/ebpf-ids-research/libbpf/include -I/usr/include/x86_64-linux-gnu/ hot_updating.c /home/arnav/research/ebpf-ids-research/.output/libbpf/libbpf.a -o /home/arnav/research/ebpf-ids-research/src/.output/hot_updating
make: Leaving directory '/home/arnav/research/ebpf-ids-research/src'
```

Preflight:

```text
[2026-10-26T22:12:18+0530] Baseline log directory: /home/arnav/research/ebpf-ids-research/verification-logs/baseline-20261026-221001-uyw17nvv/preflight
[2026-10-26T22:12:18+0530] Kernel: 6.6.87.2-microsoft-standard-WSL2; repository: /home/arnav/research/ebpf-ids-research
[command] make -C /home/arnav/research/ebpf-ids-research/src -q
[command] /home/arnav/research/ebpf-ids-research/.output/bpftool/bpftool version
bpftool v7.3.0
using libbpf v1.3
features: libbfd
[command] python3 /home/arnav/research/ebpf-ids-research/verification-logs/baseline-20261026-221001-uyw17nvv/preflight/helper.py preflight
Cannot open netlink socket: Operation not permitted
ERROR: Command '('ip', '-j', 'link', 'show')' returned non-zero exit status 1.
[2026-10-26T22:12:18+0530] ERROR: line 79: "$@" (exit 1)
[2026-10-26T22:12:18+0530] Cleaning up lab resources.
[2026-10-26T22:12:18+0530] RESULT: FAIL (exit 1)
[2026-10-26T22:12:18+0530] Logs: /home/arnav/research/ebpf-ids-research/verification-logs/baseline-20261026-221001-uyw17nvv/preflight
```

Both compilation logs have no compiler warning/error diagnostics. A later offline `readelf` inspection emitted repeated warnings `unable to apply unsupported reloc type 10` and `type 1` to `.debug_info`; these are preserved in `final-diagnostics.log`. They occurred in the host inspection tool after the successful build and do not establish either a kernel verifier failure or success. The object/skeleton were generated successfully by the repository's own bpftool.

## Cleanup and retained evidence

The failed `--check` invoked the runner's EXIT trap, which removed its generated helper and readiness paths. It had not reached lock acquisition, namespace creation, veth creation, trace capture, loader invocation or updater invocation, so no BPF/network detachment or pin removal was performed. No mount or sysctl cleanup was needed. We did not run `make clean`: `.output/` and `src/.output/` are retained for inspection along with artifact SHA256 hashes in `final-diagnostics.log`.

The only untracked addition reported by git is `verification-logs/`. Existing tracked files, parameters, and training data are unchanged. No commits/pushes were made. The local command-recording helper in `/tmp` was copied into this evidence directory; it is not a detector/source change.

## Outstanding issues and minimal required change

1. Immediate blocker: this restricted session denies netlink sockets, so even the unprivileged safety preflight cannot list links. Use an isolated test VM/session that permits the required inspection and, after approval, network-namespace/BPF operations. Retrying sudo within the current no-new-privileges/capability-restricted environment is not an established remedy.
2. Independent runtime prerequisites: bpffs is not mounted at `/sys/fs/bpf`, and tracefs is read-only/inaccessible here. Prepare those facilities in the isolated VM, with separate approval before configuration changes; this verification did not mount filesystems or alter tracing.
3. Root-only checks of existing BPF programs, pins, and ownership remain unperformed. Existing pin absence cannot be certified from this unprivileged restricted session.
4. The metadata diagnostic `git submodule status --recursive` exited 128: `fatal: no submodule mapping found in .gitmodules for path 'dataset-instance/intrusion/DVMA/brute-force'`. This pre-existing metadata issue did not prevent either build; no submodule repair or checkout update was attempted.
5. Historical success recorded in BASELINE_SUMMARY.md concerns another kernel/environment and is not evidence of this invocation's runtime success.

No source change is required by the observed preflight failure. The minimal next action is to move the unchanged baseline to a suitably configured isolated Linux VM and obtain explicit approval before running the existing privileged smoke test. Runtime kernel acceptance/attachment mode must be established there; support has not been assumed from the WSL version.

## Next validation step

First complete this same execution verification in the isolated VM: review live links/routes/pins, run the non-root/root prerequisite checks, and obtain approval before the privileged smoke run. Preserve `detector.log`, map/program IDs, all six tail-call entries, active-slot bytes, TCP logs, final-stage trace, and post-run cleanup state. Stop and report any verifier/runtime/cleanup failure without automatically changing source.

Only after execution passes, the next independent correctness validation would compare deterministic packet-derived features and every integer layer against a bit-accurate reference. That work, classification-accuracy evaluation and performance reproduction were outside this task and were not performed.
