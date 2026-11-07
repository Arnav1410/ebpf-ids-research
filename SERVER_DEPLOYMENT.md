# Native Linux server deployment — operator controlled, no SSH

Development happens on Windows/WSL2. Execute this runbook yourself on the native
Linux laptop; Codex does not remotely operate it. The existing Ethernet settings
are **enp8s0 = 192.168.77.1/24**, Windows **192.168.77.2/24**. Inspect them; do not
reconfigure them. Native compatibility and the two-laptop experiment remain
**PENDING USER EXECUTION** until actual server evidence is recorded.

The transfer branch is `feature/native-deployment-dashboard` at
`https://github.com/Arnav1410/ebpf-ids-research.git`. Compare the revision printed
below with the final verified commit supplied in the development report. The
developer must manually push that exact commit first; uncommitted/untracked
files do not transfer through GitHub. The previous verified arithmetic checkpoint
is `a99394b`; the original bidirectional baseline is
`791e25932e01a8e457c81237fdc8da2ea971b32e`.

## C1. Inspect the native laptop before changing anything

Run these in a Linux terminal, before installing packages or attaching programs:

```bash
cat /etc/os-release
uname -a
uname -m
command -v clang clang-12 llvm-objdump gcc make python3 git tc ip pkg-config
clang --version
llvm-objdump --version
gcc --version
make --version
python3 --version
pkg-config --modversion libbpf
findmnt /sys/fs/bpf
test -r /sys/kernel/btf/vmlinux && ls -lh /sys/kernel/btf/vmlinux
grep -E 'CapEff|CapBnd|NoNewPrivs|Seccomp' /proc/self/status
ip -details link show dev enp8s0
ip -4 addr show dev enp8s0
ip route show
tc -j qdisc show dev enp8s0
tc -j filter show dev enp8s0 ingress
tc -j filter show dev enp8s0 egress
```

Missing optional commands may fail here; record that fact. Expect an UP Ethernet
interface and the existing `192.168.77.1/24` address. If they differ, stop and
report the output instead of running address/route/NetworkManager commands.
The verified development architecture is x86_64, little endian. Other native
architectures/compiler combinations need their own validation.

After building the repository tool, an optional deeper kernel feature probe is:

```bash
sudo .output/bpftool/bpftool feature probe kernel
```

This probe temporarily loads feature-test BPF programs; it is an explicit
privileged operator action, not part of read-only preflight. Look for sched_cls,
hash/array/percpu_array/prog_array, tail calls, skb byte reads and spin locks.
The final loader/verifier result is authoritative. Do not upgrade the kernel
based only on a missing userspace command. Kernel BTF is required. bpffs mounting
is not needed by this deployment: all IDS maps are private and unpinned.

## C2. Ubuntu prerequisites and native build

Only use the following package commands if `/etc/os-release` identifies Ubuntu.
For another distribution, report its version and translate the packages first.

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends build-essential gcc make clang llvm \
  libelf-dev zlib1g-dev pkg-config libcap2-bin iproute2 util-linux python3 git ca-certificates file
```

No system Python packages or frontend package manager are required. The collector
and dashboard use Python's standard library (Python 3.10+). The project builds
its vendored libbpf 1.3 and bpftool; an absent/older system libbpf does not by
itself require a system-library upgrade. `libelf` and zlib development files
are needed for linking. LLVM's BPF backend must be present.

Build from a fresh source checkout as your ordinary user, **without sudo**:

```bash
make -j2 CLANG=clang
make -C tc layer-specific CLANG=clang
.output/bpftool/bpftool version
grep -E 'LIBBPF_(MAJOR|MINOR)_VERSION' libbpf/src/libbpf_version.h
file tc/.output/controller tc/.output/controller_layer tc/.output/tc_ids.bpf.o
python3 -m unittest -v deployment.tests.test_dashboard
```

These commands generate `tc/.output/vmlinux.h` from this native kernel's BTF.
Do not copy WSL2 `.output`, `.so`, executables or BPF objects. The Makefile uses
the native GCC multiarch include directory; `CLANG=clang` explicitly overrides
the development default `clang-12`. A different compiler/kernel is **not yet
verified**. If compilation or kernel loading fails, preserve its output and
stop; do not disable verifier checks, alter trained parameters, change sysctls
or reinstall the kernel as a guessed fix. The kernel needs the TC cls_bpf/clsact
features and spin-lock/helper support used by the unchanged inference object.

## C3. Transfer through GitHub HTTPS

On the WSL development laptop, inspect and manually push the completed reviewed
deployment commit, once the development report identifies it:

```bash
git status --short
git log -3 --oneline
git push -u origin feature/native-deployment-dashboard
```

Do not push an incomplete verification milestone as a completed deployment.
Do not add unrelated files or the unrelated `myshell` deletion. No automated
push is performed by this project.

On the **native Linux laptop**, clone using HTTPS authentication (GitHub PAT or
your local credential manager; never place a token in the URL or paste it into
logs). Use a fresh directory and source-only sparse checkout:

```bash
git clone --filter=blob:none --no-checkout https://github.com/Arnav1410/ebpf-ids-research.git ~/ebpf-ids-demo
cd ~/ebpf-ids-demo
git fetch origin feature/native-deployment-dashboard
git sparse-checkout init --no-cone
git sparse-checkout set --no-cone '/tc/' '/deployment/' '/dashboard/' '/quantization/' \
  '/src/' '/validation/' '/libbpf/' '/bpftool/' '/Makefile' '/run-tc-smoke.sh' '/run-baseline.sh' \
  '/.gitignore' '/BASELINE_SUMMARY.md' '/SERVER_DEPLOYMENT.md' '/DEMO_RUNBOOK.md' \
  '/DEPLOYMENT_STATUS.md' '/dataset/reproduction-xdp-data.npy' \
  '/verification-logs/layer-specific-20261107/host_results.json' \
  '/verification-logs/layer-specific-20261107/numerical_metrics.json'
git switch --detach origin/feature/native-deployment-dashboard
git rev-parse HEAD
git status --short
test -f tc/controller.c && test -f tc/deploy_guard.h
test -f quantization/calibrated.h && test -f deployment/ids.py && test -f dashboard/server.py
```

Compare `git rev-parse HEAD` with the reviewed deployment commit before building.
The sparse checkout excludes `dataset-instance` executables. Do not run
`git submodule update --recursive`: libbpf/bpftool sources are vendored as regular
files, and this repository also contains unrelated dataset gitlinks.

For an existing checkout, preserve local changes. Run `git status --short`, then
`git fetch origin feature/native-deployment-dashboard` and inspect the target
commit. Switch only with a clean or otherwise understood working tree; do not
reset or clean it. A new sparse checkout is simplest if there are local changes.

**Offline source-only USB fallback:** after the source commit is ready, run on
the development laptop:

```bash
git rev-parse HEAD > /tmp/ids-source-revision.txt
git archive --format=tar.gz --output=/tmp/ids-source.tar.gz HEAD \
  Makefile tc deployment dashboard quantization src validation libbpf bpftool \
  run-tc-smoke.sh run-baseline.sh BASELINE_SUMMARY.md SERVER_DEPLOYMENT.md DEMO_RUNBOOK.md DEPLOYMENT_STATUS.md \
  dataset/reproduction-xdp-data.npy \
  verification-logs/layer-specific-20261107/host_results.json \
  verification-logs/layer-specific-20261107/numerical_metrics.json
sha256sum /tmp/ids-source.tar.gz > /tmp/ids-source.sha256
```

Copy those three files to USB using the desktop. On Linux, inspect `tar -tzf
ids-source.tar.gz` and verify the recorded SHA256, then extract **as your ordinary
user** into a fresh directory. This archive contains committed source, not WSL
build artifacts or dataset executables. Keep `ids-source-revision.txt` alongside
it. Build natively using C2. Download prerequisites separately if the server is
offline. No SSH, scp, remote sudo or key setup is involved.

## C4. Read-only preflight and dry-run

From the repository root, after the native build:

```bash
sudo /usr/bin/python3 deployment/ids.py preflight --interface enp8s0 --mode static_q16 --client-ip 192.168.77.2
sudo /usr/bin/python3 deployment/ids.py start --interface enp8s0 --mode static_q16 --client-ip 192.168.77.2 --dry-run
```

These inspect the existing link/addresses, actual ifindex, qdiscs and classifier
state, model/object ABI, BTF and effective capabilities. They print the selected
mode and planned ingress/egress programs, handle `0x4e4e`, priority `49152`, and
parameter bytes (Q16 5,216 or layer-specific 5,304 per slot). They load no kernel
program and modify no networking. Temporary userspace inspection files are
removed. `status: PASS` means **preflight**, not verifier acceptance or packet
execution; `attachment_capabilities` and `kernel_btf` must also be true for start.

Any existing classifier on either hook is a conflict. This conservative policy
preserves other classifiers' behavior because our existing direct-action
`TC_ACT_OK` terminates classification. Existing empty clsact can be reused.
Legacy ingress qdiscs/shared classifier blocks are refused. Do not delete or
flush another application's filters to bypass a refusal; share the preflight
output for a focused diagnosis. Other root qdiscs are left untouched.

## C5. Explicitly start the IDS and collector

Only **you**, on the native server, invoke this physical-interface operation:

```bash
sudo /usr/bin/python3 deployment/ids.py start --interface enp8s0 \
  --mode static_q16 --client-ip 192.168.77.2 --state-dir /run/nn-ebpf-ids
```

Keep that terminal open. `deployment_ready` prints actual program/map IDs and
the interface index after both libbpf queries confirm attachment. The existing
controller verifies both parameter slots and all six TC-compatible tail slots.
It uses exclusive attachment, not replacement, and records pre-existing state
in `/run/nn-ebpf-ids/preflight.json`. The collector requests locked-flow and
immutable-result map snapshots every second. It creates no map pins and does
not change addresses, routes, firewall, DNS or interface administrative state.

Use `--client-ip any` to disable client filtering, or select another actual
client IPv4. The addresses above are CLI demo settings, not detector constants.
To demonstrate experimental arithmetic, first stop Q16 safely, then run the
same start command with `--mode layer_specific`. Do not attach both modes
simultaneously to the same hooks. Static Q16 is the recommended default.

Inspect real attachments and a complete map snapshot in another terminal:

```bash
tc -j filter show dev enp8s0 ingress
tc -j filter show dev enp8s0 egress
sudo /usr/bin/python3 deployment/ids.py status --interface enp8s0 --state-dir /run/nn-ebpf-ids
sudo /usr/bin/python3 deployment/ids.py snapshot --interface enp8s0 --state-dir /run/nn-ebpf-ids
tail -n 5 /run/nn-ebpf-ids/classifications.jsonl
```

Prediction requires an eligible **ingress TCP FIN or RST**. It is not produced
for every packet or HTTP response. Egress updates monitoring statistics without
changing the six ingress-derived MLP features. Class 0/1 and integer logits are
raw model outputs, not verified benign/attack diagnoses. Equal logits yield
class 1, preserving the original rule.

Start the **unprivileged local dashboard** in a third terminal, without sudo:

```bash
python3 dashboard/server.py --state /run/nn-ebpf-ids/telemetry.json --bind 127.0.0.1 --port 8080
```

Open **http://127.0.0.1:8080/** on the Linux laptop. This server refuses root
and non-loopback binding. Its HTTP endpoints are read-only; they cannot attach,
detach, run commands or modify models. The privileged collector is separate.
Absent/stale collectors and incomplete predictions are explicitly displayed.

## C6. Start the ordinary HTTP traffic service

In another ordinary-user terminal on Linux, from the repository root:

```bash
python3 -m http.server 8000 --bind 192.168.77.1 --directory deployment/http-root
```

If port 8000 is already serving the verified HTTP test, reuse it or stop your
own earlier server; do not kill an unknown listener. This binds the dedicated
test directory, not the project/dataset tree. Port 8000 is separate from the
localhost dashboard on 8080. Do not alter firewall rules if it unexpectedly
fails; preserve the error and investigate the already working connection.

## C7. Safe shutdown

Either press Ctrl+C in the **collector** terminal, or execute:

```bash
sudo /usr/bin/python3 deployment/ids.py stop --interface enp8s0 --state-dir /run/nn-ebpf-ids
cat /run/nn-ebpf-ids/cleanup.json
tc -j filter show dev enp8s0 ingress
tc -j filter show dev enp8s0 egress
tc -j qdisc show dev enp8s0
ip -4 addr show dev enp8s0
ip route show
```

The stop command requests clean controller exit and waits for ownership/ID
cleanup. Each detach checks the actual program ID at the exact handle/priority.
**clsact remains in place**, including a clsact created by us; no broad qdisc
deletion is performed. A filter inserted by another administrator after start
must remain. Compare the `before` preflight and `after` cleanup classifier
records. Do not use a qdisc deletion or filter flush as a cleanup shortcut.

An orphan recovery checks recorded boot ID, network namespace and ifindex,
then targets only still-matching recorded program IDs. If identity changed,
it refuses rather than detaching unknown programs. A recovery refusal or
cleanup error needs diagnosis; do not assume resources are gone. After a normal
stop expect `cleanup.json` status PASS and both owned IDs absent. The dashboard
shows STOPPED with historical counters. Close dashboard/test-service terminals
with Ctrl+C when finished. No payloads were stored; classification logs rotate
at 2 MiB with three backups.

Finally, on **Windows PowerShell**, verify the original connection still works:

```powershell
curl.exe --interface 192.168.77.2 --http1.0 --connect-timeout 3 --max-time 15 --fail http://192.168.77.1:8000/
```

See [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) for the complete no-SSH two-machine sequence,
bounded concurrent Windows traffic, evidence criteria and known limitations.
