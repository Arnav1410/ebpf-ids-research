# Install, build and reproduce on one Linux machine

Status legend: **E** executed successfully on this submission candidate; **V** exact CLI/source checked but not run here; **X** requires external privileges/hardware/data and has not been verified locally on this candidate. Commands use repository-relative paths. Output directories must be new; substitute a new suffix instead of deleting previous evidence.

## Requirements

Current build/host tests: Ubuntu **22.04.5 LTS**, x86-64, Python **3.10.12**, clang/LLVM **12**, GCC/make, WSL2 kernel **6.6.87.2-microsoft-standard-WSL2**. Historical kernel execution used that WSL2 kernel. The team reports an Ubuntu KVM guest on **6.8.0-138-generic** for the physical demonstration; no fresh native/VM run of this submission candidate is claimed. WSL host numerical checks do not establish native Linux compatibility. Other distributions/architectures/kernel versions are unverified.

Kernel build/load needs `/sys/kernel/btf/vmlinux`, `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, BPF JIT, scheduling classifier/direct-action support, BPF maps/program arrays, tail calls, per-CPU arrays and spin locks. TC networking operations require `CAP_NET_ADMIN`; program load/test requires appropriate BPF/perf capabilities (usually operator `sudo`); namespaces require mount/network permissions. Root in a restricted container can still lack these. No mounting, sysctl changes or upgrades are done automatically.

Inspect first (**E** basic local environment; **X** privileged feature query):

```bash
cat /etc/os-release
uname -a
python3 --version
clang-12 --version
llvm-objdump-12 --version
gcc --version
make --version
test -r /sys/kernel/btf/vmlinux
findmnt -t bpf
ip -brief address
```

Clone (**X**, GitHub authentication unavailable during this audit):

```bash
git clone https://github.com/Arnav1410/ebpf-ids-research.git
cd ebpf-ids-research
git rev-parse HEAD
```

Until the submission PR is actually merged, select the published submission branch explicitly. [Publication status](SUBMISSION_VALIDATION.md) gives the candidate name. There are no actual gitlink submodules: vendored `libbpf`, `bpftool` and bpftool's libbpf are already tracked. Do not substitute a newer library without retesting.

On **Ubuntu 22.04**, package installation (**V**, package set verified against build requirements; apt was not run during this audit):

```bash
sudo apt update
sudo apt install build-essential clang-12 llvm-12 libclang-rt-12-dev libelf-dev zlib1g-dev pkg-config binutils-dev libcap-dev python3 python3-venv iproute2 iputils-ping util-linux
```

If these exact packages are unavailable on another distribution/release, inspect first. Do not blindly upgrade the kernel or replace the compiler. `libbpf-dev` is not required: the build uses the vendored static libbpf. The installed `tc`/`ip` utilities come from iproute2. Clang-12 is named explicitly by several experiment runners; changing only `CLANG` in one Makefile does not update every runner.

## Build without loading or attaching anything

**E**, built from source in the isolated candidate:

```bash
make
make -C src
make -C tc demo-models
.output/bpftool/bpftool version
python3 -m deployment.model_config --model fresh --mode static_q16
python3 -m deployment.model_config --model fresh --mode layer_specific
```

Root `make` builds vendored dependencies; `src` builds original XDP plus updater; `demo-models` builds original/fresh controllers separately and both TC arithmetic objects. BTF generation reads the running kernel. Build products stay in ignored `.output` directories. Successful compilation or `--inspect` means neither verifier acceptance nor actual kernel execution.

After build, optional capability inspection (**X**, read-only but privileged):

```bash
sudo .output/bpftool/bpftool feature probe kernel
```

## Fastest numerical reproduction — no root or special Python packages

**E** (all are host calculations, not kernel execution):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 validation/run.py --output artifacts/original-numerical
PYTHONDONTWRITEBYTECODE=1 python3 quantization/run_host.py --output artifacts/layer-numerical
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/offline.py --output artifacts/original-three-way
```

The original suite compares every stage on 18,840 stored vectors; two optional checks skip without saved smoke evidence/original FP32 checkpoint. UBSan tests intentionally characterize original-source overflow defects on constructed invalid boundaries. They do not certify arbitrary inputs safe. Layer-specific checks reject unsupported ranges, overflow and narrowing. Three-way evaluation selects 13,844 rows held out from offline **scale calibration**, not proven original training data. Its exact rational reference is reconstructed from the rounded Q16 header.

Inspect `REPORT.md`, `results.json`, `host_results.json`, `metrics.json` and per-prediction archives in the respective new output directories. [Results guide](RESULTS.md) explains denominators and references.

## Isolated kernel and real TCP test

Do this inside a disposable Linux VM or a WSL2 installation permitting network namespaces. It does not require two laptops. Preparation (**E**) builds host fixtures/ELF inspections and creates a manifest, but does not load BPF:

```bash
./run-tc-smoke.sh --prepare --phase2 --mode static_q16 --output artifacts/tc-static
./run-tc-smoke.sh --prepare --phase2 --mode layer_specific --output artifacts/tc-layer
```

Review both reports. Only after preparation succeeds, operator-executed kernel/network commands (**X**, not rerun during this submission audit):

```bash
sudo ./run-tc-smoke.sh --run artifacts/tc-static --phase2 --mode static_q16
sudo ./run-tc-smoke.sh --run artifacts/tc-layer --phase2 --mode layer_specific
```

The runner refuses occupied owned names; it uses `tcids-server/client` namespaces and `tcids-s0/c0` veth, test addresses `33.33.33.1/.73`, not physical interfaces. It checks private verifier/test-run/concurrency cases, actual ingress/egress attachment, one/ten/burst TCP traffic, retained tensors, independent packet observations and targeted cleanup. Expected observations are nonzero directional counters, independent canonical tuples, complete six-stage predictions and cleanup PASS; **do not assert exact packet counts**.

Each prints a new `run-*` directory with `REPORT.md`, `results.json`, verifier logs and snapshots. On normal exit/signals it cleans owned children/hooks/namespaces. If interrupted cleanup fails, read the run's ownership record and invoke (**V**, exact CLI):

```bash
sudo ./run-tc-smoke.sh --cleanup /absolute/path/to/the/printed/run-directory
```

Do not delete a shared clsact qdisc, flush filters or remove unrelated resources manually. Test addresses belong only to isolated fixtures. The physical deployment makes client-IP selection explicit instead.

For the fresh-model integrated listener/collector/dashboard suite, follow [the ordered fresh pilot and network gates](TWO_LAPTOP.md). That suite adds ports 80/9000, model-map readbacks and ordinary-user HTTP tests. Kernel commands must run from an ordinary account via sudo so child services can drop privileges.

## Optional research Python environment

Runtime/dashboard/client use the standard library. Training, figures and independent sklearn metrics need extra packages. Installation **E** into an isolated temporary venv (equivalent `.venv` commands below); no system Python packages were changed:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-analysis.txt
.venv/bin/python -m pip install torch==2.5.1+cpu --index-url https://download.pytorch.org/whl/cpu
```

These are the recorded direct versions, not a guarantee of bitwise equality across CPU/software. [The submitted audit environment](evidence/analysis-environment.txt) records resolved versions. Do not run the old upstream `src/mlp_quant.py` as an installation step: it overwrites the original header.
