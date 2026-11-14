# Final two-laptop harness — Ubuntu VM + Windows Python

Use this runbook for the **new VM topology**. The original deployment guides
remain available as fallback; their physical-server example addresses differ.

| Role | Selected interface/address |
| --- | --- |
| Windows client | Existing Ethernet `192.168.77.2` |
| Ubuntu KVM/QEMU guest | Existing `enp7s0`, `192.168.77.3` |
| Physical Linux host | `enp8s0` — **not the VM interface; do not select it** |
| Dashboard | Guest browser, `127.0.0.1:8080` |
| Controlled TCP application | Guest `192.168.77.3:9000` |

Do not change NAT, addresses, routes, firewall, DNS, offloads or administrative
link state. No SSH/scp/remote execution is used. All physical/VM attachment
commands below are **manual operator actions**, never development automation.

## Source transfer and build

Development branch: `feature/final-demo-evaluation`. Manually push its reviewed
commit from WSL; no automatic push is performed:

```bash
git status --short
git log -3 --oneline
git push -u origin feature/final-demo-evaluation
```

On the VM, use the existing HTTPS GitHub source-transfer workflow from
[SERVER_DEPLOYMENT.md](SERVER_DEPLOYMENT.md), with origin
`https://github.com/Arnav1410/ebpf-ids-research.git`. Fetch the new branch and
compare the exact checked-out revision with the final handoff. Preserve local
changes; do not reset/clean them. For an existing clean ordinary checkout:

```bash
git fetch origin feature/final-demo-evaluation
git switch --detach origin/feature/final-demo-evaluation
git rev-parse HEAD
```

If using the previous sparse checkout, add the new source paths and label array
before switching/building. Retain its existing runtime/dependency paths:

```bash
git sparse-checkout add --no-cone '/demo/' '/evaluation/' '/DATASET_AUDIT.md' \
  '/THREE_WAY_COMPARISON.md' '/DEMO_HARNESS.md' '/dataset/reproduction-xdp-label.npy'
```

Build natively using the prerequisite instructions in SERVER_DEPLOYMENT.md:

```bash
make -j2 CLANG=clang
make -C tc layer-specific CLANG=clang
python3 -m unittest -v evaluation.test_audit evaluation.test_metrics demo.test_demo
```

Do not transfer `.output`, `.so` or WSL executables. Do not initialize unrelated
dataset submodules or run anything under `dataset-instance`. Neither training
script nor unsafe checkpoint deserialization is needed. Actual Windows client
execution requires only Python 3 and the three portable files below.

## Minimal classroom sequence

### 1. Inspect the existing guest interface

```bash
ip -4 addr show dev enp7s0
ip route show
tc -j qdisc show dev enp7s0
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
```

Expect `192.168.77.3/24` on the already UP guest Ethernet interface. If the
addresses/interface differ, stop and diagnose. Do not run IP/route changes.
If your previous IDS/dashboard is still running, stop **your owned instance**
through its existing controller and close its dashboard terminal. Occupied TC
hooks are refused; occupied application/dashboard ports cause safe rollback.
The launcher never kills a discovered foreign listener or removes shared clsact.

### 2. One server command (inside Ubuntu VM)

From the repository root, choose a new evidence directory:

```bash
IDS_RUN="$HOME/ids-runs/$(date +%Y%m%d-%H%M%S)"
sudo /usr/bin/python3 demo/launch.py --interface enp7s0 \
  --server-ip 192.168.77.3 --client-ip 192.168.77.2 \
  --mode static_q16 --output "$IDS_RUN"
```

The launcher prints read-only preflight and dry-run results first. Review the
interface/model/plan, then type **`ATTACH enp7s0`** when asked. Before that
confirmation no BPF attachment occurs. Wait for `experiment_ready`; it prints
the experiment ID and exact Windows client command. Keep this terminal open.
The launcher starts the existing IDS/collector plus an ordinary-user concurrent
TCP application and ordinary-user dashboard. It refuses root web serving.
Open **http://127.0.0.1:8080/** in the **guest's browser**.

The `--confirm-interface NAME` flag is explicit confirmation for controlled
automation; it was used only on owned veth interfaces during development tests.
Do not use it to bypass your physical-interface review. Defaults are the VM
settings above; `--port`, `--dashboard-port`, interface/IP and `--mode` are
configurable. Empty clsact may be reused and is always left in place.

### 3. Windows-native CSV client

Copy these three committed source files to one ordinary Windows folder, e.g.
`Documents\ids-client`, using File Explorer or the authenticated GitHub browser:

- `demo/client.py`
- `demo/common.py`
- `demo/scenarios.csv`

Source copying from the WSL repository through Explorer is fine; **execute
Windows Python**, not `wsl python`. No administrator privileges or pip packages
are needed. In Windows PowerShell 5.1+:

```powershell
Set-Location "$env:USERPROFILE\Documents\ids-client"
py -3 --version
$IdsExperiment = Read-Host 'Paste experiment_id from the Ubuntu launcher'
py -3 client.py --input scenarios.csv --count 10 --concurrency 10 --server-ip 192.168.77.3 --source-ip 192.168.77.2 --port 9000 --experiment-id $IdsExperiment --output ".\client-$IdsExperiment"
if ($LASTEXITCODE -ne 0) { throw 'Some TCP connections failed; retain client_results.csv' }
```

If your installation uses `python` instead of the `py` launcher, verify that it
is native Windows Python and substitute that executable. Each CSV row is an
ordinary TCP experiment, **not an input feature vector**. `--count N` selects
the first N rows, `--concurrency K` permits up to K simultaneous connections.
The sample has 64 rows; limits are 128 cases, concurrency 32, 64 KiB per payload,
8 MiB total, 64 chunks and 50 ms inter-chunk delay. Connections have deadlines.
For a single connection use `--count 1 --concurrency 1`; for a bounded larger
batch use `--count 32 --concurrency 32`, each with a fresh client output path.

The client records actual local/peer socket endpoints, byte counts, times and
errors, and validates the server's run/case acknowledgement. It sends an
ordinary ASCII payload and orderly write-half-close, exercising incoming FIN.
Application chunks are not assumed to equal network packets. Unknown labels
stay unknown; this generator rejects invented intrusion labels.

### 4. Observe and stop on Linux

The dashboard should show distinct source ports from one client, nonzero ingress
and egress counters, completed predictions and logits. Inspect actual hooks:

```bash
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
```

After Windows reports completion, press **Ctrl+C in the launcher terminal**.
It drains the bounded application workers, waits for fresh collector polls,
saves a full kernel snapshot, stops the IDS through its ownership-aware stop
mechanism and terminates only its own application/dashboard children. It copies
bounded prediction logs/evidence before removing its private runtime directory.
It never deletes clsact. A cleanup failure produces FAIL and retains diagnostics;
do not flush filters to work around it.

```bash
cat "$IDS_RUN/experiment.json"
cat "$IDS_RUN/cleanup.json"
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
ip -4 addr show dev enp7s0
ip route show
```

Expect owned filters absent and existing addresses/routes unchanged. Foreign
filters, if any were added separately, must remain. Runtime/control directory
identity is visible in `collector.log` if a failed shutdown needs the existing
`deployment/ids.py status/stop --state-dir ...` recovery path; never kill an
unknown PID. The verified older TC demo remains available as fallback.

### 5. Transfer the small client CSV and join

Copy Windows `client_results.csv` to the guest using USB or an **already
configured** VM shared folder, e.g. `$HOME/client_results.csv`. No new network
service, dashboard upload endpoint or SSH setup is required. Export:

```bash
python3 demo/evaluate.py --experiment "$IDS_RUN" --client "$HOME/client_results.csv" \
  --output "$IDS_RUN/joined" --attack-class 1 \
  --label-provenance 'DSN 2024 IV-B3 intended coding; controlled ordinary TCP demo'
cat "$IDS_RUN/joined/evaluation_summary.json"
```

Outputs: `client_results.csv`, `server_classifications.jsonl`,
`joined_results.csv`, `evaluation_summary.json`, `REPORT.md`. Omit the explicit
class mapping/provenance flags to report coverage without interpreting classes.
Joining uses experiment ID, collector session, TCP protocol, canonical full
tuple and the application case record. It never joins by IP alone or row order.
Identical duplicate log records are deduplicated; conflicting records,
source-port reuse, missing predictions and client failures remain visible.
Timing is a secondary server-side consistency check, not a cross-machine clock
match. Evaluate separate client batches separately; repeated case IDs in a
combined CSV are conservatively flagged.

## Interpretation: do not confuse a working pipeline with a good detector

In the actual isolated WSL2 harness, both modes matched all 86 connections and
all 11,696 kernel tensor integers, but classified every known-benign demo case
as class 1. Under the intended coding this was a **100% benign false-positive
rate** on the small controlled sample. Unknown cases were excluded from labeled
metrics. No intrusions were generated, so intrusion recall/F1 are unavailable.
Do not relabel class 1 benign to improve the presentation. The dashboard's
raw class/logits and matching coverage demonstrate execution, not attack truth.

Repeat the launcher with `--mode layer_specific` only after stopping Q16, using
a new evidence directory/experiment ID. Identical application scenarios do not
ensure identical kernel timing features. For the controlled **same-vector**
three-way comparison use the separate host evaluation, not live traffic labels:

```bash
python3 evaluation/audit.py --output /tmp/ids-audit
python3 evaluation/offline.py --output /tmp/ids-three-way --compiler clang --encoded-label-diagnostics
```

The optional diagnostic flag scores supplied NPY codes, with unverified training
overlap/collection provenance; it is not independently validated detection F1.
[DATASET_AUDIT.md](DATASET_AUDIT.md) and
[THREE_WAY_COMPARISON.md](THREE_WAY_COMPARISON.md) explain the results.

## Reproduce isolated verification

```bash
python3 demo/test_isolated.py --prepare --output /tmp/ids-harness-test
# After separate approval; only owned namespaces/veth:
sudo /usr/bin/python3 demo/test_isolated.py --run /tmp/ids-harness-test
```

The suite runs ordinary-user protocol tests, 1/10/32-connection batches in both
modes, all-layer kernel parity, tuple matching, benign-only metric rules,
occupied-port rollback and owned cleanup. Existing detector, training,
deployment and dashboard source is unchanged from `0ba2b2b`. Earlier concurrency
and numerical evidence remains valid; this is not a claim to force every CPU
interleaving. Windows-native client execution and the new guest two-laptop
harness remain **PENDING USER EXECUTION** until those actual outputs are saved.

No fresh runtime XDP comparison was attempted. The original hardcoded-source
XDP implementation is preserved, and old WSL XDP timings cannot be compared to
new VM TC timings as an equal-environment benchmark. No model retraining,
prevention, dynamic scaling or feature redefinition was implemented.
