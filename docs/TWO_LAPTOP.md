# Operator-controlled two-laptop demonstration

Commands are **V** (verified from existing CLI) or **X** (external VM/Windows/privileged execution, not rerun for this submission). The single-machine host/preparation checks are **E**, documented separately. Use the one-machine path first; physical networking is optional.

## Topology and safeguards

Example only: Windows Ethernet `192.168.77.2/24` → Linux physical `enp8s0` / host `192.168.77.1` → macvtap Ubuntu VM **`enp7s0`, `192.168.77.3/24`**. VM NAT **`enp1s0`** remains separate. Select the VM interface, not the host's `enp8s0`. No SSH is needed: transfer committed source with GitHub, build inside the VM.

The launcher validates the selected interface/IP/prefix/link, runs model/IDS preflight, reserves app/dashboard sockets, starts supervised children and waits for real readiness. It makes no IP/route/firewall/DNS/offload/NetworkManager changes. Ping failure is advisory, not a reason to reconfigure networking. It asks for `ATTACH enp7s0` before both TC hooks are attached. Existing occupied classifier hooks or ports are refused; unrelated services are never killed.

The root supervisor reserves port 80, passes inherited listeners to ordinary-user application/dashboard processes and uses ownership-aware targeted TC cleanup. It does not require a root web server, port redirection, a proxy or global privileged-port changes. Both app ports 80 and 9000 passed historical isolated socket/kernel tests; a port-80 listener is the project's ordinary TCP protocol, **not an HTTP web service**.

## Validate an integrated fresh demo on one machine first

Preparation (**E**), after building:

```bash
python3 demo/validate_server.py --prepare artifacts/demo-ready
```

Pilot (**X**, no attachments; 100 stored vectors/mode plus repeat checks; model/scaler map readbacks):

```bash
sudo /usr/bin/python3 demo/validate_server.py --pilot artifacts/demo-ready
```

Only after actual pilot PASS, use its newly printed directory:

```bash
python3 demo/validate_server.py --prepare-network artifacts/demo-network --pilot-evidence /absolute/path/to/new/pilot-directory
sudo /usr/bin/python3 demo/validate_server.py --network artifacts/demo-network --pilot-evidence /absolute/path/to/new/pilot-directory
```

The network suite uses only `idsfresh-*` and `tcids-*` namespaces/veth, never VM/physical interfaces. It runs original regressions, fresh both-mode port-80/9000 one/ten clients and original/Q16/9000 rollback, dashboard, numerical parity, occupied-port refusal, preservation and cleanup. Read the reports and actual log files; preparation PASS is not runtime PASS. Do not copy an old approval/manifest from another checkout.

## Ubuntu VM

Inspect, without changing configuration (**X**):

```bash
cd ebpf-ids-research
git rev-parse HEAD
ip -brief link show enp7s0
ip -4 address show dev enp7s0
ip route show
tc -j qdisc show dev enp7s0
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
ss -lnt
```

Verify the IP is already `192.168.77.3/24` on `enp7s0`. If missing, stop and restore the known lab configuration through the operator; the launcher does not configure it. Preserve the existing NAT interface/default route. Install/build using [getting started](GETTING_STARTED.md); WSL executables are not transferred.

Read-only plan and dry-run (**X**, code verified):

```bash
python3 deployment/ids.py preflight --interface enp7s0 --client-ip 192.168.77.2 --app-port 80 --model fresh --mode static_q16
./demo/start_server.sh --interface enp7s0 --server-ip 192.168.77.3 --prefix-length 24 --client-ip 192.168.77.2 --port 80 --dashboard-port 8080 --model fresh --mode static_q16 --dry-run
```

Start, explicitly from the ordinary VM account (**X**):

```bash
./demo/start_server.sh --interface enp7s0 --server-ip 192.168.77.3 --prefix-length 24 --client-ip 192.168.77.2 --port 80 --dashboard-port 8080 --model fresh --mode static_q16
```

The shell wrapper uses sudo for its supervisor. Type the exact attachment confirmation. Keep this terminal open. Read the printed **experiment ID**, model, arithmetic mode, parameter/scaler hashes, real listener address and output directory. Successful loaded-data verification should show fresh header `e896b31f…`, packed Q16 `1558c438…`, scaler `f900a854…`. The launcher writes `experiment.json` with the verified identity, output/state paths and selected port.

Open **http://127.0.0.1:8080/** in the VM browser; loopback is intentional. The ordinary-user dashboard is a supervised child and logs to the experiment's `dashboard.log`. In another terminal use `tail -f /actual/printed/experiment-directory/dashboard.log`. No graphical terminal emulator is assumed. Dashboard bind may be changed explicitly with `--dashboard-bind`; do not expose it to a public/campus network by accident.

Inspect (**X**, no changes):

```bash
ss -lnt 'sport = :80'
tc -j filter show dev enp7s0 ingress
tc -j filter show dev enp7s0 egress
```

## Windows 11 / Python 3.13

From a clean clone (or copy only `demo/client.py` and both scenario CSVs into one directory), open ordinary PowerShell. No WSL or administrator privilege is needed to generate traffic.

Read-only network checks (**X**):

```powershell
py -3.13 --version
Get-NetIPConfiguration -InterfaceAlias Ethernet
Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4
Test-NetConnection -ComputerName 192.168.77.3 -Port 80
```

Confirm `192.168.77.2` is actually assigned before passing it as `--source-ip`. A client still on DHCP/internet may not have this address. **Changing Windows Ethernet IPv4/DHCP/gateway/DNS settings can interrupt internet connectivity.** No Windows network-management or automatic restoration script exists in the audited source. Do not invent or rely on one: record the original adapter settings with the commands above before an operator makes any change, and restore those recorded DHCP/static/DNS settings manually afterward. The Python client does not alter networking, so it has no network-state restoration operation.

Run only one connection first (**X**), using the server's printed ID:

```powershell
cd ebpf-ids-research
$ExperimentId = Read-Host 'Paste server experiment ID'
py -3.13 demo/client.py --input demo/scenarios-reproduction-informed.csv --count 1 --concurrency 1 --server-ip 192.168.77.3 --source-ip 192.168.77.2 --port 80 --experiment-id $ExperimentId --output demo-client-one
```

Confirm completion and one matching server flow/classification. Then (**X**):

```powershell
py -3.13 demo/client.py --input demo/scenarios-reproduction-informed.csv --count 10 --concurrency 10 --server-ip 192.168.77.3 --source-ip 192.168.77.2 --port 80 --experiment-id $ExperimentId --output demo-client-ten
```

These commands work with Windows PowerShell 5.1 syntax; concurrency is Python sockets, not PowerShell 7 features. Each row is a bounded benign-intent/unknown traffic scenario. It is **not** a stored feature-vector replay or an independently labeled intrusion. The client records actual source address/port, bytes/times/errors, uses client-side half-close, and receives a checked response. FIN/RST triggers depend on actual eligible traffic, not just an application's exit.

## Evidence, matching and stop

The server retains `server_classifications.jsonl`, telemetry, application events and final `kernel_snapshot.json`; client outputs include `client_results.csv`. The same experiment ID and canonical TCP endpoint tuple (including source port) associate runs. Multiple connections from one IP stay distinct. Copy the client CSV by Git-independent USB/local transfer for evaluation; generated logs need not be committed. No SSH is required.

Exact evaluator CLI (**V**; replace paths with this run's files):

```bash
python3 demo/evaluate.py --experiment /path/to/experiment --client /path/to/client_results.csv --output artifacts/joined --attack-class 1 --label-provenance "Ordinary bounded benign TCP; not an intrusion benchmark"
```

Read `joined_results.csv` and `evaluation_summary.json`. Missing/ambiguous/duplicate predictions are explicit. Benign-only runs report coverage/FPR, not fabricated attack recall/F1. The raw features/logits must be inspected; live accuracy is not inferred from the reproduction-model held-out F1.

Stop the launcher with **Ctrl+C**. It drains/retains final state, stops its children and detaches only its recorded program IDs/handles; a shared clsact qdisc is left intact. Inspect `cleanup.json`, requiring PASS. If the supervisor died, use its actual short state path printed in `experiment.json` (**V**):

```bash
sudo /usr/bin/python3 deployment/ids.py stop --interface enp7s0 --state-dir /run/idsdemo-ACTUAL-RUN-ID
```

Never guess a stale run ID; inspect status first. Do not use `tc qdisc del`, flush filters, remove other pins or change IP/routes. Inspect TC state and connectivity afterward. `Test-NetConnection` to the application port is expected to fail when our application was stopped; ping/other existing services should remain operational. If an ordinary HTTP server was separately running, `curl.exe http://192.168.77.3:8000/` can verify it still works.

Rollback uses the same command with **`--model original --mode static_q16 --port 9000`**, after the previous owned run is fully stopped. Point the Windows client's `--port` at 9000. No header restoration or branch reset is necessary.
