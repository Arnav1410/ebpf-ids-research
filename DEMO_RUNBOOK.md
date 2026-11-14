# Two-laptop demonstration — no SSH, no Codex on the server

Status: **PENDING USER EXECUTION on native Linux and the physical Ethernet link**.
WSL2 kernel/namespace results do not establish native/physical compatibility.
Use [SERVER_DEPLOYMENT.md](SERVER_DEPLOYMENT.md) to transfer the reviewed commit
through GitHub and build natively first. Existing addresses remain unchanged.

## Linux operator sequence

From the native source checkout, in ordinary-user terminals:

For a source-only USB archive, display the accompanying
`ids-source-revision.txt` instead of the two Git commands below.

```bash
git rev-parse HEAD
git status --short
uname -r
ip -4 addr show dev enp8s0
ip route show
tc -j qdisc show dev enp8s0
tc -j filter show dev enp8s0 ingress
tc -j filter show dev enp8s0 egress
```

Compare the commit with the development report and confirm `192.168.77.1/24`
is already present on an UP `enp8s0`. If an inspection differs, stop and diagnose.

1. **HTTP service terminal**, without sudo:

   ```bash
   python3 -m http.server 8000 --bind 192.168.77.1 --directory deployment/http-root
   ```

2. **Collector terminal**, read-only checks, then explicit operator attachment:

   ```bash
   sudo /usr/bin/python3 deployment/ids.py preflight --interface enp8s0 --mode static_q16 --client-ip 192.168.77.2
   sudo /usr/bin/python3 deployment/ids.py start --interface enp8s0 --mode static_q16 --client-ip 192.168.77.2 --dry-run
   sudo /usr/bin/python3 deployment/ids.py start --interface enp8s0 --mode static_q16 --client-ip 192.168.77.2 --state-dir /run/nn-ebpf-ids
   ```

   Wait for `deployment_ready` with actual ingress/egress program IDs. The same
   process collects kernel maps automatically; keep it running. Do not proceed
   on verifier/attachment errors or existing-filter conflicts.

3. **Dashboard terminal**, without sudo:

   ```bash
   python3 dashboard/server.py --state /run/nn-ebpf-ids/telemetry.json
   ```

   Open http://127.0.0.1:8080/ in the Linux browser. It must say LIVE/CONNECTED,
   selected interface `enp8s0`, both actual hook IDs and `static_q16`. Zero flows
   initially is a valid observation, not an error. The display refreshes once a
   second and pages at 100 connections; filter by IP/port/state.

4. **Evidence terminal**, before and after Windows traffic:

   ```bash
   tc -j filter show dev enp8s0 ingress
   tc -j filter show dev enp8s0 egress
   sudo /usr/bin/python3 deployment/ids.py status --interface enp8s0
   tail -n 12 /run/nn-ebpf-ids/classifications.jsonl
   ```

   For full features and every intermediate tensor, use the privileged read-only
   `snapshot` command in SERVER_DEPLOYMENT.md. The HTTP dashboard shows logits,
   classes, directional counts and monotonic timestamps, not packet contents.

## Windows PowerShell sequence (compatible with Windows PowerShell 5.1)

Use **Windows**, not WSL, so the requests originate at the configured Ethernet
adapter. These commands use native `curl.exe`, which already reached the server.
They do not modify Windows adapter settings or routes.

```powershell
$PSVersionTable.PSVersion
Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4
ping.exe -n 2 192.168.77.1
curl.exe --version
curl.exe --interface 192.168.77.2 --http1.0 --connect-timeout 3 --max-time 15 --fail --show-error http://192.168.77.1:8000/
if ($LASTEXITCODE -ne 0) { throw 'Single HTTP request failed' }
```

Confirm `192.168.77.2/24` is already configured. The explicit source-IP binding
keeps the test on the known Ethernet path. Do not use the PowerShell `curl`
alias. `--http1.0` and connection closure encourage the existing FIN trigger.
Packets and bytes depend on TCP segmentation/offloads; do not predict exact
counts. Ping contributes global ingress/egress counts but no TCP flow.

Run **ten bounded concurrent requests**, each a separate curl process/connection:

```powershell
$idsJobs = 1..10 | ForEach-Object {
    Start-Job -ArgumentList $_ -ScriptBlock {
        param($RequestNumber)
        $code = & curl.exe --interface 192.168.77.2 --http1.0 --connect-timeout 3 --max-time 15 --fail --silent --show-error --output NUL --write-out '%{http_code}' 'http://192.168.77.1:8000/'
        [PSCustomObject]@{ Request=$RequestNumber; ExitCode=$LASTEXITCODE; HttpCode=$code }
    }
}
$null = $idsJobs | Wait-Job -Timeout 25
$idsPending = @($idsJobs | Where-Object State -ne Completed)
if ($idsPending.Count -gt 0) { $idsPending | Stop-Job }
$idsResults = @($idsJobs | Receive-Job)
$idsJobs | Remove-Job
$idsResults | Sort-Object Request | Format-Table -AutoSize
if ($idsPending.Count -gt 0 -or $idsResults.Count -ne 10 -or @($idsResults | Where-Object { $_.ExitCode -ne 0 -or $_.HttpCode -ne '200' }).Count -gt 0) { throw 'Concurrent HTTP test did not complete successfully' }
```

Look for distinct client source ports in the dashboard, sharing the same client
IP and server port 8000. Compare new canonical tuples and completed log records
with the pre-test snapshot. There can already be connections from earlier
requests or probes; total flow/prediction counts are not assumed to start at zero.

For a **longer multi-write TCP exchange**, use the .NET classes present in
PowerShell 5.1. It sends a bounded HTTP header in small writes, then explicitly
half-closes the client write side (FIN) before reading the response:

```powershell
$idsTcp = New-Object System.Net.Sockets.TcpClient
try {
    $idsLocal = New-Object System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Parse('192.168.77.2')),0
    $idsTcp.Client.Bind($idsLocal)
    $idsConnect = $idsTcp.BeginConnect('192.168.77.1', 8000, $null, $null)
    if (-not $idsConnect.AsyncWaitHandle.WaitOne(5000)) { throw 'TCP connect timeout' }
    $idsTcp.EndConnect($idsConnect)
    $idsTcp.ReceiveTimeout = 5000
    $idsTcp.SendTimeout = 5000
    $idsTcp.NoDelay = $true
    $idsStream = $idsTcp.GetStream()
    $idsRequest = 'GET / HTTP/1.0' + "`r`nHost: ids-demo`r`nX-Demo: " + ('x' * 2048) + "`r`nConnection: close`r`n`r`n"
    $idsBytes = [System.Text.Encoding]::ASCII.GetBytes($idsRequest)
    for ($idsOffset=0; $idsOffset -lt $idsBytes.Length; $idsOffset+=64) {
        $idsLength = [Math]::Min(64, $idsBytes.Length-$idsOffset)
        $idsStream.Write($idsBytes, $idsOffset, $idsLength)
        Start-Sleep -Milliseconds 10
    }
    $idsTcp.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
    $idsBuffer = New-Object byte[] 4096
    $idsReply = New-Object System.Text.StringBuilder
    while (($idsRead=$idsStream.Read($idsBuffer,0,$idsBuffer.Length)) -gt 0) {
        $null = $idsReply.Append([System.Text.Encoding]::ASCII.GetString($idsBuffer,0,$idsRead))
        if ($idsReply.Length -gt 1048576) { throw 'Unexpected response size' }
    }
    $idsReply.ToString()
    if (-not $idsReply.ToString().StartsWith('HTTP/1.0 200')) { throw 'HTTP response failed' }
} finally { $idsTcp.Close() }
```

Multiple application writes can still coalesce into fewer observed skbs. This
test creates opportunities for several packets; it does not force a packet
count or CPU interleaving. PowerShell commands are prepared for Windows
PowerShell 5.1/.NET, but remain **PENDING USER EXECUTION** on this client.

## Evidence and success criteria

- Actual filter dumps and status show both owned program IDs on `enp8s0`.
- Global ingress/egress counters increase during successful Windows requests.
- A canonical IP/port key contains nonzero counters in both hook directions.
- Distinct client ports remain separate flow records, even from one IP.
- Ingress FIN/RST produces an immutable result with all six stages, final
  integer logits and the original class rule. Classification is ingress-based;
  egress counters never become model features.
- `classifications.jsonl` records completed inferences once per session/result,
  without payloads. The dashboard shows the same real records and current data.
- There is no unexpected HTTP failure or network-configuration change.

Screenshots of UI labels alone do not prove kernel correctness. Retain the
checked-out revision, filter IDs, map snapshot, bounded JSONL records, native
kernel/compiler versions and request results. A model prediction does not prove
that an attack was correctly detected.

## Shutdown and post-detachment check

On Linux, leave the HTTP test server running and stop only the IDS:

```bash
sudo /usr/bin/python3 deployment/ids.py stop --interface enp8s0 --state-dir /run/nn-ebpf-ids
cat /run/nn-ebpf-ids/cleanup.json
tc -j filter show dev enp8s0 ingress
tc -j filter show dev enp8s0 egress
ip -4 addr show dev enp8s0
ip route show
```

Expect the owned filters/IDs gone, other filters preserved and the existing
clsact/address/routes left alone. Then rerun the single Windows `curl.exe`
command and verify HTTP 200. Stop the dashboard and ordinary HTTP service with
Ctrl+C in their own terminals. Do not delete clsact or flush any filters.

To switch inference modes, stop first, then repeat the Linux collector start
with `--mode layer_specific`. The same dashboard path can be used. It should
show the new session/mode; class integers at q18 differ from Q16 logits at q16.
The calibrated mode rejects inputs outside its documented domain, and measured
WSL2 inference was slower despite better numerical fidelity. No F1 improvement
is claimed.

## Remaining limits

IPv4/TCP over untagged Ethernet only; unsupported/malformed/fragmented packets
pass unscored. NIC offloads affect observed counts. Snapshots across maps are
not globally atomic. Helper-clock timestamp reordering is clamped/counted and
cannot reconstruct chronological wire IAT. Results and flow records are retained
up to 8,192 entries, without production aging or tuple-reuse reset; later packets
do not replace an existing completed result. Restart the owned collector between
long demo sessions to obtain fresh private maps, using the safe stop/start path.
Rotating classification logs retain a bounded history; inspect or copy the
small required evidence before rotating it away. Native kernel verifier/NIC
behavior and physical two-laptop results must be recorded by the operator.
