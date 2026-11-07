# Stage08 — native Windows client diagnostics

The Windows laptop generates controlled traffic; the detector, feature extraction and NN inference remain in the Ubuntu kernel. **WSL is not required.**

The earlier Windows inventory and corrected route output are already supplied, as are the Linux NAT mapping, IPv4 policy and VM disk/snapshot list. Do not repeat the old multi-command dump to confirm its paste errors. Historical facts remain in [direct-ethernet-observations.json](direct-ethernet-observations.json); latest host facts are in [policy-storage-observations.json](policy-storage-observations.json).

Use the standalone **`test_env/discover-windows.ps1`** for a repeatable machine-readable report. Copy that single file to the Windows laptop. It uses native PowerShell5.1 read-only cmdlets, selects the explicit Ethernet alias/index, and never falls back to Wi-Fi, WSL or VPN. The matching `test_env/discover-host.sh` runs on the Linux virtualization host, not inside the Ubuntu guest.

Canonical launch/save/import commands and JSON/error/encoding rules:
[repeatable discovery and configuration](../../test_env/CONFIGURATION.md#repeatable-host-and-windows-discovery).
Paste complete JSON reports so `test_env.configure` can parse observed values instead of manually retyping addresses. Reports are point-in-time metadata; re-run after topology/IP changes.

Actual native Windows5.1 report is received with zero collection errors: Ethernet index5 is Up at100Mbps, preferred manual `192.168.77.2/24`, DHCP disabled, no IPv4 DNS/default gateway on that adapter. Host `enp8s0` is UP/LOWER_UP at `.77.1/24`. These supersede APIPA/NO-CARRIER observations; no broad rerun is needed. The VM bridge/second NIC, usable recovery point and actual traffic remain unvalidated; see [actual review](operator-discovery-review.json) and [physical plan](direct-ethernet-plan.md).

No address assignment, route/firewall/VPN change, listener, traffic, snapshot creation or installation is performed by these collectors. The native report is operator-supplied execution evidence, not agent remote execution or physical packet acceptance.
