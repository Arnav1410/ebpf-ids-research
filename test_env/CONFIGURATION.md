# Lab environment configuration

`.env.example` is the versioned template. Root `.env` is the ignored local configuration; it is created here with the operator's known VM/host parameters. Unknown physical targets remain empty, not guessed.

The file is **literal data, not executable shell**. Do not `source .env`, run it, or use `sudo -E`. The Python entrypoints read it directly, including through sudo. Supported syntax: `KEY=VALUE`, blank lines and whole-line `#` comments; optional matching single/double quotes around an entire value. There is no variable/command substitution, escaping, tilde expansion or process-environment override. Typos, duplicate keys and malformed/invalid values are rejected.

Precedence: **explicit CLI flags > selected env file > built-in defaults**. Root `.env` is optional and automatic; `--env FILE` selects another file and errors if missing. Path values inside the file are repository-root relative, even if the config file lives elsewhere. The `--env` filename itself is caller-directory relative. Put `--env` after `live` or `replay` for the service.

## Consumers

Read-only guest physical preflight (no web dependencies required):

```bash
python3 -B -m test_env.preflight --env .env --out .output/stage08-preflight
```

This records actual guest links/addresses/routes/TC state and configuration, protects every default-route interface regardless of what the file calls management, and reports missing/unsafe targets. A blocked physical setup is a nonzero result, **not** a failed private-lab model. Preflight cannot establish physical connectivity or make Stage08 PASS from configuration alone.

Actual dashboard service, using configured backend paths/port/lifetime/sample:

```bash
.output/test-env-stage-07/venv/bin/python -B -m test_env.serve replay \
  --env .env --out .output/dashboard-replay-new

sudo .output/test-env-stage-07/venv/bin/python -B -m test_env.serve live \
  --env .env --out .output/dashboard-private-new
```

Set `IDS_SAMPLE` to a genuine retained classification JSONL for replay, or pass `--sample`. Every output path must be **new**; neither config nor CLI enables overwriting existing logs. `IDS_OUT` can provide that path, but changing `--out` per run is usually clearer. Effective file values and actual service overrides are logged to `effective-config.json`.

## Parameter scopes

- `IDS_VM_NAME`, `IDS_LIBVIRT_URI`, `IDS_HOST_WIRED_IFACE`: host discovery metadata/read-only command suggestions. No host commands or bridge changes are executed automatically.
- `IDS_GUEST_MANAGEMENT_IFACE/MAC`: expected management identity. They do not override the actual default-route protection.
- `IDS_GUEST_DEMO_IFACE/MAC`, `IDS_GUEST_DEMO_IPV4`, `IDS_CLIENT_IPV4`, `IDS_TCP_PORT`: physical preflight target metadata. The Windows source IP must come from actual diagnostics/capture, not a WSL or namespace assumption. Blank targets block safely.
- `IDS_DASHBOARD_PORT`, `IDS_RUN_SECONDS`, `IDS_REPLAY_INTERVAL`: actual service settings. Binding remains localhost-only; lifetime remains bounded to 240 seconds.
- `IDS_LOADER`, `IDS_OBJECT`, `IDS_BPFTOOL`, `IDS_READER`, `IDS_MODEL`: actual private service backend inputs; they are checked before lab creation. An empty reader selects `nn-collect` beside the effective loader, including a CLI override.
- `IDS_SAMPLE`, `IDS_OUT`: actual replay input and exclusive log-directory selection.

**`serve live` still means the accepted private namespace/veth lab.** Editing physical network fields does not make it attach to a real NIC. Private interface names, addresses and original RX source filter remain unchanged in the accepted native/BPF profile; no `.env` key disables those guards. The validation CLI (`python -m test_env ...`) and original `run-baseline.sh` retain their explicit accepted interfaces/arguments. Physical runtime support remains behind Stage08's target/permission/connectivity checks.

There are no password, SSH-key or token settings. Local `.env` files must not be committed. The native Windows client needs no WSL; read-only commands are in `evidence/stage-08/windows-client.md`.

## Repeatable host and Windows discovery

### Milestone 1 — collect each physical machine

Copy the standalone `test_env/discover-host.sh` to the **Linux virtualization host**. It needs Bash, Python3 and read access to the existing `ip`, NetworkManager and libvirt tools; it never installs them or invokes sudo:

```bash
bash ./discover-host.sh --vm ubuntu22.04 --wired enp8s0 --uri qemu:///system
```

Copy `test_env/discover-windows.ps1` to the Windows laptop. Run from its directory in native PowerShell; no WSL, Python or administrator shell is required for normal read-only inventory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\discover-windows.ps1 -InterfaceAlias Ethernet
```

Use `-InterfaceIndex 5` **instead of** `-InterfaceAlias Ethernet` if choosing by the currently observed index. Neither form guesses another adapter when the selection is missing. `Bypass` applies only to the launched process; the script does not change the machine's execution policy.

Both commands print exactly one versioned JSON report. Paste each complete report here, without a shell prompt or extra pipeline text. To save instead, append `> host-discovery.json` or `> windows-discovery.json` to the respective command. PowerShell5.1 may save UTF16; the importer accepts BOM-marked UTF16 and UTF8 with/without BOM. No passwords, Wi-Fi authentication profiles or tokens are requested; the reports do contain machine/network identifiers.

Host inventory includes links/addresses, all IPv4/IPv6 route tables, IPv4 rules, domain NIC/disk-driver/memory information, managed snapshot/checkpoint names, local disk filesystem capacity and current wired NetworkManager settings. Windows inventory includes the explicitly selected adapter, IPv4/DNS/DHCP state, all current IPv4 routes, adapter identities and OS/PowerShell versions.

Collector exit0 means the requested inspections succeeded, **not physical acceptance**. Exit1 still prints a report with explicit `errors` and unavailable sections set to null. Missing permissions/tools are not interpreted as empty safe state. Running the host script inside this guest cannot inspect host libvirt; run it on the actual host.

### Milestone 2 — import observations in the Ubuntu guest

Paste both reports here and the assistant can save/import those exact JSON inputs. Alternatively, copy the two files into the repository directory inside the guest:

```bash
# Preview only; .env is not changed.
python3 -B -m test_env.configure \
  --host host-discovery.json --windows windows-discovery.json

# Apply the observed fields to the ignored local .env.
python3 -B -m test_env.configure \
  --host host-discovery.json --windows windows-discovery.json --apply
```

Use `--env FILE` for a different local configuration. Existing settings/comments outside the discovered identity/IP fields are preserved. A missing file starts from `.env.example`; that versioned template and symlink targets cannot be overwritten. Updates are validated with the same literal parser as the service and written atomically with mode0600. No report text is executed.

The importer freshly inspects this guest. It cross-checks the host domain against the actual management/default-route MAC, then follows the selected host wire's **observed bridge** to a domain NIC and its actual guest MAC/name. All actual IPv4/IPv6 default-route interfaces remain protected. The Windows client must be the selected up, physical, non-default-route adapter with a preferred, non-link-local IPv4 address. Its unique source can be imported independently; guest demo IPv4 selection requires an unambiguous same-subnet peer pair. No `.77.2`, `.77.3` or `enpNs0` is invented.

Missing or ambiguous demo fields are cleared, including stale values from an earlier import. APIPA `169.254.*` is not accepted as the demo source. A wrong VM, malformed/duplicate-key JSON, unavailable identity or guest/Windows routes, or invalid literal setting prevents the write. Other collection errors remain explicit physical blockers. `IMPORTED` means the configuration transaction succeeded; its report still says `stage08: BLOCKED`. A valid partial import can retain known host/management fields while leaving physical targets empty.

### Milestone 3 — satisfy the physical gate

Re-run both collectors and import again after IP, adapter or topology changes; reports are point-in-time observations, not authenticated live reachability or permission. The operator retained `.77/24` as current intent, not a permanently assumed address.

These scripts do **not** create a bridge, assign addresses, add a VM NIC, snapshot/revert a VM, send packets, change routes/firewalls/VPNs or attach eBPF. Establish recovery/console access and exact network rollback, then validate the approved bridge and real TCP path. The separate physical backend and Stage08 inference/event/UI/cleanup checks must pass before committing Stage08 or proceeding to Stage09.
