# Stage 08 — physical Ethernet integration prerequisite check

```text
STAGE: 08 — Two-laptop Ethernet integration
STATUS: BLOCKED
BASE COMMIT / DIFF: 08c20c401224ed2ddf9feac7f690a143ea5a340d on test-env; native-Windows scope amendment, literal .env configuration, read-only preflight and actual service integration
CHANGES: Literal editable configuration and guarded service integration; standalone Linux-host/native Windows JSON collectors; validated preview/atomic import into ignored local env; private backend guards preserved
COMMANDS EXECUTED: Earlier configuration/service proof in config-commands.json; new regression/collector/import/preflight commands in .output/test-env-stage-08/discovery-verification/commands/commands.json
BUILD: NOT APPLICABLE — Python/Bash/PowerShell-only changes; latest suite90 tests discovered,81 passed,nine privileged cases skipped; actual configured service startup passed in prior configuration proof
VERIFIER LOAD: NOT TESTED for physical integration; unchanged NN object loaded successfully in the configured private regression
ATTACH: NOT TESTED for physical integration; configured private namespace TC hooks passed and were released
RUNTIME PACKET TEST: NOT TESTED from native Windows yet; one real private TCP exchange produced one complete kernel event through the file-configured service
CORRECTNESS TEST: NOT TESTED on the physical path; private public event matched final kernel ledger; actual management-target override refused
EXPECTED VS OBSERVED: Actual host/Windows collectors report zero errors. Host enp8s0 is UP/LOWER_UP at192.168.77.1/24; Windows Ethernet is up/static192.168.77.2/24. qcow2,8GiB VM RAM and92.6GiB available host storage confirmed. No managed snapshots/checkpoints, wired bridge or second guest NIC exist in supplied observations
EVIDENCE: operator-discovery-review.json and its retained real-input import/preflight command logs; earlier policy/storage, approval and synthetic configuration proof remain historical
CLEANUP / ROLLBACK CHECK: PASS for owned private regression resources; all services exit 0 and private BPF/namespace resources released; no physical interface changes; physical rollback readiness unconfirmed
GATE DECISION: BLOCKED — do not begin physical attachment or advance to Stage09
NEXT ACTION: Establish a VM recovery point and local console plus exact host/Windows rollback; then prepare the approved isolated bridge/second NIC and prove real traffic before physical attachment
```

## Confirmed guest state

- Guest is KVM. The operator's libvirt interface/network output maps the supplied `ubuntu22.04` management MAC through host `vnet2` to `default`, whose XML confirms NAT on `virbr0`.
- Only `lo` and Ethernet `enp1s0` exist. `enp1s0`: ifindex 2, MAC `52:54:00:73:34:a0`, address `192.168.122.20/24`, default gateway `192.168.122.1`.
- `enp1s0` has root `fq_codel`, no observed ingress/egress TC filters, and is the protected management interface. No named lab namespaces remain.
- No SSH hosts are configured in the available host-access tool; no operator-supplied host destination is available. An unknown destination is not a reason to guess or probe the gateway as a lab host.
- Libvirt XML confirms `default` uses NAT and bridge `virbr0` at `192.168.122.1/24`; `vnet2` is its forwarding port. This remains the management network, not the proposed physical demo bridge.
- Actual host report observes `enp8s0` UP/LOWER_UP, `192.168.77.1/24`, driver `r8169`, no bridge master. The earlier NO-CARRIER observation is superseded.
- Current NM profile is `enp8s0`, UUID `fe6361a5-d2e1-4012-997f-d5b161098d9a`, manual IPv4, IPv6 ignore, state connected externally. Do not assume that generated/external profile is durable or reset it to the earlier `Wired connection 1` DHCP profile on rollback.
- The disk driver is now confirmed `qcow2`, VM memory8GiB, host filesystem available92.6GiB, managed snapshots/checkpoints empty. These are preparation facts, not a created/tested recovery point. Reported routes have direct `.77/24` paths; actual packet delivery remains untested.
- Native Windows5.1 collector succeeds: physical Ethernet index5 is Up at100Mbps with preferred manual `192.168.77.2/24`, DHCP disabled, no IPv4 DNS/default route on that adapter. The original APIPA state is superseded; no Windows setting was changed by the agent.
- Host facts and the operator-approved **native Windows client, no mandatory WSL** amendment are retained in `operator-update.json`. The execution plan was updated accordingly; actual packet/inference/rollback requirements remain.

## Preserve the accepted implementation

`test_env/private_scope.h` and `private_scope.c` deliberately constrain the accepted loader/reader to the owned `ids_server` namespace and a verified `veth-idss` veth pair. It is not a general real-interface loader. That guard has not been removed or bypassed. A physical profile must be implemented separately once its exact safe scope is established.

The accepted original-feature inference profile also filters matching RX source `33.33.33.73` (`nn_bpf.h:nn_eligible`). Native Windows traffic must first be captured to establish its actual source. Editing `IDS_CLIENT_IPV4` does not silently broaden the fixed private filter or change the checked-in baseline/model; physical runtime support remains separately gated.

## Required setup and operator input

Conservative target: **retain `enp1s0` unchanged and add a second guest NIC connected to a verified wired demo bridge**. Do not add a competing default route through the demo NIC. Do not change a host's management uplink to create a bridge without reviewing its connectivity impact and rollback.

Before configuration/attachment, establish:

1. Actual host/native Windows collector reports are now received with zero errors and have been validated/imported. Do not request another broad inventory dump; establish recovery/console and scoped network rollback next.
2. Preserve the approved `.77/24` intent, candidate wired ports and second guest NIC. Discover the guest NIC's actual name/MAC after addition; do not reuse management identity or hardcode proposed IPs as observed.
3. Preserve the observed Windows source `.77.2` and verify actual guest addressing, route/interface/source selection and packet delivery after creating the approved bridge/new NIC.
4. A working VM snapshot or equivalent rollback, plus host/guest console access independent of the experimental NIC.
5. Explicit approval of the identified non-management target. Starting Stage08 is not permission to experiment on the sole management NIC.

### Read-only diagnostics still required

The operator requested one script per physical machine and automatic configuration import. `test_env/discover-host.sh` and `test_env/discover-windows.ps1` produce versioned read-only JSON. `python -m test_env.configure` cross-checks the host VM against this guest's actual management MAC and derives only an observed, non-default-route demo NIC on the bridge containing the selected wire. It clears missing/stale targets and preserves unrelated service settings; preview is the default, `--apply` writes the ignored local file.

Commands and encoding/partial-report rules are in [test_env/CONFIGURATION.md](../../test_env/CONFIGURATION.md#repeatable-host-and-windows-discovery). Copy collectors to the actual Linux host and native Windows laptop; running the host collector inside this guest cannot inventory host libvirt. Reports contain network metadata but no requested passwords or Wi-Fi secrets. Configuration import is not network configuration, physical acceptance or permission to attach.

The actual guest preflight still reports only `lo` and `enp1s0` and remains BLOCKED. No host/Windows network changes or physical eBPF load occurred. The new `.77.1` host address is operator-supplied, not an agent-applied change.

## Editable configuration and exercised checks

- Root `.env` is the ignored local file; `.env.example` is the portable template.
  Known host/VM fields are filled locally; unknown demo identity/IP fields remain
  empty and block safely. No password/key fields exist.
- `test_env/config.py` parses literal data, never shell code. CLI flags override
  the file; the file overrides builtins. Paths are repository-root relative.
- `python -B -m test_env.preflight --env .env --out NEWDIR` performs real read-only
  guest inspection and emits blockers/host command suggestions. All actual
  default-route interfaces remain protected even if config mislabels management.
  This command does not perform physical acceptance or attachment.
- `test_env.serve live|replay` consumes file-backed paths, output, port, lifetime
  and replay settings. Its `live` mode remains the accepted **private** lab.
  Physical fields are explicitly preflight-only, not an attachment switch.
- File-driven replay actually bound port 8876 for its configured lifetime;
  CLI override actually bound 8877. Chromium rendered SIMULATED REPLAY there.
  Automatic root `.env` loading was exercised separately.
- Actual preflight refused a file targeting management `enp1s0`. Invalid live
  input failed before output/lab creation. The configured private service
  accepted a real TCP exchange, produced a complete kernel event matching its
  ledger, derived its reader beside the effective loader and cleaned up.
- No native/BPF/model files changed. Among the original 20 fingerprints, only
  `.gitignore` (local env exclusion) and the user-approved execution-plan client
  amendment intentionally differ; the other 18 remain unchanged.

Usage and parameter scopes: [test_env/CONFIGURATION.md](../../test_env/CONFIGURATION.md).
Proof: [config-verification.json](config-verification.json). These are completed
configuration/private-regression checks, **not a Stage08 PASS**.

## Source control

Stage08 has **not** passed, so its current evidence is intentionally uncommitted. The commit-after-PASS policy remains in effect. Stages00–07 remain accepted and committed; no previous validation is relabeled as physical integration success.

## Discovery/import verification

[Discovery verification](discovery-verification.json) records the actual CLI
commands and their limits. The full Python suite discovered90 tests:81 passed,
nine privileged cases skipped. Collector execution in this guest returned real
network/NM/driver data and explicit missing-host-libvirt errors. PowerShell7.4.22
parsed the script without errors; actual execution on Linux returned a JSON
failure for unavailable Windows cmdlets, not invented adapter data.
That initial smoke did not exercise native Windows; actual operator-supplied
Windows5.1/host reports are now reviewed in operator-discovery-review.json.

Actual importer preview/apply used explicitly synthetic protocol fixtures plus
fresh guest inspection, writing only an isolated smoke env. It preserved the
custom port, cleared stale physical targets and set mode0600; an actual
incomplete host report was refused without modifying the file. Preflight
executed and suggested both copied collectors while remaining BLOCKED.

Active `.env`, guest interface identities/addresses and all route tables were
preserved. Raw snapshots differed only by DHCP lease lifetime countdown
2632→2402 seconds; this is recorded, not mislabeled byte-identical networking.
The temporary checksum-verified portable runtime/archive were removed after
the smoke; compact evidence and command logs remain. No new physical
networking, snapshot or BPF operation occurred.


## Actual operator reports and configuration import

`host-discovery.json` and `windows-discovery.json` are actual operator-supplied
reports collected2026-11-07, not synthetic fixtures. Their fingerprints, current
profile/storage/link facts and exact runtime evidence path are in
[operator-discovery-review.json](operator-discovery-review.json).

Actual preview/apply both exited0. `.env` already matched the observed values,
so its contents did not change; client source `.77.2` is confirmed and the
missing guest demo interface/MAC/IP remain empty. Unrelated settings were
preserved. Fresh guest preflight exited1 with no inspection-command errors:
only `lo`/protected `enp1s0` exist, the three demo fields are missing, and the
separate physical backend is not accepted. This is expected gating, not an
observed verifier/inference failure. No physical change, snapshot or attachment
was executed by the agent; Stage08 remains BLOCKED and uncommitted.

