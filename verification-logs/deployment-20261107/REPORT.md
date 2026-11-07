# Deployment/dashboard verification — WSL2 PASS; native pending

The [status and implementation report](../../DEPLOYMENT_STATUS.md) and
[operator runbook](../../SERVER_DEPLOYMENT.md) distinguish native execution
from these isolated WSL2 results. No physical interface was selected.

Successful new-path evidence:
`ready-r3/run-20261107-172333-697064/`.
[Runtime report](ready-r3/run-20261107-172333-697064/REPORT.md),
[independent offline replay](VERIFIED.json).

| Observation | Q16 | Layer-specific |
| --- | ---: | ---: |
| Attached ingress / egress program IDs | 628 / 629 | 639 / 640 |
| Retained flow/prediction records | 11 | 11 |
| Each of six tail-stage counters | 11 | 11 |
| Independently compared tensors / integers | 66 / 1,496 | 66 / 1,496 |
| Tail-call / inference failures | 0 / 0 | 0 / 0 |
| Global ingress packets / bytes | 78 / 5,795 | 77 / 5,753 |
| Global egress packets / bytes | 57 / 8,393 | 55 / 8,261 |
| Per-flow TCP ingress / egress packets | 77 / 55 | 77 / 55 |

The controls and model/flow ABI passed the actual verifier in both modes.
The HTTP dashboard process ran as UID 1000, using real collector output.
All 23 host/HTTP tests passed without skips inside the namespace. Full-capacity
and restart/dedup checks use host fixtures, not synthetic claims of live load.
Both modes preserved a separate matchall classifier added after measurement,
then refused a new deployment while it remained. The dedicated test removed
only that test-owned classifier before namespace teardown.

All owned IDS filters/private IDs, test processes, runtime directories and
namespaces passed cleanup. The controller left clsact in place, as required;
the isolated namespace was subsequently removed. Existing addresses/MTU/admin
state and IPv4 routes were unchanged. Global counts can include ARP/control
skbs; do not equate them to TCP per-flow counts.

Raw kernel feature/logit samples (different clock-derived IATs; these are not
an identical-input cross-mode experiment):

- Q16: `[85,356015,32,8000,136,4]`, logits `[-198176,171123]` at q16, class 1.
- Layer-specific: `[85,1142749,32,8000,136,4]`, logits `[-792727,684514]` at q18,
  class 1.

The full intermediate tensors are retained in the two `map-snapshot-*.log`
files and matched their respective integer references, with zero mismatches.
This verifies arithmetic, not detection accuracy.

The unchanged original regression suites ran earlier in the first approved
deployment invocation and passed both full `--phase2` gates:

- `ready/regression-static_q16/run-20261107-171750-708464/`
- `ready/regression-layer_specific/run-20261107-171755-579088/`

The final run explicitly reused those results after verifying matching source
hashes. Per mode they retain 61 predictions / 366 stage tensors / 8,296 integer
comparisons, private same-flow concurrency/failure tests, ten attached flows,
burst tests and cleanup. These counts are separate from the 11 new deployment
records above.

Earlier new-runner failures were diagnosed and preserved: a long AF_UNIX socket
path in revision 1; a raw-address-JSON comparison of the transient IPv6
`tentative` flag in revision 2. Neither required an inference change. The final
runner rejects overlong socket paths before loading and compares configured
address fields with a regression for real modifications.

Kernel/compiler: `6.6.87.2-microsoft-standard-WSL2`, x86_64,
clang `12.0.1-19ubuntu3`, vendored libbpf 1.3, bpftool 7.3.0, Python 3.10.12.
Native Linux, `enp8s0`, physical Ethernet and Windows client execution:
**PENDING USER EXECUTION**. Native browser rendering and distribution/toolchain
compatibility require operator evidence; localhost HTTP/API tests do not prove
those. No SSH, automatic push, physical attachment or host network change ran.
