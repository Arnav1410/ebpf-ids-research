# Stage 04 — PASS: bidirectional IPv4/TCP flow tracking

```text
STAGE: 04 — Correct bidirectional flow tracking and concurrency
STATUS: PASS
BASE COMMIT / DIFF: 65c49c737b6791801cc98d9839b930b77ff42435; additive flow backend plus shared TC-controller lifecycle; original src/model/runner unchanged
CHANGES: Canonical flow keys, immutable generation IDs, locked compound statistics and lifecycle, bounded header diagnostics, periodic ID-only GC, read-only inspection, independent packet/reference validation
COMMANDS EXECUTED: commands.json; standalone flows CLI; 17-regression root suite; counter-probe compatibility CLI
BUILD: PASS — clang-12 BPF and static-libbpf C controller/inspector, -Wall -Wextra -Werror
VERIFIER LOAD: PASS — actual TC ingress/egress and auxiliary GC programs
ATTACH: PASS — ID-verified ingress/egress direct-action filters on only owned ids_server/veth-idss; GC never attached
RUNTIME PACKET TEST: PASS — repeated controlled frames, eight simultaneous TCP connections per cycle, actual AF_PACKET comparison, connectivity after detach
CORRECTNESS TEST: PASS — exact independently parsed headers/statistics, variable options, unknown orientation, retransmissions, FIN half-close/full close, RST, tuple reuse, idle/closed GC, same-key replacement survives old-generation GC
EXPECTED VS OBSERVED: Two authoritative cycles each matched all 95 accepted TC observations to 95 AF_PACKET headers; zero capture/tracking loss; exact integer/timestamp reductions; all 17 regressions passed with no skips
EVIDENCE: provenance.json, root-flow-safety-final.stderr.log, safety-final/test_real_bidirectional_generations_concurrency_and_expiration/, probe-compatibility/
CLEANUP / ROLLBACK CHECK: PASS — new owned maps/programs absent, filters/qdisc removed, private lab removed, host preserved, all 20 original fingerprints unchanged
GATE DECISION: PASS — original-XDP exception not used for any new object
NEXT ACTION: Stage 05 — original six RX features/model integration and numerical/classification parity; no TC+NN claim yet
```

## Authoritative evidence

The final [flow proof](safety-final/test_real_bidirectional_generations_concurrency_and_expiration/flows.json), [lab state](safety-final/test_real_bidirectional_generations_concurrency_and_expiration/lab-state.json) and [provenance](provenance.json) cover the current source, including independently measured runtime clock bounds. The earlier [standalone CLI run](live-payload/report.json) also passed; it predates the additional clock-bound and overlapping-expiration assertions. The final root suite executed all 17 tests: ten pure parser/reference cases and seven actual privileged namespace/TC cases. No skips.

| Authoritative cycle | Concurrent TCP connections | TC header observations | Matching AF_PACKET headers | Capture loss | Ingress / egress / GC program IDs | Flow-stat map ID |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 8 | 95 | 95 | 0 | 123 / 124 / 125 | 87 |
| 2 | 8 | 95 | 95 | 0 | 129 / 130 / 131 | 94 |

Both cycles also passed the actual `flow-inspect` executable and owned-object release checks. Full identities of all seven maps are in provenance and each session's evidence. The unchanged counter-probe contract passed another [real two-cycle CLI run](probe-compatibility/report.json) after the shared C/Python lifecycle changes.

## State and concurrency contract

- Canonical key: protocol, sorted IPv4/port endpoints and protected interface index. The private map instance supplies namespace context. Reversed endpoints resolve to one generation ID.
- `a_to_b`/`b_to_a` are canonical directions, not TC hook names. Ingress/egress means protected-host RX/TX. An observed initial SYN without ACK establishes orientation; otherwise `initiator` remains `unknown`. This does not infer dataset client/server labels from hook direction.
- Every observed duplicate/retransmission counts as another observation; these are not deduplicated application bytes. Per-direction fields include packets, IPv4 bytes, TCP segment bytes, TCP header bytes, min/max segment size and timing.
- A generation is never reset in place. The bounded canonical LRU index points to unique 64-bit IDs; locked statistics are keyed by that ID. Only a definitely unpublished CAS loser is immediately discarded. A successfully published generation retains its ordinary lifetime even if subsequently displaced.
- Compound counters, timestamps, orientation and FIN/RST state use a short BPF spin lock. No helper or tail call runs while held. Snapshots use `BPF_F_LOCK` per generation; the whole table is not a global transaction.
- One FIN is half-close. Two FINs without both peer acknowledgements are `closing`, not complete. FIN acknowledgement comparisons use modulo-32-bit sequence arithmetic. RST is immediately terminal. An observed new SYN epoch retires the prior generation without changing its accumulated statistics or existing closed deadline.
- The controller periodically test-runs a dedicated GC BPF program. It checks the unique ID's state/time and marks a tombstone under lock, then deletes that ID after unlocking. It never deletes a canonical key and cannot delete a replacement with a different ID.

The [expiration proof](safety-final/test_real_bidirectional_generations_concurrency_and_expiration/flow-expiration-proof.json) observes separate closed/idle TTLs. It specifically expires generation 2 while generation 3 with the same canonical tuple remains live and unchanged. It then observes idle expiration and new-ID recreation through a stale index entry. GC scheduling is checked against the configured TTL plus an explicit five-second scheduling allowance; this is not a latency benchmark.

Storage is bounded to 8,192 statistics values and a 16,384-entry LRU index. Index pressure can split continuity; stale numeric index entries are not indefinitely retained statistics. Capacity, bounded-resolution, observation-loss, GC-failure and ID-exhaustion counters are exposed. Controlled runs require these errors to remain zero; this evidence is not a proof of all possible interleavings or overload behavior. Aligned 64-bit ID reads target this x64 VM; writes use atomic compare-and-swap.

## Parser, clocks and limits

IPv4 and TCP header lengths are validated, including options. VLAN in headers/metadata, IPv6, fragments, non-TCP/non-IPv4 protocols, truncated/malformed packets and unavailable non-linear headers have explicit skip reasons. UDP is not implemented. No packet is blocked: every packet path returns `TC_ACT_OK`.

Non-linear **payload** is supported without copying it. Complete headers must be directly readable; declared IPv4 length is checked against total skb length, not just its linear head. Header-only diagnostics are bounded and opt-in; the ordinary tracking regression verifies real request/response bytes are tracked without exporting packet headers. AF_PACKET membership and diagnostic ring mappings are released at exit. Injector manifests contain only our fixed synthetic fixtures, not captured application payload.

Timing uses actual `bpf_ktime_get_ns()`, sampled before locking and monotonically clamped under the generation lock. The independent reducer recomputes IAT/statistics exactly from these recorded observations. Python monotonic session/receive bounds also constrain the kernel and controller timestamps. AF_PACKET independently proves header contents/counts, not an exact independent wire clock. No GRO/GSO/TSO settings were disabled; no wire-segmentation, throughput, latency or model-accuracy claim follows from this gate.

The legacy six RX model features remain a separate Stage 05 contract: maximum TCP segment bytes, maximum RX gap in ns, minimum segment bytes, destination port, cumulative TCP header bytes, RX packet count. The original model triggers on the RX FIN/RST packet, not on later complete bidirectional FIN/ACK shutdown. There is no NN inference or shared NN scratch in this stage.

## Failures preserved, not suppressed

1. `build-initial.stderr.log`: clang-12 cannot lower the original C11 atomic-load IR to BPF. Explicit aligned volatile loads retain the required x64 single-copy read while all writes remain atomic CAS.
2. [Initial load](live-initial/report.json): the verifier could not bound the byte-assembled 32-bit IPv4 length before packet-pointer addition. The length now has its actual 16-bit protocol type; subsequent real loads passed.
3. [Configuration handshake](live-bounded/report.json): C included its diagnostic capacity but Python expected a smaller exact dictionary. Both now validate the same complete versioned contract, including clocks and snapshot scope.
4. [First packet comparison](live-contract/report.json): blanket rejection of non-linear skbs skipped 16 ordinary TCP data packets. This failed the independent AF_PACKET comparison. The parser now requires only headers to be linear and checks payload length against total skb length. The corrected runs match every accepted header with no skip masking, checksum normalization or offload changes.

No new cleanup waiver, package installation, original-XDP rerun, commit or push was performed.

## Interfaces and reproduction

- `test_env/flow.bpf.c`, `flow.h`: real tracking ABI and programs.
- `flow_controller.c/.h` plus shared `probe_loader.c`: private scoped loader, snapshots, bounded diagnostics, GC and inspector.
- `flows.Flow`: a backend specialization of the strict common TC lifecycle; default capture is off. `inspect()` reads current owned state, not replay.
- `flow_reference.py` and `flow_fixture.py`: independent header/statistics oracle, raw controlled frames, AF_PACKET capture and concurrent real sockets.
- `python3 -B -m test_env flows`: fixed-topology acceptance command, not a production daemon.

```bash
make -C test_env OUTPUT="$PWD/.output/test-env-new"
sudo python3 -B -m test_env flows \
  --out .output/flow-validation-new \
  --loader .output/test-env-new/flow-loader \
  --object .output/test-env-new/flow.bpf.o \
  --bpftool .output/bpftool/bpftool
```

Use a new output directory and an isolated VM with the lab names unused. Exact accepted dependency overrides are in [commands.json](commands.json). During an owned live session, `flow-inspect MAP_ID veth-idss /run/netns/ids_server --owner-pid LOADER_PID`, entered using `nsenter --net`, validates namespace/interface, kernel FD ownership and map ABI before opening a read-only descriptor and taking locked snapshots. It does not adopt resources or modify maps.
