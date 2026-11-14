# Offline-calibrated fixed-point experiment

This adds a separately selected `layer_specific` inference mode to the verified
TC baseline at `791e25932e01a8e457c81237fdc8da2ea971b32e`. `static_q16` remains
the default. Original XDP/model/training files, six ingress-derived features,
flow synchronization, canonical bidirectional monitoring and tail calls remain
unchanged. Egress statistics do not become MLP inputs. See the
[experiment report](../verification-logs/layer-specific-20261107/REPORT.md)
and [arithmetic specification](DESIGN.md) for evidence and limitations.

## Arithmetic and calibration

Integer `v` at exponent `q` means `v / 2**q`. Original Q16 uses integers to
implement fractional inference without kernel floating point; uniform `q=16`
makes the original scale transitions simple. This experiment tests whether
more activation precision and explicit rounding improve numerical fidelity.
It does not recover missing weight precision or adapt scales at runtime.

| Tensor | Original q | Experimental q |
| --- | ---: | ---: |
| Normalized inputs | 16 | 22 |
| Linear 0 / ReLU 0 | 16 | 23 |
| Linear 1 / ReLU 1 | 16 | 21 |
| Output logits | 16 | 18 |
| All weight matrices | 16 | 16 |

The bias-free 6→32→32→2 network uses unchanged Q16 weights from
`src/mlp_params.bpf.h`. No original FP32 checkpoint was available. The
high-precision reference reconstructs the **exact rational header network**,
including its already rounded normalization constants. It is not the authors'
original floating-point model.

`calibrate.py` hashes each stored feature vector with the fixed
`lsfp-20261107` salt. Identical vectors stay in one partition: 4,996 calibration
rows and 13,844 held-out rows. Labels are not used. The calibration subset
determines factor-two power-of-two bounds; per-neuron triangle bounds select
the largest safe activation exponents. Candidate weight exponents 12–16 are
evaluated; Q16 retains all available weight information and meets the bounds.
Higher exponents cannot recover information from a Q16 source. The selected
configuration and dataset/header hashes are in [calibrated.json](calibrated.json).

For each dot product, accumulator exponent is `q_input + q_weight` and the
rescaling shift is `q_input + q_weight - q_output`: 15, 18, 19 respectively.
There are no nonzero biases to convert. Experimental normalization and shifts
round to nearest, ties to even, symmetrically for negative values. Accumulation
uses checked int64, outputs checked int32; invalid scales, inputs or arithmetic
reject the prediction, increment diagnostics and release the existing inference
state. There is no silent saturation or successful wrapped result. Packets pass.

Supported input domain is componentwise
`abs(raw - mean) <= scale * [8,128,64,16,16,16]`. This is an explicit deployment
limit; flows outside it are not successfully classified in experimental mode.
Original Q16 arithmetic is retained separately, including its existing limits.
Both modes classify `logit0 > logit1` as class 0 and ties as class 1.

Example: row 0 normalizes to
`[3162003,-1742632,-310689,-1189055,-963064,-962539]` at q22. First-neuron weights
`[459,25462,-44400,-20077,-17088,-21160]` produce accumulator `31571875100` at
q38. Nearest-even division by `2**15` gives `963497` at q23. The
[saved example](../verification-logs/layer-specific-20261107/layer_example.json)
includes final logits and host comparison.

## Implementations and verification

`reference.py` supplies independent original-integer, experimental-integer and
exact-rational references. Shared [arithmetic.h](arithmetic.h) is compiled into
host C and the experimental BPF stages; host compilation is not kernel proof.
Separate TC objects/controllers avoid mixing parameter ABIs: 5,216 bytes per
original slot, 5,304 per experimental slot, with 88 bytes of scale/domain metadata.
The controller checks layouts, loads and reads back both slots, then freezes the
private parameter map before execution. The selected slot carries one immutable
configuration through the existing six-stage chain. The per-CPU workspace and
locked shared-flow ABI are unchanged.

Executed gates 1–5 passed: 21 Python tests, 19,004 host-C fixtures / 2,584,544
integer comparisons with UBSan, private kernel regression/rejection tests, and
actual attached TC tests in both modes. Gate 5 checked 122 records / 732 stage
tensors / 16,592 integers, with no mismatches; this count includes its private
kernel suites as well as live packet results. Ten-flow and same-flow checks,
packet-witness comparisons and owned resource cleanup passed. Exact kernel
interleaving and interrupt nesting are not forced by the concurrency tests.

Held-out mean absolute logit error versus the reconstructed header network was
`1.775953468e-4` for static Q16 and `9.913700805e-7` for layer-specific scaling.
All 13,844 labels agreed, with no arithmetic events. An independent Python-only
nearest-even Q16 ablation lies between them: both rounding and activation
precision contribute. These are fidelity and prediction-agreement results,
not detection accuracy or F1. Dataset provenance and the original training split
are not established.

## Reproduction and demonstration

Run from the repository root on a feature branch. These commands are unprivileged:

```bash
make -C tc layer-specific
python3 -m unittest -v quantization.test_reference quantization.test_benchmark
python3 quantization/run_host.py --output /tmp/ls-host-demo
```

Recalibration writes the checked-in generated files and numerical reports, so it
is an explicit development step, not necessary for a demo:
`python3 quantization/calibrate.py --output /tmp/ls-calibration-demo`.
Reproduction expects the original stored dataset and compiler/libbpf dependencies
described by the TC build. Use fresh evidence paths for new test preparations.

Prepare either isolated live demo without privileges:

```bash
./run-tc-smoke.sh --prepare --mode static_q16 --phase2 --output /tmp/tc-static-demo
./run-tc-smoke.sh --prepare --mode layer_specific --phase2 --output /tmp/tc-layer-demo
```

After approval for namespace/veth/TC operations, run each preparation's printed
`sudo ... --run ... --mode ... --phase2` command. It tests only owned virtual
interfaces, prints the evidence path and verifies cleanup. No primary interface
is selected. Do not reuse old frozen bundles after changing source or binaries.
On failure inspect that run's controller/verifier logs; do not globally flush TC
or BPF resources. Snapshots retain input features, every tensor, logits and class.

Saved successful evidence can be displayed without any new networking operations:

```bash
cat quantization/calibrated.json
cat verification-logs/layer-specific-20261107/layer_example.json
cat verification-logs/layer-specific-20261107/numerical_metrics.json
cat verification-logs/layer-specific-20261107/live_review.json
```

## Runtime comparison: Gate 6 passed

The validation-only benchmark uses two private unattached objects and
`BPF_PROG_TEST_RUN` with `repeat=1`. Each call must produce fresh correct tensors,
one prediction and every tail stage, with released workspace. Map resets happen
between calls, outside the recorded kernel duration. Two feature vectors and
an entry/FIN path use 12 paired blocks, 32 warmups and 64 retained samples per
mode/workload/block, alternating mode order on one allowed CPU. No outliers are
discarded. See the [pre-run protocol](../verification-logs/layer-specific-20261107/BENCHMARK_PLAN.md).

The actual private-kernel run passed on WSL2 kernel
`6.6.87.2-microsoft-standard-WSL2`, i7-1255U, CPU 0. There were 4,608 retained
timings and 2,304 warmups. All six stages executed 6,912 times each; every call
was checked for tensor consistency. Independent replay matched all 72 stored
records / 432 stage tensors / 9,792 integers, recomputed the timing summaries,
and verified that all 16 program IDs and 17 map IDs were released. No interface
was attached by this benchmark. [Raw run](../verification-logs/layer-specific-20261107/benchmark-ready/run-20261107-121805-782575/REPORT.md),
[offline audit](../verification-logs/layer-specific-20261107/benchmark_review.json).

| Workload | Q16 median ns | Layer-specific median ns | Paired block-median ratio |
| --- | ---: | ---: | ---: |
| Small TCP feature vector | 1560 | 2626 | 1.706 |
| Saved packet feature vector | 1538.5 | 2690.5 | 1.712 |
| Entry / FIN with pre-existing fresh flow | 1710.5 | 2798 | 1.652 |

Each cell summarizes 768 timings. The ratio is the median of twelve paired
block ratios, not the quotient of the pooled medians. Layer-specific arithmetic
was slower in all three measured workloads. Its rounding and safety checks
change along with scale precision; rescaling cost is not isolated. Retain static
Q16 as the default; present the experimental mode as a measured precision/cost
tradeoff, with unchanged predictions on the available held-out examples.

```bash
python3 quantization/benchmark.py --prepare --output /tmp/ls-benchmark-demo
```

Preparation runs host tests only and prints the exact privileged execution
command; obtain approval before running it. The measured kernel-returned
test-run durations include runner, tail-call, map telemetry and result-publication
costs. They do not isolate rescaling or per-stage arithmetic and do not establish
NIC throughput or end-to-end latency. WSL2 scheduling/frequency noise remains.
Compilation/verifier instruction counts are not runtime timing measurements.
Per-stage timing, rescaling-only timing, physical-NIC throughput and application
latency remain unmeasured. Use a fresh preparation after source/documentation
changes: the saved successful bundle is a frozen historical record.

Existing parser/fragmentation/offload/flow-lifecycle limits remain. Pre-lock
timestamp reordering is clamped and counted; this prevents unsigned IAT underflow
but cannot reconstruct exact chronological inter-arrival times on concurrent CPUs.
