# Offline-calibrated fixed point: arithmetic specification (Gate 1)

Baseline: `791e25932e01a8e457c81237fdc8da2ea971b32e`. Experimental branch:
`feature/layer-specific-fixed-point`. This specification precedes implementation.
Original XDP/model/training files and TC flow semantics remain unchanged.

## Actual original mathematics

Convention: an integer `v` at exponent `q` represents `v / 2**q`.
The source is `src/mlp.bpf.h`, `params.bpf.h`, `mlp_params.bpf.h` and `mlp.py`.
The three linear layers are explicitly **bias=False**; there are no bias vectors
to invent or recover. The architecture is 6 -> 32 -> 32 -> 2, with two ReLUs.

| Operation | Input/parameter representation | Arithmetic/output |
| --- | --- | --- |
| Features, rounded mean/scale | signed int64, q=0, original feature units | TCP-segment bytes, IAT ns, segment bytes, port, TCP-header bytes, packets |
| Normalization | signed comparison determines sign; unsigned magnitude and divisor | unsigned `magnitude*65536 / scale`, truncating positive quotient; narrow to int32, restore sign; output q=16 |
| Linear 0/1/2 | input int32 q=16; weights int32 q=16 | products widened before multiplication, signed int64 accumulator q=32; arithmetic `sum >> 16`, then int32 narrowing; output q=16 |
| Bias (all layers) | absent, exactly zero | algebraically zero at accumulator exponent 32 |
| ReLU | int32 q=16 | max(v,0), same exponent |
| Prediction | two int32 logits at q=16 | class 0 iff logit0 > logit1, otherwise 1, including ties |

Normalization truncates toward zero; negative linear rescaling floors on the
tested clang/x86/BPF implementation. The original is not portable for arbitrary
inputs: unsigned normalization multiplication wraps above uint64; narrowing
outside int32 is implementation-defined in C; negating INT32_MIN and overflowing
signed accumulators are undefined C operations. Negative signed right shift is
implementation-defined C, although the tested host/BPF arithmetic shift agrees.
There is no zero-scale guard in the original function. Actual stored scales are
positive. The existing validation suite characterizes these cases; they must
not be silently changed in `static_q16` mode.

The checked-in header and hardcoded shifts use 16 fractional bits. The quantizer
accepts a CLI exponent, but the repository does not establish why the authors
selected 16 or that it is optimal. Integer arithmetic avoids kernel floating
point; changing exponents can redistribute rounding error and range headroom.
It does not by itself establish improved detection accuracy or runtime.

## Parameter/data provenance

No `.th`, `.pt`, `.pth`, `.pkl`, `.onnx` or `.safetensors` checkpoint was found
under `/home/arnav/research` during inspection. The best available parameter
source is therefore the checked-in Q16 header: 192 + 1024 + 64 weights, six rounded
means and six rounded scales. Weight real values are defined **exactly** as
header integers / 65536. Rounded normalization constants cannot recover their
original unrounded values. Increasing the exponent cannot recover lost weights.

The stored NPY matrix is int64, shape (18840,6), SHA256
`787a3bf845a5714f79c27aafceaa6feeb59ec53a405035d2ebe64775a3dcb96e`.
The labels file is float64 shape (18840,), SHA256
`edbbc05ed553442139c0ddd7b8211aa8aa98347c7b8d3d2e3e7a0f72463d1924`.
They first appear in repository commit `58bbbb5` (message `update`). No collection
pipeline, train/test independence or compatible label meaning is established by
those files. The original training script splits without a fixed seed and fits
its scaler to the entire matrix; the original checkpoint/split is unavailable.
This experiment measures arithmetic fidelity and prediction agreement, not F1.

## Proposed deterministic calibration

Split by **feature-vector group**, never labels: compute SHA256 of
`b'lsfp-20261107\0' + struct.pack('<6q', *row)`; assign to calibration iff the
first eight bytes, interpreted unsigned big-endian, are below 2**62. Identical
feature vectors cannot cross the split. Inspection found 18,561 unique vectors;
this rule produces 4,996 calibration and 13,844 held-out rows. Global inspection
statistics do not enter the selector; only calibration rows determine bounds.

For feature j, choose the smallest power-of-two `B[j] >= 1` satisfying
`B[j]*scale[j] >= 2*max_cal(abs(raw[j]-mean[j]))`. This declares the supported
raw domain `abs(raw[j]-mean[j]) <= B[j]*scale[j]`, intersected with int64.
The factor two is fixed in advance, not tuned on held-out data. It gives
normalized bounds `[8,128,64,16,16,16]`. Out-of-domain inference is rejected,
counted and produces no successful prediction; packets still pass.

Weights: examine candidate q=12..16 quantization error. Select q=16 when its
exact representation satisfies accumulator safety. q>16 adds no source precision.
All actual layers meet the conservative bound with q=16, so their recorded
weight integers remain exact and unchanged. Bias is zero, at each accumulator's
exponent; no bias storage or extra model parameter is introduced.

Choose normalized q as the largest 0..24 for which every `B[j]*2**q < 2**30`.
Propagate **per-neuron triangle bounds**, not only observed activations:
`A[i] = sum(abs(W[i,j])*input_integer_bound[j])`. Require A[i] <= INT64_MAX.
Choose the largest output q in 0..30 with shift `s=q_input+16-q` in 0..62 and
`ceil(A[i]/2**s) < 2**30` for every neuron. ReLU preserves these absolute bounds.
This gives one full spare signed magnitude bit and protects every raw input in
the declared rectangular domain, including combinations absent from calibration.

| Stage | Input q | Weight q | Bias/accumulator q | Output q | Right shift |
| --- | ---: | ---: | ---: | ---: | ---: |
| Normalize | raw/mean/scale 0 | n/a | rational division | 22 | quotient/remainder division |
| Linear 0 | 22 | 16 | 38 | 23 | 15 |
| ReLU 0 | 23 | n/a | n/a | 23 | 0 |
| Linear 1 | 23 | 16 | 39 | 21 | 18 |
| ReLU 1 | 21 | n/a | n/a | 21 | 0 |
| Logits | 21 | 16 | 37 | 18 | 19 |

The largest conservative absolute accumulators are respectively
34,654,816,043,008; 224,214,960,404,480; 327,688,736,106,947, all below INT64_MAX.
The implementation must reproduce this selection and bounds independently.

## New integer rules (fully specified)

All experimental rescaling uses **round to nearest, ties to even**, symmetrically
for negative values. Python uses unbounded integers with explicit bounds checks.
C/BPF uses checked int64 accumulation and unsigned-magnitude rounding. Neither
wrap nor saturation is accepted as a successful experimental result.

Normalization computes `m=abs(raw-mean)` through signed comparison followed by
unsigned subtraction, avoiding signed subtraction/negation overflow. First
check the declared raw-domain limit and positive divisor. For `m = a*scale+r`,
compute `base=(a<<q)+((r<<q)//scale)` and remainder `(r<<q)%scale`, then round
base to nearest-even and restore sign only after checking int32 bounds. Check
unsigned shift/multiplication bounds before use. This avoids `m*2**q` overflow.
All left shifts operate on unsigned values; q is checked before shifting.

Each linear layer accumulates int32*int32 products in int64 with a checked add.
For a right shift s>0, use unsigned magnitude, quotient and low-bit remainder;
increment when remainder > half, or remainder == half and quotient is odd.
Handle s=0 separately. Check s in 0..62 and final int32 representability before
restoring the sign, including an explicit INT32_MIN case. INT64_MIN magnitude
uses unsigned subtraction, not signed negation. ReLU and the tie-to-class-1
comparison are unchanged. No negative signed left shift or unchecked narrowing
is permitted. A general nonzero bias would need conversion to q_input+q_weight
before summation; this actual network has exactly zero biases.

Hand example: x_q=3 at q_input=2 and w_q=2 at q_weight=1 represent 0.75 and 1.
Accumulator 6 is at q=3. Selecting q_output=2 means shift 1, output integer 3.
Accumulator -3 with shift 1 is -1.5 integer units and rounds to -2; -1 with
shift 1 is -0.5 and rounds to zero. These are arithmetic unit fixtures, not
claims about actual trained weights.

## References, integration and gates

1. Original Q16 reference stays `validation/reference.py` unchanged.
2. Reconstructed exact mathematical reference uses a common denominator LCM of
   the six stored scales, exact integer numerators and Q16 weights. Denominator
   multiplies by 65536 per linear layer. ReLU is exact. This is not original FP32.
3. Independent experimental Python follows the new rounding/type/domain rules.
   Host C and eBPF will share one bounded, integer-only arithmetic header.

Planned files: new `quantization/` calibration/reference/header/tests; narrow
compile-time inference hooks in `tc/tc_ids.bpf.c`; separate experimental model
layout/object/controller binary; mode selection in the existing runner/build.
Static mode retains original includes and arithmetic. Networking, flow values,
feature definitions, per-CPU workspace layout, guard and tail-chain ownership
helpers do not change. Metadata is embedded in the selected experimental model
slot and frozen with parameters. Existing two-slot selection is retained; no
hot swapping or cross-mode map sharing is introduced. Diagnostic counters track
invalid metadata/domain/arithmetic, and failures use the existing IDLE retry
and workspace release path. The original baseline remains independently runnable.

Gate 1 is satisfied by this explicit specification. Gate 2 requires reproducible
calibration, held-out numerical metrics, range proofs and Python boundary tests.
Gate 3 requires every experimental host-C tensor to match Python. Gate 4 requires
actual private kernel-stage parity plus Q16 regression before live experimental
TC tests (Gate 5). Only then may measured runtime comparisons be reported.
