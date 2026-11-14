# Deterministic numerical validation

Run the complete unprivileged suite from the repository root:

```sh
python3 validation/run.py --smoke-log /tmp/nn-ebpf-baseline.dhp5S5
```

`--smoke-log` is optional. With it, the saved active-model bytes are checked
against all 5,216 header bytes and relevant existing smoke artifacts are copied
into the new results directory. This reads historical evidence; it never loads
or queries live BPF objects. A missing requested log file fails the run.

Python 3.9+ with timezone data, Linux x86-64 headers, and clang-12 with its UBSan
runtime are required. NumPy, PyTorch, sudo, bpftool, mounted bpffs, and network
access are not needed. The current native packet shim supports little-endian
x86-64 only; the runner rejects other ABIs rather than assuming their behavior.

Choose another compiler or a **new** output directory if needed:

```sh
python3 validation/run.py --compiler clang-12 --output /tmp/nn-numerical-new-run
```

Default results go to `verification-logs/numerical-TIMESTAMP/`. Every run builds
fresh host artifacts inside that directory's `.output/`, runs unittest, and saves
`REPORT.md`, `results.json`, full test/build/sanitizer logs, exact build commands,
source/data hashes, fixture tensors, dataset stage hashes, and `SHA256SUMS`.
Exit zero means all executed comparisons and characterization checks passed;
skips and their reasons remain explicit. Do not run `test_validation.py` directly:
the runner supplies its compiled C context and evidence collector.

## What is independent

- `reference.py` parses the literal model header and NPY matrix using only the
  Python standard library. It does not import the production training code. Its
  arbitrary-precision integers explicitly model unsigned 64-bit arithmetic,
  int32 narrowing, sign restoration, arithmetic right shifts, ReLU, and argmax.
- `native.c` includes the **unchanged** `src/xdp.bpf.c`, which brings in the
  original normalization, linear, ReLU, parser and feature-update functions.
  Synthetic packet bytes therefore exercise production C, not just a second
  copy of its equations. The separate feature reference and hand-calculated
  expected vectors check ordinary flow updates.
- Test-only headers substitute host maps, a frozen controllable nanosecond
  clock, trace capture, and function dispatch for kernel helpers. A pointer-width
  `xdp_md` avoids truncating host addresses. Maps are single-threaded and capped
  at 64 entries (a smaller adjustable capacity exercises insertion failure).
  Nothing here is suitable for loading into the kernel.
- Intermediate tensors are captured between all six stages. On a golden
  SYN/data/FIN flow, all six original XDP stage functions and the original final
  comparison execute. Tests also compare all six tensors on every one of the
  18,840 stored feature vectors and 96 deterministic seeded layer vectors.

No baseline file, model array, build rule, training script, or network setting is
modified. Source/data SHA256 values are checked before/after each run. In-process
models and maps are private test memory, initialized from the existing header.

## Coverage and interpretation

The suite covers both signs, zero, fractional truncation, sum-before-shift,
negative arithmetic shifts, widening before multiplication, ReLU, integer
boundaries, narrowing, uint64 wrap, and synthetic signed-overflow cases. Some
boundary tests deliberately use arbitrary weights/scales to expose helper
limits; those do not describe inputs observed in traffic or the stored dataset.
One additional overflow case uses the unchanged actual model's IAT constants.

Native host results are compared only on cases without signed C overflow.
Undefined operations are exercised in separate UBSan subprocesses, which are
**expected to fail** with a specific diagnostic in the original source. Their
tests pass only when that defect is reproduced. These are characterization
tests, not a statement that undefined behavior is acceptable or fixed.

For out-of-range casts, the reference models the two's-complement narrowing
observed with the recorded compiler/ABI. Negative right shifts are checked
against the native compiler. Signed C overflow remains undefined even though
the [BPF ISA](https://docs.kernel.org/bpf/standardization/instruction-set.html#arithmetic-instructions)
defines wrapping register operations. The reference rejects zero-scale division
because the C expression has no guard; UBSan confirms the native error. BPF DIV
itself specifies a zero result for a zero divisor. This framework does not
claim that the host C failure proves a kernel fault or an incorrect BPF result.
The checked-in scales are all positive and nonzero.

Packet tests check byte-count units, nanosecond IATs, destination-port byte order,
TCP header options, first-packet IAT zero, FIN **or** RST after feature updating,
source-IP filtering, directional tuples, ignored reverse-source traffic, map
insertion failure, repeated FIN, and tuple reuse. Fixtures have synthetic
checksums and are never injected: passing them says nothing about real NIC
acceptance. Host code is compiled for the supported x86-64 ABI, where the
packet source's unaligned header accesses are usable; this is not a portability
proof for other host architectures.

## Findings reproduced by the tests

1. **Equal logits:** the code selects 1 on a tie, whereas Equation 5 selects 0
   in the [DSN paper](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf).
   Feeding the stored means to the bias-free network produces zero at every
   stage and `[0, 0]` logits, so this is a concrete model example. Separate tests
   execute the original output-stage comparison on positive/negative/zero ties.
2. **Normalization width limits:** unsigned multiplication wraps when
   `abs(x-mean) * 65536` reaches 2^64. With the actual stored IAT constants,
   `x = mean_IAT + 2^48` normalizes to 0 instead of the unbounded formula's
   nonzero int32-representable value. This is roughly a 3.26-day difference in
   nanoseconds, not an overflow observed in the stored rows. Positive normalized
   values and shifted linear outputs can also narrow into negative int32 values.
3. **Signed C undefined behavior:** UBSan demonstrates int64 accumulator
   overflow, negation of `INT32_MIN`, and flow-counter overflow on explicitly
   constructed boundary inputs. The mean/scale/sample domain does not guarantee
   safety for arbitrary inputs. Native zero-scale division is also diagnosed.
4. **IPv4 options:** TCP is read at a fixed twenty-byte IP offset. A valid IHL=6
   fixture records destination port 257 instead of 5001, TCP header sum 0 instead
   of 20, and misses its actual FIN. This is a parser/feature defect in that case.
5. **Malformed IP length:** `tot_len=10, IHL=5` is accepted by the current byte
   parser. Unsigned conversion and later signed narrowing give maximum length
   -10 while the minimum remains its initial sentinel.
6. **Flow lifecycle:** repeated FIN causes repeated inference; a new SYN using
   the same tuple retains old counters and IAT. No eviction or cleanup behavior
   is added by these tests.

The feature length used by the code is **IP total length minus IP header
length**, including the TCP header, rather than application payload length.
IAT values are nanoseconds. These definitions are characterized here; agreement
with CICFlowMeter conventions or dataset collection provenance is not proven.

## Floating-point comparison

No original `.th`, `.pt`, `.pth`, `.pkl` or `.onnx` checkpoint is present in
`src/` or `dataset/`. The original-float comparison therefore reports **SKIP**.
The quantized header cannot recover the original trained floating weights or
unrounded normalization constants. Tests do not retrain or unpickle anything.

For additional context, fixed fixtures include floating calculations using
`header_weight / 65536` and the rounded header mean/scale. Results are labeled
`dequantized_header_float_diagnostic`: they isolate arithmetic truncation for a
surrogate model and are **not** validation against the original FP32 checkpoint.
Recover that checkpoint and normalization statistics before claiming FP32 parity.

## What still requires privileged execution

These tests do not verify the compiled eBPF bytecode, kernel verifier/JIT,
kernel helper semantics, actual tail-call transitions, real map contents at
each stage, per-CPU concurrency, model-update races or live packet timing.
The supplied successful smoke test establishes execution, not that parity.

Next, obtain approval for a separate deterministic BPF test in an isolated VM.
Compare kernel feature values and per-layer tensors with saved host fixtures,
using `BPF_PROG_TEST_RUN` where supported. Time-dependent feature checks need
observed timestamps or a separate validation-only clock-controlled BPF harness;
exact live IATs cannot be inferred from packet bytes alone. Do not patch the
baseline detector merely to obtain those observations without approval.
After correctness, a held-out labeled evaluation can address accuracy; this
suite intentionally does not calculate classification accuracy or F1 scores.
