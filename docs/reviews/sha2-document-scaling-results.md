# SHA-2 document-size measurements — PR #112

Date: 2026-10-29. This extends the [optimization results](sha2-optimization-results.md)
with the requested 2, 4, 8 and 16 KiB messages. A KiB is 1,024 bytes, so the exact
input lengths are 2,048, 4,096, 8,192 and 16,384 bytes. The complete matrix and
independent verification finished; raw outputs stay local and ignored.

## What is being measured

The circuit proves knowledge of a fixed-length private byte string whose complete
SHA-256 or SHA-512 digest equals two or four public 128-bit limbs. It hashes every
byte with the existing optimized gadget; no reduced rounds, truncated digest or
weakened bit/carry constraints are used. The benchmark's ascending-byte witness is
intentionally public test data. These byte counts are useful proxies for document
hashing cost, not measurements of PDF/JSON/XML parsing or of policies on their fields.

The production implementation is unchanged from the completed optimization. This
extension adds optional assurance telemetry and larger profiles only. Compilation,
witness generation, setup and proving use the same compatibility API as the original
comparison: `Groth16Keys.prove(backend, BigInteger[], List<R1CSConstraint>)`. The
builder remains available for repeated witness generation. Failures on this path
are method-specific observations, not a mathematical maximum for SHA or Groth16,
and not a demonstrated limit for every ZeroJ pipeline.

## Measurement protocol

Each of the 16 requested hash/length/heap combinations gets one fresh sequential JVM,
pure-Java proving, eight visible processors, one warmup proof and three measured
proofs. Each proof must pass strict Java verification; all digest-limb mutations and
a canonical negation of proof point A must be rejected. Randomized proofs must differ.
Fresh circuit-specific development keys are generated in each JVM and deleted after
use. The insecure development setup opt-in remains explicit. Its time is not a
production MPC ceremony benchmark, and it is separate from proof latency with keys
already available.

The host is an Apple M4 Max with 128 GiB RAM, macOS 26.0.1 and Java 25.0.2. Effective
maximum heaps must be exactly 6,442,450,944 or 8,589,934,592 bytes. No other benchmark,
build or independent verifier was launched by this task while the matrix ran;
existing user background services remained active. These are shared-host diagnostic
measurements, not isolated performance certification. Three post-warmup samples
support descriptive medians, not statistical latency guarantees. Sizes run in ascending
order, with 6 GiB before 8 GiB and SHA-256 before SHA-512. This fixed order is not
randomized; timing differences cannot be attributed solely to the heap cap.

`-Xmx` limits Java heap, not RSS. Whole-process RSS also includes JVM overhead, mmap
pages and native allocations. Heap sampling every 20 ms can miss short peaks. Failed
cases retain only the last surviving atomic checkpoint; that heap sample is not
necessarily their final peak. RSS is reported where the operating-system wrapper
was able to capture it. GC logging and phase checkpoints are enabled for this matrix,
so it is separate evidence from the original comparison.

Each case has a 900-second total process budget. A timeout is reported as a timeout,
not as heap exhaustion. Fail-fast OOM preserves the last phase checkpoint and raw
JVM output. All requested profiles are attempted even when an earlier one fails.
Only a completed pipeline receives a proof-time median; any partial proof samples
must be identified separately. Independent verification follows timed runs and
explicitly records incomplete pipelines as skipped rather than successful.

## Results

**13 of 16 complete pipelines passed.** Both hashes passed at 2, 4 and 8 KiB
under both heap caps. At 16 KiB, SHA-256 passed with 8 GiB; the other three
profiles exhausted Java heap during development setup. No case timed out.

Proof times below are medians of three post-warmup proofs, excluding setup,
compilation, witness generation and verification. OOM means the full pipeline
did not reach proving; it is not a measurement of proving alone with prebuilt keys.

| Hash | Message KiB | Constraints | Measured FFT domain | Key store MiB | Proof seconds, 6 GiB | Proof seconds, 8 GiB |
|---|---:|---:|---:|---:|---:|---:|
| SHA-256 | 2 | 888,787 | 1,048,576 | 340.31 | 10.902 | 11.676 |
| SHA-512 | 2 | 1,156,169 | 2,097,152 | 506.04 | 17.100 | 16.463 |
| SHA-256 | 4 | 1,752,531 | 2,097,152 | 673.73 | 17.435 | 17.248 |
| SHA-512 | 4 | 2,248,009 | 4,194,304 | 994.61 | 27.872 | 28.410 |
| SHA-256 | 8 | 3,480,019 | 4,194,304 | 1,340.57 | 27.941 | 39.064 |
| SHA-512 | 8 | 4,431,689 | 8,388,608 | 1,971.74 | 65.178 | 65.391 |
| SHA-256 | 16 | 6,934,995 | 8,388,608 | 2,674.24 | OOM (setup) | 67.781 |
| SHA-512 | 16 | 8,799,049 | — | — | OOM (setup) | OOM (setup) |

The key/domain columns come from completed setup; SHA-512/16 KiB has neither.
All eight compiled shapes have identical rows, wires, sparse terms and canonical
relation fingerprints across heap caps, including shapes that failed later.
No case entered compiler pressure mode. The fixed compiler policy does not
adapt the relation to available heap.

### Other off-chain stages

Compile and setup are single measurements. Witness/verify are medians of the
three measured samples. Failed cases show their completed first witness only,
marked with †; no failed-stage duration is presented as a completed setup.

| Hash / KiB | Heap GiB | Compile s | Witness ms | Dev setup s | Java verify ms |
|---|---:|---:|---:|---:|---:|
| SHA-256 / 2 | 6 | 1.974 | 123.5 | 36.989 | 256.7 |
| SHA-256 / 2 | 8 | 1.690 | 89.6 | 40.747 | 286.9 |
| SHA-512 / 2 | 6 | 2.100 | 151.4 | 49.496 | 232.8 |
| SHA-512 / 2 | 8 | 2.091 | 116.7 | 49.915 | 222.3 |
| SHA-256 / 4 | 6 | 2.658 | 202.1 | 82.405 | 276.4 |
| SHA-256 / 4 | 8 | 2.932 | 210.6 | 81.218 | 296.7 |
| SHA-512 / 4 | 6 | 3.533 | 229.7 | 95.666 | 231.3 |
| SHA-512 / 4 | 8 | 3.709 | 284.0 | 99.307 | 227.6 |
| SHA-256 / 8 | 6 | 5.354 | 349.6 | 158.156 | 275.3 |
| SHA-256 / 8 | 8 | 6.144 | 417.0 | 184.211 | 355.5 |
| SHA-512 / 8 | 6 | 6.598 | 606.8 | 202.555 | 275.1 |
| SHA-512 / 8 | 8 | 7.431 | 545.8 | 249.200 | 270.7 |
| SHA-256 / 16 | 6 | 12.136 | 1017.2 † | OOM | — |
| SHA-256 / 16 | 8 | 11.685 | 983.9 | 364.993 | 330.4 |
| SHA-512 / 16 | 6 | 14.929 | 1875.7 † | OOM | — |
| SHA-512 / 16 | 8 | 15.128 | 1436.6 † | OOM | — |

### Observed memory

Each cell is **sampled heap / whole-process peak RSS**, in GiB. These are observed
peaks, not minimum RAM requirements. Failed-run heap peaks are unavailable;
their last checkpoint is deliberately not substituted for a whole-run peak.

| Hash / KiB | 6 GiB cap: heap / RSS | 8 GiB cap: heap / RSS |
|---|---:|---:|
| SHA-256 / 2 | 4.57 / 5.30 | 5.21 / 5.42 |
| SHA-512 / 2 | 2.63 / 3.45 | 2.99 / 4.85 |
| SHA-256 / 4 | 3.79 / 4.77 | 3.92 / 5.01 |
| SHA-512 / 4 | 5.75 / 6.93 | 5.70 / 7.01 |
| SHA-256 / 8 | 5.87 / 7.62 | 7.10 / 9.09 |
| SHA-512 / 8 | 5.99 / 8.15 | 7.98 / 10.18 |
| SHA-256 / 16 | unavailable / 6.26 | 7.99 / 10.88 |
| SHA-512 / 16 | unavailable / 6.26 | unavailable / 8.29 |

A 6/8 GiB heap cap does not demonstrate operation on a machine with only 6/8 GiB
physical RAM. Resident mapped-key pages are part of RSS and may be reclaimable
under pressure; this experiment does not measure that smaller-host behavior.

### Failure evidence and the next memory experiment

All three failures occurred after successful compilation, relation fingerprinting
and first-witness generation. Each JVM reported `OutOfMemoryError: Java heap space`,
exited with code 3, and had its owned temporary key directory removed by the runner.
The exact requested heap and CPU controls were confirmed. No proof was generated
by those three processes; they are excluded from proof medians and oracle success counts.

| Failed 16 KiB profile | Process elapsed s | Last stage |
|---|---:|---|
| SHA-256 / 6g | 26.477 | Development setup |
| SHA-512 / 6g | 28.647 | Development setup |
| SHA-512 / 8g | 31.739 | Development setup |

These results identify a peak in the measured API/lifetime arrangement, not an
intrinsic SHA/Groth16 maximum or proof that every ZeroJ path fails at that size.
A concrete follow-up uses the existing `Groth16Pipeline`: compile in a helper
that lets the builder/graph become unreachable before setup; defer witness
construction; then use its fingerprint-bound constraint cache and packed prover.
The current benchmark retains the builder for repeated witness samples. Setup
still needs per-wire QAP arrays, so the alternate ordering is a candidate, not
a demonstrated solution. Its cache writer also has a 2 GB file limit that must
be checked. No public out-of-core compiler was found. This alternative was
**inspected, not benchmarked in this campaign**; it must preserve the exact
relation, full digest and independent proof checks.

### Independent validation

- All **52 randomized proofs** from completed profiles passed strict Java
  verification and independent pinned snarkjs 0.7.6 verification.
- snarkjs rejected **51 invalid fixtures**: each changed digest limb and one
  canonical negated-A proof per completed profile. **103 checks passed**.
- Python hashlib independently recomputed the complete digests. Fixture byte
  lengths/patterns, exact artifact hashes and all eight cross-heap relation
  identities were checked. All 16 processes honored their requested controls.
- The three setup failures are explicitly recorded as skipped by the oracle;
  they are not counted as verified pipelines. There were no partial proof runs.
- All **13 lightweight harness tests** passed, covering OOM/timeouts, controls,
  cleanup, success-only medians and failed-case oracle accounting. A separate
  32-byte control run passed four proofs and seven snarkjs checks.

No production gadget/compiler/prover code changed for these measurements.
The earlier NIST/JCA/Circom and malicious-witness results remain the separate
circuit-soundness evidence; scaling honest proofs does not replace those tests.

## Reproduce and keep raw outputs local

The production checkout was `3921b9f` (the optimized implementation from
`e8947a6` is unchanged). The optional harness adds stage telemetry and the larger
profiles. See the [runner documentation](../../assurance/sha2-optimization/README.md).

```sh
python3 -B assurance/sha2-optimization/scale.py run --checkout . \
  --output assurance/sha2-optimization/build/document-scaling
python3 -B assurance/sha2-optimization/run.py verify \
  assurance/sha2-optimization/build/document-scaling --allow-failed \
  --snarkjs assurance/sha2-circom/node_modules/snarkjs/build/cli.cjs
```

Use a new output directory. The matrix runner returns nonzero when any profile
fails, but still attempts all requested profiles; run the oracle afterward to
check successes and account for failures. Raw logs, progress, process records,
proofs and generated keys are not committed. The local outputs and measured
report tables remain separate from the small curated proof-vector set in Git.


## Interpretation and limits

A larger document increases private circuit work, proving-key storage and off-chain
resource use. With the same two/four public digest limbs, Groth16 proof structure and
verifier input arity stay fixed. The previous local Yaci measurements were roughly
0.43 ADA for SHA-256 and 0.46 ADA for SHA-512 spending transactions, as documented in
the [cost baseline](sha2-cardano-cost-baseline.md) and optimization report. Those are
reference estimates for this statement shape; this document-size run does not itself
submit new Cardano transactions or measure a complete application validator.

Each fixed length needs its own circuit-specific keys. Arbitrary secret lengths,
variable padding, parsing, issuer authorization, replay protection and state-transition
rules add constraints and require separate measurements. Hashing a supplied field
separately from a file does not establish that the field occurs in that file.

This is BLS12-381 Groth16 research, not a post-quantum proof construction. Successful
vectors and internal reviews do not establish production readiness or side-channel
safety. Existing circuit soundness, constant-time and ceremony/audit boundaries remain
as described by [ADR-0063](../adr/0063-sha256-gadget-and-sha2-assurance.md).
