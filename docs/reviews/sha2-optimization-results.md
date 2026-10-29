# SHA-2 optimization results — PR #112

Date: 2026-10-29. Baseline: `3f1570f33ef2f45d26abeaf6085de5a2dc7a1c5e`.
Measured implementation: `e8947a6dd751fe490c5d2064cd9e83d848ce1b5c`.
Design and migration rules: [ADR-0063](../adr/0063-sha256-gadget-and-sha2-assurance.md).
This report tracks the optimization extension; the earlier
[implementation report](sha2-issue-111-validation.md) remains historical evidence.

## Implementation and relation preservation

Three changes preserve the full FIPS SHA-256/SHA-512 relation:

1. The DSL has an explicit Boolean assertion, lowering to `b*(b-1)=0` in one R1CS
   row instead of a product row plus a zero assertion. Native PlonK/Halo2 lower the
   same equation; boxed/flat/chunked witness evaluation still rejects non-bits.
   This is a typed graph operation, not a heuristic constraint-removal pass.
2. Majority reuses `ab=a*b` in `ab+c*(a+b-2*ab)`, eliminating a repeated product.
3. Round temporaries T1/T2 stay exact constrained field expressions until the next
   a/e words need bits. Their six/seven-word sums are below 2^35/2^67. The full
   sums, including all three carry bits, are decomposed before retaining low bits.

Round counts, constants, padding, byte ranges, full digest bits, proof equation,
blinding and security parameters are unchanged. No unconstrained host hashing or
new hint is introduced. New circuit-specific keys are mandatory. The Boolean
representation affects non-SHA circuits too: downstream exhaustive `Gate` visitors
need the new subtype, and all affected backends need regenerated circuit artifacts.

## Structural comparison

All rows use private fixed-length byte messages and complete public digests packed
into two/four big-endian 128-bit limbs. These figures are compiled relation sizes,
not on-chain execution counts.

| Circuit | Bytes | Rows, before → after | Reduction | FFT domain, before → after | Key store MiB, before → after |
|---|---:|---:|---:|---:|---:|
| SHA-256 | 32 | 42,694 → 25,758 | 39.67% | 65,536 → 32,768 | 17.14 → 10.10 |
| SHA-256 | 128 | 130,219 → 79,027 | 39.31% | 131,072 → 131,072 | 45.92 → 33.74 |
| SHA-256 | 1024 | 749,691 → 456,915 | 39.05% | 1,048,576 → 524,288 | 291.16 → 173.60 |
| SHA-512 | 32 | 106,332 → 64,980 | 38.89% | 131,072 → 65,536 | 39.62 → 23.67 |
| SHA-512 | 128 | 215,913 → 132,569 | 38.60% | 262,144 → 262,144 | 80.02 → 60.02 |
| SHA-512 | 1024 | 989,329 → 610,249 | 38.32% | 1,048,576 → 1,048,576 | 352.45 → 261.75 |

Rows, wires, sparse terms and canonical relation hashes agree across both heap caps.
No profile entered compiler pressure mode. Every process gets new development keys.
The 32-byte profiles and 1 KiB SHA-256 cross an FFT-domain boundary; the others do not.
SHA-512/32 is close to the 65,536-row boundary: added application checks can remove
that domain saving. Complete wire/term/fingerprint records are in the
[raw comparison](../../assurance/sha2-optimization/evidence/comparison/summary.json).

## Benchmark method

The optional [comparison harness](../../assurance/sha2-optimization/README.md)
compiles the same source against baseline and candidate checkouts. Each profile
gets a fresh sequential JVM, fixed eight visible processors, new development keys,
one warmup proof and three measured proofs. Both `-Xmx6g` and `-Xmx8g` are tested
for SHA-256/SHA-512 at 32, 128 and 1,024 message bytes. Compile, witness, setup,
prove and strict verification costs are separate. Exact rows/wires/terms, domain,
key bytes, sampled heap, GC and OS peak RSS are recorded with source/runtime hashes.
The host is an Apple M4 Max with 128 GiB RAM, macOS 26.0.1 and Java 25.0.2.
Actual JVM maximum heap and visible processor count must match the requested
controls or the profile fails. Baseline/candidate order alternates per profile.
No other build, oracle or benchmark was launched by this task during timed cases,
but existing background Java services remained active and host load varied
substantially. This is a shared-host diagnostic comparison, not an isolated
performance certification or a promise that every workload is faster.

`-Xmx` limits Java heap, not total-process RSS; native allocations, mmap pages and
JVM overhead are additional. Timings remain machine-specific diagnostics. A single
warmup does not establish complete JIT stabilization; compile/setup are one-shot
measurements. Independent verification is a separate required step.

## Proof generation under both heap caps

All **24 fresh JVMs passed**: both revisions, both hashes and all three message sizes
at each cap. All 96 randomized proofs passed strict Java verification; each changed
digest limb and canonical negated-A fixture was rejected. Effective heap limits
were exactly 6,442,450,944 and 8,589,934,592 bytes, with eight visible processors.

| Circuit / bytes | 6 GiB proof seconds, before → after | Change | 8 GiB proof seconds, before → after | Change |
|---|---:|---:|---:|---:|
| sha256-32 | 1.497 → 1.151 | 23.1% less time | 1.441 → 1.107 | 23.1% less time |
| sha256-128 | 3.805 → 3.375 | 11.3% less time | 3.969 → 2.910 | 26.7% less time |
| sha256-1024 | 11.316 → 8.408 | 25.7% less time | 11.509 → 10.686 | 7.2% less time |
| sha512-32 | 3.273 → 1.554 | 52.5% less time | 3.429 → 1.913 | 44.2% less time |
| sha512-128 | 5.985 → 3.945 | 34.1% less time | 5.316 → 5.628 | 5.9% more time |
| sha512-1024 | 14.996 → 12.530 | 16.4% less time | 12.200 → 11.320 | 7.2% less time |

The primary run improves 11 of 12 paired medians. **SHA-512/128 at 8 GiB is
5.86% slower** in this pass; that result is retained and investigated below.
A separate seven-measured-proof repeat of SHA-512/128 at 8 GiB passed, with
medians **5.294 → 4.779 s** (9.73% faster). The initial 5.86% slowdown remains
in the primary table; the repeat does not erase it or establish a universal
speedup. See the [timing repeat](../../assurance/sha2-optimization/evidence/timing-repeat/summary.json).

A larger heap is not consistently faster. These are three-sample post-warmup
medians, not latency guarantees or statistically established population speedups.

## Other off-chain stages

Compilation includes graph construction and CSR compilation; fingerprinting has
a separate raw timer. Compile/setup are single measurements. Witness/verification
are post-warmup medians. The compatibility prover API lazily materializes row views
during proving, included in proof timing. Setup is insecure development setup,
not a production MPC ceremony benchmark.

| Heap / circuit / bytes | Compile ms, before → after | Witness ms, before → after | Dev setup s, before → after | Verify ms, before → after |
|---|---:|---:|---:|---:|
| 6g/sha256-32 | 136.4 → 120.4 | 8.9 → 3.5 | 2.5 → 1.8 | 280.4 → 277.5 |
| 6g/sha256-128 | 462.0 → 240.1 | 14.4 → 10.6 | 6.9 → 4.2 | 320.2 → 319.4 |
| 6g/sha256-1024 | 1500.5 → 1113.4 | 88.4 → 52.5 | 33.1 → 25.0 | 285.2 → 302.6 |
| 6g/sha512-32 | 234.7 → 208.9 | 11.3 → 7.2 | 5.5 → 3.2 | 255.1 → 225.1 |
| 6g/sha512-128 | 525.3 → 367.3 | 25.7 → 14.7 | 10.1 → 6.4 | 241.1 → 212.2 |
| 6g/sha512-1024 | 1335.6 → 1206.2 | 107.7 → 64.3 | 34.3 → 31.7 | 279.3 → 222.8 |
| 8g/sha256-32 | 181.7 → 118.9 | 4.9 → 4.1 | 3.4 → 1.7 | 280.7 → 260.2 |
| 8g/sha256-128 | 282.3 → 254.3 | 17.2 → 9.6 | 5.5 → 3.9 | 327.1 → 290.4 |
| 8g/sha256-1024 | 1636.2 → 1012.7 | 70.2 → 68.0 | 35.1 → 18.7 | 323.6 → 304.4 |
| 8g/sha512-32 | 316.1 → 301.3 | 13.8 → 8.1 | 6.1 → 4.2 | 237.2 → 264.0 |
| 8g/sha512-128 | 453.0 → 367.4 | 18.2 → 15.7 | 8.7 → 6.9 | 217.2 → 263.4 |
| 8g/sha512-1024 | 1345.7 → 1505.8 | 117.8 → 81.1 | 37.9 → 32.2 | 227.2 → 213.9 |

Verification retains the same two/four-limb statement and proof equation. Java
verification timing varies with these small samples, runtime warmup, randomized
points and shared-host conditions; it does not establish a changed verifier cost.

## Observed memory

Whole-process peaks include compilation, setup, all proofs and negative checks.
Heap is sampled every 20 ms and can miss short peaks. RSS includes non-heap memory.
These measurements are not minimum live-memory requirements.

| Heap / circuit / bytes | Sampled heap GiB, before → after | Peak RSS GiB, before → after |
|---|---:|---:|
| 6g/sha256-32 | 1.29 → 1.20 | 1.50 → 1.46 |
| 6g/sha256-128 | 1.57 → 1.46 | 1.73 → 1.70 |
| 6g/sha256-1024 | 4.21 → 3.14 | 4.57 → 3.56 |
| 6g/sha512-32 | 1.48 → 1.29 | 1.66 → 1.53 |
| 6g/sha512-128 | 2.08 → 1.62 | 2.45 → 1.89 |
| 6g/sha512-1024 | 2.16 → 4.07 | 2.83 → 4.32 |
| 8g/sha256-32 | 1.32 → 1.20 | 1.56 → 1.44 |
| 8g/sha256-128 | 1.69 → 1.47 | 1.93 → 1.66 |
| 8g/sha256-1024 | 4.52 → 3.53 | 4.75 → 4.02 |
| 8g/sha512-32 | 1.58 → 1.31 | 1.89 → 1.51 |
| 8g/sha512-128 | 1.99 → 1.80 | 2.51 → 2.06 |
| 8g/sha512-1024 | 5.31 → 4.16 | 5.93 → 4.47 |

**The 6 GiB SHA-512/1,024-byte peak is a measured regression**, despite faster
proving and smaller relation/key storage. Baseline/candidate recorded 137/67
collections and 550/543 ms GC time. Different allocation/GC timing is plausible,
but aggregate counters do not establish a cause or measure post-collection live
state. The corresponding 8 GiB pair has lower optimized heap and RSS.

A reversed-order 6 GiB repeat with GC logging also passed: proof medians
**12.370 → 11.021 s**, sampled heap **3.657 → 3.961 GiB**, peak RSS
**4.361 → 4.545 GiB**. This retains a smaller memory regression: 8.3% heap and
4.2% RSS. Both original and repeat results remain evidence; neither is discarded.
See the [repeat](../../assurance/sha2-optimization/evidence/memory-repeat/summary.json)
and [GC review](sha2-optimization-memory-review.md). A universal memory reduction
is **not** established. Logging changes the measurement protocol, so the repeat
is separate from the primary timing table.

All tested shapes completed within the 6 GiB heap cap. This does not establish a
minimum heap, arbitrary document/application sizes, concurrent prover capacity,
or a total-process 6 GiB limit.

## Native-provider comparison

All **16 blst-backed proving runs passed** at 6/8 GiB for both hashes at 32/128 bytes.
Setup and strict verification still use Java; only the proving backend changes.
Seven of eight paired proof medians improve. SHA-256/32 at 6 GiB is 3.20% slower
(425.30 → 438.92 ms), so native timing is not uniformly improved either. All samples
and the complete comparison are retained in the
[native summary](../../assurance/sha2-optimization/evidence/blst-comparison/summary.json).

| Circuit / bytes | 6 GiB native proof seconds, before → after | 8 GiB native proof seconds, before → after |
|---|---:|---:|
| sha256-32 | 0.425 → 0.439 | 0.426 → 0.337 |
| sha256-128 | 0.741 → 0.616 | 0.814 → 0.663 |
| sha512-32 | 0.649 → 0.462 | 0.658 → 0.643 |
| sha512-128 | 1.814 → 1.495 | 1.843 → 1.776 |

## Fresh Cardano regression

Four new local Yaci DevKit runs used optimized 32-byte SHA-256/SHA-512 proofs,
one for each hash and heap cap. Each JVM used explicit `-Xmx6g`/`-Xmx8g`, confirmed
by JVM settings output. All four spends confirmed, eight VM negative cases per
run failed, and signed invalid-proof and wrong-digest transactions were rejected.
Java, backend and Haskell execution budgets agreed exactly. The current local
fee/limit/cost-model parameters were compared with the retained baseline and matched.

| Metric | SHA-256, both heaps | SHA-512, both heaps |
|---|---:|---:|
| Public 128-bit limbs | 2 | 4 |
| CPU steps | 2,191,936,964 | 2,471,295,658 |
| Memory units | 167,718 | 225,480 |
| Applied FLAT script bytes | 1,727 | 1,827 |
| Script CBOR bytes | 1,733 | 1,833 |
| Signed spending transaction bytes | 2,399 | 2,499 |
| Execution fee, ADA | 0.167716 | 0.191191 |
| Actual spending fee, ADA | 0.433097 | 0.460972 |

These costs are **unchanged** from the earlier full-digest preimage baseline.
Groth16 verification depends on the public statement and proof, not the number
of private SHA constraints. New keys are used; the verifier equation and input
arity are unchanged. The script is carried in the transaction. Fees exclude the
separate locking transaction, locked ADA and collateral requirements.

The standalone research harness uses JuLC `0.1.0-pre20-c3a31c2-SNAPSHOT` and CCL
`0.8.0-pre7`, as in the original fee experiment. Its verifier library, validator
and codec source files are byte-identical to this PR; source and runtime JAR
hashes are retained in [Cardano provenance](../../assurance/sha2-optimization/evidence/cardano/provenance.json).
This is separate from the repository default JuLC pre18/CCL pre5 toolchain.
The external research submission harness is **not bundled** in this PR; retained
signed transactions, scripts, public vectors, rejection records and protocol
parameters are included. See [reproduction scope](../../assurance/sha2-optimization/evidence/README.md).

This is local-devnet evidence, not a mainnet submission, production ceremony,
or the tutorial’s 48-byte approval application. The generic preimage validator
does not add issuer authorization, application state binding or replay prevention.

## Independent proof verification

Pinned snarkjs 0.7.6 independently checked **all 184 randomized proofs**, including
warmups, native proofs and both targeted repeats, and rejected **180 altered
proof/statement fixtures**: **364 checks passed**. The oracle also recomputes every
full digest independently with Python hashlib and checks exact artifact hashes.
The setup-free public vectors, verification keys, raw results and all oracle
verdicts are retained in [the evidence directory](../../assurance/sha2-optimization/evidence/README.md).
No production proving key or private witness is included.

## Validation and review

The retained [independent Circom/snarkjs relation run](../../assurance/sha2-circom/evidence/2026-10-29-optimized.json)
passed all **75 positive compiled-witness checks, 60 malicious-witness rejection checks
and eight invalid-input generator checks** across 25 messages, including 21 official
NIST cases. Both ZeroJ byte and bit APIs were checked against full published digests.

Focused SHA tests passed, including original NIST/JCA vectors, padding boundaries,
high-carry patterns and direct malicious-witness mutations. The new majority tests
cover all Boolean triples on all supported fields. Selected a/e decompositions
reject both low-bit changes and every carry-bit change, including non-Boolean carries.

The DSL suite passed 123 cases with one existing benchmark skip. The first full
regression run identified ten obsolete exact cost pins in nine non-SHA test classes.
Those pins were remeasured while preserving all acceptance/rejection assertions;
the focused 119-test rerun passed. The windowed-base comparison still saves exactly
1,007 rows over bitwise multiplication: both implementations lose 252 Boolean rows.

The broader run also exposed cost/identity pins in confidential-note, JMT and MPF
integration tests. Their exact migration and relation-identity compatibility rules
are recorded in the [pin migration note](sha2-optimization-pin-migration.md).

Post-implementation AI-assisted reviews:

- [Independent compiler and gadget review](sha2-optimization-independent-review.md).
  Its additional standalone `-Xmx6g` run checked 18 full SHA/JCA/R1CS cases across
  BLS12-381, BN254 and Pallas and rejected 78 altered declared-input witnesses.
- [Independent gadget review](sha2-optimization-gadget-review.md), authored by the
  DSL implementer reviewing the separate SHA implementation.

These reviews are not an external cryptographic audit. Development setup is not a
production ceremony. Existing variable-time secret-handling limitations remain;
all benchmark witnesses are public fixtures. Groth16 is not post-quantum.

The final `./gradlew build --continue --max-workers=2` passed. Default test reports
contain **5,355 passed tests, 30 skipped, zero failures/errors**, including unchanged
cached suites. The optimized runnable approval tutorial passed all its positive and
negative scenarios. `npm run check` reports zero errors/warnings/hints and validates
138 Java blocks; `npm run build` validates 64 HTML pages, 62 Markdown twins and five
AI artifacts. No new browser layout inspection was completed in this iteration
because the browser-control connection was unavailable; the earlier illustration
checks remain historical validation, not a recheck of the wider metrics table.

## Recommendation and remaining limits

Accept the bounded optimization for continued experimental use: it preserves the
reviewed full SHA relations, cuts every measured shape by 38–40%, reduces sparse
key storage, and passes actual proving at both requested heap caps. Regenerate all
affected circuit artifacts and keys; update downstream exhaustive `Gate` visitors.

Do **not** promise uniform proving latency or memory improvement. The primary
pure-Java and native matrices each include one slower pair, and the 6 GiB large
SHA-512 memory increase persists in the diagnostic repeat. Production sizing needs
repeated measurements of the actual application and concurrent workload on a
controlled host. A separate future investigation can profile phase-specific live
heap and the list-compatible prover’s transient allocations; switching prover
architecture is outside this bounded circuit change.

Neither these tests nor agent reviews constitute an external circuit audit,
constant-time evidence, production approval, or post-quantum security. SHA-2’s
standard digest is unchanged; Groth16 still relies on elliptic-curve pairings and
trusted setup.
