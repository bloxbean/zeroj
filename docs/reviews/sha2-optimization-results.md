# SHA-2 optimization results — PR #112

Date: 2026-10-29. Baseline: `3f1570f33ef2f45d26abeaf6085de5a2dc7a1c5e`.
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

| Circuit | Message bytes | Baseline rows | Optimized rows |
|---|---:|---:|---:|
| SHA-256 | 32 | 42,694 | 25,758 |
| SHA-256 | 128 | 130,219 | 79,027 |
| SHA-512 | 32 | 106,332 | 64,980 |
| SHA-512 | 128 | 215,913 | 132,569 |

## Benchmark method

The optional [comparison harness](../../assurance/sha2-optimization/README.md)
compiles the same source against baseline and candidate checkouts. Each profile
gets a fresh sequential JVM, fixed eight visible processors, new development keys,
one warmup proof and three measured proofs. Both `-Xmx6g` and `-Xmx8g` are tested
for SHA-256/SHA-512 at 32, 128 and 1,024 message bytes. Compile, witness, setup,
prove and strict verification costs are separate. Exact rows/wires/terms, domain,
key bytes, sampled heap, GC and OS peak RSS are recorded with source/runtime hashes.

`-Xmx` limits Java heap, not total-process RSS; native allocations, mmap pages and
JVM overhead are additional. Timings remain machine-specific diagnostics. A single
warmup does not establish complete JIT stabilization; compile/setup are one-shot
measurements. Independent verification is a separate required step.

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

The final `./gradlew build --continue --max-workers=2` passed: 5,355 executed tests,
30 skipped, zero failures/errors across the default suites (including cached unchanged
suites). Controlled benchmark and fresh Cardano results follow after measurement.
