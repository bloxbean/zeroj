# SHA-2 implementation validation — issue #111

This is the **pre-optimization** validation record for commit `9d56105`. The later
PR #112 optimization changes circuit shapes; its new measurements and acceptance
checks are recorded separately in [the optimization report](sha2-optimization-results.md).

Date: 2026-10-29. Baseline: `d0b1f32` on `main`. Design:
[ADR-0063](../adr/0063-sha256-gadget-and-sha2-assurance.md).
This record covers the new `Sha256` / `ZkSha256` APIs and the existing SHA-512
review and length-arithmetic hardening. It does not replace the separate Cardano
research benchmarks or establish production approval.

## Default build and regression tests

```sh
./gradlew build --max-workers=2
```

Passed in 20m 50s: 159 Gradle tasks, 145 executed and 14 up-to-date. The 348 JUnit
XML reports contain 5,377 test cases, zero failures, zero errors and 30 skipped
cases (5,347 executed). Opt-in heavy/oracle suites are separate from this count.
The build also passed `verifyDefaultModuleSurface` and `verifyNoBuiltinProfileDefine`.

The focused SHA-2/HMAC run passed all 39 tests. The subsequent full build also
includes the final SHA-256 Pallas and direct carry-wire checks. New coverage includes
21 selected original NIST CAVP vectors, JCA differential checks, empty messages,
high-bit bytes, padding transitions, multiblock inputs, byte/bit entry points,
symbolic context checks, and direct compiled-witness mutations. The test vectors
are checked against their official source ZIP by the optional oracle bootstrap.

For documentation, these commands all passed in `www/`:

```sh
npm ci
npm run check:release
npm run check
npm run build
```

The API check covered 137 Java blocks; the site check verified 62 HTML pages,
60 Markdown twins and five generated AI artifacts. The existing documentation
lockfile was used unchanged; this work does not update its dependencies.

## Fresh Groth16 proofs and performance

```sh
./gradlew :zeroj-integration-tests:heavyTest --tests '*Sha2Groth16Test' --max-workers=2
```

Passed both tests in a 30-second Gradle invocation. Four independently randomized
proofs per hash verified with the strict Java verifier. Changing each of the six
public limbs, or negating proof point A for either hash, was rejected. Setup was
fresh, explicitly opted-in single-party development setup; it is not a production
ceremony. See the [proof review](sha2-proof-review-issue-111.md) for detailed evidence.

Pinned snarkjs 0.7.6 independently accepted the two retained final proofs and rejected
all eight altered proof/statement fixtures. The small
[proof-vector directory](../../assurance/sha2-proof-vectors/README.md) retains those
artifacts, exact hashes and a runner for reproducing all ten checks without setup:

```sh
python3 assurance/sha2-proof-vectors/verify.py
```

This command uses the pinned optional snarkjs installation described in that directory.

Both messages are 32 ascending bytes; all digest bits are bound as two/four limbs.
Measurements use pure Java on an Apple M4 Max with 128 GiB RAM, Java 25.0.2,
16 visible processors and a 12 GiB test heap. Other workloads were active.

| Metric | SHA-256 | SHA-512 |
|---|---:|---:|
| Constraints | 42,694 | 106,332 |
| Wires | 141,470 | 352,560 |
| QAP domain | 65,536 | 131,072 |
| Compile/materialize | 198.20 ms | 184.15 ms |
| Development setup | 2,604.62 ms | 3,503.56 ms |
| Warm witness median | 4.49 ms | 11.25 ms |
| Warm proof median | 1,420.82 ms | 2,452.27 ms |
| Warm strict Java verification median | 324.41 ms | 340.42 ms |
| Temporary key-store bytes | 17,977,255 | 41,549,352 |

Warm medians use three samples after one separately recorded first proof. Compile,
setup and initial-witness measurements are single samples. These are shared-host
diagnostics, not performance guarantees, a controlled Java/Circom speed comparison,
or Cardano execution/fee measurements. The ordinary 32-public-byte SHA-256 unit
test has 42,724 constraints; that is a different public statement from the two-limb
proof circuit, not a changed hash.

## Independent Circom constraint cross-check

```sh
bash assurance/sha2-circom/bootstrap.sh
python3 assurance/sha2-circom/run.py all
```

The equivalent separately scheduled `export` and `check` phases passed. All
25 messages (21 official NIST cases plus four 32/128-byte profiles) agreed across
Circom and ZeroJ's byte/bit APIs: **75 accepted compiled witnesses**, **60 rejected
direct witness mutations**, and **eight rejected Circom generator inputs**.
These relation checks use snarkjs independently of ZeroJ's witness checker.
All start/end source and harness hashes matched. The
[optional runner and retained evidence](../../assurance/sha2-circom/README.md)
pin compiler/library versions and the official-vector source.

| Message shape | ZeroJ byte-API constraints | Circom O2 constraints |
|---|---:|---:|
| SHA-256, 32 bytes | 42,694 | 29,636 |
| SHA-256, 128 bytes | 130,219 | 90,633 |
| SHA-512, 32 bytes | 106,332 | 74,952 |
| SHA-512, 128 bytes | 215,913 | 152,453 |

Both sides bind the same full two/four-limb digest on BLS12-381. Circom O2 produces
fewer constraints; this implementation prioritizes the existing ZeroJ construction
and DSL conventions without introducing a compiler optimization. Different internal
circuit representations and proving backends prevent inferring a proof-time ratio
from constraint counts alone.

Circom can eliminate both an original byte signal and some decomposition bits.
The harness reconstructs them using the compiler's explicit affine substitution
map, with field arithmetic and cycle/missing-map/bounds checks. Every reconstructed
byte and bit is checked; mutations target named, retained witness wires. Hashes of
the symbol and substitution maps are recorded. Two mapping issues were corrected
in this optional harness during validation; neither required gadget changes or
removing a positive/negative check.

## Scope and review boundaries

The [SHA-512 review](sha512-issue-111.md) found an unchecked Java length-overflow
edge case, not a demonstrated false-proof acceptance. Its hardening preserves the
ordinary compression function, digest order and circuit relation. Existing SHA-512
and HMAC-SHA512 tests passed.

The [source/proof review](sha2-proof-review-issue-111.md) and separate implementation
reviews are AI-assisted checks, not a human or external cryptographic audit. SHA-256
remains experimental. No runtime dependency, default-build external tool, compiler
optimization, proof-system change or secret-handling guarantee is added.

The gadgets expose complete standard digests. The assurance circuits pack them into
two/four 128-bit public limbs for SHA-256/SHA-512 without digest reduction or truncation.
Fixed message length, application authorization, public-digest privacy, variable-time
witness/prover code and production setup requirements remain explicit limitations.
