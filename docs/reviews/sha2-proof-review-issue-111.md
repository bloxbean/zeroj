# SHA-2 implementation and proof review — issue #111

This is a bounded AI-assisted independent source review and executable regression record for
[issue #111](https://github.com/bloxbean/zeroj/issues/111) and
[ADR-0063](../adr/0063-sha256-gadget-and-sha2-assurance.md), performed by a separate
review agent from the gadget implementation agents. It is not a human or external
cryptographic audit, a production approval or a constant-time assessment. The
review agent authored the additional heavy proof regression described below.

## Reviewed scope

The reviewer did not implement `Sha256`, `ZkSha256`, or the SHA-512 changes. Review
covered the SHA-256 compression and padding code, symbolic ownership checks,
SHA-512 arithmetic and length hardening, and the new SHA-2 regression tests. The
normative algorithm reference is [FIPS 180-4, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
Separate Circom evidence is maintained in `assurance/sha2-circom` and the SHA-512
review in [sha512-issue-111.md](sha512-issue-111.md).

The source review found no missing SHA-256 input, carry, digest or intermediate
constraint, and no mismatch in the IV, round constants, schedule, round updates,
padding or digest order. This conclusion is limited to the reviewed source and
tests; it does not establish that every possible compiler or prover defect is absent.

## Constraint invariants checked

- The byte API decomposes and reconstructs each byte into eight Boolean bits. The
  bit API asserts Boolean inputs and permits only byte-aligned message lengths.
- Internal words are little-endian bit arrays. SHA input and output ordering is
  big-endian; conversion reverses bits within words/bytes at the API boundaries.
- `Ch = g + e(f-g)` and `Maj = ab + c(a XOR b)` produce Boolean values when their
  inputs are Boolean. Rotations and logical shifts reindex those bits or insert zero.
- Every modular addition reconstructs complete input words and decomposes the
  entire sum, including carry bits. For two, four and five SHA-256 addends the
  decomposition has 33, 34 and 35 bits respectively; SHA-512 has the corresponding
  65, 66 and 67-bit bounds. All supported scalar fields are larger than these sums.
- Round constants, initial words, padding and length suffixes are circuit constants.
  There is no witness-controlled branch, host-hash hint or digest truncation.
- Checked message/padded-array lengths reject integer overflow before allocating
  arrays or emitting constraints. Java array limits are stricter than FIPS maxima.
  SHA-512 hardening changes oversized-input failure behavior, not the ordinary relation.
- The symbolic SHA-256 adapter uses the existing context ownership checks. Its
  nonempty-message restriction comes from `ZkBytes`; the underlying byte/bit APIs
  support empty messages. There is no unchecked public symbolic entry point.

The new unit tests include selected published NIST vectors, JCA differential
checks, padding transitions, multiblock messages, both input APIs and symbolic
adapters. SHA-256 also exercises BLS12-381, BN254 and Pallas. The direct R1CS
negatives mutate digest bytes, input bytes/bits and actual addition carry/low-bit
wires; these checks bypass the honest witness generator. They complement source
reasoning and do not by themselves constitute a proof of circuit soundness.

The optional Circom lane was also reviewed: both wrappers constrain byte ranges
and bind complete digests, the exporter calls the actual ZeroJ byte/bit gadgets,
and snarkjs checks the resulting relations independently. Circom O2 may eliminate
both a byte and some decomposition bits. A follow-up narrow review checked the
runner's use of the compiler's exact affine substitution map: signal labels stay
distinct from witness indices; label zero means one; nested expressions are
evaluated modulo Fr with caching and cycle/missing/bounds checks. Every reconstructed
byte and all eight Boolean bits must match the original message. A `.sym` index of
`-1` is never used as a witness index. The SHA-512/55-byte artifact exhibits this
nested case. Negative checks still mutate actual retained byte/bit wires, and report
the selected signal, wire and value kind; they do not mutate arbitrary dependencies
and call them input bits. Symbol/substitution maps are hashed. Tooling stays in an
explicit Gradle init-script source set, outside default runtime artifacts.

## Opt-in proof regression

`zeroj-integration-tests/src/test/java/org/zeroj/it/sha2/Sha2Groth16Test.java` builds
fresh 32-byte SHA-256 and SHA-512 circuits using the upstream gadgets. Each full
digest is bound as consecutive big-endian 128-bit public limbs: two for SHA-256,
four for SHA-512. This avoids reducing an entire digest modulo the scalar field.
The messages are known ascending-byte fixtures, deliberately not private test data.

Run from the repository root with Java 25:

```sh
./gradlew :zeroj-integration-tests:heavyTest --tests '*Sha2Groth16Test' --max-workers=2
```

The existing `heavyTest` task enables the explicit development-setup guard and
defaults to a 12 GiB test heap. No new runtime dependency, native prover, default
test task or production setup path is added. Fresh sparse development keys live in
JUnit temporary directories; the setup uses the existing built-in Java setup API.
The tiny `PowersOfTauBLS381.generate(4)` invocation supplies a random tau scalar,
not a ceremony transcript supporting the larger SHA relation.

For each relation the regression checks:

1. Four fresh pure-Java Groth16 proofs verify through the strict public verifier.
2. The four serialized proofs are distinct (a regression against missing
   randomization, not a statistical or cryptographic RNG assessment).
3. Changing each public digest limb separately causes verification failure.
4. Negating proof point A produces a canonical on-curve subgroup point and must
   fail the pairing equation. This is a proof-validity check rather than only a
   malformed-encoding check.

Each invocation writes a unique directory under
`zeroj-integration-tests/build/sha2-proof-assurance/`. It retains JSON timings,
constraint/wire counts, QAP domain, key-store size, relation/key/proof hashes,
message/digest fixtures, four valid proofs, verification key, public inputs and
invalid proof/public-input fixtures. Toxic setup material is not copied into these
artifacts. An incomplete or failed test does not write a successful `result.json`.

Compilation (including constraint materialization), witness generation, setup,
proof generation and verification are timed separately. The first proof is
identified separately from the following three samples; the same key remains open.
These are shared-host diagnostics, not portable performance guarantees or a
controlled comparison with Circom. No wall-clock CI threshold is asserted.

## Execution evidence

Both heavy tests passed on 2026-10-29; Gradle completed in 30 seconds. The strict
Java verifier accepted eight fresh randomized proofs and rejected six changed-limb
statements and two canonical negated-A proofs. A subsequent independent snarkjs
0.7.6 run accepted each retained final proof and rejected all eight negatives.

The two final proof/VK/public triples, negative fixtures, public messages/digests,
raw measurement JSON, exact source hashes and a setup-free verification runner
are retained in [assurance/sha2-proof-vectors](../../assurance/sha2-proof-vectors/README.md).
Its [verification result](../../assurance/sha2-proof-vectors/verification-result.json)
records all ten independent checks and artifact/tool hashes. This uses the pinned
snarkjs installation from the optional Circom lane; it adds no dependency.

Measured on an Apple M4 Max, macOS/aarch64, Java 25.0.2+12-LTS, 16 available
processors and a 12 GiB heap. The repository build and Circom export had finished;
the Circom checking phase started only after these proof timings. This remains a
shared host, with observed initial load averages 14.55 and 25.98, not an isolated
benchmark. Three subsequent samples are too few for a robust latency distribution.

| 32-byte message relation | SHA-256 | SHA-512 |
|---|---:|---:|
| Public 128-bit digest limbs | 2 | 4 |
| Constraints | 42,694 | 106,332 |
| Wires | 141,470 | 352,560 |
| QAP domain | 65,536 | 131,072 |
| Compilation including constraint materialization (ms) | 198.20 | 184.15 |
| First witness generation (ms) | 33.95 | 18.45 |
| Development setup (ms) | 2,604.62 | 3,503.56 |
| Temporary key-store bytes | 17,977,255 | 41,549,352 |
| First proof (ms) | 1,713.11 | 2,443.91 |
| Three subsequent proofs, median (ms) | 1,420.82 | 2,452.27 |
| Subsequent proof range (ms) | 1,390.91–1,438.42 | 2,384.64–2,475.02 |
| Subsequent witness generation, median (ms) | 4.49 | 11.25 |
| Strict Java verification, median (ms) | 324.41 | 340.42 |

Proof timers exclude witness generation, setup and JSON serialization. Verification
timers include the strict envelope/material decode path. Setup includes the existing
development tau generation and sparse key-store write. Key-store sizes describe the
temporary setup output, which is not retained in the repository. Both measurements
share a JVM and are ordered SHA-256 then SHA-512; their compilation times must not be
treated as an algorithm ranking. No on-chain performance conclusion follows from
these host verification times.

## Remaining limits

Groth16 is classical, pairing-based and setup-dependent. A correct SHA-2 gadget
does not make the surrounding proof quantum-resistant. These tests neither
establish setup security nor remove the need for production ceremony and artifact
binding. They do not measure Cardano execution units, fees or transaction size.
The public digest leaks information about a low-entropy message and a preimage
relation alone does not prove issuer authorization. Private use also requires the
repository's existing side-channel, deployment and application-statement reviews.
