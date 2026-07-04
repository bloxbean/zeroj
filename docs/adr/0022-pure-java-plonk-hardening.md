# ADR-0022: Pure Java PlonK Backend Review Outcomes and Hardening Posture

## Status
Accepted — hardening implemented for the current beta path; remaining
production gates tracked by ADR-0026

## Date
2026-06-27

## Context

ZeroJ now has a pure Java PlonK path spanning:

- `zeroj-crypto/src/main/java/.../crypto/plonk` for setup, `.ptau`/`.zkey`
  import, proving keys, and BN254/BLS12-381 pure Java provers.
- `zeroj-verifier-plonk/src/main/java/.../verifier/plonk` for structured
  snarkjs/ZeroJ JSON verification on BN254 and BLS12-381.
- `zeroj-codec/src/main/java/.../codec/SnarkjsPlonkCodec.java` for PlonK
  proof and verification-key JSON parsing.

The current production-hardening scope is BLS12-381 first. Cardano currently
supports BLS12-381 on-chain, not BN254, so BN254 PlonK hardening is explicitly
postponed and must remain non-production until a separate BN254 decision and
security pass are completed.

This implements the direction from ADR-0008 and ADR-0012: portable PlonK
generation and verification without native dependencies, while gnark remains an
alternate native proving path. A focused review of the current pure Java PlonK
backend found that the happy path is functional and the focused test suites pass:

```
./gradlew :zeroj-verifier-plonk:test --tests '*Plonk*' --tests '*Transcript*'
./gradlew :zeroj-crypto:test --tests 'com.bloxbean.cardano.zeroj.crypto.plonk.*'
```

The review also found that the implementation is not ready to be treated as a
hardened verifier/prover boundary for untrusted artifacts. The off-chain PlonK
verification equation is treated as the asset to preserve; the hardening gaps
are primarily boundary validation, setup-material validation, availability, and
security-contract clarity rather than failures in the ordinary toy-circuit happy
path.

## Implementation Status

Phase 0 has started. The immediate Cardano/on-chain fail-closed work is tracked
in ADR-0023.

Implemented so far:

- BLS12-381 PlonK verifier now enforces envelope/material consistency, proof/VK
  protocol and curve metadata, VK hash binding, public-input scalar range,
  proof-evaluation scalar range, canonical normalized G1/G2 encodings,
  BLS12-381 point validity/subgroup checks, non-infinity proof commitments and
  opening witnesses, VK domain root validation, and permutation coset membership
  validation before transcript or pairing.
- BLS12-381 malformed inputs now return typed reason codes for the covered
  classes instead of a blanket `INTERNAL_ERROR`.
- BLS12-381 negative tests cover invalid public inputs, wrong public-input
  count, material/circuit mismatch, wrong proof/VK curve metadata, gnark and
  unsupported proof formats, over-field proof scalars, off-curve commitments,
  non-normalized proof encodings, forbidden infinity encodings, invalid VK
  domain roots, invalid permutation cosets, forbidden `X_2` infinity, and VK
  hash mismatch.
- PlonK proof/VK JSON metadata fields `protocol` and `curve` are now required by
  the codec instead of defaulted.
- `SnarkjsPlonkCodec` now applies bounded JSON byte size, nesting, number/string
  length limits, duplicate-key rejection, exact G1/G2 arity checks, and canonical
  non-negative decimal parsing before `BigInteger` construction.
- PlonK codec malformed-input tests now cover oversized streams and strings,
  missing metadata, duplicate keys, wrong G1/G2 arity, negative decimals,
  non-canonical decimals, overlong decimals, and invalid text metadata.
- `FiatShamirTranscript` now rejects negative, over-field scalar inputs and
  over-width coordinate encodings instead of silently trimming high bytes.
- BLS12-381 PlonK setup now validates selector shape/range, sigma lengths/ranges,
  bounded domain size, SRS length, and non-infinity on-curve/subgroup-valid SRS
  points before producing a proving key.
- BLS12-381 PlonK prover entry now requires exact domain-sized wire arrays,
  non-null wires/blinders, valid public-input count, and canonical public-input
  scalars before FFT or transcript construction. The public prover supports a
  caller-supplied `SecureRandom` for production RNG policy and uses rejection
  sampling for blinding scalars.
- BLS12-381 PlonK prover/verifier now support an explicit Cardano on-chain
  transcript profile, `zeroj-plonk-bls12381-cardano-v1-json`, where Fiat-Shamir
  G1 inputs are canonical compressed BLS12-381 bytes. The existing
  `snarkjs-plonk-json` transcript remains unchanged for off-chain compatibility,
  and Cardano-profile proofs are rejected if mislabeled as snarkjs transcript
  proofs.
- BLS12-381 `.ptau` and PlonK `.zkey` importers now use bounded reads, required
  section/duplicate/size checks, expected BLS12-381 `q`/`r` checks, bounded domain
  dimensions, canonical field-element parsing, and non-infinity on-curve/subgroup
  validation for required SRS and proving-key points.
- BLS12-381 setup/import now checks powers-of-tau consistency for loaded/used SRS
  powers by anchoring `[1]_1`/`[1]_2` to the standard generators and checking
  `e([tau^i]_1, [1]_2) == e([tau^(i-1)]_1, [tau]_2)` for required G1 powers.
- BLS12-381 `.ptau` and PlonK `.zkey` importers now expose SHA-256 pinning
  overloads that reject unexpected setup artifacts before parsing.

Still open before final value-bearing release: selecting and documenting the
actual production ceremony source and per-circuit artifact hashes, coverage-
guided parser/importer fuzzing, standing differential gates against external
implementations, and independent cryptographic/security audit. GraalVM
native-image work is explicitly deferred because it does not immediately improve
security. BN254-specific point validation and BN254 importer/prover/setup parity
are postponed because Cardano does not currently support BN254 on-chain.

### Review findings that require a decision

1. **External proof/VK point validation is missing.**
   `SnarkjsPlonkCodec` parses arbitrary `BigInteger` coordinates. The PlonK
   verifiers convert them directly to curve objects. BN254 verifier point types
   do not expose point validation; BLS12-381 point types expose `isValid()` but
   the PlonK verifier does not call it. Malformed, off-curve, subgroup-invalid,
   or unexpected infinity points can reach transcript and pairing code.

2. **Scalars and public inputs are not canonicalized or rejected at the
   boundary.**
   Proof evaluations, VK scalar fields, and `PublicInputs` accept arbitrary
   `BigInteger`s. `FiatShamirTranscript.writeBigEndian` trims over-width values
   instead of rejecting them. Negative and over-width scalar encodings therefore
   create non-injective transcript encodings and proof malleability risk.

3. **Verification material is not bound to the envelope before backend
   execution.**
   `VerifierOrchestrator` chooses a backend from the envelope and passes
   `VerificationMaterial` through without checking that the material's proof
   system, curve, circuit id, or hash matches the envelope. The PlonK verifiers
   also parse but do not enforce proof/VK `protocol` and `curve` fields.

4. **Trusted setup importers are permissive.**
   `.ptau` importers skip or lightly parse section metadata and do not compare
   declared primes to the expected curve constants. `.zkey` importers read
   declared `q` and `r` values without comparing them to the selected curve.
   Imported points are reduced into field objects without curve/subgroup
   validation. For BLS12-381, subgroup validation is mandatory for untrusted
   setup material.

5. **Prover input invariants are too loose.**
   `PlonKProver` and `PlonKProverBLS381` accept wire arrays with length greater
   than the domain size, but then pass those arrays directly into FFT/IFFT paths.
   That changes the interpolation domain and can later truncate coefficients
   during blinding. This is a trusted local API-contract gap rather than a
   remote verifier-input attack, but the API should require exact domain-sized
   wires or slice explicitly before interpolation.

6. **Setup accepts invalid sigma/permutation data silently.**
   `PlonKSetup` and `PlonKSetupBLS381` do not validate sigma array lengths or
   target ranges. Invalid decoded columns fall through to column A instead of
   failing.

7. **Pure Java proving remains variable-time for witness-dependent scalars.**
   MSM and scalar multiplication branch on scalar bits and window digits. This
   is acceptable for a portable local prover, but not a constant-time contract
   for high-value secret-bearing workloads in shared or adversarial runtimes.

8. **Tests are mostly happy-path gates.**
   Existing tests cover snarkjs transcript compatibility, Java-generated
   BLS12-381 proof acceptance, BN254 snarkjs proof acceptance, one tampered
   evaluation, wrong public input count, and a wrong-witness prover case. They
   do not cover non-canonical encodings, off-curve points, BLS subgroup failures,
   setup section corruption, wrong proof/VK metadata, oversized wire arrays, or
   larger differential vectors.

9. **Untrusted inputs can consume unbounded verifier/importer resources.**
   JSON proof/VK fields, `power`/`domainSize`, `nPublic`, `.ptau`/`.zkey` file
   sizes, section sizes, SRS counts, and decimal scalar strings are not bounded
   before parsing, allocation, loops, or `modInverse` work. Malformed input can
   therefore become an availability issue even when it cannot forge a proof.

10. **VK domain scalars are not validated.**
    The verifier consumes `domainSize`, `omega`, `k1`, and `k2` from the VK.
    If the VK is accepted as untrusted material, those parameters must satisfy
    the PlonK domain and coset requirements, not only point membership.

## Decision

### 1. Treat PlonK proof, VK, and public-input parsing as a strict cryptographic boundary

The structured snarkjs/ZeroJ PlonK verifier must reject malformed encodings
before transcript construction, allocation-heavy work, unbounded loops, or
pairing:

- G1/G2 coordinate arrays must have the expected arity and no extra elements
  before coordinates are materialized into curve objects.
- Coordinates must be canonical field elements: `0 <= value < p`.
- Scalar fields and public inputs must be canonical scalar field elements:
  `0 <= value < r`.
- `domainSize` must be a supported power of two, `nPublic` must be bounded, and
  verifier work derived from those values must be capped before loops or
  allocations.
- For untrusted VK material, `omega` must be a primitive `domainSize`-th root of
  unity. The permutation cosets must be disjoint by membership, not merely by
  scalar inequality: `k1` and `k2` must not be in `<omega>`, and
  `k1 * k2^-1` must not be in `<omega>`. If a deployment treats the VK as
  trusted-by-pinned-hash instead, the hash binding decision must be explicit and
  enforced before verification.
- Proof commitments and opening witnesses must be on curve, in the expected
  subgroup where required, and non-infinity. VK commitments must be on curve and
  subgroup-valid; non-infinity must be required for SRS powers, `X_2`, and
  permutation commitments, while selector commitments may be infinity when they
  canonically represent a zero selector polynomial.
- Projective encodings must be normalized or rejected deterministically; a
  point at infinity must use one accepted canonical representation only.
- Transcript serialization must reject values that do not fit the configured
  scalar/base-field byte width. It must not silently trim high bytes.
- `Z_H(zeta) = 0` or `zeta` equal to a public-input Lagrange denominator must be
  an `INVALID_PROOF` result, not a generic internal exception.
- The BN254 point types need explicit `isOnCurve`/subgroup validation APIs before
  the BN254 verifier can satisfy this decision.
- Pairing helpers that skip infinity operands must not be relied on to catch
  invalid points; the verifier must reject invalid/infinity inputs first.

The verifier must return `MALFORMED_ENVELOPE`, `INVALID_PUBLIC_INPUTS`, or
`INVALID_PROOF` rather than `INTERNAL_ERROR` for expected malformed input
classes, and it must not echo raw parser or arithmetic exception text into
public error messages.

### 2. Bound parser, verifier, and importer resource usage

Untrusted artifacts must be bounded before expensive parsing or cryptographic
work:

- JSON parsing must use document-size, nesting, array-length, and string-length
  limits suitable for expected proof/VK sizes.
- Duplicate JSON keys must be rejected instead of using last-wins behavior.
- Decimal scalar strings must have a maximum length before `BigInteger`
  construction.
- `power`, `domainSize`, `nPublic`, SRS counts, section sizes, and polynomial
  counts must be checked against configured maxima before allocations, loops, or
  `modInverse` calls.
- Importers must reject files above a configured maximum size before
  `readAllBytes`.

### 3. Enforce envelope, verification material, proof JSON, and VK JSON consistency

Before invoking the backend or before accepting a backend result:

- `VerificationMaterial.proofSystemId()` must match `envelope.proofSystem()`.
- `VerificationMaterial.curveId()` must match `envelope.curve()`.
- `VerificationMaterial.circuitId()` must match `envelope.circuitId()`.
- If the envelope references a VK hash, it must match the material hash or the
  hash of `material.vkBytes()`.
- PlonK proof JSON `protocol` must be `plonk`.
- PlonK proof/VK JSON `curve` must match the selected verifier curve.
- The proof and VK curves must match each other.
- VK `nPublic` must match the envelope public input count, as today.

This is a defense-in-depth decision. Applications still own policy, key
registry, circuit lifecycle, and authorization, but the cryptographic verifier
must not silently combine inconsistent artifacts.

### 4. Harden `.ptau` and `.zkey` importers before treating imported setup material as trusted

The setup importers must fail early on malformed or wrong-curve files:

- Enforce a maximum file size before reading the full artifact.
- Check required sections exist exactly once and have plausible sizes.
- Check section offsets and sizes with overflow-safe arithmetic so
  `offset + size <= fileLength` before slicing.
- Check declared base/scalar field byte widths and assert declared `q` and `r`
  equal the selected curve constants immediately after reading them, before
  using either value as a reduction modulus.
- Check domain size is a power of two and within the supported FFT range.
- Check SRS counts and section-derived array lengths against configured maxima
  before allocation.
- Check SRS arrays are large enough for the maximum polynomial degree the prover
  will commit.
- Validate imported G1/G2 points for curve membership and, for BLS12-381,
  subgroup membership.
- Reject unexpected infinity points in SRS powers, permutation commitments, and
  `X_2`. Selector commitments may be infinity only when that is the canonical
  commitment to a zero selector polynomial.
- Convert malformed importer failures into typed exceptions rather than leaking
  `NullPointerException`, `NegativeArraySizeException`, integer truncation, or
  unchecked parser exceptions.

Development single-party SRS generation remains allowed for tests and local
demos, but it must stay documented as non-production. Persisting or exposing
`tauScalar` is not acceptable for production setup material.

### 5. Tighten prover/setup API invariants

The prover and setup APIs should fail on invalid internal inputs instead of
trying to continue:

- Wire arrays passed to `prove` must have length exactly equal to
  `pk.domainSize()`, or the method must explicitly copy exactly `n` entries into
  a domain-sized array before FFT.
- `pubInputs.length` must equal `pk.nPublic()` and every public input must be in
  the scalar field.
- `domainSize` must be a power of two and at least the minimum required by the
  blinding/coset strategy.
- `gateSelectors` must have shape `[numGates][5]`.
- `sigmaA`, `sigmaB`, and `sigmaC` must each have `numGates` entries.
- Every sigma target must be in `[0, 3 * numGates)`.
- `decodeSigmaTarget` must reject unknown columns rather than falling back to
  column A.
- SRS length must be checked once at setup/proving-key construction against the
  maximum polynomial degree required by the prover.

### 6. Make negative/malformed tests release gates

Before advertising the pure Java PlonK backend as hardened, add tests for:

- Negative, over-`r`, and over-width proof scalars.
- Negative, over-`r`, and over-width public inputs.
- Non-canonical G1/G2 coordinates (`p`, `p + x`, negative).
- Off-curve G1/G2 proof commitments and VK commitments.
- BLS12-381 subgroup-invalid points.
- Non-canonical and unexpected infinity encodings.
- Proof/VK `protocol` and `curve` mismatches.
- `VerificationMaterial` proof-system, curve, circuit-id, and hash mismatches.
- VK `domainSize`, `omega`, `k1`, and `k2` domain/coset failures.
- `zeta` landing inside the evaluation domain or causing a Lagrange denominator
  of zero.
- Oversized JSON documents, large decimal strings, excessive arrays, duplicate
  keys, and bounded `power`/`nPublic` violations.
- Missing, duplicate, short, long, or wrong-prime `.ptau`/`.zkey` sections.
- Oversized and undersized wire arrays.
- Invalid sigma array lengths and out-of-range sigma targets.
- Tampering each proof commitment and each evaluation independently.
- Differential proof vectors for more than the multiplier circuit, including at
  least one circuit with multiple public inputs and non-trivial copy
  constraints.

These tests should live near the relevant boundary:

- Codec validation tests in `zeroj-codec`.
- Verifier negative tests in `zeroj-verifier-plonk`.
- Setup/importer/prover invariant tests in `zeroj-crypto`.
- End-to-end differential vectors in `zeroj-test-vectors` or the module tests
  that consume it.

### 7. State the pure Java prover side-channel contract explicitly

The pure Java PlonK prover is portable and correctness-first. It is not a
constant-time implementation. The docs and Javadocs must avoid implying
side-channel resistance for witness-dependent MSM/scalar operations. High-value
production proving in shared runtimes should prefer a side-channel-reviewed
native backend or an isolated proving environment.

### 8. Keep gnark binary PlonK separate until a dedicated adapter exists

The pure Java PlonK verifiers consume structured snarkjs/ZeroJ proof JSON.
gnark opaque binary PlonK proof JSON remains unsupported by this verifier path.
That separation should remain explicit until there is a dedicated gnark PlonK
adapter with its own transcript, serialization, and vector coverage.

## Consequences

### Easier

- Malformed proofs, wrong-curve keys, and inconsistent envelopes fail before
  expensive pairing work.
- Transcript inputs become injective and auditable.
- Availability limits become part of the verifier contract instead of relying on
  best-effort parsing.
- Setup-material trust assumptions become explicit.
- Future pairing/MSM/prover optimizations can proceed behind a stronger negative
  test suite.

### Harder

- Codecs and verifiers become stricter than the current permissive JSON parser,
  so some previously accepted non-canonical artifacts will fail.
- BLS12-381 subgroup checks on setup material are expensive unless optimized or
  cached.
- Parser and importer limits need configuration and migration notes for unusually
  large local development fixtures.
- The test suite gains more negative fixtures and setup-corruption cases.

### Neutral

- The high-level architecture from ADR-0001, ADR-0006, ADR-0008, and ADR-0012
  does not change.
- gnark remains the native prover path; pure Java remains the portable path.
- Existing valid canonical snarkjs/ZeroJ artifacts should continue to verify.

## Test Plan

1. Add codec-level canonical encoding tests for all proof, VK, and public-input
   scalar/point fields.
2. Add parser/resource-limit tests for oversized JSON, large decimal strings,
   excessive arrays, duplicate keys, bounded `power`, and bounded `nPublic`.
3. Add verifier-level malformed proof/VK tests and assert stable reason codes.
4. Add VK domain-scalar tests for invalid `domainSize`, non-primitive `omega`,
   and non-distinct permutation cosets.
5. Add orchestrator/material mismatch tests for proof system, curve, circuit id,
   and VK hash.
6. Add `.ptau` and `.zkey` corruption fixtures for missing sections,
   wrong-prime headers, wrong-prime-before-reduction, invalid point encodings,
   short sections, huge sections, truncated section offsets, and unexpected
   infinity.
7. Add prover/setup invariant tests for wire length, public input range, domain
   size, SRS length, selector shape, and sigma range.
8. Add end-to-end vectors for multiple public inputs and non-trivial copy
   constraints on both BN254 and BLS12-381 where feasible.
9. Keep the existing focused suites green:

```
./gradlew :zeroj-verifier-plonk:test --tests '*Plonk*' --tests '*Transcript*'
./gradlew :zeroj-crypto:test --tests 'com.bloxbean.cardano.zeroj.crypto.plonk.*'
```

## Implementation Plan

1. Add the negative tests first, marking currently missing behavior with clear
   names.
2. Add parser and importer resource limits before doing deeper crypto changes.
3. Introduce curve-specific PlonK validation helpers for canonical scalar,
   canonical coordinate, G1, and G2 validation. For BN254 this requires adding
   point validation APIs before the verifier can call them.
4. Update `FiatShamirTranscript` to reject over-width and negative values
   instead of trimming.
5. Validate VK domain scalars or enforce pinned-VK trust before verification.
6. Enforce proof/VK metadata and `VerificationMaterial` consistency before
   pairing.
7. Harden `.ptau` and `.zkey` importers with file-size, section, prime,
   point, subgroup, overflow-safe offset, and SRS-size validation.
8. Tighten `PlonKSetup` and `PlonKProver` invariants.
9. Update docs and README status so BN254/BLS12-381 PlonK verifier status and
   pure Java side-channel posture are accurate.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| Off-curve or subgroup-invalid points reach pairing code | High | Validate all proof/VK/SRS points before transcript or pairing |
| Non-canonical scalars create transcript malleability | High | Reject negative, over-field, and over-width scalars at codec/transcript boundaries |
| Wrong VK material is combined with an envelope | High | Enforce proof-system, curve, circuit-id, and hash consistency before backend execution |
| Invalid VK domain scalars collapse permutation/coset assumptions | High | Validate `domainSize`, primitive `omega`, and distinct cosets, or enforce pinned-VK trust |
| Untrusted artifacts exhaust CPU or memory before crypto rejection | High | Bound JSON, file, section, `nPublic`, `power`, SRS, and string sizes before parsing/work |
| Malformed setup material produces unsound or unverifiable proving keys | High | Validate `.ptau`/`.zkey` sections, primes, points, subgroups, and SRS length |
| Strict validation breaks existing permissive tests or hand-written fixtures | Medium | Update fixtures to canonical encodings; keep migration notes in docs |
| BLS subgroup validation makes setup import slower | Medium | Cache validation results and consider optimized subgroup checks after correctness gates |
| Pure Java prover side-channel leakage is misunderstood | Medium | Document the side-channel contract; recommend native or isolated proving for high-value workloads |

## References

- ADR-0001: Verifier-First Architecture
- ADR-0006: Separation of Crypto and Policy Verification
- ADR-0008: PlonK Support via gnark
- ADR-0012: Pure Java Provers for Groth16 and PlonK
- ADR-0021: BLS12-381 Implementation Review Outcomes and Hardening Posture
- PlonK paper: <https://eprint.iacr.org/2019/953>
- CIP-0381: <https://cips.cardano.org/cip/CIP-0381>
