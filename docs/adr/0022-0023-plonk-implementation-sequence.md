# Implementation Sequence: ADR-0022 and ADR-0023 PlonK Hardening

## Status
Planning note

## Date
2026-06-28

## Scope

This document sequences implementation of:

- ADR-0022: Pure Java PlonK Backend Review Outcomes and Hardening Posture
- ADR-0023: On-Chain PlonK Verifier Hardening Posture
- Addendum: ADR-0022 & ADR-0023 PlonK Production-Readiness Gaps
- ADR-0024: PlonK Release Gates and Multi-Public-Input On-Chain Profile

The order is intentionally conservative: make misuse impossible first, then
harden untrusted boundaries, then prove setup provenance, then add broad test
gates, and only then revisit on-chain PlonK.

Current implementation priority is BLS12-381. Cardano currently supports
BLS12-381 on-chain, not BN254, so BN254 PlonK hardening is postponed and is not a
blocker for BLS12-381 prover/off-chain verifier production readiness.
After the one-public-input Cardano profile, the next planned PlonK implementation
phase is the bounded multi-public-input on-chain profile described in ADR-0024.

## Readiness Assessment

The production-readiness addendum makes sense with one correction already folded
back into the addendum: `zeroj-codec` and `zeroj-verifier-plonk` already have
native-image metadata, while `zeroj-crypto` does not. The real GraalVM gate is
metadata coverage plus an end-to-end native-image smoke test, not metadata from
zero.

The highest priority addition is valid: trusted-setup provenance and SRS
pairing-consistency checks are necessary. On-curve/subgroup validation proves
points are valid group elements; it does not prove they are powers of one toxic
waste value.

## Phase 0: Safety Defaults And Scope Lock

Goal: prevent accidental production use while hardening is incomplete.

1. Keep ADR-0022 and ADR-0023 in `Proposed` until the relevant gates pass.
2. Keep on-chain PlonK explicitly experimental in docs and support matrices.
3. Change `OnChainFeasibility.isFeasible` so experimental PlonK is not reported
   as generally feasible without explicit opt-in.
4. Rename or wrap `PlonkBLS12381FullVerifier` so it no longer signals a complete
   verifier. This has started with `PlonkBLS12381TranscriptPrototype`.
5. State the recommended production route today: off-chain PlonK verification
   and on-chain Groth16 for value-bearing Cardano validators.

Deliverable: misuse-prevention PR with docs/tests only, no cryptographic behavior
changes beyond fail-closed status reporting.

## Phase 1: Test Harness And Failure Taxonomy

Goal: add red tests and stable error expectations before changing parser and
verifier behavior.

1. Define typed malformed-input outcomes across codec, verifier, orchestrator,
   and importer paths.
2. Add negative test scaffolding for malformed proof/VK JSON, wrong envelope
   metadata, invalid public inputs, invalid setup files, and invalid prover/setup
   inputs.
3. Add regression tests proving raw exception messages are not exposed through
   public verifier results.
4. Add test fixtures for oversized JSON, large decimal strings, excessive arrays,
   duplicate keys, bounded `power`, and bounded `nPublic`.

Deliverable: negative tests initially failing or marked with clear pending names.

## Phase 2: Parser, Codec, And Envelope Boundary

Goal: reject bad public inputs before transcript construction or expensive work.

1. Add JSON parser limits: document size, nesting depth, array length, and string
   length.
2. Reject duplicate JSON keys.
3. Check G1/G2 arity before materializing coordinates.
4. Reject negative, over-field, and over-width scalar and coordinate encodings.
5. Update `FiatShamirTranscript` to reject non-canonical scalars instead of
   trimming.
6. Enforce proof/VK `protocol` and `curve` metadata.
7. Enforce `VerificationMaterial` proof system, curve, circuit id, and VK hash
   consistency before backend execution.
8. Return `MALFORMED_ENVELOPE`, `INVALID_PUBLIC_INPUTS`, or `INVALID_PROOF`
   deterministically for expected malformed inputs.

Deliverable: strict codec/orchestrator/verifier boundary with stable reason
codes.

Implementation status: partially complete. BLS12-381 verifier-side checks are in
place for envelope/material consistency, proof/VK metadata, scalar ranges, point
validity, VK domain data, and stable malformed-input reason codes. The shared
snarkjs PlonK codec now applies JSON size/nesting/number/string limits,
duplicate-key rejection, exact G1/G2 arity checks, mandatory metadata, and
canonical decimal parsing. `FiatShamirTranscript` now rejects negative,
over-field, and over-width values instead of trimming. Focused malformed codec
coverage is in place for oversized inputs, missing metadata, duplicate keys,
wrong G1/G2 arity, negative/non-canonical/overlong decimals, and invalid text
metadata. BN254 verifier boundary hardening is postponed because Cardano does
not currently support BN254 on-chain.

## Phase 3: Curve And VK Semantic Validation

Goal: keep invalid group elements and invalid PlonK domain data out of the proof
equation.

1. Add BN254 `isOnCurve` and subgroup/prime-order validation APIs.
2. Wire BLS12-381 and BN254 point validation into PlonK proof and VK parsing.
3. Reject unexpected infinity for proof commitments and opening witnesses.
4. Scope VK infinity handling correctly: selector commitments may be the
   canonical zero commitment; SRS powers, `X_2`, and permutation commitments may
   not be unexpected infinity.
5. Validate `domainSize` as a supported power of two.
6. Validate `omega` as a primitive `domainSize`-th root of unity.
7. Validate PlonK permutation cosets by membership:
   `k1 notin <omega>`, `k2 notin <omega>`, and
   `k1 * k2^-1 notin <omega>`.
8. Explicitly reject `zeta` values that land in the evaluation domain or cause
   public-input Lagrange denominator inversion failure.

Deliverable: the existing off-chain pairing equation is reached only after
canonical, curve-valid, domain-valid inputs are established.

Implementation status: partially complete for BLS12-381. BLS verifier/setup and
importer point validation is in place for the covered paths. BN254 validation
APIs and BN254 verifier/importer wiring are postponed and are not part of the
current BLS12-381 production-readiness gate.

## Phase 4: Setup Importer And SRS Trust

Goal: make setup material a real cryptographic trust boundary, not just a binary
parser.

1. Enforce maximum `.ptau` and `.zkey` file sizes before `readAllBytes`.
2. Check required sections, uniqueness, plausible sizes, and overflow-safe
   `offset + size <= fileLength`.
3. Assert declared `q` and `r` equal curve constants immediately after reading
   and before using either as a reduction modulus.
4. Bound SRS counts and section-derived array sizes before allocation.
5. Validate imported G1/G2 points for curve and subgroup membership.
6. Add SRS pairing-consistency checks:
   `e([tau^i]_1, [1]_2) == e([tau^(i-1)]_1, [tau]_2)`, preferably batched.
7. Check `[1]_1`, `[1]_2`, and `[tau]_2` anchors.
8. Add production artifact hash pinning and documented ceremony provenance.
9. Keep local single-party setup generation explicitly dev/test-only; never
   persist or expose `tauScalar` in production paths.

Deliverable: imported setup material is bounded, well-formed, curve-valid,
subgroup-valid, internally powers-of-tau consistent, and provenance-pinned.

Implementation status: complete for the BLS12-381 code path. The BLS `.ptau` and
PlonK `.zkey` importers now apply bounded reads, required section,
duplicate-section, size/alignment, BLS12-381 `q`/`r`, domain-dimension,
canonical field-element, and required point on-curve/subgroup checks. BLS setup
and import now check loaded/used powers-of-tau consistency by anchoring standard
generators and checking `e([tau^i]_1, [1]_2) == e([tau^(i-1)]_1, [tau]_2)`.
The BLS `.ptau` and `.zkey` importers expose SHA-256 pinning overloads that
reject unexpected artifacts before parsing. Still open outside the reusable code:
choosing and documenting the production ceremony source and exact artifact hashes
for each production circuit. BN254 importer parity is postponed until BN254 is a
supported Cardano target.

## Phase 5: Prover And Setup API Invariants

Goal: remove trusted-input foot-guns and make the prover contract explicit.

1. Require wire arrays to match `pk.domainSize()` exactly, or copy exactly `n`
   entries before FFT.
2. Require public input count and scalar range at prover entry.
3. Validate domain size, selector shape, sigma lengths, sigma ranges, and SRS
   length at setup/proving-key construction.
4. Make `decodeSigmaTarget` reject unknown columns.
5. Document that blinding scalars must come from a CSPRNG.
6. Document the JVM secret-lifetime limitation: witness, blinders, and dev-mode
   `tauScalar` cannot be reliably zeroized because `BigInteger` values are
   immutable and GC-copyable.

Deliverable: local prover/setup misuse fails early and the side-channel/secret
contract is explicit.

Implementation status: complete for the BLS12-381 code path. Setup validates
selector shape/range, sigma lengths/ranges, bounded domain size, SRS length, and
non-infinity on-curve/subgroup-valid SRS points. The prover now requires exact
domain-sized wire arrays, non-null wires/blinders, matching public-input count,
and canonical public-input scalars. The public prover supports caller-supplied
`SecureRandom` and rejection-sampled blinding scalars. BN254 parity is postponed.

## Phase 6: Broad Assurance Gates

Goal: move from hand-picked negative tests to ongoing release gates.

1. Add coverage-guided fuzzing for `SnarkjsPlonkCodec`, `PtauImporter`, and
   `PlonKZkeyImporter` with persisted corpus and CI budget.
2. Add a differential oracle against snarkjs/gnark verification over a generated
   circuit corpus with accept and reject cases.
3. Add multi-public-input and non-trivial-copy-constraint vectors.
4. Defer GraalVM native-image metadata review and smoke testing to a later
   portability gate; it is not a near-term security blocker.
5. Run focused suites:

```bash
./gradlew :zeroj-verifier-plonk:test --tests '*Plonk*' --tests '*Transcript*'
./gradlew :zeroj-codec:test
./gradlew :zeroj-crypto:test --tests 'com.bloxbean.cardano.zeroj.crypto.plonk.*'
```

Deliverable: recurring CI gates for malformed inputs, fuzzing, differential
behavior, and GraalVM native-image compatibility.

## Phase 7: Off-Chain Release Gate

Goal: decide whether ADR-0022 can move from `Proposed` to `Accepted`.

1. Run the full regression, fuzz, differential, and native-image gates.
2. Complete an independent cryptographic/security audit of the pure Java PlonK
   verifier/importer/prover path.
3. Close or explicitly defer audit findings with severity-appropriate rationale.
4. Update support matrices and release notes with the final production contract.

Deliverable: off-chain pure Java PlonK can be considered production-ready only
after this phase.

## Phase 8: On-Chain PlonK Design Gate

Goal: decide whether on-chain PlonK should proceed, and with which transcript.

1. Keep Groth16 as the recommended value-bearing on-chain verifier until this
   phase passes.
2. Pick exactly one on-chain PlonK transcript profile:
   structured snarkjs/ZeroJ, gnark-compatible, or a new compressed-point profile.
3. Add a version tag to the envelope and Fiat-Shamir transcript.
4. Produce cross-implementation vectors for the selected profile.
5. If using a compressed-point transcript, update the off-chain prover/verifier
   or adapter so proofs are generated for the same transcript. Current
   snarkjs/gnark artifacts are not reusable as-is.
6. If using gnark raw-byte compatibility, explicitly implement and budget the
   coordinate serialization path, or reject the profile as impractical.

Deliverable: a written go/no-go decision for the on-chain PlonK transcript
profile before KZG verifier coding begins.

Implementation status: complete for the first Cardano profile. The selected
profile is `zeroj-plonk-bls12381-cardano-v1-json`, which hashes canonical
compressed G1 bytes in the Fiat-Shamir transcript and therefore binds the bytes
used for transcript derivation to the bytes uncompressed by Plutus BLS builtins.
Existing snarkjs/gnark proof artifacts are not reusable for this on-chain path
without re-proving or an adapter that emits this profile.

Implementation status for the bounded MPI profile: complete as
`zeroj-plonk-bls12381-cardano-mpi-v1-json`. The MPI profile binds the profile
tag, exact public input count, and ordered fixed-width public input scalars into
the same compressed-point transcript profile.

## Phase 9: On-Chain Implementation And Measurement

Goal: replace the transcript/inverse prototype with a measured verifier, if the
design gate passes.

1. Implement the full KZG batch-opening predicate for the chosen profile.
2. Bind transcript encodings to curve-operation encodings.
3. Enforce exact datum/redeemer shape, scalar range, point validity, non-infinity,
   and fixed VK/hash policy.
4. Correct `ScriptBudgetEstimator` for the completed verifier, including the
   selected hash, pairing costs, G1 aggregation/MSM shape, redeemer overhead, and
   script-size assumptions.
5. Measure CPU, memory, applied script size, and redeemer size against Cardano
   limits.
6. Decide whether CIP-33 reference scripts are required and document fee impact.
7. Add adversarial on-chain tests: mutated commitments, evaluations, opening
   witnesses, public inputs, compressed/raw mismatch, infinity encodings, wrong
   VK params, wrong domain params, and wrong challenge tags.

Implementation status: complete for the current one-public-input Cardano profile
and the bounded MPI profile. `PlonkBLS12381Verifier` performs strict compressed
point/scalar/domain validation, reconstructs the linearized commitment, folds
KZG openings, and checks the final pairing for the v1 one-input profile.
`PlonkBLS12381MultiInputVerifier` performs the same proof checks for the MPI
profile while deriving the public-input polynomial from exactly 1 through 8
datum values and verified inverse witnesses. `PlonKProverToCardano` converts
Java prover output to Cardano compressed proof/VK data and computes the required
inverse scalars. Measured Julc VM budget is approximately `4.803B` CPU and
`865k` memory for the one-input v1 profile, and up to `4.945B` CPU and `1.357M`
memory for the 8-input MPI profile. Remaining work before final release:
production ceremony artifact pins, broader fuzzing/differential vectors, and
third-party audit.

Deliverable: on-chain PlonK remains experimental unless the full predicate and
all measurement gates pass.

The older `PlonkBLS12381TranscriptPrototype` remains only as a gnark transcript
regression harness and must not be used as a trustless verifier.

## Phase 10: On-Chain Audit And Promotion

Goal: decide whether ADR-0023 can move beyond experimental.

1. Run an independent audit of the on-chain PlonK verifier and its off-chain
   transcript/proof-generation profile.
2. Close audit findings.
3. Re-run budget measurements on representative transactions.
4. Promote status only if correctness, budget, script-size, deployment, and audit
   gates all pass.

Deliverable: either accepted on-chain PlonK support, or a documented decision to
keep PlonK off-chain and use Groth16 for Cardano value-bearing validators.
