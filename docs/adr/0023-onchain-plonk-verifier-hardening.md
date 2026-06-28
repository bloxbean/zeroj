# ADR-0023: On-Chain PlonK Verifier Hardening Posture

## Status
Accepted - implemented for BLS12-381 v1 and bounded MPI profiles; external
audit and release-assurance gates pending

## Date
2026-06-28

## Context

`zeroj-onchain-julc` contains an experimental BLS12-381 PlonK validator:

- `PlonkBLS12381TranscriptPrototype`
- `OnChainFeasibility`
- `PlonkBLS12381TranscriptPrototypeTest`

The implementation is useful for Julc data-shape, transcript, inverse, and
budget exploration. It is not a trustless on-chain PlonK verifier today. The
code and docs already say the KZG batch opening pairing check is deferred, but
the class name and positive test can still create a production-readiness
misunderstanding.

The focused review confirmed:

1. **The acceptance condition is not a PlonK proof check.**
   `validate` returns only `inv1Ok && inv2Ok`. The computed linearized
   commitment pieces, proof evaluations, opening witnesses, and decompressed
   points are not part of the final acceptance predicate. A redeemer with
   arbitrary parseable proof data can pass if the transcript-derived `zeta`
   avoids `1` and `omega` and the caller supplies the matching inverses.

2. **Transcript bytes are not bound to the points used for curve operations.**
   The redeemer carries compressed G1 points and separate uncompressed raw G1
   bytes. The Javadoc says the verifier compares them, but the code does not.
   Fiat-Shamir challenges are derived from the raw bytes, while BLS operations
   use the compressed bytes. This is a fatal binding gap once a pairing check is
   added.

3. **Most proof data is currently dead for soundness.**
   `r0`, `[D]`, witness points, `X_2`, and generator points are computed or
   decompressed, but acceptance does not depend on the KZG opening equation.
   This burns budget and makes the prototype look more complete than it is.

4. **Datum and scalar boundaries are too permissive.**
   The validator reads only the head of the datum list as the single public
   input. It does not enforce exact datum shape, expected public-input count,
   scalar range, or non-negative/canonical integer encodings. The implementation
   is specialized to the one-public-input multiplier fixture.

5. **The public-input polynomial sign differs from the off-chain verifier
   convention.**
   The off-chain PlonK verifier subtracts public inputs when computing `PI`.
   The on-chain prototype adds the single public input. This does not currently
   affect acceptance because the KZG equation is not enforced, but it must be
   resolved before completing the verifier.

6. **On-chain transcript documentation is inconsistent.**
   The prototype calls `sha2_256`, while nearby docs and fixtures describe a
   different production transcript direction. The issue is not SHA-256
   availability in Julc; the issue is that the prototype's gnark-style
   SHA-256/raw-byte transcript, the off-chain snarkjs/ZeroJ transcript, and any
   final Plutus-reproducible transcript profile must be explicitly reconciled.

## Implementation Status

Phase 0 has started and the Cardano-profile verifier implementation is now in
place for the current one-public-input PlonK proof shape:

- `OnChainFeasibility.isFeasible` now reports only production-ready `WORKING`
  paths. Experimental PlonK requires explicit
  `isFeasibleWithExperimentalOptIn`.
- The former `PlonkBLS12381FullVerifier` class has been renamed to
  `PlonkBLS12381TranscriptPrototype` so the class name no longer signals a full
  verifier.
- `PlonkBLS12381TranscriptPrototype` now rejects non-canonical compressed BLS
  encodings, wrong-sized raw G1 transcript byte strings, non-scalar proof values,
  and datum values that are empty, extra, negative, or outside `Fr`.
- `PlonkBLS12381Verifier` implements the selected
  `zeroj-plonk-bls12381-cardano-v1-json` profile: compressed G1 Fiat-Shamir
  transcript bytes, strict compressed point canonicality, exact one-public-input
  datum shape, scalar range checks, VK domain/coset validation, precomputed
  inverse checks, linearized commitment reconstruction, folded KZG opening
  aggregation, and the final BLS12-381 pairing predicate.
- `PlonKProverToCardano` converts ZeroJ BLS12-381 PlonK prover output and VK
  material into the Cardano compressed byte format and computes the inverse
  scalars required by the on-chain verifier.
- `PlonkBLS12381MultiInputVerifier` implements the bounded
  `zeroj-plonk-bls12381-cardano-mpi-v1-json` profile for 1 through 8 public
  inputs. It binds the profile tag, exact public input count, and ordered public
  input scalars into the Fiat-Shamir transcript, verifies per-input inverse
  witnesses, and computes the public-input polynomial on-chain using the same
  sign convention as the off-chain verifier.
- The measured Julc VM budget for the one-public-input verifier is approximately
  `4.803B` CPU and `865k` memory. The test gate currently caps it at
  `5.5B` CPU and `1.5M` memory.
- The measured Julc VM budget for the MPI verifier ranges from approximately
  `4.810B` CPU / `905k` memory at one input to `4.945B` CPU / `1.357M` memory
  at eight inputs. The 8-input applied script is `5,608` flat bytes and the
  proof redeemer is `944` CBOR bytes for the current test circuit.
- The measured deployment size for the same applied validator is `5,283` UPLC
  flat bytes and the proof redeemer is `733` CBOR bytes. The test gate keeps both
  below the 16,384-byte inline size limit.
- Adversarial tests cover wrong public input, extra public input, tampered proof
  commitment, and over-field proof evaluation scalar. The full verifier test
  runs against a Java-generated Cardano-profile proof.
- MPI adversarial tests cover wrong, swapped, missing, extra, and over-field
  public inputs, malformed inverse witnesses, tampered proof commitments, and
  profile mismatch rejection in the off-chain verifier.

Still open before final value-bearing release: third-party cryptographic/security
audit, production ceremony artifact pinning, and expanded fuzzing/differential
cross-implementation vectors. The feasibility matrix therefore remains
experimental opt-in until those release gates close.

## Decision

### 1. Keep on-chain PlonK explicitly experimental and fail closed for value-bearing use

`PlonkBLS12381TranscriptPrototype` must not be advertised or used as a production
validator until it enforces the full PlonK acceptance equation. Until then:

- Docs and support matrices must call it a transcript/inverse prototype.
- Any deployment examples must state that it must not secure funds or
  authorization decisions.
- The class has been renamed away from `FullVerifier` to avoid a production
  signal.
- `OnChainFeasibility.isFeasible` must not report experimental PlonK as
  generally feasible unless the caller has explicitly opted into experimental
  paths.
- If exposed in a production build profile, the validator must fail closed
  unless an explicit experimental flag/path is selected.

### 2. Pin one target proving system and transcript before implementing the pairing check

Before implementing the final predicate, the on-chain path must choose one
target proof/transcript profile and lock it with cross-implementation vectors:

- hash function;
- G1/G2 point serialization;
- public-input encoding;
- challenge order;
- domain-separation tags and preimage boundaries;
- batching/folding challenge derivation.

The current off-chain `PlonkBLS12381Verifier` is the executable reference only
for the structured snarkjs/ZeroJ transcript profile. If the on-chain target stays
gnark-compatible, the reference must be gnark verifier behavior and gnark vectors
instead. The ADR deliberately does not assume that snarkjs/ZeroJ and gnark
challenges are interchangeable.

### 3. Implement the full KZG batch opening check before accepting proofs

The on-chain verifier must derive and enforce all challenges and equations for
the chosen profile. For the structured snarkjs/ZeroJ profile this includes
`beta`, `gamma`, `alpha`, `zeta`, KZG folding challenge `v`, and opening
aggregation challenge `u`; for a gnark profile the KZG batch-opening transcript
must follow gnark's verifier exactly.

The final predicate must cover:

- Vanishing polynomial, Lagrange evaluations, public-input polynomial, `r0`,
  linearized commitment `[D]`, folded commitment `[F]`, evaluation commitment
  `[E]`, and final KZG pairing equation.
- The final predicate must be the pairing result plus all structural checks, not
  only inverse checks.

### 4. Bind transcript encodings to curve-operation encodings

The validator must remove the duplicate untrusted representation or prove the
two representations are identical:

- The verifier must not rely on deriving gnark's 96-byte `RawBytes` transcript
  representation from a Plutus BLS group value unless that coordinate
  serialization is explicitly implemented and budgeted. Julc's JVM `byte[]`
  representation for uncompressed points must not be treated as proof that the
  same bytes are available on-chain.
- The preferred on-chain profile is a compressed-point transcript that hashes the
  48-byte compressed encoding the script can reproduce by checking
  `compress(uncompress(point)) == point`. This is a cross-component protocol
  choice, not only an on-chain optimization: the off-chain prover and verifier
  must adopt the same transcript profile, and existing snarkjs/gnark proof
  artifacts will not verify on-chain without a matching adapter or re-proving
  flow.
- If both compressed and raw bytes remain in the redeemer, reject unless every
  raw point is proven to be the canonical transcript encoding of the matching
  compressed point under the chosen profile.
- Apply the same binding to verification-key parameters supplied at script
  parameterization time.

### 5. Treat datum, redeemer, and params as strict cryptographic inputs

The validator must reject malformed inputs before expensive curve work:

- Datum must contain exactly the supported number of public inputs.
- Public inputs and all proof scalars must satisfy `0 <= value < Fr`.
- Proof commitments and opening witnesses must be valid non-infinity BLS12-381
  points under the chosen encoding.
- Challenge-name bytes, domain size, `omega`, `k1`, `k2`, `nInv`, generators,
  and VK commitments must be fixed by the deployed script hash or a documented
  VK hash policy.
- Transcript preimages must use fixed-width fields or explicit separators for
  every segment, including the VK block, public inputs, and proof commitments.
- The one-public-input multiplier specialization must not be generalized by
  convention; generic PlonK needs explicit public-input and domain handling.

### 6. Add budget, memory, and script-size go/no-go gates

The on-chain PlonK status must not advance until the full verifier is measured
against explicit Cardano limits:

- CPU must stay below the 10,000,000,000 execution-unit limit with a documented
  safety margin.
- Memory must stay below the 14,000,000 execution-unit limit with a documented
  safety margin.
- Applied script size must be checked against the 16,384-byte inline script
  limit.
- If the verifier requires CIP-33 reference scripts, the deployment docs must
  say so and include reference-script fee implications.
- `ScriptBudgetEstimator` must be corrected to model the full PlonK verifier,
  including roughly 18 scalar-multiplication/MSM elements for the current
  equation shape, the selected hash costs, pairing costs, and redeemer/data
  overhead.
- The ADR must state the assumed protocol/builtin baseline, including whether a
  BLS12-381 multi-scalar-multiplication builtin is available and used.
- Budget estimates must be reconciled with measured Julc/Plutus evaluation for
  the completed predicate before status changes.

### 7. Add adversarial tests before changing status

The on-chain PlonK test suite must prove sound rejection, not only known-vector
acceptance:

- The selected transcript profile must match independent prover/verifier vectors.
- Mutating each commitment, each evaluation, each opening witness, and each
  public input must fail.
- Mismatching compressed and raw point encodings must fail.
- Negative, over-`Fr`, empty, extra, and wrong-shaped datum/redeemer values must
  fail.
- Infinity encodings for proof commitments and opening witnesses must fail.
- Wrong VK params, wrong challenge names, wrong domain params, and wrong
  public-input count must fail.
- Budget tests must be run only after the full pairing predicate is in place.

## Consequences

### Easier

- The on-chain PlonK status becomes unambiguous.
- Future work has concrete release gates.
- The prototype remains useful for transcript and budget exploration without
  implying proof soundness.
- Transcript interoperability becomes an explicit design choice rather than an
  accidental mix of snarkjs, gnark, and Julc serialization behavior.

### Harder

- Completing PlonK on-chain requires additional transcript rounds, MSM-like G1
  aggregation, and at least one pairing check.
- A gnark-compatible raw-byte transcript may require either a different proof
  profile or expensive on-chain coordinate serialization.
- Strict input validation can increase script size and budget.
- Reference-script deployment may become mandatory if the applied verifier
  exceeds the inline script-size limit.

## Test Plan

1. Keep the existing positive gnark-vector transcript test.
2. Add transcript-profile conformance tests for the selected hash,
   serialization, challenge order, and domain separation.
3. Add negative tests showing that current proof-data tampering is rejected once
   the full predicate is implemented.
4. Add a specific regression test for compressed/raw point mismatch or, if the
   raw representation is removed, compressed transcript canonicality.
5. Add datum/redeemer shape, scalar canonicality, and infinity rejection tests.
6. Add a comparison test against the correct reference for the chosen transcript
   profile: snarkjs/ZeroJ off-chain verifier for the structured profile, or
   gnark verifier/vectors for the gnark profile.
7. Add `OnChainFeasibility` tests proving experimental PlonK is not reported as
   generally feasible without explicit opt-in.
8. Re-run CPU, memory, script-size, and redeemer-size measurements only after the
   full KZG check is wired into the final predicate.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| Prototype is mistaken for a production verifier | Critical | Rename/relabel, fail closed for production paths, and document experimental status |
| Arbitrary proofs pass because only inverse checks gate acceptance | Critical | Implement and gate on the full KZG pairing equation |
| Transcript points differ from curve-operation points | Critical | Bind or eliminate duplicate point encodings |
| The verifier implements a pairing equation for the wrong transcript profile | Critical | Pin one proof/transcript profile before implementation and test against the matching reference |
| Public inputs are malformed or extra data is ignored | High | Enforce exact datum shape and scalar canonicality |
| Final on-chain transcript diverges from the prover transcript | High | Lock transcript hash, serialization, and domain separation with cross-implementation vectors |
| Full verifier exceeds CPU, memory, or script-size limits | High | Correct the estimator, measure after correctness, require go/no-go gates, and use reference scripts only with explicit deployment policy |
| Julc byte-array behavior is mistaken for Plutus group-value serialization | High | Avoid raw uncompressed transcript derivation unless implemented and budgeted explicitly |

## References

- ADR-0008: PlonK Support via gnark
- ADR-0012: Pure Java Provers for Groth16 and PlonK
- ADR-0022: Pure Java PlonK Backend Review Outcomes and Hardening Posture
- `docs/plonk-support.md`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/plonk/validator/PlonkBLS12381TranscriptPrototype.java`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/analysis/OnChainFeasibility.java`
- `zeroj-verifier-plonk/src/main/java/com/bloxbean/cardano/zeroj/verifier/plonk/PlonkBLS12381Verifier.java`
