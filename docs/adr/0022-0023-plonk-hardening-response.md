# Response: ADR-0022 & ADR-0023 PlonK Hardening Review

## Status
Response after incorporation

## Date
2026-06-28

## Summary

Claude's review was technically useful and most recommendations were
incorporated. The updated ADRs now treat the off-chain PlonK verifier as a
correct equation behind an insufficiently hardened boundary, and the on-chain
PlonK validator as an experimental transcript/inverse prototype that still needs
a pinned transcript profile, full KZG predicate, and explicit budget/size gates.

Updated files:

- `docs/adr/0022-pure-java-plonk-hardening.md`
- `docs/adr/0023-onchain-plonk-verifier-hardening.md`
- `docs/plonk-support.md`
- `zeroj-onchain-julc/src/test/resources/test-circuits/plonk-multiplier-bls12381/plonk_cardano.json`

## ADR-0022 Changes

Accepted and incorporated:

- Added availability/resource-exhaustion as a first-class threat class.
- Added JSON parser limits: document size, nesting, array length, scalar-string
  length, and duplicate-key rejection.
- Added verifier bounds for `power`, `domainSize`, and `nPublic` before loops,
  allocation, or `modInverse` work.
- Added setup importer limits for file size, section sizes, SRS counts,
  overflow-safe section arithmetic, and typed importer failures.
- Strengthened `.zkey` wording so declared `q`/`r` must be asserted equal to
  curve constants immediately after read and before use as reduction moduli.
- Added VK domain-scalar validation for untrusted VK material: supported
  power-of-two `domainSize`, primitive `omega`, and distinct `{1, k1, k2}`
  permutation cosets.
- Scoped infinity rejection: SRS powers, `X_2`, proof commitments, opening
  witnesses, and permutation commitments must reject unexpected infinity, while
  selector commitments may be infinity when they canonically commit to a zero
  selector polynomial.
- Added the BN254 prerequisite: point validation APIs must be added before the
  BN254 PlonK verifier can satisfy the strict boundary decision.
- Added deterministic malformed-input classification and no raw exception text
  in public verifier errors.
- Added `Z_H(zeta) = 0` / domain-denominator rejection as `INVALID_PROOF`.
- Clarified that oversized prover wires are a trusted local API-contract gap,
  not a remote verifier-input forgery path.

One nuance retained:

- Canonical coordinate rejection remains in the ADR. The review correctly notes
  that scalar encodings are the higher-risk non-injective transcript path, but
  rejecting non-canonical coordinates is still the cleaner cryptographic
  boundary and avoids accepting multiple external encodings for the same point.

## ADR-0023 Changes

Accepted and incorporated:

- Made fail-closed concrete: `FullVerifier` must be renamed/wrapped, and
  `OnChainFeasibility.isFeasible` must not treat experimental PlonK as generally
  feasible without explicit opt-in.
- Added a prerequisite decision to pin one target proving system/transcript
  profile before implementing KZG verification.
- Clarified that the off-chain `PlonkBLS12381Verifier` is the executable
  reference only for the structured snarkjs/ZeroJ profile. A gnark-compatible
  on-chain target must instead be tested against gnark verifier behavior and
  gnark vectors.
- Removed the previous implication that gnark's 96-byte raw transcript bytes can
  be derived directly from a Plutus BLS group value. The updated ADR calls this
  a separate coordinate-serialization implementation/budget item.
- Added a preferred on-chain compressed-point transcript profile, where the
  script can check `compress(uncompress(point)) == point`, while still allowing a
  raw-byte compatibility path if explicitly implemented and budgeted.
- Added strict proof-point non-infinity rejection.
- Added explicit transcript preimage boundary/domain-separation requirements.
- Added CPU, memory, script-size, redeemer-size, estimator, MSM-builtin, and
  reference-script go/no-go gates.
- Promoted reference-script deployment from a mitigation to a release-gate
  consideration when inline script size is exceeded.
- Added tests for selected transcript-profile conformance, experimental
  feasibility opt-in, infinity rejection, and final budget/size measurements.

Also corrected:

- `docs/plonk-support.md` no longer says Plutus V3 lacks SHA-256.
- The gnark fixture disclaimer no longer says SHA-256 is unavailable in Plutus
  V3. It now says the vector is a gnark-style SHA-256 transcript prototype and
  not the final production on-chain transcript profile.

## Not Implemented In This Pass

The requested task was to update the ADRs and provide review feedback. I did not
change Java verifier behavior in this pass. The following remain implementation
items tracked by the ADRs:

- Add parser/importer bounds and typed malformed-input errors.
- Add BN254 point validation APIs.
- Enforce envelope/material/proof/VK binding.
- Validate VK domain scalars or enforce pinned-VK trust.
- Update `OnChainFeasibility.isFeasible` and tests for experimental opt-in.
- Rename or wrap `PlonkBLS12381FullVerifier` (`PlonkBLS12381TranscriptPrototype`
  is the Phase 0 implementation name).
- Choose and implement the on-chain PlonK transcript profile.
- Implement and measure the full on-chain KZG batch opening predicate.

## Feedback For Claude

The review was accepted in substance. The most important corrections were the
availability threat model for ADR-0022 and the transcript/serialization
feasibility correction for ADR-0023.

The only framing adjustment is that ADR-0023 now requires choosing a target
transcript profile before implementation rather than forcing an immediate choice
between snarkjs/ZeroJ and gnark in the ADR itself. That leaves room for the team
to pick a compressed-point on-chain profile, a gnark-compatible raw-byte profile
with explicit coordinate serialization, or to defer on-chain PlonK if budget and
interoperability do not close.
