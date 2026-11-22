# ADR-0049: Groth16 G2 JSON provider profile

- Status: **Proposed — awaiting maintainer choice; not accepted for implementation**
- Date: 2026-09-26
- Issue: #51
- Risk: **R2**, untrusted point decoding and provider compatibility
- Governing decisions: ADR-0025 validation boundaries, ADR-0045 infinity policy,
  ADR-0047 snarkjs affine export profile

## Problem and evidence

`G2Point.fromProjective` and the pure-Java Groth16 verifier interpret a nonzero
Fp2 Z as homogeneous coordinates: `x = X/Z`, `y = Y/Z`. The blst verifier and
`SnarkjsToCardano` converter reject G2 `Z != [1,0]`. Ordinary snarkjs JSON exports
use affine coordinates with `Z = [1,0]` and interoperate today.

A pinned-reference check reveals why normalization cannot be selected casually:
ffjavascript's generic EC implementation uses Jacobian normalization
`x = X/Z^2`, `y = Y/Z^3`. ZeroJ's current homogeneous convention is therefore not
interchangeable with reference internal projective coordinates. This is evidence
of a convention ambiguity outside ordinary affine exports, not a demonstrated
proof-equation bypass. Merely changing Z while keeping X/Y fixed does not preserve
the original point under either convention.

The existing G1 JSON helpers also use homogeneous normalization in both providers.
This proposal must not silently change that shared primitive API while resolving
G2 provider parity. If a universal affine-only G1/G2 profile is desired, its G1
compatibility break needs an explicit extension of the decision and tests.

## Threat model and trust assumptions

Proof JSON, VK JSON, public inputs, Fp2 components and projective markers are
untrusted. An application chooses a trusted VK/circuit binding; a valid proof is
not application authorization or replay protection. All values decoded here are
public; this change must not introduce a secret-operation path or make timing
claims. Native provider decoding is not a substitute for checking canonical field
ranges and the selected JSON shape before conversion.

## Proposed choice: affine-only G2 JSON (recommended)

Both off-chain Groth16 verifiers require exactly three Fp2 pairs, exactly two
components per pair, canonical Fp integers, and `Z = [1,0]`. Preserve the existing
explicit infinity rejection for `Z = [0,0]`. Reject every other Z before point
conversion. Then enforce on-curve, prime-order subgroup and non-infinity rules
for proof B and VK beta/gamma/delta under ADR-0045.

The transport codec can still parse shapes according to its current contract;
cryptographic profile enforcement remains at verifier/conversion boundaries.
This is a canonical **G2 coordinate profile**, not a claim that arbitrary JSON
text has only one whitespace, property-order or decimal representation.

Compatibility: ordinary snarkjs output and current blst acceptance remain intact.
Pure Java intentionally stops accepting non-affine G2 JSON. Document that change
and require callers with custom projective inputs to normalize explicitly using
their known coordinate convention before serialization. No proof, pairing,
compressed on-chain wire format, trusted setup or transcript change is required.

## Alternative: explicitly preserve ZeroJ homogeneous compatibility

If the maintainer chooses backward compatibility for existing Java callers, accept
nonzero homogeneous Z consistently in both off-chain providers and the JSON-to-
Cardano converter. Validate all six Fp components before inversion, normalize
`X/Z,Y/Z` once, and apply the same curve/subgroup/infinity checks afterward.
Document this as a ZeroJ extension, not arbitrary snarkjs/ffjavascript projective
interoperability. Normal exporters must continue emitting affine coordinates.

This accepts multiple coordinate representations and therefore needs the explicit
compatibility rationale required by #51. Raw VK JSON hashes continue to identify
bytes, not an equivalence class of projective encodings; normalization must not
silently change what the application authenticated.

Adopting Jacobian normalization in place of ZeroJ's existing homogeneous behavior
is a separate breaking alternative. It is not a safe implicit interpretation of
“align providers” and is not recommended within this bounded milestone.

## Exact invariants for either choice

1. Both verifiers agree on acceptance/rejection at every G2 proof/VK position.
2. Reject negative, p-or-larger, missing, excess and malformed Fp components before
   any modular reduction or fixed-width serialization.
3. Reject off-curve, non-subgroup and forbidden infinity points after decoding.
4. Public-input ordering, VK/circuit binding and proof equations do not change.
5. Binary zkey imports remain affine and retain their independent validation.
6. Compressed on-chain proof/VK formats remain unchanged. Check the JSON converter
   against the chosen G2 profile, including range checks before writing 48 bytes.
7. Shared general-purpose G1/G2 arithmetic APIs are not silently redefined.

## Pinned references

- [snarkjs v0.7.6 groth16_prove.js](https://github.com/iden3/snarkjs/blob/v0.7.6/src/groth16_prove.js), affine export before JSON serialization.
- [snarkjs v0.7.6 zkey_export_verificationkey.js](https://github.com/iden3/snarkjs/blob/v0.7.6/src/zkey_export_verificationkey.js), VK export.
- [ffjavascript v0.3.1 ec.js](https://github.com/iden3/ffjavascript/blob/v0.3.1/src/ec.js), `affine` uses inverse-Z squared/cubed.
- [ffjavascript v0.3.1 wasm_curve.js](https://github.com/iden3/ffjavascript/blob/v0.3.1/src/wasm_curve.js), object/affine representation boundary.

## Implementation milestones after acceptance

1. Record the maintainer's selected policy and its compatibility rationale here.
2. Add failing full-envelope tests for valid non-affine transformations in every
   G2 location; transform X and Y consistently with the tested convention.
3. Implement the bounded provider and JSON-converter change under the selected
   policy. Avoid changes to pairings, shared scalar multiplication or transcripts.
4. Add zero-Z, noncanonical field, malformed-pair, off-curve, non-subgroup and
   infinity negatives; retain affine fixture controls and native error parity.
5. Run verifier/codec/crypto/on-chain conversion tests and pinned snarkjs 0.7.6
   interoperability. Inspect importer and compressed on-chain behavior for drift.
6. Review the diff, document the compatibility change and retain audit gates.

## Production and review gates

The status must be accepted before implementing either behavior. AGENTS.md says:
“R2/R3 changes require an ADR or equivalent accepted security design before
implementation” and “If references disagree or are ambiguous, stop and escalate
the design question.” This PR supplies the concrete decision for that review;
it does not close #51. The remaining ADR-0026 audit, ceremony, side-channel and
application-authorization gates still apply.
