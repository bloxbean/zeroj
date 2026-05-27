# Phase 8: Advanced Symbolic Gadget Adapters

## Status

Approved and completed for the Phase 8 commit.

## Goal

Expose the existing Jubjub, Pedersen, and EdDSA in-circuit gadgets through the
annotation-friendly symbolic API so annotated circuits can use realistic
credential and commitment primitives without dropping to `Variable` plumbing.

## Implemented Changes

- Added `ZkJubjubPoint` as an extended-coordinate symbolic point wrapper.
- Added `ZkPedersen` for symbolic Pedersen commitments over `ZkUInt` and
  `ZkBits` scalar inputs.
- Added `ZkEdDSAJubjub` for symbolic EdDSA-Jubjub signature verification.
- Kept these adapters in `zeroj-circuit-lib`, not the annotation API module,
  because they depend on optional circuit-library gadgets.
- Added differential and negative tests against existing off-circuit and
  in-circuit Jubjub/Pedersen/EdDSA behavior.
- Added an annotated Pedersen commitment example using the generated companion
  flow.

## Exit Criteria

- Pedersen commitments can be computed and verified from symbolic inputs.
- EdDSA-Jubjub verification can be called from `Zk*` proof code.
- Jubjub point equality/addition helpers are usable without raw `Variable`
  references.
- BLS12-381 field guards remain intact for Jubjub-based gadgets.
- Tests cover valid and invalid openings/signatures and adapter guardrails.

## Verification

- `./gradlew :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest`
  passed.
- `./gradlew :zeroj-examples:test --tests com.bloxbean.cardano.zeroj.examples.annotation.AnnotatedCircuitExamplesTest`
  passed.
- `./gradlew :zeroj-circuit-annotation-api:test :zeroj-circuit-annotation-processor:test :zeroj-circuit-dsl:test`
  passed.

Exit criteria results:

- Pedersen commitments are computed from symbolic `ZkUInt` and LSB-first
  `ZkBits` inputs.
- EdDSA-Jubjub verification is callable from `Zk*` proof code.
- Jubjub point constants, affine binding, addition, equality, and affine output
  assertions are available without raw `Variable` references.
- BLS12-381 field guards are inherited from existing Jubjub-based gadgets and
  covered by negative tests.
- Tests cover valid and invalid Pedersen openings, LSB-first bit-vector inputs,
  canonical scalar checks, standalone point field guards, valid and tampered
  EdDSA signatures, identity-key rejection, scalar-width guardrails, and the
  annotated Pedersen example.

## Review Results

Approved after three independent review tracks:

- API/design review: approved after the point wrapper exposed only trusted
  affine construction, documented the trust boundary, and kept Jubjub/Pedersen
  helpers layered in `zeroj-circuit-lib`.
- Correctness/security review: approved after the adapters added BLS12-381
  field guards, canonical Pedersen scalar checks, no public extended-coordinate
  constructor, and in-circuit EdDSA public-key identity rejection.
- Tests/docs/ergonomics review: approved after adding LSB-first `ZkBits`
  Pedersen coverage, standalone point guard tests, the annotated Pedersen
  example, and user-guide/README wording for the advanced adapters.

## Commit

Pending final phase commit.
