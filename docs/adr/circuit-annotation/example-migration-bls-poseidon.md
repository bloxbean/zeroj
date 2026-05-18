# ADR: Example Migration to BLS12-381 Poseidon

## Status

Implemented.

## Date

2026-05-18

## Context

The Cardano gadget support matrix makes BLS12-381 Groth16 the default on-chain
path. It also makes one important hash distinction:

- MiMC in the current circuit library is BN254-only.
- Poseidon supports BLS12-381 when callers pass explicit BLS12-381 params.

Some reference examples still looked Cardano-facing while using MiMC or a
BN254/default hash path. That is confusing because those examples either fail
compile-time field checks on `CurveId.BLS12_381` or suggest a hash choice that is
not the recommended Cardano path.

## Decision

Migrate Cardano-facing examples to explicit BLS12-381 Poseidon:

- sealed-bid auction
- anonymous voting
- hash chain template
- multi-input commitment template
- Merkle membership template when used as a Cardano example
- annotated sealed bid
- annotated anonymous voting
- `zeroj-usecases` annotated private voting
- `zeroj-usecases` annotated proof of reserves
- `zeroj-usecases` annotated compliance credential

Keep MiMC examples only when they are explicitly BN254/off-chain:

- `AnnotatedHashCommitment` remains the small MiMC adapter example.
- `AnnotatedMerkleMembership` with `HashType.MIMC` remains the parameterized
  BN254/off-chain Merkle example.
- `NWayMerkleCircuit.HashType.MIMC` remains available for BN254/off-chain
  template demonstrations.

## Design

Cardano-facing DSL examples call:

```java
SignalPoseidon.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, left, right)
```

Cardano-facing annotated examples call:

```java
ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, left, right)
```

Variable-arity commitments use the already-shipped explicit params API:

```java
ZkPoseidonN.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, a, b, c)
```

Off-circuit expected values are computed with:

```java
PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, left, right)
PoseidonHash.hashN(PoseidonParamsBLS12_381T3.INSTANCE, values...)
```

This keeps the compile field visible at every hash call site. The no-params
Poseidon overload remains available for backward-compatible BN254 usage, but it
is not used by Cardano-facing examples.

## Sealed Bid Shape

The sealed-bid example now proves the reserve condition inside the circuit
instead of exposing a public `isAboveReserve` flag.

Public inputs:

```text
[bidCommitment, reservePrice]
```

Private inputs:

```text
[bidAmount, salt]
```

Constraints:

```text
bidCommitment == PoseidonBLS12_381(bidAmount, salt)
bidAmount >= reservePrice
```

This matches the on-chain auction validator flow where the datum contains only
the proof public inputs and the validator independently binds the reserve price
parameter to the public reserve value.

## Testing

Tests must prove or assert:

- Cardano-facing examples compile and calculate witnesses on `CurveId.BLS12_381`.
- Cardano-facing examples reject `CurveId.BN254` because their Poseidon params
  require BLS12-381.
- MiMC examples compile on `CurveId.BN254` and are labeled as BN254/off-chain.
- MiMC examples reject `CurveId.BLS12_381` when the in-circuit gadget enforces
  `FieldConfig.BN254`.
- Negative witnesses still fail: wrong commitments, invalid vote bits, and
  sealed bids below reserve.

## Consequences

Positive:

- New users see BLS12-381 Poseidon in the examples that are intended for
  Cardano.
- Example code aligns with the generic Cardano Groth16 verifier and the
  on-chain sealed-bid fixture.
- BN254 MiMC remains usable and tested without being presented as a Cardano
  default.
- The standalone annotated usecases now compile against the Cardano-oriented
  BLS12-381 path rather than serving only as BN254/off-chain symbolic examples.

Negative:

- Existing example witness values and public-input counts change for sealed
  bid.
- BN254 compilation is intentionally rejected for examples that now hard-code
  BLS12-381 Poseidon params.
