# ADR: Params-Aware ZkMerkle Poseidon Helpers

## Status

Implemented.

## Date

2026-05-18

## Context

Annotated Cardano-oriented Merkle circuits previously worked through
`ZkMerkle`'s custom hash lambda:

```java
ZkMerkle.isMember(
        zk,
        leaf,
        root,
        siblings,
        pathBits,
        (ctx, left, right) -> ZkPoseidon.hash(
                ctx,
                PoseidonParamsBLS12_381T3.INSTANCE,
                left,
                right));
```

This is functionally correct, but it is too much ceremony for a default
Cardano path. Developers should not need to drop into a custom lambda for the
common "Merkle path with BLS12-381 Poseidon" case.

The existing `ZkMerkle.HashType.POSEIDON` enum is not enough because it uses the
no-params `ZkPoseidon` path, which is BN254-oriented for backward
compatibility. Adding a named enum such as `POSEIDON_BLS12_381_T3` would solve
one preset, but it would not scale cleanly if ZeroJ adds more Poseidon
parameter sets.

## Decision

ZeroJ now provides params-aware symbolic Merkle helpers:

```java
ZkField root = ZkMerkle.computeRootPoseidon(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        leaf,
        siblings,
        pathBits);

ZkBool ok = ZkMerkle.isMemberPoseidon(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        leaf,
        root,
        siblings,
        pathBits);

ZkMerkle.verifyPoseidon(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        leaf,
        root,
        siblings,
        pathBits);
```

These helpers:

- live on the existing `ZkMerkle` class
- accept explicit `PoseidonParams`
- delegate to the existing custom-hash implementation
- call `ZkPoseidon.hash(zk, params, left, right)` for each Merkle level
- inherit Poseidon field guards from the underlying `Poseidon` gadget
- record the Poseidon params field before path processing, so zero-depth paths
  still reject mismatched compile or witness curves
- preserve the existing path-bit convention:
  - `0`: current node is the left child, sibling is right
  - `1`: sibling is left, current node is right

Do not change the existing `HashType.POSEIDON` behavior in this slice. It
remains a BN254/off-chain convenience for backward compatibility. Cardano-facing
docs and examples should use the params-aware helper.

## Scope

In scope:

- `computeRootPoseidon(...)`
- `isMemberPoseidon(...)`
- `verifyPoseidon(...)`
- `verifyProofPoseidon(...)` alias for consistency with existing naming
- differential tests against the existing custom lambda path
- BLS12-381 witness and compile tests
- BN254 compile rejection when BLS12-381 params are used
- an annotated BLS12-381 Poseidon Merkle membership example
- docs/support-matrix updates

Out of scope:

- changing `HashType.POSEIDON`
- deprecating `HashType.POSEIDON`
- true arity-specific Poseidon Merkle hash variants
- generic/generated Cardano Groth16 verifier work

## API Shape

```java
public static ZkField computeRootPoseidon(
        ZkContext zk,
        PoseidonParams params,
        ZkField leaf,
        ZkArray<ZkField> siblings,
        ZkArray<ZkBool> pathBits);

public static void verifyPoseidon(
        ZkContext zk,
        PoseidonParams params,
        ZkField leaf,
        ZkField root,
        ZkArray<ZkField> siblings,
        ZkArray<ZkBool> pathBits);

public static void verifyProofPoseidon(
        ZkContext zk,
        PoseidonParams params,
        ZkField leaf,
        ZkField root,
        ZkArray<ZkField> siblings,
        ZkArray<ZkBool> pathBits);

public static ZkBool isMemberPoseidon(
        ZkContext zk,
        PoseidonParams params,
        ZkField leaf,
        ZkField root,
        ZkArray<ZkField> siblings,
        ZkArray<ZkBool> pathBits);
```

The params argument is placed immediately after `ZkContext`, matching
`ZkPoseidon.hash(zk, params, left, right)` and `ZkPoseidonN.hash(zk, params,
inputs...)`.

## Testing

Implemented coverage:

- compare the params-aware helper path to the existing custom lambda path
- verify BLS12-381 witnesses against `PoseidonHash.hash(...)`
- reject an invalid root
- reject compiling BLS12-381 params under `CurveId.BN254`
- reject null params
- exercise a generated annotated circuit using the helper

## Consequences

Positive:

- Cardano-ready annotated Merkle circuits no longer need a custom lambda
- the API remains explicit about Poseidon params and target field
- existing `ZkMerkle` behavior remains backward compatible

Negative:

- `HashType.POSEIDON` remains ambiguous for new users until docs consistently
  steer Cardano circuits to the params-aware helper
- additional Poseidon parameter presets still need explicit caller selection
