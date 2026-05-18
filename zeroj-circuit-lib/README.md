# zeroj-circuit-lib

Reusable ZK circuit components for the ZeroJ circuit DSL.

This module contains standard gadgets and helper APIs that sit on top of
`zeroj-circuit-dsl`. Use it when building application circuits that need hashes,
Merkle membership, range/comparison checks, binary decomposition, multiplexing,
or Jubjub-style primitives.

## What It Provides

| Area | Key Types |
|------|-----------|
| Hashes | `Poseidon`, `PoseidonN`, `MiMC`, `MiMCSponge` |
| Merkle proofs | `Merkle`, `SignalMerkle` |
| Comparisons | `Comparators`, `SignalComparators` |
| Binary gadgets | `Binary`, `SignalBinary`, `AliasCheck` |
| Selection | `Mux` |
| Signal helpers | `SignalPoseidon`, `SignalMiMC` |
| Annotation helpers | `ZkPoseidon`, `ZkMiMC`, `ZkMerkle`, `ZkJubjubPoint`, `ZkPedersen`, `ZkEdDSAJubjub` |
| Jubjub primitives | `JubjubCurve`, `PedersenCommitment`, `EdDSAJubjub`, in-circuit variants |
| Poseidon parameters | `PoseidonParams*`, `PoseidonHash`, Grain LFSR generation helpers |

## Why It Is Useful

- Avoids reimplementing common ZK gadgets in every application circuit.
- Keeps hash and Merkle circuits consistent across examples and production code.
- Provides field-aware Poseidon parameters for BN254 and BLS12-381 use cases.
- Lets higher-level privacy patterns build on reviewed, reusable components.

## Usage Shape

The library is designed to be called from a `CircuitBuilder` definition:

```java
var circuit = CircuitBuilder.create("membership")
        .publicVar("root")
        .secretVar("leaf")
        .defineSignals(c -> {
            var leaf = c.privateInput("leaf");
            var root = c.publicInput("root");
            var commitment = SignalPoseidon.hash(c, leaf, c.constant(BigInteger.ONE));
            c.assertEqual(commitment, root);
        });
```

For larger circuits, prefer the `Signal*` helper classes with `SignalBuilder`
and reusable `CircuitSpec` components.

Annotation-based circuits can use symbolic adapters from
`com.bloxbean.cardano.zeroj.circuit.lib.zk`. Cardano/BLS12-381 hash examples
also use `PoseidonParamsBLS12_381T3` from
`com.bloxbean.cardano.zeroj.circuit.lib.poseidon`:

```java
var hash = ZkPoseidon.hash(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        left,
        right);
var root = ZkMerkle.computeRoot(
        zk,
        leaf,
        siblings,
        pathBits,
        (ctx, l, r) -> ZkPoseidon.hash(ctx, PoseidonParamsBLS12_381T3.INSTANCE, l, r));
var commitment = ZkPedersen.commit(zk, value, blinding, 64);
```

These adapters delegate to the existing `Signal*` and in-circuit gadgets and
validate that their inputs belong to the supplied `ZkContext`. `ZkMiMC` is
guarded as BN254-only; use explicit Poseidon parameters when targeting
BLS12-381. The no-params Poseidon helpers are BN254-oriented for backward
compatibility, and `ZkMerkle.HashType.MIMC` / no-params `HashType.POSEIDON`
should be treated as BN254/off-chain conveniences until params-aware Merkle
helpers are added. Jubjub, Pedersen, and EdDSA-Jubjub adapters are BLS12-381-only and
inherit the curve/subgroup-check contracts documented on the underlying
in-circuit gadgets. Use `ZkJubjubPoint.fromTrustedAffine(...)` only for points
validated off-circuit for curve membership, subgroup membership, and non-identity
where the protocol requires it. `ZkEdDSAJubjub.verify(...)` rejects identity
public keys in-circuit.

The Cardano-oriented support matrix is maintained in
[`docs/adr/circuit-annotation/cardano-gadget-support-matrix.md`](../docs/adr/circuit-annotation/cardano-gadget-support-matrix.md).

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-lib'
}
```
