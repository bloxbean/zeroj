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

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-lib'
}
```
