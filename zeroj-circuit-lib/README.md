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
| Annotation helpers | `ZkPoseidon`, `ZkPoseidonN`, `ZkMiMC`, `ZkMerkle`, `ZkMpf`, `ZkMpfProof`, `ZkJubjubPoint`, `ZkPedersen`, `ZkEdDSAJubjub` |
| Jubjub primitives | `JubjubCurve`, `PedersenCommitment`, `EdDSAJubjub`, in-circuit variants |
| Poseidon parameters | `PoseidonParams*`, `PoseidonHash`, Grain LFSR generation helpers |

## Gadget Status

This table is intentionally conservative. "Cardano-ready" means the gadget can
be used in a circuit compiled over `CurveId.BLS12_381`, proved with Groth16, and
verified with ZeroJ's reusable Plutus V3 BLS12-381 verifier. The gadget logic
itself runs off-chain inside the circuit/prover flow; Cardano only sees the
final proof, verification key data, and public inputs.

| Gadget | DSL APIs | Symbolic APIs | Field / curve status | Cardano status | Notes |
|--------|----------|---------------|----------------------|----------------|-------|
| Field arithmetic | `Signal`, `SignalBuilder`, `CircuitAPI` | `ZkField` | Generic over supported circuit fields | Ready on BLS12-381 Groth16 | Core DSL feature, not a separate gadget. |
| Boolean values | DSL equality and constraints | `ZkBool` | Generic | Ready on BLS12-381 Groth16 | `ZkBool` constrains values to 0/1 and prevents Java `boolean` control-flow mistakes. |
| Unsigned integers | `Comparators`, `SignalComparators`, `Binary`, `SignalBinary` | `ZkUInt` | Generic, `ZkUInt.MAX_BITS = 253`; comparisons require width `< 253` | Ready on BLS12-381 Groth16 | `ZkUInt` adds range constraints on construction. |
| Fixed arrays and matrices | Java arrays passed to gadgets | `ZkArray<T>`, including rectangular `ZkArray<ZkArray<T>>` | Generic | Ready on BLS12-381 Groth16 | Deeper nesting is intentionally out of scope until a real circuit needs it. |
| Bit and byte vectors | `Binary`, `SignalBinary` | `ZkBits`, `ZkBytes` | Generic | Ready for binding/equality on BLS12-381 Groth16 | Symbolic bitwise operations are still limited; use `SignalBinary` or add wrappers when needed. |
| Binary decomposition | `Binary`, `SignalBinary`, `AliasCheck` | Partly via `ZkUInt`, `ZkBits`, `ZkBool` | Generic | Ready on BLS12-381 Groth16 | `AliasCheck` remains a lower-level helper for canonical field representation checks. |
| Comparators and ranges | `Comparators`, `SignalComparators` | Mostly through `ZkUInt` | Generic | Ready on BLS12-381 Groth16 | Optional symbolic `min`/`max` helpers can be added later if needed. |
| Selection / mux | `Mux` | `ZkBool.select(...)`, `ZkJubjubPoint.select(...)` | Generic for scalar values | Ready on BLS12-381 Groth16 | Dynamic array access remains a lower-level `Mux.arrayAccess(...)` pattern. |
| MiMC | `MiMC`, `SignalMiMC` | `ZkMiMC` | BN254 only | Not Cardano-ready | `MiMC` and `SignalMiMC` call `requireField(FieldConfig.BN254)`. Use Poseidon for Cardano circuits. |
| MiMC sponge | `MiMCSponge` | No direct `ZkMiMCSponge` | BN254 only, because it uses MiMC | Not Cardano-ready | Useful for BN254/off-chain legacy circuits only. |
| Poseidon T3 | `Poseidon`, `SignalPoseidon` | `ZkPoseidon` | BN254 default; BLS12-381 with explicit params | Ready when using `PoseidonParamsBLS12_381T3.INSTANCE` | No-params overloads are BN254 for backward compatibility. |
| Folded Poseidon N | `PoseidonN` | `ZkPoseidonN` | BN254 default in DSL overloads; symbolic API requires explicit params | Ready when using `PoseidonParamsBLS12_381T3.INSTANCE` | Folded two-input Poseidon, not a separate variable-width Poseidon permutation. |
| Merkle membership | `Merkle`, `SignalMerkle` | `ZkMerkle` | Hash-dependent | Ready with params-aware BLS12-381 Poseidon helpers | Use `ZkMerkle.*Poseidon(..., PoseidonParamsBLS12_381T3.INSTANCE, ...)` for Cardano. `HashType.MIMC` and default `HashType.POSEIDON` are BN254-oriented convenience paths. |
| Poseidon MPF | No `Signal*` facade; host witness helpers live in `zeroj-mpf-poseidon` | `ZkMpf`, `ZkMpfProof` | BLS12-381 Poseidon only | Technically usable through gnark Groth16, but experimental/heavy | Ready at witness/circuit level. Current MPF circuit is large, so MPF-specific Yaci demo and pure Java proving are deferred until optimization. Not compatible with native Aiken/Blake2b MPF roots. |
| Jubjub point arithmetic | `InCircuitJubjub`, `JubjubPoint` | `ZkJubjubPoint` | BLS12-381 scalar field only | Ready on BLS12-381 Groth16 | `fromTrustedAffine(...)` assumes curve/subgroup/non-identity checks were done off-circuit when required by the protocol. |
| Pedersen commitment | `InCircuitPedersen`, `PedersenCommitment` | `ZkPedersen` | BLS12-381 scalar field only | Ready on BLS12-381 Groth16 | Symbolic scalar inputs are capped at `ZkPedersen.MAX_SCALAR_BITS = 252`. |
| EdDSA-Jubjub | `InCircuitEdDSAJubjub`, `EdDSAJubjub` | `ZkEdDSAJubjub` | BLS12-381 scalar field only | Ready on BLS12-381 Groth16 | Identity public keys are rejected in-circuit; affine inputs are still trusted for curve/subgroup membership unless separately checked. |
| Poseidon parameters and off-circuit hashing | `PoseidonParams*`, `PoseidonHash`, `PoseidonGrainLFSR` | Used by `ZkPoseidon*`, `ZkMerkle`, `ZkMpf` | BN254 T3, BLS12-381 T3, BLS12-381 T5 presets exist | Ready when matched to the circuit field and gadget shape | `PoseidonHash` is host-side hashing for expected roots/test vectors, not a circuit constraint by itself. The in-circuit `Poseidon` gadget currently supports T3/alpha-5 only. |

For the broader Cardano/annotation matrix, see
[`docs/adr/circuit-annotation/cardano-gadget-support-matrix.md`](../docs/adr/circuit-annotation/cardano-gadget-support-matrix.md).

## Why It Is Useful

- Avoids reimplementing common ZK gadgets in every application circuit.
- Keeps hash and Merkle circuits consistent across examples and production code.
- Provides field-aware Poseidon parameters for BN254 and BLS12-381 use cases.
- Lets higher-level privacy patterns build on reviewed, reusable components.

## Usage Shape

ZeroJ supports three circuit authoring styles. Prefer them in this order unless
you have a specific reason to drop lower in the stack.

### 1. Symbolic Annotations

Use this for new application circuits. The annotation processor generates the
`CircuitBuilder`, schema, metadata, and input helpers, while the body stays
close to ordinary Java domain code.

```java
@ZKCircuit(name = "sealed-bid", version = 1)
public class SealedBid {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField bidCommitment,
            @Public @UInt(bits = 64) ZkUInt reservePrice,
            @Secret @UInt(bits = 64) ZkUInt bidAmount,
            @Secret ZkField salt) {
        var commitmentMatches = ZkPoseidon.hash(
                        zk,
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        bidAmount.asField(),
                        salt)
                .isEqual(bidCommitment);

        return commitmentMatches.and(bidAmount.gte(reservePrice));
    }
}

var circuit = SealedBidCircuit.build();
```

### 2. CircuitSpec

Use `CircuitSpec` when you want an explicit reusable circuit class without the
annotation processor, or when working close to the `SignalBuilder` API is useful.

```java
public class SealedBidCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal bidAmount = c.privateInput("bidAmount");
        Signal salt = c.privateInput("salt");
        Signal bidCommitment = c.publicOutput("bidCommitment");
        Signal reservePrice = c.publicInput("reservePrice");

        c.assertEqual(
                SignalPoseidon.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, bidAmount, salt),
                bidCommitment);
        c.assertEqual(
                SignalComparators.greaterOrEqual(c, bidAmount, reservePrice, 64),
                c.constant(1));
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("sealed-bid")
                .publicVar("bidCommitment")
                .publicVar("reservePrice")
                .secretVar("bidAmount")
                .secretVar("salt")
                .defineSignals(new SealedBidCircuit());
    }
}
```

### 3. Inline Circuit DSL

Use inline `CircuitBuilder` definitions for small tests, examples, and quick
experiments.

```java
var circuit = CircuitBuilder.create("sealed-bid")
        .publicVar("bidCommitment")
        .publicVar("reservePrice")
        .secretVar("bidAmount")
        .secretVar("salt")
        .defineSignals(c -> {
            var bidAmount = c.privateInput("bidAmount");
            var salt = c.privateInput("salt");
            var bidCommitment = c.publicOutput("bidCommitment");
            var reservePrice = c.publicInput("reservePrice");

            c.assertEqual(
                    SignalPoseidon.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, bidAmount, salt),
                    bidCommitment);
            c.assertEqual(
                    SignalComparators.greaterOrEqual(c, bidAmount, reservePrice, 64),
                    c.constant(1));
        });
```

All three styles use the same underlying circuit library gadgets. Symbolic
annotation-based circuits use adapters from
`com.bloxbean.cardano.zeroj.circuit.lib.zk`; `CircuitSpec` and inline DSL code
usually use the `Signal*` helpers directly. Cardano/BLS12-381 examples should
also use `PoseidonParamsBLS12_381T3` from
`com.bloxbean.cardano.zeroj.circuit.lib.poseidon`.

Common symbolic adapter calls:

```java
var hash = ZkPoseidon.hash(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        left,
        right);
var commitment = ZkPoseidonN.hash(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        owner,
        assetId,
        nonce);
var root = ZkMerkle.computeRootPoseidon(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        leaf,
        siblings,
        pathBits);
var pedersen = ZkPedersen.commit(zk, value, blinding, 64);
```

These adapters delegate to the existing `Signal*` and in-circuit gadgets and
validate that their inputs belong to the supplied `ZkContext`.

Curve and parameter guidance:

- **MiMC** — `ZkMiMC` is guarded as BN254-only. Use Poseidon when targeting BLS12-381.
- **Poseidon** — `ZkPoseidonN` requires explicit Poseidon params and is the
  symbolic path for folded multi-input commitments. The no-params Poseidon
  helpers are BN254-oriented for backward compatibility.
- **Merkle** — `ZkMerkle.HashType.MIMC` and the no-params `HashType.POSEIDON`
  paths are BN254/off-chain conveniences. For Cardano Merkle circuits, use
  `ZkMerkle.computeRootPoseidon`, `isMemberPoseidon`, or `verifyPoseidon` with
  explicit BLS12-381 Poseidon params.
- **Jubjub / Pedersen / EdDSA-Jubjub** — BLS12-381-only adapters. They inherit
  the curve/subgroup-check contracts documented on the underlying in-circuit
  gadgets. Use `ZkJubjubPoint.fromTrustedAffine(...)` only for points validated
  off-circuit for curve membership, subgroup membership, and non-identity where
  the protocol requires it. `ZkEdDSAJubjub.verify(...)` rejects identity public
  keys in-circuit.

The Cardano-oriented support matrix is maintained in
[`docs/adr/circuit-annotation/cardano-gadget-support-matrix.md`](../docs/adr/circuit-annotation/cardano-gadget-support-matrix.md).

The status table above was checked against the current implementation in
`src/main/java`, especially `MiMC`, `Poseidon`, `PoseidonN`, `ZkMerkle`,
`ZkMpf`, `ZkPedersen`, `ZkEdDSAJubjub`, and the adapter coverage in
`src/test/java/com/bloxbean/cardano/zeroj/circuit/lib/zk/ZkGadgetAdaptersTest.java`.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-lib'
}
```
