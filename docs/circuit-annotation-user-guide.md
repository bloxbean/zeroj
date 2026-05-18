# Circuit Annotation User Guide

Annotation-based circuits are a Java-first authoring layer over the existing
`CircuitBuilder`, `CircuitSpec`, and `SignalBuilder` stack. They generate normal
ZeroJ circuits at compile time.

## Minimal Range Proof

```java
@ZKCircuit(name = "range-proof", version = 1)
public class RangeProof {
    @Secret @UInt(bits = 16)
    ZkUInt secret;

    @Public @UInt(bits = 16)
    ZkUInt lo;

    @Public @UInt(bits = 16)
    ZkUInt hi;

    @Prove
    ZkBool inRange() {
        return secret.gte(lo).and(secret.lte(hi));
    }
}
```

The annotation processor generates `RangeProofCircuit` with:

```java
var circuit = RangeProofCircuit.build();
var schema = RangeProofCircuit.schema();
var inputs = RangeProofCircuit.inputs()
        .secret(42)
        .lo(18)
        .hi(99);

circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381);
inputs.publicValues();
inputs.toPublicInputs();

var envelope = RangeProofCircuit.proofEnvelopeBuilder(
        circuit,
        ProofSystemId.GROTH16,
        CurveId.BLS12_381,
        proofJson.getBytes(StandardCharsets.UTF_8),
        inputs,
        new VerificationKeyRef.ById("range-proof-v1"))
    .build();
```

## Cardano Default Path

For circuits intended to be verified on Cardano, use BLS12-381 Groth16 as the
default target:

```text
@ZKCircuit
  -> generated *Circuit companion
  -> compileR1CS(CurveId.BLS12_381)
  -> Groth16 proof
  -> Julc / Plutus V3 BLS12-381 verifier
```

When a circuit needs a hash, prefer Poseidon with explicit BLS12-381
parameters:

```java
ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, left, right);
```

Do not use no-params Poseidon or MiMC as Cardano defaults. The no-params
Poseidon overload is retained for BN254 compatibility, and `ZkMiMC` delegates
to the BN254-only MiMC gadget. The full gadget and curve support matrix is in
[`docs/adr/circuit-annotation/cardano-gadget-support-matrix.md`](adr/circuit-annotation/cardano-gadget-support-matrix.md).

## Authoring Rules

- Use symbolic types in proof code: `ZkField`, `ZkBool`, `ZkUInt`,
  `ZkArray<T>`, `ZkBits`, and `ZkBytes`.
- Do not return Java `boolean` from `@Prove`; return `ZkBool` or use explicit
  assertion methods.
- Use `ZkBool.and(...)`, `or(...)`, `not(...)`, and `select(...)` instead of
  Java `&&`, `||`, `!`, or `if` over secret values.
- Use `@UInt(bits = N)` for every `ZkUInt` input. The constructor adds range
  constraints eagerly.
- Use `@FixedSize(...)` for every `ZkArray`, `ZkBits`, and `ZkBytes`.
- Put build-time circuit shape values in constructor parameters annotated with
  `@CircuitParam`.
- Keep existing DSL and `Signal*` APIs for low-level or unsupported cases.

## Field Style And Parameter Style

Field style is concise for simple circuits:

```java
@Secret @UInt(bits = 16) ZkUInt secret;

@Prove
ZkBool prove() {
    return secret.gte(lo).and(secret.lte(hi));
}
```

Parameter style keeps proof dependencies visible in the method signature:

```java
@Prove
ZkBool prove(@Secret @UInt(bits = 8) ZkUInt age,
             @Public @UInt(bits = 8) ZkUInt threshold) {
    return age.gte(threshold);
}
```

## Parameterized Circuits

Parameterized circuits keep Java's template-like circuit generation:

For Cardano-oriented Merkle circuits, bind the hash to BLS12-381 Poseidon
explicitly:

```java
@ZKCircuit(name = "merkle-bls12-381", nameTemplate = "merkle-bls-d{depth}")
public class MerkleMembership {
    public MerkleMembership(@CircuitParam("depth") int depth) {
    }

    @Prove
    ZkBool prove(ZkContext zk,
                 @Secret ZkField leaf,
                 @Public ZkField root,
                 @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
                 @Secret @FixedSize(param = "depth") ZkArray<ZkBool> pathBits) {
        return ZkMerkle.isMember(
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
    }
}
```

```java
var circuit = MerkleMembershipCircuit.build(32);
var inputs = MerkleMembershipCircuit.inputs(32);
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
```

Changing a circuit parameter changes the generated circuit identity and should
be treated as a different proving/verifying key lifecycle. For parameterized
circuits, the rendered `nameTemplate` is a readable prefix; generated names also
append a canonical parameter suffix to avoid collisions between different
parameter sets.

`ZkMerkle.HashType.MIMC` and `ZkMerkle.HashType.POSEIDON` remain useful for
BN254/off-chain compatibility. Today they are not the Cardano default path:
`MIMC` is BN254-only, and `POSEIDON` uses the no-params Poseidon overload. Use
the custom hash lambda shown above until a params-aware `ZkMerkle` convenience
API is added.

## Testing Pattern

Every annotated circuit should have tests for:

- generated schema ordering
- valid witness calculation
- at least one invalid witness
- public input extraction through `inputs.publicValues()`
- typed public input extraction through `inputs.toPublicInputs()`
- backend compilation for the curve and proof system you intend to use

The examples in
`zeroj-examples/src/test/java/com/bloxbean/cardano/zeroj/examples/annotation`
show this pattern without requiring external prover tooling.

## Proof Flow Integration

Generated companions expose the same metadata and public inputs needed by the
existing prover and verifier APIs:

```java
var circuit = AgeVerificationCircuit.build();
var inputs = AgeVerificationCircuit.inputs()
        .age(25)
        .threshold(18);

BigInteger[] witness = AgeVerificationCircuit.calculateWitness(
        circuit, inputs, CurveId.BLS12_381);
PublicInputs publicInputs = inputs.toPublicInputs();
CircuitId circuitId = AgeVerificationCircuit.circuitId();
ZkCircuitMetadata metadata = AgeVerificationCircuit.metadata();
```

`metadata.envelopeMetadata()` includes the circuit name, author-controlled
`@ZKCircuit(version = ...)`, and `@CircuitParam` values. `CircuitId` is the
generated circuit name; keep version in metadata for key registries and
allowlists that need name-plus-version policies. Generated parameterized circuit
names and metadata use a restricted canonical encoding: supported values are
converted to stable display strings, then stored as `length:value`.
Use `proofEnvelopeBuilder(...)` to create a
`ZkProofEnvelope.Builder` with the generated circuit ID and public-input order:

```java
var envelope = AgeVerificationCircuit.proofEnvelopeBuilder(
        circuit,
        ProofSystemId.GROTH16,
        CurveId.BLS12_381,
        proof.proveResponse().proofJson().getBytes(StandardCharsets.UTF_8),
        inputs,
        new VerificationKeyRef.ById("age-v1"))
    .build();
```

Exporter- or prover-specific code remains outside the generated companions.
For example, `AnnotatedAgeVerificationProofHelper` converts a generated witness
to `.wtns` bytes with `WitnessExporter` and passes generated witness maps to the
existing `GnarkProverHelper`.

## Bit And Byte Inputs

Use `ZkBits` for fixed-size bit vectors and `ZkBytes` for fixed-size byte
messages or serialized fields.

```java
@Prove
ZkBool prove(@Secret @FixedSize(32) ZkBytes message,
             @Public @FixedSize(32) ZkBytes expected) {
    return message.isEqual(expected);
}
```

Each `ZkBits` element is constrained as a boolean. Each `ZkBytes` element is
constrained to 8 bits. Generated input builders accept indexed values and
`List<BigInteger>` values.

## Advanced Gadget Adapters

`zeroj-circuit-lib` exposes symbolic adapters for the optional circuit-library
gadgets:

```java
var commitment = ZkPedersen.commit(zk, value, blinding, 64);
commitment.assertAffineEquals(zk, expectedU, expectedV);
```

`ZkPedersen.commitBits(...)` accepts LSB-first `ZkBits` scalar inputs.
Pedersen scalar inputs are constrained to canonical Jubjub subgroup scalars
`< l`; range-limit any application amount separately when it has a smaller
business-domain bound.
Jubjub-based adapters use BLS12-381 and preserve the lower-level gadget
contracts: arbitrary witness points are not implicitly curve- or
subgroup-checked. Bind public keys and signature points with
`ZkJubjubPoint.fromTrustedAffine(...)` only after off-circuit curve validity,
subgroup membership, and non-identity checks. `ZkEdDSAJubjub.verify(...)`
also rejects the identity public key in-circuit.

`ZkEdDSAJubjub.verify(...)` also needs two reduction witnesses,
`kModL` and `kQuotient`, so the circuit can prove the Poseidon challenge was
reduced modulo the Jubjub subgroup order. Compute those host values with
`ZkEdDSAJubjub.witnessComputeKReduction(signature.r(), publicKey, message)` and
bind them as secret `ZkUInt` inputs, using 252 bits for `kModL` and 4 bits for
`kQuotient`.

## Current Limits

- Nested `@ZKCircuit` classes are not supported.
- Nested annotated array inputs such as `ZkArray<ZkArray<T>>` are not
  supported; flatten to fixed-size parallel arrays.
- Private `@Prove` methods are not supported.
- Private field-style symbolic inputs are not supported; use package-private
  fields or parameter-style inputs.
- Static `@Prove` methods must use parameter-style inputs.
- `@CircuitParam` belongs on constructor parameters, not proof method
  parameters.
- `ZkPoseidon` exposes two-input hashes. Use repeated folding or the
  lower-level `PoseidonN`/Signal APIs for variable-arity hashing until
  `ZkPoseidonN` is added. For Cardano, pass
  `PoseidonParamsBLS12_381T3.INSTANCE` explicitly.
- `ZkMiMC` is BN254-only because the underlying MiMC gadget is BN254-only.
  Treat MiMC-based annotated circuits as BN254/off-chain unless a separate
  BLS12-381 MiMC variant is added.
- `ZkMerkle.HashType.MIMC` and the no-params `HashType.POSEIDON` path are not
  Cardano defaults today. Use a custom BLS12-381 Poseidon hash lambda for
  Cardano Merkle circuits.
- `ZkBits` and `ZkBytes` store one constrained field element per bit or byte;
  packed byte encodings are deferred.
