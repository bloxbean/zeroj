# zeroj-circuit-annotation-api

Public API for annotation-based ZeroJ circuit authoring.

Current Phase 9 status: this module exposes the foundational annotations,
symbolic `Zk*` types, runtime schema/input helpers, and proof-envelope metadata
helpers used by generated companions.

This module contains:

- circuit annotations such as `@ZKCircuit`, `@Prove`, `@Public`, `@Secret`,
  `@CircuitParam`, `@UInt`, `@FieldElement`, `@FixedSize`, and `@Order`
- symbolic circuit value types: `ZkField`, `ZkBool`, `ZkUInt`, `ZkArray`,
  `ZkBits`, and `ZkBytes`
- generated-circuit metadata and witness helpers: `ZkCircuitSchema`,
  `ZkInputMap`, and `ZkCircuitMetadata`

The API is intentionally layered on top of `zeroj-circuit-dsl`. It does not
replace `CircuitSpec`, `SignalBuilder`, or the existing circuit library.

Manual symbolic circuits can be written directly against `SignalBuilder`:

```java
var circuit = CircuitBuilder.create("range")
        .publicVar("threshold")
        .secretVar("age")
        .defineSignals(c -> {
            var age = ZkUInt.secret(c, "age", 8);
            var threshold = ZkUInt.publicInput(c, "threshold", 8);
            age.gte(threshold).assertTrue();
        });
```

Generated companions use the schema/input helpers like this:

```java
var schema = RangeProofCircuit.schema();
var inputs = RangeProofCircuit.inputs()
        .secret(BigInteger.valueOf(42))
        .lo(BigInteger.valueOf(18))
        .hi(BigInteger.valueOf(99));

var witness = circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381);
var publicValues = inputs.publicValues();
```

Cardano-oriented annotated circuits should use BLS12-381 Groth16 by default:

```text
generated *Circuit companion
  -> compileR1CS(CurveId.BLS12_381)
  -> Groth16 proof
  -> Julc / Plutus V3 BLS12-381 verifier
```

For hashes in Cardano circuits, use explicit BLS12-381 Poseidon parameters:

```java
ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, left, right);
```

Do not rely on no-params Poseidon or MiMC for Cardano defaults. The no-params
Poseidon path is BN254-compatible behavior, and `ZkMiMC` delegates to the
BN254-only MiMC gadget.

Important API rules:

- `ZkBool.publicInput` / `secret` add boolean constraints eagerly.
- `ZkUInt.publicInput` / `secret` add range constraints eagerly.
- `ZkUInt` supports widths `1..253`; comparison requires widths below `253`.
- `ZkUInt.add` and `mul` widen output widths when safe; `sub` rejects
  unsigned underflow by constraining the result range.
- `ZkArray.secretFields`, `secretBools`, `secretUInts`, `publicFields`,
  `publicBools`, and `publicUInts` encode visibility for built-in element
  types. `ZkArray.bind` is for custom symbolic types.
- `ZkBits` represents fixed-size bit vectors backed by constrained `ZkBool`
  values.
- `ZkBytes` represents fixed-size byte vectors backed by 8-bit `ZkUInt` values.
- `wrap(...)` rejects signals from a different `SignalBuilder`.
- `ZkCircuitSchema.publicInputs().names()` and
  `ZkCircuitSchema.secretInputs().names()` expose flattened input order.
- `ZkInputMap.publicValues(schema)` extracts public values in schema order.

Known limitations:

- Annotated inputs support fixed-size `ZkArray<T>` for built-in element types,
  but not nested `ZkArray<ZkArray<T>>`; flatten nested structures into parallel
  arrays when needed.
- `ZkPoseidon` currently exposes two-input hashes. For N-input commitments, fold
  inputs through repeated two-input hashes or use the lower-level
  `PoseidonN`/Signal APIs until a dedicated `ZkPoseidonN` helper is added. For
  Cardano, pass BLS12-381 Poseidon params explicitly.
- `ZkMiMC` is BN254-only because it delegates to the existing MiMC gadget. Use
  `ZkPoseidon` with explicit BLS12-381 parameters for Cardano/BLS12-381
  circuits.
- `ZkMerkle.HashType.MIMC` and the no-params `HashType.POSEIDON` convenience
  path are BN254-oriented today. For Cardano Merkle circuits, use a custom hash
  lambda that calls `ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE,
  left, right)` until a params-aware `ZkMerkle` helper is added.
- Elliptic-curve composite symbolic types are available for the shipped Jubjub
  use cases (`ZkJubjubPoint`, Pedersen, EdDSA-Jubjub). Add a curve-specific
  symbolic wrapper before using another curve family.
- Private field-style symbolic inputs are rejected by the processor. Use
  package-private field style or parameter-style inputs.

See [docs/adr/circuit-annotation/README.md](../docs/adr/circuit-annotation/README.md)
for the accepted implementation plan, and
[docs/adr/circuit-annotation/cardano-gadget-support-matrix.md](../docs/adr/circuit-annotation/cardano-gadget-support-matrix.md)
for the current Cardano gadget/curve support matrix.
