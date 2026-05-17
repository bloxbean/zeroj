# zeroj-circuit-annotation-api

Public API for annotation-based ZeroJ circuit authoring.

Current Phase 5 status: this module exposes the foundational annotations,
symbolic `Zk*` types, and runtime schema/input helpers used by generated
companions.

This module contains:

- circuit annotations such as `@ZKCircuit`, `@Prove`, `@Public`, `@Secret`,
  `@CircuitParam`, `@UInt`, `@FieldElement`, `@FixedSize`, and `@Order`
- symbolic circuit value types: `ZkField`, `ZkBool`, `ZkUInt`, and `ZkArray`
- generated-circuit metadata and witness helpers: `ZkCircuitSchema` and
  `ZkInputMap`

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

var witness = circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254);
var publicValues = inputs.publicValues();
```

Important API rules:

- `ZkBool.publicInput` / `secret` add boolean constraints eagerly.
- `ZkUInt.publicInput` / `secret` add range constraints eagerly.
- `ZkUInt` supports widths `1..253`; comparison requires widths below `253`.
- `ZkUInt.add` and `mul` widen output widths when safe; `sub` rejects
  unsigned underflow by constraining the result range.
- `ZkArray.secretFields`, `secretBools`, `secretUInts`, `publicFields`,
  `publicBools`, and `publicUInts` encode visibility for built-in element
  types. `ZkArray.bind` is for custom symbolic types.
- `wrap(...)` rejects signals from a different `SignalBuilder`.
- `ZkCircuitSchema.publicInputs().names()` and
  `ZkCircuitSchema.secretInputs().names()` expose flattened input order.
- `ZkInputMap.publicValues(schema)` extracts public values in schema order.

See [docs/adr/circuit-annotation/README.md](../docs/adr/circuit-annotation/README.md)
for the accepted implementation plan.
