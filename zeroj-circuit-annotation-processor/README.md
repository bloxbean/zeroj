# zeroj-circuit-annotation-processor

Compile-time annotation processor for annotation-based ZeroJ circuit authoring.

Current Phase 9 status: this module scans `@ZKCircuit` classes and generates
`*Circuit` companions with `build(...)`, `schema(...)`, `inputs(...)`,
`publicInputs(...)`, `publicInputValues(...)`, `calculateWitness(...)`,
`circuitId(...)`, `metadata(...)`, `proofEnvelopeBuilder(...)`, and input-name
constants.

The generated companions build normal `CircuitBuilder` / `CircuitSpec`
circuits and produce ordinary witness maps for `calculateWitness(...)`.

Supported:

- field-style and parameter-style `@Prove` methods
- `ZkContext` proof parameters
- constructor `@CircuitParam` values
- `@FixedSize(...)` arrays, bits, and bytes
- `@Public`, `@Secret`, `@UInt`, `@FieldElement`, and `@Order`
- generated schema metadata, input builders, circuit metadata, and proof
  envelope helpers
- compile-time diagnostics for unsupported symbolic types and proof returns

Not supported:

- nested `@ZKCircuit` classes
- nested annotated array inputs such as `ZkArray<ZkArray<T>>`
- private `@Prove` methods
- static `@Prove` methods with field-style inputs
- `@CircuitParam` on `@Prove` parameters
- private field-style symbolic inputs

Consumer usage:

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-annotation-api'
    annotationProcessor 'com.bloxbean.cardano:zeroj-circuit-annotation-processor'
}
```

See [docs/adr/circuit-annotation/README.md](../docs/adr/circuit-annotation/README.md)
for the accepted implementation plan, and
[docs/adr/circuit-annotation/cardano-gadget-support-matrix.md](../docs/adr/circuit-annotation/cardano-gadget-support-matrix.md)
for the current Cardano-oriented gadget, curve, and symbolic-adapter support
matrix.
