# zeroj-circuit-annotation-processor

Compile-time annotation processor for annotation-based ZeroJ circuit authoring.

Current Phase 5 status: this module scans `@ZKCircuit` classes and generates
`*Circuit` companions with `build(...)`, `schema(...)`, `inputs(...)`,
`publicInputs(...)`, and input-name constants.

The generated companions build normal `CircuitBuilder` / `CircuitSpec`
circuits and produce ordinary witness maps for `calculateWitness(...)`.

Supported in Phase 4:

- field-style and parameter-style `@Prove` methods
- `ZkContext` proof parameters
- constructor `@CircuitParam` values
- `@FixedSize(param = "...")` arrays
- `@Public`, `@Secret`, `@UInt`, `@FieldElement`, and `@Order`
- generated schema metadata and input builders
- compile-time diagnostics for unsupported symbolic types and proof returns

Not supported in Phase 4:

- nested `@ZKCircuit` classes
- private `@Prove` methods
- static `@Prove` methods with field-style inputs
- `@CircuitParam` on `@Prove` parameters

Consumer usage:

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-annotation-api'
    annotationProcessor 'com.bloxbean.cardano:zeroj-circuit-annotation-processor'
}
```

See [docs/adr/circuit-annotation/README.md](../docs/adr/circuit-annotation/README.md)
for the accepted implementation plan.
