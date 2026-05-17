# zeroj-circuit-annotation-processor

Compile-time annotation processor for annotation-based ZeroJ circuit authoring.

Current Phase 1 status: this module contains a registered no-op processor
placeholder. It does not yet scan annotations or generate source.

The processor will scan classes annotated with `@ZKCircuit` and generate
companion classes that build normal `CircuitBuilder` / `CircuitSpec` circuits.

Current phase status:

- the module is scaffolded
- the processor is registered with Java's service provider mechanism
- functional processing is intentionally deferred to Phase 4 of the ADR plan

Consumer usage after the API stabilizes:

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-annotation-api'
    annotationProcessor 'com.bloxbean.cardano:zeroj-circuit-annotation-processor'
}
```

See [docs/adr/circuit-annotation/README.md](../docs/adr/circuit-annotation/README.md)
for the accepted implementation plan.
