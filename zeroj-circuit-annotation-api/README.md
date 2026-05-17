# zeroj-circuit-annotation-api

Public API for annotation-based ZeroJ circuit authoring.

Current Phase 1 status: this module is a compile-safe placeholder. It does not
yet expose annotations or symbolic `Zk*` types.

This module will contain:

- circuit annotations such as `@ZKCircuit`, `@Prove`, `@Public`, `@Secret`,
  `@CircuitParam`, `@UInt`, `@FieldElement`, `@FixedSize`, and `@Order`
- symbolic circuit value types such as `ZkField`, `ZkBool`, `ZkUInt`, and
  `ZkArray`
- schema and binding support used by generated circuit companions

The API is intentionally layered on top of `zeroj-circuit-dsl`. It does not
replace `CircuitSpec`, `SignalBuilder`, or the existing circuit library.

See [docs/adr/circuit-annotation/README.md](../docs/adr/circuit-annotation/README.md)
for the accepted implementation plan.
