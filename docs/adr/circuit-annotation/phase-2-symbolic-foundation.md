# Phase 2: Symbolic Foundation

## Status

Approved.

## Goal

Introduce the foundational annotation API and symbolic `Zk*` value wrappers
used by later processor and gadget phases.

## Implemented Changes

- Added v1 annotations:
  - `@ZKCircuit`
  - `@Prove`
  - `@Public`
  - `@Secret`
  - `@CircuitParam`
  - `@UInt`
  - `@FieldElement`
  - `@FixedSize`
  - `@Order`
- Added symbolic types:
  - `ZkValue`
  - `ZkContext`
  - `ZkField`
  - `ZkBool`
  - `ZkUInt`
  - `ZkArray`
- Added visibility-aware `SignalBuilder` input lookup in `zeroj-circuit-dsl`
  so `publicInput(...)` and `privateInput(...)` reject mismatched declarations.
- Added focused unit tests for field arithmetic, boolean constraints, unsigned
  range constraints, unsigned arithmetic bit-width behavior, subtraction
  underflow, comparisons, arrays, backend compilation, and differential range
  behavior against a hand-written `Signal` circuit.

## Public API Changes

- `ZkBool` values are constrained bits and are not Java booleans.
- `ZkUInt` values eagerly assert their configured bit width for public and
  secret inputs.
- `ZkUInt.add` and `ZkUInt.mul` widen their output bit widths when safe.
- `ZkUInt.sub` constrains the result range and rejects unsigned underflow.
- `ZkArray` flattens element signals and provides visibility-specific helpers
  for built-in element types plus neutral `bind(...)` for custom symbolic types.
- `wrap(...)` rejects signals from another `SignalBuilder`.
- Annotation retention is `SOURCE`; processor behavior remains deferred to
  Phase 4.

## Exit Criteria Mapping

| ADR exit criterion | Phase 2 result |
|--------------------|----------------|
| Hand-written symbolic range circuit works without annotations | Covered by `symbolicRangeCircuitMatchesSignalCircuitBehavior`. |
| Hand-written symbolic fixed-depth Merkle input shape works without annotations | Covered by `merkleShapedInputsSupportFieldSiblingsAndBooleanPathBits`. |
| Valid witnesses pass | Covered across field, bool, uint, range, array, and Merkle-shaped tests. |
| Invalid witnesses fail | Covered for wrong arithmetic output, non-boolean inputs, false comparisons, out-of-range uints, subtraction underflow, wrong array aggregate, and non-boolean Merkle path bits. |
| Backend compilation works for R1CS, PlonK, and Halo2 | Covered by `symbolicCircuitCompilesToAllBackends`. |
| Behavior compares to hand-written `Signal` circuits | Covered by the differential symbolic-vs-`Signal` range test. |

## Verification

- `./gradlew :zeroj-circuit-annotation-api:test` passed.
- `./gradlew :zeroj-circuit-dsl:test` passed.
- `./gradlew :zeroj-circuit-annotation-processor:test` passed.
- `rg -n "[[:blank:]]$" docs/adr/circuit-annotation zeroj-circuit-annotation-api zeroj-circuit-annotation-processor` passed.
- `git diff --cached --check` passed.

## Review Results

Three-agent review approved Phase 2 after blocker fixes:

- API/design review initially blocked on `ZkArray` visibility ambiguity. The
  final review approved the visibility-specific built-in helpers and neutral
  custom `bind(...)` API.
- ZK-safety review initially blocked on visibility mismatch and cross-builder
  wrapping hazards. The final review approved the visibility-aware
  `SignalBuilder` lookup and `ZkContext.requireSignal(...)` guard.
- Tests/docs review initially blocked on missing ADR exit-criterion coverage.
  The final review approved the differential range test, Merkle-shaped input
  test, expanded negative cases, and exit-criteria mapping.

## Commit

Pending.
