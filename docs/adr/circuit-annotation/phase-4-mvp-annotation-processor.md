# Phase 4: MVP Annotation Processor

## Status

Approved and completed for the Phase 4 commit.

## Goal

Generate the first usable `*Circuit` companion classes from annotated Java
source while still targeting the existing `CircuitBuilder` and `SignalBuilder`
pipeline.

## Implemented Changes

- Replaced the no-op processor with a real `@ZKCircuit` processor.
- Generated `*Circuit` companions with:
  - `CIRCUIT_NAME`
  - input-name constants
  - `build(...)`
- Supported field-style annotated inputs.
- Supported parameter-style annotated inputs.
- Supported `ZkContext` proof parameters.
- Supported constructor `@CircuitParam` values.
- Supported `@FixedSize(param = "...")` for `ZkArray`.
- Supported `@Public`, `@Secret`, `@UInt`, `@FieldElement`, and `@Order`.
- Generated parameterized circuit names from `nameTemplate` or a canonical
  suffix such as `circuit--depth-32`.
- Added compile-time diagnostics for unsupported `boolean` and `BigInteger`
  proof methods.
- Added compile-time diagnostics for invalid Phase 4 shapes:
  - private `@Prove` methods
  - nested `@ZKCircuit` classes
  - static `@Prove` methods with field-style inputs
  - `@CircuitParam` on `@Prove` parameters
  - invalid or duplicate constructor `@CircuitParam` names
  - invalid `nameTemplate` placeholders
  - invalid `@UInt` widths
  - duplicate generated input names, constants, and flattened array names
- Allocated generated local names under an internal `__zeroj*` prefix so user
  input names such as `c`, `zk`, `builder`, and `instance` do not collide with
  generated source.
- Added compile tests that run javac with the processor, load generated
  companions, build circuits, and calculate witnesses.
- Updated the processor README.

## Public API Changes

- Consumers can add the processor through Java annotation processing and call
  generated `ExampleCircuit.build(...)` methods.
- Phase 4 generated companions do not expose schema or input-builder helpers;
  those remain Phase 5 work.
- Array input names are generated from `@Public(name = "...")` or
  `@Secret(name = "...")`; otherwise field/parameter names are singularized for
  arrays, for example `siblings -> sibling` and `pathBits -> pathBit`.

## Exit Criteria Mapping

| ADR exit criterion | Phase 4 result |
|--------------------|----------------|
| Generated `RangeProofCircuit.build()` compiles | Covered by the field-style range compile test. |
| Generated `MerkleMembershipCircuit.build(32, POSEIDON)` compiles | Covered by the parameterized Merkle compile test using a concrete depth and `ZkMerkle.HashType`. |
| Generated circuits calculate witnesses successfully for valid inputs | Covered by range, age, and Merkle tests. |
| Generated circuits reject invalid inputs | Covered by range, age, and Merkle negative witness tests. |
| Processor rejects unsupported `boolean` and `BigInteger` proof methods | Covered by negative compile tests. |
| Processor rejects invalid `@FixedSize(param = "...")` references | Covered by a negative compile test. |
| Generated source remains valid for reserved-looking user input names | Covered by a parameter-style compile test using `c`, `zk`, `builder`, and `instance`. |

## Verification

- `./gradlew :zeroj-circuit-annotation-processor:test --tests com.bloxbean.cardano.zeroj.circuit.annotation.processor.CircuitAnnotationProcessorTest` passed.
- `./gradlew :zeroj-circuit-annotation-processor:test` passed.
- `./gradlew :zeroj-circuit-annotation-api:test :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest` passed.
- `./gradlew :zeroj-circuit-annotation-processor:test :zeroj-circuit-annotation-api:test :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest :zeroj-circuit-dsl:test` passed.
- `rg -n "[[:blank:]]$" docs/adr/circuit-annotation zeroj-circuit-annotation-processor` found no trailing whitespace.
- `git diff --cached --check` passed.

## Review Results

Approved after blocker fixes by three independent review tracks:

- API/design review: approved after Phase 4 validation rules were tightened for
  field/static style combinations, proof-parameter `@CircuitParam`, private
  proof methods, nested circuit classes, and `ZkContext` annotation ordering.
- Correctness/security review: approved after generated constant names,
  duplicate/unsafe circuit parameters, and generated local-name collisions were
  fixed.
- Tests/docs/ergonomics review: approved after regression coverage was added for
  each blocker and the focused processor test class passed with 18 tests.

## Commit

Pending final phase commit.
