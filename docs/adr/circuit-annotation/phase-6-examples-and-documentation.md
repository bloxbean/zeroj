# Phase 6: Examples and Documentation

## Status

Approved and completed for the Phase 6 commit.

## Goal

Make annotation-based circuit authoring understandable from working examples,
not only from the ADR and processor tests.

## Implemented Changes

- Added annotated example circuits in `zeroj-examples`:
  - field-style range proof
  - parameter-style age verification
  - private transfer conservation proof
  - MiMC hash commitment
  - parameterized Merkle membership
- Added example tests that use generated companions through:
  - `build(...)`
  - `schema(...)`
  - `inputs(...)`
  - `publicValues()`
  - `toWitnessMap()`
- Added the annotation API and processor to the examples module.
- Added a user guide for authoring and testing annotated circuits.
- Updated the examples README with the annotation examples.

## Verification

- `./gradlew :zeroj-examples:test --tests com.bloxbean.cardano.zeroj.examples.annotation.AnnotatedCircuitExamplesTest` passed.
- `./gradlew :zeroj-examples:test --tests com.bloxbean.cardano.zeroj.examples.annotation.AnnotatedCircuitExamplesTest :zeroj-circuit-annotation-api:test :zeroj-circuit-annotation-processor:test :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest :zeroj-circuit-dsl:test` passed.
- `./gradlew :zeroj-examples:clean :zeroj-examples:test --tests com.bloxbean.cardano.zeroj.examples.annotation.AnnotatedCircuitExamplesTest` passed in review, confirming generated companions rebuild cleanly.
- `rg -n "[[:blank:]]$" docs/adr/circuit-annotation docs/circuit-annotation-user-guide.md zeroj-examples zeroj-circuit-annotation-api zeroj-circuit-annotation-processor` found no trailing whitespace.
- `git diff --cached --check` passed.

## Review Results

Approved after three independent review tracks:

- API/design review: approved after the guide was corrected to say
  `@CircuitParam` annotates constructor parameters, not constructors.
- Correctness/security review: approved after a clean examples rebuild and all
  five annotation example tests passed.
- Tests/docs/ergonomics review: approved after scoped example tests and diff
  checks passed. A full `zeroj-examples:test --rerun-tasks` run reported
  pre-existing out-of-scope failures in non-annotation examples; Phase 6
  annotation tests passed.

## Commit

Pending final phase commit.
