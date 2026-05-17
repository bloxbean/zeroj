# Phase 9: Proving Flow Integration

## Status

Approved and completed for the Phase 9 commit.

## Goal

Make generated annotated circuits easy to hand to the existing ZeroJ compile,
witness, prover, verifier, and proof-envelope APIs without adding prover-specific
dependencies to the annotation API or generated companions.

## Implemented Changes

- Added `ZkCircuitMetadata` to carry generated circuit ID, circuit version, and
  parameter metadata for proof envelopes.
- Added `@ZKCircuit(version = ...)` so circuit versions are author-controlled
  and validated as positive integers.
- Added canonical parameter suffixes to parameterized circuit names, including
  `nameTemplate`-based names, to avoid collisions between different parameter
  sets.
- Added `ZkInputMap.publicInputs(schema)` so generated input builders can return
  typed `PublicInputs` in canonical schema order.
- Extended generated companions with:
  - `CIRCUIT_VERSION`
  - `circuitId(...)`
  - `metadata(...)`
  - `publicInputValues(inputs)`
  - `calculateWitness(circuit, inputs, curve)`
  - `proofEnvelopeBuilder(circuit, ...)`
- Extended generated `Inputs` classes with:
  - `toPublicInputs()`
  - `calculateWitness(circuit, curve)`
- Added `AnnotatedAgeVerificationProofHelper` as the proof-flow example:
  - compiles the generated annotated circuit to R1CS
  - calculates witnesses through generated input builders
  - exports `.wtns` bytes with the existing `WitnessExporter`
  - passes generated witness maps to `GnarkProverHelper`
  - builds `ZkProofEnvelope` values from generated metadata and public inputs
- Updated the user guide, ADR, examples README, and implementation plan.

## Exit Criteria

- Annotated circuits can expose typed public inputs in verifier order.
- Generated companions expose circuit ID/version metadata for proof envelopes.
- Existing prover helpers can consume generated circuits and input builders.
- Optional witness-byte export remains outside generated companions.
- Tests cover metadata, public input extraction, witness calculation, and proof
  envelope construction.

## Verification

- `./gradlew :zeroj-circuit-annotation-api:test --tests com.bloxbean.cardano.zeroj.circuit.annotation.ZkSymbolicTypesTest`
  passed.
- `./gradlew :zeroj-circuit-annotation-processor:test --tests com.bloxbean.cardano.zeroj.circuit.annotation.processor.CircuitAnnotationProcessorTest`
  passed.
- `./gradlew :zeroj-examples:test --tests com.bloxbean.cardano.zeroj.examples.annotation.AnnotatedCircuitExamplesTest`
  passed.
- `./gradlew :zeroj-circuit-dsl:test :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest`
  passed.

Exit criteria results:

- `Inputs.toPublicInputs()` and `ZkInputMap.publicInputs(schema)` produce typed
  `PublicInputs` in schema order.
- Generated `circuitId(...)` and `metadata(...)` expose stable circuit identity,
  author-controlled version, and `@CircuitParam` metadata. Circuit IDs are
  name-based; version is carried separately in proof-envelope metadata so key
  registries can choose name-only or name-plus-version lookup policies.
  Parameterized circuit IDs include a canonical `length:value` parameter suffix
  even when a readable `nameTemplate` prefix is present.
- Generated `calculateWitness(...)` helpers delegate to the existing
  `CircuitBuilder` witness calculator after validating that the circuit name
  matches the generated input schema name.
- `AnnotatedAgeVerificationProofHelper` demonstrates R1CS generation, witness
  calculation, `.wtns` export, gnark handoff, and proof-envelope construction
  without requiring native proving during unit tests.
- Processor tests reject generated constant collisions with `CIRCUIT_VERSION`,
  invalid circuit versions, unsupported `@CircuitParam` types, and mismatched
  circuit/input shapes. Template-collision tests confirm that ambiguous
  placeholders such as `{a}{b}` still produce distinct circuit names for
  distinct parameter maps.

## Review Results

Approved after three independent review tracks:

- API/design review: approved after adding author-controlled
  `@ZKCircuit(version = ...)`, direct `zeroj-api` exposure from the annotation
  API module, and explicit name-based `CircuitId` plus metadata-carried version
  semantics.
- Correctness/security review: approved after generated witness and envelope
  helpers validate circuit/schema identity, supported `@CircuitParam` types were
  restricted, null parameters were rejected, and every parameterized circuit name
  gained a canonical parameter suffix to avoid `nameTemplate` collisions.
- Docs/examples review: approved after the proof helper rejected prover-response
  curve mismatches, docs stopped claiming native prove/verify in unit tests, and
  ADR wording consistently described readable templates plus canonical suffixes.

## Commit

Included in the Phase 9 commit.
