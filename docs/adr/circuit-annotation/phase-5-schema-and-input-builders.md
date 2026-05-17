# Phase 5: Schema and Input Builders

## Status

Approved and completed for the Phase 5 commit.

## Goal

Add the generated metadata and witness-building helpers that make annotated
circuits practical to test and use without hand-written
`Map<String, List<BigInteger>>` values.

## Planned Changes

- Added runtime schema types to `zeroj-circuit-annotation-api`.
- Added a small runtime input-map helper to preserve witness map insertion order
  and public input extraction.
- Generated `schema(...)` companions for concrete circuit shapes.
- Generated `inputs(...)` builders for scalar and fixed-size array inputs.
- Generated `publicInputs(Inputs)` as a convenience wrapper over the generated
  input builder.
- Recorded constructor `@CircuitParam` values in schema metadata.
- Preserved deterministic public and secret input ordering from Phase 4.
- Rejected ambiguous array base names that overlap flattened input names.
- Hardened generated string literal escaping for unusual annotation values.
- Avoided generating scalar `wait(long)` setters, which would collide with
  final `Object.wait(long)`.
- Allowed `@FixedSize(param = "...")` to reference primitive `int` and boxed
  `Integer` constructor `@CircuitParam` values.

## Public Surface

For a non-parameterized circuit:

```java
var schema = RangeProofCircuit.schema();
var inputs = RangeProofCircuit.inputs()
        .secret(BigInteger.valueOf(42))
        .lo(BigInteger.valueOf(18))
        .hi(BigInteger.valueOf(99));

circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254);
inputs.publicValues();
```

For a parameterized circuit:

```java
var schema = MerkleMembershipCircuit.schema(32, ZkMerkle.HashType.POSEIDON);
var inputs = MerkleMembershipCircuit.inputs(32, ZkMerkle.HashType.POSEIDON);
```

## Exit Criteria

- Generated `schema(...)` exposes stable circuit name, parameters, public input
  order, secret input order, bit widths, array sizes, and flattened signal
  names.
- Generated input builders produce witness maps accepted by
  `CircuitBuilder.calculateWitness(...)`.
- Generated input builders expose public values in schema order.
- Parameterized circuits produce schema metadata for the concrete parameter
  values.
- Processor compile tests cover scalar and array input builders.

## Verification

- `./gradlew :zeroj-circuit-annotation-api:test :zeroj-circuit-annotation-processor:test --tests com.bloxbean.cardano.zeroj.circuit.annotation.processor.CircuitAnnotationProcessorTest` passed.
- `./gradlew :zeroj-circuit-annotation-api:test :zeroj-circuit-annotation-processor:test :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest :zeroj-circuit-dsl:test` passed.
- `rg -n "[[:blank:]]$" docs/adr/circuit-annotation zeroj-circuit-annotation-api zeroj-circuit-annotation-processor` found no trailing whitespace.
- `git diff --cached --check` passed.

## Review Results

Approved after blocker fixes by three independent review tracks:

- API/design review: approved with no blockers after schema and input helper
  APIs were verified against the ADR.
- Correctness/security review: approved after fixes for generated string
  literal escaping, array base-name ambiguity, exact schema lookup precedence,
  and scalar `wait(long)` generation.
- Tests/docs/ergonomics review: approved after regression coverage was added
  for exact schema lookup, flattened-name overlap rejection, generated array
  message escaping, and generated input builders.

## Commit

Pending final phase commit.
