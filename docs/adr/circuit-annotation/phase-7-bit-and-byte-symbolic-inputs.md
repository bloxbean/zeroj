# Phase 7: Bit and Byte Symbolic Inputs

## Status

Approved and completed for the Phase 7 commit.

## Goal

Add fixed-size bit and byte symbolic values without changing the Phase 4-6
field/range/hash/Merkle authoring surface.

## Implemented Changes

- Add `ZkBits` as a fixed-size vector of constrained `ZkBool` values.
- Add `ZkBytes` as a fixed-size vector of 8-bit constrained `ZkUInt` values.
- Support `@FixedSize(...) ZkBits` and `@FixedSize(...) ZkBytes` in generated
  circuit companions.
- Extend generated schemas and input builders for bit and byte vector inputs.
- Add API and processor tests for valid and invalid bit/byte witnesses.

## Exit Criteria

- Fixed-size byte messages can be represented.
- Invalid byte values are rejected.
- Invalid bit values are rejected.
- Byte/bit APIs do not complicate existing range/hash/Merkle examples.

## Verification

- `./gradlew :zeroj-circuit-annotation-api:test --tests com.bloxbean.cardano.zeroj.circuit.annotation.ZkSymbolicTypesTest`
  passed.
- `./gradlew :zeroj-circuit-annotation-processor:test --tests com.bloxbean.cardano.zeroj.circuit.annotation.processor.CircuitAnnotationProcessorTest`
  passed.
- `./gradlew :zeroj-circuit-dsl:test`
  passed.
- `./gradlew :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest`
  passed.

Exit criteria results:

- Fixed-size byte messages are represented by `ZkBytes`, generated as flattened
  byte inputs in schemas and input builders.
- Invalid byte witnesses are rejected through 8-bit `ZkUInt` constraints.
- Invalid bit witnesses are rejected through `ZkBool` constraints.
- Existing range/hash/Merkle examples continue to use their Phase 6 APIs; bit
  and byte vectors are additive.

## Review Results

- API/design review found that the public `ZkBytes` constructor did not enforce
  the 8-bit invariant. The constructor now rejects non-8-bit `ZkUInt` values,
  and tests cover the direct constructor path.
- API/design review also requested stronger `ZkCircuitSchema` invariants. Schema
  metadata now rejects `bits == 0`, scalar `BITS`/`BYTES`, and mismatched bit
  widths for field, bool, uint, bit-vector, and byte-vector inputs.
- Tests/docs review requested explicit negative processor tests and current
  phase docs. Processor tests now cover missing/invalid `@FixedSize` declarations
  for `ZkBits`/`ZkBytes`, and README/guide text reflects Phase 7.
- Correctness review found additional generated-companion guardrails: positive
  `@FixedSize(param = ...)` checks, reserved generated constant names, and
  rejected visibility annotations on `ZkContext` parameters. These are now fixed
  and tested.

## Commit

Pending final phase commit.
