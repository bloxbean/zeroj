# ADR: Nested ZkArray Symbolic Inputs

## Status

Implemented.

## Date

2026-05-18

## Context

Annotation-based circuits currently support one-dimensional fixed-size symbolic
arrays:

```java
@Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings
```

The generated companion flattens that input into deterministic witness and
schema names:

```text
sibling_0, sibling_1, ..., sibling_n
```

This is enough for Merkle paths, but some real circuits naturally group inputs
as matrices or rows:

- batched Merkle openings
- grouped credential attributes
- matrix-style compliance checks
- multi-row proof-of-reserves or solvency checks
- small fixed tables used by domain-specific validation logic

Today those circuits must flatten the data manually and keep row/column offset
math in user code. That is error-prone because public-input order and witness
names are part of the circuit identity.

## Decision

Support two-dimensional symbolic arrays:

```java
@ZKCircuit(name = "matrix-bounds", nameTemplate = "matrix-bounds-{rows}x{cols}")
public class MatrixBounds {
    private final int rows;
    private final int cols;

    public MatrixBounds(
            @CircuitParam("rows") int rows,
            @CircuitParam("cols") int cols) {
        this.rows = rows;
        this.cols = cols;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public @UInt(bits = 16) ZkUInt max,
            @Secret @UInt(bits = 16)
            @FixedSize(param = "rows", innerParam = "cols")
            ZkArray<ZkArray<ZkUInt>> values) {
        ZkBool ok = ZkBool.constant(zk, true);
        for (int row = 0; row < values.size(); row++) {
            for (int col = 0; col < values.get(row).size(); col++) {
                ok = ok.and(values.get(row).get(col).lte(max));
            }
        }
        return ok;
    }
}
```

The implementation supports `ZkArray<ZkArray<T>>` where `T` is one of:

- `ZkField`
- `ZkBool`
- `ZkUInt`

It does not support deeper nesting in this phase.

## Fixed Size Syntax

Existing one-dimensional syntax remains valid:

```java
@FixedSize(4)
@FixedSize(param = "depth")
```

Nested arrays use the existing outer dimension plus a new inner dimension:

```java
@FixedSize(value = 2, inner = 3)
@FixedSize(param = "rows", inner = 3)
@FixedSize(value = 2, innerParam = "cols")
@FixedSize(param = "rows", innerParam = "cols")
```

Rules:

- exactly one of `value` or `param` must define the outer dimension
- nested arrays require exactly one of `inner` or `innerParam`
- non-nested arrays, `ZkBits`, and `ZkBytes` must not set `inner` or
  `innerParam`
- all literal dimensions must be positive
- all parameter dimensions must reference integer-like `@CircuitParam`s
- generated `build(...)`, `schema(...)`, and `inputs(...)` methods reject
  non-positive parameter dimensions

## Flattening Contract

Nested arrays flatten in row-major order:

```text
matrix_0_0, matrix_0_1, matrix_0_2,
matrix_1_0, matrix_1_1, matrix_1_2
```

For a public nested input, this flattened order is the public-input order used
by:

- `schema().publicInputs().names()`
- `Inputs.publicValues()`
- `Inputs.toPublicInputs()`
- proof-envelope public-input serialization
- Cardano Groth16 verifier datum public inputs

This order is part of the circuit identity and must not change silently.

## Generated Builder API

For a nested input named `values`, the generated companion exposes:

```java
inputs.values(row, col, BigInteger.valueOf(10));
inputs.values(row, col, 10);
inputs.values(List.of(
        List.of(BigInteger.ONE, BigInteger.TWO),
        List.of(BigInteger.valueOf(3), BigInteger.valueOf(4))));
```

The list-based method rejects:

- wrong outer size
- wrong inner row size
- null row lists
- null element values

Ragged nested input values fail before witness calculation.

## Runtime Schema

`ZkCircuitSchema.Input` continues to expose:

- `name()`
- `kind()`
- `bits()`
- `size()`
- `signalNames()`

For nested arrays:

- `size()` is the flattened signal count
- `signalNames()` is row-major flattened
- a new `dimensions()` accessor records the shape, for example `[2, 3]`

One-dimensional arrays have dimensions `[n]`. Scalars have an empty dimension
list.

## Soundness Requirements

- A nested `ZkBool` array must still boolean-constrain every element.
- A nested `ZkUInt` array must still range-constrain every element.
- Schema names, builder witness names, and circuit declared variables must be
  identical.
- Public-input flattening must be deterministic and covered by tests.
- Duplicate flattened names must be rejected at compile time when detectable.
- Parameterized dimensions must be guarded at runtime before circuit
  construction or input-builder creation.

## Implementation Plan

1. Extend `@FixedSize` with `inner()` and `innerParam()`.
2. Extend `ZkArray` with matrix factories for fields, bools, and uints.
3. Extend `ZkCircuitSchema.Input` with dimensions while preserving existing
   one-dimensional factory methods.
4. Add `ZkInputMap.putNestedArray(...)` for row-major witness flattening.
5. Update the annotation processor to detect `ZkArray<ZkArray<T>>`, validate
   the second dimension, generate row-major variable declarations, bind nested
   symbolic values, and generate nested input-builder methods.
6. Add processor tests for generated schema names, witness maps, public-input
   order, ragged input rejection, and invalid declarations.
7. Add at least one real example under `zeroj-examples`.
8. Add one `zeroj-usecases` example or migration that demonstrates nested
   symbolic input usage.

## Implementation Notes

- `@FixedSize` now has `inner()` and `innerParam()` for the second dimension.
- `ZkArray` exposes matrix factories for `ZkField`, `ZkBool`, and `ZkUInt`.
- `ZkCircuitSchema.Input.dimensions()` exposes `[]`, `[n]`, or `[rows, cols]`.
- `ZkInputMap.putNestedArray(...)` flattens nested values row-major.
- The annotation processor rejects missing inner dimensions, invalid inner
  params, unsupported leaf types, and deeper nesting.
- `AnnotatedBatchThresholdMatrix` demonstrates a BLS12-381-compatible nested
  `ZkArray<ZkArray<ZkUInt>>` circuit in `zeroj-examples`.

## Testing Strategy

Unit-level tests:

- `ZkArray` matrix factories flatten signals row-major.
- `ZkCircuitSchema.Input.array(..., List.of(rows, cols))` exposes deterministic
  dimensions and names.
- `ZkInputMap.putNestedArray(...)` flattens row-major.

Processor tests:

- `ZkArray<ZkArray<ZkField>>`
- `ZkArray<ZkArray<ZkBool>>`
- `ZkArray<ZkArray<ZkUInt>>`
- literal dimensions
- parameter dimensions
- public nested arrays preserve public-input order
- secret nested arrays preserve witness names
- ragged values fail in generated input builders
- missing inner dimension fails compilation
- non-nested use of `inner` or `innerParam` fails compilation
- deeper nesting fails compilation

Integration tests:

- compile and calculate a valid witness for a nested-array annotated circuit
- fail witness calculation for a bad element value or failed assertion
- compile over `CurveId.BLS12_381` for a Cardano-oriented example

## Consequences

Positive:

- Matrix and grouped-input circuits become easier to read and less error-prone.
- Public-input order remains generated and inspectable instead of hand-managed.
- Existing one-dimensional annotation code remains valid.

Negative:

- `@FixedSize` grows a second-dimension surface.
- Generated companion code becomes more complex.
- Only rectangular two-dimensional arrays are supported in this phase.

## Out of Scope

- `ZkArray<ZkArray<ZkArray<T>>>`
- ragged arrays
- dynamic array sizes
- nested `ZkBits` or `ZkBytes`
- on-chain verifier changes
