# ADR: ZkPoseidonN Symbolic Adapter

## Status

Implemented.

## Date

2026-05-18

## Context

The Cardano gadget support matrix identifies variable-arity Poseidon as the
next priority for symbolic annotated circuits. The low-level circuit library
already has `PoseidonN`, which folds N inputs through the reviewed two-input
`Poseidon` gadget:

```text
PoseidonN(a, b, c, d) = Poseidon(Poseidon(Poseidon(a, b), c), d)
```

That API already supports explicit `PoseidonParams`, including
`PoseidonParamsBLS12_381T3.INSTANCE`. Annotation authors can use it today only
by extracting `Signal` values and wrapping the result back into `ZkField`, which
breaks the symbolic style and makes common multi-input commitments noisier than
they should be.

## Decision

ZeroJ now provides a symbolic adapter:

```java
ZkField commitment = ZkPoseidonN.hash(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        owner,
        assetId,
        nonce,
        amount);
```

The adapter:

- live in `com.bloxbean.cardano.zeroj.circuit.lib.zk`
- accept `ZkContext`, explicit `PoseidonParams`, and `ZkField... inputs`
- reject empty input lists
- reject null inputs
- reject symbolic values from another `SignalBuilder`
- delegate directly to `PoseidonN.hash(SignalBuilder, PoseidonParams, Signal...)`
- return a wrapped `ZkField`

Do not add a no-params symbolic overload in this phase. The existing no-params
low-level `PoseidonN` overload defaults to BN254 for backward compatibility.
For annotated circuits, especially Cardano-facing examples, forcing an explicit
`PoseidonParams` argument is safer and keeps the compile curve visible at the
call site.

## Scope

In scope:

- `ZkPoseidonN` symbolic adapter
- differential tests against existing `PoseidonN`
- BLS12-381 compile/witness tests
- one annotated example using `PoseidonParamsBLS12_381T3.INSTANCE`
- documentation updates that remove the previous "drop to Signal" guidance

Out of scope:

- true width-N Poseidon parameter sets
- changing the existing `PoseidonN` folding semantics
- changing the BN254 default on existing non-symbolic APIs
- params-aware `ZkMerkle`; that remains the next follow-up

## API Shape

```java
public final class ZkPoseidonN {
    public static ZkField hash(
            ZkContext zk,
            PoseidonParams params,
            ZkField... inputs);
}
```

Single-input semantics match `PoseidonN`: `ZkPoseidonN.hash(zk, params, x)` is
equivalent to `Poseidon(x, 0)` under the same params. This is a ZeroJ
convention and not a separate external Poseidon one-input standard.

## Testing

Add tests that:

- compare `ZkPoseidonN` witness output and gate count against `PoseidonN` for
  BN254 parameters
- verify BLS12-381 params compile on `CurveId.BLS12_381` and reject
  `CurveId.BN254`
- compare BLS12-381 circuit output against `PoseidonHash.hashN(...)`
- reject empty input arrays
- reject inputs from another circuit builder
- compile and exercise an annotated BLS12-381 multi-input commitment example

Implemented coverage:

- `ZkGadgetAdaptersTest` covers BN254 differential behavior, BLS12-381
  field-guard behavior, invalid outputs, empty input rejection, and foreign
  builder rejection.
- `AnnotatedCircuitExamplesTest` covers the generated
  `AnnotatedMultiInputCommitmentCircuit` companion over `CurveId.BLS12_381`.

## Consequences

Positive:

- annotated circuits can express multi-input commitments without using the
  Signal escape hatch
- Cardano examples can use explicit BLS12-381 Poseidon params directly
- implementation stays thin and inherits existing `PoseidonN` behavior and
  tests

Negative:

- BN254 users must pass `PoseidonParamsBN254T3.INSTANCE` explicitly in symbolic
  code
- developers who want true arity-specific Poseidon must still use a future
  width-specific gadget
