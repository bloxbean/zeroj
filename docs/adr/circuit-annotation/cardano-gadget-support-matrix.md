# ADR: Cardano Gadget Support Matrix for Symbolic Annotated Circuits

## Status

Accepted follow-up plan. Priorities 1 through 6 are completed in the current
code and docs.

## Date

2026-05-18

## Context

ZeroJ now supports annotation-based circuit authoring with symbolic `Zk*`
types. The next design question is not whether annotated circuits can express
complex circuits in general; they can. The important operational question is:

- which existing ZeroJ gadgets can be used directly from annotated circuits
- which curve each gadget requires
- whether a circuit using that gadget can produce a proof that is practical for
  Cardano on-chain verification
- which gaps should be closed next

This ADR records the current support matrix and the follow-up implementation
plan for Cardano-oriented annotated circuit authoring.

## Key Distinction

Circuit gadgets do not execute on-chain. They execute during circuit definition
and witness/proof generation. Cardano validators only verify the final proof.

Therefore, "Cardano on-chain support" means:

- the circuit can compile and prove over a Cardano-supported proof curve
- ZeroJ has, or can generate, a matching Plutus/Julc verifier for that proof
  system and curve
- public inputs are serialized in the order expected by the verification key
  and validator

For production Cardano use, the default target should be:

```text
Annotated symbolic circuit
  -> CurveId.BLS12_381
  -> Groth16
  -> Julc / Plutus V3 BLS12-381 verifier
```

## Current Curve and Proof-System Matrix

| Proof system | Curve | ZeroJ off-chain support | Cardano on-chain support | Current status |
|--------------|-------|-------------------------|--------------------------|----------------|
| Groth16 | BLS12-381 | Yes | Yes | Production path. `OnChainFeasibility` marks this `WORKING`. |
| PlonK | BLS12-381 | Yes | Experimental | Julc verifier prototype exists, but the full KZG batch opening pairing check is deferred. |
| Halo2 | BLS12-381 | Assessment only | No production verifier | Research path only in current repo. |
| Groth16 | BN254 | Yes | No | Plutus V3 has no BN254 pairing builtins in the current ZeroJ support model. |
| PlonK | BN254 | Yes | No | Useful off-chain, not a Cardano on-chain target today. |
| Halo2 | Pallas | Incubator/off-chain | No | No Pallas curve builtins or Cardano on-chain verifier in current repo. |
| BBS | BLS12-381 | Yes, separate proof system | No ZeroJ on-chain verifier today | Useful for off-chain selective disclosure; not an annotated circuit gadget. |

Relevant source:

- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/analysis/OnChainFeasibility.java`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/groth16/validator/Groth16BLS12381Verifier.java`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/groth16/lib/Groth16BLS12381Lib.java`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/plonk/validator/PlonkBLS12381TranscriptPrototype.java`
- `zeroj-verifier-groth16/...`
- `zeroj-verifier-plonk/...`
- `incubator/zeroj-verifier-halo2/...`

## Current Circuit Field Support

The circuit DSL currently exposes three scalar fields through `FieldConfig`:

| FieldConfig | CurveId | Intended use |
|-------------|---------|--------------|
| `FieldConfig.BN254` | `CurveId.BN254` | Circom/snarkjs-compatible off-chain circuits and Ethereum-style proof ecosystems. |
| `FieldConfig.BLS12_381` | `CurveId.BLS12_381` | Cardano-oriented Groth16/PlonK circuits and Jubjub-in-BLS scalar-field gadgets. |
| `FieldConfig.PALLAS` | `CurveId.PALLAS` | Halo2/Pasta experiments. |

Gadgets that depend on field-specific constants call
`CircuitAPI.requireField(...)`. `CircuitBuilder` then rejects compile or witness
calculation if the requested curve does not match the gadget's required field.
This is important for hashes such as Poseidon and MiMC, where using constants
from one field while compiling over another field would produce incompatible
and potentially unsafe circuits.

Relevant source:

- `zeroj-circuit-dsl/.../FieldConfig.java`
- `zeroj-circuit-dsl/.../CircuitAPI.java`
- `zeroj-circuit-dsl/.../CircuitBuilder.java`

## Gadget Support Matrix

| Gadget or library | Purpose | Curve / field support | Symbolic annotation support today | Cardano on-chain support | Action needed |
|-------------------|---------|-----------------------|-----------------------------------|--------------------------|---------------|
| Core arithmetic | Field add, sub, mul, div, equality | Generic over `BN254`, `BLS12_381`, `PALLAS` | Direct through `ZkField` | Yes when compiled/proved over `BLS12_381 + Groth16` | None. |
| `ZkField` | Raw field element | Generic | Direct | Yes on BLS12-381 Groth16 | None. |
| `ZkBool` | Boolean-constrained field bit | Generic | Direct | Yes on BLS12-381 Groth16 | None. |
| `ZkUInt` | Unsigned integer with bit width and range constraints | Generic, width-limited | Direct | Yes on BLS12-381 Groth16 | Document max width and comparison limits. Current `MAX_BITS` is 253 and comparisons require compare width `< 253`. |
| `ZkArray<T>` | Fixed-size symbolic arrays | Generic | Direct for one-dimensional arrays and rectangular `ZkArray<ZkArray<T>>` matrices | Yes on BLS12-381 Groth16 | Deeper nesting remains out of scope until a real circuit needs it. |
| `ZkBits` | Fixed-size bit vector | Generic | Direct for binding/equality | Yes on BLS12-381 Groth16 | Add ergonomic bitwise operations if bit-heavy circuits appear. |
| `ZkBytes` | Fixed-size byte vector | Generic | Direct for binding/equality | Yes on BLS12-381 Groth16 | Add packing/unpacking helpers when byte-oriented circuits appear. |
| `Comparators` / `SignalComparators` | `<`, `<=`, `>`, `>=`, range, min, max | Generic | Mostly direct through `ZkUInt` | Yes on BLS12-381 Groth16 | Optional symbolic helpers for `min` and `max`. |
| `Binary` / `SignalBinary` | Bit decomposition, recomposition, bitwise ops, shifts | Generic | Partial through `ZkBits` and `ZkBool` | Yes on BLS12-381 Groth16 | Add `ZkBits.and/or/xor/rotate/shift` wrappers for better ergonomics. |
| `Mux` | Conditional select and array access | Generic | Direct scalar select through `ZkBool.select` | Yes on BLS12-381 Groth16 | Add `ZkArray.select` or dynamic array access helper if needed. |
| `AliasCheck` | Canonical field representation check | Generic | Mostly covered by `ZkUInt` range checks | Yes on BLS12-381 Groth16 | Optional `ZkAliasCheck` for raw `ZkField`. |
| `MiMC` / `SignalMiMC` | MiMC-7 two-input hash | BN254 only in current circuit lib | Direct through `ZkMiMC` | No for Cardano on-chain, because the circuit requires BN254 | Use Poseidon for Cardano. Consider a separate BLS12-381 MiMC variant only if there is a concrete interop need. |
| `MiMCSponge` | Variable-length MiMC sponge | BN254 only, because it calls `MiMC` | No direct `ZkMiMCSponge` | No for Cardano on-chain | Add symbolic wrapper only for BN254/off-chain legacy use. |
| `Poseidon` | Two-input Poseidon T3 hash | BN254 default; BLS12-381 supported with explicit params | Direct through `ZkPoseidon` for two inputs | Yes if `PoseidonParamsBLS12_381T3.INSTANCE` is used | Make BLS12-381 params prominent in Cardano examples. |
| `PoseidonN` | Variable-arity folded Poseidon | BN254 default; BLS12-381 supported with explicit params | Direct through `ZkPoseidonN` with explicit params | Yes if `PoseidonParamsBLS12_381T3.INSTANCE` is used | None. |
| `Merkle` / `SignalMerkle` | Fixed-depth Merkle membership | Hash-dependent | Direct through `ZkMerkle`; params-aware Poseidon helpers are available | Yes when `ZkMerkle.*Poseidon(..., PoseidonParamsBLS12_381T3.INSTANCE, ...)` is used | None. |
| `ZkMerkle.HashType.MIMC` | Merkle with MiMC | BN254 only | Direct | No for Cardano on-chain | Mark as BN254/off-chain in docs. |
| `ZkMerkle.HashType.POSEIDON` | Merkle with default Poseidon | BN254 by default today | Direct | No if using default enum path | Use params-aware `ZkMerkle.*Poseidon(...)` for Cardano. |
| `ZkMerkle` with custom hash lambda | Merkle with caller-provided hash | Depends on lambda | Direct | Yes with a BLS12-381-compatible lambda | Keep as advanced escape hatch. |
| `ZkMpf` / `zeroj-mpf-poseidon` | Private CCL MPF inclusion and conservative exclusion over a Poseidon-rooted commitment | BLS12-381 Poseidon only | Direct through `ZkMpfProof` flattened arrays and `PoseidonMpfCodec` witness generation | Path exists through Groth16 BLS12-381; MPF-specific proof/Yaci demo is deferred until constraint optimization. Not compatible with native Aiken/Blake2b MPF roots. | Completed at witness level. Terminal fork exclusions are rejected in v1. Use `Groth16BLS12381Lib` in custom validators for root/nullifier/domain checks. |
| `JubjubPoint` | Off-circuit Jubjub point arithmetic | Jubjub over BLS12-381 scalar field | Used by symbolic wrappers | Yes for BLS12-381 circuits | None. |
| `InCircuitJubjub` | In-circuit Jubjub arithmetic | Requires BLS12-381 scalar field | Direct through `ZkJubjubPoint` | Yes | Document trusted point binding and subgroup-check contract. |
| `ZkJubjubPoint` | Symbolic Jubjub point | Requires BLS12-381 scalar field | Direct | Yes | Add in-circuit curve/subgroup checks only if untrusted public points must be accepted directly. |
| `InCircuitPedersen` / `ZkPedersen` | Jubjub Pedersen commitment | Requires BLS12-381 scalar field | Direct | Yes | None; document constraint cost and scalar width. |
| `InCircuitEdDSAJubjub` / `ZkEdDSAJubjub` | EdDSA-Jubjub verification | Requires BLS12-381 scalar field | Direct | Yes | None for trusted/subgroup-checked points. |
| `zeroj-bls12381` | BLS12-381 field, G1/G2, pairing, hash-to-curve | BLS12-381 | Not a circuit gadget | Supports off-chain proof verification and conversion paths; Cardano has BLS builtins | Use for proof systems and BBS, not directly inside symbolic circuits unless a circuit gadget is built. |
| `zeroj-blst` | Native BLS12-381 provider | BLS12-381 | Not a circuit gadget | Off-chain helper | No annotation work. |
| `zeroj-bls12381-wasm` | WASM BLS12-381 provider | BLS12-381 | Not a circuit gadget | Off-chain helper | No annotation work. |
| `zeroj-bbs` / `zeroj-bbs-wasm` | CFRG BBS signatures and presentations | BLS12-381 | Not an annotated circuit gadget | No current ZeroJ on-chain verifier | Keep separate from annotated circuits for now. |
| Groth16 pure Java provers | Proof generation | BN254 and BLS12-381 | Consumes generated circuits through R1CS/witness APIs | BLS12-381 proofs target Cardano through the canonical arbitrary-count verifier | None for public-input count; consider generated fixed-count validators only for budget-critical circuits. |
| PlonK pure Java provers | Proof generation | BN254 and BLS12-381 | Consumes generated circuits through existing compile APIs | BLS12-381 on-chain is experimental | Do not make PlonK the Cardano default until on-chain verifier is complete. |
| Halo2 incubator verifier | Halo2 IPA verification | Pallas | Not a symbolic circuit target for Cardano | No | Keep as incubator/off-chain. |

## Important Current Limitations

### Canonical Groth16 On-Chain Verifier Public-Input Count

Status: completed. The design and implementation notes are tracked in
[`cardano-groth16-arbitrary-public-inputs.md`](cardano-groth16-arbitrary-public-inputs.md).

`Groth16BLS12381Verifier` now provides the general path. It accepts the
full `IC` vector as one `PlutusData` list parameter and folds it against the
datum public-input list:

```text
vk_x = IC[0] + pub[0] * IC[1] + ... + pub[n - 1] * IC[n]
```

The verifier rejects empty `IC` lists and any mismatch where
`len(IC) != len(publicInputs) + 1`. Custom validators compose the reusable
`Groth16BLS12381Lib` `@OnchainLibrary` helper with their own domain checks.
Generated fixed-count validators remain a possible future optimization if
budget-critical circuits need lower script cost.

### MiMC Is BN254-Only in the Circuit Library

The current `MiMC`, `SignalMiMC`, `ZkMiMC`, and `MiMCSponge` path is BN254-only.
`MiMC.hash(...)` calls `api.requireField(FieldConfig.BN254)`.

This is not a problem for off-chain BN254 circuits, but it is not a good default
for Cardano. Cardano-facing examples should use BLS12-381 Poseidon instead.

Existing examples that compute MiMC with a BLS12-381 prime outside the circuit
should be treated as legacy/test code that needs migration or clarification.
The in-circuit gadget now correctly prevents compiling that path as a
BLS12-381 circuit.

### Poseidon Defaults Are BN254 for Back Compatibility

The no-params Poseidon overload defaults to BN254. This is correct for
backward compatibility but risky for Cardano examples.

For Cardano circuits, code should use:

```java
ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, left, right)
```

or a future convenience API that makes the BLS12-381 choice explicit.

### BBS Is Not an Annotated Circuit Gadget

BBS support is important for selective disclosure, but it is a separate proof
system in ZeroJ today. It should not be presented as a symbolic annotated
circuit gadget until ZeroJ either has:

- an in-circuit BBS verification gadget, or
- a Cardano on-chain BBS verifier path.

## Decision

For new Cardano-oriented annotated circuits:

1. Use `CurveId.BLS12_381` as the default compile/prove target.
2. Use Groth16 as the default proof system for on-chain verification.
3. Use Poseidon with explicit BLS12-381 parameters as the default ZK hash.
4. Use Jubjub/Pedersen/EdDSA-Jubjub symbolic adapters only on BLS12-381.
5. Treat MiMC as BN254/off-chain unless a BLS12-381 MiMC variant is explicitly
   designed and documented.
6. Treat PlonK on-chain support as experimental until the full KZG opening
   verifier is implemented.
7. Generate or generalize the Groth16 BLS12-381 on-chain verifier so annotated
   circuits with arbitrary public-input schemas have a first-class Cardano path.

## Follow-Up Implementation Plan

### Phase A: Documentation and Defaults

Goal: prevent developers from accidentally writing BN254-only annotated
circuits when they intend to target Cardano.

Tasks:

- Add this support matrix to the circuit annotation documentation.
- Update annotated examples and user guide text to state that Cardano examples
  should use BLS12-381 Poseidon, not default Poseidon or MiMC.
- Mark `ZkMiMC` and `ZkMerkle.HashType.MIMC` as BN254/off-chain in docs.
- Add a short Cardano recipe:
  `@ZKCircuit -> build -> compileR1CS(BLS12_381) -> prove Groth16 -> Julc verifier`.

Exit criteria:

- A user can identify which symbolic gadgets are Cardano-compatible without
  reading source.
- Docs clearly say that no-params Poseidon and MiMC are not Cardano defaults.

### Phase B: `ZkPoseidonN`

Status: completed. The symbolic adapter is tracked in
[`zk-poseidon-n-symbolic-adapter.md`](zk-poseidon-n-symbolic-adapter.md).

Goal: expose variable-arity Poseidon cleanly in symbolic annotated circuits.

Tasks:

- Added `ZkPoseidonN.hash(ZkContext, PoseidonParams, ZkField...)`.
- Skipped the no-params overload to avoid Cardano mistakes.
- Added BN254 differential tests against `PoseidonN` and BLS12-381 tests
  against `PoseidonHash.hashN(...)` plus compile-curve guards.
- Added an annotated example using BLS12-381 `ZkPoseidonN`.

Exit criteria:

- Multi-input commitments can be written without dropping to `Signal`.
- BLS12-381 params are supported and tested.

### Phase C: Params-Aware `ZkMerkle`

Status: completed. The helper design is tracked in
[`zk-merkle-poseidon-params-helpers.md`](zk-merkle-poseidon-params-helpers.md).

Goal: make BLS12-381 Merkle circuits ergonomic and hard to misconfigure.

Tasks:

- Added params-aware helpers:

```java
ZkMerkle.verifyPoseidon(
    zk,
    PoseidonParamsBLS12_381T3.INSTANCE,
    leaf,
    root,
    siblings,
    pathBits);
```

- Kept the custom hash lambda path for advanced users.
- Added tests that reject mismatched compile fields through `requireField`.
- Added `AnnotatedBlsPoseidonMerkleMembership` for the BLS12-381 path.

Exit criteria:

- A Cardano Merkle membership circuit can be written without a custom lambda.
- `ZkMerkle.HashType.POSEIDON` ambiguity is documented in Cardano-facing
  examples.

### Phase D: Cardano Groth16 Verifier Generation or Generalization

Status: completed. The implementation is tracked in
[`cardano-groth16-arbitrary-public-inputs.md`](cardano-groth16-arbitrary-public-inputs.md).

Goal: make arbitrary annotated BLS12-381 Groth16 circuits usable on-chain.

Tasks:

- Added `Groth16BLS12381Verifier`.
- Removed the old fixed two-input verifier before release.
- Added `Groth16BLS12381Lib` as the reusable on-chain library helper.
- Preserved stable public-input order by consuming datum values positionally.
- Added Julc VM budget output for two-input and three-input proofs.
- Added tests for two inputs, more-than-two inputs, wrong values, too few
  values, too many values, and empty `IC` lists.
- Updated the pure Java Yaci DevKit e2e to use the canonical verifier.

Exit criteria:

- Annotated circuits are not limited by the current 2-public-input verifier.
- The generated schema, proof envelope, and on-chain validator agree on public
  input ordering.

### Phase E: Example Migration

Status: completed. The implementation is tracked in
[`example-migration-bls-poseidon.md`](example-migration-bls-poseidon.md).

Goal: align reference examples with the Cardano support model.

Tasks:

- Migrated sealed bid, anonymous voting, hash chain, and multi-input
  commitment examples to explicit BLS12-381 Poseidon.
- Kept Merkle `HashType.MIMC` only as an explicitly BN254/off-chain template
  path and use params-aware BLS12-381 Poseidon for Cardano Merkle tests.
- Migrated annotated sealed bid and annotated anonymous voting to explicit
  BLS12-381 `ZkPoseidon`.
- Migrated the `zeroj-usecases` annotated private voting, proof-of-reserves,
  and compliance credential examples to explicit BLS12-381 Poseidon.
- Left BN254 MiMC examples in place only when they are explicitly labeled
  off-chain/BN254.
- Made tests use `FieldConfig.BN254` only for MiMC examples and
  `FieldConfig.BLS12_381` for Cardano examples.

Exit criteria:

- Example names and README text make it obvious whether an example is
  Cardano-on-chain-ready or BN254/off-chain.

### Phase F: Nested `ZkArray<ZkArray<T>>`

Status: completed. The implementation is tracked in
[`nested-zkarray-symbolic-inputs.md`](nested-zkarray-symbolic-inputs.md).

Goal: support matrix-like and grouped fixed-size symbolic inputs without manual
flattening.

Rationale:

- Annotated circuits now support one-dimensional `ZkArray<T>` and rectangular
  two-dimensional `ZkArray<ZkArray<T>>`.
- Deeper nesting can still be worked around by flattening inputs, but that
  pushes offset math and naming conventions into user code.
- Nested arrays are not Cardano-specific, but they improve ergonomics for
  circuits with grouped attributes, batched Merkle openings, matrices, or
  multi-row compliance proofs.

Tasks:

- Extended annotation validation so nested `ZkArray<ZkArray<T>>` declarations
  require explicit outer and inner fixed sizes.
- Defined stable schema flattening such as `matrix_0_0`, `matrix_0_1`,
  `matrix_1_0`, and `matrix_1_1`.
- Generated input builder methods that accept rectangular nested lists.
- Rejected ragged nested input values at input-builder time.
- Preserved public-input order and witness-map order across generated schema,
  input builders, and proof-envelope public values.
- Added tests for public and secret nested arrays of `ZkField`, `ZkBool`, and
  `ZkUInt`.

Exit criteria:

- A two-dimensional annotated symbolic input can be declared, compiled, and
  tested without manually flattening it in user code.
- Generated schema names and input builders are deterministic and documented.

### Phase G: Optional BLS12-381 MiMC Decision

Goal: decide whether ZeroJ needs a BLS12-381 MiMC variant.

Recommendation:

- Do not prioritize this unless a concrete external protocol requires MiMC over
  the BLS12-381 scalar field.
- Prefer BLS12-381 Poseidon for new Cardano circuits because ZeroJ already has
  BLS12-381 Poseidon constants and symbolic adapters.

If implemented:

- Create a separate params-named gadget instead of changing existing MiMC
  behavior.
- Keep BN254 MiMC backward compatibility.
- Add independent test vectors for the BLS12-381 variant.
- Add explicit docs explaining that this is not circomlib BN254 MiMC.

Exit criteria:

- No existing BN254 MiMC circuit changes behavior.
- BLS12-381 MiMC is only exposed under an explicit name.

### Phase H: Poseidon MPF Gadget

Status: completed. The design and implementation are tracked in
[`zk-mpf-gadget.md`](zk-mpf-gadget.md).

Goal: support private CCL MPF inclusion and conservative exclusion witnesses
inside annotated BLS12-381 circuits.

Tasks:

- Added `zeroj-mpf-poseidon` with a CCL `HashFunction`, custom
  `CommitmentScheme`, in-memory trie helpers, reference verifier, value
  commitments, and a proof-to-witness codec.
- Added `ZkMpfProof` and `ZkMpf` symbolic helpers.
- Added BLS12-381 inclusion/exclusion differential tests against supported
  CCL-generated proofs, plus rejection for forged terminal-fork exclusion.
- Added an annotated private-registry inclusion example using the generated
  circuit surface.
- Added a standalone `zeroj-usecases` witness-level private registry example.
- Documented that ZeroJ Poseidon MPF roots are separate from native
  Blake2b/Aiken MPF roots.

Exit criteria:

- CCL-generated Poseidon MPF inclusion and supported exclusion proofs verify
  inside ZeroJ circuits.
- Developers can build witness maps from CCL proof bytes without hand-flattening
  MPF arrays.

## Recommended Priority

1. Documentation and defaults. Completed.
2. `ZkPoseidonN`. Completed.
3. Params-aware BLS12-381 `ZkMerkle`. Completed.
4. Generic/generated Cardano Groth16 verifier for arbitrary public-input count. Completed.
5. Example migration to BLS12-381 Poseidon. Completed.
6. Nested `ZkArray<ZkArray<T>>` support. Completed.
7. Poseidon MPF gadget. Completed.
8. Optional BLS12-381 MiMC only if a real integration requires it.

## Testing Strategy

For every new symbolic wrapper:

- compare generated constraints/witness behavior against the existing
  `Signal*` or low-level gadget
- test both valid and invalid witnesses
- test compile/witness rejection when field-specific params do not match the
  requested compile curve
- include at least one generated annotated circuit using the wrapper

For Cardano on-chain readiness:

- compile annotated circuit to R1CS over `CurveId.BLS12_381`
- generate or load a Groth16 BLS12-381 proof
- verify off-chain with the BLS12-381 Groth16 verifier
- convert proof and verification key to Cardano compressed BLS bytes
- evaluate the Julc validator in tests
- confirm public input order matches generated `schema()` and
  `publicInputValues(...)`

## Consequences

Positive:

- Cardano-oriented circuit authors get a clear default path.
- Symbolic annotation APIs remain usable for BN254/off-chain circuits without
  pretending those circuits are Cardano-on-chain-ready.
- Poseidon, Merkle, Pedersen, and EdDSA-Jubjub become the primary building
  blocks for real Cardano privacy circuits.
- Public-input ordering and verifier generation become explicit requirements,
  reducing deployment risk.

Negative:

- Documentation must distinguish between "usable in annotated circuits" and
  "usable for Cardano on-chain verification."
- A generalized/generated on-chain verifier adds a new implementation slice.

## Open Questions

- Do any target partner ecosystems require MiMC over BLS12-381, or is Poseidon
  sufficient for all near-term Cardano use cases?
