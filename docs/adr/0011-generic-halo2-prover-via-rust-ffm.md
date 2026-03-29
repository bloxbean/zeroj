# ADR-0011: Generic Halo2 Prover via Rust FFM

## Status
Proposed

## Date
2026-03-29

## Context

ADR-0009 established the Halo2 support strategy with phased off-chain verification, on-chain KZG, and recursive aggregation. ADR-0010 delivered the Java circuit DSL with a Halo2 backend compiler (`Halo2Compiler`) that produces a correct `Halo2CircuitSystem` — a PLONKish gate table with BigInteger selectors, advice columns, and permutation cycles.

However, **the Halo2 proving pipeline is disconnected from the circuit DSL**:

| Layer | Status |
|-------|--------|
| Java DSL -> `Halo2CircuitSystem` | Production-ready (20 gate-satisfaction tests, LinComb chaining, virtual wires) |
| `Halo2CircuitSystem.toJson()` -> Rust prover | Gap: toJson() does not serialize permutation cycles or public input bindings |
| Rust prover (`Halo2Library`) | Gap: `setupAndProve(k, a, b)` is a hardcoded multiplier circuit — does not accept arbitrary circuits |
| Halo2 verifier | Working (Rust FFM, tested with tampered proofs and wrong inputs) |

The gnark integration (ADR-0008) proves this architecture works: Java serializes constraints + witness as JSON, passes via FFM to a native prover, and receives proof bytes back. The gnark Go wrapper's `GenericR1CS` struct accepts arbitrary R1CS circuits from the Java DSL. **The Halo2 Rust side needs the same treatment.**

The key insight: Halo2's Rust `Circuit` trait requires a concrete type at compile time, but the gate structure (`qL*a + qR*b + qO*c + qM*(a*b) + qC = 0`) is fixed — only the column values change per circuit. This means a single `GenericHalo2Circuit` Rust struct can implement `Circuit<F>` once and synthesize any circuit from the Java DSL.

## Decision

### Build a generic Rust Halo2 prover that accepts arbitrary circuits from the Java DSL via FFM

The flow:

```
Java DSL circuit
  -> Halo2Compiler.compile()
  -> Halo2CircuitSystem.toJson(witness)
  -> FFM call (C string)
  -> Rust: deserialize JSON -> GenericHalo2Circuit
  -> Rust: keygen_vk + keygen_pk + create_proof
  -> serialize proof + params + public signals as JSON
  -> return to Java
```

### 1. Complete `Halo2CircuitSystem.toJson()` serialization

Current gaps to fill:

**Permutation cycles** — currently serializes only the count. Must emit the full cycle data:

```json
{
  "permutationCycles": [
    {"cells": [{"col": 0, "row": 2}, {"col": 2, "row": 5}]},
    {"cells": [{"col": 1, "row": 0}, {"col": 0, "row": 3}, {"col": 2, "row": 7}]}
  ]
}
```

**Public input bindings** — Halo2 uses an instance column for public inputs. The JSON must indicate which advice cells are bound to which instance rows:

```json
{
  "publicInputBindings": [
    {"instanceRow": 0, "adviceCol": 2, "adviceRow": 0}
  ]
}
```

**Instance column values** — the public input values themselves:

```json
{
  "instanceValues": ["33"]
}
```

### 2. Implement `GenericHalo2Circuit` in Rust

A single Rust struct that implements `halo2_proofs::plonk::Circuit<F>`:

```rust
struct GenericHalo2Circuit {
    k: u32,
    num_rows: usize,
    num_public_inputs: usize,
    advice_values: Vec<Vec<F>>,       // 3 columns x num_rows
    selector_values: Vec<Vec<F>>,     // 5 columns x num_rows
    permutation_cycles: Vec<Vec<(usize, usize)>>,  // (col, row) pairs
    public_bindings: Vec<(usize, usize, usize)>,   // (instance_row, advice_col, advice_row)
    instance_values: Vec<F>,
}
```

**`configure()`** — called once, defines:
- 3 advice columns (a, b, c)
- 1 instance column (public inputs)
- 5 fixed selector columns (qL, qR, qO, qM, qC)
- 1 custom gate: `qL*a + qR*b + qO*c + qM*(a*b) + qC = 0`
- Equality enabled on all advice columns + instance column

**`synthesize()`** — called per proof, assigns:
- All advice cell values from `advice_values`
- All fixed selector values from `selector_values`
- Permutation constraints via `region.constrain_equal()` for each cycle
- Public input constraints via `layouter.constrain_instance()` for each binding

### 3. FFI entry points

New C-ABI exports in `lib.rs`, following the existing pattern:

```rust
#[no_mangle]
pub extern "C" fn zeroj_halo2_fullprove(
    circuit_json: *const c_char,
    result_out: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32;
```

The function:
1. Parses JSON into `GenericHalo2Circuit`
2. Generates params: `Params::<EqAffine>::new(k)`
3. Key generation: `keygen_vk` + `keygen_pk`
4. Proves: `create_proof` with Blake2b transcript
5. Optionally verifies (sanity check): `verify_proof`
6. Returns JSON: `{ "proof": "<base64>", "params": "<base64>", "publicSignals": ["33"], "verified": true }`

### 4. Java FFM bindings

Update `Halo2Library.java` with a new method:

```java
public String fullProve(String circuitJson) {
    // FFM call to zeroj_halo2_fullprove
}
```

Add `Halo2Prover.java` following the `GnarkProver` pattern:

```java
public class Halo2Prover {
    public ProveResult prove(Halo2CircuitSystem circuit, BigInteger[] witness) {
        String json = circuit.toJson(witness);
        String resultJson = library.fullProve(json);
        return parseResult(resultJson);
    }
}
```

### 5. Curve and commitment scheme support

| Phase | Crate | Curve | Commitment | Setup |
|-------|-------|-------|------------|-------|
| Initial | `zcash/halo2_proofs` v0.3 | Pallas | IPA | None (transparent) |
| Future | PSE/Axiom halo2 fork | BN254 | KZG | Universal SRS |
| Future | PSE/Axiom halo2 fork | BLS12-381 | KZG | Universal SRS |

Start with IPA/Pallas (already in use, no trusted setup). KZG support via feature flags later.

### 6. Module structure

```
incubator/zeroj-verifier-halo2/       (existing, evolves into prover+verifier)
  src/main/java/.../halo2/
    Halo2Library.java                  (update: add fullProve method)
    Halo2Prover.java                   (new: high-level prove API)
    Halo2Verifier.java                 (existing, unchanged)
    Halo2NativeLoader.java             (existing, unchanged)

incubator/zeroj-halo2-rust/           (existing Rust source)
  src/
    lib.rs                             (update: add zeroj_halo2_fullprove)
    generic_circuit.rs                 (new: GenericHalo2Circuit impl)
    json_parser.rs                     (new: deserialize circuit JSON)
  Cargo.toml                          (existing, deps already correct)
```

## Implementation Plan

### Phase A: JSON serialization completeness (1-2 days)
- Serialize permutation cycles with full `(col, row)` positions in `Halo2CircuitSystem.toJson()`
- Add `publicInputBindings` field linking advice cells to instance rows
- Add `instanceValues` field with public input values as decimal strings
- Unit tests verifying JSON round-trip

### Phase B: Rust GenericHalo2Circuit (3-5 days)
- Implement `Circuit<pallas::Base>` for `GenericHalo2Circuit`
- `configure()`: define columns, single arithmetic custom gate, enable equality
- `synthesize()`: assign values, apply permutation constraints, bind public inputs
- Test with `MockProver` first (halo2's built-in constraint checker)
- Test with real IPA prover for the multiplier circuit
- Test with a comparator circuit (exercises LinComb chaining / virtual wires)

### Phase C: FFI wiring (1-2 days)
- Export `zeroj_halo2_fullprove` with C ABI
- Error handling: return descriptive error strings for parse failures, proving failures
- Memory management: caller frees result/error via `zeroj_halo2_free`

### Phase D: Java integration (1-2 days)
- Update `Halo2Library.java` with `fullProve(String circuitJson)` method
- Create `Halo2Prover.java` with typed `prove(Halo2CircuitSystem, BigInteger[])` API
- Register as prover SPI if applicable

### Phase E: End-to-end tests (2-3 days)
- `CircuitBuilder` -> `compileHalo2` -> `Halo2Prover.prove` -> `Halo2Verifier.verify`
- Multiplier circuit (basic)
- Comparator circuit with `lessThan` (exercises multi-term LinComb, virtual wires)
- Poseidon hash circuit from `zeroj-circuit-lib` (real-world complexity)
- Negative tests: tampered proof, wrong public inputs, wrong witness

### Phase F: Multi-curve support (3-5 days, optional)
- Add PSE halo2 fork dependency behind feature flag
- Support BN254 + KZG (for EVM compatibility)
- Support BLS12-381 + KZG (for Cardano on-chain verification)
- Curve selection driven by `CurveId` in the circuit JSON

## Consequences

### Positive
- Java developers can prove Halo2 circuits defined in the Java DSL — no Rust required
- Same DSL circuit compiles to R1CS (Groth16), PlonK (gnark), and Halo2 (Rust) — three proof systems from one definition
- IPA variant provides trustless proofs (no ceremony, no universal SRS)
- Architecture proven by gnark FFM integration — low risk
- Halo2's `MockProver` enables comprehensive Rust-side testing before FFI integration

### Negative
- Adds Rust build toolchain dependency (cargo) alongside Go (gnark)
- Halo2 crate ecosystem is fragmented (zcash vs PSE vs Axiom forks)
- JSON serialization of large circuits may be slow — binary format may be needed later
- Two native library dependencies to cross-compile for production (Go + Rust)

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Permutation cycle encoding mismatch between Java and Rust | Medium | `MockProver` gives detailed error messages; test with multiple circuit types |
| Public input binding ordering differs from halo2 expectations | Medium | Follow halo2 `assign_advice_from_instance` convention exactly |
| Large circuit JSON parsing overhead | Low | Start with JSON; switch to binary format (MessagePack/flatbuffers) if benchmarks show >10% overhead |
| Halo2 crate breaking changes | Low | Pin to `halo2_proofs` v0.3.0 (stable); PSE fork pinned to specific commit |
| Rust panics across FFI boundary | Low | Wrap all Rust code in `catch_unwind`; return error codes (same pattern as existing code) |

## References

- ADR-0009: Halo2 Support Strategy
- ADR-0010: Java DSL for ZK Circuit Definition
- [Halo2 Book — Simple Example](https://zcash.github.io/halo2/user/simple-example.html)
- [halo2_proofs Circuit trait](https://docs.rs/halo2_proofs/0.3.0/halo2_proofs/plonk/trait.Circuit.html)
- [gnark wrapper main.go — GenericR1CS pattern](zeroj-prover-gnark/gnark-wrapper/main.go)
