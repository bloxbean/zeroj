# ADR-0010: Java DSL for ZK Circuit Definition

## Status
Proposed

## Date
2026-03-28

## Context

ZeroJ provides verification, proving (via FFM), and submission infrastructure for ZK proofs. However, defining circuits still requires external languages:

- **circom** — Rust-based DSL, compiles to R1CS + WASM. Requires circom CLI + Node.js (for snarkjs witness calculation).
- **gnark Go** — Circuits defined as Go structs. Requires Go toolchain.
- **Halo2 Rust** — Circuits defined in Rust. Requires Rust toolchain.

This forces Java developers to learn a different language, switch toolchains, and manage cross-language build pipelines. The vision for ZeroJ is that a Java developer can define circuits, generate proofs, and verify them — all in Java.

### Current external tool dependencies

| Step | Current tool | Language |
|------|-------------|----------|
| Define circuit | circom / gnark Go | circom / Go |
| Compile circuit | circom CLI / go build | Rust / Go |
| Calculate witness | snarkjs (Node.js) OR GraalWasm | JS / WASM |
| Prove | gnark FFM / rapidsnark FFM | Go / C++ |
| Verify | **Pure Java** (zeroj-verifier-*) | Java |

### Prior art

| Project | Language | Status | Output | Issues |
|---------|----------|--------|--------|--------|
| jsnark | Java | Dead (2019) | Pinocchio format → libsnark | Non-standard format, JDK 8 era |
| xjsnark | Java/MPS | Dead (2018) | via jsnark → libsnark | Requires JetBrains MPS IDE |
| DIZK | Java/Spark | Dead (2020) | Internal R1CS | Apache Spark dependency |
| Zilch/ZeroJava | Java | Dead (2021) | STARK only | Different proof system |

**No maintained Java circuit DSL exists.** The space is empty.

## Decision

### Build a Java circuit DSL with two backends: R1CS (Groth16) and PlonK

The DSL captures arithmetic circuit structure using a `CircuitAPI` interface. The same circuit definition compiles to either R1CS (for Groth16 provers) or PlonK constraint format (for PlonK provers).

### 1. Core DSL design

The circuit is defined as a Java lambda against the `CircuitAPI` interface:

```java
var circuit = CircuitBuilder.create("multiplier")
    .publicVar("z")
    .secretVar("x")
    .secretVar("y")
    .define(api -> {
        var product = api.mul(api.var("x"), api.var("y"));
        api.assertEqual(product, api.var("z"));
    });
```

The `CircuitAPI` mirrors gnark's `frontend.API` (proven design with ~25 methods):

```java
public interface CircuitAPI {
    // Core primitives (mathematically complete)
    Variable add(Variable a, Variable b);
    Variable mul(Variable a, Variable b);
    void assertEqual(Variable a, Variable b);
    Variable select(Variable cond, Variable ifTrue, Variable ifFalse);

    // Arithmetic (built from core)
    Variable sub(Variable a, Variable b);
    Variable neg(Variable a);
    Variable inv(Variable a);
    Variable div(Variable a, Variable b);
    Variable constant(long value);
    Variable constant(BigInteger value);

    // Binary (bit decomposition + logic)
    Variable[] toBinary(Variable a, int nBits);
    Variable fromBinary(Variable[] bits);
    Variable xor(Variable a, Variable b);
    Variable and(Variable a, Variable b);
    Variable or(Variable a, Variable b);
    Variable not(Variable a);

    // Assertions
    void assertBoolean(Variable a);
    void assertInRange(Variable a, int nBits);
    void assertNotEqual(Variable a, Variable b);

    // Comparison
    Variable isZero(Variable a);
    Variable isEqual(Variable a, Variable b);
    Variable lessThan(Variable a, Variable b);

    // Array
    Variable[] arrayVar(String name, int size);
    Variable arrayAccess(Variable[] arr, Variable index);

    // Variable access
    Variable var(String name);
}
```

`Variable` is an opaque wire reference — it has no runtime value during circuit definition. It's a symbolic placeholder that the compiler maps to wire indices.

### 2. Internal representation: ConstraintGraph

The DSL builds an abstract `ConstraintGraph` — an ordered list of operations (gates) on variables. This is proof-system-agnostic:

```
Gate types:
  ADD(output, left, right)           — output = left + right
  MUL(output, left, right)           — output = left * right
  CONST(output, value)               — output = constant
  ASSERT_EQ(left, right)             — constraint: left == right
  SELECT(output, cond, ifTrue, ifFalse) — conditional MUX
```

The graph tracks which variables are public inputs, secret inputs, and intermediate wires.

### 3. Backend A: R1CS Compiler (Groth16)

Compiles the constraint graph to R1CS: `(A · w) × (B · w) = (C · w)`.

Each multiplication gate becomes one R1CS constraint. Addition gates are free (linear combinations absorbed into A, B, C vectors).

Output formats:
- **iden3 `.r1cs` binary** — standard format consumed by snarkjs, rapidsnark
- **In-memory R1CS** — for pure Java Groth16 prover (future)

```java
var r1cs = circuit.compileR1CS(CurveId.BN254);
byte[] r1csBytes = r1cs.toIden3Binary();  // feed to rapidsnark
BigInteger[] witness = r1cs.calculateWitness(inputs);
byte[] wtnsBytes = WitnessExporter.toWtns(witness, r1cs.prime(), r1cs.n32());
```

### 4. Backend B: PlonK Compiler

Compiles the constraint graph to PlonK gate table + copy constraints.

Each gate becomes a row: `qL·a + qR·b + qO·c + qM·(a·b) + qC = 0`

| Gate | qL | qR | qO | qM | qC |
|------|----|----|----|----|-----|
| `c = a + b` | 1 | 1 | -1 | 0 | 0 |
| `c = a * b` | 0 | 0 | -1 | 1 | 0 |
| `c = constant k` | 0 | 0 | -1 | 0 | k |
| `assertEqual(a, b)` | 1 | -1 | 0 | 0 | 0 |

Plus a permutation σ encoding copy constraints (which wires must have equal values).

Output formats:
- **gnark SparseR1CS CBOR** — consumed by gnark FFM prover
- **Custom JSON** — for debugging and interop

```java
var plonk = circuit.compilePlonK(CurveId.BLS12_381);
byte[] scsBytes = plonk.toGnarkBinary();  // feed to gnark FFM
BigInteger[] witness = plonk.calculateWitness(inputs);
```

### 5. Witness calculator (shared)

Both backends share the same witness calculator. Given concrete input values, it evaluates the constraint graph to compute all intermediate wire values:

```java
var witness = circuit.calculateWitness(Map.of(
    "x", List.of(BigInteger.valueOf(3)),
    "y", List.of(BigInteger.valueOf(11)),
    "z", List.of(BigInteger.valueOf(33))
));
// witness = [1, 33, 3, 11]
```

This replaces both:
- snarkjs `wtns calculate` (Node.js)
- The GraalWasm witness calculator (for circom .wasm)

For Java-defined circuits, witness calculation is native Java — no WASM needed.

### 6. Module structure

```
zeroj-circuit-dsl/
  src/main/java/com/bloxbean/cardano/zeroj/circuit/
    CircuitBuilder.java          — fluent API entry point
    CircuitAPI.java              — interface (the DSL surface)
    CircuitDefinition.java       — functional interface for circuit body
    Variable.java                — opaque wire reference
    ConstraintGraph.java         — proof-system-agnostic representation
    Gate.java                    — sealed interface for gate types
    WitnessCalculator.java       — evaluates circuit on concrete inputs
    r1cs/
      R1CSCompiler.java          — graph → R1CS constraints
      R1CSConstraintSystem.java  — A, B, C sparse matrices
      R1CSSerializer.java        — writes iden3 .r1cs binary
    plonk/
      PlonKCompiler.java         — graph → PlonK gate table + permutation
      PlonKConstraintSystem.java — gate rows + σ permutation
      PlonKSerializer.java       — writes gnark SparseR1CS binary
```

Future (separate module):
```
zeroj-circuit-lib/
  Poseidon.java                  — ZK-friendly hash (low constraint count)
  MiMC.java                      — MiMC hash
  SHA256.java                    — SHA-256 in constraints (~25K gates)
  EdDSA.java                     — EdDSA signature verification
  Merkle.java                    — Merkle proof verification
  Comparators.java               — LessThan, GreaterThan, InRange
```

### 7. Prover integration

The compiled constraint system feeds into existing zeroj provers:

| Backend | Output | Prover | Curve support |
|---------|--------|--------|---------------|
| R1CS | iden3 `.r1cs` + `.wtns` | rapidsnark FFM | BN254 |
| R1CS | iden3 `.r1cs` + `.wtns` | gnark FFM (Groth16) | BN254 + BLS12-381 |
| R1CS | in-memory | Pure Java prover (future) | BN254 + BLS12-381 |
| PlonK | gnark SparseR1CS | gnark FFM (PlonK) | BN254 + BLS12-381 |

### 8. Scope boundary: Julc is NOT in scope

The circuit DSL defines circuits and generates proofs **off-chain**. On-chain verification (Julc-based Plutus scripts) is a separate concern:

```
Off-chain (circuit DSL scope):
  Define circuit → compile → calculate witness → prove → verify

On-chain (Julc scope, NOT this ADR):
  Deploy Plutus verifier script → submit proof in Cardano tx → on-chain verify
```

The on-chain Julc verifier consumes the **proof output** of the off-chain pipeline. It doesn't need to know how the circuit was defined — it only verifies the proof against a verification key. This is already working for Groth16 BLS12-381 in zeroj-examples.

A future ADR may address **automatic Julc verifier generation** from circuit definitions (generate both the prover circuit and the matching on-chain verifier from one Java definition), but that is explicitly out of scope here.

## Consequences

### Positive

1. **Java developers can define ZK circuits without learning circom, Go, or Rust.** The DSL uses standard Java constructs (lambdas, generics, type safety).

2. **No external tools at circuit definition time.** The constraint compiler is pure Java. No circom CLI, no Go toolchain.

3. **One circuit definition → multiple proof systems.** The same `CircuitBuilder` code compiles to both R1CS (Groth16) and PlonK format.

4. **Witness calculation is native Java.** No Node.js (snarkjs), no WASM (circom), no subprocess. Given inputs, the witness calculator evaluates the constraint graph directly.

5. **Composable circuit libraries.** Java's type system, generics, and interfaces enable reusable circuit components (e.g., `MerkleProof<Poseidon>`) that are impossible in circom.

6. **IDE support for free.** Autocompletion, refactoring, type checking, debugging — all work out of the box.

7. **Testable circuits.** Unit test circuit logic with JUnit, mock inputs, check constraint satisfaction — standard Java testing practices.

### Negative

1. **No existing circom ecosystem reuse.** circomlib has hundreds of battle-tested templates (SHA-256, EdDSA, Merkle, etc.). We need to reimplement these as Java circuit libraries, which is significant effort and carries security risk.

2. **Performance of witness calculation.** Java BigInteger arithmetic is slower than circom's WASM-based field arithmetic. For large circuits (>100K constraints), witness calculation may be noticeably slower.

3. **Two serialization formats to maintain.** The iden3 `.r1cs` and gnark SparseR1CS formats may change across versions. We need to track upstream format changes.

4. **PlonK permutation argument is complex.** Building the wire permutation σ correctly is the most subtle part of the PlonK backend. Bugs here would produce circuits that compile but fail verification.

### Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Circuit DSL doesn't express all patterns | API mirrors gnark's proven `frontend.API` which is known-complete |
| R1CS serialization bugs | Byte-for-byte comparison with circom-generated `.r1cs` for same circuit |
| PlonK permutation bugs | Cross-verify: compile same circuit in gnark (Go), compare gate tables |
| Security of reimplemented circuit libraries | Differential testing against circomlib, formal verification for critical circuits (future) |
| Performance for large circuits | Profile and optimize hot paths; users can fall back to circom for very large circuits |

## Implementation Plan

### Phase 1: Core DSL + R1CS backend (smallest useful increment)
- `CircuitBuilder`, `CircuitAPI`, `Variable`, `ConstraintGraph`, `Gate`
- `R1CSCompiler` + `R1CSSerializer` (iden3 format)
- `WitnessCalculator`
- Test: multiplier circuit → R1CS → rapidsnark prove → pure Java verify

### Phase 2: PlonK backend
- `PlonKCompiler` (gate table + permutation σ)
- `PlonKSerializer` (gnark SparseR1CS format)
- Test: same multiplier circuit → PlonK → gnark prove → pure Java verify

### Phase 3: Standard library (zeroj-circuit-lib)
- Poseidon hash (ZK-friendly, low constraint count)
- Comparators (LessThan, InRange)
- Binary operations (Num2Bits, Bits2Num)
- Test: Poseidon-based Merkle proof circuit

### Phase 4: Advanced features
- Hints (non-deterministic advice, like gnark's `api.NewHint`)
- Custom PlonK gates (beyond basic arithmetic)
- Lookup tables (PlonKish)
- Pure Java Groth16 prover (no native FFM needed)
- Automatic Julc verifier generation (future ADR)

## References

- [gnark frontend.API documentation](https://docs.gnark.consensys.io/HowTo/write/circuit_api)
- [gnark circuit structure](https://docs.gnark.consensys.io/HowTo/write/circuit_structure)
- [iden3 R1CS binary format specification](https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md)
- [circom documentation](https://docs.circom.io/)
- ADR-0003: Pure Java MVP
- ADR-0008: PlonK Support via gnark
