# ZeroJ Circuit DSL — User Guide

## Overview

The ZeroJ Circuit DSL lets you define ZK arithmetic circuits in Java and compile them to **three proof systems** from a single definition:

| Backend | Proof System | Prover | Use Case |
|---------|-------------|--------|----------|
| R1CS | Groth16 | rapidsnark FFM, gnark FFM | Smallest proofs, cheapest on-chain verification |
| PlonK | PlonK | gnark FFM | Universal setup, no per-circuit ceremony |
| Halo2 | Halo2 (IPA/KZG) | Halo2 Rust FFM | No trusted setup (IPA), recursive proofs |

No circom, no Go, no Rust needed to define circuits. Just Java.

## Quick Start

```java
// 1. Define the circuit
var circuit = CircuitBuilder.create("multiplier")
    .publicVar("z")           // public: the product (visible to verifier)
    .secretVar("x")           // private: first factor (hidden)
    .secretVar("y")           // private: second factor (hidden)
    .define(api -> {
        var product = api.mul(api.var("x"), api.var("y"));
        api.assertEqual(product, api.var("z"));
    });

// 2. Calculate witness
var witness = circuit.calculateWitness(Map.of(
    "z", List.of(BigInteger.valueOf(33)),
    "x", List.of(BigInteger.valueOf(3)),
    "y", List.of(BigInteger.valueOf(11))
), CurveId.BN254);

// 3. Compile to any proof system
var r1cs  = circuit.compileR1CS(CurveId.BN254);      // Groth16
var plonk = circuit.compilePlonK(CurveId.BN254);      // PlonK
var halo2 = circuit.compileHalo2(CurveId.PALLAS);     // Halo2
```

## Core Concepts

### Variables

A `Variable` is a symbolic reference to a wire in the circuit. It doesn't hold a value — it represents a placeholder that the constraint compiler resolves into wire indices.

```java
// Declared explicitly
.publicVar("output")    // visible to the verifier
.secretVar("secret")    // hidden from the verifier

// Created implicitly by operations
var sum = api.add(a, b);    // sum is a new intermediate variable
var prod = api.mul(a, b);   // prod is a new intermediate variable
```

### Public vs Secret

- **Public variables**: Part of the "statement." The verifier sees these values.
- **Secret variables**: Part of the "witness." Only the prover knows these.

Example: "I know two numbers that multiply to 33" — `z=33` is public (everyone sees the product), `x` and `y` are secret (only the prover knows they're 3 and 11).

### Constraints

Constraints enforce relationships between variables. If the witness doesn't satisfy them, proof generation fails.

```java
api.assertEqual(a, b);     // a must equal b
api.assertBoolean(flag);   // flag must be 0 or 1
api.assertInRange(v, 8);   // 0 ≤ v < 256 (8-bit range)
```

## CircuitAPI Reference

### Arithmetic

| Method | Effect | Constraints (R1CS) |
|--------|--------|-------------------|
| `add(a, b)` | a + b | Free (linear combination) |
| `sub(a, b)` | a - b | Free |
| `mul(a, b)` | a × b | 1 constraint |
| `neg(a)` | -a | Free |
| `inv(a)` | a⁻¹ mod p | 1 constraint |
| `div(a, b)` | a / b = a × b⁻¹ | 2 constraints |
| `constant(42)` | constant value | Free |

**Key insight**: additions are free in R1CS — they're absorbed into linear combinations. Only multiplications create constraints. Design your circuits to minimize multiplications.

### Binary Operations

| Method | Effect | Constraints |
|--------|--------|------------|
| `toBinary(a, n)` | Decompose to n bits (LSB first) | n (boolean) + 1 (sum) |
| `fromBinary(bits)` | Recompose from bits | Free |
| `xor(a, b)` | a ⊕ b (both must be boolean) | 1 |
| `and(a, b)` | a ∧ b | 1 |
| `or(a, b)` | a ∨ b | 1 |
| `not(a)` | ¬a (1 - a) | Free |

### Assertions

| Method | Effect | Constraints |
|--------|--------|------------|
| `assertEqual(a, b)` | Force a == b | 1 |
| `assertBoolean(a)` | Force a ∈ {0, 1} | 1 |
| `assertInRange(a, n)` | Force 0 ≤ a < 2ⁿ | n + 1 |
| `assertNotEqual(a, b)` | Force a ≠ b | 2 |

### Comparison

| Method | Returns | Constraints |
|--------|---------|------------|
| `isZero(a)` | 1 if a == 0, else 0 | 2 |
| `isEqual(a, b)` | 1 if a == b, else 0 | 2 |
| `lessThan(a, b, n)` | 1 if a < b (n-bit), else 0 | n + 2 |
| `select(cond, a, b)` | a if cond==1, b if cond==0 | 2 |

### Array

| Method | Returns | Constraints |
|--------|---------|------------|
| `arrayAccess(arr, idx)` | arr[idx] via MUX tree | O(arr.length) |

## Standard Library (zeroj-circuit-lib)

Import: `com.bloxbean.cardano.zeroj.circuit.lib.*`

### Comparators

```java
var older = Comparators.greaterOrEqual(api, api.var("age"), api.var("threshold"), 8);
var inBounds = Comparators.inRange(api, api.var("value"), min, max, 16);
var smallest = Comparators.min(api, a, b, 8);
```

### MiMC Hash

```java
// Hash two field elements
var hash = MiMC.hash(api, api.var("left"), api.var("right"));
```

Approximately 364 constraints per hash (91 rounds × 4 multiplications).

### Merkle Proof

```java
// Verify a Merkle proof with any hash function
Merkle.verifyProof(api, leaf, root, siblings, pathBits, MiMC::hash);
```

For a depth-20 tree: 20 × 364 ≈ 7,280 constraints with MiMC.

### Binary Utilities

```java
var bits = Binary.num2Bits(api, value, 8);           // decompose to 8 bits
var value = Binary.bits2Num(api, bits);               // recompose
var xored = Binary.bitXor(api, bitsA, bitsB);        // bitwise XOR
var rotated = Binary.rotateLeft(bits, 3);             // free (index shift)
```

### Multiplexers

```java
var result = Mux.mux1(api, selector, valueA, valueB);               // 2-way
var result = Mux.mux2(api, sel0, sel1, a, b, c, d);                 // 4-way
var element = Mux.arrayAccess(api, array, index);                    // array lookup
```

## Practical Examples

### 1. Age Verification — Prove age ≥ 18 without revealing age

```java
var circuit = CircuitBuilder.create("age-check")
    .publicVar("minAge")         // 18 (verifier knows the threshold)
    .publicVar("isOldEnough")    // 1 or 0 (verifier sees the result)
    .secretVar("myAge")          // actual age (hidden from verifier)
    .define(api -> {
        var result = Comparators.greaterOrEqual(
            api, api.var("myAge"), api.var("minAge"), 8);
        api.assertEqual(result, api.var("isOldEnough"));
    });
```

### 2. Voting — Prove vote is valid with hash commitment

```java
var circuit = CircuitBuilder.create("vote")
    .publicVar("commitment")     // hash(vote, nullifier) — public
    .secretVar("vote")           // 0 or 1 — hidden
    .secretVar("nullifier")      // unique per voter — hidden
    .define(api -> {
        api.assertBoolean(api.var("vote"));
        var hash = MiMC.hash(api, api.var("vote"), api.var("nullifier"));
        api.assertEqual(hash, api.var("commitment"));
    });
```

### 3. Merkle Membership — Prove you own a leaf in a tree

```java
var circuit = CircuitBuilder.create("membership")
    .publicVar("root")
    .secretVar("leaf")
    .secretVar("sibling0").secretVar("sibling1").secretVar("sibling2")
    .secretVar("path0").secretVar("path1").secretVar("path2")
    .define(api -> {
        var siblings = new Variable[]{
            api.var("sibling0"), api.var("sibling1"), api.var("sibling2")};
        var pathBits = new Variable[]{
            api.var("path0"), api.var("path1"), api.var("path2")};
        Merkle.verifyProof(api, api.var("leaf"), api.var("root"),
            siblings, pathBits, MiMC::hash);
    });
```

### 4. Conditional Logic — Different computation based on flag

```java
var circuit = CircuitBuilder.create("conditional")
    .publicVar("result")
    .secretVar("flag").secretVar("a").secretVar("b")
    .define(api -> {
        var product = api.mul(api.var("a"), api.var("b"));
        var sum = api.add(api.var("a"), api.var("b"));
        // flag=1 → result = a*b, flag=0 → result = a+b
        var out = api.select(api.var("flag"), product, sum);
        api.assertEqual(out, api.var("result"));
    });
```

### 5. Range Proof — Prove balance is within bounds

```java
var circuit = CircuitBuilder.create("balance-check")
    .publicVar("lowerBound").publicVar("upperBound")
    .publicVar("inRange")
    .secretVar("balance")
    .define(api -> {
        var result = Comparators.inRange(api,
            api.var("balance"), api.var("lowerBound"), api.var("upperBound"), 16);
        api.assertEqual(result, api.var("inRange"));
    });
```

## Compilation Backends

### R1CS (Groth16)

```java
var r1cs = circuit.compileR1CS(CurveId.BN254);

// Serialize to iden3 .r1cs binary (for rapidsnark/snarkjs)
byte[] r1csBytes = R1CSSerializer.serialize(r1cs);
Files.write(Path.of("circuit.r1cs"), r1csBytes);

// Serialize witness to .wtns
byte[] wtnsBytes = WitnessExporter.toWtns(witness, r1cs.prime(), r1cs.fieldConfig().n32());
```

Properties:
- **Additions are free** — absorbed into linear combinations
- Only multiplications create constraints
- Smallest proofs (~128 bytes for BN254)
- Fastest verification (~3ms)
- Requires per-circuit trusted setup

### PlonK

```java
var plonk = circuit.compilePlonK(CurveId.BN254);
```

Properties:
- Each gate is a row: `qL·a + qR·b + qO·c + qM·(a·b) + qC = 0`
- Copy constraints via permutation σ
- Universal setup (one ceremony for all circuits)
- Slightly larger proofs than Groth16

### Halo2 (PLONKish)

```java
var halo2 = circuit.compileHalo2(CurveId.PALLAS);

// Serialize to JSON (intermediate format for Rust FFM prover)
String json = halo2.toJson(witness);
```

Properties:
- Same gate model as PlonK (compatible)
- 3 advice columns (a, b, c) + 5 fixed selector columns
- Permutation cycles for copy constraints
- Supports Pallas/Vesta (IPA, no setup) and BLS12-381 (KZG)
- Future: custom gates, lookup tables

## Curves

| Curve | Proof Systems | On-chain? | Note |
|-------|--------------|-----------|------|
| BN254 | Groth16, PlonK | No (no Plutus builtins) | circom/snarkjs ecosystem |
| BLS12-381 | Groth16, PlonK | **Yes** (Plutus V3) | Cardano on-chain verification |
| Pallas | Halo2 IPA | No | No trusted setup, recursive proofs |

## Witness Calculation

The witness calculator evaluates the circuit on concrete inputs:

```java
var witness = circuit.calculateWitness(Map.of(
    "x", List.of(BigInteger.valueOf(3)),
    "y", List.of(BigInteger.valueOf(11)),
    "z", List.of(BigInteger.valueOf(33))
), CurveId.BN254);

// witness[0] = 1           (constant wire, always 1)
// witness[1] = 33          (first public var: z)
// witness[2] = 3           (first secret var: x)
// witness[3] = 11          (second secret var: y)
// witness[4+] = ...        (intermediate wires)
```

If a constraint is violated (e.g., `z != x*y`), the calculator throws `ArithmeticException`.

## Testing Circuits

```java
@Test
void multiplier_validWitness() {
    var circuit = CircuitBuilder.create("mul")
        .publicVar("z").secretVar("x").secretVar("y")
        .define(api -> api.assertEqual(api.mul(api.var("x"), api.var("y")), api.var("z")));

    // Valid: 3 * 11 = 33
    assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
        "z", List.of(BigInteger.valueOf(33)),
        "x", List.of(BigInteger.valueOf(3)),
        "y", List.of(BigInteger.valueOf(11))), CurveId.BN254));

    // Invalid: 3 * 11 ≠ 99 → throws ArithmeticException
    assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
        "z", List.of(BigInteger.valueOf(99)),
        "x", List.of(BigInteger.valueOf(3)),
        "y", List.of(BigInteger.valueOf(11))), CurveId.BN254));
}
```

## End-to-End Flow

```
Java CircuitBuilder DSL
        │
        ├──▶ compileR1CS()  ──▶ .r1cs binary ──▶ rapidsnark FFM ──▶ proof
        │                                          └──▶ gnark FFM ──▶ proof
        │
        ├──▶ compilePlonK() ──▶ PlonK gates  ──▶ gnark FFM ──▶ proof
        │
        ├──▶ compileHalo2() ──▶ Halo2 JSON   ──▶ Halo2 Rust FFM ──▶ proof
        │
        └──▶ calculateWitness() ──▶ BigInteger[] (pure Java)
                                         │
                                         ▼
                               WitnessExporter.toWtns()
                                         │
                                         ▼
                                    .wtns binary

Verification (pure Java, zero native deps):
  Groth16BN254Verifier / Groth16BLS12381PureJavaVerifier
  PlonkBN254Verifier / PlonkBLS12381Verifier
  Halo2Verifier (Rust FFM)
```

## Constraint Optimization Tips

1. **Minimize multiplications** — additions are free in R1CS, multiplications cost one constraint each.

2. **Reuse intermediate results** — `api.mul(a, b)` creates a variable. Use it multiple times instead of recomputing.

3. **Use `toBinary` sparingly** — each bit costs one boolean constraint. An 8-bit decomposition = 9 constraints.

4. **Prefer `select` over branching** — ZK circuits can't branch. Use `api.select(cond, a, b)` for conditional logic.

5. **Use ZK-friendly hashes** — Poseidon (~300 constraints) and MiMC (~364 constraints) are much cheaper than SHA-256 (~25,000 constraints) inside circuits.

## Module Dependencies

```gradle
// Circuit DSL (define and compile circuits)
implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'

// Standard library (Poseidon, Merkle, comparators)
implementation 'com.bloxbean.cardano:zeroj-circuit-lib'

// Provers (choose based on your proof system)
implementation 'com.bloxbean.cardano:zeroj-prover-gnark'       // gnark (Groth16 + PlonK)
implementation 'com.bloxbean.cardano:zeroj-prover-rapidsnark'   // rapidsnark (Groth16 BN254)

// Verifiers (pure Java, zero native deps)
implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'    // Groth16 (BN254 + BLS12-381)
implementation 'com.bloxbean.cardano:zeroj-verifier-plonk'      // PlonK (BN254 + BLS12-381)
```
