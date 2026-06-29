# ZeroJ Circuit DSL — User Guide

## Table of Contents

- [Overview](#overview)
- [Two Ways to Define Circuits](#two-ways-to-define-circuits)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Writing CircuitSpec Circuits (Recommended)](#writing-circuitspec-circuits-recommended)
- [CircuitAPI Reference](#circuitapi-reference)
- [Standard Library (zeroj-circuit-lib)](#standard-library-zeroj-circuit-lib)
- [Practical Examples (CircuitSpec)](#practical-examples-circuitspec)
- [Compilation Backends](#compilation-backends)
- [Curves](#curves)
- [Witness Calculation](#witness-calculation)
- [Testing Circuits](#testing-circuits)
- [End-to-End Flow](#end-to-end-flow)
- [Constraint Optimization Tips](#constraint-optimization-tips)
- [Module Dependencies](#module-dependencies)

---

## Overview

The ZeroJ Circuit DSL lets you define ZK arithmetic circuits in Java and compile them to the main ZeroJ proof-system shapes from a single definition:

| Backend | Proof System | Prover | Use Case |
|---------|-------------|--------|----------|
| R1CS | Groth16 | **Pure Java**, gnark FFM | Smallest proofs, cheapest on-chain verification |
| PlonK | PlonK | **Pure Java**, gnark FFM | Universal setup, no per-circuit ceremony |

No circom, Go, or Rust is needed for the Java DSL plus pure-Java proving path.

## Two Ways to Define Circuits

### Recommended: CircuitSpec Class (reusable, testable, composable)

```java
public class MultiplierCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal x = c.privateInput("x");
        Signal y = c.privateInput("y");
        Signal z = c.publicOutput("z");
        c.assertEqual(x.mul(y), z);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .defineSignals(new MultiplierCircuit());
    }
}

// Usage
var circuit = MultiplierCircuit.build();
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
```

### Alternative: Inline Lambda (quick prototyping)

```java
var circuit = CircuitBuilder.create("multiplier")
    .publicVar("z").secretVar("x").secretVar("y")
    .define(api -> {
        api.assertEqual(api.mul(api.var("x"), api.var("y")), api.var("z"));
    });
```

Both produce identical R1CS constraints. **Use CircuitSpec for reusable application circuits** — it is testable, reusable, and self-documenting.

## Quick Start

```java
// 1. Define the circuit
var circuit = MultiplierCircuit.build();

// 2. Calculate witness
var witness = circuit.calculateWitness(Map.of(
    "z", List.of(BigInteger.valueOf(33)),
    "x", List.of(BigInteger.valueOf(3)),
    "y", List.of(BigInteger.valueOf(11))
), CurveId.BLS12_381);

// 3. Compile to the supported mainline proof-system shapes
var r1cs  = circuit.compileR1CS(CurveId.BLS12_381);   // Groth16
var plonk = circuit.compilePlonK(CurveId.BLS12_381);   // PlonK

// 4. Prove with pure Java prover (see pure-java-prover-guide.md)
var proof = Groth16ProverBLS381.prove(pk, witness, constraints, numWires);
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

## Writing CircuitSpec Circuits (Recommended)

A `CircuitSpec` is a Java class that defines a ZK circuit. This is the **preferred pattern** for reusable circuits because it is testable, reusable, and self-documenting.

### Anatomy of a CircuitSpec

```java
import com.bloxbean.cardano.zeroj.circuit.*;
import com.bloxbean.cardano.zeroj.circuit.lib.*;

public class MyCircuit implements CircuitSpec {

    // Optional: constructor parameters (Java replaces Circom's template parameters)
    private final int bitWidth;
    public MyCircuit(int bitWidth) { this.bitWidth = bitWidth; }

    @Override
    public void define(SignalBuilder c) {
        // 1. Declare signals
        Signal secretValue = c.privateInput("secret");  // only prover knows
        Signal publicResult = c.publicOutput("result");  // verifier sees this
        Signal threshold = c.publicInput("threshold");   // verifier provides this

        // 2. Build constraints using Signal operations
        Signal comparison = SignalComparators.greaterOrEqual(c, secretValue, threshold, bitWidth);
        c.assertEqual(comparison, publicResult);
    }

    // 3. Factory method (declares variable layout)
    public static CircuitBuilder build(int bitWidth) {
        return CircuitBuilder.create("my-circuit")
                .publicVar("threshold")
                .publicVar("result")
                .secretVar("secret")
                .defineSignals(new MyCircuit(bitWidth));
    }
}
```

### Signal API vs Functional API

The `CircuitSpec` uses the **Signal API** where operations are methods on `Signal` objects:

```java
// Signal API (recommended for CircuitSpec)
Signal sum = a.add(b);           // a + b
Signal product = a.mul(b);       // a * b (1 constraint)
Signal cond = flag.select(x, y); // flag ? x : y
flag.assertBoolean();            // flag ∈ {0, 1}
c.assertEqual(product, output);  // constrain equality
```

The inline lambda uses the **Functional API** where operations are methods on `api`:

```java
// Functional API (for inline lambdas)
var sum = api.mul(api.var("a"), api.var("b"));
api.assertEqual(sum, api.var("output"));
```

Both produce identical constraints. Use whichever feels natural.

### Example: Hash Commitment Circuit

Prove knowledge of a preimage without revealing it:

```java
public class HashCommitmentCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal secret = c.privateInput("secret");
        Signal salt = c.privateInput("salt");
        Signal commitment = c.publicOutput("commitment");

        // Cardano-facing hash: Poseidon over the BLS12-381 scalar field.
        var hash = SignalPoseidon.hash(
                c,
                PoseidonParamsBLS12_381T3.INSTANCE,
                secret,
                salt);
        c.assertEqual(hash, commitment);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("hash-commitment")
                .publicVar("commitment")
                .secretVar("secret")
                .secretVar("salt")
                .defineSignals(new HashCommitmentCircuit());
    }
}
```

### Example: Parameterized Circuit (Java Replaces Circom Templates)

In Circom: `template HashChain(depth) { ... }`. In Java: constructor parameter.

```java
public class HashChainCircuit implements CircuitSpec {
    private final int depth;  // parameter (like Circom template parameter)

    public HashChainCircuit(int depth) { this.depth = depth; }

    @Override
    public void define(SignalBuilder c) {
        Signal secret = c.privateInput("secret");
        Signal digest = c.publicOutput("digest");

        Signal current = secret;
        Signal zero = c.constant(0);
        for (int i = 0; i < depth; i++) {
            current = SignalPoseidon.hash(
                    c,
                    PoseidonParamsBLS12_381T3.INSTANCE,
                    current,
                    zero);
        }
        c.assertEqual(current, digest);
    }

    public static CircuitBuilder build(int depth) {
        return CircuitBuilder.create("hash-chain-" + depth)
                .publicVar("digest")
                .secretVar("secret")
                .defineSignals(new HashChainCircuit(depth));
    }
}

// Usage: different depths, same code
var shallow = HashChainCircuit.build(1);  // ~364 constraints
var deep = HashChainCircuit.build(5);     // ~1821 constraints
```

### Example: Merkle Proof Circuit (Array Signals + Hash Function Parameter)

```java
public class MerkleProofCircuit implements CircuitSpec {
    private final int depth;
    private final SignalMerkle.HashFn hashFn;

    public MerkleProofCircuit(int depth, SignalMerkle.HashFn hashFn) {
        this.depth = depth;
        this.hashFn = hashFn;
    }

    @Override
    public void define(SignalBuilder c) {
        Signal leaf = c.privateInput("leaf");
        Signal root = c.publicOutput("root");

        Signal[] siblings = new Signal[depth];
        Signal[] pathBits = new Signal[depth];
        for (int i = 0; i < depth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        SignalMerkle.verifyProof(c, leaf, root, siblings, pathBits, hashFn);
    }

    public static CircuitBuilder build(int depth) {
        var builder = CircuitBuilder.create("merkle-d" + depth)
                .publicVar("root").secretVar("leaf");
        for (int i = 0; i < depth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }
        return builder.defineSignals(new MerkleProofCircuit(
                depth,
                (sb, left, right) -> SignalPoseidon.hash(
                        sb,
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        left,
                        right)));
    }
}
```

### Compiling and Serializing to R1CS

```java
var circuit = HashCommitmentCircuit.build();

// Compile to R1CS (for Groth16)
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
System.out.println("Constraints: " + r1cs.numConstraints());
System.out.println("Wires: " + r1cs.numWires());
System.out.println("Public inputs: " + r1cs.numPublicInputs());

// Serialize to iden3 .r1cs binary (compatible with snarkjs)
byte[] r1csBytes = R1CSSerializer.serialize(r1cs);
Files.write(Path.of("circuit.r1cs"), r1csBytes);

// Calculate witness for Java proving
BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
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

Import: `com.bloxbean.cardano.zeroj.circuit.lib.*`. For explicit BLS12-381
Poseidon parameters, also import
`com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3`.

### Hash Functions

MiMC is BN254-only in the current circuit library. For Cardano/BLS12-381
circuits, use Poseidon with explicit BLS12-381 parameters.

```java
// MiMC-7 hash (2 inputs -> 1 output, ~364 constraints, BN254-only)
var hash = MiMC.hash(api, api.var("left"), api.var("right"));

// Poseidon hash (2 inputs -> 1 output, ~330 constraints, Cardano/BLS12-381)
var hash = Poseidon.hash(
        api,
        PoseidonParamsBLS12_381T3.INSTANCE,
        api.var("in0"),
        api.var("in1"));

// Variable-arity Poseidon (N inputs via left-fold)
var hash = PoseidonN.hash(
        api,
        PoseidonParamsBLS12_381T3.INSTANCE,
        api.var("a"),
        api.var("b"),
        api.var("c"),
        api.var("d"));

// MiMC Sponge (variable-length input, single or multi-output)
var hash = MiMCSponge.hash(api, new Variable[]{api.var("in0"), api.var("in1"), api.var("in2")});
var outputs = MiMCSponge.hashMulti(api, inputs, 2);  // 2 outputs
```

Signal API equivalents:
```java
Signal hash = SignalMiMC.hash(c, left, right);
Signal hash = SignalPoseidon.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, in0, in1);
Signal hash = PoseidonN.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, a, b, inputC, inputD);
Signal hash = MiMCSponge.hash(c, new Signal[]{in0, in1, in2});
```

### Comparators

```java
var older = Comparators.greaterOrEqual(api, api.var("age"), api.var("threshold"), 8);
var inBounds = Comparators.inRange(api, api.var("value"), min, max, 16);
var smallest = Comparators.min(api, a, b, 8);
```

### Merkle Proof

```java
// Verify a Merkle proof with any hash function
Merkle.verifyProof(api, leaf, root, siblings, pathBits, MiMC::hash);
Merkle.verifyProof(api, leaf, root, siblings, pathBits,
        (ctx, l, r) -> Poseidon.hash(ctx, PoseidonParamsBLS12_381T3.INSTANCE, l, r));
```

For a depth-20 tree: 20 × 364 ≈ 7,280 constraints with MiMC, or 20 × 330 ≈ 6,600 with Poseidon.

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

### AliasCheck

```java
// Assert value is in canonical field range [0, p-1] (prevents field aliasing)
AliasCheck.check(api, api.var("value"), 253);
```

## Practical Examples (CircuitSpec)

All examples use the recommended `CircuitSpec` pattern — a reusable Java class per circuit.

### 1. Age Verification — Prove age ≥ 18 without revealing age

```java
public class AgeVerificationCircuit implements CircuitSpec {
    private final int bitWidth;

    public AgeVerificationCircuit(int bitWidth) { this.bitWidth = bitWidth; }

    @Override
    public void define(SignalBuilder c) {
        Signal myAge       = c.privateInput("myAge");        // actual age (hidden)
        Signal minAge      = c.publicInput("minAge");        // 18 (verifier knows)
        Signal isOldEnough = c.publicOutput("isOldEnough");  // 1 or 0 (verifier sees)

        c.assertEqual(
            SignalComparators.greaterOrEqual(c, myAge, minAge, bitWidth),
            isOldEnough);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("age-check")
                .publicVar("minAge")
                .publicVar("isOldEnough")
                .secretVar("myAge")
                .defineSignals(new AgeVerificationCircuit(8));
    }
}

// Usage
var circuit = AgeVerificationCircuit.build();
var witness = circuit.calculateWitness(Map.of(
    "myAge", List.of(BigInteger.valueOf(25)),
    "minAge", List.of(BigInteger.valueOf(18)),
    "isOldEnough", List.of(BigInteger.ONE)), CurveId.BLS12_381);
```

### 2. Voting — Prove vote is valid with hash commitment

```java
public class VotingCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal vote       = c.privateInput("vote");       // 0 or 1 (hidden)
        Signal nullifier  = c.privateInput("nullifier");  // unique per voter (hidden)
        Signal commitment = c.publicOutput("commitment");  // hash output (public)

        vote.assertBoolean();  // vote must be 0 or 1
        var hash = SignalPoseidon.hash(
                c,
                PoseidonParamsBLS12_381T3.INSTANCE,
                vote,
                nullifier);
        c.assertEqual(hash, commitment);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("vote")
                .publicVar("commitment")
                .secretVar("vote")
                .secretVar("nullifier")
                .defineSignals(new VotingCircuit());
    }
}
```

### 3. Merkle Membership — Prove you own a leaf in a tree

```java
public class MerkleMembershipCircuit implements CircuitSpec {
    private final int depth;

    public MerkleMembershipCircuit(int depth) { this.depth = depth; }

    @Override
    public void define(SignalBuilder c) {
        Signal leaf = c.privateInput("leaf");
        Signal root = c.publicOutput("root");

        Signal[] siblings = new Signal[depth];
        Signal[] pathBits = new Signal[depth];
        for (int i = 0; i < depth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("path_" + i);
        }

        SignalMerkle.verifyProof(
                c,
                leaf,
                root,
                siblings,
                pathBits,
                (sb, left, right) -> SignalPoseidon.hash(
                        sb,
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        left,
                        right));
    }

    public static CircuitBuilder build(int depth) {
        var builder = CircuitBuilder.create("merkle-d" + depth)
                .publicVar("root")
                .secretVar("leaf");
        for (int i = 0; i < depth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("path_" + i);
        }
        return builder.defineSignals(new MerkleMembershipCircuit(depth));
    }
}

// Usage: parameterized depth
var shallow = MerkleMembershipCircuit.build(3);   // ~1,100 constraints
var deep    = MerkleMembershipCircuit.build(20);   // ~7,300 constraints
```

### 4. Conditional Logic — Different computation based on flag

```java
public class ConditionalCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal flag   = c.privateInput("flag");
        Signal a      = c.privateInput("a");
        Signal b      = c.privateInput("b");
        Signal result = c.publicOutput("result");

        flag.assertBoolean();

        Signal product = a.mul(b);
        Signal sum     = a.add(b);

        // flag=1 → result = a*b, flag=0 → result = a+b
        c.assertEqual(flag.select(product, sum), result);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("conditional")
                .publicVar("result")
                .secretVar("flag").secretVar("a").secretVar("b")
                .defineSignals(new ConditionalCircuit());
    }
}
```

### 5. Range Proof — Prove balance is within bounds

```java
public class RangeProofCircuit implements CircuitSpec {
    private final int bitWidth;

    public RangeProofCircuit(int bitWidth) { this.bitWidth = bitWidth; }

    @Override
    public void define(SignalBuilder c) {
        Signal balance    = c.privateInput("balance");
        Signal lowerBound = c.publicInput("lowerBound");
        Signal upperBound = c.publicInput("upperBound");
        Signal inRange    = c.publicOutput("inRange");

        Signal aboveLower = SignalComparators.greaterOrEqual(c, balance, lowerBound, bitWidth);
        Signal belowUpper = SignalComparators.lessOrEqual(c, balance, upperBound, bitWidth);

        c.assertEqual(aboveLower.and(belowUpper), inRange);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("range-proof")
                .publicVar("lowerBound").publicVar("upperBound").publicVar("inRange")
                .secretVar("balance")
                .defineSignals(new RangeProofCircuit(16));
    }
}
```

### 6. Multi-Input Commitment — Hash N secret fields into one digest

```java
public class MultiFieldCommitCircuit implements CircuitSpec {
    private final String[] fieldNames;

    public MultiFieldCommitCircuit(String... fieldNames) {
        this.fieldNames = fieldNames;
    }

    @Override
    public void define(SignalBuilder c) {
        Signal[] inputs = new Signal[fieldNames.length];
        for (int i = 0; i < fieldNames.length; i++) {
            inputs[i] = c.privateInput(fieldNames[i]);
        }
        Signal commitment = c.publicOutput("commitment");

        Signal acc = PoseidonN.hash(
                c,
                PoseidonParamsBLS12_381T3.INSTANCE,
                inputs);
        c.assertEqual(acc, commitment);
    }

    public static CircuitBuilder build(String... fieldNames) {
        var builder = CircuitBuilder.create("multi-commit").publicVar("commitment");
        for (String name : fieldNames) builder = builder.secretVar(name);
        return builder.defineSignals(new MultiFieldCommitCircuit(fieldNames));
    }
}

// Usage with descriptive field names (impossible in Circom templates!)
var circuit = MultiFieldCommitCircuit.build("name", "age", "address", "balance");
```

## Compilation Backends

### R1CS (Groth16)

```java
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

// Serialize to iden3 .r1cs binary (for snarkjs or gnark import)
byte[] r1csBytes = R1CSSerializer.serialize(r1cs);
Files.write(Path.of("circuit.r1cs"), r1csBytes);

// Witness values are returned as BigInteger[] for Java proving.
```

Properties:
- **Additions are free** — absorbed into linear combinations
- Only multiplications create constraints
- Compact proofs compared with universal-setup systems
- Requires per-circuit trusted setup

### PlonK

```java
var plonk = circuit.compilePlonK(CurveId.BLS12_381);
```

Properties:
- Each gate is a row: `qL·a + qR·b + qO·c + qM·(a·b) + qC = 0`
- Copy constraints via permutation σ
- Universal setup (one ceremony for all circuits)
- Slightly larger proofs than Groth16

## Curves

| Curve | Proof Systems | On-chain? | Note |
|-------|--------------|-----------|------|
| BLS12-381 | Groth16, PlonK | Groth16: **Yes**; PlonK: experimental opt-in | Cardano-native BLS builtins; PlonK has a full KZG verifier for the current one-public-input Cardano profile, pending audit and release gates |
| BN254 | Legacy/off-chain only | No (no Plutus builtins) | Disabled by default in ZeroJ verifiers; explicit opt-in required for experiments |

## Witness Calculation

The witness calculator evaluates the circuit on concrete inputs:

```java
var witness = circuit.calculateWitness(Map.of(
    "x", List.of(BigInteger.valueOf(3)),
    "y", List.of(BigInteger.valueOf(11)),
    "z", List.of(BigInteger.valueOf(33))
), CurveId.BLS12_381);

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
        "y", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381));

    // Invalid: 3 * 11 ≠ 99 → throws ArithmeticException
    assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
        "z", List.of(BigInteger.valueOf(99)),
        "x", List.of(BigInteger.valueOf(3)),
        "y", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381));
}
```

## End-to-End Flow

```
Java CircuitSpec / CircuitBuilder DSL
        │
        ├──▶ compileR1CS()  ──▶ Groth16ProverBLS381 (pure Java) ──▶ proof
        │                    └──▶ gnark FFM ──▶ proof (see alternate-backends.md)
        │
        ├──▶ compilePlonK() ──▶ PlonKProverBLS381 (pure Java) ──▶ proof
        │                    └──▶ gnark FFM ──▶ proof
        │
        └──▶ calculateWitness() ──▶ BigInteger[] (pure Java)

Verification (pure Java, zero native deps):
  Groth16BLS12381PureJavaVerifier / Groth16BLS12381Verifier
  PlonkBLS12381Verifier

On-Chain (Cardano Plutus V3):
  Groth16BLS12381Verifier (Julc)
  PlonkBLS12381Verifier (Julc experimental: Cardano-profile BLS12-381 PlonK, one public input)
  PlonkBLS12381TranscriptPrototype (Julc prototype: gnark transcript regression only)
```

**Recommended path**: CircuitSpec → `compileR1CS(BLS12_381)` → `Groth16ProverBLS381` → on-chain verify.
See the [Pure Java Prover Guide](pure-java-prover-guide.md) for the complete pipeline.

## Constraint Optimization Tips

1. **Minimize multiplications** — additions are free in R1CS, multiplications cost one constraint each.

2. **Reuse intermediate results** — `api.mul(a, b)` creates a variable. Use it multiple times instead of recomputing.

3. **Use `toBinary` sparingly** — each bit costs one boolean constraint. An 8-bit decomposition = 9 constraints.

4. **Prefer `select` over branching** — ZK circuits can't branch. Use `api.select(cond, a, b)` for conditional logic.

5. **Use ZK-friendly hashes** — Poseidon (~300 constraints) and MiMC (~364 constraints) are much cheaper than SHA-256 (~25,000 constraints) inside circuits. For Cardano/BLS12-381 circuits, use Poseidon with explicit BLS12-381 parameters; MiMC is BN254-only in the current circuit library.

## Module Dependencies

```gradle
implementation platform('com.bloxbean.cardano:zeroj-bom-core:0.1.0')

// Circuit DSL (define and compile circuits)
implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'

// Standard library (Poseidon, MiMC, Merkle, Comparators, Binary, Mux, AliasCheck)
implementation 'com.bloxbean.cardano:zeroj-circuit-lib'

// Pure Java prover
implementation 'com.bloxbean.cardano:zeroj-crypto'

// Optional native prover
// implementation 'com.bloxbean.cardano:zeroj-prover-gnark'    // gnark (Groth16 + PlonK)

// Verifiers (pure Java, zero native deps)
implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'    // Groth16 BLS12-381
implementation 'com.bloxbean.cardano:zeroj-verifier-plonk'      // PlonK BLS12-381
```
