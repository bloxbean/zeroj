# zeroj-prover-wasm

Circom witness calculation via GraalVM WebAssembly — no Node.js dependency.

This module loads circom-compiled `.wasm` files and computes witnesses entirely within the JVM using GraalVM's WebAssembly runtime. This eliminates the Node.js/snarkjs dependency for circom-based circuits.

## Usage

```java
// Load a circom-compiled WASM file
var calculator = new WasmWitnessCalculator(Path.of("multiplier.wasm"));

// Compute witness from inputs
var inputs = Map.of(
    "a", List.of(BigInteger.valueOf(3)),
    "b", List.of(BigInteger.valueOf(11)));

BigInteger[] witness = calculator.calculateWitness(inputs);
// witness = [1, 33, 3, 11]  (constant, output, public input, private input)

// Export as standard .wtns for downstream provers
byte[] wtnsBytes = calculator.calculateWtns(inputs);
```

## Complete Flow (no Node.js)

```
circom CLI (build-time only)
    │
    ▼
  .wasm + .r1cs
    │
    ├── WasmWitnessCalculator (GraalVM, in-process)
    │         │
    │         ▼ witness
    │    gnark FFM or Java prover → proof
    │
    └── Pure Java verifier → verified ✓

External tools at runtime: ZERO
Build-time only: circom compiler
```

## Prerequisites

- GraalVM JDK (the project already uses GraalVM 25)
- circom-compiled `.wasm` file (from `circom --wasm`)

## How It Works

1. Loads the circom `.wasm` binary via GraalVM's polyglot JavaScript + WebAssembly engines
2. Provides the `runtime` imports that circom WASM expects (exceptionHandler, etc.)
3. Sets input signals using FNV-1a hashed signal names (matching circom's convention)
4. Reads computed witness values from WASM shared memory
5. Exports to standard `.wtns` format for downstream provers

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-prover-wasm'
}
```

Requires GraalVM polyglot dependencies (included transitively):
- `org.graalvm.polyglot:polyglot`
- `org.graalvm.polyglot:wasm`
- `org.graalvm.polyglot:js`
