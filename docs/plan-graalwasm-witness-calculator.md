# Plan: GraalWasm Witness Calculator

## Goal

Eliminate the Node.js/snarkjs dependency for circom-based circuits by running the circom-generated `.wasm` witness calculator directly in the JVM using GraalVM's WebAssembly runtime.

## Current State

```
circom circuit → compile → .wasm + .r1cs
                              │
                              ▼
              ┌── Node.js snarkjs ────────────┐
              │  snarkjs wtns calculate        │  ← Requires Node.js
              │  .wasm + input.json → .wtns    │
              └───────────────────────────────┘
                              │
                              ▼
              gnark FFM or pure Java prover → proof
```

## Target State

```
circom circuit → compile → .wasm + .r1cs
                              │
                              ▼
              ┌── GraalWasm (in JVM) ─────────┐
              │  WasmWitnessCalculator         │  ← Pure Java, no Node.js
              │  .wasm + inputs → witness      │
              └───────────────────────────────┘
                              │
                              ▼
              gnark FFM or pure Java prover → proof
```

## Design

### Incubator module: `zeroj-prover-wasm`

```
incubator/zeroj-prover-wasm/
  src/main/java/com/bloxbean/cardano/zeroj/prover/wasm/
    WasmWitnessCalculator.java    — main API
    CircomWasmRuntime.java        — GraalWasm context management
    WitnessExporter.java          — convert witness to .wtns / gnark binary format
  build.gradle                    — depends on org.graalvm.polyglot:wasm
```

### API

```java
// Load a circom-compiled WASM file
var calculator = new WasmWitnessCalculator(Path.of("multiplier.wasm"));

// Compute witness from inputs
Map<String, BigInteger> inputs = Map.of("a", BigInteger.valueOf(3), "b", BigInteger.valueOf(11));
byte[] witnessWtns = calculator.calculateWitness(inputs);

// Export to .wtns
Path wtnsPath = WitnessExporter.writeWtns(witnessWtns, tempDir);
// Or export for gnark
byte[] gnarkWitness = WitnessExporter.toGnarkBinary(witnessWtns, CurveId.BN254);
```

### Complete flow (all in JVM)

```java
// 1. Calculate witness (GraalWasm — no Node.js)
var calculator = new WasmWitnessCalculator(circuitWasmPath);
byte[] witness = calculator.calculateWitness(Map.of("a", "3", "b", "11"));

// 2. Prove with gnark FFM or the pure Java prover

// 3. Verify (pure Java — zero native deps)
var verifier = new Groth16BN254Verifier();
var result = verifier.verify(envelope, material);
```

## Implementation Steps

### Phase 1: Understand circom WASM interface

circom-generated `.wasm` files export these functions:
- `getFieldNumLen32()` → number of 32-bit limbs per field element
- `getVersion()` → circom version
- `getRawPrime()` → field prime as limbs
- `getWitnessSize()` → number of witness signals
- `init(sanityCheck)` → initialize the circuit
- `writeSharedRWMemory(index, value)` → write input signal limb
- `readSharedRWMemory(index)` → read output signal limb
- `setSignal(componentId, signalIndex, value)` → set input signal
- `getWitness(index)` → get witness signal value

Reference: snarkjs `wtns_calculate.js` and circom `calcwit.cpp`

### Phase 2: Implement WasmWitnessCalculator

1. Load `.wasm` via `Context.newBuilder("wasm")`
2. Call `init(1)` for sanity checking
3. For each input signal: decompose BigInteger into 32-bit limbs, write via `writeSharedRWMemory`/`setSignal`
4. Read all witness values via `getWitness`
5. Assemble into `.wtns` binary format (header + field elements)

### Phase 3: Wire into prover pipeline

1. `WasmWitnessCalculator` produces witness bytes
2. `WitnessExporter` converts to `.wtns` or gnark binary format
3. Prover takes witness + r1cs -> proof
4. Pure Java verifier checks proof

### Phase 4: Integration tests

- Multiplier circuit: compute witness for a=3, b=11, verify output c=33
- Compare witness output with snarkjs `wtns calculate` output (byte-for-byte)
- End-to-end: wasm witness -> gnark or pure Java prove -> pure Java verify

## Dependencies

```gradle
// zeroj-prover-wasm/build.gradle
dependencies {
    implementation 'org.graalvm.polyglot:polyglot:24.1.0'
    implementation 'org.graalvm.polyglot:wasm:24.1.0'
    implementation project(':zeroj-api')
}
```

Requires GraalVM JDK (already the project's toolchain: Java 25 GraalVM).

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| GraalWasm performance may be slower than Node.js | Witness calculation is fast (~ms); proving is the bottleneck, not witness calc |
| circom WASM import interface may change between versions | Pin to circom 2.x, test against multiple circom outputs |
| Some circom circuits use WASM features not yet in GraalWasm | GraalWasm supports WASM MVP + reference types; test with complex circuits |
| Memory management between Java and WASM | Use GraalVM managed memory; arena-based lifecycle |

## Success Criteria

- `WasmWitnessCalculator` produces identical witness bytes as `snarkjs wtns calculate`
- End-to-end: circom `.wasm` -> GraalWasm witness -> gnark or pure Java proof -> pure Java verify
- No Node.js process needed at any point
- Works with GraalVM native-image
