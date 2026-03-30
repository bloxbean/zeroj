# Alternate Prover Backends — gnark FFM, rapidsnark, snarkjs

## Table of Contents

- [Backend Comparison](#backend-comparison)
- [gnark FFM (Foreign Function & Memory)](#gnark-ffm-foreign-function--memory)
- [snarkjs CLI](#snarkjs-cli)
- [circom Integration](#circom-integration)
- [When to Use Each Backend](#when-to-use-each-backend)

---

ZeroJ's **recommended** prover is the [pure Java prover](pure-java-prover-guide.md) (`zeroj-crypto`), which requires zero native dependencies. This document covers the **alternate native backends** for cases where you need:

- Maximum proving speed (~10-100x faster for large circuits)
- Compatibility with existing gnark/snarkjs workflows
- BN254 curve support (pure Java prover focuses on BLS12-381 for Cardano)

## Backend Comparison

| Backend | Proof Systems | Curves | Speed | Dependencies | Module |
|---------|-------------|--------|-------|-------------|--------|
| **Pure Java** | Groth16, PlonK | BN254, BLS12-381 | Baseline | None | `zeroj-crypto` |
| **gnark FFM** | Groth16, PlonK | BN254, BLS12-381 | ~10-50x faster | Go native lib | `zeroj-prover-gnark` |
| **rapidsnark FFM** | Groth16 only | BN254 only | ~50-100x faster | C++ native lib | `zeroj-prover-rapidsnark` |
| **snarkjs CLI** | Groth16, PlonK | BN254, BLS12-381 | Slowest | Node.js + snarkjs | (external process) |

## gnark FFM (Foreign Function & Memory)

The gnark prover runs **inside the JVM** via Java 22+ Foreign Function & Memory API. No external process, no CLI.

### Setup

```bash
# Build the gnark native library (requires Go 1.21+)
cd zeroj-prover-gnark/gnark-wrapper && make build
```

### Usage — Groth16

```java
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;

// Define circuit and compile R1CS (same as pure Java path)
var circuit = MyCircuit.build();
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
byte[] r1csBytes = R1CSSerializer.serialize(r1cs);
byte[] wtnsBytes = WitnessExporter.toWtns(witness, r1cs.prime(), r1cs.fieldConfig().n32());

// Prove with gnark (in-process, no external CLI)
try (var prover = new GnarkProver()) {
    var result = prover.groth16FullProve(r1csBytes, wtnsBytes, "bls12381");

    String proofJson = result.proveResponse().proofJson();
    String vkJson = result.vkJson();
    String publicJson = result.proveResponse().publicInputsJson();
}
```

### Usage — PlonK

```java
try (var prover = new GnarkProver()) {
    var result = prover.plonkFullProve(r1csBytes, wtnsBytes, "bls12381");
    // Same JSON format as Groth16
}
```

### Verification

gnark proofs are verified using the same pure Java verifiers:

```java
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, circuitId);
var verifier = new Groth16BLS12381PureJavaVerifier();
var result = verifier.verify(envelope, material);
```

### Gradle

```gradle
implementation 'com.bloxbean.cardano:zeroj-prover-gnark'
```

## snarkjs CLI

For teams already using snarkjs workflows. Runs as an external Node.js process.

### Prerequisites

```bash
npm install -g snarkjs
```

### Usage

```java
import com.bloxbean.cardano.zeroj.examples.dsl.common.SnarkjsProver;

var snarkjs = new SnarkjsProver();

// 1. Generate Powers of Tau
Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);

// 2. Groth16 setup
var setup = snarkjs.groth16Setup(r1csBytes, ptau, workDir);

// 3. Prove
var proof = snarkjs.groth16Prove(setup.zkeyFile(), wtnsBytes, workDir, setup.vkJson());

// 4. Verify (via snarkjs CLI)
boolean valid = snarkjs.groth16Verify(workDir);
```

### Mixing: snarkjs Setup + Pure Java Prove

You can use snarkjs for the trusted setup ceremony and the pure Java prover for proof generation:

```java
// Import snarkjs .zkey (from multi-party ceremony)
var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(Path.of("circuit.zkey")));

// Prove with pure Java (no snarkjs needed at runtime)
var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness,
    zkeyData.constraints(), zkeyData.numWires());
```

This is the **recommended production pattern**: ceremony via snarkjs, proving via pure Java.

## circom Integration

Circuits written in circom work with all backends:

```bash
# Compile circom → R1CS
circom circuit.circom --r1cs --wasm --sym -p bls12381

# Generate witness
node circuit_js/generate_witness.js circuit.wasm input.json witness.wtns

# Setup via snarkjs
snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit.zkey
```

Then prove with any backend:

```java
// Pure Java
var zkeyData = ZkeyImporterBLS381.importZkeyFull(zkeyBytes);
var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness, ...);

// OR gnark FFM
var proof = prover.groth16Prove(zkeyPath, wtnsPath, workDir);

// OR snarkjs CLI
var proof = snarkjs.groth16Prove(zkeyPath, wtnsPath, workDir);
```

## When to Use Each Backend

| Scenario | Recommended Backend |
|----------|-------------------|
| **Cardano on-chain verification** | Pure Java (BLS12-381) |
| **Development / testing** | Pure Java (zero setup, instant) |
| **Large circuits (>10K constraints)** | gnark FFM (10-50x faster) |
| **BN254 proofs (Ethereum)** | gnark FFM or rapidsnark |
| **Existing snarkjs workflow** | snarkjs CLI → import .zkey → pure Java prove |
| **Mobile / serverless** | Pure Java (no native deps, GraalVM compatible) |
| **CI/CD pipelines** | Pure Java (no build toolchain needed) |
