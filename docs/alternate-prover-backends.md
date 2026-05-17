# Alternate Prover Backends — gnark FFM and snarkjs

## Table of Contents

- [Backend Comparison](#backend-comparison)
- [gnark FFM (Foreign Function & Memory)](#gnark-ffm-foreign-function--memory)
- [snarkjs CLI](#snarkjs-cli)
- [circom Integration](#circom-integration)
- [When to Use Each Backend](#when-to-use-each-backend)

---

ZeroJ's **recommended** prover is the [pure Java prover](pure-java-prover-guide.md) (`zeroj-crypto`), which requires zero native dependencies. This document covers the **alternate native backends** for cases where you need:

- Integration with a native proving library
- Compatibility with existing gnark/snarkjs workflows
- External ceremony or proof-generation tooling

## Backend Comparison

| Backend | Proof Systems | Curves | Dependencies | Module |
|---------|-------------|--------|--------------|--------|
| **Pure Java** | Groth16, PlonK | BN254, BLS12-381 | None | `zeroj-crypto` |
| **gnark FFM** | Groth16, PlonK | BN254, BLS12-381 | Go native lib | `zeroj-prover-gnark` |
| **snarkjs CLI** | Groth16, PlonK | BN254, BLS12-381 | Node.js + snarkjs | external process |

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

// Prove with gnark (in-process, no external CLI)
try (var prover = new GnarkProver()) {
    var result = prover.groth16FullProve(r1cs, witness, CurveId.BLS12_381);

    String proofJson = result.proveResponse().proofJson();
    String vkJson = result.vkJson();
    List<BigInteger> publicSignals = result.proveResponse().publicSignals();
    String publicJson = publicSignals.stream()
            .map(v -> "\"" + v + "\"")
            .collect(java.util.stream.Collectors.joining(",", "[", "]"));
}
```

### Usage — PlonK

```java
try (var prover = new GnarkProver()) {
    var result = prover.plonkFullProve(r1cs, witness, CurveId.BLS12_381);
    // gnark binary PlonK proof JSON; verify with gnark until an adapter lands
}
```

### Verification

For Groth16, gnark and snarkjs artifacts can be normalized into the same
envelope model and verified by the pure Java verifiers:

```java
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, circuitId);
var verifier = new Groth16BLS12381PureJavaVerifier();
var result = verifier.verify(envelope, material);
```

For PlonK, the pure Java verifiers consume structured snarkjs/ZeroJ proof JSON.
gnark's opaque binary PlonK proof JSON is kept as a typed artifact and should be
verified with gnark native verification until a dedicated decoder/adapter is
implemented.

### Gradle

```gradle
implementation platform('com.bloxbean.cardano:zeroj-bom-all:0.1.0')
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

This is the recommended ceremony/import pattern when evaluating a setup beyond local single-party test keys.

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
| **Cardano on-chain verification** | Pure Java BLS12-381 path |
| **Development / testing** | Pure Java local setup |
| **Native proving acceptable** | gnark FFM |
| **Existing snarkjs workflow** | snarkjs CLI for setup/artifacts, then import `.zkey` |
| **Mobile / serverless** | Pure Java path |
| **CI/CD pipelines** | Pure Java path when native build toolchains are undesirable |
