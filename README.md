# ZeroJ

Java-first zero-knowledge proof toolkit for Cardano.

ZeroJ lets Java developers **define ZK circuits**, **generate proofs**, **verify** them off-chain, and **execute on-chain verification** on Cardano — all without leaving the Java ecosystem.

## What You Can Do Today

### Define ZK Circuits
- **Java Circuit DSL** — define circuits in pure Java (no circom, no Go, no Rust)
- **circom support** — use existing circom circuits (`.circom` → `.r1cs` + `.wasm`); witness calculation via GraalVM WASM (incubator) or snarkjs CLI
- **Standard library** — Poseidon, MiMC, Merkle proofs, comparators, binary ops
- **Multi-backend** — single Java DSL circuit compiles to Groth16 (R1CS), PlonK, or Halo2

### Generate Proofs
- **gnark FFM** — in-process Groth16/PlonK proving via Go native library (primary)
- **snarkjs** — external CLI for circom-based circuits
- **rapidsnark** — native BN254 Groth16 prover (incubator)

### Verify ZK Proofs in Java (Pure Java, Zero Native Deps)
- **Groth16 BN254** — pure Java verification
- **Groth16 BLS12-381** — pure Java verification (also available via blst for ~1ms perf)
- **PlonK BN254/BLS12-381** — pure Java verification, byte-for-byte verified against gnark
- **Halo2 IPA** — via Rust FFM bindings (incubator)
- Parse snarkjs proof artifacts (`proof.json`, `verification_key.json`, `public.json`)
- Pluggable backend SPI — add new proof systems without changing application code

### Verify On-Chain (Cardano Plutus V3)
- **Groth16 BLS12-381** — reusable Plutus V3 spending validator via Julc
- **PlonK BLS12-381** — full on-chain PlonK verifier with Fiat-Shamir transcript
- VK baked at deploy time, proof passed as redeemer, public inputs as datum
- Tested end-to-end on Yaci DevKit

### Anchor on Cardano L1
- 4 anchor patterns: proof hash, state root + proof hash, full verification ref, nullifier commitment
- CCL integration — fluent helpers for attaching proof metadata to transactions
- Validation-before-anchoring — verify proof before committing to chain

### Use Standard ZK Patterns
- **State Transition** — prove new_state = f(old_state) without revealing f or its inputs
- **Nullifier Claim** — one-time claims with double-spend prevention
- **Membership Proof** — prove set membership + constraints without revealing which element

## Getting Started

See the **[Getting Started Guide](docs/getting-started.md)** for a complete walkthrough from circuit definition to on-chain verification.

Quick overview of the two circuit paths:

```
Path 1: Java DSL (recommended)          Path 2: circom
─────────────────────────                ──────────────────
Java DSL (define circuit)                circom CLI (.circom → .r1cs + .wasm)
    |                                        |
    v                                        v
Compile to R1CS / PlonK  (pure Java)     Load .r1cs + witness via WASM or snarkjs
    |                                        |
    +────────────────────────────────────────+
    |
    v
Generate proof via gnark FFM    (in-process, no external tools)
    |
    v
Verify off-chain in Java        (pure Java, zero native deps)
    |
    v
Submit on-chain via Julc         (Plutus V3, BLS12-381 pairings)
    |
    v
Execute on Yaci DevKit / Cardano mainnet
```

## Prerequisites

### Required

| Dependency | Version | Notes |
|------------|---------|-------|
| **Java** | 25+ | GraalVM recommended for native-image support |
| **Gradle** | 9.2+ | Included via wrapper (`./gradlew`) |

Install Java 25 with [SDKMAN!](https://sdkman.io/):

```bash
sdk install java 25.0.2-graal
sdk use java 25.0.2-graal
```

### Optional (for specific modules)

| Dependency | Version | Required By | Notes |
|------------|---------|-------------|-------|
| **Go** | 1.21+ | `zeroj-prover-gnark` | Compile gnark native library |
| **Rust** | stable | `zeroj-verifier-halo2` (incubator) | Compile halo2 native library |
| **circom** | 2.x | Circuit compilation (if using circom) | `cargo install circom` |
| **snarkjs** | 0.7+ | Proof generation (if using snarkjs) | `npm install -g snarkjs` |
| **Node.js** | 18+ | snarkjs runtime | -- |

## Building

### Core library (no native dependencies needed)

```bash
./gradlew build
```

This builds and tests all modules. The core verification (Groth16 + PlonK, both BN254 and BLS12-381) is pure Java and requires no native libraries.

### gnark native library (optional)

Required only if you use `zeroj-prover-gnark` for in-process proving:

```bash
cd zeroj-prover-gnark/gnark-wrapper
make build
```

### Run tests

```bash
./gradlew test
```

### Run the end-to-end demo

```bash
./gradlew :zeroj-examples:run
```

## Architecture

ZeroJ follows a **verifier-first** design. Circuits can be defined in Java (DSL) or externally (circom, gnark Go). Proofs are generated in-process (gnark FFM) or externally (snarkjs). Verification is pure Java. On-chain verification uses Julc-compiled Plutus V3 validators.

```
                Java Circuit DSL
                      |
             +--------+--------+
             |                 |
         compileR1CS()    compilePlonK()
             |                 |
       gnark FFM prove    gnark FFM prove
             |                 |
             +--------+--------+
                      |
              Pure Java Verify
           (Groth16 / PlonK verifiers)
                      |
              On-Chain Verify (Julc)
           (Plutus V3, BLS12-381 pairings)
```

### Module Organization

ZeroJ modules are split into **core** (top-level) and **incubator** (experimental/alternative):

#### Core Modules

| Module | Description |
|--------|-------------|
| [`zeroj-api`](zeroj-api/) | Core proof model, envelopes, verification result types |
| [`zeroj-codec`](zeroj-codec/) | Proof serialization -- snarkjs JSON, CBOR, canonical hashing |
| [`zeroj-backend-spi`](zeroj-backend-spi/) | Service Provider Interface for verification backends |
| [`zeroj-verifier-core`](zeroj-verifier-core/) | Verifier orchestration and backend routing |
| [`zeroj-verifier-groth16`](zeroj-verifier-groth16/) | Groth16 verification -- BN254 (pure Java) + BLS12-381 (pure Java / blst) |
| [`zeroj-verifier-plonk`](zeroj-verifier-plonk/) | PlonK verification -- BN254 + BLS12-381 (pure Java) |
| [`zeroj-blst`](zeroj-blst/) | BLS12-381 pairing operations via blst native library |
| [`zeroj-circuit-dsl`](zeroj-circuit-dsl/) | Java Circuit DSL -- define circuits, compile to R1CS/PlonK/Halo2 |
| [`zeroj-circuit-lib`](zeroj-circuit-lib/) | Circuit standard library -- Poseidon, MiMC, Merkle, comparators |
| [`zeroj-prover-gnark`](zeroj-prover-gnark/) | gnark native prover (Groth16 + PlonK) via FFM |
| [`zeroj-patterns`](zeroj-patterns/) | High-level ZK patterns -- state transitions, nullifier claims, membership proofs |
| [`zeroj-submission`](zeroj-submission/) | Proof submission wire format, Ed25519 signatures |
| [`zeroj-ingestion`](zeroj-ingestion/) | Submission ingestion pipeline, governance, security checks |
| [`zeroj-cardano`](zeroj-cardano/) | Cardano anchoring -- proof anchor model, metadata encoding |
| [`zeroj-ccl`](zeroj-ccl/) | Cardano Client Lib integration -- fluent transaction helpers |
| [`zeroj-onchain-julc`](zeroj-onchain-julc/) | Reusable Plutus V3 on-chain verifiers (Groth16 + PlonK) via Julc |
| [`zeroj-test-vectors`](zeroj-test-vectors/) | Shared test fixtures -- pre-generated proofs and VKs |
| [`zeroj-examples`](zeroj-examples/) | End-to-end demos: DSL circuit to on-chain verification |
| [`zeroj-bom`](zeroj-bom/) | Bill of Materials for version alignment |

#### Incubator Modules (`incubator/`)

Experimental and alternative backends. Still compiled, tested, and published -- just visually separated.

| Module | Description |
|--------|-------------|
| [`zeroj-prover-rapidsnark`](incubator/zeroj-prover-rapidsnark/) | RapidSNARK native prover -- BN254 Groth16 via FFM |
| [`zeroj-prover-sidecar`](incubator/zeroj-prover-sidecar/) | HTTP client for external prover services |
| [`zeroj-prover-wasm`](incubator/zeroj-prover-wasm/) | Circom witness calculation via GraalVM WebAssembly |
| [`zeroj-verifier-halo2`](incubator/zeroj-verifier-halo2/) | Halo2 IPA verification via Rust FFM (no trusted setup) |
| [`zeroj-onchain-experimental`](incubator/zeroj-onchain-experimental/) | On-chain helpers -- proof preparation, budget estimation |

## Quick Start

### Define and Prove a Circuit (Java DSL + gnark)

```java
// 1. Define the circuit
var circuit = CircuitBuilder.create("multiplier")
    .publicVar("z")
    .secretVar("x")
    .secretVar("y")
    .define(api -> {
        var product = api.mul(api.var("x"), api.var("y"));
        api.assertEqual(product, api.var("z"));
    });

// 2. Compile to R1CS and calculate witness
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
var witness = circuit.calculateWitness(Map.of(
    "z", List.of(BigInteger.valueOf(33)),
    "x", List.of(BigInteger.valueOf(3)),
    "y", List.of(BigInteger.valueOf(11))
), CurveId.BLS12_381);

// 3. Prove in-process via gnark
try (var prover = new GnarkProver()) {
    var result = prover.groth16FullProve(r1csBytes, witnessBytes, "bls12381");
}
```

### Verify a Groth16 Proof (Pure Java)

```java
// Load proof artifacts (snarkjs format)
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson,
        new CircuitId("my-circuit"));

// Verify -- pure Java, zero native dependencies
var verifier = new Groth16BLS12381PureJavaVerifier();
VerificationResult result = verifier.verify(envelope, material);

if (result.proofValid()) {
    System.out.println("Proof verified!");
}
```

### Dependency (Gradle)

```gradle
dependencies {
    implementation platform('com.bloxbean.cardano:zeroj-bom:0.1.0')

    // Circuit definition
    implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'
    implementation 'com.bloxbean.cardano:zeroj-circuit-lib'

    // Verification (pure Java)
    implementation 'com.bloxbean.cardano:zeroj-verifier-core'
    implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
    implementation 'com.bloxbean.cardano:zeroj-verifier-plonk'

    // Proving (gnark FFM)
    implementation 'com.bloxbean.cardano:zeroj-prover-gnark'

    // Cardano integration
    implementation 'com.bloxbean.cardano:zeroj-cardano'
    implementation 'com.bloxbean.cardano:zeroj-ccl'
}
```

## Documentation

- **[Getting Started Guide](docs/getting-started.md)** -- end-to-end: DSL to on-chain
- [Circuit DSL User Guide](docs/circuit-dsl-user-guide.md)
- [Architecture Overview](docs/architecture-overview.md)
- [PlonK Support](docs/plonk-support.md)
- [ADR: Verifier-First Architecture](docs/adr/0001-verifier-first-architecture.md)
- [ADR: External Proof Submission](docs/adr/0002-external-proof-submission-first-class.md)
- [ADR: Hybrid Crypto Backend](docs/adr/0003-pure-java-mvp.md)
- [ADR: Off-Chain Cardano Anchoring](docs/adr/0004-off-chain-cardano-anchoring-first.md)
- [ADR: Crypto / Policy Separation](docs/adr/0006-separation-of-crypto-and-policy-verification.md)
- [ADR: Module Structure](docs/adr/0007-module-structure-and-boundaries.md)
- [ADR: PlonK via gnark](docs/adr/0008-plonk-support-via-gnark.md)
- [ADR: Halo2 Strategy](docs/adr/0009-halo2-support-strategy.md)
- [ADR: Java Circuit DSL](docs/adr/0010-java-circuit-dsl.md)
- [Contributing Guide](CONTRIBUTING.md)

## License

MIT License -- see [LICENSE](LICENSE) for details.
