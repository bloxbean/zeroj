# ZeroJ

Java-first ZK verification platform for Cardano.

ZeroJ provides zero-knowledge proof verification for Java developers building on Cardano, with integration across Yaci app-layer networks and Cardano Client Lib (CCL).

## Architecture

ZeroJ follows a **verifier-first** design — proofs are generated externally (snarkjs, gnark, arkworks, etc.) and verified in Java.

### Supported Proof Systems
- **Groth16** — BN254 (pure Java) and BLS12-381 (via blst native library)
- PlonK, fflonk, Halo2 — planned via SPI backends

### Modules

| Module | Description |
|--------|-------------|
| `zeroj-api` | Core proof model, envelopes, and verification result types |
| `zeroj-codec` | Proof serialization — snarkjs JSON, CBOR, canonical hashing |
| `zeroj-backend-spi` | Service Provider Interface for verification backends |
| `zeroj-verifier-core` | Verifier orchestration and backend routing |
| `zeroj-verifier-groth16` | Groth16 verification — BN254 + BLS12-381 |
| `zeroj-blst` | BLS12-381 curve operations via blst |
| `zeroj-test-vectors` | Shared test fixtures (pre-generated proofs, VKs) |
| `zeroj-bom` | Bill of Materials for version alignment |

## Requirements

- Java 25 (GraalVM recommended)
- Gradle 9.2+

## Building

```bash
./gradlew build
```

## Usage

Add the BOM to your project:

```gradle
dependencies {
    implementation platform('com.bloxbean.cardano:zeroj-bom:0.1.0')
    implementation 'com.bloxbean.cardano:zeroj-verifier-core'
    implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
}
```

## License

MIT License — see [LICENSE](LICENSE) for details.
