# zeroj-verifier-groth16

Groth16 proof verification for BLS12-381, the Cardano-supported pairing curve.

This module provides two default verification backends:

| Backend | Curve | Implementation | Performance |
|---------|-------|----------------|-------------|
| `Groth16BLS12381PureJavaVerifier` | BLS12-381 | Pure Java | zero native dependencies |
| `Groth16BLS12381Verifier` | BLS12-381 | Native via blst | faster opt-in path |

## BN254 Legacy Path

`Groth16BN254Verifier` remains in the codebase for legacy off-chain tests, but it
is **not registered via ServiceLoader** and verification is disabled by default.
BN254 is not supported by Cardano Plutus builtins. To run legacy experiments
explicitly, start the JVM with `-Dzeroj.allowLegacyBn254=true`.

## BLS12-381

The BLS12-381 pure Java backend uses `zeroj-bls12381` and requires no native
library. The blst-backed backend delegates pairing operations to `zeroj-blst`
for the faster native path. BLS12-381 is the same curve used by Cardano's
Plutus V3 BLS primitives.

## Usage

```java
// Register backends
var registry = VerifierRegistry.empty();
registry.register(new Groth16BLS12381PureJavaVerifier()); // Pure Java
registry.register(new Groth16BLS12381Verifier());         // Native blst

// Parse snarkjs artifacts and verify
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson,
        new CircuitId("my-circuit"));
var material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16,
        CurveId.BLS12_381, new CircuitId("my-circuit"), vkHash);

var orchestrator = new VerifierOrchestrator(registry, vkRegistry);
VerificationResult result = orchestrator.verify(envelope, material);
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
}
```
