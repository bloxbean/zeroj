# zeroj-verifier-groth16

Groth16 proof verification for BN254 and BLS12-381 curves.

This module provides two verification backends:

| Backend | Curve | Implementation | Performance |
|---------|-------|----------------|-------------|
| `Groth16BN254Verifier` | BN254 | Pure Java | snarkjs/circom-compatible |
| `Groth16BLS12381PureJavaVerifier` | BLS12-381 | Pure Java | zero native dependencies |
| `Groth16BLS12381Verifier` | BLS12-381 | Native via blst | faster opt-in path |

## BN254 (Pure Java)

The BN254 backend is implemented entirely in Java with no native dependencies. It includes:
- Complete field arithmetic (`Fp`, `Fp2`, `Fp6`, `Fp12`)
- Elliptic curve operations (`G1Point`, `G2Point`) in projective coordinates
- Optimal ate pairing computation (`BN254Pairing`)
- Validated against Ethereum EIP-196/197 test vectors

The pairing check verifies: `e(A,B) * e(-alpha,beta) * e(-vk_x,gamma) * e(-C,delta) == 1`

## BLS12-381

The BLS12-381 pure Java backend uses `zeroj-bls12381` and requires no native
library. The blst-backed backend delegates pairing operations to `zeroj-blst`
for the faster native path. BLS12-381 is the same curve used by Cardano's
Plutus V3 BLS primitives.

## Usage

```java
// Register backends
var registry = VerifierRegistry.empty();
registry.register(new Groth16BN254Verifier());      // Pure Java
registry.register(new Groth16BLS12381PureJavaVerifier()); // Pure Java
registry.register(new Groth16BLS12381Verifier());         // Native blst

// Parse snarkjs artifacts and verify
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson,
        new CircuitId("my-circuit"));
var material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16,
        CurveId.BN254, new CircuitId("my-circuit"), vkHash);

var orchestrator = new VerifierOrchestrator(registry, vkRegistry);
VerificationResult result = orchestrator.verify(envelope, material);
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
}
```
