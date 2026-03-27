# zeroj-test-vectors

Shared test fixtures for ZeroJ — pre-generated proofs, verification keys, and public inputs.

This module contains test resources used across multiple ZeroJ modules. It is **not published** to Maven Central — it is a test-only dependency.

## Contents

| Directory | Description |
|-----------|-------------|
| `test-vectors/groth16-bn254/` | Groth16/BN254 proof, VK, public inputs (snarkjs format) |
| `test-vectors/groth16-bls12381/` | Groth16/BLS12-381 proof, VK, public inputs |
| `test-vectors/eip197-bn254-pairing/` | Ethereum EIP-197 pairing test vectors for BN254 validation |
| `test-vectors/plonk-bls12381/` | PlonK/BLS12-381 test vectors (gnark format) |

## Test Circuit

The primary test circuit proves `a * b = c` (public: `[c, a]`, private: `b`).
- Example: `3 * 11 = 33` with public inputs `[33, 3]`

## Usage

Used as a test dependency in other modules:

```gradle
dependencies {
    testImplementation project(':zeroj-test-vectors')
}
```

Test resources are loaded via classpath:

```java
String proofJson = loadResource("/test-vectors/groth16-bn254/proof.json");
String vkJson = loadResource("/test-vectors/groth16-bn254/verification_key.json");
String publicJson = loadResource("/test-vectors/groth16-bn254/public.json");
```
