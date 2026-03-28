# zeroj-verifier-plonk

PlonK proof verification for BLS12-381 and BN254 curves.

This module provides pure Java PlonK verification, removing the gnark native dependency for the verification path. Proving still uses gnark (via `zeroj-prover-gnark`), but verification is done entirely in Java + blst.

| Backend | Curve | Implementation | Status |
|---------|-------|----------------|--------|
| `PlonkBLS12381Verifier` | BLS12-381 | Java + blst (pairing) | Full implementation |
| `PlonkBN254Verifier` | BN254 | Pure Java | Challenge derivation done, pairing TODO |

## Architecture

PlonK verification involves 6 steps:

1. **Fiat-Shamir challenge derivation** — re-derive beta, gamma, alpha, zeta, v, u from the proof transcript using SHA-256
2. **Vanishing polynomial** — evaluate Z_H(zeta) = zeta^n - 1
3. **Lagrange polynomial** — evaluate L_1(zeta) for the gate identity check
4. **Public input polynomial** — compute PI(zeta) from the public inputs and Lagrange basis
5. **Linearized commitment** — combine selector, permutation, and quotient commitments via MSM
6. **KZG pairing check** — verify the opening proofs via two pairings

## Key Classes

| Class | Purpose |
|-------|---------|
| `PlonkBLS12381Verifier` | Implements `ZkVerifier` SPI — full PlonK verification via blst pairings |
| `PlonkBN254Verifier` | Implements `ZkVerifier` SPI — BN254 PlonK (scaffold, challenge derivation complete) |
| `FiatShamirTranscript` | SHA-256 transcript for deterministic challenge generation |
| `KzgVerifier` | KZG polynomial commitment opening proof verification |
| `PlonkProof` | Parsed proof record (commitments + evaluations) |
| `PlonkVerificationKey` | Parsed VK record (selectors, permutations, SRS, domain) |

## Usage

```java
// Via SPI (auto-discovered by VerifierOrchestrator)
var registry = VerifierRegistry.discover(); // finds PlonkBLS12381Verifier

// Or direct
var verifier = new PlonkBLS12381Verifier();

// Parse snarkjs PlonK artifacts
var envelope = SnarkjsPlonkCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson,
        new CircuitId("my-circuit"));
var material = VerificationMaterial.of(vkBytes, ProofSystemId.PLONK,
        CurveId.BLS12_381, new CircuitId("my-circuit"), vkHash);

VerificationResult result = verifier.verify(envelope, material);
```

## Fiat-Shamir Transcript

The transcript must match the prover's byte layout exactly. The current implementation follows snarkjs's PlonK transcript format:

- Round 1: append A, B, C commitments → squeeze beta, gamma
- Round 2: append Z commitment → squeeze alpha
- Round 3: append T1, T2, T3 → squeeze zeta
- Round 4: append evaluations (a, b, c, s1, s2, z_omega) → squeeze v
- Round 5: append W_zeta, W_{zeta*omega} → squeeze u

## Test Vectors

- `zeroj-test-vectors/.../plonk-bn254/` — snarkjs PlonK BN254 (multiplier: 3 × 11 = 33)
- `zeroj-test-vectors/.../plonk-bls12381/` — gnark PlonK BLS12-381 (same circuit)

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-verifier-plonk'
}
```
