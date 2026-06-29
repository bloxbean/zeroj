# zeroj-api

Core proof model, envelopes, and verification result types for ZeroJ.

This module defines the foundational data types shared across all ZeroJ modules. It has **no external dependencies** and serves as the lingua franca of the entire library.

## Key Types

| Type | Description |
|------|-------------|
| `ZkProofEnvelope` | Immutable container for a ZK proof — proof bytes, public inputs, VK reference, circuit ID, proof system, curve |
| `VerificationResult` | Separates cryptographic validity from policy validity with typed reason codes |
| `VerificationMaterial` | VK bytes + proof system/curve/circuit metadata for verification |
| `ProofSystemId` | Enum: `GROTH16`, `PLONK`, `FFLONK`, `HALO2`, `BBS` |
| `CurveId` | Enum: `BLS12_381`, `PALLAS`, and legacy/off-chain `BN254` |
| `CircuitId` | Typed wrapper for circuit identifiers (non-blank string) |
| `PublicInputs` | Immutable list of `BigInteger` field elements |
| `VerificationKeyRef` | Sealed interface — `ByHash` (SHA-256) or `ById` (named registry lookup) |
| `Witness` | Opaque witness data for provers (byte array with defensive copy) |

## Design Principles

- **Immutability**: All types are immutable. Byte arrays are defensively copied on construction and access.
- **Fail-fast**: Constructors reject `null`, empty, or malformed inputs immediately.
- **No dependencies**: This module depends on nothing — it can be used standalone.
- **GraalVM compatible**: No reflection required; native-image configs included.

## Usage

```java
// Build a proof envelope
var envelope = ZkProofEnvelope.builder()
        .proofSystem(ProofSystemId.GROTH16)
        .curve(CurveId.BLS12_381)
        .circuitId(new CircuitId("multiplier"))
        .proofBytes(proofBytes)
        .publicInputs(PublicInputs.of(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3))))
        .vkRef(VerificationKeyRef.byHash(vkHash))
        .build();

// Build verification material
var material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16,
        CurveId.BLS12_381, new CircuitId("multiplier"), vkHash);
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-api'
}
```
