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

### Commitment contracts (`org.zeroj.api.commitment`, ADR-0059, experimental)

Profile-independent types for commitments, specified in
[`commitment-profiles-v1`](../docs/specs/commitment-profiles-v1.md) §12.1. They perform no group
arithmetic and hold no secret; the Jubjub Pedersen profiles in `zeroj-circuit-lib` implement them.

| Type | Description |
|------|-------------|
| `CommitmentProfileId`, `CommitmentProfile` | Registry identifier (§2.1 grammar) and the one descriptor per profile; compare descriptors with `==` |
| `CommitmentKind`, `CommitmentGroup` | `SCALAR`/`BYTES`/`VECTOR`; `JUBJUB`/`BLS12_381_G1` (separate from `CurveId`) |
| `Commitment`, `CommitmentCodec<C>` | A commitment of one profile; the expected profile's strict decoder, taken from your configuration |
| `CommitmentEnvelope` | Off-chain container `0x01 ‖ u8(len) ‖ id ‖ point`; decoded only under the expected codec, never by its embedded identifier. Not authentication |
| `CommitmentKey` | Map/set key over profile, point and context (schema digest for vectors). Use it instead of a commitment's `equals` |
| `CommitmentAcceptance`, `ProvenancePolicy`, `OpeningCheck`, `CommitmentCheck` | Decode, provenance and opening in one call; accepted only if all three succeed. Format errors, provenance results and a false opening become the result's reason; exceptions from the provenance rule, an opening check's `INVALID_CONFIGURATION` and `IOException` propagate |
| `CommitmentError`, `CommitmentFormatException` | The error classes; the exception extends `IllegalArgumentException` |

The expected profile (and, for vectors, the schema: the envelope carries none) always comes from
your trusted configuration. A matching label is not provenance; authenticate the association of
point, profile and context where issuance matters. An opening check is usually a variable-time
disclosed verification: run it where the opening is already public or nobody it is still secret
from can observe the verifier's timing (spec §6.2).

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
    implementation 'org.zeroj:zeroj-api'
}
```
