# zeroj-cardano

Cardano proof anchoring model and CIP-10 metadata encoding.

This module provides the data model and encoding for anchoring ZK proof results on Cardano L1. It defines four anchor patterns that trade off on-chain footprint against verifiability, and encodes them as CIP-10 transaction metadata.

## Anchor Patterns

| Pattern | On-Chain Data | Use Case |
|---------|---------------|----------|
| `PROOF_HASH_ONLY` | Proof hash (~32 bytes) | Minimal footprint; proof available off-chain |
| `STATE_ROOT_AND_PROOF_HASH` | State root + proof hash (~64 bytes) | State machine verification |
| `FULL_VERIFICATION_REF` | State root + circuit ID + VK hash (~96+ bytes) | Full on-chain verifiability reference |
| `NULLIFIER_COMMITMENT` | Nullifier hash | Privacy-preserving double-spend prevention |

## Key Types

| Type | Description |
|------|-------------|
| `ProofAnchor` | Immutable anchor with pattern, proof hash, optional state root / circuit ID / VK hash / nullifier |
| `AnchorPattern` | Enum defining the four anchoring strategies |
| `AnchorMetadataEncoder` | CIP-10 metadata encoding with configurable label (default: `7270`) |

## Usage

```java
// Build an anchor
var anchor = ProofAnchor.builder()
        .pattern(AnchorPattern.FULL_VERIFICATION_REF)
        .proofHash(proofHash)
        .stateRoot(stateRoot)
        .circuitId("multiplier/v1")
        .vkHash(vkHash)
        .build();

// Encode as CIP-10 metadata
byte[] metadata = AnchorMetadataEncoder.encode(anchor);
```

This module is Cardano-aware but does not depend on `cardano-client-lib`. For transaction building integration, use `zeroj-ccl`.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-cardano'
}
```
