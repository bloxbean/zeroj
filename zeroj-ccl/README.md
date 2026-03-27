# zeroj-ccl

Cardano Client Lib (CCL) integration for attaching ZK proof metadata to transactions.

This module provides fluent helpers that bridge ZeroJ's proof verification with [cardano-client-lib](https://github.com/bloxbean/cardano-client-lib) transaction building. It creates CIP-10 metadata objects that can be attached directly to CCL transactions.

## Key Types

| Type | Description |
|------|-------------|
| `ZkTransactionHelper` | Fluent builder for proof anchor metadata with optional verify-before-anchor |

## Usage

```java
// Simple: anchor a proof hash
Metadata metadata = ZkTransactionHelper.anchorProofHash(proofHash)
        .buildMetadata();

// Anchor state root + proof hash
Metadata metadata = ZkTransactionHelper.anchorStateRoot(stateRoot, proofHash)
        .buildMetadata();

// Full verification reference
Metadata metadata = ZkTransactionHelper.anchorFullRef(stateRoot, proofHash, "multiplier/v1", vkHash)
        .buildMetadata();

// Nullifier commitment
Metadata metadata = ZkTransactionHelper.anchorNullifier(nullifierHash)
        .buildMetadata();

// Verify proof before anchoring (recommended)
Metadata metadata = ZkTransactionHelper.anchorProofHash(proofHash)
        .validateAndBuildMetadata(envelope, material, orchestrator);

// Custom CIP-10 label
Metadata metadata = ZkTransactionHelper.anchorProofHash(proofHash)
        .withLabel(9999L)
        .buildMetadata();
```

The `validateAndBuildMetadata` method verifies the proof cryptographically before generating metadata, preventing invalid proofs from being anchored on-chain.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-ccl'
}
```

This transitively brings in `cardano-client-lib:0.7.1`.
