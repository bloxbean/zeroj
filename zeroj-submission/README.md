# zeroj-submission

Proof submission wire format, Ed25519 signatures, and result types.

This module defines the data model for **proof-backed state transition submissions**. A submission represents a signed request to transition application state, backed by a ZK proof. It includes the proof, public inputs, state roots, submitter identity, and an Ed25519 signature.

## Key Types

| Type | Description |
|------|-------------|
| `AppProofSubmission` | Immutable submission message — app ID, proof, state roots, submitter signature, sequence number |
| `SubmissionResult` | Result of pipeline processing — accepted/rejected, stage, reason, message |
| `SubmissionHash` | Deterministic SHA-256 hash of submission fields for Ed25519 signing |
| `Ed25519Signer` | Generate key pairs, sign submission hashes, verify signatures |

### Validation Stages

| Stage | Description |
|-------|-------------|
| `SYNTACTIC` | Proof non-empty, VK hash valid, public inputs present |
| `SIGNATURE` | Ed25519 signature valid, submitter known and authorized |
| `CIRCUIT_RESOLUTION` | Circuit allowed, VK found in registry |
| `CRYPTOGRAPHIC_VERIFICATION` | ZK proof is valid |
| `POLICY` | State root chain, sequence ordering, nullifier uniqueness |
| `ACCEPTED` | All checks passed, state updated |

### Rejection Reasons

`EMPTY_PROOF`, `INVALID_VK_HASH_LENGTH`, `MALFORMED_SUBMISSION`, `INVALID_SIGNATURE`, `UNKNOWN_SUBMITTER`, `UNAUTHORIZED_SUBMITTER`, `UNKNOWN_CIRCUIT`, `RETIRED_CIRCUIT`, `VK_NOT_FOUND`, `PROOF_INVALID`, `PROOF_VERIFICATION_ERROR`, `STALE_STATE_ROOT`, `DUPLICATE_SEQUENCE`, `USED_NULLIFIER`, `SEQUENCE_GAP`

## Usage

```java
// Generate submitter keys
KeyPair keys = Ed25519Signer.generateKeyPair();

// Build a submission
var submission = AppProofSubmission.builder()
        .appId("my-app")
        .proofSystem(ProofSystemId.GROTH16)
        .curve(CurveId.BN254)
        .circuitId("multiplier")
        .circuitVersion("v1")
        .prevStateRoot(currentRoot)
        .newStateRoot(newRoot)
        .publicInputs(List.of(BigInteger.valueOf(33)))
        .proofBytes(proofBytes)
        .vkHash(vkHash)
        .submitterId("alice")
        .submitterSignature(new byte[64])  // placeholder
        .sequence(1)
        .build();

// Sign with Ed25519
byte[] hash = SubmissionHash.compute(submission);
byte[] signature = Ed25519Signer.sign(hash, keys.getPrivate());
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-submission'
}
```
