# zeroj-ingestion

6-stage submission ingestion pipeline with governance, security, and audit.

This module orchestrates the complete validation of proof-backed state transition submissions. It enforces a strict 6-stage pipeline with fail-fast semantics: if any stage rejects, processing stops immediately with a typed rejection reason.

## Pipeline Stages

```
Submission
    |
    v
1. SYNTACTIC       -- proof non-empty, VK hash 32 bytes, public inputs present
    |
2. SIGNATURE       -- Ed25519 valid, submitter known, authorized for app
    |
3. CIRCUIT         -- circuit allowed (not retired), VK found in registry
    |
4. CRYPTOGRAPHIC   -- delegate to VerifierOrchestrator (actual proof verification)
    |
5. POLICY          -- state root chain valid, sequence monotonic, nullifier unused
    |
6. ACCEPT          -- update state root, record sequence, mark nullifier used
    |
    v
SubmissionResult (accepted/rejected + stage + reason)
```

## Key Types

### Pipeline

| Type | Description |
|------|-------------|
| `SubmissionIngestionPipeline` | Orchestrates all 6 stages; fail-fast on first rejection |

### Governance Interfaces

| Interface | Purpose | In-Memory Implementation |
|-----------|---------|--------------------------|
| `CircuitAllowlist` | Allow/retire circuit ID + version combinations | `InMemoryCircuitAllowlist` |
| `CircuitRegistry` | Extended lifecycle: ACTIVE -> DEPRECATED -> RETIRED | `InMemoryCircuitRegistry` |
| `SubmitterRegistry` | Ed25519 public keys + app authorization per submitter | `InMemorySubmitterRegistry` |
| `VersionedVkRegistry` | VK rotation with transition windows per circuit | `VersionedVkRegistry` |

### Security Stores

| Interface | Purpose | In-Memory Implementation |
|-----------|---------|--------------------------|
| `StateRootStore` | Track current accepted state root per app | `InMemoryStateRootStore` |
| `SequenceTracker` | Enforce monotonically increasing sequences (replay protection) | `InMemorySequenceTracker` |
| `NullifierStore` | Track used nullifiers (double-spend prevention) | `InMemoryNullifierStore` |

### Audit

| Type | Description |
|------|-------------|
| `AuditLog` | Immutable record of all submission results | `InMemoryAuditLog` |

All in-memory implementations are thread-safe (using `ConcurrentHashMap` / `CopyOnWriteArrayList`).

## Usage

```java
// Set up governance infrastructure
var submitterReg = new InMemorySubmitterRegistry();
submitterReg.register("alice", alicePublicKey, "my-app");

var circuitAllowlist = new InMemoryCircuitAllowlist();
circuitAllowlist.allow("multiplier", "v1");

var stateRootStore = new InMemoryStateRootStore();
stateRootStore.initialize("my-app", genesisRoot);

var sequenceTracker = new InMemorySequenceTracker();
var nullifierStore = new InMemoryNullifierStore();

// Create pipeline
var pipeline = new SubmissionIngestionPipeline(
        orchestrator, vkRegistry, submitterReg, circuitAllowlist,
        stateRootStore, sequenceTracker, nullifierStore);

// Process a submission
SubmissionResult result = pipeline.process(submission);

if (result.accepted()) {
    System.out.println("State transition accepted!");
} else {
    System.out.println("Rejected at " + result.stage() + ": " + result.reason().orElse(null));
}
```

## Production Notes

The in-memory stores are suitable for development and testing. For production deployments, implement the store interfaces with database-backed persistence.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-ingestion'
}
```
