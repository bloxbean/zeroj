# zeroj-verifier-core

Verifier orchestration and backend routing for ZeroJ.

This module is the main entry point for proof verification. It routes verification requests to the correct backend based on the proof system and curve, resolves verification keys from the registry, and returns structured results.

## Key Types

| Type | Description |
|------|-------------|
| `VerifierOrchestrator` | Routes proofs to the correct `ZkVerifier` backend; resolves VKs from registry |
| `VerifierRegistry` | Backend registry with `ServiceLoader` auto-discovery or manual registration |

## Usage

```java
// Option 1: Auto-discover backends via ServiceLoader
var registry = VerifierRegistry.withServiceLoader();

// Option 2: Manual registration
var registry = VerifierRegistry.empty();
registry.register(new Groth16BN254Verifier());
registry.register(new Groth16BLS12381Verifier());

// Create orchestrator
var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

// Verify a proof
VerificationResult result = orchestrator.verify(envelope, material);

if (result.proofValid()) {
    System.out.println("Proof verified!");
}
```

## Architecture

```
Application Code
       |
   VerifierOrchestrator --- VerificationKeyRegistry (VK lookup)
       |
   VerifierRegistry (backend routing)
      / \
     /   \
Groth16  Halo2    ... (pluggable backends)
```

The orchestrator never performs verification itself — it delegates to the appropriate `ZkVerifier` implementation.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-verifier-core'
}
```
