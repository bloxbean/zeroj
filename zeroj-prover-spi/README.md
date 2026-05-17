# zeroj-prover-spi

Service Provider Interface for proof generation backends.

This module defines the small prover-side contract shared by native, pure Java,
or remote proving implementations. It is intentionally separate from
`zeroj-backend-spi`, which is verifier-side only.

## Key Types

| Type | Purpose |
|------|---------|
| `ProverService` | Minimal interface for generating a proof from a request |
| `ProveRequest` | Circuit name, input map, and optional proving-key identifier |
| `ProveResponse` | Proof JSON, public signals, protocol, curve, and proving time |
| `ProverException` | Typed proving failure with backend-friendly error codes |

## Why It Is Useful

- Keeps prover contracts in a stable core module instead of tying them to one
  transport or implementation.
- Lets `zeroj-prover-gnark` and future prover backends share response/error
  types without depending on a specific transport implementation.
- Makes local-first proving the default while leaving room for optional remote
  deployments later.

## Example

```java
ProverService prover = request -> {
    // Backend-specific proving logic.
    return new ProveResponse(proofJson, publicSignals, "groth16", "bls12381", 42);
};

var response = prover.prove(ProveRequest.of("multiplier", Map.of(
        "x", "3",
        "y", "11",
        "z", "33"
)));
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-prover-spi'
}
```
