# zeroj-prover-sidecar

Java client SDK for external ZK proof generation services.

This module provides an HTTP client that connects to an external snarkjs-based prover sidecar service. The sidecar model keeps proving (computationally expensive) separate from verification (lightweight), following ZeroJ's verifier-first architecture.

## Key Types

| Type | Description |
|------|-------------|
| `SidecarProverClient` | HTTP client with health checks, proof generation, and retry support |
| `ProverService` | Interface contract for proof generation (implemented by all prover modules) |
| `ProveRequest` | Immutable request — circuit name + input map |
| `ProveResponse` | Immutable response — proof JSON + public signals |
| `ProverConfig` | Endpoint URI, timeouts, retry policy |
| `ProverException` | Typed error codes: `CONNECTION_FAILED`, `INVALID_RESPONSE`, `PROOF_GENERATION_FAILED`, `TIMEOUT` |

## Usage

```java
// Connect to sidecar
var config = ProverConfig.localhost(); // http://localhost:3000
var client = new SidecarProverClient(config);

// Check health
boolean healthy = client.isHealthy();

// Generate a proof
var request = ProveRequest.of("multiplier", Map.of("a", "3", "b", "11"));
ProveResponse response = client.prove(request);

// Generate and wrap as ZkProofEnvelope (ready for verification)
ZkProofEnvelope envelope = client.proveAndWrap(request, "multiplier");
```

## Docker Sidecar

A Docker-based snarkjs proving service is included in the `docker/` directory. See [docker/README.md](docker/README.md) for setup instructions.

```bash
docker build -t zeroj-prover docker/
docker run -p 3000:3000 -v /path/to/circuits:/circuits zeroj-prover
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-prover-sidecar'
}
```
