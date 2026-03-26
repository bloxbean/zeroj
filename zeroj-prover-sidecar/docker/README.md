# ZeroJ Prover Sidecar

A Docker-based snarkjs proving service for ZeroJ.

## Quick Start

```bash
# Build the image
docker build -t zeroj-prover .

# Run with circuit artifacts
docker run -p 3000:3000 -v /path/to/circuits:/circuits zeroj-prover
```

## Circuit Directory Structure

Mount a directory with circuit artifacts at `/circuits`:

```
/circuits/
  multiplier/
    multiplier.wasm          # circom WASM witness calculator
    multiplier_final.zkey    # Groth16 proving key
    verification_key.json    # Verification key
  transfer/
    transfer.wasm
    transfer_final.zkey
    verification_key.json
```

## API

### `GET /health`
Returns `{"status": "ok", "circuits": N}`.

### `GET /circuits`
Returns `["multiplier", "transfer", ...]`.

### `GET /circuits/:name/vk`
Returns the verification key JSON for a circuit.

### `POST /prove`
Generate a proof.

Request:
```json
{
  "circuit": "multiplier",
  "input": {"a": "3", "b": "11"}
}
```

Response:
```json
{
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...], "protocol": "groth16", "curve": "bn128" },
  "publicSignals": ["33", "3"],
  "protocol": "groth16",
  "curve": "bn128",
  "provingTimeMs": 150
}
```

### `POST /reload`
Reload circuit discovery (after mounting new volumes).

## Java Client

```java
var client = new SidecarProverClient(ProverConfig.localhost());

// Check health
boolean healthy = client.isHealthy();

// Generate proof
var response = client.prove(ProveRequest.of("multiplier", Map.of("a", "3", "b", "11")));

// Generate proof and wrap as ZkProofEnvelope (ready for verification)
var envelope = client.proveAndWrap(ProveRequest.of("multiplier", Map.of("a", "3", "b", "11")), "multiplier");
```
