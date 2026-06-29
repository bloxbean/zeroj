# zeroj-codec

Proof serialization for ZeroJ — snarkjs JSON parsing, CBOR encoding, and canonical hashing.

This module bridges external proof tooling (snarkjs, gnark) and ZeroJ's internal model. It parses proof artifacts into `ZkProofEnvelope` objects and provides deterministic serialization for network transmission and content addressing.

## Features

| Class | Description |
|-------|-------------|
| `SnarkjsJsonCodec` | Parse snarkjs `proof.json`, `verification_key.json`, `public.json` into ZeroJ types |
| `SnarkjsProof` | Record holding Groth16 proof coordinates (piA, piB, piC) + protocol + curve |
| `SnarkjsVerificationKey` | Record holding VK points (alpha, beta, gamma, delta, IC) |
| `CborEnvelopeCodec` | Deterministic CBOR serialization of `ZkProofEnvelope` (integer-keyed map) |
| `CanonicalHash` | SHA-256 hash of canonical VK encoding for content addressing |
| `EnvelopeValidator` | Validates envelope fields before verification |
| `GnarkPlonkCodec` | Typed envelope codec for gnark binary PlonK proof artifacts; verification still uses gnark native verification until a structured adapter exists |
| `Halo2Codec` | Codec for Halo2 proof artifacts |

Groth16 snarkjs JSON and CBOR envelope parsing use bounded input reads,
duplicate-key detection, canonical decimal checks, and typed `CodecException`
failures for malformed input.

## Usage

```java
// Parse snarkjs artifacts
var proof = SnarkjsJsonCodec.parseProof(proofJson);
var vk = SnarkjsJsonCodec.parseVerificationKey(vkJson);
var publicInputs = SnarkjsJsonCodec.parsePublicInputs(publicJson);

// Build envelope directly from JSON files
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson,
        new CircuitId("multiplier"));

// CBOR encode/decode for network transmission
byte[] cbor = CborEnvelopeCodec.encode(envelope);
ZkProofEnvelope decoded = CborEnvelopeCodec.decode(cbor);

// Compute canonical hash for content addressing
byte[] hash = CanonicalHash.hash(envelope);
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-codec'
}
```
