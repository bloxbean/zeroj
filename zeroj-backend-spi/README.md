# zeroj-backend-spi

Service Provider Interface for ZK verification backends.

This module defines the contracts that verification backends must implement. It enables ZeroJ's pluggable architecture — new proof systems can be added without changing application code.

## Key Types

| Type | Description |
|------|-------------|
| `ZkVerifier` | SPI interface — `verify(envelope, material)` + `descriptor()` |
| `BackendDescriptor` | Declares what a backend supports (proof system + curve + name) |
| `VerificationKeyRegistry` | Store and look up VKs by reference (`ByHash` or `ById`) |
| `InMemoryVerificationKeyRegistry` | HashMap-based VK registry for development and testing |

## Implementing a Custom Backend

```java
public class MyVerifier implements ZkVerifier {
    @Override
    public BackendDescriptor descriptor() {
        return new BackendDescriptor(ProofSystemId.GROTH16, CurveId.BN254, "my-verifier");
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        // Your verification logic here
        return VerificationResult.ok();
    }
}
```

Backends are discovered automatically via `ServiceLoader` when registered in `META-INF/services/com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier`.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-backend-spi'
}
```
