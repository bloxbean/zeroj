# zeroj-bom-core

The **single stable BOM** for ZeroJ ([ADR-0044](../docs/adr/0044-focused-module-surface-and-optional-provider-isolation.md)):
Java circuits, pure-Java proving, verification, operator tooling, and the Julc
on-chain BLS12-381 verifiers.

`zeroj-bom-all` was removed. Opt-in product modules are **not** constrained here;
declare those with an explicit version (see below).

## Gradle

```gradle
dependencies {
    implementation platform('org.zeroj:zeroj-bom-core:0.1.0')

    // Constrained by the BOM — no version needed
    implementation 'org.zeroj:zeroj-circuit-dsl'
    implementation 'org.zeroj:zeroj-circuit-lib'
    implementation 'org.zeroj:zeroj-crypto'
    implementation 'org.zeroj:zeroj-backend-spi'
    implementation 'org.zeroj:zeroj-verifier-groth16'
    implementation 'org.zeroj:zeroj-onchain-julc'

    // Opt-in product modules are OUTSIDE this BOM — give them an explicit version
    implementation 'org.zeroj:zeroj-verifier-plonk:0.1.0'
    implementation 'org.zeroj:zeroj-mpf-poseidon:0.1.0'
}
```

## Constrained modules

| Module | Purpose |
|--------|---------|
| `zeroj-api` | Core proof model, envelopes, verification result types |
| `zeroj-codec` | Proof serialization — snarkjs JSON, CBOR, canonical hashing |
| `zeroj-backend-spi` | Verifier SPI, backend discovery, registry and orchestration |
| `zeroj-verifier-groth16` | Groth16 verification (BLS12-381 pure Java / blst) |
| `zeroj-bls12381` | Pure Java BLS12-381 field, curve and pairing primitives |
| `zeroj-blst` | Native BLS12-381 via `libblst` (FFM), built from source |
| `zeroj-crypto` | Pure Java Groth16 + PlonK prover and setup |
| `zeroj-crypto-blst` | Opt-in blst-accelerated prover backend bridge |
| `zeroj-circuit-dsl` | Java circuit DSL — compile to R1CS or PlonK |
| `zeroj-circuit-lib` | Circuit standard library (Poseidon, Merkle, comparators, …) |
| `zeroj-circuit-annotation-api` | Compile-time annotation API |
| `zeroj-circuit-annotation-processor` | Companion generator for annotated circuits |
| `zeroj-onchain-julc` | Reusable Plutus V3 on-chain verifiers via Julc |
| `zeroj-tools` | Ceremony library and the `zeroj-ceremony` CLI |

## Not in this BOM

**Opt-in product modules** — published and supported, but deliberately outside
the stable BOM so they are never pulled into a default dependency graph. Declare
each with an explicit version: `zeroj-verifier-plonk`, `zeroj-bbs`,
`zeroj-mpf-poseidon`, `zeroj-jmt-poseidon`.

**Removed coordinates** — `zeroj-verifier-core` (merged into `zeroj-backend-spi`,
packages unchanged), `zeroj-ceremony` (merged into `zeroj-tools`),
`zeroj-prover-spi`, `zeroj-prover-gnark`, `zeroj-verifier-halo2`,
`zeroj-prover-wasm`, `zeroj-cardano`, `zeroj-ccl`, `zeroj-patterns`,
`zeroj-bom-all`. See the
[migration note](../docs/migration/0044-module-cleanup.md).

**Never published** — `zeroj-test-vectors`, `zeroj-integration-tests`, and
everything under `assurance/` and `benchmarks/`.
