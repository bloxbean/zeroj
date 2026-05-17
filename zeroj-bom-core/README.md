# zeroj-bom-core

Core Bill of Materials for the stable ZeroJ v3 path: Java circuits/proving,
verification, Cardano anchoring, and Julc on-chain BLS12-381 verifiers.

## Gradle

```gradle
dependencies {
    implementation platform('com.bloxbean.cardano:zeroj-bom-core:0.1.0')

    implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'
    implementation 'com.bloxbean.cardano:zeroj-circuit-lib'
    implementation 'com.bloxbean.cardano:zeroj-crypto'
    implementation 'com.bloxbean.cardano:zeroj-verifier-core'
    implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
    implementation 'com.bloxbean.cardano:zeroj-onchain-julc'
}
```

## Included Modules

- `zeroj-api`
- `zeroj-codec`
- `zeroj-backend-spi`
- `zeroj-verifier-core`
- `zeroj-verifier-groth16`
- `zeroj-verifier-plonk`
- `zeroj-bls12381`
- `zeroj-blst`
- `zeroj-crypto`
- `zeroj-circuit-dsl`
- `zeroj-circuit-lib`
- `zeroj-prover-spi`
- `zeroj-prover-gnark`
- `zeroj-onchain-julc`
- `zeroj-cardano`
- `zeroj-ccl`
- `zeroj-patterns`
