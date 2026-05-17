# zeroj-bom-all

Bill of Materials for all publishable ZeroJ modules, including core, opt-in
privacy backends, WASM providers, and incubator modules.

Most applications should start with `zeroj-bom-core`. Use this BOM when you
explicitly want optional modules such as BBS, WASM providers, or incubator
backends aligned to the same version.

## Usage

### Gradle

```gradle
dependencies {
    implementation platform('com.bloxbean.cardano:zeroj-bom-all:0.1.0')

    // Now declare modules without version
    implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'
    implementation 'com.bloxbean.cardano:zeroj-circuit-lib'
    implementation 'com.bloxbean.cardano:zeroj-verifier-core'
    implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
    implementation 'com.bloxbean.cardano:zeroj-verifier-plonk'
    implementation 'com.bloxbean.cardano:zeroj-prover-gnark'
    implementation 'com.bloxbean.cardano:zeroj-patterns'
    implementation 'com.bloxbean.cardano:zeroj-cardano'
    implementation 'com.bloxbean.cardano:zeroj-ccl'
}
```

### Maven

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.bloxbean.cardano</groupId>
            <artifactId>zeroj-bom-all</artifactId>
            <version>0.1.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

## Included Modules

All publishable ZeroJ modules are covered by this BOM.

**Core:**
- `zeroj-api`
- `zeroj-codec`
- `zeroj-backend-spi`
- `zeroj-verifier-core`
- `zeroj-verifier-groth16`
- `zeroj-verifier-plonk`
- `zeroj-bls12381`
- `zeroj-blst`
- `zeroj-crypto`
- `zeroj-cardano`
- `zeroj-ccl`
- `zeroj-patterns`
- `zeroj-circuit-dsl`
- `zeroj-circuit-lib`
- `zeroj-prover-spi`
- `zeroj-prover-gnark`
- `zeroj-onchain-julc`

**Mainline opt-in:**
- `zeroj-bbs`
- `zeroj-bbs-wasm`
- `zeroj-bls12381-wasm`

**Incubator opt-in:**
- `zeroj-prover-wasm`
- `zeroj-verifier-halo2`
