# zeroj-bom

Bill of Materials for ZeroJ version alignment.

Import this Gradle platform to ensure all ZeroJ modules use consistent versions without specifying version numbers individually.

## Usage

### Gradle

```gradle
dependencies {
    // Import BOM
    implementation platform('com.bloxbean.cardano:zeroj-bom:0.1.0')

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
            <artifactId>zeroj-bom</artifactId>
            <version>0.1.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

## Included Modules

All publishable ZeroJ modules are covered by this BOM:

**Core:**
- `zeroj-api`
- `zeroj-codec`
- `zeroj-backend-spi`
- `zeroj-verifier-core`
- `zeroj-verifier-groth16`
- `zeroj-verifier-plonk`
- `zeroj-blst`
- `zeroj-submission`
- `zeroj-ingestion`
- `zeroj-cardano`
- `zeroj-ccl`
- `zeroj-patterns`
- `zeroj-circuit-dsl`
- `zeroj-circuit-lib`
- `zeroj-prover-gnark`
- `zeroj-onchain-julc`

**Incubator:**
- `zeroj-prover-sidecar`
- `zeroj-prover-rapidsnark`
- `zeroj-prover-wasm`
- `zeroj-verifier-halo2`
- `zeroj-onchain-experimental`
