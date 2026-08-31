# Migration 0044: Focused Module Surface and Optional-Provider Isolation

[ADR-0044](../adr/0044-focused-module-surface-and-optional-provider-isolation.md)
narrows the published ZeroJ surface to the Java-first product path, removes the
gnark (Go) and Halo2 (Rust) runtime providers, and moves the WASM assurance
providers and the MPF/JMT load tools out of the default build.

This is a **structural** change. No cryptographic algorithm, proof equation,
transcript, domain separator, public-input order, circuit relation, canonical
encoding, trusted-setup rule, or validation rule changes. No maturity, audit,
side-channel, production, or mainnet claim is upgraded.

## Removed coordinates

| Old coordinate | Migration |
|---|---|
| `com.bloxbean.cardano:zeroj-verifier-core` | Depend on `com.bloxbean.cardano:zeroj-backend-spi`. `VerifierRegistry` and `VerifierOrchestrator` moved into that artifact and **kept their `com.bloxbean.cardano.zeroj.verifier.core` package**, so imports do not change — only the dependency coordinate does. |
| `com.bloxbean.cardano:zeroj-prover-spi` | **No replacement.** `ProverService`, `ProveRequest`, `ProveResponse`, and `ProverException` are removed. Use the concrete `zeroj-crypto` proving APIs (`Groth16SetupBLS381`, `Groth16ProverBLS381`, `Groth16PkStore`, `Groth16Pipeline`) or, for accelerated Groth16 proving, `zeroj-crypto-blst`. A provider-neutral proving contract requires a separate accepted API design. |
| `com.bloxbean.cardano:zeroj-prover-gnark` | **No runtime replacement artifact.** Use `zeroj-crypto` for Java Groth16/PlonK proving, or `zeroj-crypto-blst` for opt-in blst-accelerated Groth16 proving. The pinned gnark Go fixture generator survives as a non-published assurance harness under `assurance/gnark-fixtures/`. |
| `com.bloxbean.cardano:zeroj-verifier-halo2` | **No replacement.** Preserved through Git history. Reintroduction requires a current product goal and a new or updated ADR. |
| `com.bloxbean.cardano:zeroj-prover-wasm` | **No replacement.** Preserved through Git history. Pin the last release if you depend on circom-WASM witness calculation. |
| `com.bloxbean.cardano:zeroj-ceremony` | Depend on / use `com.bloxbean.cardano:zeroj-tools`. `CeremonyCli` moved there and **kept its `com.bloxbean.cardano.zeroj.ceremony` package**. The `zeroj-ceremony` command name, CLI behavior, transcript bytes, and release artifact names are unchanged. |
| `com.bloxbean.cardano:zeroj-cardano` | **No core SDK replacement.** `ProofAnchor`, `AnchorPattern`, and `AnchorMetadataEncoder` were application-level reference code. Adopt explicit application metadata in your own code or in a maintained use case. |
| `com.bloxbean.cardano:zeroj-ccl` | Use Cardano Client Lib directly in application code, as the maintained use cases already do. |
| `com.bloxbean.cardano:zeroj-patterns` | Use application-specific policies in [zeroj-usecases](https://github.com/bloxbean/zeroj-usecases). ZeroJ implies **no** generic authorization, replay-protection, or nullifier guarantee; see "Application authorization is not proof validity" below. |
| `com.bloxbean.cardano:zeroj-bom-all` | Use `com.bloxbean.cardano:zeroj-bom-core` plus explicitly versioned opt-in product artifacts. |
| `com.bloxbean.cardano:zeroj-bls12381-wasm` | Not a runtime product. It is now an explicit assurance module under `assurance/`, built with `-PincludeAssurance`, and is not published. |
| `com.bloxbean.cardano:zeroj-bbs-wasm` | Same as above. |
| `zeroj-examples` (never published) | Use [zeroj-usecases](https://github.com/bloxbean/zeroj-usecases) for tutorials and runnable applications. Its security regressions moved into `zeroj-integration-tests`. |

## Retained coordinates

Every retained module keeps its existing Maven coordinate and package names.

**Default product surface** — constrained by `zeroj-bom-core`:

`zeroj-api`, `zeroj-codec`, `zeroj-backend-spi`, `zeroj-verifier-groth16`,
`zeroj-bls12381`, `zeroj-blst`, `zeroj-crypto`, `zeroj-crypto-blst`,
`zeroj-circuit-dsl`, `zeroj-circuit-lib`, `zeroj-circuit-annotation-api`,
`zeroj-circuit-annotation-processor`, `zeroj-onchain-julc`, `zeroj-tools`.

**Explicit opt-in product modules** — published, but *not* constrained by the
stable BOM. Declare them with an explicit version:

`zeroj-verifier-plonk`, `zeroj-bbs`, `zeroj-mpf-poseidon`, `zeroj-jmt-poseidon`.

"Opt-in" means the module is not pulled into the default dependency graph and
its maturity is documented independently. It does not mean untested.

## BOM change

`zeroj-bom-core` is the single stable BOM. Two artifacts were **added** to it
(`zeroj-crypto-blst`, `zeroj-tools`) and several were **removed**
(`zeroj-verifier-core`, `zeroj-prover-spi`, `zeroj-prover-gnark`,
`zeroj-cardano`, `zeroj-ccl`, `zeroj-patterns`), along with the opt-in product
artifacts `zeroj-verifier-plonk`, `zeroj-mpf-poseidon`, and `zeroj-jmt-poseidon`.

```groovy
dependencies {
    implementation platform("com.bloxbean.cardano:zeroj-bom-core:$zerojVersion")

    implementation "com.bloxbean.cardano:zeroj-circuit-dsl"      // version from the BOM
    implementation "com.bloxbean.cardano:zeroj-crypto"
    implementation "com.bloxbean.cardano:zeroj-verifier-groth16"

    // opt-in product artifacts need an explicit version
    implementation "com.bloxbean.cardano:zeroj-verifier-plonk:$zerojVersion"
    implementation "com.bloxbean.cardano:zeroj-mpf-poseidon:$zerojVersion"
}
```

## Build changes

The default build is pure Java. A clean checkout needs **no** Go, Rust, Cargo,
Node.js, WASM toolchain, or RocksDB JNI:

```bash
./gradlew build
```

Optional surfaces are explicit opt-ins:

```bash
# BLS/BBS WASM independent differential providers (needs Rust/Cargo + the wasm32 target)
./gradlew -PincludeAssurance :zeroj-bls12381-wasm:test :zeroj-bbs-wasm:test

# MPF/JMT load and benchmark tools (needs RocksDB JNI)
./gradlew -PincludeBenchmarks :zeroj-mpf-poseidon-load:build :zeroj-jmt-poseidon-load:build

# cross-module integration and end-to-end regressions
./gradlew :zeroj-integration-tests:test        # offline
./gradlew :zeroj-integration-tests:e2eTest     # needs Yaci DevKit and/or snarkjs
```

`./gradlew verifyDefaultModuleSurface` asserts that the stable graph has no
runtime edge into an assurance, benchmark, or removed module; that MPF and JMT
stay independent; that the annotation API and processor stay separate; and that
no pure-Java module acquires a native or WASM dependency. It runs in CI,
snapshot, and release.

## Where the assurance evidence went

| Evidence | New home |
|---|---|
| zkcrypto BLS12-381 WASM differential provider | `assurance/zeroj-bls12381-wasm` (`-PincludeAssurance`) |
| zkryptium BBS WASM differential provider | `assurance/zeroj-bbs-wasm` (`-PincludeAssurance`) |
| gnark PlonK BLS12-381 fixture generator (pinned gnark v0.14.0) | `assurance/gnark-fixtures/` — regenerates the committed `zeroj-test-vectors` PlonK vectors that the Java verifier is tested against |
| Groth16/PlonK end-to-end, tampering, wrong-input, invalid-witness, public-input-order, comparator-relation, Julc VM and Yaci on-chain regressions from `zeroj-examples` | `zeroj-integration-tests` |
| snarkjs interoperability proving path | `zeroj-integration-tests` (`@Tag("e2e")`) |
| BBS official CFRG draft-10 vectors across pure-Java / blst / WASM providers | `zeroj-bbs` keeps the pure-Java and blst rows in the default build; the WASM row runs under `-PincludeAssurance` |
| MPF/JMT golden-root, proof, transition, structure-confusion, and manifest checks | unchanged, in `zeroj-mpf-poseidon` and `zeroj-jmt-poseidon` |
| Ceremony snarkjs mixed-tool transcript verification | `zeroj-tools` |

## Application authorization is not proof validity

`zeroj-patterns` shipped typed membership, nullifier, and state-transition
helpers. Their removal is a **scope correction**, not a downgrade: cryptographic
proof validity was never application authorization. Applications must still
reason separately about `ScriptContext` binding, replay protection, nullifier
registries, authorization, state/input/output binding, and business policy.
ZeroJ's reusable verifier code does not provide those guarantees.

## Verification status

All structural milestones are complete and the default build is green. The
final Yaci DevKit gate passed on 2026-08-31: `SealedBidOnChainE2ETest` and
`PureJavaProverYaciE2ETest` both submitted confirmed lock and ZK-verified unlock
transactions and passed rather than skipping. See the
[ADR's implementation status](../adr/0044-focused-module-surface-and-optional-provider-isolation.md#implementation-status).

Nothing about this cleanup upgrades any maturity, audit, side-channel,
production, or mainnet claim. The production gates in the governing ADRs for
Groth16, PlonK, BBS, BLS12-381, MPF, JMT, trusted setup, and the on-chain
validators are all unchanged and still open.

## If you depend on a removed module

Pin the previous ZeroJ version until your application has migrated to the
replacement path above. ZeroJ is pre-1.0 experimental/research software and
coordinates may still evolve.
