# ADR-0044: Focused module surface and optional-provider isolation

## Status

Accepted

## Date

2026-08-28

## Implementation status

**In progress — all structural work complete, one verification gate outstanding.**

Implemented on branch `refactor/adr-0044-module-cleanup`. Every implementation
milestone (M0–M6) is complete, and the coordinate migration table is published in
[the migration note](../migration/0044-module-cleanup.md).

Completed and evidenced:

- default root projects reduced 35 → 21 (20 product + `zeroj-integration-tests`);
- `./gradlew build` green; `./gradlew verifyDefaultModuleSurface` green;
- every security regression migrated out of `zeroj-examples` before its removal,
  green in `zeroj-integration-tests`, including snarkjs independent-prover
  interoperability for Groth16 and PlonK;
- both mergers verified with identical test counts, packaged-JAR ServiceLoader
  discovery, a working packaged `zeroj-ceremony` CLI, and the snarkjs mixed-tool
  ceremony transcript check;
- the zkcrypto/zkryptium WASM differential oracles preserved and fail-closed
  under `-PincludeAssurance` (mutation-tested);
- the pinned gnark PlonK fixture generator preserved and shown to produce a fresh
  independent artifact that ZeroJ's Java verifier and transcript still accept;
- every surviving canonical resource — test vectors, ServiceLoader files,
  native-image metadata — byte-identical before and after (SHA-256 compared);
  the only removals are the 20 files owned by removed providers;
- all 13 `zeroj-usecases` projects build, 46 of their tests pass, against the
  candidate artifacts with the removed coordinates made unresolvable.

Outstanding before this becomes "Implemented":

1. **Execute the Yaci DevKit on-chain end-to-end suite.** The tests were migrated
   and are correctly discovered, but they skipped because no local DevKit was
   running in the implementation environment. Close this gate with a running
   DevKit and `./gradlew :zeroj-integration-tests:e2eTest`, which must show
   `SealedBidOnChainE2ETest` and `PureJavaProverYaciE2ETest` passing rather than
   skipped.

This ADR authorizes structural cleanup only and closes no production or audit
gate; see "Production and audit gates" below.

## Risk classification

Primary classification: **R1**. This ADR changes module, publication, dependency,
and compatibility boundaries without intentionally changing cryptographic
algorithms.

The work has an **R2 assurance impact** because provider extraction and test
movement can accidentally remove independent differential or adversarial
coverage. The assurance invariants and verification gates in this ADR are
therefore mandatory even though the intended runtime behavior is unchanged.

Any implementation step that changes a canonical encoding, validation rule,
transcript, public-input order, circuit relation, proof equation, trusted-setup
semantics, secret operation, or provider security semantics is outside this
ADR and requires a separate R2/R3 design.

## Supersedes and preserves

This ADR supersedes the current module-surface, BOM, prover-SPI, gnark-default,
WASM/default-build, app-helper, and example-module decisions in
[ADR-0020](0020-module-cleanup-and-core-restructure.md).

It supersedes only the packaging/default-build aspects of:

- [ADR-0009](0009-halo2-support-strategy.md) and
  [ADR-0011](0011-generic-halo2-prover-via-rust-ffm.md) for the current Halo2
  incubator module;
- [ADR-0018](0018-shared-bls12381-primitives-and-wasm-provider.md) and
  [ADR-0019](0019-cfrg-bbs-pure-java-and-wasm-providers.md) for the two WASM
  providers;
- [ADR-0031](0031-groth16-mpc-trusted-setup-ceremony.md) and
  [ADR-0036](0036-groth16-api-facade-and-pipeline.md) for the ceremony CLI
  artifact boundary.

It preserves the cryptographic, interoperability, provider-conformance,
trusted-setup, and circuit decisions in those ADRs. In particular, it does not
authorize loss of the WASM-backed independent differential oracles.

It preserves the separate MPF and JMT product modules and their security
boundaries from
[ADR-0042](0042-operation-specific-poseidon-mpf-and-jmt-circuits.md).

Related tracking issue:
[GitHub issue #24](https://github.com/bloxbean/zeroj/issues/24).

## Context

The repository currently includes 35 Gradle projects. The default root build
mixes several different kinds of software:

- the portable Java circuit, proving, verification, and Cardano path;
- explicit opt-in product modules such as PlonK, BBS, MPF, and JMT;
- native and WASM providers;
- research/incubator implementations;
- application-level helpers and examples;
- operator and benchmark tools; and
- two BOMs with overlapping but different support messages.

This makes repository inclusion, default build inclusion, Maven publication,
and product support appear equivalent even though they are not.

The current root build excludes only `zeroj-test-vectors`, `zeroj-examples`,
`zeroj-mpf-poseidon-load`, and `zeroj-jmt-poseidon-load` from its generic
publication path. Native, WASM, and incubator providers otherwise remain part
of the root project and publication/release surface. CI, snapshot, and release
workflows build gnark and Halo2 native artifacts across several platforms, and
the BLS/BBS WASM resource tasks invoke Cargo from an ordinary Gradle build.

### Consumer evidence

The current `zeroj-usecases` working tree directly uses the following ZeroJ
artifacts:

- `zeroj-api`;
- `zeroj-codec`;
- `zeroj-verifier-groth16`;
- `zeroj-verifier-plonk`;
- `zeroj-bls12381`;
- `zeroj-blst`;
- `zeroj-crypto`;
- `zeroj-crypto-blst`;
- `zeroj-circuit-dsl`;
- `zeroj-circuit-lib`;
- `zeroj-circuit-annotation-api`;
- `zeroj-circuit-annotation-processor`;
- `zeroj-onchain-julc`;
- `zeroj-bbs`; and
- `zeroj-mpf-poseidon`.

It contains no declared dependency or Java import for:

- `zeroj-cardano`;
- `zeroj-ccl`;
- `zeroj-patterns`;
- `zeroj-prover-gnark`;
- `zeroj-prover-spi`;
- `zeroj-verifier-core`;
- `zeroj-tools` or `zeroj-ceremony` as application libraries;
- either WASM provider;
- the WASM witness provider; or
- the Halo2 incubator module.

This does not prove that no private or unindexed external consumer exists.
Public GitHub code search found no concrete third-party usage of the removal
candidates. The only additional repository hit for `zeroj-verifier-core` and
`zeroj-patterns` was a Yano version-catalog declaration; no Yano build or source
usage was found. Published artifacts still require a compatibility and
deprecation plan.

### Small boundaries that no longer justify artifacts

- `zeroj-verifier-core` contains two substantive orchestration classes plus
  package metadata. Its functionality is valuable, but its separation from the
  five-class verifier-side `zeroj-backend-spi` is not.
- `zeroj-prover-spi` contains four types and no tests. Gnark consumes only
  `ProveResponse` and `ProverException`; neither gnark nor the pure-Java prover
  implements `ProverService` as a shared provider contract.
- `zeroj-ceremony` contains one main class, `CeremonyCli`, wrapping the reusable
  ceremony machinery already owned by `zeroj-tools`.
- `zeroj-cardano` contains three app-level anchoring classes;
  `zeroj-ccl` contains one app-level transaction helper.

### Current gnark status and disposition

`zeroj-prover-gnark` is implemented and useful within a bounded experimental
scope:

- the Go wrapper is pinned to gnark `v0.14.0`;
- BLS12-381 Groth16 and PlonK setup/prove calls exist;
- PlonK native verification exists;
- Java-DSL R1CS can use Groth16 or PlonK full-prove entry points;
- BN254 is rejected unless the legacy opt-in is explicit;
- native libraries are built for the supported CI platforms; and
- on 2026-08-28, `./gradlew :zeroj-prover-gnark:test --rerun-tasks`
  passed the current native-loading, full-prove, PlonK lifecycle, external
  verification, tamper-rejection, and curve-policy tests on macOS arm64.

It is not complete as a default production prover backend:

- the Java-DSL full-prove entry points serialize the complete constraints and
  witness as JSON across the FFM boundary;
- those entry points compile and run setup again for every call;
- the in-process Go runtime is capped at `GOMAXPROCS(2)` as a JVM-stability
  workaround;
- no representative small/medium/large benchmark compares gnark with the
  current pure-Java and blst-backed pipelines;
- no gnark path reuses the snarkjs ceremony `.zkey` or ZeroJ
  `Groth16PkStore` used by the primary Groth16 release path;
- gnark binary PlonK artifacts still require gnark-native verification because
  the structured codec/adapter is not implemented;
- the current Groth16 full-prove unit and example tests assert artifact shape
  but do not cryptographically verify the emitted proof against the emitted
  verification key; and
- the Go runtime and platform artifacts are not a GraalVM-native-image path.

The implementation is real, but that does not make it a useful continuing
product boundary. ZeroJ now has native-free Java implementations for both
Groth16 and PlonK, and the current PlonK use cases use `zeroj-crypto` with
`zeroj-verifier-plonk`, not gnark. Keeping only the gnark PlonK entry points
would retain the same Go runtime, FFM, cross-platform packaging, and release
burden as keeping the whole module.

The correct disposition is therefore to remove the gnark Java/FFM runtime
provider for both Groth16 and PlonK. The pinned gnark Go implementation may be
preserved only as an explicit, non-published test-vector or differential oracle
where it supplies evidence independent of the Java implementation.

### Native-binding inventory

There are three Java FFM native-library bindings in the current source tree:

| Binding | Disposition |
|---|---|
| gnark Go binding in `zeroj-prover-gnark` | Remove the Java/FFM runtime and publication. Preserve only a pinned, explicit Go test oracle if it provides independent evidence. |
| Halo2 Rust binding in `zeroj-verifier-halo2` | Remove/archive as already decided; it has no current consumer or committed product path. |
| direct `libblst` binding in `zeroj-blst` | Retain. It is used through `zeroj-crypto-blst`, has measured roughly 5x Groth16 proving value, and is checked for result equivalence against the pure-Java path. |

The uses of `Arena` and `MemorySegment` in `zeroj-crypto` are file mapping and
off-heap memory management, not foreign-library downcalls. They remain part of
the pure-Java large-circuit memory strategy and are not native bindings.

`zeroj-blst` also currently uses `foundation.icon:blst-java` through JNI/SWIG
for pairing and provider operations. That is a separate native boundary, not an
FFM binding. It remains while Groth16 verification, BBS, and current use cases
depend on it. Replacing or removing that JNI/SWIG path requires separate
provider-conformance and deployment evidence; this cleanup does not authorize
such a change.

## Threat model and trust assumptions

The cleanup must defend against these failures:

1. A provider or module move silently changes accepted proof, point, scalar,
   key, or witness encodings.
2. Removing an independent WASM implementation leaves pure Java and blst
   checking only each other even though both may share assumptions or code.
3. Moving examples deletes the only end-to-end, invalid-witness, tampering, or
   on-chain regression for a security property.
4. Merging verifier modules changes ServiceLoader discovery, backend routing,
   verification-key lookup, or provider selection.
5. Merging the ceremony CLI weakens dev-setup guardrails, changes transcript
   bytes, mishandles contribution secrets, or makes ZeroJ-authored verification
   replace the independent snarkjs transcript check.
6. Removing published coordinates breaks known or unknown downstream builds
   without a usable migration path.
7. Optional native/research providers are accidentally loaded merely because
   their artifacts are present.
8. A smaller repository is incorrectly presented as evidence of higher
   cryptographic maturity or production readiness.

Trust assumptions:

- Git history is sufficient archival provenance for code that is deliberately
  removed and has no continuing assurance role.
- WASM/Rust implementations remain independent only while their pinned upstream
  implementations, build inputs, and conformance vectors remain preserved.
- snarkjs remains the independent ceremony-transcript verifier required by
  ADR-0031.
- published pre-1.0 artifacts may evolve, but removal still requires explicit
  release notes and coordinate mapping.
- absence from `zeroj-usecases` and public GitHub search is consumer evidence,
  not proof that private consumers do not exist.

## Security and compatibility invariants

Implementation of this ADR must preserve all of the following:

1. No cryptographic algorithm, proof equation, transcript, domain separator,
   public-input order, circuit relation, or canonical encoding changes.
2. Existing trust-boundary validation remains fail-closed and byte-for-byte
   compatible unless a separate security ADR changes it.
3. Pure Java, blst, WASM, verifier, prover, and on-chain paths retain equivalent
   protocol semantics where equivalence is currently promised.
4. Official/reference vectors, negative malformed-input vectors, proof
   tampering tests, circuit invalid-witness tests, and cross-provider tests are
   moved before their old module is removed.
5. The independent zkcrypto BLS12-381 and zkryptium BBS differential oracles
   remain runnable in an explicit interop/assurance workflow.
6. The default Java build requires no Go, Rust, Cargo, Node.js, or unrelated
   native artifact unless an explicitly selected provider/test requires it.
7. Optional providers remain explicit; classpath presence alone does not change
   the active provider.
8. `zeroj.allowInsecureTrustedSetup` and all production-ceremony distinctions
   remain unchanged.
9. The `zeroj-ceremony` command behavior and snarkjs-compatible transcript bytes
   remain unchanged when the CLI moves into `zeroj-tools`.
10. No maturity, audit, side-channel, production, or mainnet claim is upgraded
    as a consequence of cleanup.
11. Maven coordinates removed or relocated by this ADR receive documented
    replacements or an explicit “no replacement” statement.
12. GraalVM/native-image metadata and ServiceLoader resources move with the
    classes they describe and are tested from packaged artifacts.

## Decision

### 1. Retain a focused default product surface

The default root build retains these modules:

| Module | Decision |
|---|---|
| `zeroj-api` | Retain core proof and circuit model. |
| `zeroj-codec` | Retain canonical codecs and hashing. |
| `zeroj-backend-spi` | Retain as the surviving verifier API/SPI artifact and absorb `zeroj-verifier-core`. |
| `zeroj-verifier-groth16` | Retain the primary Groth16 verification backend. |
| `zeroj-bls12381` | Retain the pure-Java BLS12-381 primitive/provider boundary. |
| `zeroj-blst` | Retain explicit native BLS12-381 acceleration. |
| `zeroj-crypto` | Retain pure-Java proving and cryptographic foundations. |
| `zeroj-crypto-blst` | Retain the optional bridge so native acceleration does not leak into `zeroj-crypto`. |
| `zeroj-circuit-dsl` | Retain circuit definition and compilation. |
| `zeroj-circuit-lib` | Retain reusable circuit gadgets. |
| `zeroj-circuit-annotation-api` | Retain the compile-time annotation API boundary. |
| `zeroj-circuit-annotation-processor` | Retain the processor separately from its API. |
| `zeroj-onchain-julc` | Retain Cardano/Plutus V3 verifier libraries and validators. |
| `zeroj-tools` | Retain reusable operator tooling and absorb `CeremonyCli`. |
| `zeroj-test-vectors` | Retain independent, malformed, interoperability, and protocol fixtures. |
| `zeroj-bom-core` | Retain as the single stable BOM coordinate. |

`zeroj-backend-spi` keeps its artifact coordinate to minimize migration. The
existing `com.bloxbean.cardano.zeroj.verifier.core` packages may remain during
the compatibility window even after their classes move into the surviving JAR.
A rename to `zeroj-verifier-api` is not part of this ADR.

`zeroj-bom-core` is the surviving BOM because it is already the documented
default. `zeroj-bom-all` is removed. The stable BOM must not constrain research,
benchmark, or incubator artifacts. Explicit opt-in product artifacts are added
by coordinate and version until their support classification warrants inclusion
in the stable BOM.

### 2. Retain explicit opt-in product modules

These substantive product modules remain in the main repository and root build,
but applications select them explicitly:

| Module | Reason retained |
|---|---|
| `zeroj-verifier-plonk` | Used by current PlonK use cases and has substantive prover/verifier/on-chain work. |
| `zeroj-bbs` | Used by reusable KYC and carries the CFRG draft-10 implementation. |
| `zeroj-mpf-poseidon` | Used by the private-registry flow and governed by ADR-0042. |
| `zeroj-jmt-poseidon` | Substantive authenticated-state implementation with independent ADR-0042 security and readiness boundaries. |

“Opt-in” does not mean untested or disposable. It means that the module is not
silently pulled into the default dependency graph and its maturity remains
documented independently.

### 3. Remove modules that add no retained product or assurance value

Remove these modules from the repository root, publication, BOM, default CI,
and release workflows:

| Module | Disposition |
|---|---|
| `zeroj-verifier-halo2` | Remove from ZeroJ and preserve through Git history or a research archive. Reintroduction requires a current product goal and a new/updated ADR. |
| `zeroj-prover-wasm` | Remove from ZeroJ and preserve through Git history or a research archive unless browser/circom-WASM witness calculation becomes a committed product goal. |
| `zeroj-prover-gnark` | Remove the published Java/FFM Groth16 and PlonK runtime. The pure-Java providers are the product paths; a pinned Go oracle may survive only in the explicit assurance surface. |
| `zeroj-prover-spi` | Remove with no general replacement. Its abstraction is unused by the pure-Java pipelines and exists only to support the removed gnark runtime. |
| `zeroj-cardano` | Deprecate, then remove. Its three metadata/anchoring classes are app-level reference code with no current use-case consumer. |
| `zeroj-ccl` | Deprecate, then remove. Its single transaction helper is not used by current use cases, which use CCL directly. |
| `zeroj-patterns` | Deprecate, then remove from the SDK. Do not merge it into `zeroj-cardano`; application policy belongs in use cases/reference applications. |
| `zeroj-examples` | Remove after migrating security and end-to-end regression coverage. Tutorials and runnable applications belong in `zeroj-usecases`. |
| `zeroj-bom-all` | Remove in favor of the single stable `zeroj-bom-core`. |

Do not copy app-level modules into `zeroj-usecases` merely to preserve them.
Move only code that a maintained use case deliberately adopts; otherwise Git
history and migration notes are the archive.

### 4. Preserve assurance and benchmark code outside the default build

The following code remains available but is not part of default
`settings.gradle`, default build, stable BOM, ordinary publication, snapshot,
or release workflows:

| Module | Disposition |
|---|---|
| `zeroj-bls12381-wasm` | Move to an explicit interop/assurance build or repository. Preserve the pinned zkcrypto implementation and differential vectors. |
| `zeroj-bbs-wasm` | Move to the same explicit interop/assurance surface. Preserve the pinned zkryptium implementation, RNG-boundary tests, and differential vectors. |
| `zeroj-mpf-poseidon-load` | Move to an explicit non-published benchmark/operator build. Preserve dataset provenance and reproducibility. |
| `zeroj-jmt-poseidon-load` | Move to an explicit non-published benchmark/operator build. Preserve dataset provenance and reproducibility. |
| pinned gnark Go oracle, if retained | Keep only the minimum reproducible fixture/differential harness outside the runtime and publication graph. It must not expose a Java FFM provider API. |

An explicit Gradle included build, opt-in settings flag, or separate repository
is acceptable. The selected mechanism must make a clean default build independent
of Go, Rust, Cargo, and optional native artifacts while keeping assurance jobs
reproducible.

### 5. Eliminate three unnecessary module boundaries

#### `zeroj-verifier-core` into `zeroj-backend-spi`

Move `VerifierRegistry`, `VerifierOrchestrator`, their tests, ServiceLoader
behavior, and native-image resources into `zeroj-backend-spi`. Remove the
`zeroj-verifier-core` Gradle project after its compatibility period.

The merger changes packaging only. Backend selection, descriptor matching,
verification-key resolution, result semantics, and failure behavior must remain
identical.

#### Remove `zeroj-prover-spi`

Remove `ProverService`, `ProveRequest`, `ProveResponse`, and `ProverException`
with the gnark runtime. No retained Java provider implements this contract, and
the pure-Java proving pipelines already expose their concrete lifecycle and key
ownership APIs.

Do not move an unimplemented abstraction into `zeroj-api`. A future unified
provider-neutral proving contract must include the pure-Java pipeline, setup/key
reuse, artifact ownership, secret lifetime, cancellation/progress, and error
semantics and therefore requires a separate accepted API design.

#### `zeroj-ceremony` into `zeroj-tools`

Move `CeremonyCli`, its tests, Picocli configuration, native-image metadata, and
CLI packaging into `zeroj-tools`; then remove the `zeroj-ceremony` Gradle project.
Preserve the executable/command name `zeroj-ceremony` and its command-line
behavior for compatibility.

This merger does not move ceremony cryptography. `ZkeyContributor`,
`SnarkjsHashToG2`, and `ChaChaRng` already belong to `zeroj-tools`. Their
transcript, randomness, validation, and secret-handling behavior must not change.

### 6. Remove gnark as a runtime; preserve only independent evidence

Remove the Java FFM loader, Groth16 and PlonK Java facades, bundled Go shared
libraries, native publication jobs, examples, and runtime documentation. Do not
replace the in-process binding with a subprocess product API under this ADR.

Before removal, identify whether the pinned gnark implementation supplies any
test vectors or cross-implementation checks not available from another
independent source. If so, preserve the minimum Go command or fixture generator
in the explicit assurance build and require Java to verify its emitted
artifacts. The oracle must be pinned, reproducible, non-published, and absent
from the runtime dependency graph. If it supplies no unique assurance value,
Git history is sufficient preservation.

This decision applies to both Groth16 and PlonK. Retaining PlonK alone is not a
meaningful simplification because it preserves the Go runtime, FFM surface,
platform matrix, and native release lifecycle, while maintained use cases
already exercise the Java PlonK path.

## Target project surface

The current 35 root projects reduce as follows:

| Change | Count |
|---|---:|
| Remove obsolete/app/example/all-BOM/gnark projects | -9 |
| Merge verifier-core and ceremony boundaries | -2 |
| Move two WASM providers and two load tools outside the default root build | -4 |
| Default root projects after cleanup | **20** |

A dedicated non-published integration-test project may make the default count
21 if cross-module E2E tests cannot live safely in focused source sets. Project
count is not itself a security or architectural invariant; the dependency and
support boundaries are.

## Compatibility and migration

This is pre-1.0 software, but current coordinates have been published. Apply
these rules:

1. Publish migration notes before removing a coordinate.
2. Where practical, provide one transition release with a deprecation or Maven
   relocation artifact. A temporary compatibility artifact is not part of the
   final project count.
3. Do not retain forwarding Java facades that create two accepted security
   paths unless their behavior is mechanically identical and tested.
4. Record this minimum mapping:

| Old coordinate | Migration |
|---|---|
| `zeroj-verifier-core` | Depend on `zeroj-backend-spi`; existing orchestrator packages remain during the compatibility window. |
| `zeroj-prover-spi` | No replacement; use the concrete `zeroj-crypto` proving APIs. |
| `zeroj-prover-gnark` | No runtime replacement artifact; use `zeroj-crypto` for Java Groth16/PlonK proving or `zeroj-crypto-blst` for opt-in accelerated Groth16 proving. |
| `zeroj-ceremony` | Depend on/use `zeroj-tools`; invoke the preserved `zeroj-ceremony` command. |
| `zeroj-cardano` | No core SDK replacement; adopt explicit application metadata in the maintained use case if needed. |
| `zeroj-ccl` | Use CCL directly in application code or maintained use-case helpers. |
| `zeroj-patterns` | Use application-specific policies in `zeroj-usecases`; no generic authorization guarantee is implied. |
| `zeroj-examples` | Use `zeroj-usecases`; security regressions move into focused ZeroJ integration tests. |
| `zeroj-bom-all` | Use `zeroj-bom-core` plus explicitly versioned opt-in product artifacts. |
| Halo2/WASM witness artifacts | Pin the last release or use the named research archive if one is created. |
| BLS/BBS WASM artifacts | Use the explicit interop/assurance build; they are not default runtime products. |

## Implementation milestones

### M0: Freeze and audit the graph

- Record the exact current 35-project dependency graph.
- Check Maven Central metadata/download evidence, public GitHub references,
  known private consumers, and downstream builds where available.
- Freeze the final default, opt-in product, interop, benchmark, archived, and
  compatibility-only classifications.
- Record the tests and resources owned by every project to be moved or removed.

### M1: Correct support and publication surfaces

- Remove gnark, WASM, Halo2, load tools, and experimental app helpers from the
  stable BOM and default publication path.
- Remove Go/Rust runtime-provider jobs from mandatory stable CI, snapshot, and release
  dependencies.
- Make interop/provider jobs explicit and independently runnable.
- Correct README, architecture, support matrix, and provider maturity claims.

### M2: Preserve tests before removing examples/providers

- Move each security-relevant `zeroj-examples` test to the module or focused
  integration source set that owns the invariant.
- Preserve Groth16/PlonK end-to-end proof verification, proof tampering,
  invalid-witness, public-input-order, and Julc/Yaci tests.
- Establish the opt-in BLS/BBS WASM differential job before changing their
  default-build membership.
- Preserve any uniquely valuable gnark-generated fixtures or differential
  checks in a pinned, non-published assurance harness before removing the FFM
  runtime.
- Prove the moved tests fail when their protected behavior is deliberately
  mutated where practical.

### M3: Remove app and research modules

- Deprecate and remove `zeroj-cardano`, `zeroj-ccl`, and `zeroj-patterns`.
- Remove `zeroj-examples` after M2.
- Remove/archive the current Halo2 and WASM witness modules.
- Remove `zeroj-prover-gnark` and `zeroj-prover-spi` after the
  assurance-fixture audit.
- Remove `zeroj-bom-all` and retain one authoritative stable BOM.

### M4: Merge module boundaries

- Merge verifier orchestration into `zeroj-backend-spi` and verify discovery,
  manual registration, duplicate handling, key lookup, and failure semantics.
- Remove the unused prover-SPI abstraction; do not move its types into a
  retained product module.
- Merge the ceremony CLI into `zeroj-tools`, preserving CLI, native-image,
  transcript, and snarkjs interoperability tests.

### M5: Isolate optional builds

- Move BLS/BBS WASM assurance providers into the selected explicit interop
  build/repository.
- Move MPF/JMT load tools into the selected benchmark/operator build.
- Move only a minimum pinned gnark fixture/differential harness into the
  assurance build if M2 establishes unique independent value.

### M6: Migration and release verification

- Publish the complete coordinate migration table and deprecation notes.
- Verify POMs, BOM constraints, Gradle metadata, source/javadoc jars, signing,
  native resources, and clean-checkout behavior.
- Build current `zeroj-usecases` against the candidate artifacts.
- Verify a clean stable build has no Go, Rust, Cargo, Node.js, or optional-native
  prerequisite.
- Record remaining audit and production gates without upgrading maturity.

## Verification strategy

At minimum, implementation must run:

- all tests of every retained stable and opt-in product module;
- `zeroj-usecases` builds and relevant end-to-end tests;
- packaged-JAR ServiceLoader and native-image resource checks for the merged
  verifier and tools artifacts;
- official/reference vectors and negative codec vectors;
- Groth16 and PlonK proof tampering and wrong-public-input tests;
- circuit invalid-witness tests for moved examples;
- Groth16 Julc VM and maintained Yaci end-to-end tests;
- BBS official draft-10 vectors and negative presentation tests;
- BLS/BBS pure-Java, WASM, and blst conformance/differential suites in the
  explicit interop build;
- any retained gnark-generated Groth16/PlonK fixtures verified by the Java
  verifier, including wrong-input and tampered-artifact rejection;
- MPF/JMT golden-root, proof, transition, structure-confusion, and manifest
  checks; and
- ceremony mixed-tool transcript verification through independent
  `snarkjs zkey verify`.

Before and after the module changes, compare canonical serialized artifacts,
R1CS fingerprints where relevant, public-input order, provider descriptors,
ServiceLoader results, and accepted/rejected vector sets. Any difference stops
the cleanup until explained by a separate accepted design.

The implementation must also run Gradle dependency analysis to prove:

- no stable module depends on an extracted research/interop/benchmark module;
- pure-Java modules do not acquire native or WASM dependencies;
- annotation API and processor remain separate;
- MPF and JMT remain separate and do not depend on each other; and
- no dependency cycle is introduced by the verifier or tools mergers.

## Consequences

### Positive

- The default repository and release story matches the Java-first product.
- Stable builds no longer require unrelated Go/Rust/WASM toolchains.
- App policy and examples stop masquerading as cryptographic SDK layers.
- Verifier and operator-tool boundaries become easier to understand.
- One BOM communicates one stable support surface.
- Independent WASM assurance remains available without becoming a runtime or
  release dependency.
- The Go runtime, gnark FFM surface, and its platform-specific release matrix
  are removed from the product while independent evidence can remain explicit.

### Costs

- Published consumers need coordinate and package migration.
- Optional provider, interop, and benchmark builds require separate CI entry
  points and documentation.
- Moving example tests safely is more work than deleting the example project.
- The surviving `zeroj-backend-spi` artifact contains orchestration as well as
  SPI types, so its name is broader in practice than before.
- Opt-in product artifacts require explicit version declarations while outside
  the stable BOM.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A security regression test disappears with `zeroj-examples`. | Inventory and move tests before deleting the module; require mutation evidence for critical relations where practical. |
| WASM removal weakens independent assurance. | Keep pinned independent implementations and vectors in an explicit interop job; removal is blocked until that job runs. |
| Verifier merge changes provider routing or validation. | Byte-for-byte vectors plus ServiceLoader/manual-registration and wrong-backend tests before and after. |
| Ceremony merge changes transcript or secret behavior. | No algorithm edits in the move; retain mixed snarkjs/ZeroJ transcript tests and secret/randomness rules from ADR-0031. |
| Unknown published consumers break. | Consumer audit, transition release/relocation where practical, and explicit migration notes. |
| Removing gnark also removes independent interoperability evidence. | Audit its fixtures first; preserve only a pinned Go oracle that emits artifacts consumed and verified by Java. |
| Optional code silently returns to default CI/release. | Add dependency and workflow checks asserting the stable graph has no optional provider edge. |
| Cleanup is misrepresented as security maturity. | Keep all experimental/audit/mainnet warnings unchanged and list remaining gates. |

## Rejected alternatives

### Delete the BLS/BBS WASM providers outright

Rejected because they are the only independent zkcrypto/zkryptium differential
implementations currently integrated with the provider conformance suites.

### Keep every module but remove it from the BOM

Rejected because root Gradle inclusion, publication, CI, snapshot, and release
work still impose toolchain and maintenance cost and continue to blur support.

### Merge `zeroj-patterns` into `zeroj-cardano`

Rejected because patterns are application policy, not Cardano metadata. Current
use cases do not consume either module, and merging them would create a larger
unused app-layer artifact.

### Move `zeroj-prover-spi` into `zeroj-api`

Rejected because the existing SPI is not implemented across providers and does
not model setup/key reuse, artifact ownership, secret lifetime, progress, or
the pure-Java pipeline.

### Keep gnark as an optional runtime provider

Rejected because both supported proof systems now have Java product paths, no
current use case consumes the binding, and optional publication still carries
the Go runtime, FFM, platform packaging, and release burden. A test-only oracle
retains independent evidence without retaining a second runtime architecture.

### Keep only gnark PlonK

Rejected because it retains nearly all of the native lifecycle and maintenance
cost while current PlonK use cases already use the Java prover and verifier.

### Merge MPF and JMT or remove JMT because no current use case imports it

Rejected by ADR-0042. They are incompatible commitment/security domains with
substantive separate implementations. Current consumer absence is not evidence
that either security boundary should be erased.

### Keep `zeroj-ceremony` separate solely because it is a CLI

Rejected because the one-class CLI already wraps `zeroj-tools`, and
`zeroj-tools` is the intended home for operator commands. The command identity
and ceremony security behavior remain separate concerns even when the Gradle
artifact boundary disappears.

## Production and audit gates

This ADR authorizes structural cleanup only. It does not close any existing
production gate for Groth16, PlonK, BBS, BLS12-381, MPF, JMT, trusted setup, or
on-chain validators.

Production claims still require the applicable external review, exact
reference vectors, ceremony provenance, provider semantics, side-channel
evidence, Yaci/public-network execution, current Cardano budget validation,
and application `ScriptContext`/replay/authorization binding required by their
governing ADRs.
