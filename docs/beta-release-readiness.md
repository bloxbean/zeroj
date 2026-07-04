# ZeroJ Beta Release Readiness Report

> Superseded by
> [`docs/production-readiness-review-2026-07-02.md`](production-readiness-review-2026-07-02.md)
> and
> [`docs/adr/0026-production-readiness-review-and-remediation-plan.md`](adr/0026-production-readiness-review-and-remediation-plan.md).
> The PlonK on-chain KZG-deferred status in this report is stale.

Date: 2026-05-28
Branch: `main`
HEAD reviewed: `503adc6`
Current project version: `0.1.0-pre2-SNAPSHOT`

## Executive Summary

ZeroJ is close to beta for the core Java/Cardano privacy path, but I would not
tag a beta yet.

The normal build, unit/integration test suite, and local Maven publication all
pass. The main blocker is the opt-in `:zeroj-examples:e2eTest` gate: it failed
with one real test failure and skipped the two Yaci DevKit transaction tests
because DevKit was not reachable. If the beta announcement claims full
Cardano/Yaci end-to-end verification, those Yaci checks should run green on a
local DevKit before tagging.

The biggest non-test work is scope control. Groth16 BLS12-381 is the beta path.
PlonK on-chain, BN254 legacy/off-chain code, MPF-on-Yaci, BBS/WASM, Halo2, and native gnark
should be clearly marked experimental or optional.

## Verification Run

Commands run locally:

| Command | Result | Notes |
|---------|--------|-------|
| `./gradlew projects` | Passed | 28 subprojects configured. Gradle reports deprecations incompatible with Gradle 10. |
| `./gradlew test` | Passed | 135 actionable tasks: 30 executed, 105 up-to-date. |
| `./gradlew build` | Passed | 217 actionable tasks: 82 executed, 135 up-to-date. Javadoc warnings remain. |
| `./gradlew publishToMavenLocal -PskipSigning` | Passed | 233 actionable tasks: 81 executed, 152 up-to-date. Artifacts published locally using commit-suffixed snapshot version. |
| `./gradlew :zeroj-examples:e2eTest` | Failed | 15 tests completed, 1 failed, 2 skipped. |

## Release Blockers

1. Fix the failing `:zeroj-examples:e2eTest`.

   `SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve()` currently calls
   `generateGroth16ProofNative(...)` for an invalid bid and expects a proof-like
   response. The circuit correctly enforces `bidAmount >= reservePrice`, so the
   witness calculator throws:

   `java.lang.ArithmeticException: Constraint violation: w1889=0 != w1890=1`

   Recommended fix: make the gnark negative-path test match the snarkjs
   negative-path test and assert `ArithmeticException`.

2. Run the actual Yaci DevKit transaction tests.

   These skipped in the current run:

   - `PureJavaProverYaciE2ETest.pureJavaProve_groth16_onChainVerify()`
   - `SealedBidOnChainE2ETest.sealedBidVerifiedOnChain()`

   The skip reason was `Yaci DevKit not running`. For beta, start Yaci DevKit
   and require `./gradlew :zeroj-examples:e2eTest` to pass.

3. Decide the beta version and remove snapshot state before tagging.

   `gradle.properties` is currently `0.1.0-pre2-SNAPSHOT`. The root build
   appends the git commit to subproject snapshot versions, so local artifacts
   publish as versions such as `0.1.0-pre2-503adc6-SNAPSHOT`. Pick the tagged
   beta coordinate, for example `0.1.0-beta1`, and verify all README/guide
   dependency snippets match it.

4. Clean the working tree.

   Current uncommitted state includes `CLAUDE.md`, `gradle.properties`, this
   report, `docs/migration/`, vision docs, and several PNGs. Decide what belongs
   in the beta commit and keep unrelated local artifacts out of the release tag.

## Scope Decisions Before Beta

Supported beta surface should be:

- Java 25 / Gradle 9.2 build.
- Core proof model, codec, verifier SPI, verifier orchestrator.
- Circuit DSL and symbolic annotation processor.
- Circuit library for BLS12-381 Groth16-ready gadgets.
- Pure Java Groth16 proving and verification for BLS12-381.
- Groth16 BLS12-381 on-chain verifier via Julc / Plutus V3.
- Cardano anchoring and CCL helpers.

Mark these as experimental or optional:

- PlonK on-chain BLS12-381: transcript and inverse checks exist, but KZG batch
  opening pairing check is explicitly deferred.
- BN254 verifiers: disabled by default and not ServiceLoader-registered. Keep
  them documented as legacy/off-chain only unless they are moved to an incubator
  module or removed.
- MPF Poseidon full proof/Yaci flow: witness/circuit pieces exist, but the
  circuit is documented as too large for the default practical Groth16/Yaci
  path.
- BBS/BBS+ and WASM modules.
- Halo2 incubator.
- gnark FFM native prover.

## Build And Release Hygiene

- Fix Gradle 10 deprecations:
  - `build.gradle`: Groovy space-assignment syntax at publishing credential and
    artifact lines.
  - `zeroj-onchain-julc/build.gradle`: `url "..."` in the buildscript repo.
- Clean Javadoc warnings before a public beta if possible. The build passes
  because `failOnError = false`, but warnings remain in `zeroj-backend-spi`,
  `zeroj-circuit-dsl`, `zeroj-circuit-lib`, `zeroj-crypto`,
  `zeroj-verifier-groth16`, and incubator Halo2.
- Add `CHANGELOG.md` / release notes for the beta.
- Verify the GitHub release workflow on the intended scope. It currently builds
  native gnark and Halo2 libraries, runs `./gradlew build`, and publishes every
  publishable module, including optional/incubator modules.
- Confirm Sonatype Central requirements with real credentials after the local
  `publishToMavenLocal` pass.

## Native Image Readiness

Several modules either lack native-image metadata or have empty placeholder
directories:

- No native-image directory: `zeroj-crypto`,
  `zeroj-circuit-annotation-api`, `zeroj-circuit-annotation-processor`,
  `zeroj-mpf-poseidon`, `zeroj-examples`.
- Empty native-image directory: `zeroj-circuit-dsl`, `zeroj-circuit-lib`.

`zeroj-examples` is non-publishable and lower priority. For beta, prioritize
`zeroj-crypto`, `zeroj-circuit-dsl`, `zeroj-circuit-lib`, and the annotation
modules because they are part of the main Java developer path. Add metadata or
document that no reflection/resource config is required, then run one GraalVM
native-image smoke test for a core prove/verify flow.

## Documentation Tasks

- Add a top-level support matrix to `README.md` with three statuses:
  `supported`, `experimental`, and `incubator/optional`.
- Keep top-level and module READMEs clear that BLS12-381 is the Cardano path and
  BN254 is disabled by default.
- Update all dependency snippets from `0.1.0` to the chosen beta version.
- Consolidate or clearly label `docs/vision.md`, `docs/vision-v2.md`,
  `docs/vision-v3.md`, and `plan.md` so beta users know which vision document
  is current.
- Keep the README warning that this is not production-audited unless a real
  cryptographic/security review has been completed.

## Recommended Pre-Beta Checklist

1. Fix `SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve()`.
2. Start Yaci DevKit and get `./gradlew :zeroj-examples:e2eTest` green.
3. Add README support matrix and keep BN254 / PlonK on-chain wording explicit.
4. Add `CHANGELOG.md` and choose final beta version.
5. Clean Gradle deprecation warnings and high-noise Javadoc warnings.
6. Add/verify GraalVM native-image metadata for core modules.
7. Run:
   - `./gradlew clean build -PskipSigning=true`
   - `./gradlew publishToMavenLocal -PskipSigning`
   - `./gradlew :zeroj-examples:e2eTest`
8. Tag the beta only from a clean worktree.
