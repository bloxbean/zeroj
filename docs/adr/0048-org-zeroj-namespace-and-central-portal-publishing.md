# ADR-0048: The `org.zeroj` namespace, Central Portal publishing, and a rehearsable release

## Status
Proposed — implemented on branch `refactor/org-zeroj-namespace`, awaiting maintainer review.

## Date
2026-09-12

## Risk classification
**R0/R1.** This is a namespace, build, and release-process change. No cryptographic algorithm,
proof equation, transcript, domain separator, public-input order, circuit relation, field or
curve operation, canonical encoding, validation rule, trusted-setup rule, or secret-handling
path changes. Every class keeps its simple name, its members, and its bytes-in/bytes-out
behavior; only the package it is declared in and the Maven group it ships under change.

It is **R1, not R0**, because two of the couplings it touches fail silently rather than at
compile time:

- `META-INF/services` provider files are named after the service interface and contain the
  provider's fully qualified name. Renaming the packages without renaming those files and their
  contents compiles cleanly and produces a `ZkVerifier` registry that finds no verifier at
  runtime — a *verification-availability* failure, not a soundness one.
- `META-INF/native-image/<groupId>/<artifactId>/` is resolved from the Maven group. Config that
  no longer resolves is skipped **silently**, and a JVM build cannot observe it. Reflection and
  resource registrations would go missing only in a downstream `native-image` build.

No maturity, audit, side-channel, production, or mainnet claim is upgraded by this ADR. The
`0.1.0-pre*` experimental status, the ADR-0025/ADR-0026 audit gates, and every open
production gate in ADR-0037/0044/0045/0046 are unchanged.

## Context

### The namespace

ZeroJ has shipped under group `com.bloxbean.cardano` with package root
`com.bloxbean.cardano.zeroj.*` since `0.1.0-pre1`. That namespace says ZeroJ is a Cardano
sub-component of the bloxbean Cardano stack. It is not: ZeroJ is a Java ZK toolkit whose
Cardano-specific surface is two modules (`zeroj-onchain-julc` and the CCL-facing parts of the
use cases), while the Groth16/PlonK provers, the BLS12-381 primitives, the circuit DSL, the
gadget library, and the BBS implementation are curve-and-protocol code with no Cardano
dependency at all.

The `org.zeroj` namespace has been reserved and verified in the Maven Central Portal.

Sibling projects made the same move: Yano to `org.yanoproject` (bloxbean/yano#130) and yano-x
to `org.yanoproject.x`. This ADR follows that pattern deliberately, including its publishing
half, so the bloxbean release pipelines stay recognizably one pipeline.

### Publishing

The build published through `io.github.gradle-nexus.publish-plugin` against the legacy OSSRH
staging API (`ossrh-staging-api.central.sonatype.com`), a compatibility shim in front of the
Central Portal. A `v*` tag ran `publishToSonatype closeSonatypeStagingRepository`, and two
further side effects were unconditional: the tag created a **public GitHub release** with the
ceremony CLI distributions attached.

That makes a release impossible to rehearse. There was no way to exercise the real signing
path, the real bundle, and the real Portal validation without also announcing a release.

### Javadoc size

JDK 21+ embeds ~3.9 MB of DejaVu web fonts into every generated javadoc tree, and ZeroJ
publishes a javadoc jar per module. The fonts are byte-identical across every one of them and
the page style falls back to system fonts without them.

## Decision

### 1. `com.bloxbean.cardano.zeroj.*` → `org.zeroj.*`, group `com.bloxbean.cardano` → `org.zeroj`

ZeroJ owns its whole package namespace, so the package move is a blanket replace. It is safe
here by inspection, not by assumption: `com.bloxbean.cardano.zeroj` is **never** followed by an
identifier character anywhere in the repository (`git grep -E
'com\.bloxbean\.cardano\.zeroj[A-Za-z0-9_]'` is empty), so no sibling package can be captured
by it. The three surviving `com.bloxbean.cardano.*` namespaces — `julc`, `vds`, `client` — are
untouched by construction.

The group move is deliberately **not** a blanket replace. `com.bloxbean.cardano` still owns
ZeroJ's dependencies — Cardano Client Lib, Julc, VDS — so only coordinates naming a `zeroj-*`
artifact moved. In particular `build.gradle`'s ADR-0042 CCL version pin still matches on
`details.requested.group == 'com.bloxbean.cardano'`, and must.

**One package stays where it is on purpose.**
`benchmarks/zeroj-mpf-poseidon-load/.../com/bloxbean/cardano/vds/mpf/BenchmarkMpfProofDepthScanner.java`
keeps its `com.bloxbean.cardano.vds.mpf` package because the concrete MPF node types it
traverses are package-private in CCL `0.8.0-pre5`. It is benchmark code in a never-published
module and it is not ZeroJ's namespace to move.

#### The couplings a dotted replace misses

- **`META-INF/services` files have no extension**, so any filter by file type skips them. Three
  `ZkVerifier` provider files (`zeroj-verifier-groth16`, `zeroj-verifier-plonk`, `zeroj-bbs`)
  were renamed on disk to `org.zeroj.backend.spi.ZkVerifier` and their contents rewritten. The
  annotation processor's `javax.annotation.processing.Processor` keeps its (JDK-owned) filename
  and has its content rewritten. Getting this half-right compiles cleanly and fails at
  `ServiceLoader` time.
- **`META-INF/native-image/<groupId>/<artifactId>/` is resolved from the group**, so ten group
  directories moved from `com.bloxbean.cardano` to `org.zeroj`. Config that no longer resolves
  is skipped silently.
- **Slash-separated paths** (`com/bloxbean/cardano/zeroj`) are invisible to a dotted replace and
  appear in architecture tests that assert on source layout, in docs, and in the ceremony
  rehearsal script.

Two pre-existing defects in that native-image layout were carried across rather than fixed
here, and are recorded so they are not mistaken for rename damage:

- The two assurance modules had their config under `META-INF/native-image/com.bloxbean.cardano.zeroj/`,
  which never matched their actual group `com.bloxbean.cardano`. They are never published, so
  the config never resolved. They now sit under `org.zeroj/`, which *does* match the new group.
- `zeroj-backend-spi` still carries a `zeroj-verifier-core` config directory for an artifact
  ADR-0044 merged away. It resolved under neither group and still does not; it moved with the
  rest and should be removed or merged into `zeroj-backend-spi/` separately.

#### Compatibility

**This is a hard break with no shim.** There are no type aliases, no relocated duplicates, and
no `com.bloxbean.cardano:zeroj-*` artifacts after `0.1.0-pre11`. ZeroJ is experimental
(`0.1.0-pre*`) software with a small, known set of consumers; a compatibility layer would double
the published surface and the `ServiceLoader` registration paths for the life of the alias.
`docs/migration/0048-org-zeroj-namespace.md` carries the mechanical migration.

Consumers who cannot migrate should pin `com.bloxbean.cardano:zeroj-*:0.1.0-pre11`, which stays
on Maven Central and is unaffected.

#### What the rename cannot change

Proof bytes, verification keys, transcripts, and serialized artifacts are unaffected: none of
them encode a Java package name. Circuit constraint systems and their fingerprints are derived
from the constraints, not from class names.

The one case that needed an actual measurement is the on-chain script hash.
`zeroj-onchain-julc` compiles Java validator sources to UPLC through Julc. If Julc embedded a
class's fully qualified name in the compiled term — in a trace string, an error message, or a
constant — the compiled script bytes, and therefore the Cardano script hash and script address,
would change with the package rename. The repository pins no golden script hash anywhere
(`git grep -E '"[0-9a-f]{56}"'` over `zeroj-onchain-julc` and `zeroj-integration-tests` is
empty); every on-chain test derives the hash and compares it to itself for determinism, so a
green suite would **not** have proved the hash unchanged.

It was therefore measured directly rather than assumed. The same probe —
`unappliedValidatorSha256(compileValidator(Groth16AuthenticatedStateTransitionValidator.class).program())`
— was run in a `main` worktree (package `com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator`)
and in this branch (`org.zeroj.onchain.julc.groth16.validator`). Both produce

```
6ee3ad3fbb38e9da14fa5b829ff206c1cf278c7208fb31c5d6be83a1b9d41874
```

Julc does not carry the Java package name into the compiled UPLC, so **the compiled validator
bytes, the Cardano script hash, and the script address are unchanged by this rename.** A
deployed ZeroJ-derived validator keeps its address. The probe was temporary and is not part of
the branch; the hash above is the evidence.

### 2. Publish through the Central Portal, and separate staging from publishing

`io.github.gradle-nexus.publish-plugin` is replaced by `com.gradleup.nmcp` (per project) and
`com.gradleup.nmcp.aggregation` (root), matching Yano.

Deployments upload as **`USER_MANAGED`**: the release run stops once Sonatype has validated the
bundle, and nothing reaches Maven Central until a human publishes it — from the Portal UI, or
through the new approval-gated `.github/workflows/publish-central.yml`, which takes the
deployment id the release run reports in its step summary. Publishing a version to Central can
never be undone, so it is deliberately not a consequence of pushing a tag.

The per-project `publishing.repositories.maven { ... }` OSSRH block is removed; releases and
snapshots both leave through the root aggregation. `snapshot.yml` therefore moves from
`./gradlew publish` — which would now have no remote target at all — to
`publishAggregationToCentralPortalSnapshots`.

**The deployment scope is derived, not restated.** It is `subprojects - nonPublishable`, the
same list the per-project publishing block uses, hoisted to `rootProject.ext` so one definition
feeds both. `verifyMavenReleasePublicationScope` asserts that the set of projects in the
deployment equals the set of projects that actually declare a `MavenPublication`, and fails on
either a module that publishes but is not deployed or a module that is deployed but publishes
nothing. A deployment that silently loses a module is worse than one that fails.

That check is attached to **`nmcpZipAggregation`**, not to the `publishAggregationToCentralPortal`
alias. The alias's dependencies are unordered relative to each other, so hanging the check off
it would let the upload run first. The zip is what every portal task depends on, so attaching it
there puts the check ahead of both the bundle and the network calls.

`zeroj-bom-core` applies `com.gradleup.nmcp` in its own build script: the root `subprojects`
block returns early for BOM projects (`java-platform` is incompatible with `java-library`), so
it would otherwise drop out of the deployment.

The root project is not deployed. It declares no publication — it has no sources, and only ever
had `maven-publish` applied because the whole build does.

### 3. Every irreversible side effect of a tag is opt-in

`github_release` in `gradle.properties` defaults to **false**. With it off, a `v*` tag:

- builds libblst from source on three platforms,
- runs the full test suite,
- runs the ADR-0044 module-surface guard and the ADR-0048 deployment-scope guard,
- signs and uploads a real Central Portal deployment, which stops at VALIDATED,
- builds the ceremony CLI native distributions on four platforms and keeps them as workflow
  artifacts,

and publishes nothing. A release becomes rehearsable end to end. `false` is the fallback
(`${VAR:-false}`), so a missing property fails safe.

The GitHub release is checked against `needs.validate.outputs.github_release` rather than being
removed from the job graph, so the distributions are still built and retained for inspection
when the release itself is skipped.

ZeroJ has no Docker or npm publication, so unlike Yano those two gates are not needed here.

### 4. Javadoc ships no fonts

`options.addBooleanOption('-no-fonts', true)` on every `Javadoc` task. The javadoc is otherwise
unchanged — same pages, same indexes, same search — and falls back to system fonts. Only the
8.8 KB `legal/dejavufonts.md` license file remains in each jar.

The 18 published javadoc jars now total **3.46 MB** and the whole Central bundle is **5.81 MB**
(both measured). The JDK 25 doclet carries 3.91 MB of `.woff`/`.woff2` faces per javadoc tree
(measured in `jdk.javadoc.jmod`), and those formats are already compressed, so the bundle would
otherwise have been roughly 70 MB larger — an estimate, not a measurement, since the
pre-change bundle was never built under the new group.

## Alternatives considered

- **Keep `com.bloxbean.cardano`.** Rejected: the namespace misdescribes the project, and the
  reserved `org.zeroj` namespace already exists.
- **Move the group but keep the package root.** Rejected: it leaves `com.bloxbean.cardano.zeroj`
  classes shipping from an `org.zeroj` group, which is the confusing half of both worlds and
  still breaks nothing less.
- **Ship `com.bloxbean.cardano.zeroj` type aliases / a relocation shim.** Rejected: see
  Compatibility above.
- **Keep publishing through the OSSRH staging API.** Rejected: it is a compatibility shim on top
  of the Portal, and it gives no natural place to put the human approval between validation and
  publication.
- **Keep `publishAggregationToCentralPortal` with `AUTOMATIC` publishing.** Rejected: a tag
  would then push an unretractable version to Central with no review, which is exactly the
  property this ADR is removing.
- **Delete the GitHub release job for dev tags.** Rejected: the four-platform native build is
  most of the value of a rehearsal. Gating the upload step keeps the build and drops only the
  announcement.

## Verification

Executed on this branch; `docs/migration/0048-org-zeroj-namespace.md` carries the consumer-facing
mapping.

1. **Default build.** `./gradlew clean build -PskipSigning=true` — **4101 tests passed, 0 failed,
   22 skipped**, across 19 test tasks. Includes `verifyDefaultModuleSurface` (run from `check`
   since ADR-0046; "21 default projects") and the ADR-0046 test-fixtures metadata guard.
2. **Independent oracles.** `./gradlew -PincludeAssurance :zeroj-bls12381-wasm:test
   :zeroj-bbs-wasm:test :zeroj-bbs:test` — **129 passed, 0 failed**, including the four
   zkcrypto/zkryptium WASM provider rows of the CFRG BBS conformance suite. This is the only run
   that exercises the renamed `assurance/` modules and their moved `org.zeroj` native-image
   directories.
3. **Opt-in benchmark modules.** `-PincludeBenchmarks` compile green; under that flag the
   deployment scope stays at 19 coordinates while the module-surface guard sees 23 projects, so
   neither guard leaks an opt-in module into the published surface.
4. **No residue.** `git grep` for the dotted, slash and coordinate forms is empty outside
   `docs/`; inside `docs/` only this ADR, migration 0048, and the deliberately preserved
   historical lines in migration 0044 and ADR-0037 remain. No file sits under a
   `com/bloxbean/cardano/zeroj` path; the one intentional `com/bloxbean/cardano/vds` benchmark
   file is accounted for above.
5. **The deployment bundle.** `nmcpZipAggregation` — **19 coordinates**, all under `org/zeroj/`:
   18 jar coordinates each with jar, sources, javadoc, POM and Gradle module metadata, plus
   `zeroj-bom-core` as `pom` packaging. Zero `com/bloxbean` or `com.bloxbean` paths in any jar
   (sources jars included). Every POM carries `<name>` and `<description>`. POM dependency
   groups are `org.zeroj` for ZeroJ modules and still `com.bloxbean.cardano` for Julc and CCL.
   `zeroj-crypto`'s module metadata declares only `apiElements`, `runtimeElements`,
   `sourcesElements`, `javadocElements` — no test-fixtures variant (ADR-0046 holds).
   `zeroj-tools` ships its picocli config at
   `META-INF/native-image/picocli-generated/org.zeroj/zeroj-ceremony/`.
6. **Downstream consumer.** `publishToMavenLocal`, then all 13 `zeroj-usecases` projects built
   and tested against `org.zeroj:*:0.1.0-pre12-dev1` from Maven Local — **73 tests passed, 0
   failed, 8 skipped**. This is what exercises the `ServiceLoader` registration and the
   annotation processor across a module boundary, which a compile alone cannot.
7. **On-chain identity.** The Julc-compiled validator hash is byte-identical across the rename
   (Decision 1).

Every local run used `-PskipSigning=true`, so signing was left to the tag.

8. **The tag rehearsal.** `v0.1.0-pre12-dev1` ran the real pipeline
   ([run 34673413353](https://github.com/bloxbean/zeroj/actions/runs/34673413353), all 9 jobs
   green): libblst from source on linux/amd64, linux/aarch64 and mac/aarch64; the full suite;
   the module-surface guard; a signed deployment uploaded as `USER_MANAGED`, which reached
   **VALIDATED** as `f04ee872-a2f5-4444-8d6c-a647dde1e2f3` and stopped there; and the ceremony
   CLI native distributions on linux-x86_64, linux-arm64, macos-arm64 and windows-x86_64.

   Passing Central validation is what closes the signing gap: the Portal checks the `.asc`
   detached signatures, the sources/javadoc requirement per coordinate, and the namespace
   ownership, so it confirms both that signing works under nmcp and that `org.zeroj` is verified
   for this account.

   With `github_release = false`, the latest GitHub release is still `v0.1.0-pre11` — nothing was
   announced — while the four CLI distributions were still built and retained as
   `ceremony-cli-preview-*` workflow artifacts. That is the rehearsable release this ADR is for:
   a tag that exercises everything and publishes nothing.

## Production gates that remain open

Unchanged by this ADR, and restated so the rename is not mistaken for progress on any of them:
the ADR-0025/ADR-0026 independent Groth16/BLS12-381 audit, the ADR-0037 Jubjub remediation
(P0–P6), the ADR-0044 module-surface Yaci gate, the ADR-0045 and ADR-0046 review gates, and the
production trusted-setup ceremony. ZeroJ remains experimental research software.

## Human review / action required

- The `release` GitHub environment must have **required reviewers** configured in repository
  settings. `environment: release` in `publish-central.yml` is only an approval gate if it does;
  without reviewers it is a no-op label and the workflow publishes on dispatch alone. This
  cannot be done from the repository contents.
- The staged deployment from the `v0.1.0-pre12-dev1` rehearsal —
  `f04ee872-a2f5-4444-8d6c-a647dde1e2f3` — must be **dropped** in the Portal, not published. It
  is a dev build and would otherwise occupy `org.zeroj:*:0.1.0-pre12-dev1` on Central forever.
