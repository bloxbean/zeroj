# ADR-0050: Julc `0.1.0-pre17`, the `org.julclang` namespace, and typed BLS12-381 values

## Status
Proposed. Implemented through M7 on branch `build/julc-pre17-org-julclang` (cut from `origin/main`
at `ad68fc5`) and awaiting maintainer review. It lands before ZeroJ `0.1.0-pre12` (Q1). M8 is
follow-up work outside this repository.

## Date
2026-09-29

## Risk classification
**R2.** Upgrading Julc from `0.1.0-pre16` to `0.1.0-pre17` means:

- editing the source of every on-chain verifier library (Groth16, PlonK, BBS), including the lines
  that compute the proof equation, because pre17 retypes BLS12-381 values;
- renaming a public on-chain helper (`Groth16BLS12381Lib.publicInputs`), because pre17 rejects
  overloaded methods;
- changing the compiled bytes, script hashes and budgets of every Julc validator, and with them
  the authenticated-state release identity (`COMPILER_PROFILE`).

It is not intended to be R3: no proof equation, transcript, domain separator, challenge derivation,
public-input order, canonical-encoding rule, subgroup/infinity rule or field/curve operation is
meant to change. The source edits in proof-equation code must still be reviewed with R3 care. They
are supposed to change types only, and review must confirm that line by line.

No maturity, audit, production or mainnet claim changes. PlonK and BBS on-chain remain
experimental. Groth16 on-chain remains beta and testnet-only. The ADR-0026 production gates are
unchanged.

## Pinned references

- Julc tag `v0.1.0-pre17` (commit `a353da6a`), published to Maven Central as
  `org.julclang:julc-*:0.1.0-pre17`. Verified 2026-09-29: `julc-stdlib`, `julc-ledger-api`,
  `julc-annotation-processor`, `julc-compiler`, `julc-testkit`, `julc-vm-java`,
  `julc-cardano-client-lib`, `julc-gradle-plugin` and the plugin marker
  `org.julclang.julc:org.julclang.julc.gradle.plugin:0.1.0-pre17` all resolve.
- Julc ADR-040 (groupId and package rename), ADR-047 (typed BLS values and MSM), ADR-052 (pre17
  profile freeze), ADR-060 (generated-binder namespace, overload rejection), the pre17 release notes
  and `reference/hash-stability.md`.
- ZeroJ ADR-0042 (the pre14 → pre16 upgrade precedent), ADR-0045 (Groth16 infinity-IC profile),
  ADR-0048 (namespace-rename couplings), and `zeroj-onchain-julc/README.md` (the compiler-upgrade rule).

## Context

### What pre17 changes

1. **Coordinates.** The group changes from `com.bloxbean.cardano` to `org.julclang`. The package
   root changes from `com.bloxbean.cardano.julc.*` to `org.julclang.*`, with the same subpackages. The
   Gradle plugin id changes from `com.bloxbean.cardano.julc` to `org.julclang.julc`. There is no
   dual publish and no alias. Julc verified that the rename alone produces byte-identical UPLC (58
   validators in `julc-examples`).
2. **Typed BLS12-381 values (Julc ADR-047).** Points are `JulcG1` and `JulcG2`, and Miller-loop
   results are `JulcMlResult` (package `org.julclang.core.types`). Every `Builtins.bls12_381_*`
   method now takes and returns these types. Only `*_compress` produces `byte[]`, and only
   `*_uncompress` consumes it. A point typed as `byte[]` is rejected (`JULC0041`), and so is a point
   at a validator boundary (`JULC0042`). According to the release notes, code that uses `var` or the
   new types keeps its bytes.
3. **New rejections (Julc ADR-060).** Overloaded methods are rejected (`JULC0054`) unless they
   compile to identical code, because pre16 ran the *last* declared overload for every call. Also
   rejected: compound bit operators (`JULC0052`), multi-variable declarations (`JULC0053`),
   calls on untyped receivers (`JULC0055`), field updates in loops (`JULC0056`), and
   `instanceof` pattern variables that shadow a field (`JULC0059`).
4. **Correctness fixes that change bytes for affected shapes.** These cover builder binders
   capturing user variables (#186), generated names colliding with user names, and compound
   assignment in loops. A program that used an affected shape now behaves like Java and has
   different bytes.
5. **New default-on optimizations since pre16.** O5 (sealed dispatch lowered to PV11 `Case`), O8,
   O10, O14 and O15 all landed between pre16 and pre17, and they are part of the default `pv11-safe`
   profile. The pre17 freeze (Julc ADR-052) promises stable bytes *from pre17 onward*, not
   relative to pre16. **ZeroJ's scripts should therefore be expected to change even where the
   source does not.** This must be measured, not assumed.
6. **Unchanged.** The JVM behaviour of the BLS builtins is the same (both versions throw
   `UnsupportedOperationException` off-chain; evaluation is in the Julc VM). Julc's CCL dependency
   is 0.7.2 in both versions, and ZeroJ's rule pinning CCL to `0.8.0-pre5` keys on CCL's own group,
   which the rename doesn't touch.

### Spike (2026-09-29, throwaway worktree at `origin/main` `ad68fc5`)

- A mechanical rename of coordinates, plugin id and imports touched **31 files / 159 lines**
  outside `docs/` and `www/`. All **28** Julc classes ZeroJ imports exist under the mapped
  `org.julclang` name.
- `./gradlew :zeroj-onchain-julc:compileJava` then fails in the Julc annotation processor for all
  six validators:
  - **Groth16** (`Groth16BLS12381Verifier`, `…TxOutRefBindingVerifier`,
    `Groth16AuthenticatedStateTransitionValidator`): `Method publicInputs is declared more than
    once in Groth16BLS12381Lib` (`JULC0054`). The library declares six overloads, one for each of
    1–6 public inputs.
  - **PlonK** (`PlonkBLS12381Verifier`, `…MultiInputVerifier`, `…MultiInputParamVerifier`):
    `Variable 'qm' initializer received G1, but requires ByteString` (`JULC0041`).
  - The compiler stops at the first error per validator, so these counts are a lower bound. The
    retyping errors in the Groth16 and BBS libraries surface only after the overload fix.
- Retyping scope, estimated from source: locals assigned a point or Miller-loop result from a BLS
  builtin number 17 in `Groth16BLS12381Lib`, 20 in `PlonkBLS12381Lib` and 3 in `BbsProofVerify`.
  Helper parameters and returns that carry points add to this (for example `computeVkX`,
  `addPublicInput` and `verifyWithComputedVkX` in Groth16). The on-chain libraries use recursion,
  not loops, so the pre17 rule that a native BLS accumulator must be a loop's only accumulator
  does not apply. `@Param` fields and redeemer/datum fields are compressed `byte[]` and stay that
  way.

### Finding: pre16 overload behaviour (confirmed)

Per the Julc release notes, pre16 compiled every call to `Groth16BLS12381Lib.publicInputs(...)`
to the last declared overload, which is the 6-input one. M1 reproduced this on pre16 with a probe
validator. Calls with 1, 2 and 3 inputs failed at evaluation (`UnListData: expected data, got
VLam`); the 6-input call succeeded. The bug **fails closed**: a validator that builds fewer than 6
inputs this way rejects every spend and never accepts an invalid one. There are no on-chain callers
in this repository. The one known on-chain caller, `zeroj-usecases/personhood-airdrop`
`FaucetMintingPolicy`, passes 6 inputs and was therefore correct.

### Finding: the pre17 Gradle plugin fails `build` without `src/main/plutus`

`compileJulc` compiles Julc's `.plutus` DSL sources from `src/main/plutus`. Its `sourceDir` input
was `@SkipWhenEmpty` in pre16 and is `@Optional` in pre17. As a result, pre17 fails `build` with an
input-validation error when the directory is absent, even though the property is optional. Julc
ADR-040 lists this as an open follow-up. ZeroJ's validators are Java and are compiled by the
annotation processor, so the task has no work here. `zeroj-onchain-julc/build.gradle` enables it
only when `src/main/plutus` exists. `test` never runs the task, so only `build` exposed this.

## Security invariants (must hold before and after)

- **I1: Groth16 equation.** The same builtin sequence evaluates
  `e(A,B)·e(−α,β) == e(vkX,γ)·e(C,δ)` via `millerLoop`, `mulMlResult` and `finalVerify`, with the
  same operand order.
- **I2: Point validation.** Compressed lengths (48/96), the canonical round trip
  `compress(uncompress(x)) == x`, and the non-infinity rules for proof and VK points are unchanged,
  as is the ADR-0045 IC profile.
- **I3: Public inputs.** Each scalar must be in `[0, r)`, input and IC lengths must match, and an
  empty IC is rejected. The `vkX` accumulation order is unchanged.
- **I4: PlonK.** Transcript bytes and order, domain separators, challenge derivation, profile and
  count binding, inverse-witness checks and the KZG batch-opening pairing are unchanged.
- **I5: BBS.** `hash_to_scalar`, the challenge and the pairing check are unchanged.
- **I6: Context binding.** TxOutRef binding and the authenticated-state rules (roots, version
  increment, signer, value/token conservation, no mint) are unchanged.
- **I7: Boundary encodings.** `@Param`, datum and redeemer shapes stay compressed bytes and
  integers, so `ProverToCardano`, `SnarkjsToCardano`, `PlonKProverToCardano` and the VK codec are
  unchanged.
- **I8: No silent relabel.** `COMPILER_PROFILE` moves to `julc-0.1.0-pre17/plutus-v3` only
  together with regenerated bytes, a new template digest and new release manifests. Artifacts
  produced under pre16 keep their pre16 label.

## Decision (proposed)

1. Move to `org.julclang:*:0.1.0-pre17` and plugin `org.julclang.julc` on this branch in one change.
   No mixed state.
2. Retype BLS values with the explicit types (`JulcG1`, `JulcG2`, `JulcMlResult`) rather than
   `var`. Both keep bytes, according to the release notes. Explicit types document which group
   each value is in and let the compiler reject a G1/G2 mix-up (`JULC0041`).
3. Replace the six `publicInputs` overloads with distinct names (see Q2).
4. Keep Julc's default `pv11-safe` profile and accept new script bytes. Do not select `none` or
   `baseline` to chase pre16 bytes: neither reproduces pre16, and Julc ADR-052 rules out using
   `baseline` to recover historical output.
5. Bump `COMPILER_PROFILE` and the README baseline, and regenerate the authenticated-state template
   digest and manifests, following the rule already in `zeroj-onchain-julc/README.md`.

### Alternatives considered
- **Use `var` for BLS values.** This is a smaller diff with identical bytes, but a G1/G2 mix-up
  would no longer be visible in the source. Rejected for verifier code.
- **Stay on pre16.** Every later Julc fix would then be out of reach, including the pre17
  miscompile fixes, and consumers would be stuck on a namespace Julc no longer publishes. Rejected
  as a long-term state; it is only an option for sequencing (Q1).
- **Also switch vkX accumulation to `BlsLib.g1MultiScalarMul` (PV11 MSM).** Julc reports this is
  cheaper in CPU from about 7 inputs. But it changes the proof-equation code path and depends on
  PV11 being live on the target network. Deferred to its own R2/R3 ADR.

## Inventory

| Area | Change |
|---|---|
| `zeroj-onchain-julc/build.gradle` | buildscript classpath, `plugins { id }`, `apply plugin`, `julcVersion`, 6 dependency coordinates; `compileJulc` enabled only when `src/main/plutus` exists |
| `zeroj-integration-tests/build.gradle` | `julcVersion`, 5 dependency coordinates |
| `zeroj-onchain-julc/src/main` | imports in 11 files; BLS retyping in the Groth16, PlonK and BBS libraries; `publicInputs` rename; `COMPILER_PROFILE` |
| `zeroj-onchain-julc/src/test`, `zeroj-integration-tests/src/test` | imports in 18 files; test validators follow the library changes; regenerated fixtures |
| `zeroj-onchain-julc/README.md` | Julc baseline and compiler-profile text |
| `docs/migration/0050-julc-pre17.md` (new) | consumer migration: Julc coordinates, plugin id, imports, `publicInputs` rename, new script hashes |
| `www/` | coordinates in `installation.mdx`, `guides/verifying/on-chain.mdx` and `tutorials/verify-on-cardano.mdx`; Julc imports in 5 pages; `scripts/check-release.mjs` (hard-coded `com.bloxbean.cardano` group); `release.json` `julc`; AI starter pack regenerates from these |
| Not changed | historical ADR text (ADR-0042, ADR-0048) and `docs/migration/0048-*`, which record decisions as they were made |
| Outside this repo | `zeroj-usecases`: 11 modules, still on Julc **pre14**, plus the `publicInputs` rename in `personhood-airdrop`. Separate follow-up. |

## Compatibility

- **Consumers of the `@OnchainLibrary` helpers** compile ZeroJ's library source with their own
  Julc. After this change they need Julc pre17 under `org.julclang`, because the library source
  uses `JulcG1`/`JulcG2`. This is breaking by design, matching Julc's own no-alias policy.
- **`Groth16BLS12381Lib.publicInputs(...)`** is a source-breaking rename for on-chain callers.
- **Script hashes change.** Scripts already deployed keep working, since on-chain bytes never
  change. New deployments get new hashes and addresses, and reference scripts must be
  republished. Authenticated-state manifests from pre16 stay valid only under their pre16 label.
- **Off-chain APIs are unchanged.** Codecs, provers, verifiers and parameter/redeemer encodings
  (I7) don't change.

## Implementation milestones

- **M0: plan.** This ADR and the branch.
- **M1: pre16 baseline, no edits.** Clean-build `origin/main`. Save every
  `META-INF/plutus/*.plutus.json` (template `cborHex`, hash and size) for the six validators, plus
  the test-compiled validators (fixed four-input Groth16, sealed-bid auction, BBS probes). Record
  the authenticated-state template digest and the CPU/memory of each positive VM test.
  Reproduce the fewer-arity `publicInputs` call on pre16 and record fail-closed or not.
- **M2: mechanical rename.** Change coordinates, plugin id and imports, and bump the version.
  Residue audit: `git grep -E 'com\.bloxbean\.cardano(\.julc|:julc)'` may only hit the historical
  documents listed above.
- **M3: source migration.** Rename the overloads, retype the BLS values, and clear any further
  `JULC0052`–`JULC0059` diagnostics. Review the diff of the three libraries line by line: types
  and names only, no expression, operand or order change (I1–I5).
- **M4: verification.**
  - The full `zeroj-onchain-julc` and `zeroj-integration-tests` suites pass, including every
    negative case: tampered proof, wrong VK, non-canonical and infinity points, out-of-range
    scalars, arity mismatch, replay and binding.
  - **Verdict equivalence:** every proof and context in the test corpus gets the same
    accept/reject from the pre16 and pre17 scripts.
  - Record the byte and hash diff against M1, with CPU/memory and size before and after, and
    confirm limits still hold (BBS was about 2.4×10⁹ CPU).
- **M5: release identity.** Bump `COMPILER_PROFILE`. Regenerate the template digest and the
  release manifests the tests use. Update the README.
- **M6: on-chain.** Run the Yaci DevKit E2E tests (Groth16 pure-Java prover, sealed-bid auction,
  authenticated state) against live protocol parameters.
- **M7: documentation.** Write the migration note, update the docsite snippets and imports, make
  `check-release.mjs` group-aware, and update `release.json` `julc` together with the ZeroJ
  release that ships this change (Q1).
- **M8: follow-ups.** Migrate `zeroj-usecases` (pre14 → pre17). Write the MSM ADR.

The decisive evidence is not that the suite passes. It is:

1. verdict equivalence across pre16 and pre17 on the full corpus;
2. a review showing type-only changes in proof-equation code;
3. the documented byte and budget diff.

## Verification evidence (2026-09-29)

**Method.** For **pre16**, the baseline was `origin/main` at `ad68fc5`, unmodified, in a separate
worktree. For **pre17**, it was this branch. Each run added a temporary copy of Julc's testkit
`BudgetAssertions`, generated from Julc's own source at the matching tag. The copy keeps the
original method bodies and also appends every `assertSuccess`/`assertFailure` to a ledger: the
calling test, the call's ordinal within that test, the expected and actual verdict, CPU and
memory. The copy was never on the branch. No existing test's inputs or expectations changed. The
only test edits are import renames, the PlonK prototype's type changes, and the new
`PublicInputsBuilderTest`.

**Tests.** `zeroj-onchain-julc` runs 69 tests on both versions (2 skipped on both), plus 16 new
`PublicInputsBuilderTest` cases on pre17. The new cases check each `publicInputsN` in order and
reject reordered inputs and inputs of another length. `zeroj-integration-tests` runs 63 tests on
both versions. `:zeroj-onchain-julc:build`, `:zeroj-integration-tests:build`, `:zeroj-bom-core:build`
and both benchmark modules (`-PincludeBenchmarks`) build. The full `./gradlew build` passes: 19
modules, 4,144 tests, 0 failures, 22 skipped. The docsite builds, and `check-site`,
`check-api-refs` and `check-release` pass, the last against Maven Central.

**Verdict equivalence.** All 84 ledger checks common to both runs give the same verdict on pre16
and pre17: 22 accepts and 62 rejects. Every check met its expectation on both. The rejects cover
tampered proofs, wrong keys, non-canonical and infinity points, out-of-range scalars, arity
mismatches, and replay and binding failures across the Groth16, PlonK, BBS and authenticated-state
validators.

**Costs of accepted spends** (median per test class, Julc VM, pre16 → pre17):

| Test class | n | CPU | Memory |
|---|---:|---|---|
| `Groth16BLS12381VerifierTest` | 4 | 2,919.3M → 2,901.1M (−0.6%) | 227.5k → 161.2k (−29.2%) |
| `Groth16BLS12381PureJavaProverTest` | 1 | 2,822.1M → 2,805.4M (−0.6%) | 211.8k → 154.2k (−27.2%) |
| `CircomToOnChainE2ETest` | 1 | 2,822.1M → 2,805.4M (−0.6%) | 211.8k → 154.2k (−27.2%) |
| `Groth16AuthenticatedStateTransitionValidatorTest` | 2 | 2,974.8M → 2,926.3M (−1.6%) | 714.5k → 554.2k (−22.4%) |
| `PoseidonAuthenticatedStateTransitionE2ETest` | 2 | 2,975.0M → 2,926.5M (−1.6%) | 714.5k → 554.2k (−22.4%) |
| `PlonkBLS12381VerifierTest` | 1 | 4,606.0M → 4,559.5M (−1.0%) | 703.7k → 565.4k (−19.7%) |
| `PlonkBLS12381MultiInputVerifierTest` | 5 | 4,683.8M → 4,622.5M (−1.3%) | 987.4k → 788.6k (−20.1%) |
| `PlonkBLS12381TranscriptPrototypeTest` | 1 | 3,092.3M → 2,999.1M (−3.0%) | 719.3k → 491.5k (−31.7%) |
| `BbsProofVerifyVmTest` | 1 | 2,434.4M → 2,433.8M (0.0%) | 144.7k → 169.5k (**+17.1%**) |
| `BbsHashToScalarVmTest` | 4 | 12.1M → 14.2M (**+17.4%**) | 33.4k → 45.8k (**+37.0%**) |

BBS is the one regression. `BbsHashToScalar` is unchanged source, so its cost change comes from the
compiler alone. It stays far inside the per-transaction limits (10¹⁰ CPU, 1.4×10⁷ memory), and BBS
on-chain remains experimental. It is recorded here instead of being tuned away in this change.

**Compiled validators** (unapplied template bytes, pre16 → pre17). All six changed; all are smaller:

| Validator | Bytes |
|---|---|
| `Groth16BLS12381Verifier` | 1,064 → 1,059 (−5) |
| `Groth16BLS12381TxOutRefBindingVerifier` | 1,279 → 1,260 (−19) |
| `Groth16AuthenticatedStateTransitionValidator` | 3,307 → 3,015 (−292) |
| `PlonkBLS12381Verifier` | 4,036 → 3,914 (−122) |
| `PlonkBLS12381MultiInputVerifier` | 4,435 → 4,308 (−127) |
| `PlonkBLS12381MultiInputParamVerifier` | 4,435 → 4,308 (−127) |

**On-chain (Yaci DevKit).** `PureJavaProverYaciE2ETest` and `SealedBidOnChainE2ETest` pass on both
versions. In the pure-Java Groth16 unlock, the node accepted the pre16 spend at 3,016,542,406 steps
and 246,119 memory (script hash `a40afdf7…`). It accepted the pre17 spend at 2,996,842,825 steps
(−0.7%) and 177,281 memory (−28.0%) (script hash `cb0001ec…`).

**Source review (I1–I5).** The three libraries changed only in declared types (`byte[]` →
`JulcG1`/`JulcG2`/`JulcMlResult` for points and Miller-loop results), the `publicInputsN` names and
the imports. A script made the type edits: 56 locals and 9 helper signatures in the libraries, and 23
locals in the PlonK test prototype, each one checked. A manual pass found one more local
(`beta`) that the script's pattern missed because of alignment spacing.
No expression, operand, call order, check or constant changed. Compressed inputs, `@Param` fields
and redeemer and datum fields stay `byte[]`.

**Not covered.** The authenticated-state bundles from the benchmark modules (`-Dzeroj.poseidon*`),
the two skipped tests, snarkjs-only E2E tests and GraalVM native-image builds were not rerun here.
Pre16 bundles are refused by design (I8). They are regenerated by the release process.

## Open questions

Resolved by the maintainer on 2026-09-29:

- **Q1: sequencing.** Land before `0.1.0-pre12`, so pre12 ships on `org.julclang`. `release.json`
  now names JuLC `0.1.0-pre17`.
- **Q2: the overload replacement.** `publicInputs1` … `publicInputs6`. The count is part of each
  name, which is exactly what the overloads lost on-chain. The helpers stay because
  `zeroj-usecases` relies on them.
- **Q3: typing.** Explicit `JulcG1` / `JulcG2` / `JulcMlResult` rather than `var`.

## Production and audit gates
Unchanged. Any audit scope that covered Julc-compiled bytes must now cover the pre17 bytes. A
review of pre16 scripts does not carry over to recompiled ones.
