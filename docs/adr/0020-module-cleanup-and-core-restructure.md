# ADR-0020: Module Cleanup and Core Restructure

## Status
Accepted

## Date
2026-05-17

## Context

ZeroJ has accumulated too many top-level Gradle modules. Some are shipping and
important, some are optional accelerators, some are incubating research paths,
and some are app-layer workflows that are not required for the privacy-first
vision in `docs/vision-v3.md`.

The current module layout makes the project look broader and less focused than
the intended product:

```text
Java circuit authoring
pure-Java proving and verification
Groth16 / PlonK over BLS12-381
Cardano transaction binding
JuLC on-chain verification
privacy templates and proof envelopes
```

Several dependency-layering problems also exist:

1. `zeroj-prover-gnark` depends on `zeroj-prover-sidecar` only to reuse
   prover contracts and result/error types. The shared prover SPI should not
   live inside an HTTP sidecar transport module.
2. Before this cleanup, `zeroj-crypto` depended on `zeroj-verifier-plonk` for
   Fiat-Shamir transcript code. This made a foundation module depend on a
   verifier implementation.
3. The BOM currently advertises optional and incubating modules as first-class
   dependencies, which blurs the difference between the shipping core and
   experimental integrations.

The cleanup must preserve everything the v3 vision classifies as shipping:

- Groth16 BLS12-381 verification
- PlonK BLS12-381 verification, budget-sensitive
- pure-Java proving where available
- gnark native proving as a production fast path
- `zeroj-blst` as stable opt-in BLS12-381 acceleration
- BBS as a visible mainline credential backend, but not part of the core
  Cardano SNARK BOM

## Decision

### 1. Define the mainline core

The mainline project remains focused on the privacy-first Cardano path.

Core modules included in `zeroj-bom-core`:

| Module | Role |
|--------|------|
| `zeroj-api` | Core proof envelopes, IDs, public inputs, witnesses, verification material. |
| `zeroj-codec` | Canonical proof and VK serialization. |
| `zeroj-backend-spi` | Verifier-side SPI: `ZkVerifier`, backend descriptors, VK registry. |
| `zeroj-verifier-core` | Verifier registry and orchestration. |
| `zeroj-verifier-groth16` | Groth16 verification, including BLS12-381 path for Cardano. |
| `zeroj-verifier-plonk` | PlonK verification; BLS12-381 is shipping but budget-sensitive on-chain. |
| `zeroj-bls12381` | Pure Java BLS12-381 primitives and provider interface. |
| `zeroj-blst` | Stable opt-in native BLS12-381 acceleration. |
| `zeroj-crypto` | Pure Java proving and cryptographic foundations. |
| `zeroj-circuit-dsl` | Java circuit authoring API. |
| `zeroj-circuit-lib` | Circuit gadgets and privacy primitives. |
| `zeroj-prover-spi` | New prover-side SPI, extracted from sidecar. |
| `zeroj-prover-gnark` | Shipping native gnark prover fast path. |
| `zeroj-onchain-julc` | JuLC-based Cardano on-chain verifiers and on-chain preparation helpers. |
| `zeroj-cardano` | Lightweight Cardano anchoring and proof metadata models. |
| `zeroj-ccl` | Cardano Client Lib transaction integration. |
| `zeroj-patterns` | Privacy templates: nullifier, membership, credential, DPP, range patterns. |

Mainline modules included only in `zeroj-bom-all`:

| Module | Role |
|--------|------|
| `zeroj-bbs` | Mainline BBS credential backend; visible and supported, but outside the core Cardano SNARK BOM. |

Support modules:

| Module | Role |
|--------|------|
| `zeroj-test-vectors` | Test fixtures and interoperability vectors. |
| `zeroj-examples` | Demos and end-to-end examples; not a production dependency signal. |
| `zeroj-bom-core` | New BOM for the shipping privacy-first Cardano path. |
| `zeroj-bom-all` | New BOM including optional and incubating modules. |

### 2. Add `zeroj-prover-spi`

Create a new module, `zeroj-prover-spi`, for prover-side abstractions.

Move these types from `zeroj-prover-sidecar`:

- `ProverService`
- `ProveRequest`
- `ProveResponse`
- `ProverException`

`zeroj-prover-gnark` must depend on `zeroj-prover-spi`, not on
`zeroj-prover-sidecar`. It may use shared response and exception types without
implementing `ProverService` directly if its native proving API requires richer
inputs than `ProveRequest` can express.

`zeroj-prover-spi` is separate from `zeroj-backend-spi` because
`zeroj-backend-spi` is verifier-side SPI:

- `ZkVerifier`
- `BackendDescriptor`
- `VerificationKeyRegistry`
- `InMemoryVerificationKeyRegistry`

Do not overload `zeroj-backend-spi` with prover transport concerns. A future
rename to `zeroj-verifier-spi` may be considered, but is not part of this ADR.
`zeroj-prover-gnark` must not service-load a verifier-side `ZkVerifier`; PlonK
verification is owned by `zeroj-verifier-plonk`.

### 3. Remove app-layer submission pipeline modules

Remove:

- `zeroj-submission`
- `zeroj-ingestion`

These modules model proof-backed application submissions, state-root updates,
submitter authorization, nullifier storage, sequence checks, audit logs, and
pipeline governance. They are useful application infrastructure, but they are
not required for the v3 core SDK and distract from the focused Java/Cardano/ZK
developer path.

If needed later, they can return as a separate reference app or Yaci-oriented
integration package.

### 4. Remove sidecar prover module for now

Remove:

- `zeroj-prover-sidecar`

Remote proving is a valid deployment choice, but it is not needed for the
local-first v3 core. Removing it also prevents an HTTP transport module from
owning shared prover SPI types.

If remote proving becomes a product requirement later, reintroduce it as an
optional implementation of `zeroj-prover-spi`.

### 5. Remove RapidSNARK module

Remove:

- `zeroj-prover-rapidsnark`

Rationale:

- BN254 is not Cardano on-chain feasible with current Plutus builtins.
- The module is native and platform-packaging-heavy.
- RapidSNARK adds LGPL/native distribution complexity.
- It is not needed for the v3 shipping path.

### 6. Merge useful on-chain experimental helpers, then remove the module

Remove:

- `zeroj-onchain-experimental`

Before removal, merge useful code into `zeroj-onchain-julc` where it directly
supports the shipping on-chain verifier path:

- `ScriptBudgetEstimator`
- `OnChainFeasibility`
- selected deployment pattern/config types from `ReferenceScriptDeployer`

Do not blindly move everything:

- `OnChainProofPreparer` overlaps with `SnarkjsToCardano` and
  `ProverToCardano`.
- `OnChainVkPreparer` overlaps with existing VK/proof conversion flows.

Any moved helper must get tests in `zeroj-onchain-julc`. Stale or duplicate
conversion code should be deleted instead of preserved.

### 7. Keep BBS visible but outside the core BOM

Keep:

- `zeroj-bbs`

`zeroj-bbs` is a real, tested credential backend and supports the privacy
vision. It remains mainline so credential developers can find it easily.

However, BBS is not the same as Cardano on-chain SNARK verification. It is an
off-chain credential presentation backend today, with future circuit/on-chain
integration possible. Therefore:

- include it in `zeroj-bom-all`
- exclude it from `zeroj-bom-core`
- document it as "mainline credential backend, not part of the core Cardano
  SNARK path"

### 8. Keep WASM and research providers outside the core BOM

Keep as optional/incubating modules, but outside `zeroj-bom-core`:

- `zeroj-bbs-wasm`
- `zeroj-bls12381-wasm`
- `zeroj-prover-wasm`
- `zeroj-verifier-halo2`

These modules are useful for provider experimentation, compatibility, or
research, but they are not required for the default Java/Cardano/ZK path.

They may remain in `settings.gradle`; physical moves into `incubator/` are not
required for this cleanup. BOM exclusion and documentation grouping do the
important work without adding directory churn.

`zeroj-verifier-halo2` remains research/incubator because Halo2/Pallas is not
Cardano on-chain feasible today. Do not archive it as part of this cleanup.

### 9. Keep gnark, PlonK, and blst in mainline

Do not demote:

- `zeroj-prover-gnark`
- `zeroj-verifier-plonk`
- `zeroj-blst`

Rationale:

- `zeroj-prover-gnark` is shipping and remains the production fast path for
  native proving.
- `zeroj-verifier-plonk` is shipping; Groth16 is the default on-chain path, but
  PlonK BLS12-381 is supported and budget-sensitive.
- `zeroj-blst` is stable opt-in native acceleration for BLS12-381.

Documentation must distinguish:

- pure Java proving and verification as the zero-dependency path
- gnark and blst as production acceleration paths
- Groth16 as the default on-chain path
- PlonK as supported and budget-sensitive

### 10. Fix `zeroj-crypto` to not depend on `zeroj-verifier-plonk`

Move shared transcript code currently used by both PlonK proving and PlonK
verification out of `zeroj-verifier-plonk`.

Target:

- `zeroj-crypto`, if transcript code is fundamentally proving/crypto
  infrastructure
- or a small shared package inside a lower-level module

After the change:

- `zeroj-crypto` must not depend on `zeroj-verifier-plonk`, including test
  dependencies
- `zeroj-verifier-plonk` may depend on `zeroj-crypto` or the shared lower-level
  transcript implementation

### 11. Split the BOM

Replace the single broad BOM with:

| BOM | Includes |
|-----|----------|
| `zeroj-bom-core` | Main shipping Cardano privacy path: API, codec, verifier SPI/core, Groth16, PlonK, BLS12-381, blst, crypto, circuit DSL/lib, prover SPI, gnark, onchain-julc, cardano, CCL, patterns. |
| `zeroj-bom-all` | Everything in core plus BBS, WASM providers, Halo2, prover WASM, examples-facing optional modules. |

If the existing artifact name `zeroj-bom` is already public, keep it for one
transition release as an alias to `zeroj-bom-all` or document the replacement
clearly. New users should be directed to `zeroj-bom-core`.

## Implementation Plan

### Phase 1: Prover SPI extraction

1. Add `zeroj-prover-spi`.
2. Move `ProverService`, `ProveRequest`, `ProveResponse`, and
   `ProverException` into it.
3. Update packages and imports in `zeroj-prover-gnark`.
4. Update tests that refer to old sidecar package names.
5. Remove `zeroj-prover-gnark -> zeroj-prover-sidecar` dependency.
6. Remove any gnark verifier-side SPI registration; gnark remains the native
   proving path, while `zeroj-verifier-plonk` owns PlonK verification.

### Phase 2: Remove app-layer and sidecar modules

1. Remove `zeroj-submission`, `zeroj-ingestion`, and `zeroj-prover-sidecar`
   from `settings.gradle`.
2. Remove these modules from BOM constraints.
3. Update or delete examples that depend on them.
4. Audit docs and use cases for removed modules:
   - `zeroj-submission`
   - `zeroj-ingestion`
   - `zeroj-prover-sidecar`
5. Add migration guidance in `docs/migration/0020-module-cleanup.md` or the
   project changelog, listing removed coordinates and replacements.
6. Remove README references that present removed modules as core modules.

### Phase 3: Remove RapidSNARK

1. Remove `zeroj-prover-rapidsnark` from `settings.gradle`.
2. Remove BOM and README references.
3. Add RapidSNARK to the migration guidance with the recommendation to use
   `zeroj-prover-gnark` for native proving or `zeroj-crypto` for pure Java
   proving.
4. Remove related docs or mark historical docs as obsolete if needed.

### Phase 4: Merge on-chain helpers

1. Move tested, useful helpers from `zeroj-onchain-experimental` into
   `zeroj-onchain-julc`.
2. Add or move tests for budget estimation and feasibility matrix.
3. Check conversion helpers against `SnarkjsToCardano` and `ProverToCardano`;
   delete duplicates rather than preserving two paths.
4. Audit and update `META-INF/native-image` resources for
   `zeroj-onchain-julc` after moving classes.
5. Remove `zeroj-onchain-experimental` from `settings.gradle`, BOM, and README.

### Phase 5: Fix PlonK transcript layering

1. Move `FiatShamirTranscript` and any required shared transcript utilities
   below `zeroj-verifier-plonk`.
2. Update `zeroj-crypto` PlonK prover imports.
3. Update `zeroj-verifier-plonk` imports.
4. Audit and update native-image metadata for `zeroj-crypto` and
   `zeroj-verifier-plonk`.
5. Remove `zeroj-crypto -> zeroj-verifier-plonk`, including test-scoped edges.

### Phase 6: Split BOMs and documentation

1. Add `zeroj-bom-core`.
2. Add or repurpose `zeroj-bom-all`.
3. Update top-level `README.md` module tables into:
   - Core
   - Cardano integration
   - Privacy and credential backends
   - Optional accelerators
   - Incubator/research
   - Examples and test fixtures
4. Update `docs/architecture-overview.md` so its module boundaries match the
   new BOM and settings layout.
5. Document that `zeroj-bbs` is mainline but outside the core BOM.

## Consequences

### Easier

- The default project story becomes simpler and closer to the v3 vision.
- The core BOM is smaller and safer for production users.
- Prover SPI is no longer tied to an HTTP sidecar implementation.
- `zeroj-crypto` becomes a cleaner foundation module.
- Cardano on-chain helper code has one owner: `zeroj-onchain-julc`.
- Optional and incubating modules stop driving the perceived product surface.

### Harder

- Existing users of `zeroj-submission`, `zeroj-ingestion`, `zeroj-prover-sidecar`,
  or `zeroj-prover-rapidsnark` will need migration guidance or must pin an older
  version.
- Examples that currently demonstrate submission/ingestion flows must be
  rewritten or removed.
- Splitting BOMs introduces publication and documentation work.
- Moving transcript code requires careful package compatibility and test
  coverage to avoid changing PlonK prover/verifier behavior.

## Risks

| Risk | Mitigation |
|------|------------|
| Removing modules breaks downstream users. | Treat this as a pre-1.0 cleanup or provide one release note with migration guidance. |
| Useful on-chain conversion logic is lost. | Merge only after comparing against `SnarkjsToCardano` and `ProverToCardano`, then add tests. |
| `zeroj-bom-core` accidentally omits a needed shipping dependency. | Validate by building examples that use only the core Cardano privacy path. |
| BBS visibility drops if excluded from core BOM. | Keep `zeroj-bbs` mainline and document it prominently as a credential backend. |
| Prover SPI grows into a second orchestration framework. | Keep `zeroj-prover-spi` minimal: request, response, service, and shared exception only; do not force every prover to implement `ProverService`. |
| PlonK transcript move changes challenge derivation. | Preserve byte-for-byte test vectors before and after the move. |

## Test Plan

- Compile core modules after each phase.
- Run:
  - `:zeroj-api:test`
  - `:zeroj-codec:test`
  - `:zeroj-backend-spi:test`
  - `:zeroj-verifier-core:test`
  - `:zeroj-verifier-groth16:test`
  - `:zeroj-verifier-plonk:test`
  - `:zeroj-crypto:test`
  - `:zeroj-circuit-dsl:test`
  - `:zeroj-circuit-lib:test`
  - `:zeroj-prover-gnark:test`
  - `:zeroj-onchain-julc:test`
  - `:zeroj-cardano:test`
  - `:zeroj-ccl:test`
  - `:zeroj-patterns:test`
  - `:zeroj-bbs:test`
- Run example tests after removing submission/ingestion demos.
- Verify Gradle project listing no longer includes removed modules.
- Verify `zeroj-bom-core` resolves without incubator modules.
- Verify `zeroj-bom-all` resolves optional modules that remain.

## Final Target

Removed:

- `zeroj-submission`
- `zeroj-ingestion`
- `zeroj-prover-sidecar`
- `zeroj-prover-rapidsnark`
- `zeroj-onchain-experimental`

Added:

- `zeroj-prover-spi`
- `zeroj-bom-core`
- `zeroj-bom-all`

Mainline but outside core BOM:

- `zeroj-bbs`

Optional/incubator outside core BOM:

- `zeroj-bbs-wasm`
- `zeroj-bls12381-wasm`
- `zeroj-prover-wasm`
- `zeroj-verifier-halo2`
