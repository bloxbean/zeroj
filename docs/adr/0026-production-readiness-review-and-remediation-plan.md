# ADR-0026: Full-Stack Production-Readiness Review and Remediation Plan (BLS12-381, BBS, Groth16, PlonK, On-Chain)

## Status
Accepted — review complete; P0 beta remediation implemented in branch;
external security review still pending

## Date
2026-07-02

## Context

ADR-0021 hardened the shared BLS12-381 primitives, ADR-0022/0023/0024 hardened
the PlonK stack, and ADR-0025 recorded a cross-cutting Groth16+PlonK security
audit with testnet gates. What had not been done is a **single
production-readiness pass over every cryptographic surface the project ships**
— the BLS12-381 implementations (pure Java, blst, WASM), the CFRG BBS
implementation, and both pure-Java proof pipelines end-to-end *including a live
on-chain execution attempt* — asking one question: what stands between the
current `main` (`6b0f163`, 0.1.0-pre4) and production use?

The review ran as five parallel deep passes (BLS, BBS, Groth16 e2e, PlonK e2e,
build/test health) with all soundness-critical files read in full, plus a live
run of the complete test suite and the opt-in e2e gate against a local Yaci
DevKit. The full findings document (~50 findings with file:line citations and
a 27-item prioritized task list) is
`docs/production-readiness-review-2026-07-02.md`; this ADR records the
*decisions* that follow from it. It supersedes the readiness assessment in
`docs/beta-release-readiness.md` (2026-05-28), whose PlonK "KZG deferred"
claim is now stale.

### What the review confirmed as strong (lock in, do not regress)

- **3,543/3,543 unit/integration tests pass** across 25 modules; clean build.
- **PlonK on-chain verification is complete**: all three deployable Julc
  validators perform the full linearized-commitment + batched KZG pairing
  check (`PlonkBLS12381Lib.verifyKzg`), VM-tested at ~4.8–4.95e9 CPU with
  budget-gated tests, and `PlonkOnChainDeployableGuardTest` prevents
  regression to the non-verifying prototype (now test-scoped per ADR-0025 §4).
- **Groth16 on-chain verification is complete**: full pairing check via Plutus
  builtins at ~2.14e9 CPU / 71.5k mem for 2 public inputs (~21% of budget).
- **PlonK Fiat-Shamir transcript is byte-consistent** across prover, off-chain
  verifier, Cardano codec, and on-chain lib, including the 40-byte MPI
  domain-separation tag — re-verified absorption-by-absorption in this review.
- **BBS is byte-exact against the full official CFRG draft-10 fixture suite**
  for both ciphersuites, including byte-identical proof regeneration from
  fixture random scalars; conformance tests run across all three BLS backends.
- **Serialization and hash-to-curve are spec-correct**: ZCash/IETF flag bits,
  G2 ordering, sort-bit semantics, field-element < p on read; full RFC 9380
  SSWU with RFC vectors; Fp2 sqrt verifies `root² == input`.
- **ADR-0025's F2–F10 mitigations are all present in code** (subgroup checks,
  `[0,r)` ranges off- and on-chain, cache integrity, importer bounds/pinning).

No CRITICAL proof-system soundness defect was found on any validated input
path.

### The structural findings

Weaknesses are concentrated in five themes rather than scattered defects:

1. **Application-layer replay**: shipped Groth16/PlonK sample validators ignore
   `ScriptContext` (`groth16/validator/Groth16BLS12381Verifier.java:33-36`);
   the tx-binding example exists only under `src/test/java`, while
   `docs/pure-java-prover-guide.md` locks ADA at the unbound validator.
2. **Trusted setup**: the Java Phase-2 setup mathematically requires the known
   tau (`Groth16SetupBLS381.java:52-98`) and can never consume MPC artifacts;
   no production ceremony artifact hash is pinned for either proof system
   (ADR-0013 remains unimplemented).
3. **Performance architecture**: subgroup checks are full mul-by-r in affine
   BigInteger coordinates executed at every SPI boundary (`ec/G1Point.java:32-34`),
   throttling even the blst and WASM backends; final exponentiation is a
   generic ~2031-bit `Fp12.pow` (`pairing/BLS12381Pairing.java:163-181`) — the
   default pairing for PlonK and BBS verification; PlonK prover/setup have
   O(n²) hot spots (`PlonKProverBLS381.cosetEval`, `PlonKSetupBLS381.evalOmegaPow`).
   Largest circuit proven in-repo: ~1,821 constraints. No benchmarks exist.
4. **Supply chain / native image**: `foundation.icon:blst-java:0.3.2` is a
   2021-era third-party binary of unverified provenance. At review start,
   `zeroj-blst` also had no GraalVM `jni-config.json`, no native-resource
   inclusion metadata, and a README that wrongly claimed FFM. The P0 branch
   fixes the local metadata/docs issues; provenance remains open. During this
   review the same native-loading weakness surfaced in Yaci DevKit itself
   (see below).
5. **Assurance**: no external audit, no parser/importer fuzzing, no standing
   differential CI, and the on-chain e2e gate has never been recorded green.

### Live e2e evidence (new since ADR-0025)

The `:zeroj-examples:e2eTest` gate ran 12/15 green. The three failures:

- `SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve` — the May blocker,
  confirmed as a test-authoring bug: the gnark variant asserts a successful
  proof for an invalid bid instead of `assertThrows(ArithmeticException.class,
  ...)` like its snarkjs sibling (`SealedBidE2ETest.java:94-105`).
- `PureJavaProverYaciE2ETest` / `SealedBidOnChainE2ETest` — after a DevKit
  restart, topup succeeds and the **lock transaction confirms on-chain**, but
  the unlock fails in server-side script-cost evaluation:
  `500 Handler dispatch failed: NoClassDefFoundError: Could not initialize
  class supranational.blst.blstJNI`. The observed failure is in the Yaci DevKit
  transaction evaluator (`bloxbean/yaci-cli:0.12.0-beta5`, linux/aarch64,
  Temurin 21): it cannot load blst JNI natives, so it cannot cost PlutusV3
  BLS12-381-builtin scripts on Apple Silicon. This blocks the on-chain e2e gate
  on aarch64 until DevKit ships a working native bundle or zeroj supplies a
  manual-ex-units/local-evaluator fallback.

**Update (2026-07-03): full e2e gate recorded green — 15/15 passed, 0 skipped.**
Root cause of the evaluator failure was isolated to yaci-store's GraalVM
native-image builds missing blst JNI metadata (fix specified in yaci-store
ADR 017; DevKit ≥0.12 evaluates via Scalus→blst-java in-process). Running
DevKit `0.11.0-beta1`, whose store delegates cost evaluation to **Ogmios**
(Haskell, native blst), the complete `:zeroj-examples:e2eTest` gate passed on
the P0 branch: both on-chain tests verified Groth16 proofs on-chain
(`PureJavaProverYaciE2ETest` unlock tx ZK-verified; `SealedBidOnChainE2ETest`
lock+unlock confirmed), and the fixed
`SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve` passed. Both May-2026
beta blockers are closed.

### Severity-tagged findings driving the decisions (abridged)

| # | Sev | Finding |
|---|---|---|
| R1 | HIGH | Sample on-chain validators unbound to `ScriptContext` → replay/front-running; guide demonstrates the unsafe pattern |
| R2 | HIGH | `BbsSecretKey`/`BbsKeyPair` records lack `toString` overrides → issuer secret scalar leaks into logs/exceptions |
| R3 | HIGH | Subgroup checks via full mul-by-r everywhere; naive final exponentiation; both dominate all verification paths |
| R4 | HIGH | `blst-java:0.3.2` provenance + pre-remediation missing GraalVM JNI metadata / false FFM claim; related native-loading gap also breaks DevKit on aarch64 |
| R5 | HIGH | No production trusted-setup story in-repo; no pinned ceremony artifacts |
| R6 | MED | PlonK on-chain constants (`fr`, `g1Gen`, `g2Gen`) are script params, only shape-checked (`PlonkBLS12381Lib.java:314,341-343`) — a wrong deployment is silently unsound |
| R7 | MED | PlonK provers use 9 blinding scalars; paper/snarkjs use 11 (b10/b11 quotient-split blinding missing) — ZK-margin, not soundness |
| R8 | MED | `CfrgBbsCore.proofInit` multiplies by hidden `e` via variable-time public path (`CfrgBbsCore.java:411`); raw `proofVerify` has no size cap (CPU DoS) |
| R9 | MED | Comparator gadgets unsound on non-range-checked raw signals; obligation only in a code comment; guide example trips it. `AliasCheck` broken as documented |
| R10 | MED | No torsion (on-curve, out-of-subgroup) negative vectors anywhere; `PippengerBLS381.msm` silently truncates scalars ≥ 2^255 |
| R11 | MED | No production facade for PlonK compile→setup→wire-assignment→prove; soundness-relevant glue duplicated across tests |
| R12 | MED | Interop one-directional: zeroj verifies snarkjs proofs; snarkjs never verifies a zeroj proof in any test |

## Decision

### 1. Component readiness posture (declared statuses)

| Component | Status declared by this ADR |
|---|---|
| zeroj-codec / zeroj-api envelopes | Beta (closest to production quality) |
| BBS verification path (`zeroj-bbs`) | Beta — production-track after P0/P1 items |
| Groth16 off-chain (prove/verify, BLS12-381) | Beta |
| Groth16 on-chain (Julc/Plutus V3) | Testnet-eligible; **not value-bearing** |
| PlonK off-chain verifier | Beta |
| PlonK off-chain prover | Beta |
| PlonK on-chain | Experimental (keep current labeling) |
| BLS12-381 pure Java | Beta |
| BLS12-381 blst provider | Beta after supply-chain/native-image remediation |
| BLS12-381 WASM provider | Beta leaning experimental |
| BN254 (Groth16 + PlonK legacy) | Frozen non-production; stays flag-gated until point-validation parity or removal |
| BBS issuer path on default (pure Java) provider | Not recommended; document blst for issuers |

Nothing may be described as production-ready in READMEs or release notes
until Phase 3 below completes: external audit, production ceremony provenance,
green e2e, parser/importer fuzzing, and standing differential CI.

### 2. P0 gate — the following five fixes block the next tag

1. Redact `toString()` on `BbsSecretKey`/`BbsKeyPair` (R2).
2. Route `signature.e()` through `g1SecretScalarMul` in `CfrgBbsCore.proofInit`
   (R8).
3. Fix `SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve` to
   `assertThrows(ArithmeticException.class, ...)`.
4. Hardcode (or byte-assert against literals) `fr`, `g1Gen`, `g2Gen` in
   `PlonkBLS12381Lib` instead of trusting script parameters (R6).
5. Promote a tx-binding Groth16 validator from test to main sources and add a
   front-running warning + bound example to the prover guide; mirror the
   warning for PlonK samples (R1).

### 3. Performance architecture is a correctness-adjacent workstream, not an optimization

Fast subgroup checks (psi-endomorphism for G2, Bowe/(1−z²) for G1) and a
proper final exponentiation (Frobenius + cyclotomic squarings + x-chain) are
scheduled as P1 work. Rationale: the current design is a deserialization DoS
amplification surface, throttles the native/WASM backends to pure-Java speed,
and makes PlonK/BBS verification latency unfit for production; fixing it also
collapses several redundant-validation findings. The `PippengerBLS381.msm`
scalar-truncation guard rides along (R10).

### 4. Verification-layer negative coverage becomes a release gate

Torsion (on-curve, out-of-subgroup) test vectors must exist for both off-chain
verifiers, the `.zkey`/`.ptau` importers, and — as far as builtins allow — the
Julc VM tests; ZCash valid/invalid serialization suites get imported. An
implemented-but-untested subgroup check is treated as a regression waiting to
happen (extends ADR-0025 §2).

### 5. Trusted-setup provenance before any value-bearing use

Production ceremony artifacts (Groth16 `.zkey` lineage, PlonK universal
`.ptau`) must be selected and SHA-256-pinned in-repo; VK extraction is added
to `ZkeyImporterBLS381` so snarkjs is not needed for VK export; ADR-0013
ceremony verification tooling is re-affirmed as the long-term path (R5).

### 6. Supply-chain resolution for blst

Either pin and verify the exact upstream blst commit embedded in
`blst-java:0.3.2`, or, if that provenance cannot be established, treat the
dependency as unverifiable and build/bundle upstream blst in-repo. The P0
branch adds `jni-config.json` + native-lib resources for GraalVM and corrects
the README FFM claim; provenance resolution remains open. The DevKit aarch64 failure is
tracked against Yaci DevKit (bundle linux-aarch64 blst natives in the evaluator);
zeroj's e2e harness additionally hardens `YaciHelper.topUp()` to degrade to an
assumption-skip and skips only the known `supranational.blst.blstJNI`
cost-evaluation failure. A manual-ex-units/local-evaluator fallback remains
open so the on-chain gate can run even when server-side costing is unavailable
(R4).

### 7. Pipeline ergonomics are in scope before value-bearing release

A PlonK proving facade (compile → setup → wire-assignment → prove) ships in
main sources, replacing the duplicated test glue (R11). Comparator range-check
obligations move from code comments into `CircuitAPI`/`Comparators` javadoc,
the guide's `BalanceProofCircuit` example is fixed, and `AliasCheck` is fixed
or deleted (R9). b10/b11 quotient-split blinding is added to both PlonK
provers (R7).

### 8. Interop becomes bidirectional and CI-enforced

Export paths (Groth16 proof JSON, PlonK `proof.json`) are added so snarkjs CLI
verifies zeroj-generated proofs in CI; BBS gains cross-implementation interop
checks (pairing_crypto or grotto fixtures) and runs the official *invalid*
fixtures through the WASM provider (R12).

### 9. Documentation truth-maintenance

`docs/beta-release-readiness.md` gains a superseded-by banner pointing at the
2026-07-02 review; ADR-0012/0022 status headers move to Accepted/Implemented;
MiMC circomlib-compatibility claims are corrected; version snippets updated;
CHANGELOG added at the next tag. The README "not production-audited" warning
stays until an external audit completes.

## Consequences

### Easier
- A single, dated, severity-ranked source of truth for "what blocks
  production" replaces three partially stale documents.
- The P0 gate is small (five items, all local changes) and unblocks the next
  pre-release tag quickly.
- Declared component statuses give release notes and READMEs unambiguous
  language and stop scope creep into value-bearing use.

### Harder
- Fast subgroup checks and the final-exponentiation rewrite are the largest
  crypto changes since ADR-0021 and need careful differential testing against
  the existing (correct but slow) implementations.
- The on-chain e2e gate now has an external dependency (DevKit aarch64 blst
  fix) that zeroj cannot close from this repo alone; the manual-ex-units
  fallback mitigates but adds harness complexity.
- Bidirectional interop CI requires snarkjs CLI in the CI image.

### Neutral
- BN254 stays frozen behind flags; no new work unless parity is funded.
- BBS blind-signature/pseudonym extensions remain explicitly out of scope.

## Test Plan

- P0 items: unit tests per fix (toString redaction asserted, secret-path
  boundary test extended, e2e negative-path test asserts the exception,
  on-chain constant byte-assertion test, bound-validator VM test).
- Subgroup/final-exp rewrite: differential tests old-vs-new over random points
  and scalars (≥10⁴ cases), all existing 1,808 `zeroj-bls12381` tests stay
  green, plus imported ZCash valid/invalid vectors and new torsion vectors.
- PlonK blinding change: existing prove/verify round-trips plus a test that
  T1/T2/T3 commitments differ across two proofs of the same witness.
- Interop: CI job proving with zeroj and verifying with snarkjs CLI for both
  proof systems; BBS cross-implementation fixture exchange.
- e2e: `:zeroj-examples:e2eTest` recorded green (DevKit fixed or ex-units
  fallback) becomes a tag prerequisite, per ADR-0025's original intent.

## Implementation Plan

- **Phase 0 (P0 gate)** — the five blocking fixes in Decision §2 are
  implemented in this branch.
- **Phase 1 (security/correctness hardening)** — fast subgroup checks, final
  exponentiation, MSM guard, torsion + ZCash vectors, comparator/AliasCheck
  docs-and-fixes, b10/b11 blinding, BBS proof-size cap, blst supply
  chain + GraalVM JNI config, e2e harness hardening, secret-scalar contract
  documentation.
- **Phase 2 (production enablement)** — ceremony artifact pinning + VK
  extraction, PlonK facade, O(n²) fixes, benchmarks at 2^14–2^17 constraints,
  Groth16 script-size measurement + CIP-33 path, bidirectional interop CI,
  BBS interop + zeroization + generator memoization, external GT KAT.
- **Phase 3 (value-bearing gates)** — external cryptographic audit (pure-Java
  crypto stack + Julc-compiled UPLC), parser/importer fuzzing, standing
  differential CI, real MPC ceremony process. Mirrors and extends ADR-0025
  Phase 3.

Full task-level detail: `docs/production-readiness-review-2026-07-02.md`
(“Consolidated Task List”, items 1–27).

## Risks

- Rewriting subgroup checks/final exponentiation risks introducing subtle
  errors into currently-correct code; mitigated by keeping the slow
  implementations as differential oracles in tests.
- Pinning a production `.ptau`/`.zkey` lineage depends on the availability of
  a trustworthy BLS12-381 universal ceremony (noted scarce in the
  ADR-0022/0023 production-readiness addendum); this may become the long pole.
- The DevKit aarch64 blst fix lives in another repo; until it lands, "green
  e2e" is only achievable via the ex-units fallback or on x86_64.
- An external audit may reorder these priorities; this ADR should be revisited
  when audit findings arrive.

## References

- `docs/production-readiness-review-2026-07-02.md` — full findings and task list
- `docs/beta-release-readiness.md` (2026-05-28) — superseded readiness assessment
- ADR-0013 — trusted-setup ceremony tools (re-affirmed)
- ADR-0019 — CFRG BBS providers
- ADR-0021 — BLS12-381 review and hardening
- ADR-0022/0023/0024 — PlonK hardening and release gates
- ADR-0025 — end-to-end security audit and public-testnet readiness gates
