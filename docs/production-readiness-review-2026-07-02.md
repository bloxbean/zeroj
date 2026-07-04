# ZeroJ Production-Readiness Review — BLS, BBS, Groth16, PlonK (incl. on-chain)

Date: 2026-07-02
Branch: `main`, HEAD `6b0f163` (version `0.1.0-pre4`)
Method: five parallel deep reviews (BLS12-381 stack, BBS, Groth16 e2e pipeline, PlonK e2e pipeline, build/test health) with all soundness-critical files read in full and a live full-suite + e2e test run.

## Executive Summary

**No reviewed component is production-ready today; most are solid beta.** The
codebase quality is genuinely high — 3,543/3,543 unit/integration tests pass
across 25 modules, spec compliance is verified byte-exact where official
vectors exist (RFC 9380 hash-to-curve, ZCash serialization, CFRG BBS draft-10
fixtures for both ciphersuites, snarkjs interop fixtures), and the May-2026
"KZG pairing check deferred" status for PlonK on-chain is **stale — the full
KZG batch-opening pairing check is now implemented in all three deployable
Julc validators**, with a guard test preventing regression.

What separates the project from production is concentrated in five
cross-cutting themes rather than scattered defects:

1. **On-chain replay/front-running**: shipped Groth16/PlonK sample validators
   ignore `ScriptContext`; once a proof hits the mempool anyone can rebuild a
   competing spend. The tx-binding example exists only in *test* sources while
   the main guide locks ADA at the unbound validator.
2. **Trusted setup**: the Java Phase-1/Phase-2 setup is dev-only (correctly
   gated behind `-Dzeroj.allowInsecureTrustedSetup`); production Groth16
   requires an external snarkjs MPC ceremony, and no production ceremony
   artifact hash is pinned anywhere for either proof system.
3. **Performance ceilings**: subgroup checks are full scalar-mul-by-r in
   affine BigInteger arithmetic (throttling even the native blst backend),
   final exponentiation is a naive ~2031-bit pow (10–50× slow; it is the
   default pairing for PlonK and BBS verification), and the PlonK
   prover/setup have O(n²) hot spots. Largest circuit proven in-repo is
   ~1,821 constraints; nothing is benchmarked beyond 2^13.
4. **Supply chain / native-image**: `zeroj-blst` depends on
   `foundation.icon:blst-java:0.3.2` (2021-era, third-party, unverified
   provenance), ships no JNI config for GraalVM native image, and its README
   wrongly claims FFM.
5. **Assurance**: no external cryptographic audit, no fuzzing of
   parsers/importers, no standing differential CI, and the Yaci on-chain e2e
   tests have still never been recorded green (currently failing on a devkit
   faucet 500, previously skipped).

## Verdicts at a Glance

| Area | Component | Verdict |
|---|---|---|
| BLS | `zeroj-bls12381` (pure Java) | Beta — correctness strong, performance & side-channel posture below production |
| BLS | `zeroj-blst` | Beta — correct wrapper, but slow-path validation round-trips, GraalVM JNI gap, dependency provenance |
| BLS | `zeroj-bls12381-wasm` | Beta (leaning experimental) |
| BBS | `zeroj-bbs` | Beta — **verification path near production-ready**; issuer-side gaps (toString leak, side channels, zeroization) |
| BBS | `zeroj-bbs-wasm` | Beta — correct vs fixtures; zkryptium 0.6.1 unaudited; thinner negative coverage |
| Groth16 | prover/setup (`zeroj-crypto`) | Beta — hardened & well-gated; setup dev-only; perf unproven beyond 2^11 |
| Groth16 | off-chain verifiers | Beta — soundness checks complete (subgroup, canonicality, ranges, IC length); blst/pure-Java parity-tested |
| Groth16 | on-chain (Julc/Plutus V3) | Beta / testnet-eligible — full pairing check on-chain (~2.14e9 CPU ≈ 21% of budget); ctx unbound; unaudited |
| PlonK | off-chain prover | Beta — full 5-round protocol; missing b10/b11 quotient-split blinding; O(n²) hot spots |
| PlonK | off-chain verifier | Beta, closest to production — full equation + KZG pairing, 18 negative tests, snarkjs vector |
| PlonK | on-chain (Julc/Plutus V3) | Experimental (correctly labeled) — full KZG check implemented, VM-tested at ~4.8–4.95e9 CPU; constants as script params |
| Codec/API (`zeroj-codec`, `zeroj-api`) | | Beta, closest to production quality |
| BN254 (Groth16/PlonK legacy) | | Legacy/off-by-default — PlonK BN254 verifier lacks point-validation parity; keep disabled |
| Build health | | Healthy — 3,543 tests green, clean build; e2e gate 12/15 for known reasons |

## Build & Test Snapshot (2026-07-02)

- `./gradlew test`: **3,543 tests, 0 failures, 0 skips** (120 classes, 25 modules; largest suites: bls12381 1,808, crypto 959, circuit-lib 184, bbs 87+26).
- `./gradlew build -x test`: clean; 59 non-fatal javadoc warnings (mostly unescaped `<` in circuit-lib/dsl docs, a few broken `{@link}`s).
- `./gradlew :zeroj-examples:e2eTest`: **12/15 passed, 3 failed**:
  - `SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve` — same failure as May report; **test-authoring bug**: the gnark variant asserts a successful proof for an invalid bid instead of `assertThrows(ArithmeticException.class, ...)` like its snarkjs sibling (`SealedBidE2ETest.java:94-105`). The passing `bidAboveReserve` test confirms the gnark FFM prover itself works (~450–490 ms).
  - `PureJavaProverYaciE2ETest`, `SealedBidOnChainE2ETest` — first run failed at
    setup (faucet topup HTTP 500; fixed by restarting DevKit). After the DevKit
    restart, both tests progress further: topup succeeds and the **lock
    transaction confirms on-chain**, but the unlock/spend step fails in
    cardano-client-lib script-cost evaluation — the DevKit server returns
    `500 Handler dispatch failed: ExceptionInInitializerError` /
    `NoClassDefFoundError: Could not initialize class supranational.blst.blstJNI`.
    **Root cause is inside Yaci DevKit** (`bloxbean/yaci-cli:0.12.0-beta5`,
    linux/aarch64 container, Temurin 21): its transaction-evaluation service
    cannot load the blst JNI native library, so it cannot cost PlutusV3
    BLS12-381-builtin scripts at all. This is the same `blst-java` packaging
    weakness flagged in the BLS review (finding 3/4) surfacing in a second
    product. Until DevKit ships a working linux-aarch64 blst native (or the
    tests supply manual ex-units / a local evaluator to bypass server-side
    costing), the on-chain e2e gate cannot go green on Apple Silicon.
    `YaciHelper.topUp()` should also degrade to an assumption-skip on faucet
    failure instead of hard-failing.
- Gradle 10 deprecations: `build.gradle:108,109,116` and `zeroj-onchain-julc/build.gradle:5` (Groovy space-assignment). JVM restricted-method warning from Gradle's native-platform under Java 25.

## Findings by Area

Severity legend: CRITICAL (soundness/exploitable) · HIGH · MEDIUM · LOW.
No CRITICAL proof-system soundness defects were found in any validated input
path. Fiat-Shamir transcripts (PlonK) were checked absorption-by-absorption
across prover, off-chain verifier, Cardano codec, and on-chain lib — byte-for-
byte consistent, no "frozen heart" pattern.

### BLS12-381 (`zeroj-bls12381`, `zeroj-blst`, `zeroj-bls12381-wasm`)

1. **HIGH — Subgroup checks are full mul-by-r in affine BigInteger coords**, run on every SPI op, twice per hash-to-curve, and re-run on results blst already validated (`ec/G1Point.java:32-34`, `spi/Bls12381Provider.java:34-48`, `BlstBls12381Provider.java:159-165`). Dominant cost of the library; DoS-amplification surface; throttles native/WASM backends to pure-Java speed. Fix: psi-endomorphism (G2) / Bowe-style (G1) checks.
2. **HIGH — Naive final exponentiation**: hard part as one ~2031-bit `Fp12.pow` (`pairing/BLS12381Pairing.java:163-181`); declared Frobenius coefficients are dead code. 10–50× slower than standard; default pairing for PlonK verify + BBS.
3. **HIGH — `zeroj-blst` GraalVM story broken**: no `jni-config.json` for `supranational.blst.*`, no native-lib resource handling; README claims "FFM" but binding is SWIG/JNI (`zeroj-blst/build.gradle:10`).
4. **HIGH — blst dependency provenance**: `foundation.icon:blst-java:0.3.2` is a 2021-era third-party repackage; upstream blst commit unverified; multiple upstream hardening releases since.
5. MEDIUM — Miller loop uses affine G2 with an Fp2 inversion per step (~64/pairing).
6. MEDIUM — Degenerate `lineFuncAdd` branch places the vertical-line value in the wrong sparse slot (`BLS12381Pairing.java:137-140`); unreachable for order-r inputs but `pairingCheck`/`millerLoop` are public and unvalidated.
7. MEDIUM — "Fixed-schedule" ladder isn't uniform (leaks effective bit-length via INFINITY early-returns; `JacobianG1BLS381.java:172-197`); secret-scalar contracts on blst/WASM providers undocumented or misleading.
8. MEDIUM — `PippengerBLS381.msm` silently truncates positive scalars ≥ 2^255 (`msm/PippengerBLS381.java:19,94-103`); callers currently pre-reduce, but no guard.
9. MEDIUM — Pairing KAT is self-pinned; no external GT-value cross-validation (boolean-only cross-checks vs blst/zkcrypto; CFRG fixtures do exercise the full pairing).
10. LOW — inversion-of-zero surfaces as raw `ArithmeticException`; null-coordinate INFINITY sentinel; over-broad `allDeclared*` reflect-config; inconsistent native-image path convention (`com.bloxbean.cardano` vs `com.bloxbean.cardano.zeroj`); fragile Rust `Vec::with_capacity`/`from_raw_parts` alloc idiom in WASM.

Verified strengths: ZCash/IETF serialization exactly right (flags, G2 ordering, sort-bit, field-element < p, strict infinity), full RFC 9380 SSWU + isogeny with RFC vectors (RO+NU, SHAKE), Montgomery CIOS backed by differential tests, Fp2 sqrt verifies `root² == input` so decompression can't accept fake roots.

### BBS (`zeroj-bbs`, `zeroj-bbs-wasm`)

Byte-exact against the full official draft-10 fixture suite (keypair, h2s,
generators, MapMessageToScalarAsHash, mockedRng, signature001–010,
proof001–015) for BOTH ciphersuites, including byte-identical proof
*regeneration* from fixture random scalars — ordering/serialization proven.
Backend-conformance tests run the fixtures across pure-Java/blst/WASM providers.

1. **HIGH — `BbsSecretKey`/`BbsKeyPair` are records without `toString` overrides** (`BbsSecretKey.java:9`) — issuer secret scalar leaks into any log/debugger/exception rendering.
2. MEDIUM — `proofInit` multiplies `Abar` by hidden value `e` via the variable-time public `g1ScalarMul` instead of `g1SecretScalarMul` (`CfrgBbsCore.java:411`) — inconsistent with the module's own secret boundary.
3. MEDIUM — Raw `proofVerify` path has no proof-size/message-count cap → CPU DoS (one hash-to-curve per claimed message; `BbsCodec.java:126-139`). The envelope path (`BbsPresentationCodec`, 1 MB / 1024 msgs) is protected; the direct API is not.
4. MEDIUM — No zeroization anywhere (BigInteger secrets, byte[] copies, WASM linear memory never overwritten).
5. MEDIUM — Default backend side-channel posture is best-effort, disclaimed; issuer guidance should point to blst.
6. LOW — public deterministic-scalar helpers in the production jar (`seededRandomScalars`); `verifyPresentation` throws where `proofVerify` returns false; WASM module doesn't run the official *invalid* fixtures; deprecated Chicory API; generators recomputed per op (no memoization).

Gaps vs a production credential stack: no JWK/multikey/DID key formats, no revocation story, no cross-implementation interop CI (MATTR pairing_crypto / grotto), no blind-BBS/pseudonym extensions (optional).

### Groth16 end-to-end (DSL → setup → prove → verify → on-chain)

The pipeline works purely in Java on BLS12-381 **with the insecure dev
setup**. Production trust requires two snarkjs seams: (a) Phase-2 MPC ceremony
(Java Phase 2 mathematically requires the known tau — it can never consume MPC
artifacts; `Groth16SetupBLS381.java:52-98`), and (b) VK export
(`ZkeyImporterBLS381` extracts only the proving key). On-chain verification is
FULL Groth16 via Plutus builtins — `finalVerify(ML(A,B)·ML(−α,β),
ML(vkX,γ)·ML(C,δ))` (`Groth16BLS12381Lib.java:198-206`) with on-chain
scalar-range, canonicality, and IC/input-length checks; measured ~2.14e9 CPU /
71.5k mem for 2 public inputs (~21% of tx budget).

1. **HIGH — Shipped on-chain validator ignores `ScriptContext` → proofs replayable/front-runnable** (`groth16/validator/Groth16BLS12381Verifier.java:33-36`). Binding example exists only under `src/test/java`; `docs/pure-java-prover-guide.md:221-270` locks 5 ADA at the unbound validator with no warning.
2. **HIGH (operational) — No production trusted-setup story in-repo** (ceremony tooling ADR-0013 unimplemented); honestly documented and policy-gated, but any real deployment inherits the snarkjs ceremony + BLS12-381 ceremony-maturity burden.
3. MEDIUM — Comparator gadgets (circomlib `LessThan` pattern) are unsound on non-range-checked inputs; the obligation lives only in a code comment (`CircuitAPIImpl.java:252-264`), and the guide's own `BalanceProofCircuit` example uses a raw comparator on an unconstrained secret. Typed `ZkUInt` layer is safe.
4. MEDIUM — `AliasCheck` can't fulfill its documented contract (needs ≥254 bits, `toBinary` caps at 253); silently over-constrains rather than unsound, but broken as documented.
5. MEDIUM — No non-subgroup (torsion) negative test vector anywhere in the Groth16 suites, despite subgroup checks being implemented at all layers — untested check = regression risk. (ADR-0025's own mitigation line is unbacked.)
6. MEDIUM — `SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve` still failing (test-authoring bug, see build section).
7. MEDIUM — Applied Groth16 script size vs the 16,384-byte inline limit unmeasured (recorded 5,283–5,608 B sizes are PlonK-only); `ReferenceScriptDeployer` (CIP-33) is config-only.
8. MEDIUM — Scale unproven: largest proven circuit ≈ 1,821 constraints (2^11 domain); importer caps allow 2^24; no benchmarks; BigInteger/record-based arithmetic will be slow/memory-heavy at production sizes.
9. LOW — cosmetic toxic-waste "erasure" (immutable BigInteger; honestly documented, dev-only); prover not constant-time (Pippenger `testBit` over secret scalars); package-private `proveUnblinded` (r=s=0) in main sources; MiMC/MiMCSponge circomlib-compat claims false (SHA-256-derived constants, docs say keccak); `zeroj-prover-spi.ProverService` has zero implementations; verifiers don't cross-check `proof.protocol()/curve()` against descriptor (routing handled upstream).

Verified strengths: e12d18e hardening is real (ADR-0025 F2–F10 all present: subgroup checks on proof+VK, `[0,r)` input ranges off- and on-chain, cache integrity + pairing re-validation, importer bounds + SHA-256 pinning); on-chain Fr modulus recomputed and confirmed; strict snarkjs JSON codec (duplicate detection, bounds, IC == nPublic+1); versioned CBOR envelope; blst/pure-Java verifier parity tests.

### PlonK end-to-end

Implemented as "path 2": prover for zeroj's own `PlonKCompiler` constraint
system with SRS from `.ptau` (`PlonKSetupBLS381` replaces `snarkjs plonk
setup`); a snarkjs PlonK `.zkey` importer also exists. The `.ptau` importer is
heavily validated (magic/prime/canonical/per-point on-curve+subgroup, generator
anchors, pairing-consistency of powers, optional SHA-256 pinning). On-chain:
the old non-verifying transcript prototype was moved to test scope; all three
deployable validators delegate to `PlonkBLS12381Lib.verifyKzg` performing the
full linearized-commitment + batched KZG pairing check
(`PlonkBLS12381Lib.java:192-276`), budget-gated in a real UPLC VM at ~4.8–4.95e9
CPU; `PlonkOnChainDeployableGuardTest` enforces it stays true.

1. MEDIUM — On-chain protocol constants (`fr`, `g1Gen`, `g2Gen`) are script *parameters*, only shape-checked (`PlonkBLS12381Lib.java:314,341-343`) — a wrong deployment silently yields an unsound validator. Hardcode or assert byte-equality with literals.
2. MEDIUM — Both provers use 9 blinding scalars; the paper/snarkjs use 11 — b10/b11 quotient-split blinding omitted (`PlonKProverBLS381.java:72-73,634-636`). ZK-margin deviation, not soundness; ~10-line fix in round 3.
3. MEDIUM — No production facade from compiled circuit + witness to prover wires; the soundness-relevant glue (selectors, extendWitness, wire mapping, padding) is duplicated across tests (`PlonKBLS381EndToEndTest.java:61-81` et al.).
4. MEDIUM — O(n²) hot spots: `cosetEval` recomputes `powFr(shift,i)` per coefficient (`PlonKProverBLS381.java:554-559,467-472`), `evalOmegaPow` quadratic across rows — caps practical size far below the 2^24 domain cap.
5. MEDIUM — No production ceremony artifact pinned; suitable BLS12-381 universal PlonK SRS is scarce (noted in ADR addendum A.2).
6. MEDIUM — BN254 legacy verifier lacks the point-validation layer of the BLS path (gated off by default; keep frozen until parity).
7. LOW — sample validators ignore `ScriptContext` (same replay caveat as Groth16; documented as application responsibility); interop one-directional (zeroj verifies snarkjs proofs; no zeroj→snarkjs proof.json exporter, snarkjs never verifies a zeroj proof in tests); BN254 prover accepts oversized wire arrays; stale docs (`beta-release-readiness.md:90-91` "KZG deferred" now false; ADR-0022/0012 headers still "Proposed").

Verified strengths: transcript profiles byte-consistent across all four
implementations incl. the 40-byte MPI domain-separation tag; on-chain lib
validates canonical encodings via compress/uncompress round-trip, non-infinity,
scalar ranges, ω primitivity, k1/k2 coset checks, witnessed inverses re-verified
by multiplication; off-chain verifier has DoS bounds (power ≤ 24, ≤ 256 public
inputs), envelope/VK-hash binding, typed failure reasons, 18 negative tests +
independent snarkjs BLS12-381 vector; ~150 PlonK tests across 8 modules.

## Consolidated Task List

### P0 — small, high-impact; do immediately
1. Redact `toString()` on `BbsSecretKey`/`BbsKeyPair` (secret-leak into logs).
2. Route `signature.e()` through `g1SecretScalarMul` in `CfrgBbsCore.proofInit`.
3. Fix `SealedBidGnarkE2ETest.groth16_gnark_bidBelowReserve` → `assertThrows(ArithmeticException.class, ...)`.
4. Hardcode (or byte-assert) `fr`/`g1Gen`/`g2Gen` in `PlonkBLS12381Lib` instead of trusting script params.
5. Promote a tx-binding (first-input/signer/output-bound) Groth16 validator from test to main sources; add front-running warning + bound example to the prover guide (and mirror for PlonK samples).

### P1 — security/correctness hardening before any beta tag
6. Fast subgroup checks (psi-endomorphism G2, Bowe/(1−z²) G1) in both field stacks; route `isInSubgroup()` through them (unblocks blst/WASM throughput, kills the DoS amplification).
7. Rewrite final exponentiation (Frobenius + cyclotomic squarings + x-chain); target ≥10× pure-Java pairing speedup.
8. Add b10/b11 quotient-split blinding to both PlonK provers.
9. Cap proof length / hidden-message count on raw BBS `proofVerify` (mirror MAX_MESSAGES=1024).
10. Add torsion (on-curve, out-of-subgroup) negative vectors to Groth16/PlonK verifier tests, zkey importer tests, and (as builtins allow) Julc VM tests; import ZCash valid/invalid serialization suites.
11. Document the comparator pre-range-check obligation in `CircuitAPI`/`Comparators` javadoc; fix the guide's `BalanceProofCircuit`; fix or delete `AliasCheck`.
12. Guard `PippengerBLS381.msm` (reduce all scalars mod r or reject ≥ 2^255); mirror in the private G2 MSM.
13. Resolve blst supply chain: pin/verify upstream blst commit or build it in-repo; add GraalVM `jni-config.json` + native-lib resources; correct the README FFM claim (or migrate to FFM).
14. Harden `YaciHelper.topUp()` to degrade to assumption-skip on faucet failure; restart/refund DevKit and record a green `:zeroj-examples:e2eTest` run.
15. Document secret-scalar contracts on blst/WASM providers; fix the "uniform schedule" ladder overstatement; point BBS issuer guidance at blst.

### P2 — production enablement
16. Trusted-setup story: select and SHA-256-pin production ceremony artifacts (Groth16 `.zkey` lineage + PlonK universal `.ptau`); add VK extraction to `ZkeyImporterBLS381` (drop the snarkjs VK-export seam); implement ceremony verification tooling (ADR-0013).
17. Ship a PlonK proving facade (compile → setup → wire-assignment → prove) in main sources.
18. Fix PlonK O(n²) hot spots (incremental power computation in `cosetEval`/`evalOmegaPow`).
19. Benchmark pure-Java Groth16/PlonK at 2^14–2^17 constraints (time + heap); publish numbers; measure applied Groth16 script size vs the 16 KB inline limit and wire the CIP-33 reference-script path if needed.
20. Bidirectional snarkjs interop tests: export zeroj proofs (Groth16 JSON + PlonK proof.json exporter) and have snarkjs CLI verify them in CI.
21. BBS: run official invalid fixtures through the WASM provider; add cross-implementation interop CI (pairing_crypto/grotto); best-effort zeroization; memoize generators.
22. External GT-value cross-validation KAT (convert blst/zkcrypto Fp12 into ZeroJ tower layout).

### P3 — hygiene & docs
23. Fix Gradle-10 deprecations (`build.gradle:108,109,116`, `zeroj-onchain-julc/build.gradle:5`); clean the 59 javadoc warnings.
24. Native-image hygiene: unify `META-INF/native-image/<groupId>/<artifactId>` convention (groupId is `com.bloxbean.cardano`); trim `allDeclared*` reflect entries; add metadata (or "none needed" markers) for `zeroj-crypto`, circuit modules; run one native-image smoke test of prove/verify.
25. Docs: fix stale `beta-release-readiness.md` KZG-deferred claim; bump ADR-0022/0012 statuses; fix MiMC circomlib-compat claims; update version snippets (`0.1.0` → current); consolidate vision docs; add CHANGELOG; keep the "not production-audited" README warning.
26. Delete or implement `zeroj-prover-spi.ProverService`; decide `verifyPresentation` failure contract (throw vs false); remove/guard `proveUnblinded` and public seeded-scalar helpers.
27. Before any value-bearing deployment: commission an external cryptographic audit (pure-Java field/curve/pairing stack + Julc-compiled UPLC), add parser/importer fuzzing, and standing differential CI vs snarkjs/blst.

## Delta vs `docs/beta-release-readiness.md` (2026-05-28)

- ✅ PlonK on-chain KZG pairing check: **now implemented** (was "explicitly deferred") — that doc's line 90-91 is stale.
- ❌ Blocker #1 (`SealedBidGnarkE2ETest`): still failing, same root cause.
- ❌ Blocker #2 (green Yaci e2e run): still never achieved — now fails on faucet HTTP 500 instead of skipping.
- Unchanged: scope-control recommendations (BN254/BBS/WASM/Halo2/gnark labeling), Gradle-10 deprecations, native-image gaps, CHANGELOG/version tasks.

## What Was Verified vs Assumed

Verified: all cited file:line findings by direct source reading; PlonK
Fiat-Shamir ordering across four implementations; on-chain Groth16 pairing
equation and Fr modulus; serialization/hash-to-curve constants against RFC/ZCash
values; full live test runs (3,543 unit + 15 e2e). Assumed/not verified:
correctness of Julc's Java→UPLC compilation; Plutus builtin subgroup semantics
(CIP-0381) inside the Julc VM; the exact upstream blst commit in
`blst-java:0.3.2`; zkryptium 0.6.1 internals; deep pairing math beyond
bilinearity/fixture evidence; Chicory timing characteristics.
