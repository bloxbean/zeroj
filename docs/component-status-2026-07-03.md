# ZeroJ Component Status Report

Date: 2026-07-03
State assessed: branch `fix/adr_0026` working tree (ADR-0026 P0 remediation applied), base `6b0f163` (0.1.0-pre4)
Evidence baseline: **3,547/3,547 unit/integration tests green** across 25 modules; **full `:zeroj-examples:e2eTest` gate green — 15/15 passed, 0 skipped** (2026-07-03), including live on-chain Groth16 verification against Yaci DevKit (`0.11.0-beta1`, Ogmios-mode cost evaluation).

Related documents:

- Decisions and remediation plan: [ADR-0026](adr/0026-production-readiness-review-and-remediation-plan.md)
- Full findings (~50, with file:line citations): [production-readiness-review-2026-07-02.md](production-readiness-review-2026-07-02.md)
- DevKit evaluator fix (external dependency): yaci-store ADR 017

Every status below is backed by passing tests, numeric verification, or a
recorded live run — none of the "Beta" rows are aspirational.

## What we can confidently claim

| Component | Status | Evidence backing the claim |
|---|---|---|
| Core proof model, codecs, SPI (`zeroj-api`, `zeroj-codec`, `zeroj-backend-spi`, `zeroj-verifier-core`) | **Beta** — closest to production quality | Versioned CBOR envelope, strict snarkjs JSON parsing (duplicate/bounds/IC-length checks), negative tests throughout |
| Circuit DSL + annotations (`zeroj-circuit-dsl`, annotation modules) | **Beta** | R1CS export conformance-tested against circom format; constant-one wire pinned (closes the unconstrained-wire hole); 100+ tests |
| Gadget library (`zeroj-circuit-lib`) | **Beta with named caveats** | Poseidon cross-verified vs circomlibjs + Sage; 184 tests. Caveats still open: comparator range-check obligation not yet in API javadoc, `AliasCheck` broken-as-documented, MiMC circomlib-compat claim false |
| Groth16 BLS12-381 off-chain (prove + verify) | **Beta** | Verifier soundness checks complete (subgroup, canonicality, `[0,r)` ranges, IC length) on proof *and* VK; blst/pure-Java parity-tested; verifies real snarkjs proofs; **proven end-to-end on-chain** |
| Groth16 BLS12-381 on-chain (Julc/Plutus V3) | **Beta — testnet only** | Full pairing check via Plutus builtins, ~21% CPU budget measured, Julc VM negative tests, **live green run on Yaci DevKit (2026-07-03)** — lock + ZK-verified unlock confirmed; tx-binding validator (`Groth16BLS12381TxOutRefBindingVerifier`) shipped in main sources |
| PlonK BLS12-381 off-chain verifier | **Beta** — strongest verifier in the repo | Full verification equation incl. KZG batch-opening pairing; Fiat-Shamir verified byte-for-byte across prover / verifier / Cardano codec / on-chain lib; 18 negative tests + independent snarkjs vector; DoS bounds (domain ≤ 2^24, ≤ 256 public inputs) |
| PlonK BLS12-381 off-chain prover | **Beta** | Full 5-round protocol, SecureRandom blinding with rejection sampling, snarkjs-compatible transcript. Known deviation: b10/b11 quotient-split blinding missing (ZK-margin, not soundness); O(n²) hot spots cap practical circuit size |
| PlonK BLS12-381 on-chain | **Experimental** (correctly labeled) | Full KZG check in all 3 deployable validators; protocol constants (`fr`, `g1Gen`, `g2Gen`) pinned on-chain and numerically verified against known BLS12-381 values; tamper tests for fr/g1Gen/g2Gen pass in the UPLC VM; ~4.9e9 CPU budget-gated; guard test prevents regression to the non-verifying prototype |
| BBS verification path (`zeroj-bbs`) | **Beta — near production** | Byte-exact against the complete official CFRG draft-10 fixture suite, both ciphersuites (SHA-256 + SHAKE-256), incl. byte-identical proof regeneration from fixture random scalars; proof-size DoS cap (1024 messages) at both codec layers. Caveat: the spec is an IRTF draft, not yet an RFC |
| BBS issuance path | **Beta with caveat** | Secret-scalar boundary now consistent (hidden `e` routed through `g1SecretScalarMul`), key material redacted from `toString`. Caveat: variable-time BigInteger scalar arithmetic, no zeroization — issuer keys should use the blst provider or accept the risk |
| BLS12-381 pure Java (`zeroj-bls12381`) | **Beta — verification-grade** | ZCash/IETF serialization exact (flags, G2 ordering, sort bit, field element < p), RFC 9380 hash-to-curve with official vectors, 1,808 tests, full pairing exercised end-to-end by CFRG BBS fixtures. Caveats: pairing 10–50× slower than production libraries, mul-by-r subgroup checks, no external GT-value KAT yet |
| blst native (`zeroj-blst`) | **Beta, opt-in** | Correct wrapper, parity-tested vs pure Java; GraalVM JNI + resource metadata present and verified against the actual `blst-java-0.3.2.jar` layout. Caveats: no native-image smoke test executed yet; upstream binary provenance unpinned |
| Cardano anchoring/CCL (`zeroj-cardano`, `zeroj-ccl`, `zeroj-patterns`) | **Beta** | Thin, coherent, tested; anchoring (off-chain verify + hash on L1) documented as distinct from on-chain verification |
| gnark FFM prover (`zeroj-prover-gnark`) | **Experimental, opt-in** | Works — both positive and negative e2e paths green (~450–490 ms proving); optional Go native library |
| WASM backends (`zeroj-bls12381-wasm`, `zeroj-bbs-wasm`) | **Experimental, opt-in** | Correct vs official fixtures, sandboxed (Chicory interpreter), careful memory handling, pinned Rust toolchain. Caveats: single-threaded, official *invalid* BBS fixtures not yet run through the WASM provider |
| MPF Poseidon (`zeroj-mpf-poseidon`) | **Experimental** | Circuit documented as too large for the practical on-chain path |
| BN254 (Groth16 + PlonK legacy) | **Disabled by default — keep it that way** | PlonK BN254 verifier lacks the point-validation layer of the BLS path; flag-gated (`-Dzeroj.allowLegacyBn254=true`), not ServiceLoader-registered; not a Cardano curve |
| Halo2 verifier, WASM prover (`incubator/*`) | **Incubator** | By construction |
| Build/test health | **Healthy** | 3,547 tests green across 25 modules, clean build, full e2e gate green; outstanding: Gradle-10 deprecations (4 lines), javadoc warnings (59, cosmetic) |

## What we still cannot claim — for any component

Project-wide gaps; these are the Phase 1–3 gates in ADR-0026:

1. **"Production-ready" or value-bearing/mainnet use** — no external
   cryptographic audit of the Java crypto stack or the Julc-compiled UPLC.
2. **Constant-time secret operations** on the default provider — documented,
   not fixed; do not run high-value issuer/prover keys on the pure-Java
   backend in adversarial co-located environments.
3. **Performance at scale** — nothing proven beyond ~2^11 constraints in-repo
   (~2^13 via snarkjs CLI); no published benchmarks.
4. **Production trusted setup** — no pinned ceremony artifacts; Groth16
   production setup still requires the external snarkjs MPC ceremony; the
   in-repo setup is dev-only and gated behind
   `-Dzeroj.allowInsecureTrustedSetup=true`.
5. **blst supply-chain provenance** — still the unverified 2021 third-party
   binary (`foundation.icon:blst-java:0.3.2`, shared with Scalus and
   yaci-store).
6. **Bidirectional snarkjs interop** — zeroj verifies snarkjs proofs; snarkjs
   has never verified a zeroj-generated proof in any test.
7. **GraalVM native-image at runtime** — metadata is present and correct on
   paper, but no native-image smoke test has actually been executed.

## Operational notes

- **Local on-chain testing**: use Yaci DevKit **0.11.x** (Ogmios-mode cost
  evaluation) until yaci-store ADR 017 lands. DevKit ≥ 0.12 evaluates via
  Scalus in a GraalVM native image that cannot load blst JNI, so PlutusV3
  BLS12-381 script costing fails there on all platforms; the zeroj e2e tests
  detect this and skip with an explicit message instead of failing.
- **Milestones closed 2026-07-03**: both May-2026 beta blockers (the
  `SealedBidGnarkE2ETest` negative-path bug and the never-green Yaci e2e
  gate); ADR-0026 P0 gate (all five items, independently verified, including
  numeric verification of the pinned on-chain constants).

## Bottom line

**ZeroJ is at beta level for testnet ZK workflows on Cardano.** The flagship
claim — Java DSL circuit → pure Java prove → on-chain Plutus V3 verification —
is demonstrated end-to-end, not asserted. The remaining production gates are
identified, prioritized, and tracked in ADR-0026; none of them are silently
blocking. Before tagging `0.1.0-beta1`: CHANGELOG, version snippets, and
optionally the Gradle-10 deprecation cleanup.
