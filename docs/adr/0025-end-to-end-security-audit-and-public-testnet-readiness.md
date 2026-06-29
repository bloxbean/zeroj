# ADR-0025: End-to-End Security Audit Outcomes and Public-Testnet Readiness Gates (Groth16 + PlonK)

## Status
Accepted — BLS12-381 Groth16 and PlonK public-testnet blockers implemented;
value-bearing/mainnet use still requires independent audit and release-assurance
gates

## Date
2026-06-29

## Context

Prior hardening ADRs took individual layers to an internally reviewable state:
ADR-0021 reviewed the shared BLS12-381 primitives, and ADR-0022/0023/0024 hardened
the pure-Java PlonK prover, the off-chain PlonK verifier, and the on-chain PlonK
profiles. This ADR records the outcome of a **cross-cutting, end-to-end security
audit of both proof systems** — Groth16 and PlonK, off-chain and on-chain — framed
around a single product question: *what is required to put a Groth16 and/or PlonK
flow on a public Cardano testnet, and what must wait for mainnet?*

The audit was a focused, adversarially-verified multi-agent pass over the
security-critical surfaces, with independent corroboration of the highest-severity
finding and a green build of the critical modules (`1,041` tests pass, `0` failures
across `zeroj-verifier-groth16`, `zeroj-verifier-plonk`, `zeroj-crypto`,
`zeroj-onchain-julc`). Six surfaces were reviewed:

1. Off-chain Groth16 verifiers (BN254 pure Java, BLS12-381 pure Java, BLS12-381 blst).
2. Off-chain PlonK verifiers (BN254, BLS12-381) and the Fiat-Shamir transcript.
3. Low-level crypto primitives (fields, EC, pairing, MSM, FFT, codecs, hash-to-curve).
4. Trusted setup / SRS handling and the setup cache.
5. Codec / parsing of untrusted artifacts (`.zkey`/`.ptau`/`.r1cs`/`.wtns`, JSON, CBOR envelope).
6. On-chain Plutus V3 verification via Julc (Groth16 and PlonK validators).

### What the audit confirmed as strong (lock in, do not regress)

- **PlonK off-chain Fiat-Shamir transcript is complete and correctly ordered**, and is
  cross-validated against snarkjs challenge values (`SnarkjsTranscriptCompatTest`). The
  transcript binds the verification key, all public inputs, and all prior commitments
  before each challenge. The "Frozen Heart" class of soundness failure is avoided. This
  is the single hardest thing a PlonK implementation must get right, and it is correct.
- **Crypto primitives are correct and reference-validated.** Montgomery constants
  (cross-checked vs `BigInteger`), FFT roots of unity, the BN254 G2 twist, RFC 9380
  hash-to-curve KATs, and EIP-197 BN254 pairing vectors all pass. No arithmetic
  correctness bug was found.
- **Groth16 on-chain is genuinely sound and proven end-to-end.** The Plutus validator
  performs the full pairing equation, the verification key is baked into the script hash
  (so it cannot be attacker-swapped), the Cardano `bls12_381_*_uncompress` builtins
  enforce prime-order subgroup membership, and there is a real-node (Yaci DevKit) E2E.
- **The deployable on-chain PlonK validators perform the full batched-KZG pairing
  check** (`PlonkBLS12381Verifier`, `PlonkBLS12381MultiInputVerifier`,
  `PlonkBLS12381MultiInputParamVerifier`), with inverse witnesses re-verified on-chain.
- **The BLS12-381 `.ptau` and PlonK `.zkey` importers are well-hardened** — bounds,
  canonical-field checks, on-curve + subgroup checks, pairing-based SRS consistency, and
  optional SHA-256 pinning.

### The structural finding: hardening is bimodal and was not propagated

The audit's central observation is that a strong validation/hardening pattern exists in
the codebase — in the off-chain BLS12-381 PlonK verifier, the BLS12-381 ptau/zkey
importers, and `SnarkjsPlonkCodec` — but was **not propagated** to the Groth16
verifiers, the BN254 paths, the Groth16 `.zkey` importer, or the non-PlonK JSON codecs.
The result is a set of soundness and robustness gaps that are individually fixable by
copying patterns that already exist in the tree.

### Findings (severity-tagged)

The table records the original audit findings. The implementation-status section below
records which findings have since been closed, deferred, or left as release-assurance
gates.

| ID | Sev | Surface | Finding | Location |
|---|---|---|---|---|
| F1 | **Critical** | On-chain PlonK | `PlonkBLS12381TranscriptPrototype` is a non-verifying stub (`return inv1Ok && inv2Ok;`) — no pairing/verification equation — yet compiles to a deployable `PlutusScriptV3` blueprint with no guardrail. Accepts any well-formed proof. | `…/plonk/validator/PlonkBLS12381TranscriptPrototype.java:217` |
| F2 | **High** | Off-chain Groth16/PlonK | BN254 proof/VK points fed into the pairing with no on-curve and no subgroup check; the BN254 `G1Point`/`G2Point` classes expose neither method. | `…/verifier/groth16/bn254/Groth16BN254Verifier.java:82-91`, `…/verifier/plonk/PlonkBN254Verifier.java:225-229` |
| F3 | **High** | Off-chain Groth16 | BLS12-381 pure-Java verifier has `isValid()` available but never calls it; blst verifier gets on-curve from deserialize but never calls `in_group()` (no subgroup check). | `…/verifier/groth16/bls12381/Groth16BLS12381PureJavaVerifier.java`, `Groth16BLS12381Verifier.java` |
| F4 | **High** | Off-chain + on-chain Groth16 | Public inputs not range-checked to `[0, r)`; `(proof, input)` and `(proof, input+k·r)` and negatives all verify, presenting different values to app logic (nullifier/dedup/equality malleability). PlonK already checks this; Groth16 does not. | `…/groth16/bn254/Groth16BN254Verifier.java:61`, `…/onchain/julc/groth16/lib/Groth16BLS12381Lib.java:210` |
| F5 | **High** | Trusted setup | Dev/prod boundary not enforced: `PowersOfTau*.generate()` returns a single-party SRS with known `tau` (forgeable), guarded only by a `System.err` warning — no runtime opt-in gate. | `…/setup/PowersOfTauBLS381.java:45-96` |
| F6 | **High** | Trusted setup | Setup cache reconstructs points from raw limbs with no integrity hash, no on-curve, no subgroup, no pairing-consistency re-check — bypassing the importer's validation (cache poisoning via local write). | `…/setup/SrsCache.java`, `Groth16SetupCache.java`, `SetupCacheIO.java` |
| F7 | **High** | Codec | Unbounded allocations / `long→int` truncation in `R1CSImporter`, BN254 `ZkeyImporter`/`PtauImporter`/`PlonKZkeyImporter`, `ZkeyImporterBLS381`, and the Groth16/Halo2/gnark JSON codecs → OOM / CPU-DoS, with untyped runtime exceptions instead of clean `CodecException`. | `…/groth16/R1CSImporter.java`, `…/groth16/ZkeyImporterBLS381.java`, `…/codec/SnarkjsJsonCodec.java` |
| F8 | Medium | On-chain | All validators ignore `ScriptContext`: no replay/nullifier/authorization. By design for a reusable verifier, but load-bearing and currently under-documented. | `…/groth16/validator/Groth16BLS12381Verifier.java`, PlonK validators |
| F9 | Medium | Off-chain PlonK | BLS12-381 PlonK path has no independent (snarkjs/gnark) cross-verification vectors — a shared prover↔verifier bug would pass all tests. The on-chain PlonK transcript profile is bespoke and unaudited. | `PlonkBLS12381VerifierTest` |
| F10 | Medium | Off-chain Groth16 | VK points unvalidated; `toEnvelopeFromJson` accepts proof and VK from the same bundle without pinning, so VK is trusted only if the integrator pins the hash out-of-band. | `…/codec/SnarkjsJsonCodec.java` |
| F11 | Medium | Trusted setup | Self-generated toxic waste (`tauScalar`) is serialized to disk in cleartext with default file permissions. | `…/setup/SrsCache.java:50-57` |
| F12 | Medium | Docs | `README.md:39` materially misstates PlonK on-chain status (says KZG check "deferred"; in fact 3 of 4 validators do it, 1 is a stub). | `README.md:39` |

Several of these reinforce items already tracked: F2/F3 extend the validation contract of
ADR-0021 to the verifier layer; F7/F9 overlap ADR-0024 §8 (fuzzing/differential gates);
F5/F6/F11 sit alongside ADR-0013 (trusted-setup tooling). ADR-0025 records the
**cross-cutting decisions and the public-testnet gating** that those per-layer ADRs did
not own.

## Decision

### 1. Public-testnet readiness posture (per path)

We adopt the following posture. "Testnet-eligible" means a clearly-labeled,
non-value-bearing public testnet after the listed gates; it is **not** mainnet approval.

| Path | Audit score | Posture |
|---|---:|---|
| Groth16 on-chain (BLS12-381 Plutus V3) | 7/10 | **Testnet-eligible** after Decisions 3, 5, 6 |
| Groth16 off-chain — blst | 3/10 (path) | Testnet-eligible after Decision 2 |
| Groth16 off-chain — pure Java (BLS / BN254) | 3/10 | BLS12-381 testnet-eligible after Decision 2; BN254 legacy opt-in only |
| PlonK off-chain | 6/10 | BLS12-381 testnet-eligible after Decision 7 vector coverage; BN254 legacy opt-in only |
| PlonK on-chain | 3/10 | BLS12-381 experimental/testnet-eligible after Decisions 4, 7; **not value-bearing** until external review |
| Trusted setup | 5/10 | Testnet only with imported ceremony SRS (Decision 5) |
| Codec / parsing | 5/10 | Harden before exposing to untrusted input (Decision 6) |

**Headline product decision:** the **Groth16 BLS12-381 end-to-end flow is the primary
public-testnet path.** PlonK BLS12-381 is now testnet-eligible as an explicitly
experimental path after the internal gates below, but must not gate funds or other
value-bearing state until independent cryptographic/security review closes.

### 2. Make point and public-input validation a verifier-layer release gate

Every off-chain verifier must, before any group operation or pairing, reject inputs that
are not (a) canonically encoded, (b) on-curve, and (c) in the prime-order subgroup, and
must reject public inputs outside `[0, r)`. This applies to proof points, VK points, and
each IC element.

- **BLS12-381 pure-Java Groth16:** call the existing `G1Point/G2Point.isValid()` on every
  parsed point (F3).
- **blst Groth16:** add `P1_Affine.in_group()` / `P2_Affine.in_group()` after
  deserialize (F3).
- **BN254:** remains legacy/off-chain-only and is not part of Cardano readiness.
  High-level BN254 proving and verification require explicit legacy opt-in, and BN254
  verifiers are **not** registered as default SPI services for untrusted input. Point
  validation parity is deferred unless legacy BN254 support is re-promoted.
- **Public inputs:** add an `0 <= x < r` check in the Groth16 off-chain verifiers and in
  `Groth16BLS12381Lib` on-chain (`scalarInFr`, matching the PlonK path) (F4).

### 3. Harden the on-chain Groth16 validator to parity with PlonK

`Groth16BLS12381Lib` must range-check each public input (`scalarInFr`) and reject
infinity/identity proof points, matching the checks the PlonK validators already perform.
The full pairing equation and VK-in-script-hash trust model are confirmed correct and are
locked in.

### 4. The non-verifying PlonK prototype must not be deployable

`PlonkBLS12381TranscriptPrototype` must be removed, or excluded from blueprint
generation and moved to test scope, or made to fail compilation in production builds
(F1). No artifact that does not perform the verification/pairing equation may emit a
deployable `PlutusScriptV3` blueprint. We also add a build-time guard: a generated
spending-validator blueprint must correspond to a validator that performs a pairing
check.

### 5. Trusted-setup boundary and cache integrity

- A known-`tau` (single-party) SRS may only be obtained through an explicit insecure
  opt-in (typed acknowledgement or required system property), and such an SRS must be a
  distinct type that production/testnet-release APIs refuse (F5). Testnet and mainnet
  circuits must use an **imported real-ceremony artifact** (Hermez / Perpetual PoT /
  Zcash) via the hardened BLS importers.
- The setup cache must bind a content hash (or signature) and re-validate points
  (on-curve + subgroup, and SRS pairing-consistency for SRS material) on load (F6).
- `tauScalar` must not be persisted by default; if a dev flow needs it, write owner-only
  (`0600`) to a clearly-marked `.insecure` file (F11).

### 6. Propagate codec hardening to all untrusted-input parsers

Port the existing `readBounded` size caps, section-offset/length validation, count/`n8`
bounds, canonical-field checks, and typed-failure behavior from `PtauImporterBLS381` /
`SnarkjsPlonkCodec` into `R1CSImporter`, `ZkeyImporter`, `ZkeyImporterBLS381`,
`PlonKZkeyImporter`, `PtauImporter`, both `importWtns`, and the
`SnarkjsJsonCodec`/`Halo2Codec`/`GnarkPlonkCodec` JSON codecs (F7). Bound
`CborEnvelopeCodec.decode` input size. This is the structural complement to the
fuzzing/differential CI gates already required by ADR-0024 §8.

### 7. PlonK soundness assurance before value-bearing use

- Add at least one independent (snarkjs or gnark) cross-verification vector to the
  BLS12-381 PlonK off-chain test suite (F9).
- The bespoke on-chain PlonK transcript profile requires independent cryptographic review
  plus differential testing against a reference verifier (reaffirms ADR-0024 §8).
- Add a real-node (Yaci DevKit) PlonK E2E and re-measure budgets on current protocol
  parameters before any value-bearing release.

### 8. Documentation corrections

Correct `README.md:39` to distinguish the three full on-chain PlonK verifiers from the
deferred-KZG prototype (F12), and document that all on-chain validators ignore
`ScriptContext`, so integrators **must** add replay/nullifier protection and
authorization (F8). Provide a composing example that binds a proof to the spending
`txOutRef` / a nullifier.

## Consequences

### Easier
- A clear, defensible public-testnet story: Groth16 BLS12-381 end-to-end is the supported
  path, with an honest, gated posture for everything else.
- The validation contract from ADR-0021 becomes uniform across primitives, verifiers,
  importers, and the cache — downstream integrators get consistent fail-closed behavior.
- No non-verifying artifact can be mistaken for a real validator.

### Harder
- More validation on every verifier hot path (subgroup checks add cost; see ADR-0021
  Decision 4 for the endomorphism-based optimization roadmap).
- BN254 verifiers gain an explicit experimental/off-chain-only status until point
  validation lands, narrowing what is advertised as ready.
- Trusted-setup ergonomics tighten: an explicit insecure opt-in is now required to get a
  dev SRS, and cache files must carry integrity metadata.

### Neutral
- No change to the verifier-first architecture (ADR-0001) or crypto/policy separation
  (ADR-0006). The on-chain VK-in-script-hash trust model is unchanged.
- Performance optimizations remain deferred per ADR-0021 Decision 4.

## Test Plan

Negative/adversarial vectors become release gates across all BLS12-381 verifiers
(shared where possible). BN254 gates apply only if legacy/off-chain BN254 support is
re-promoted beyond explicit opt-in:

- **Point validation:** off-curve point rejected; on-curve but off-subgroup (torsion)
  point rejected; infinity proof point rejected; non-canonical coordinate (`x >= p`)
  rejected — for Groth16 (BN254, BLS pure-Java, blst) and PlonK (BN254, BLS).
- **Public-input range:** `x = x + r` and negative `x` rejected (Groth16 off-chain and
  on-chain).
- **On-chain Groth16:** add the F3/F4 negatives to the Julc-VM suite; keep the real-node
  E2E green.
- **On-chain PlonK:** assert no deployable blueprint exists for a validator that does not
  perform a pairing check (guards F1).
- **Trusted setup:** `generate()` without the insecure opt-in fails; a tampered cache file
  (mutated point / wrong hash) is rejected on load; `tauScalar` is not present in the
  default cache file.
- **Codec:** oversized input, huge count/`n8`, negative `nPrivate`, truncated section,
  duplicate section, huge `BigInteger` string, non-canonical decimal, duplicate JSON key —
  each returns a stable typed failure (extends ADR-0024 §8 fuzzing corpora).
- **PlonK cross-verification:** at least one snarkjs/gnark-sourced BLS12-381 vector
  verified by `PlonkBLS12381Verifier`.

Sanity-check that each new gate fails against the unfixed code before the fix lands.

## Implementation Plan

### Phase 1 — Testnet blockers (Groth16 path)
1. Decision 4: make the PlonK prototype non-deployable (F1).
2. Decision 2: point + public-input validation in the Groth16 verifier(s) used on the
   testnet path; Decision 3: on-chain Groth16 `scalarInFr` + infinity rejection.
3. Decision 5: enforce imported-ceremony SRS for testnet circuits; gate `generate()`.
4. Decision 8: README correction + replay-protection documentation and example.
Exit: Groth16 BLS12-381 end-to-end testnet flow passes positive + new negative gates and
the real-node E2E.

### Implementation status — 2026-06-29

- **Completed for BLS12-381 Groth16:** Decisions 2 and 3 for the Cardano-supported
  Groth16 path. The pure-Java and blst off-chain verifiers now reject non-canonical
  public inputs (`x < 0` or `x >= r`), non-canonical base-field coordinates (`x >= p`),
  infinity proof/VK/IC points, and points that are not on-curve and in the prime-order
  subgroup before pairing.
- **Completed for on-chain Groth16:** `Groth16BLS12381Lib` now checks public inputs are
  canonical BLS12-381 scalars and rejects non-canonical or infinity compressed proof/VK/IC
  points before scalar multiplication or pairing. Both the variable-input and fixed-four
  helper paths are covered.
- **Tests added and passing:** `:zeroj-verifier-groth16:test --tests '*Groth16BLS12381*'`
  and `:zeroj-onchain-julc:test --tests '*Groth16BLS12381VerifierTest'` cover positive
  verification, `x + r`, negative public inputs, non-canonical proof coordinates, and
  off-chain projective infinity / on-chain compressed infinity points.
- **Completed for trusted setup/cache on the BLS12-381 path:** `PowersOfTau*.generate()`
  and single-party Groth16 setup now require
  `-Dzeroj.allowInsecureTrustedSetup=true` (or `ZEROJ_ALLOW_INSECURE_TRUSTED_SETUP=true`).
  BLS12-381 setup caches use a versioned SHA-256-bound payload, re-validate cached
  points on load, re-check SRS pairing consistency, and stop persisting `tauScalar` by
  default. The only API that persists `tauScalar` is the explicitly named
  `saveBls12381InsecureDevSrsWithTau(...)`, guarded by the insecure setup opt-in and
  written with owner-only permissions where POSIX permissions are available.
  Cache point validation now uses the Jacobian scalar-multiplication path for subgroup
  checks, avoiding the affine inversion-per-step performance cliff seen during
  end-to-end usecase testing while preserving subgroup validation.
- **Completed for BLS12-381 Groth16 import/codec hardening:** `R1CSImporter`,
  `ZkeyImporterBLS381`, `importWtns`, `SnarkjsJsonCodec`, and `CborEnvelopeCodec.decode`
  now have bounded input reads, strict section/count checks, canonical field/decimal
  parsing, subgroup/curve validation for BLS12-381 zkey points, optional SHA-256 zkey
  pinning, and stable typed failures (`IOException` or `CodecException`).
  `toEnvelopeFromJson` now parses and validates the VK/public-input profile before
  binding the envelope to the VK hash.
- **Documentation updated:** README and trusted-setup docs now state that reusable
  on-chain verifiers verify only the cryptographic statement; application scripts must
  bind replay/nullifier/authorization policy to `ScriptContext`. The PlonK on-chain
  README wording distinguishes the full pairing-check validator profiles from the
  experimental status rather than describing all PlonK KZG checks as deferred.
- **Usecase integration completed:** `zeroj-usecases` was updated to consume the local
  `0.1.0-pre3` ZeroJ artifact and Julc `0.1.0-pre14`; local demo tests explicitly opt
  into dev-only trusted setup. Groth16 demos no longer persist Powers-of-Tau `tau` in
  SRS cache files; they cache only circuit-specific setup and guard cached setup reuse
  by checking the current R1CS wire/public-input shape.
- **Tests added and passing for this phase:** `:zeroj-codec:test` and
  `:zeroj-crypto:test` cover tampered cache rejection, default tau omission, explicit
  insecure tau cache, insecure setup gate, BLS12-381 zkey/witness malformed inputs,
  real snarkjs BLS12-381 zkey interop, duplicate JSON keys, non-canonical decimals, VK
  public-input mismatch, and malformed CBOR VK refs.
- **End-to-end Yaci evidence:** after publishing the local ZeroJ artifact to Maven
  local, the proof-of-reserves Groth16 Yaci test passed against a running Yaci DevKit
  with real lock/spend transactions. First run spent ~3.5 minutes creating the local
  dev setup cache for a 27,866-constraint / 48,440-wire demo circuit; cached rerun spent
  ~61 seconds loading/validating setup and ~14 seconds across proof generation, script
  compilation, submission, and confirmation. The PlonK proof-of-reserves and compliance
  credential Yaci E2E tests also passed.
- **Completed for BLS12-381 PlonK testnet readiness:** the non-verifying transcript
  prototype is no longer in deployable main sources. `PlonkBLS12381Lib` now provides a
  reusable `@OnchainLibrary` for custom validators, the built-in PlonK validators
  delegate to it, and a guard test asserts that the library performs a BLS12-381 Miller
  loop plus final pairing check. `PlonkBLS12381VerifierTest` now verifies an
  independently generated snarkjs BLS12-381 PlonK vector, and the Cardano-profile
  one-input and bounded MPI validators remain covered by positive, negative, budget,
  and Yaci E2E tests. `zeroj-usecases` proof-of-reserves and compliance-credential
  PlonK demos now use app-local validators that compose `PlonkBLS12381Lib` with
  usecase-specific public-input policy, and both demos passed real Yaci DevKit
  lock/spend E2E tests after publishing the local ZeroJ artifact.
- **BN254 PlonK status:** BN254 high-level proving and verification APIs require the
  explicit legacy opt-in `-Dzeroj.allowLegacyBn254=true` or
  `ZEROJ_ALLOW_LEGACY_BN254=true`, and BN254 verifiers are not auto-discovered. BN254
  point-validation parity remains postponed and is no longer a Cardano
  production-readiness blocker because Cardano only exposes BLS12-381 builtins.
- **Still pending before value-bearing/mainnet use:** broader fuzzing/differential CI
  gates and third-party cryptographic/security audit. These are release-assurance gates,
  not blockers for labeled non-value-bearing public testnet trials.

### Phase 2 — Robustness hardening
5. Decision 6: propagate codec/importer bounds and typed failures; bound CBOR decode.
6. Decision 5: cache integrity hash + on-load re-validation; stop persisting `tauScalar`.
7. Decision 2: keep BN254 point-validation parity postponed unless legacy/off-chain
   BN254 support is re-promoted; it is not part of Cardano production readiness.
Exit: all parsers fail closed on the adversarial corpus; cache poisoning vector closed.

### Phase 3 — PlonK value-bearing gates
8. Decision 7: internal independent PlonK cross-verification vector, real-node PlonK E2E,
   and budget re-measurement are complete for BLS12-381 public-testnet trials. Broader
   transcript-profile differential/fuzz coverage remains a release-assurance gate.
9. Independent third-party cryptographic audit (mandatory before mainnet, per ADR-0024).
Exit: PlonK on-chain external-audit findings closed or explicitly deferred with
rationale.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| Non-verifying prototype deployed to a value-bearing context | Critical | Decision 4: make it non-deployable; build-time blueprint guard; F1 test gate |
| Off-curve / off-subgroup point accepted → Groth16 forgery | High | Decision 2: enforce on-curve + subgroup on every verifier path; torsion-point negative gates |
| Public-input malleability breaks nullifier/dedup invariants | High | Decision 2/3: `[0, r)` range check off-chain and on-chain |
| Dev SRS (known tau) used on testnet/mainnet → all proofs forgeable | High | Decision 5: insecure opt-in, distinct type, imported-ceremony requirement |
| Cache poisoning via local write yields forgeable proofs | High | Decision 5: integrity hash + on-load re-validation |
| Untrusted artifact triggers OOM/CPU-DoS or untyped crash | High | Decision 6: bounds + typed failures; fuzzing corpora (ADR-0024 §8) |
| Bespoke PlonK transcript has an undetected soundness gap | High | Decision 7: independent review + differential testing + cross-verification vector |
| Missing replay protection treated as the verifier's job | Medium | Decision 8: document the ctx trust assumption; provide a binding example |

## References

- ADR-0001: Verifier-First Architecture
- ADR-0006: Separation of Crypto and Policy Verification
- ADR-0012: Pure Java Provers for Groth16 and PlonK
- ADR-0013: Trusted Setup Ceremony Tools
- ADR-0021: BLS12-381 Implementation Review Outcomes and Hardening Posture
- ADR-0022: Pure Java PlonK Backend Review Outcomes and Hardening Posture
- ADR-0023: On-Chain PlonK Verifier Hardening Posture
- ADR-0024: PlonK Release Gates and Multi-Public-Input On-Chain Profile
- `docs/beta-release-readiness.md`
- CIP-0381 (Plutus BLS12-381 builtins): <https://cips.cardano.org/cip/CIP-0381>
- RFC 9380 hash-to-curve: <https://www.rfc-editor.org/rfc/rfc9380>
