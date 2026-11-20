# ADR-0064: On-Chain BBS ProofVerify Hardening and Draft-10 Scalar Bounds

## Status
Proposed — 2026-11-20 (pending external review sign-off). Hardens on-chain BBS presentation verification and aligns off-chain proof encoding, deserialization, and WASM provider boundaries with CFRG BBS draft-10. Amends [ADR-0019](0019-cfrg-bbs-pure-java-and-wasm-providers.md) to cover the on-chain Cardano Plutus V3 verifier (`BbsProofVerify`) and resolves the out-of-scope BBS scalar-range finding noted in [ADR-0060](0060-pedersen-bls12-381-g1-profiles.md).

**Risk class: R3.** Changes cryptographic proof-input validation on the on-chain BBS presentation verifier (`zeroj-onchain-julc/.../bbs/lib/BbsProofVerify.java`) and aligns off-chain proof encoding/deserialization (`zeroj-bbs/.../internal/BbsCodec.java`), parameter derivation (`BbsToCardano.java`), and the opt-in WASM provider boundary (`WasmBbsProvider.java`) with `draft-irtf-cfrg-bbs-signatures-10`.

**PR coupling note (explicit maintainer exception):** PR #118 ships ADR-0064 together with the maintainer-directed toolchain upgrades to JuLC `0.1.0-pre22` (governed by the 2026-11-20 addendum to [ADR-0050](0050-julc-pre17-org-julclang-and-typed-bls.md)) and Cardano Client Lib `0.8.0-pre8` (governed by the 2026-11-20 addendum to [ADR-0042](0042-operation-specific-poseidon-mpf-and-jmt-circuits.md), which delivers CCL's terminal-fork MPF verification fix).

## Date
2026-11-20

## Context
`org.zeroj.onchain.julc.bbs.lib.BbsProofVerify` is a Plutus V3 `@OnchainLibrary` porting CFRG BBS `CoreProofVerify` (`BLS12381G1-SHA-256`, 5-message credential disclosing indexes `{2, 3}`). ADR-0019 explicitly scoped only off-chain pure-Java and WASM providers ("No Cardano on-chain verifier is implied"), leaving `BbsProofVerify` without a governing ADR.

During internal security review, a **total presentation forgery** was discovered and reproduced in the Julc VM against `BbsProofVerify.verify`:

1. **Missing identity-point rejection (critical forgery):** `BbsProofVerify.verify` uncompressed redeemer-supplied `abar`, `bbar`, and `d` directly without checking that none is the compressed G1 point at infinity (`0xc0 || 0x00^47`). In CFRG BBS draft-10, `CoreProofVerify` (§3.6.4) relies on `octets_to_proof` (§4.2.4.5 step 7) to reject `Identity_G1`. Without that check, an attacker with no credential and no secret key can forge a presentation for any issuer key `W`, any disclosed messages `msg2`/`msg3`, and any presentation header `ph`:
   - Set `Abar = Bbar = O` (`0xc0 || 0x00^47`) and `D = compress(Bv)` (publicly computable from `P1`, `Q1`, `H2`, `H3`, `domain`, `msg2`, `msg3`).
   - Pick arbitrary scalars `eHat`, `r1Hat`, `mHat0`, `mHat1`, `mHat2` (even **all non-zero** in `[1, r-1]`).
   - Compute `T1 = r1Hat·D` and `T2 = mHat0·H0 + mHat1·H1 + mHat2·H4` (neither depends on `c`).
   - Compute `c = hash_to_scalar(...)` using `Abar = Bbar = O`, `D = Bv`, `T1`, `T2`, `domain`, `ph`, and set `r3Hat = (r - c) mod r`.
   - On-chain: `T2 = c·Bv + (r - c)·Bv + Σ mHat_j·H_j = Σ mHat_j·H_j` matches the committed `T2`, `c == challenge` passes, and `finalVerify(millerLoop(O, W), millerLoop(O, BP2))` evaluates `finalVerify(1, 1) == true`.
2. **Missing proof-scalar bounds (malleability & draft-10 divergence):**
   - On-chain `BbsProofVerify.verify` never range-checked `eHat`, `r1Hat`, `r3Hat`, `mHat0`, `mHat1`, `mHat2`, or `c`. Because `bls12_381_G1_scalarMul` reduces scalars modulo `r`, `s` and `s ± r` were accepted interchangeably (redeemer malleability).
   - Off-chain `BbsCodec.octetsToProof` parsed proof scalars with `scalarFromBytes` (`[0, r-1]`), and `BbsCodec.ProofParts` / `proofToOctets` accepted and serialized `0`, diverging from draft-10 §4.2.4.4 (`proof_to_octets`) and §4.2.4.5 step 14 (`if s_j = 0 or if s_j >= r, return INVALID`).
   - In the opt-in WASM differential oracle (`assurance/zeroj-bbs-wasm`, `zkryptium 0.6.1`), `PoKSignature::from_bytes` (`rust/src/lib.rs:436`) accepted `0` scalars (leaving rejection to the later challenge check) and surfaced `s >= r` as a WASM error (`InvalidProofOfKnowledgeSignature`) rather than returning `false`.
   - Note: rejecting zero scalars alone does **not** prevent the forgery above (the all-non-zero variant bypasses zero-scalar checks). Identity-point rejection is the forgery fix; `[1, r-1]` scalar checking eliminates malleability and restores draft-10 conformance.
3. **Unvalidated issuer key in `BbsToCardano.verifierParams`:** `BbsPublicKey` does not validate its compressed G2 bytes at construction, and `BbsToCardano.verifierParams` forwarded `publicKey.bytes()` without checking curve membership, subgroup membership, or non-identity.

## Threat Model and Trust Assumptions
- **Untrusted:** All redeemer inputs to `BbsProofVerify.verify` (`abar`, `bbar`, `d`, `eHat`, `r1Hat`, `r3Hat`, `mHat0`, `mHat1`, `mHat2`, `c`, `msg2`, `msg3`, `ph`).
- **Trusted deploy-time validator parameters:** `w` (issuer G2 public key), `bp2`, `p1`, `q1`, `h0..h4`, `domain`, `dstH2S`, `dstMap` are baked into the validator script hash at deployment.
  - **`W` / `domain` binding assumption:** `domain` is precomputed off-chain and passed as a validator parameter; `w` is not re-hashed on-chain into `domain`. Soundness requires the deployer to derive `domain` from the exact same `w`, credential `header`, and generators (as `BbsToCardano.verifierParams` does).
- **Trusted ledger primitives:** Cardano Plutus V3 CIP-0381 builtins (`bls12_381_G1_uncompress`, `bls12_381_G2_uncompress`, `bls12_381_G1_compress`, `bls12_381_G1_add`, `bls12_381_G1_scalarMul`, `bls12_381_millerLoop`, `bls12_381_finalVerify`, `sha2_256`).
- **Application boundary (ADR-0006):** `BbsProofVerify` verifies cryptographic presentation validity only and does not read `ScriptContext`. Real value-bearing validators must separately bind disclosed attribute checks, payout/authorization, and replay protection (binding `ph` to the spend).
- **No secrets on-chain:** Verification processes public data only; off-chain issuance and presentation generation remain bound by ADR-0062 I3 (offline/isolated-host only).

## Pinned Normative References
- `draft-irtf-cfrg-bbs-signatures-10` (8 January 2026):
  - §3.6.4 (`CoreProofVerify`)
  - §4.2.4.4 (`proof_to_octets`): requires all serialized proof scalars (`e^`, `r1^`, `r3^`, `m^_j`, `c`) in `[1, r - 1]`.
  - §4.2.4.5 (`octets_to_proof`): step 7 rejects `Identity_G1` on `Abar`, `Bbar`, `D`; step 14 rejects `s_j == 0` or `s_j >= r` for all serialized proof scalars (`e^`, `r1^`, `r3^`, `m^_j`, `c`); step 17 rejects trailing bytes.
- CIP-0381 (`86b89208`): Plutus V3 BLS12-381 builtins and Zcash compressed point serialization (`0xc0 || 0x00^47` for G1 identity, `0xc0 || 0x00^95` for G2 identity).
- [ADR-0019](0019-cfrg-bbs-pure-java-and-wasm-providers.md) (off-chain CFRG BBS pure-Java and WASM providers), [ADR-0050](0050-julc-pre17-org-julclang-and-typed-bls.md) (JuLC toolchain upgrades), [ADR-0042](0042-operation-specific-poseidon-mpf-and-jmt-circuits.md) (CCL pin & MPF/JMT circuits), and [ADR-0056](0056-single-decompression-groth16-plutus-v3.md) (single-decompression Plutus V3 verification discipline).
- JuLC `v0.1.0-pre22` / Cardano Client Lib `v0.8.0-pre8`.

## Decision
1. **D1 (On-chain identity-point rejection before decompression):**
   At the top of `BbsProofVerify.verify`, reject `abar`, `bbar`, or `d` unless each is 48 bytes and byte-unequal to compressed G1 identity (`0xc0 || 0x00^47`), **before** calling `bls12_381_G1_uncompress`. Also reject `w` unless it is 96 bytes and byte-unequal to compressed G2 identity (`0xc0 || 0x00^95`) as cheap defense-in-depth.
   - **No redundant re-compression round-trip:** CIP-0381 `bls12_381_G1_uncompress` / `bls12_381_G2_uncompress` (backed by `blst` in both `cardano-node` and the Julc VM) already rejects wrong lengths, cleared compression bits, non-canonical infinity encodings (`0xe0 || 0x00^47`, non-zero body), `x >= p`, off-curve points, and out-of-subgroup points, and `abar`/`bbar`/`d` raw bytes are hashed directly into the Fiat-Shamir challenge. Omitting redundant `compress(uncompress(b)) == b` keeps single-decompression ExUnits low (~2.44B CPU).
2. **D2 (Strict `[1, r-1]` proof-scalar bounds on-chain and across all off-chain providers):**
   - On-chain `BbsProofVerify.verify`: compute `r = BbsHashToScalar.scalarFieldOrder()` **once** and require `1 <= s < r` for all 7 proof scalars (`eHat`, `r1Hat`, `r3Hat`, `mHat0`, `mHat1`, `mHat2`, `c`) before any decompression or hashing. Also require `0 <= domain < r`.
   - Off-chain `BbsCodec.ProofParts` & `proofToOctets`: enforce `requireNonZeroScalar` (`1 <= s < r`) on construction and serialize with `scalarToBytes` per draft-10 §4.2.4.4 so the encoder cannot emit a proof the decoder rejects.
   - Off-chain `BbsCodec.octetsToProof`: replace `scalarFromBytes` with `nonZeroScalarFromBytes` (`1 <= s < r`) for all proof scalars (including `c`). This automatically hardens `CfrgBbsCore` (pure-Java and `blst` BLS providers) and `BbsToCardano.onChainProof`.
   - Opt-in WASM oracle `WasmBbsProvider.proofVerify`: validate `BbsCodec.octetsToProof(proof.bytes(), ciphersuite)` before calling `zkryptium 0.6.1` (returning `false` on `IllegalArgumentException`) so all providers exhibit identical boolean rejection semantics for `0` and `>= r` scalars without rebuilding the pinned Rust WASM binary.
3. **D3 (Deploy-time public key & ciphersuite validation in `BbsToCardano`):**
   - `BbsToCardano.verifierParams` validates `publicKey.bytes()` via `BbsCodec.octetsToPublicKey` (96 bytes, on-curve, prime-order subgroup, non-identity) and asserts `publicKey.ciphersuite() == ciphersuite`.
   - `BbsToCardano.onChainProof` asserts `presentation.proof().ciphersuite() == ciphersuite`.

## Alternatives Considered
- **Only rejecting zero scalars (`[1, r-1]`):** Rejected — does not stop the all-non-zero identity-point forgery.
- **Adding `compress(uncompress(b)) == b` for all points:** Rejected for `BbsProofVerify` — wastes ExUnits on Plutus V3 because CIP-0381 `uncompress` already rejects non-canonical encodings (verified in VM and on-chain tests) and the raw `abar`/`bbar`/`d` bytes enter the challenge hash directly.
- **Recomputing `domain` on-chain:** Rejected — hashing all generators and header on-chain would significantly increase script size and ExUnits; baking `domain` as a deploy-time `@Param` derived by `BbsToCardano.verifierParams` is the intended Plutus V3 trade-off and is documented explicitly as a trust assumption.
- **Dropping validation checks to keep memory delta below +1%:** Rejected — security invariant correctness strictly outranks a 37k memory-unit delta (~0.26% of Cardano's 14M tx memory limit).

## Security Invariants
- **I1:** No presentation with `Abar == O`, `Bbar == O`, or `D == O` (or non-canonical infinity) is accepted on-chain or off-chain, regardless of scalar values.
- **I2:** Every proof scalar (`eHat`, `r1Hat`, `r3Hat`, `mHat_j`, `c`) outside `[1, r-1]` (including `0`, negative values, `r`, and `s + r`) is rejected on-chain and across all off-chain providers (`PureJavaBbsProvider` with pure-Java/blst, `WasmBbsProvider`, `BbsCodec` encode/decode, and `BbsToCardano`).
- **I3:** Invalid proof scalars and identity/wrong-length proof points are rejected **before** any elliptic-curve decompression, scalar multiplication, hashing, or pairing builtin runs.
- **I4:** `BbsToCardano.verifierParams` refuses identity, off-curve, out-of-subgroup, wrong-length, or wrong-ciphersuite issuer public keys.
- **I5 (Measured Performance Ceiling):** Against the pre-fix JuLC `0.1.0-pre22` baseline (`2,434,070,891` CPU / `170,454` mem; `9923f55` pre18 baseline `2,433,775,021` CPU / `169,451` mem), hardened honest verification measures **`2,442,385,555` CPU (+0.34%)** and **`207,274` mem (+21.6%, +36,820 units — ~1.48% of Cardano's 14M tx memory limit)**. Regression bounds in `BbsProofVerifyVmTest` enforce `CPU <= 2,460,000,000` and `Mem <= 215,000`, and fail-fast rejection of invalid scalars/identity points under `100,000,000` CPU.

## Consequences
- **Easier / Stronger:** Eliminates a total presentation forgery on Plutus V3, closes redeemer scalar malleability, aligns off-chain encoder/decoder and WASM oracle semantics with CFRG draft-10 §4.2.4.4–§4.2.4.5, and catches invalid issuer public keys at deploy-time parameter derivation.
- **Harder / Costs:**
  - Honest on-chain BBS verification memory increases by `+36,820` units (`170,454 -> 207,274`, still ~1.48% of Cardano's 14M tx limit) and CPU by `+8.3M` steps (+0.34%).
  - Validators embedding `BbsProofVerify` (and, due to the co-shipped JuLC `0.1.0-pre22` bump documented in ADR-0050, **all** JuLC validators) produce new script hashes and must be redeployed.

## Risks
- **Deployer parameter mismatch (`W` vs `domain`):** Because `domain` is not recomputed from `W` on-chain, a deployer constructing validator parameters outside `BbsToCardano.verifierParams` could bind mismatched `W` and `domain`. Mitigated by explicit trust-boundary documentation and `BbsToCardano.verifierParams` validation.
- **Replay / missing `ScriptContext` binding:** Callers that omit spend-specific `ph` binding remain vulnerable to presentation replay; `BbsProofVerify` is strictly crypto-only.
- **Draft specification evolution:** `draft-irtf-cfrg-bbs-signatures-10` is an IRTF draft and may change before RFC publication.

## Compatibility
- **Breaking on-chain script hashes:** Every validator embedding `BbsProofVerify` produces a new compiled UPLC script and script hash after this change (affecting downstream consumers such as `zeroj-usecases/reusable-kyc`). In addition, because PR #118 upgrades JuLC from `0.1.0-pre18` to `0.1.0-pre22` (see the 2026-11-20 addendum to [ADR-0050](0050-julc-pre17-org-julclang-and-typed-bls.md)), **all** shipped JuLC validators (Groth16, PlonK, Authenticated State, and BBS/example validators) receive regenerated UPLC bytes and new script hashes. Release notes must list all affected validators explicitly.
- **Off-chain wire format:** Unchanged for honest proofs; proofs with any zero scalar are now rejected by both encoder (`ProofParts`/`proofToOctets`) and decoder (`octetsToProof`) in compliance with draft-10 §4.2.4.4–§4.2.4.5.

## Implementation Milestones
- **M1 — On-chain & off-chain hardening (Complete):** Implement D1–D3 in `BbsProofVerify`, `BbsHashToScalar`, `BbsCodec` (`ProofParts`, `proofToOctets`, `octetsToProof`), `BbsToCardano`, and `WasmBbsProvider`. Exit criteria: all positive and negative unit, VM, and WASM cross-provider tests pass.
- **M2 — VM regression & mutation verification (Complete):** Reproduce the all-zero and all-non-zero identity-point forgeries against pre-fix `BbsProofVerify`, confirm fail-fast rejection (`< 100M` CPU) after hardening, and lock honest VM budget ceilings (`<= 2.46B` CPU / `<= 215k` mem).
- **M3 — Live Plutus V3 E2E verification (Complete):** Run `BbsProofVerifyDevKitE2ETest` on Yaci DevKit confirming Phase-2 node rejection of all-non-zero forgery, `eHat + r` malleability, `eHat = 0`, and tampered `ph`, followed by confirmed on-chain spend of an honest presentation.
- **M4 — External review & audit gate (Open):** Address PR review comments, accept ADR-0064 after review sign-off, and complete independent external cryptographic audit prior to value-bearing / mainnet use.

## Verification Strategy
1. **Off-chain (`zeroj-bbs` and `assurance/zeroj-bbs-wasm`):**
   - Full official CFRG draft-10 JSON vector suites (SHA-256 & SHAKE-256 across pure-Java, `blst`, and `wasm-zkcrypto` BLS providers) remain green.
   - Negative tests rejecting `0`, `-1`, and `>= r` in every proof-scalar slot (`eHat`, `r1Hat`, `r3Hat`, `mHat_i`, `c`) in `BbsCodec.ProofParts` / `proofToOctets`, `BbsCodec.octetsToProof`, `BbsService.verifyPresentation`, and `WasmBbsProvider.proofVerify`.
   - Negative tests in `BbsToCardanoTest` rejecting identity `W`, malformed `W`, and ciphersuite mismatches.
2. **Julc VM (`zeroj-onchain-julc` — `BbsProofVerifyVmTest`):**
   - Honest presentation accepted; measured ExUnits (`2,442,385,555` CPU / `207,274` mem) asserted against I5 ceilings (`<= 2.46B` CPU / `<= 215k` mem).
   - Both **all-zero** and **all-non-zero** identity-point forgery variants rejected (`< 100M` CPU).
   - Individual `Abar = O`, `Bbar = O`, `D = O` rejected.
   - Every proof scalar tested at `0`, `-1`, `s - r`, `s + r`, and `r` → rejected (`< 100M` CPU).
   - Malformed point encodings (`0xe0 || 0^47`, cleared compression bit, 47-byte, 49-byte) → rejected.
   - `W == G2_INFINITY`, `domain = r`, and `W` / `domain` mismatch → rejected.
3. **Real Cardano Node (`zeroj-integration-tests` — `BbsProofVerifyDevKitE2ETest`):**
   - On Yaci DevKit (Plutus V3): submit (1) the all-non-zero identity-point forgery, (2) a scalar-malleated (`eHat + r`) redeemer, (3) a zero-scalar (`eHat = 0`) redeemer, and (4) a tampered presentation header (against a UTxO whose datum matches the tampered header so `BbsProofVerify.verify` itself rejects it) → assert Phase-2 node rejection (`ValidationTagMismatch` / `PlutusFailure`) on all four; then submit the honest presentation → assert on-chain confirmation and log real ExUnits & fee.

## Remaining Production / Audit Gates
- External cryptographic audit of `BbsProofVerify`, `BbsHashToScalar`, and `zeroj-bbs` remains required before value-bearing / mainnet use.
- `draft-irtf-cfrg-bbs-signatures-10` is an IRTF draft, not yet a finalized RFC.

## Revision History
| Date | Status | Summary |
|---|---|---|
| 2026-11-20 | Proposed (rev 1) | Initial ADR and implementation for `BbsProofVerify`, `BbsCodec.octetsToProof`, and `BbsToCardano` hardening. |
| 2026-11-20 | Proposed (rev 2) | Addressed PR #118 review findings: changed status to `Proposed`, enforced `[1, r - 1]` in `BbsCodec.ProofParts`/`proofToOctets` and `WasmBbsProvider.proofVerify`, corrected I5 to measured +0.34% CPU / +21.6% mem with tight VM bounds, aligned DevKit E2E tampered-`ph` case, added Milestones/Consequences/Risks/Revision History, documented PR coupling to ADR-0042/ADR-0050 addenda. |
