# ADR-0064: On-Chain BBS ProofVerify Hardening and Draft-10 Scalar Bounds

## Status
Accepted — 2026-11-20. Hardens on-chain BBS presentation verification and aligns off-chain proof deserialization with CFRG BBS draft-10. Amends ADR-0019 to cover the on-chain Cardano Plutus V3 verifier (`BbsProofVerify`).

**Risk class: R3.** Changes cryptographic proof-input validation on the on-chain BBS presentation verifier (`zeroj-onchain-julc/.../bbs/lib/BbsProofVerify.java`) and aligns off-chain proof deserialization (`zeroj-bbs/.../internal/BbsCodec.java`) and parameter derivation (`BbsToCardano.java`) with `draft-irtf-cfrg-bbs-signatures-10`.

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
   - Off-chain `BbsCodec.octetsToProof` parsed proof scalars with `scalarFromBytes` (`[0, r-1]`) instead of `nonZeroScalarFromBytes` (`[1, r-1]`), diverging from draft-10 §4.2.4.5 step 14 (`if s_j = 0 or if s_j >= r, return INVALID`).
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
  - §4.2.4.5 (`octets_to_proof`): step 7 rejects `Identity_G1` on `Abar`, `Bbar`, `D`; step 14 rejects `s_j == 0` or `s_j >= r` for all serialized proof scalars (`e^`, `r1^`, `r3^`, `m^_j`, `c`); step 17 rejects trailing bytes.
- CIP-0381 (`86b89208`): Plutus V3 BLS12-381 builtins and Zcash compressed point serialization (`0xc0 || 0x00^47` for G1 identity, `0xc0 || 0x00^95` for G2 identity).
- ADR-0019 (off-chain CFRG BBS pure-Java and WASM providers) and ADR-0056 (single-decompression Plutus V3 verification discipline).
- JuLC `v0.1.0-pre22` / Cardano Client Lib `v0.8.0-pre8`.

## Decision
1. **D1 (On-chain identity-point rejection before decompression):**
   At the top of `BbsProofVerify.verify`, reject `abar`, `bbar`, or `d` unless each is 48 bytes and byte-unequal to compressed G1 identity (`0xc0 || 0x00^47`), **before** calling `bls12_381_G1_uncompress`. Also reject `w` unless it is 96 bytes and byte-unequal to compressed G2 identity (`0xc0 || 0x00^95`) as cheap defense-in-depth.
   - **No redundant re-compression round-trip:** CIP-0381 `bls12_381_G1_uncompress` / `bls12_381_G2_uncompress` (backed by `blst` in both `cardano-node` and the Julc VM) already rejects wrong lengths, cleared compression bits, non-canonical infinity encodings (`0xe0 || 0x00^47`, non-zero body), `x >= p`, off-curve points, and out-of-subgroup points, and `abar`/`bbar`/`d` raw bytes are hashed directly into the Fiat-Shamir challenge. Omitting redundant `compress(uncompress(b)) == b` keeps single-decompression ExUnits low (~2.44B CPU).
2. **D2 (Strict `[1, r-1]` proof-scalar bounds on-chain and off-chain):**
   - On-chain `BbsProofVerify.verify`: compute `r = BbsHashToScalar.scalarFieldOrder()` **once** and require `1 <= s < r` for all 7 proof scalars (`eHat`, `r1Hat`, `r3Hat`, `mHat0`, `mHat1`, `mHat2`, `c`) before any decompression or hashing. Also require `0 <= domain < r`.
   - Off-chain `BbsCodec.octetsToProof`: replace `scalarFromBytes` with `nonZeroScalarFromBytes` (`1 <= s < r`) for all proof scalars (including `c`). This automatically hardens `BbsToCardano.onChainProof` as well.
3. **D3 (Deploy-time public key & ciphersuite validation in `BbsToCardano`):**
   - `BbsToCardano.verifierParams` validates `publicKey.bytes()` via `BbsCodec.octetsToPublicKey` (96 bytes, on-curve, prime-order subgroup, non-identity) and asserts `publicKey.ciphersuite() == ciphersuite`.
   - `BbsToCardano.onChainProof` asserts `presentation.proof().ciphersuite() == ciphersuite`.

## Alternatives Considered
- **Only rejecting zero scalars (`[1, r-1]`):** Rejected — does not stop the all-non-zero identity-point forgery.
- **Adding `compress(uncompress(b)) == b` for all points:** Rejected for `BbsProofVerify` — wastes ExUnits on Plutus V3 because CIP-0381 `uncompress` already rejects non-canonical encodings (verified in VM and on-chain tests) and the raw `abar`/`bbar`/`d` bytes enter the challenge hash directly.
- **Recomputing `domain` on-chain:** Rejected — hashing all generators and header on-chain would significantly increase script size and ExUnits; baking `domain` as a deploy-time `@Param` derived by `BbsToCardano.verifierParams` is the intended Plutus V3 trade-off and is documented explicitly as a trust assumption.

## Security Invariants
- **I1:** No presentation with `Abar == O`, `Bbar == O`, or `D == O` (or non-canonical infinity) is accepted on-chain or off-chain, regardless of scalar values.
- **I2:** Every proof scalar (`eHat`, `r1Hat`, `r3Hat`, `mHat_j`, `c`) outside `[1, r-1]` (including `0`, negative values, `r`, and `s + r`) is rejected on-chain and off-chain.
- **I3:** Invalid proof scalars and identity/wrong-length proof points are rejected **before** any elliptic-curve decompression, scalar multiplication, hashing, or pairing builtin runs.
- **I4:** `BbsToCardano.verifierParams` refuses identity, off-curve, out-of-subgroup, wrong-length, or wrong-ciphersuite issuer public keys.
- **I5 (Performance):** Honest verification ExUnits remain within +1% of the pre-hardening baseline (~2.44B CPU / ~0.19M mem), comfortably inside Cardano's per-transaction budget (10B CPU / 14M mem).

## Compatibility
- **Breaking on-chain script hash:** Every validator embedding `BbsProofVerify` produces a new compiled UPLC script and script hash after this change (affecting downstream consumers such as `zeroj-usecases/reusable-kyc`). Release notes must call this out explicitly.
- **Off-chain wire format:** Unchanged for honest proofs; proofs with any zero scalar are now rejected in compliance with draft-10 §4.2.4.5.

## Verification Strategy
1. **Off-chain (`zeroj-bbs`):**
   - Full official CFRG draft-10 JSON vector suites (SHA-256 & SHAKE-256, pure-Java & blst) remain green.
   - New negative tests rejecting `0` and `>= r` in every proof-scalar slot (`eHat`, `r1Hat`, `r3Hat`, `mHat_i`, `c`) in `BbsCodec.octetsToProof` and `BbsService.verifyPresentation`.
   - New negative tests in `BbsToCardanoTest` rejecting identity `W`, malformed `W`, and ciphersuite mismatches.
2. **Julc VM (`zeroj-onchain-julc` — `BbsProofVerifyVmTest`):**
   - Honest presentation accepted; measured ExUnits logged and asserted within budget.
   - Both **all-zero** and **all-non-zero** identity-point forgery variants rejected.
   - Individual `Abar = O`, `Bbar = O`, `D = O` rejected.
   - Every proof scalar tested at `0`, `-1`, `s - r`, `s + r`, and `r` → rejected.
   - Malformed point encodings (`0xe0 || 0^47`, cleared compression bit, 47-byte, 49-byte) → rejected.
   - `W == G2_INFINITY` and `W` / `domain` mismatch → rejected.
3. **Real Cardano Node (`zeroj-integration-tests` — `BbsProofVerifyDevKitE2ETest`):**
   - On Yaci DevKit (Plutus V3): submit the all-non-zero identity-point forgery, a scalar-malleated (`eHat + r`) redeemer, and a tampered presentation header to the real node → assert Phase-2 node rejection; then submit the honest presentation → assert on-chain confirmation and log real ExUnits & fee.

## Remaining Production / Audit Gates
- External cryptographic audit of `BbsProofVerify`, `BbsHashToScalar`, and `zeroj-bbs` remains required before value-bearing / mainnet use.
- `draft-irtf-cfrg-bbs-signatures-10` is an IRTF draft, not yet a finalized RFC.
