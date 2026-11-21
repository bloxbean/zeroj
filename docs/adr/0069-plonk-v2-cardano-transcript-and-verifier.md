# ADR-0069: Future PlonK v2 Cardano Transcript, Single-Decode Verifier, and Parameter Surface

- **Status:** Proposed
- **Date:** 2026-11-21
- **Risk Classification:** R3 (Fiat-Shamir transcript, proof verification equation, on-chain Plutus V3 validator)
- **Related ADRs:** ADR-0010 (PlonK on-chain verifier), ADR-0022 (PlonK BLS12-381), ADR-0047 (snarkjs interop), ADR-0056 (Groth16 single-decode & MSM optimization), ADR-0066 (PlonK `.ptau` & `t3 = n + 6`)

---

## Context

ZeroJ's current PlonK BLS12-381 Cardano profiles (`COMPRESSED_G1` / `COMPRESSED_G1_MPI`) follow snarkjs 0.7.6's Fiat-Shamir challenge derivation, which binds the VK and public inputs into `beta` and chains `gamma`, `alpha`, `zeta`, and `v` through the preceding challenge, but derives the multipoint opening challenge `u` solely from `(Wxi, Wxiw)` without chaining the prior transcript state (`plonk_verify.js:267-270`). On-chain, `PlonkBLS12381Lib` also calls `bls12_381_G1_uncompress` 19 times across its verifier helpers (decompressing the proof and VK G1 commitments repeatedly instead of once per point) and exposes redundant validator `@Param` values.

Separately, the current `xiMinusOmegaInv` check in the v1 on-chain verifier (`PlonkBLS12381Lib`) excludes `zeta == omega` (where `zeta - omega == 0`), alongside `zeta != 1` and the public-input positions checked via supplied inverses, whereas the off-chain `PlonkBLS12381Verifier` checks `Z_H(zeta) = zeta^n - 1 != 0` directly (which implies `zeta != 1` and `zeta != omega` because `omega^n == 1`). Unifying the on-chain check onto `Z_H(zeta) != 0` and eliminating redundant decompressions is batched into the versioned v2 profile rather than mutating v1 in place, to avoid an unversioned v1 Plutus V3 script-hash change.

Because changing the Fiat-Shamir transcript or `@Param` layout breaks interoperability with existing snarkjs 0.7.6 PlonK proofs and changes on-chain Plutus V3 script hashes, these improvements MUST be introduced as a versioned **v2 Cardano PlonK profile** while keeping the existing snarkjs-compatible v1 profile intact.

---

## Threat Model & Trust Assumptions

- **Adversarial prover:** Attempts to grind Fiat-Shamir challenges independently across rounds, exploit unchained transcript state (weak Fiat-Shamir / frozen-heart style attacks), substitute a proof across circuits/profiles/public-input arities, or exploit degenerate evaluation points (`xi in {0, 1, omega}` or `Z_H(xi) == 0`).
- **On-chain resource attacker:** Submits proofs sized to approach Plutus V3 CPU/memory execution budgets; eliminating redundant G1 decompressions directly increases safety margin under Cardano mainnet transaction budgets.
- **Trust assumptions:** Domain-separated Keccak-256 / Blake2b-256 (selected explicitly in the v2 wire profile) is modeled as a random oracle; the CRS (`tau*G1`, `tau*G2`) originates from an independently audited Powers of Tau ceremony.

---

## Normative References

- Gabizon, Williamson & Ciobotaru, *"PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge"*, IACR ePrint 2019/953.
- Dao, Miller, Wright & Grubbs, *"Weak Fiat-Shamir Attacks on Modern Proof Systems"*, IEEE S&P 2023 (IACR ePrint 2023/691) — motivating full transcript chaining across every round including `u` and VK/public-input binding.
- CIP-0381 (Plutus V3 BLS12-381 primitives).
- ZeroJ ADR-0056 (single G1 decompression before arithmetic in Plutus V3 validators).

---

## Proposed Security Invariants (v2 Profile)

1. **I1 (Fully chained, domain-separated Fiat-Shamir transcript):**
   - Initialize a single running sponge/hash state with an explicit v2 domain separator tag (`"zeroj-plonk-bls12381-v2"`), circuit VK commitment digest (`qM, qL, qR, qO, qC, s1, s2, s3`, canonical 96-byte compressed G2 opening key `X2 = tau * G2`, `power`, `k1`, `k2`, `nPublic`), and length-prefixed public inputs.
   - Absorb each round's compressed G1 commitments and evaluations in strict protocol order and chain every prior challenge into the next challenge derivation (`beta`, `gamma`, `alpha`, `zeta`, `v`, and **`u`** — never hashing standalone subsets).
2. **I2 (Single decompression per G1 point on-chain):**
   - Decompress each compressed 48-byte G1 commitment in the VK and proof **once** via CIP-0381 `bls12_381_G1_uncompress` (which enforces length, canonical encoding, curve, and subgroup) and reuse the decompressed `G1Element` handles throughout linear combination and pairing evaluation, eliminating repeated G1 decompressions across the 19 current call sites in `PlonkBLS12381Lib`.
3. **I3 (Degenerate challenge exclusion):**
   - Preserve the explicit fail-closed exclusion of `zeta == 0`, `zeta^n == 1` (`Z_H(zeta) == 0`), and `zeta == omega` (`zeta - omega == 0`) before any division or inversion. Because `omega` is a primitive `n`-th root of unity (`omega^n == 1`), rejecting `Z_H(zeta) == 0` subsumes `zeta == 1`, `zeta == omega`, and every other domain point `omega^i` (closing the v1 off-chain vs. on-chain gap where `PlonkBLS12381Verifier` checks `Z_H(zeta) != 0` while v1 `PlonkBLS12381Lib` checks only `zeta != 1`, `zeta != omega`, and public-input positions via inverses).
4. **I4 (Minimal, non-redundant `@Param` surface):**
   - Audit and remove redundant derived `@Param` fields (e.g. values derivable cheaply from `power`/`omega` or folded into the precomputed VK digest) while documenting exact script-hash impact and binding all VK commitments (including `X2`) into the v2 transcript.
5. **I5 (Strict v1/v2 profile separation):**
   - Legacy snarkjs 0.7.6 v1 profiles remain unchanged for backward compatibility and cross-tool interop; v2 uses a distinct `proofFormat` identifier (`"zeroj-plonk-cardano-v2"`) so v1 and v2 proofs can never be confused.

---

## Decision & Alternatives Considered

- **Separate v2 profile vs. mutating v1 in place:** Mutating v1 would silently break snarkjs 0.7.6 interop and invalidate existing on-chain script hashes. Introducing a distinct v2 profile preserves v1 interop while allowing Cardano-native deployments to adopt strong Fiat-Shamir chaining and lower Plutus V3 CPU cost.
- **Keep `xiMinusOmegaInv` vs. replacing with `Z_H(zeta) != 0`:** Removing `xiMinusOmegaInv` without an equivalent `zeta != omega` guard would leave an unchecked zero denominator; v2 explicitly enforces `zeta != 0` and `Z_H(zeta) != 0` (which implies `zeta != omega` and rejects every domain root).

---

## Implementation Milestones (Future Work)

- **M1:** Specify exact byte-level v2 transcript schedule and independent KAT vectors (reference script + pure-Java prover/verifier), including VK-binding vectors (covering `X2`) and challenge-boundary vectors (`zeta in {0, 1, omega}` and `Z_H(zeta) == 0`).
- **M2:** Implement `TranscriptEncoding.CARDANO_V2` in `PlonKProverBLS381` and `PlonkBLS12381Verifier` with negative transcript-tampering and degenerate-challenge tests.
- **M3:** Implement single-decode v2 Plutus V3 validator in `zeroj-onchain-julc`, benchmark CPU/memory reduction against v1 in Julc VM and Yaci DevKit, and audit minimal `@Param` set.
- **M4:** External cryptographic review before any non-experimental promotion.

---

## Verification & Audit Gates

- Independent Python/Rust reference transcript KATs matching Java and Plutus V3 byte-for-byte.
- Negative tests for challenge grinding, missing VK or `X2` binding, `u` tampering, `zeta in {0, 1, omega}`, `Z_H(zeta) == 0`, and cross-profile (`v1` vs `v2`) replay.
- Mandatory external cryptographic audit before promotion to production-safe status.
