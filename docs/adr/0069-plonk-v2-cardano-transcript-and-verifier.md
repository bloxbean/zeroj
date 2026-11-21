# ADR-0069: Future PlonK v2 Cardano Transcript, Single-Decode Verifier, and Parameter Surface

- **Status:** Proposed
- **Date:** 2026-11-21
- **Risk Classification:** R3 (Fiat-Shamir transcript, proof verification equation, on-chain Plutus V3 validator)
- **Related ADRs:** ADR-0010 (PlonK on-chain verifier), ADR-0022 (PlonK BLS12-381), ADR-0047 (snarkjs interop), ADR-0056 (Groth16 single-decode & MSM optimization), ADR-0066 (PlonK `.ptau` & `t3 = n + 6`)

---

## Context

ZeroJ's current PlonK BLS12-381 Cardano profiles (`COMPRESSED_G1` / `COMPRESSED_G1_MPI`) inherit snarkjs 0.7.6's unchained per-round Fiat-Shamir challenge derivation (including deriving `u` without chaining all prior transcript state) and decompress G1 proof/VK commitments multiple times on-chain (18 redundant decodes across verifier steps) while exposing redundant validator `@Param` values.

Separately, the current `xiMinusOmegaInv` check in the on-chain verifier excludes the degenerate evaluation point `xi == omega` (where `X - xi * omega` / `xi - omega` vanishes); any future simplification must preserve that exact exclusion or prove an equivalent guard.

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
   - Initialize a single running sponge/hash state with an explicit v2 domain separator tag (`"zeroj-plonk-bls12381-v2"`), circuit VK commitment digest (`qM, qL, qR, qO, qC, s1, s2, s3`, `power`, `k1`, `k2`, `nPublic`), and length-prefixed public inputs.
   - Absorb each round's compressed G1 commitments and evaluations in strict protocol order and chain every prior challenge into the next challenge derivation (`beta`, `gamma`, `alpha`, `zeta`, `v`, and **`u`** — never hashing standalone subsets).
2. **I2 (Single decompression per G1 point on-chain):**
   - Decompress each compressed 48-byte G1 commitment in the VK and proof **once** via CIP-0381 `bls12_381_G1_uncompress` (which enforces length, canonical encoding, curve, and subgroup) and reuse the decompressed `G1Element` handles throughout linear combination and pairing evaluation, eliminating 18 redundant decodes.
3. **I3 (Degenerate challenge exclusion):**
   - Preserve the explicit exclusion of `zeta == 0`, `zeta^n == 1` (`Z_H(zeta) == 0`), and `zeta == omega` (`xiMinusOmegaInv` check or direct equality rejection on `zeta` and `zeta * omega`), failing closed before division or inversion.
4. **I4 (Minimal, non-redundant `@Param` surface):**
   - Audit and remove redundant derived `@Param` fields (e.g. values derivable cheaply from `power`/`omega` or folded into the precomputed VK digest) while documenting exact script-hash impact and binding all VK commitments into the v2 transcript.
5. **I5 (Strict v1/v2 profile separation):**
   - Legacy snarkjs 0.7.6 v1 profiles remain unchanged for backward compatibility and cross-tool interop; v2 uses a distinct `proofFormat` identifier (`"zeroj-plonk-cardano-v2"`) so v1 and v2 proofs can never be confused.

---

## Decision & Alternatives Considered

- **Separate v2 profile vs. mutating v1 in place:** Mutating v1 would silently break snarkjs 0.7.6 interop and invalidate existing on-chain script hashes. Introducing a distinct v2 profile preserves v1 interop while allowing Cardano-native deployments to adopt strong Fiat-Shamir chaining and lower Plutus V3 CPU cost.
- **Keep `xiMinusOmegaInv` vs. removing it:** Removing the check without an equivalent `zeta != omega` guard would leave an unchecked zero denominator; v2 retains an explicit guard against `zeta in {0, 1, omega}` and `Z_H(zeta) == 0`.

---

## Implementation Milestones (Future Work)

- **M1:** Specify exact byte-level v2 transcript schedule and KAT vectors (independent reference script + pure-Java prover/verifier).
- **M2:** Implement `TranscriptEncoding.CARDANO_V2` in `PlonKProverBLS381` and `PlonkBLS12381Verifier` with negative transcript-tampering and degenerate-challenge tests.
- **M3:** Implement single-decode v2 Plutus V3 validator in `zeroj-onchain-julc`, benchmark CPU/memory reduction against v1 in Julc VM and Yaci DevKit, and audit minimal `@Param` set.
- **M4:** External cryptographic review before any non-experimental promotion.

---

## Verification & Audit Gates

- Independent Python/Rust reference transcript KATs matching Java and Plutus V3 byte-for-byte.
- Negative tests for challenge grinding, missing VK binding, `u` tampering, `zeta == 1`, `zeta == omega`, and cross-profile (`v1` vs `v2`) replay.
- Mandatory external cryptographic audit before promotion to production-safe status.
