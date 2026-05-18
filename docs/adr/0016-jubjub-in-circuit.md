# ADR-0016: Jubjub-in-Circuit for BLS12-381 Cardano Proofs

## Status
Accepted

## Date
2026-04-18

## Context

ADR-0015 shipped standards-compatible Poseidon over the BLS12-381 scalar
field. That unlocks hash-based primitives (Merkle trees, nullifiers,
commitments from `Poseidon(secret, value)`) but leaves a gap: **no
elliptic-curve operations inside the circuit.**

ZeroJ's current circuit library offers `api.add`, `api.mul`, `api.toBinary`,
etc. — field-level arithmetic. The `Poseidon`/`PoseidonN` gadgets layer on
top of those. What's missing for the Cardano ZK roadmap:

- **Asymmetric signatures in-circuit.** Today `identity-kyc` uses
  `Poseidon(issuerSecret, claims)` — a shared-secret scheme where issuer
  and holder both know the secret. ADR-0014 flagged this as inadequate for
  W3C VC / DID / Atala PRISM interop. The fix is in-circuit EdDSA. EdDSA
  over any useful curve inside a BLS12-381 SNARK is prohibitively expensive
  unless the curve's base field *is* BLS12-381's scalar field.

- **Pedersen commitments.** Hiding + binding + homomorphic — the workhorse
  of confidential amounts, private voting tallies, and range proofs. Built
  from two EC scalar-mults plus one addition per commitment.

- **Alternative Merkle layouts.** Jubjub-Pedersen Merkle trees, hybrid
  Jubjub/Poseidon Merkle, etc.

### Why Jubjub, not BabyJubJub

BabyJubJub is the twisted-Edwards curve embedded in **BN254's** scalar
field — the Ethereum / circom-ecosystem choice. Using BabyJubJub inside a
Cardano-verifiable SNARK means either (a) proving over BN254 (no Plutus
builtin; unverifiable on Cardano) or (b) emulating BabyJubJub inside a
BLS12-381 SNARK (tens of thousands of constraints per scalar-mul).

**Jubjub** is the Zcash/zkcrypto curve whose base field *is* the BLS12-381
scalar field. A Jubjub scalar-mul inside a BLS12-381 SNARK costs roughly
one constraint per bit of the scalar — a few hundred constraints total.
That's the whole point of an "embedded curve".

The upshot: **Jubjub is Cardano-native**, BabyJubJub is not. Existing
Plutus V3 Groth16 verifiers (`zeroj-onchain-julc/Groth16BLS12381GenericVerifier`,
`PlonkBLS12381FullVerifier`) accept Jubjub proofs without modification —
all the complexity lives inside the SNARK.

### Terminology note

Early zeroj code and ADR-0014 occasionally used "BabyJubJub" loosely. For
this ADR and all subsequent work, "Jubjub" means the Zcash/zkcrypto curve
with the parameters pinned below. BabyJubJub (BN254 sibling) is not
implemented by zeroj.

### Security history

ADR-0014 notes that an earlier BabyJubJub implementation was removed from
`zeroj-circuit-lib` during a security audit. The issues found were generic
to twisted-Edwards in-circuit work and apply equally to Jubjub:

- Missing cofactor-clearing / subgroup checks → malicious points from the
  full curve group bypass verification.
- EdDSA signature malleability → multiple valid `S` exist for the same
  message (`S` and `S + l` both verify).
- Zero test coverage for edge cases.

This ADR explicitly handles all three.

## Decision

### 1. Curve parameters — pin the Zcash/zkcrypto Jubjub

Authoritative reference: <https://github.com/zkcrypto/jubjub>.

| Parameter | Value |
|---|---|
| Host field | BLS12-381 scalar field (r = 0x73eda753…00000001) |
| Curve form | Twisted Edwards: `-u² + v² = 1 + d·u²·v²` |
| a (Edwards param) | -1 |
| d | `0x2a9318e74bfa2b48 f5fd9207e6bd7fd4 292d7f6d37579d26 01065fd6d6343eb1` (little-endian limbs) |
| Base point u | `0x62edcbb8bf3787c8 8b0f03ddd60a8187 caf55d1b29bf81af e4b3d35df1a7adfe` |
| Base point v | `0x000000000000000b` (= 11) |
| Subgroup order `l` | 0x0e7db4ea6533afa906673b0101343b00 (Jubjub scalar field prime) |
| Cofactor | 8 |

Values extracted verbatim from `zkcrypto/jubjub:src/lib.rs` at HEAD. The
zeroj implementation will pin a specific commit and regenerate if upstream
releases a parameter update (none expected).

### 2. Coordinate system — extended twisted Edwards

In-circuit representation uses **affine (u, v)** coordinates (cheap for a
one-shot use but costly for multi-step chains because of the inverse in
the addition formula).

Off-circuit and in-gadget-internal representation uses **extended Edwards
coordinates (U, V, Z, T)** per Hisil–Wong–Carter–Dawson 2008:

- Point = `(U, V, Z, T)` with affine `(u, v) = (U/Z, V/Z)` and `T = U·V/Z`.
- Unified addition formula (no branching; complete for `a = -1` and
  non-square `d`, both satisfied by Jubjub).
- Doubling formula specialized for 2P.

This is the same choice zkcrypto and ark-ed-on-bls12-381 make. It
minimizes both the off-circuit CPU cost and the in-circuit constraint
count for scalar-mul.

### 3. Scalar multiplication — fixed-base via windowed table, variable-base via double-and-add

- **Fixed-base scalar-mul** (for the generator G and a handful of
  application-specific bases): precompute a 3-bit windowed lookup table,
  use conditional-add gadgets. ~255 constraints per 255-bit scalar for
  the generator alone; table is a one-time compile-time cost.

- **Variable-base scalar-mul** (arbitrary points — needed for Pedersen
  public keys and generic EC ops): double-and-add over the scalar bits.
  No windowing; ~3x more expensive than fixed-base but unavoidable for
  runtime-chosen bases.

Both use the unified addition formula; no exceptional cases in the
add-chain because `a = -1` and `d` is non-square.

### 4. Subgroup check required on every untrusted point

Jubjub has cofactor 8. An attacker-controlled point may lie outside the
prime-order subgroup, enabling invariant-subgroup attacks on EC-based
verification. Every point entering a circuit from an untrusted source
(signature R, public key, commitment) must pass an in-circuit
`isInSubgroup()` check.

Subgroup check: `[l] · P == O` where `l` is the Jubjub scalar field order.
Cost: one variable-base scalar-mul, ~800 constraints. Cached when the
point is reused within a proof.

### 5. EdDSA-Jubjub per RFC 8032 with strict encoding

- **Signature**: `(R, S)` where `R` ∈ Jubjub and `S` ∈ [0, l).
- **Verification**: `[S]·G == R + [H(R, pk, msg)]·pk`, where H is a hash
  function committed to below.
- **Hash function in-circuit**: Poseidon over the BLS12-381 scalar field
  (from ADR-0015's `PoseidonParamsBLS12_381T3`). This gives a direct
  in-circuit hash without needing SHA-512 emulation.
- **Malleability prevention**: reject `S ≥ l` (strict range check in
  circuit via `S.assertInRange(253)` plus `S < l` conditional assert).
- **Subgroup enforcement**: both `R` and `pk` must pass `isInSubgroup()`
  before entering the verification equation.

Off-circuit signing (for test-vector generation and application code) uses
the same spec; compatibility is asserted via cross-check tests.

### 6. Pedersen commitment — two-base, variable-scalar

`Commit(v, r) = [v]·G + [r]·H` where `H = hashToCurve("zeroj.pedersen.H")`
is a second base point whose discrete log w.r.t. G is unknown (binding).

`hashToCurve` procedure: Poseidon hash of the domain tag, reduced mod
the Jubjub base field, then mapped to a point via Elligator 2 (or the
simpler "try-and-increment" if performance permits, since this runs
once at library init).

### 7. Optional — Jubjub-Merkle (M4 nice-to-have)

For most applications Poseidon-Merkle is better (smaller circuits,
simpler cost model). Jubjub-Merkle makes sense only when the parent hash
needs homomorphic properties (e.g. proof-of-solvency Merkle sum trees
where a parent holds the Pedersen-committed sum of children). Scope is
narrow; implemented as an opt-in gadget in M4.

### 8. BLS12-381 Poseidon `t=5` preset

ADR-0015 deferred `BLS12_381_T5` to this ADR. M4 adds it via the existing
`PoseidonParamsCodegen` path (`Preset("PoseidonParamsBLS12_381T5", ..., t=5, rf=8, rp=60)`).
Used by Jubjub-Pedersen hashing that consumes `(x, y, cofactor_cleared,
domain_tag, ...)` tuples in a single compression.

## Milestones

| # | Scope | Tests / oracles | Est. effort |
|---|---|---|---|
| **M1** | Off-circuit `JubjubPoint` (extended coords), add/double/negate, scalar-mul, subgroup check, (de)compression | zkcrypto/jubjub test vectors | 3 days |
| **M2** | In-circuit point add + fixed-base scalar-mul gadget | Self-consistency vs M1 over 100+ random scalars | 4 days |
| **M3** | Variable-base scalar-mul gadget | Same | 3 days |
| **M4** | Pedersen commitment + `BLS12_381_T5` preset; optional Jubjub-Merkle | Cross-check Pedersen `Commit(v, r)` against off-circuit impl | 2 days |
| **M5** | EdDSA-Jubjub off-circuit sign/verify + in-circuit verify | zkcrypto/jubjub / zcash sapling test vectors; edge cases (S = l-1, R not in subgroup, signature malleability) | 1 week |
| **M6** | Consolidated cross-verification suite | External vectors + Sage-reference-Docker golden file (same pattern as ADR-0015) | 2 days |

Usecase integration (identity-kyc EdDSA migration) happens after M5, with
end-to-end verification on yaci-devkit as a merge gate.

## Consequences

### Easier

- W3C VC / DID / Atala PRISM interop paths open (issuer-signed credentials
  become in-circuit verifiable).
- Pedersen-backed confidential amounts enable private voting, confidential
  proof-of-reserves, sealed-bid auctions, privacy-preserving loyalty.
- Schnorr / EdDSA wallet-signature-in-circuit enables provable Cardano-
  wallet-ownership gated features.
- **No onchain changes**: existing `Groth16BLS12381GenericVerifier` and
  `PlonkBLS12381FullVerifier` accept Jubjub-using proofs as-is.

### Harder

- Circuit compile times grow (each EdDSA verify adds ~3000 constraints).
  Mitigations: gadget caches, parallel provers already shipped.
- Larger test surface; cross-verification against an external ecosystem
  (zcash/zkcrypto) is a hard requirement.

### Neutral

- No new BLS12-381 onchain primitives needed.
- No backward-compatibility breaks to Poseidon callers; Jubjub is purely
  additive.

## Risks

1. **Subgroup-check omission** in application code. If a caller forgets
   to call `isInSubgroup()` on an incoming signature's `R` or public key,
   malicious small-subgroup points can forge verifications.
   Mitigation: the high-level `EdDSAJubjub.verify(api, sig, pk, msg)`
   gadget *always* performs subgroup checks internally. Low-level point
   ops are clearly documented as "no subgroup check — caller's
   responsibility".

2. **Encoding / endianness bugs** in off-circuit / in-circuit interop.
   Jubjub points have a canonical compressed form (32 bytes, v-coord LSB
   bit indicates sign). Any mismatch breaks cross-checks.
   Mitigation: test vectors from zkcrypto/jubjub (`test_to_from_bytes`
   vectors) are asserted byte-for-byte; a Sage reference computes the
   same encoding.

3. **EdDSA non-canonical S** — the classic malleability. Accept `S < l`
   strictly; reject `S ≥ l` or the `S + l` "alternate signature".
   Mitigation: `SignalBinary.assertInRange(253)` + `l.assertLessThan(S)`
   both enforced in-circuit.

4. **Unified-addition completeness assumption**. The unified formula is
   complete for twisted-Edwards iff `a` is a square and `d` is non-square.
   Jubjub satisfies this (`a = -1` is square in BLS12-381 scalar field;
   `d` is non-square per the Zcash parameter verification).
   Mitigation: `JubjubCurveTest.assertParameterSquareness` test pins the
   assumption; regenerating from the upstream curve parameters would
   surface any future divergence.

5. **Performance: in-circuit EdDSA is ~3000 constraints per verify**. For
   a batch verifier (aggregating k signatures), consider batched scalar-mul
   tricks. Scope: out of this ADR; revisit if usecase proof times become
   problematic.

6. **No Cardano onchain Jubjub**. All Jubjub operations live inside the
   SNARK. Any Plutus script that wants to *directly* compute a Jubjub
   point op would have to emulate it in BigInteger arithmetic (impractical
   for non-trivial ops). Mitigation: this is the same situation as any
   non-builtin curve; the ADR's design explicitly assumes Jubjub stays
   in-SNARK.

## Open questions (resolved)

- **Subgroup check cost**: in-circuit `[l]·P` ~800 constraints per check.
  Acceptable.
- **M5 scope**: include EdDSA verify gadget in the primary ADR scope, not
  defer. User explicitly authorized full scope.
- **Use case migration target**: `identity-kyc` — direct fit with ADR-0014
  motivation.

## Implementation plan

Sequenced per milestone above. After each milestone, **four-agent review**
(ADR conformance + crypto correctness + Java quality + Codex second
opinion) before moving on, matching the ADR-0015 pattern. Fixes applied
before the next milestone starts.

Final phase: migrate `identity-kyc` usecase to EdDSA-Jubjub-signed
credentials. End-to-end verification on yaci-devkit as merge gate.
Comprehensive tutorial / user documentation ensures the API is
approachable by new developers.

## References

- zkcrypto/jubjub — <https://github.com/zkcrypto/jubjub>
- Zcash Sapling spec — <https://zips.z.cash/protocol/sapling.pdf> §5.4.8
- Hisil, Wong, Carter, Dawson — *Twisted Edwards Curves Revisited*, 2008
- RFC 8032 — *Edwards-Curve Digital Signature Algorithm (EdDSA)*
- Poseidon paper + hadeshash — pinned in ADR-0015
- ADR-0014 — W3C Verifiable Credential Support (motivation for EdDSA)
- ADR-0015 — Standards-compatible Poseidon for BLS12-381 (prerequisite)
