# ADR-0028: Circuit-DSL Optimization — Fixed-Base Windowing, Lazy Reduction, and a Hint-Soundness Contract

## Status
Proposed — Phase A (windowing) **done and validated** (~4× on Ed25519 scalar mult); Phases B/C planned.

## Date
2026-07-07

## Context

ADR-0027 delivered correct-first in-circuit gadgets (SHA-512, HMAC, Blake2b, `GF(2^255-19)`,
Ed25519, and the composed CIP-1852 derivation). Every gadget is validated at the **witness**
level against authoritative oracles (JCA, cardano-client-lib, BouncyCastle, `BigInteger`), and
the full `m/1852'/1815'/0'/0/0` derivation reproduces the exact Cardano payment key hash.

The remaining gap is **performance, not correctness**: the derivation circuit is ~90M constraints
(measured: `Fe25519` mul = 8,051; Ed25519 point-add = 115,468; one 255-bit scalar mult ≈ 29M ×3
scalar mults). That is ~13–15× larger than an equivalent circom/gnark implementation (~6.5M) and,
per ADR-0027 §6.1/M7, well past the comfortably-provable band. Three sources account for almost
all of the gap:

1. **No prover advice (hints).** ZeroJ's `Fe25519` reduces every product deterministically by
   in-circuit limb carry-propagation because the DSL has no general advice mechanism. circom/gnark
   instead have the prover *supply* the quotient/remainder and check a single integer identity —
   an order of magnitude cheaper.
2. **No lazy reduction.** ZeroJ fully canonicalizes after *every* add/sub/mul; fast libraries keep
   values loosely reduced and normalize only when necessary.
3. **No fixed-base windowing.** Both ZeroJ and the reference circom do ~255 conditional adds per
   scalar mult; a *w*-bit window cuts that to ~⌈255/*w*⌉.

**Key enabling facts.** (a) The DSL **already has a hint mechanism** — `Gate.Hint(output, HintType,
input)` with a `HintType` enum (INVERSE, IS_ZERO) plus `Gate.BitDecompose`, computed by the
`WitnessCalculator`. Optimization #1 is therefore an *extension of a reviewed pattern*, not a
greenfield feature. (b) ADR-0027's deterministic `Fe25519`/`Ed25519Point`/derivation gadgets,
validated against external oracles, are a **golden reference** most projects building hint-based
non-native arithmetic do not have.

## Decision

Optimize the DSL in three phases, **safest-first**, under a single overriding **hint-soundness
contract** and verification framework. The framework — not the optimizations — is what makes this
safe; it is normative for every optimized gadget.

### The verification framework (normative)

1. **Golden-reference differential testing.** The ADR-0027 deterministic gadgets are retained
   **permanently** as a reference mode and are never deleted. Every optimized gadget must produce
   **bit-identical** results to its deterministic twin across a large random + adversarial input
   set, and both must agree with the external oracle (BouncyCastle / cardano-client / `BigInteger`).

2. **Soundness (under-constraint) negative tests — mandatory for any hinted gadget.** A hint value
   is *unconstrained by the witness calculator*; soundness comes **only** from the constraints the
   gadget adds. Therefore each hinted gadget ships a test that **mutates every hint output**
   (±1, and + the native modulus) and asserts the constraint system **rejects** the tampered
   witness. An accepted mutation = an under-constrained, forgeable gadget = a release blocker.

3. **Magnitude-bound tracking for lazy reduction.** Each `Fe25519` carries an explicit bound on how
   far its limbs are from reduced. Every operation updates the bound; any operation that would
   exceed the field or a `toBinary` width **forces a reduction first**, and a bound violation is a
   loud assertion — never a silent wraparound.

4. **The integer-identity discipline (the #1 audit item).** Hint-based `a·b mod p` must check the
   identity `a·b − q·p − r = 0` **over the integers** (limb-wise, with range-bounded carries), *not*
   `≡ 0 (mod native field)`. Checking mod the native field lets a malicious prover forge by adding a
   multiple of the native modulus. This check gets a written correctness argument in the gadget.

5. **Independent audit + provability gate.** No optimized gadget backs real value until an external
   circuit audit signs off. Each optimized derivation must additionally be shown to produce a real
   Groth16 proof (not merely a witness) at its reduced size, closing the loop ADR-0027 M7 opened.

### Phase A — Fixed-base windowing (low risk) — *this phase*

Add `Ed25519Point.scalarMulFixedBaseBWindowed(api, scalarBits, w)`: process *w* bits per step
against per-window precomputed tables `table_j[k] = (k · 2^{w·j}) · B` (compile-time constants from
the trusted `Ed25519Host`), selecting the window multiple with a binary MUX tree and performing one
point-add per window. ~⌈255/w⌉ adds instead of 255. No new trust surface — the base point is a
compile-time constant, tables are computed off-circuit, and the result is diff-tested against the
non-windowed `scalarMulFixedBaseB` and BouncyCastle. Keep the bit-by-bit method as the reference.

### Phase B — Lazy reduction (medium risk)

Give `Fe25519` an explicit magnitude bound; skip full canonicalization after add/sub and defer
reduction until an operation requires it (framework pillar 3). Diff-tested vs the deterministic
`Fe25519`. Danger is silent overflow → converted to a loud assertion by the bound tracking.

### Phase C — General hints → CRT non-native reduction (high risk, highest payoff)

Extend `Gate.Hint` to enumerated, **trusted-core** multi-input/multi-output hints (not arbitrary
per-gadget lambdas), and implement CRT-based `Fe25519` multiplication: the prover supplies `q, r`;
the circuit enforces the integer identity (pillar 4) + range checks. Field mul ~8k → a few hundred
constraints. Gated on the soundness negative tests (pillar 2), the integer-identity argument
(pillar 4), and the external audit (pillar 5).

## Milestones

| # | Scope | Validation | Status |
|---|-------|-----------|--------|
| **A** | Fixed-base windowing for Ed25519 scalar mult | ✅ **DONE** — `Ed25519Point.scalarMulFixedBaseBWindowed` + `Ed25519WindowedTest`; result **bit-identical** to the deterministic `scalarMulFixedBaseB` and to BouncyCastle over edge + random scalars, w∈{1,2,3,4,5}, on BN254 & BLS12-381. **Measured (32-bit): w=4 → 3.97×, w=5 → 4.51×** fewer constraints (⇒ 255-bit scalar mult ~29M → ~7M at w=4). | **DONE** |
| **B** | `Fe25519` magnitude bounds + lazy reduction | ✅ **DONE** — `Fe25519` overflow tracking + `addLazy`/`subLazy` + loose-operand `mul` (reduced path bit-identical, still 8,051); `Ed25519Point.add` switched to lazy. `Fe25519LazyTest` validates vs `BigInteger` incl. high-overflow chains past the mul reduce-backstop and canonical on overflow-9 accumulators; Ed25519 point-add vs BouncyCastle and the full ~90M CIP-1852 derivation vs cardano-client still exact. **point-add 107k → 73,859 (~1.45×)**; combined A+B: 255-bit scalar mult ~29M → ~4.7M. | **DONE** |
| **C** | General trusted hints + CRT non-native mul | soundness negative tests (mutate hints → reject) + integer-identity argument + audit | planned |
| **D** | Switch the derivation circuit to the optimized gadgets; re-validate vs cardano-client; measure end-to-end reduction; provability check | full-path pkh unchanged; real Groth16 proof at reduced size | planned |

Per-milestone branch → the `feat/adr_0028_dsl_optimizations` integration branch, with a review per
milestone (matching the ADR-0015/0016/0027 pattern). Phase C does not merge to anything with value
until the audit gate clears.

## Consequences

### Easier
- The Ed25519 scalar mult (and thus the derivation circuit) shrinks toward circom/gnark territory
  (~6.5M), making an at-scale on-chain proof feasible once combined with the blst MSM prover (M7).
- The general hint mechanism unlocks cheaper non-native arithmetic for **secp256k1** (Bitcoin/
  Ethereum) and any future foreign-field gadget.

### Harder
- Hints add a genuinely new **soundness surface**: a subtly wrong constraint design can pass every
  differential test on honest inputs yet remain forgeable. This is why Phase C is audit-gated and
  sequenced last.
- Two implementations of each core gadget (deterministic reference + optimized) must be maintained
  and kept in lockstep by the differential tests.

### Neutral
- Existing gadgets are unaffected (optimizations are opt-in per gadget); the deterministic path
  remains the default until each optimized gadget clears its gate.

## Risks

1. **Under-constrained hints → forgeable proofs.** *Mitigation:* framework pillars 2 + 4; the
   deterministic reference; external audit before value.
2. **Silent overflow from lazy reduction.** *Mitigation:* explicit magnitude bounds with loud
   assertions (pillar 3); overflow-boundary tests.
3. **Windowing table / MUX bugs.** *Mitigation:* low risk (constants + algebra); diff vs
   non-windowed + BouncyCastle over many scalars, including edge scalars (0, 1, 2^k, order-1).
4. **Reference drift.** If the deterministic gadget is ever "optimized in place," the oracle is
   lost. *Mitigation:* the reference gadgets are frozen and covered by their own oracle tests.

## References

- ADR-0027 — the correct-first gadgets this optimizes (and their oracle tests, now the reference).
- ADR-0010 — the Java Circuit DSL (gate model, existing `Hint`/`BitDecompose`).
- gnark `emulated` field / circom bigint — prior art for hint-based non-native reduction and the
  integer-identity discipline.
- RFC 8032 / zkcrypto — Ed25519 fixed-base windowing references.
