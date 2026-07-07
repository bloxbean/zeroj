# ADR-0028 Phase C — Implementation Spec: General Hints + CRT Non-Native Multiplication

**Status: QUEUED — spec ready, gated on the soundness tests + external audit (ADR-0028 pillars 2, 4, 5).**
This is the concrete, implementation-ready plan for the high-risk / highest-payoff phase. It is
deliberately **not implemented yet**: Phase C introduces a genuinely new *forgeable-proof*
soundness surface, so no code lands on a branch that merges to anything with value until the
under-constraint negative tests and an external circuit audit clear it.

## Goal

Collapse `Fe25519` multiplication from **8,051 constraints** to a **few hundred** by having the
prover *supply* the quotient/remainder of the modular reduction (advice) instead of computing it
deterministically via limb carry-propagation. This is the single biggest remaining lever: with
Phase A (~4×) + B (~1.45×) the Ed25519 scalar mult is ~4.7M; Phase C targets the ~9 muls per
point-add directly and brings the full CIP-1852 derivation toward the ~6.5M circom/gnark band —
the point at which an at-scale on-chain proof (with the M7 blst MSM prover) becomes feasible.

## Step 1 — General hint mechanism (safe infrastructure)

The DSL already has `Gate.Hint(output, HintType{INVERSE,IS_ZERO_*}, input)` computed by
`WitnessCalculator`. Extend it to a multi-input/multi-output, **enumerated, trusted-core** hint —
*not* arbitrary per-gadget lambdas (keeps witness logic centralized and reviewed once):

```
record HintN(Variable[] outputs, HintKind kind, Variable[] inputs) implements Gate {}
enum HintKind { NONNATIVE_MUL_REDUCE /* , future: NONNATIVE_INV, ... */ }
```

`WitnessCalculator` computes `NONNATIVE_MUL_REDUCE` in the trusted core: given the 5+5 operand
limbs and the modulus `p`, compute the full integer product, then `q = prod / p`, `r = prod % p`,
and emit `q`'s and `r`'s limbs. **This step is not a soundness risk** — a hint only *provides
candidate witness values*; soundness is enforced entirely by the constraints Step 2 adds. Ship it
with a test that the hint computes correct `q, r` for random inputs (a witness-computation check,
not a soundness claim).

## Step 2 — CRT-based `mulHint` (the audit-critical part)

`a * b mod p` with `a, b` in 5×51-bit limbs:

1. **Hint**: prover supplies `r` (5 limbs, the remainder) and `q` (≈5 limbs, the quotient), with
   `a·b = q·p + r`.
2. **Range-check** every limb of `r` and `q` to 51 bits (`toBinary`); additionally constrain
   `r < p` (canonical, via the existing conditional-subtract trick) so `r` is the unique remainder.
3. **Enforce the identity `a·b − q·p − r = 0` OVER THE INTEGERS** — the #1 audit item. Compute the
   limb-wise products of both sides (`a·b` and `q·p`) into wide columns, subtract, and verify the
   result is zero by a **carry-chain that pins each limb difference to 0 with range-bounded
   carries**. It must **NOT** be checked as `≡ 0 (mod native field)` — that lets a malicious prover
   forge by adding a multiple of the native modulus. Two accepted formulations, pick one and prove
   it on paper in the gadget javadoc:
   - **CRT / multi-modulus**: check the identity mod several coprime small moduli whose product
     exceeds the max integer magnitude of `a·b` (≈2^510), so equality mod each ⟹ integer equality.
   - **Limb-carry** (gnark-style): evaluate `a·b − q·p − r` column by column, propagate a signed
     carry, and assert every column residue is 0 and the final carry is 0, with each carry
     range-checked so no wrap hides a nonzero difference.
4. Result `r` is the normalized product (overflow 0), feeding the rest of the field API unchanged.

The eager/lazy `mul` from Phase B stays as the **frozen deterministic reference**; `mulHint` must
be bit-identical to it (and to `BigInteger`) on every input.

## Step 3 — Mandatory soundness tests (ADR-0028 pillar 2) — release blockers

These probe *forgeability*, not just correctness. Any accepted mutation blocks the release:

1. **Hint-mutation rejection**: for random `(a,b)`, compute the honest `(q,r)`, then for each limb
   inject `+1`, `−1`, `+p_native`, `+2^51`, and a random delta, and assert the constraint system
   **rejects** every mutated witness. Automate over the full limb set.
2. **Wrong-remainder / non-canonical `r`**: supply `r' = r + p` (same residue mod p, but `r' ≥ p`)
   and assert rejection (proves the `r < p` constraint bites).
3. **Native-modulus forgery**: attempt the classic attack — supply `(q', r')` that satisfy
   `a·b − q'·p − r' ≡ 0 (mod native field)` but not over the integers — and assert rejection.
   This is the direct test of the integer-identity discipline (Step 2.3).
4. **Differential**: `mulHint(a,b).canonical() == mul(a,b).canonical() == (a·b mod p)` over a large
   random + edge set, on BN254 and BLS12-381.

Because the DSL has no advice-forgery at the witness layer (the honest witness calculator always
computes correct `q,r`), these tests must **inject wrong witnesses directly** (build the witness
map by hand with tampered `q,r` values) — the harness needs a path to supply raw hint witness
values, mirroring the wire-readback pattern already used in `Bip32Ed25519Test`.

## Step 4 — Audit + provability gate (ADR-0028 pillar 5)

- External circuit audit of the integer-identity argument and the range-check completeness.
- Re-validate the full CIP-1852 derivation (vs cardano-client) with `mulHint`.
- Produce a **real Groth16 proof** (not just a witness) at the reduced circuit size, closing the
  loop M7 opened — the deliverable that proves the derivation is finally provable at scale.

## Step 5 — Phase D wiring

Switch `Fe25519.mul`/`Ed25519Point`/`Cip1852Derivation` to `mulHint`, measure end-to-end, and
report the final constraint count for the full derivation circuit.

## Risk & why it is gated

A subtly wrong integer-identity check (Step 2.3) can pass every honest-input differential test and
still be forgeable. Steps 3 and 4 exist precisely to catch that, and no value depends on `mulHint`
until they pass. Until then, the deterministic Phase-A/B path remains the default.
