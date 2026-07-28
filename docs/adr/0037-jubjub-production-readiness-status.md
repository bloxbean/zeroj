# ADR-0037 Addendum: Jubjub Production-Readiness Status

## Status
Informational — status report, not a decision record. Companion to
[ADR-0037](0037-jubjub-soundness-and-hardening.md).
**Partially withdrawn and amended by [ADR-0038](0038-jubjub-dsl-remediation-plan.md)** —
see the withdrawal notice below before relying on any verdict in this document.
The online/offline secret-operation roadmap is superseded by
[ADR-0039](0039-jubjub-online-and-offline-readiness.md); the current offline-only
classification remains in force until that ADR's hardened-Java gates pass.
ADR-0039 now has a locally implemented fixed-limb/hedged **candidate**, tracked in its
[implementation status](0039-jubjub-implementation-status.md). Its validated factory remains
fail-closed because external cryptographic, JVM/platform, and deployment gates are not
complete; the restriction in this addendum therefore still applies.

## Date
2026-07-25 (amended 2026-07-27 by ADR-0038 P7)

## Withdrawal notice and resolution (ADR-0038)

A later independent review found **two soundness defects and one performance regression this
document's verdicts did not account for**. All are now fixed; this table records what was
withdrawn and what closed it.

| Withdrawn claim | Why it was wrong | Status |
|---|---|---|
| ✅ verdicts covering `ZkJubjubPoint` | `fromTrustedAffine` never asserted the curve equation and `assertWellFormed()` emitted nothing — off-curve `(1,1)` was accepted | **Fixed (P2).** `witnessAffine` asserts the curve equation (5 rows); `assertWellFormed()` emits the projective invariants (13 rows), idempotently. `fromTrustedAffine` deprecated, delegating |
| ✅ verdict for the DSL comparator surface | `BitDecomposition` did not bind its issuing circuit; wire ids restart per circuit, so foreign evidence passed — reopening the `p − 1 < 1,000,000` forgery | **Fixed (P1).** Opaque per-circuit owner token, validated by all four consumers before any bit is read; `decompose` also resolves its source against this circuit's wires |
| Unconditional ✅ for off-circuit `PedersenCommitment` | Both secret scalars ran through variable-time `scalarMul` | **Hardened (P4/P7.2), restriction stands.** Both legs now use fresh 64-bit multiple-of-`l` blinding and a fixed 316-iteration schedule. Java/`BigInteger` remains variable-time — see §3.1 |
| "Two independent review passes found no HIGH or MEDIUM issue" | A third pass found two HIGH-severity defects both earlier passes missed | **Superseded.** Five further review passes ran during ADR-0038; each found real defects in the fix itself, including two wrong *rationales* |
| "Does it regress large circuits? No." | Generalised from one measured shape (CIP-1852); a high-fan-out shape showed ~72× nonzero amplification. P3's immediate-fan-out heuristic then missed a depth-9 binary tree by ~27× against its stated baseline | **Fixed (P3/P7.1).** One integer pre-pass plus one sparse emission tracks CSR, live-frontier, and a cumulative input-term copy/merge work proxy independently, entering deterministic pressure mode before fixed limits. Stable Poseidon/Jubjub rows, NNZ, and domains are pinned exactly |

The verdicts not listed above stand as written, still gated on external review (§2).

## Scope

Where the Jubjub surface stands after ADR-0037 M0–M5 and the follow-up security review.
"Jubjub" is not one component and the parts differ sharply in readiness, so this assesses
each separately rather than issuing a single verdict.

Normative scheme definition: [`docs/specs/jubjub-eddsa-v1.md`](../specs/jubjub-eddsa-v1.md).

---

## 1. Component status

| Component | Status | Basis |
|---|---|---|
| `JubjubCurve`, `JubjubPoint` (off-circuit) — algebraic/public-data use | ✅ Ready\* | Constants re-derived, not restated. The unified-addition completeness assumption (`a` square, `d` non-square) is finally asserted — ADR-0016 Risk 4 named this gate but never wrote it. Generic secret-scalar use remains subject to §3 |
| `EdDSAJubjub.verify` (off-circuit) | ✅ Ready\* | Identity-`pk` forgery closed; `sk`/`msg` ranges enforced; subgroup checks on `pk` and `R`; cofactorless |
| **`EdDSAJubjub.sign`** | ⛔ **Restricted** | **Not constant-time. See §3** |
| `PedersenCommitment` (off-circuit) — algebraic construction | ✅ Ready\* | NUMS base, cofactor-cleared, fixture-pinned. Unchanged by this work |
| **`PedersenCommitment.commit` — secret-bearing execution** | ⛔ **Restricted** | Fixed 316-iteration, multiple-of-`l`-blinded schedule; residual Java/`BigInteger` timing remains. **See §3.1** |
| `InCircuitJubjub` | ✅ Ready\* | Low-level arithmetic is sound under an explicit binding precondition: prover points enter through `witnessAffine`, or genuinely projective inputs pass `assertWellFormed`, before arithmetic. The raw public `Point` record is unchecked. The named EdDSA verifier enforces affine binding at its own signature |
| `ZkJubjubPoint` (symbolic adapter) | ✅ Ready\* | Safe by construction since ADR-0038 P2: `witnessAffine` asserts the curve equation, `assertWellFormed()` emits the projective invariants idempotently |
| `InCircuitEdDSAJubjub.verifyStrict` | ✅ Ready\* | **Self-contained** — soundness requires nothing outside the circuit |
| `InCircuitEdDSAJubjub.verifyWithRegisteredKey` | ⚠️ Conditional | Sound only if the final verifier binds `pk` to a subgroup-checked registry entry. See §4 |
| `InCircuitPedersen` | ✅ Ready\* | Proves the represented bit-vector residues; callers requiring scalar canonicality must separately establish `< l` |
| `ZkPedersen` | ✅ Ready\* | Asserts scalar canonicality `< l` through the sound comparator and reuses the owned decompositions |
| DSL comparators — `Variable` overloads (`lessThan(a, b, nBits)` and facades over it) | ✅ Ready\* | Repo-wide fix; both forgeable directions closed |
| DSL comparators — `BitDecomposition` overloads | ✅ Ready\* | Typed evidence binds its issuing circuit since ADR-0038 P1; every consumer validates provenance before reading a bit |
| Poseidon `t=6` preset | ✅ Ready\* | Generated by the pinned hadeshash Sage script, reproduced byte-for-byte by the Java LFSR, digest-pinned over all 444 values |

**\* Pending external cryptographic review**, which gates every ✅ above. See §2.

---

## 2. What gates everything: external review

No part of this surface has had an external cryptographic review. That is the ceiling on
every ✅ in the table.

This should carry real weight rather than being treated as a formality. Multiple adversarial
review rounds on this code found genuine defects, including forgeries — and notably:

- the **first proposed fix for the main forgery did not work**. The all-zero point
  `(0,0,0,0)` satisfies both the curve equation and the `T` invariant identically, so a fix
  carrying only those two conjuncts left the forgery fully intact;
- the comparator finding was **directionally wrong** in an earlier draft — it was recorded as
  affecting one direction when both are forgeable;
- two later rounds each found issues the previous round had missed.

A surface with that history is not one where "we looked hard and found nothing further" is
strong evidence of absence.

---

## 3. Hard restriction: secret-bearing off-circuit operations are not constant-time

### Where the leak is

`EdDSAJubjub.sign` has two secret-dependent paths. Both remain variable-time, although the
coarsest scalar-multiplication channels are now mitigated:

1. **Secret scalar multiplication**:
   - P4 removed the `scalar.bitLength()` loop bound, zero early return and
     Hamming-weight-dependent operation count;
   - the raw 252-iteration primitive still leaked `lowestSetBit(k)`: before the first set bit
     its accumulator stayed at the small-coordinate identity and ran measurably faster;
   - P7.2 routes secret-bearing call sites through `[k + m·l]P`, with fresh uniform 64-bit `m`
     and a fixed 316-iteration schedule. Because `l` is odd, this randomises the represented
     scalar's low 64 bits while preserving the result for the known subgroup bases;
   - `testBit` selection remains a branch, and scalar blinding is not a constant-time proof;
   - `BigInteger.mod()` performs division and `BigInteger.multiply()` switches algorithm by
     operand size, so both are variable-time regardless of the branching above.

2. **The nonce, `Poseidon(NONCE_TAG; sk, msg)`** — feeds `sk` straight through Poseidon's
   `BigInteger` field arithmetic, which is variable-time for the same reasons.

Verification is unaffected throughout: it handles only public data.

### 3.1 The same leak outside signing: `PedersenCommitment.commit`

Added by ADR-0038 P0. The original implementation called variable-length
`JubjubPoint.scalarMul` for **both** secret inputs, so this document's unconditional execution
verdict was wrong. P4 replaced that with a fixed 252-operation schedule; measurement then
showed the residual was not generic "magnitude" but the raw scalar's trailing-zero count,
because the accumulator remained the cheap identity until its first set bit.

Unlike signing, Pedersen does **not** expose the Schnorr/HNP relation, so this is not a
key-recovery claim.

**ADR-0038 P7.2 status: scalar blinding shipped, restriction stands.** Both legs now sample a
fresh 64-bit `m` and run exactly 316 additions/doublings over `k + m·l`. The commitment remains
bit-identical because `G` and `H` have order `l`. Deterministic tests cover `m = 0`, `1`, and
`2^64−1`, both bases, boundary scalars, and the mixed-order counterexample proving why this
helper must not be generalized to arbitrary points.

The mitigation randomises the known trailing-zero signal, but does not make the operation
constant-time. `BigInteger`, the branch, reductions, scalar-blinding arithmetic, JIT and GC
remain data-dependent. On the final recorded P7.2 run, raw fixed-252 medians retained a
0.808–1.093 ms trailing-zero profile while the blinded path clustered at 1.353–1.366 ms across
zero, powers of two, dense, boundary and random scalars. That is evidence that the intended
signal was blinded on that machine; a negative timing experiment is never proof of
constant-time safety.

**Do not expose secret-bearing off-circuit commitment generation to an untrusted timing
observer or a co-resident adversary.**

### Why `BigInteger` cannot be made constant-time

It is not a matter of removing branches. `BigInteger` stores values with leading zeros
trimmed, so its internal length is data-dependent; `multiply` selects between schoolbook,
Karatsuba and Toom-Cook by size; `mod` divides. Constant-time arithmetic requires a
**fixed-limb representation** with a uniform operation schedule.

### The fix, in order of increasing cost

**A useful head start already exists.** Jubjub's base field *is* the BLS12-381 scalar field,
and `zeroj-bls12381` already ships `MontFr381` — a fixed-limb (4×64) Montgomery layer whose
modulus is exactly `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
The field arithmetic does not need to be written, only reused and hardened. Note ADR-0021
§"What the review surfaced" records that its Montgomery conditional subtraction still
branches on data, so it is fixed-limb but not yet branchless.

| Step | Work | Removes |
|---|---|---|
| **1. Fixed schedule + scalar blinding (shipped)** | Fixed 316 iterations over `k + m·l`, fresh 64-bit `m`; selection remains a Java branch | Removes the loop/operation-count channel and randomises the raw trailing-zero signal; does not claim constant time |
| **2. Fixed-limb point arithmetic (candidate implemented)** | Separate mask-selected 4×64 Montgomery `Fq`/`Fr` and extended-point kernels; stable `JubjubPoint` remains unchanged | Removes `BigInteger` from candidate secret point arithmetic; external/JVM review remains |
| **3. Fixed-limb nonce (candidate implemented)** | Poseidon t=3 over the new `Fq` kernel, deterministic-v1 differential path, and externally-review-gated hedged transcript | Removes `BigInteger` from candidate secret nonce derivation; does not itself approve the custom profile |
| **4. Validation (in progress)** | Diagnostic Welch harness with a leaky negative control has run under interpreter/C1/C2 on one machine | Local evidence only; generated-code, remote, repeated-platform, and external gates remain |

### The honest caveat

Even with all four steps, **Java cannot offer a universal hard constant-time guarantee.** JIT
recompilation, GC pauses, and branch prediction operate below the source language. That does
not make a pure-Java online profile impossible: fixed-size arithmetic can remove the known
secret-dependent mechanisms and be reviewed/measured for an explicit JVM/CPU/deployment
profile. It does mean the claim must stay scoped to that profile and cannot cover a hostile
co-tenant or privileged local observer.

### Options, with a recommendation

| Option | Effort | Result |
|---|---|---|
| **A. Hardened fixed-limb pure Java** | Substantial | ADR-0039 target: online-ready for reviewed dedicated/single-tenant JVM/CPU profiles; not a universal constant-time claim |
| **B. Keep the current offline-only restriction** | None | Current posture while the hardened path is incomplete |
| **C. Complete-operation HSM/enclave** | Deployment-specific | Qualifies only if the custom nonce, Jubjub, scalar, and self-check operations all execute inside the reviewed boundary |

**Recommendation: (B) remains the release posture while (A) proceeds through ADR-0039.** The
fixed-limb implementation and hedged transcript now exist as review candidates, but the
validated factory deliberately throws until M4–M8 pass. Keep the validation harness current
and model exploitability at the distance the issuer actually runs from an attacker.
Measurement can reject an implementation; it cannot prove constant-time safety.

Until then the classification stands: **not approved for value-bearing issuance on shared or
network-reachable infrastructure.** Approved uses are local/offline signing and test issuance.

---

## 4. `verifyWithRegisteredKey` — the conditional entry point

The DSL enforces that `pk` is a public input or circuit constant, resolved by **wire ID**
rather than `Variable.name()`. That establishes the key is verifier-visible. It does **not**
establish that the key is valid.

The residual is wider than `pk` alone: because `pk` is not proven to be in the prime-order
subgroup, cofactorless verification does not force `R` into the subgroup either. Both
obligations transfer to the protocol.

Concretely, if registration skips the subgroup check, one signing key `sk'` yields **eight
distinct registry identities** (`pk' + jT`, `j = 0..7`), all of which pass the
`[8]·pk != O` backstop. Revoke one and the other seven keep working.

`verifyStrict` has none of this. It proves `[l]·pk == O` in-circuit for roughly 5,500 extra
constraints, and once `pk` is in the subgroup the verification equation forces `R` there too.

---

## 5. Safe-to-use recipe for the current preview line

- Verify in-circuit with **`verifyStrict`**. Pay the extra constraints; it removes an entire
  class of protocol obligation.
- Verify off-circuit with `EdDSAJubjub.verify` freely.
- **Sign offline only.**
- **Generate off-circuit Pedersen commitments offline only**, on the same reasoning as
  signing (§3.1). The commitments themselves, and the in-circuit Pedersen gadgets, are
  unaffected — the restriction is on secret-bearing *execution*, not on the scheme.
- Bind prover-supplied points with `ZkJubjubPoint.witnessAffine(...)` (or
  `InCircuitJubjub.witnessAffine(...)` at the gadget layer). `fromTrustedAffine` is deprecated
  and delegates there.
- A `BitDecomposition` is valid only in the circuit that minted it; passing one across
  circuits is rejected at definition time. Reuse within a circuit — via
  `ZkUInt.decomposition()` or the typed `InCircuitPedersen.commit` overload — is the supported
  way to avoid decomposing a scalar twice.
- **Prefer `sign(Keypair, msg)`.** It is the primary API and is faster than the deprecated
  `sign(sk, msg)`, which must re-derive `pk` on every call. Both perform a full
  verify-before-release check for the modeled single-computation fault class. The check is
  unconditional and there is no public unchecked signing path; its measured cost is accepted
  for the offline signer because release of a suitable deterministic-nonce fault can expose
  the key. This is detection, not general fault resistance.
- `Keypair` is now a validating final class rather than a record. Its public `(sk, pk)`
  constructor rejects an out-of-range secret or mismatched public key and recomputes the
  relation; use `keypairFromSecret` / `generateKeypair` to avoid duplicate validation work.
  The `sk()` / `pk()` accessors, value equality, and former record hash are preserved, but
  record reflection, record patterns/metadata, and assignment to `java.lang.Record` require
  migration and recompilation.
- Avoid `verifyWithRegisteredKey` unless the registry check in §4 is actually built.

---

## 6. What changed, for context

Before ADR-0037, in-circuit EdDSA verification was **forgeable**: a prover could obtain an
accepted proof for a message that was never signed, under a real issuer key, with an `R` not
on the curve. The identity public key was a universal forgery on both layers. Both defects
are published on Maven Central across nine `0.1.0-preN` versions and are publicly resolvable
by any downstream build.

After: those are closed, and the fixed verifier costs **less than the broken one did** —
8,962 constraints against 18,965. The comparator fix hardened every circuit in the
repository, not only Jubjub.

Backward compatibility is not a concern on a preview line, so no migration tooling is
required. What survives of that obligation is **disclosure**: the fix should ship as a
release whose notes name the defect, because "preview" describes our intent, not what a
downstream consumer downloaded.

---

## 7. Summary

| Question | Answer |
|---|---|
| Is verification production-ready? | Code-complete and locally green, but not production-labelled until external cryptographic review. Use `verifyStrict` |
| Is signing production-ready? | **No** — local/offline, or inside a reviewed isolated boundary that performs the complete Jubjub and Poseidon operation, until constant-time work lands. Merely storing the key in an HSM is insufficient |
| Is off-circuit Pedersen commitment *generation* production-ready? | **Not for side-channel-exposed use** — same offline restriction (§3.1). The scheme and the in-circuit gadgets are unaffected |
| Is anything still forgeable? | No known forgery remains. The two ADR-0038 defects — cross-circuit `BitDecomposition` reuse and off-curve `ZkJubjubPoint` binding — are closed by P1 and P2, each with a mutation-verified fixture suite |
| Can it be labelled "production"? | Not until an external reviewer has had a pass. ADR-0038 P0–P7 and local regression gates are green |
| Does it regress large circuits? | **Claim scoped to measured gates.** High-fan-out 500×500, both constant-mul and pure-`Add` variants: 251,000 → 2,002 nonzeros for one extra row; distributed and deep-copy fixtures trigger online pressure. Exact Poseidon/Jubjub rows, NNZ, and padded domains are unchanged. Final 40k-row repeats ranged from 0.992× to 1.038× incumbent time with 1.000× measured allocation. The opt-in 18,754,215-row CIP-1852 gate matches the incumbent row count exactly |

---

## References

- [ADR-0037](0037-jubjub-soundness-and-hardening.md) — soundness fixes and hardening plan
- [ADR-0016](0016-jubjub-in-circuit.md) — original Jubjub-in-circuit design, partially superseded
- [ADR-0021](0021-bls12381-review-and-hardening.md) — constant-time posture precedent; `MontFr381`
- [ADR-0034](0034-frontend-memory-reduction.md) — frontend compile memory floor
- [ADR-0039](0039-jubjub-online-and-offline-readiness.md) — online/offline secret-operation
  architecture and release plan
- [`docs/specs/jubjub-eddsa-v1.md`](../specs/jubjub-eddsa-v1.md) — normative scheme definition
