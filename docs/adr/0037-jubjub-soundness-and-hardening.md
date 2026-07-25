# ADR-0037: Jubjub Soundness Fixes and Production-Readiness Hardening

## Status
Accepted — M0–M5 implemented 2026-07-25.

### Implementation outcome

All six milestones landed. What changed against the plan, and the final measurements:

**Decision 5 was implemented in full rather than in the sanctioned interim.** The plan
allowed shipping domain separation as an extra folded `t=3` permutation (+828) and deferring
`t=6` to M5. Measurement made that unnecessary: a tagged `t=6` challenge costs *less* than the
previous untagged four-fold `t=3` chain, so the interim would have invalidated signatures
twice for no benefit. `t=6` shipped in M3.

**Decision 7's `t=6` saving estimate rested on an assumption the compiler did not meet.** The
predicted `~−2,500` per verify assumed constant multiplications were free. They were not: the
R1CS compiler emitted a constraint for each, so a Poseidon MDS step cost `t²` constraints per
round. M5 item 2 fixed that in the compiler, which is where most of the performance gain
actually came from — Poseidon `t=3` fell from 828 to 240 constraints, benefiting every gadget
in the repository, not just Jubjub.

**Final measured constraint counts** (original → final):

| Gadget | Before | After |
|---|---:|---:|
| `add` / `doubled` | 10 / 10 | 8 / 8 |
| `witnessAffine` (new) | — | 5 |
| `assertWellFormed` (new) | — | 13 |
| fixed-base scalar-mul, 252-bit | 6,049 | **1,506** |
| variable-base scalar-mul, 252-bit | 8,559 | 5,533 |
| Pedersen commit, 252-bit | 12,108 | **3,020** |
| Poseidon `t=3`, 2-input | 828 | **240** |
| EdDSA challenge (5-input, tagged) | 3,312 untagged | **321** |
| `verifyWithRegisteredKey` | 19,000 | **8,962** |
| `verifyStrict` | 27,569 | **14,500** |

For scale: the original **forgeable** verifier cost 18,965. The fixed one — affine-bound,
canonically reduced, domain-separated, small-order-safe — is 8,962 with a registered key.

The Decision 7 targets were `verifyWithRegisteredKey ≤ ~8k` and `verifyStrict ≤ ~14k`. Both
are missed, by 12% and 4%. The remaining cost is dominated by the variable-base multiplication
for `[k]·pk`, which the windowed multilinear-selector trick does not help because its table is
not constant. Recorded as missed rather than rounded to "met".

**Still open before production use**, unchanged from the original assessment: the public-key
binding model wired into a consuming protocol and verified end to end, a migration path for
artifacts invalidated by Decisions 2 and 5, a constant-time signing path or acceptance of the
Decision 8 restriction, and an external cryptographic review.

The original plan follows unchanged below.

## Date
2026-07-25

## Context

ADR-0016 shipped Jubjub-in-circuit for BLS12-381 proofs: off-circuit curve arithmetic
(`JubjubCurve`, `JubjubPoint`), an EdDSA-over-Jubjub scheme with a Poseidon challenge
(`EdDSAJubjub`), Pedersen commitments (`PedersenCommitment`), the in-circuit gadgets
(`InCircuitJubjub`, `InCircuitEdDSAJubjub`, `InCircuitPedersen`), and the annotation-layer
adapters (`ZkJubjubPoint`, `ZkPedersen`, `ZkEdDSAJubjub`). The whole feature landed in a
single commit (`8b535d5`) rather than through the per-milestone review gates ADR-0016's
implementation plan called for.

We performed a correctness/security/performance review of that surface ahead of using it
for value-bearing applications: manual read of all sources and tests, numeric re-derivation
of every curve constant, compilation of each gadget to count real R1CS constraints, and
executable proofs-of-concept for the suspected soundness gaps. Every "confirmed" and
"measured" statement below was produced by running code, not by inspection.

### What the review confirmed (no action beyond locking it in)

- **Constants are exact.** `p` (BLS12-381 `Fr`) and `l` are prime; `d == -10240/10241 mod p`;
  cofactor 8; `FULL_GENERATOR` is on the curve; `[8]·FULL_GENERATOR == SUBGROUP_GENERATOR`;
  `[l]·SUBGROUP_GENERATOR == O` while `[l]·FULL_GENERATOR != O`.
- **The completeness precondition actually holds.** `a = -1` is a quadratic residue and `d`
  is a non-residue in `Fq`, so the unified HWCD §3.2 addition formula has no exceptional
  inputs on this curve. ADR-0016 Risk 4 asserted this; the review verified it.
- **Formulas are transcribed correctly.** HWCD §3.2 add and §3.3 dedicated doubling match the
  published formulas in both `JubjubPoint.java:137-173` and `InCircuitJubjub.java:76-140`.
- **Encoding is standards-correct.** Compressed 32-byte form matches zkcrypto/jubjub
  byte-for-byte across 16 sequential multiples of the generator, and `fromBytes` rejects
  `v >= p` and the non-canonical `u = 0` with sign bit set. Tonelli–Shanks is correct for
  this field (2-adicity 32, so the `(p+1)/4` shortcut correctly does not apply).
- **The off-circuit EdDSA scheme is well specified.** Subgroup checks on `pk` and `R`,
  `S ∈ [0, l)` malleability rejection, and `pk` bound into the challenge (key-substitution
  defense).
- **Pedersen `H` is sound as a second base.** NUMS-derived from a domain-separated Poseidon
  try-and-increment, cofactor-cleared, subgroup-checked, and pinned by a fixture test.
- **The field guard works.** Every gadget calls `requireField(BLS12-381)`, and a BN254
  compile is tested to throw.

### What the review surfaced as needing a decision

1. **The in-circuit point representation is unconstrained, and EdDSA verification is
   forgeable because of it.** `InCircuitJubjub.Point` is a public record of four free wires.
   No constraint ties `T` to `U·V/Z`, and there is no on-curve assertion anywhere in the
   in-circuit layer. In the HWCD addition formula the intermediates `F` and `G'` depend only
   on `(Z1, T1, Z2, T2)`, and the two projective-equality assertions in
   `InCircuitEdDSAJubjub.verify` reduce to `G' = E/u_target` and `F = H/v_target` — both
   directly solvable for `Z1` and `T1`. A prover therefore picks arbitrary `R.u`, `R.v`
   (which fix the challenge), any `S < l` (which fixes the target `[S]·G`), and then solves
   for the remaining two wires.

   A proof-of-concept produced a **circuit-accepted EdDSA proof for a message that was never
   signed**, under a real issuer public key, with an `R` that is not even on the curve.
   `InCircuitEdDSAJubjub.verify` is public and takes this record, so the break is reachable
   from the documented low-level API. The annotation layer avoids it only incidentally:
   `ZkJubjubPoint.fromTrustedAffine` pins `z = constant(1)` and `t = u·v`, which removes the
   two degrees of freedom. That is a property of one call site, not an enforced invariant.

2. **The Fiat–Shamir challenge is not uniquely determined.** `InCircuitEdDSAJubjub.java:91`
   range-checks `kQuotient` to 4 bits. Because `kQuotient·l + kModL == kRaw` is a *field*
   equation, and `δ = p − 8·l = 0x207c9f6499bdd7e87b478d0848469a49` (126 bits), the pair
   `(q + 8, kModL + δ)` also satisfies `q < 16` and `kModL < l`. A proof-of-concept had the
   circuit accept both `(q=1, k=…f341)` and `(q=9, k=…d8a)` for one transcript. This is not
   by itself a forgery — the prover still cannot produce a matching `S` — but it voids the
   "challenge is a function of the transcript" property the soundness argument depends on,
   and it is a live hazard for any composition that binds to `kModL`.

3. **The off-circuit verifier accepts the identity public key.** `EdDSAJubjub.verify`
   (`EdDSAJubjub.java:123`) checks subgroup membership, which `IDENTITY` passes, but never
   rejects it. Since `R + [k]·O = R`, anyone forges by choosing `r`, setting `R = [r]·G` and
   `S = r`. Confirmed returning `true`. `ZkEdDSAJubjub` rejects identity in-circuit; the
   off-circuit verifier does not.

4. **The in-circuit verifier accepts any small-order public key — including in-circuit
   identity — and no proposed cofactoring fixes that.** `InCircuitEdDSAJubjub.verify` has no
   identity, subgroup, or torsion check on `pk`. Confirmed: with the affine well-formedness
   binding of Decision 1 applied, `pk = IDENTITY` is accepted and yields a universal forgery
   (`[k]·pk = O`, so the equation collapses to `[S]·G == R`; set `R = [S]·G` for any `S`).
   Identity is on the curve, so no curve-membership check can reject it.

   The same holds for every point of order dividing 8 — `(0, −1)` of order 2, or `[l]·
   FULL_GENERATOR` of order 8. Under a **cofactored** verification equation this gets
   strictly worse: `[8]·([k]·pk) = O` for all such `pk`, so the equation reduces to
   `[8S]·G == [8]·R` and `R = [S]·G` forges for any message. Confirmed by direct computation:
   the same forgery is **accepted** by the cofactored equation and **rejected** by the
   cofactorless one shipping today. ADR-0016 §4 and Risk 1 claimed the high-level gadget
   "*always* performs subgroup checks internally"; it never did.

5. **The projective representation is a hash input.** `InCircuitEdDSAJubjub.java:80-81`
   hashes the *extended* `u()`/`v()` wires while `witnessComputeKReduction` hashes
   `affineU()`/`affineV()`. These agree only when `Z = 1`. Any gadget-produced point (`Z != 1`)
   silently diverges, and a prover who controls `Z` can rescale `(λU, λV, λZ, λT)` — the same
   logical point with a different challenge — i.e. grind Fiat–Shamir.

6. **Key-material and input-validation gaps.** `EdDSAJubjub.Keypair` is a record, so the
   generated `toString()` prints the private key (confirmed: `Keypair[sk=12648430, pk=...]`).
   There is no `generateKeypair(SecureRandom)` and no use of `SecureRandom` anywhere in the
   module, so every caller hand-rolls uniform sampling in `[1, l)`. `sign()` accepts `sk >= l`
   while `keypairFromSecret` rejects it. `msg` is not required to be `< p`, so a signature
   over `msg` also verifies for `msg + p` (confirmed). There is no `hashToField` helper, so
   each caller invents its own byte-message encoding.

7. **No domain separation in the folded Poseidon.** `PoseidonN` / `PoseidonHash.hashN` is a
   bare left-fold of the two-input permutation, so `hashN(a,b) == hash(a,b)`, and the nonce
   `Poseidon(sk, msg)` shares construction and parameters with the five-input challenge. No
   exploit today (the arity is fixed and `sk` is secret), but it removes the margin a domain
   tag would provide.

8. **A misleading in-code security warning.** `EdDSAJubjub.java:100-104` claims the mod-`l`
   nonce reduction carries "~2^-3 bias (p/l ≈ 8)" and warns about signing volume. The actual
   statistical distance is `≈ δ/p ≈ 2^-129`; there is no volume limit. The warning invites
   callers to work around a non-problem.

9. **Measured cost is far above the documented estimates, and cheap wins are unclaimed.**
   Compiled R1CS constraint counts over BLS12-381:

   | Gadget | Actual | Documented |
   |---|---:|---|
   | `add` / `doubled` | 10 / 10 | "~9" |
   | fixed-base scalar-mul, 252-bit | 6,049 | "~2,500" |
   | variable-base scalar-mul, 252-bit | 8,559 | "~5,000" |
   | Pedersen commit, 252-bit | 12,108 | "~10,000" |
   | **EdDSA verify** | **18,965** | **ADR-0016: "~3,000"** |
   | Poseidon 2-in (reference) | 828 | — |

   Off-circuit, warm JIT: `scalarMul` 1.01 ms, `isInSubgroup` 1.00 ms, `sign` 2.89 ms,
   `verify` 4.03 ms, Pedersen `commit` 1.76 ms, `fromBytes` 0.23 ms, `toBytes` 0.013 ms.

   The dominant avoidable costs are: `InCircuitJubjub.select` (line 146) calling `api.select`
   four times with the same condition, so `CircuitAPIImpl.select` re-asserts booleanity on
   each coordinate (measured: 1 scalar select = 3 constraints, 4 with the same condition = 12,
   no dedup) on bits that `toBinary` already constrained; fixed-base additions being emitted
   as full variable additions even though the table entries are constants with `Z = 1` (six of
   the ten multiplications collapse to linear combinations); the windowed fixed-base table
   specified in ADR-0016 §3 never being implemented; and the five-input challenge being four
   folded `t=3` permutations (~3,312 constraints) because `PoseidonParamsBLS12_381T5` is
   generated and Sage-cross-checked but unusable — `PoseidonHash.hash:40` hard-rejects
   `t != 3` and the in-circuit `Poseidon` gadget is `t=3`-only.

10. **No adversarial structural/soundness tests.** There *are* negative tests — `InCircuit
    EdDSAJubjubTest` rejects tampered messages, a malleated `S`, and a wrong public key. What
    is absent is the class that varies the *witness structure* rather than its values: nothing
    asserts that a malformed point, a non-boolean bit, an aliased quotient, or an
    out-of-range comparator operand is rejected. That is the class that would have caught
    items 1, 2, and 11.

11. **`CircuitAPIImpl.lessThan` is unsound on operands that carry no range constraint, and
    the exposure is project-wide.** `lessThan(a, b, n)` forms `diff = (2^n − 1) + b − a` and
    takes the MSB of an `(n+1)`-bit decomposition. If `a` carries no `< 2^n` constraint, the
    subtraction wraps modulo `p`, and for a band of `a` near `p` the wrapped value lands back
    inside `[2^n, 2^(n+1))` and the gadget returns *true*.

    **Both directions are forgeable**, depending on which operand lacks the constraint:

    | Asserted form | Unbounded operand | Confirmed witness |
    |---|---|---|
    | `a < b` | left (`a`) | `lessThan(p − 1, l, 252)` accepted; `lessThan(p − 1, 10^6, 64)` accepted |
    | `a >= b` | right (`b`) | `greaterOrEqual(0, p − (2^64 − 1), 64)` accepted |

    An earlier draft of this ADR claimed the `>=` direction was safe. That was wrong — it had
    been tested by varying the left operand only. Enlarging the *right* operand drives
    `diff = (2^n − 1) + b − a` to wrap to a small residue, and the comparison returns true.

    `InCircuitEdDSAJubjub`'s `S < l` and `kModL < l` checks and
    `ZkPedersen.assertCanonicalScalar` (line 108) are sound today **only** because
    `scalarMulFixedBase` / `scalarMulVariableBase` and `InCircuitPedersen.commit` later emit
    `toBinary(·, 252)` on the same wires. The repository-wide audit also found
    `Signal.lessThan` (a public facade) and `SignalComparators.greaterOrEqual` in
    `SealedBidCircuit:38` and `BalanceThresholdCircuit:28`. Both compare an unbounded private
    witness against an **unbounded public input** (`reservePrice`, `threshold`). They are
    therefore **not sound as circuit relations as written**; they hold only if the surrounding
    protocol independently guarantees the public operand is below `2^64`, and neither circuit
    documents that precondition.

### Blast radius today

`zeroj-examples/.../AnnotatedPedersenCommitment.java` is the only in-repository consumer of
these gadgets, and EdDSA-Jubjub is not wired into any shipped usecase. However, commit
`8b535d5` **is contained in every release tag in the repository** (`v0.1.0-pre1` through
`v0.1.0-pre10`), so the affected code has been published. We can state that there is no known
in-repository EdDSA-Jubjub consumer; we cannot state that no deployed artifact needs
revocation. An adoption/release audit is required before that claim can be made, and it is a
prerequisite of M0 below.

**Release audit result (M0, completed 2026-07-25).** The audit was run and the answer is
worse than "published in a tag": `com.bloxbean.cardano:zeroj-circuit-lib` is **live on Maven
Central** in nine versions — `0.1.0-pre1`, `pre3`, `pre4`, `pre5`, `pre6-ci2`, `pre7`, `pre8`,
`pre9`, `pre10` — with `pre10` released 2026-07-17. The published jar was downloaded and
inspected: it contains `InCircuitEdDSAJubjub.class`, `InCircuitJubjub$Point.class`,
`ZkEdDSAJubjub.class`, and the rest of the affected surface. The forgeable gadget is
therefore not merely tagged but publicly resolvable by any downstream Gradle/Maven build
today. We still have no evidence of an actual downstream consumer, but the exposure is
"anyone can depend on it", not "it exists in history". This is what makes Decision 0
immediate rather than M4 cleanup, and it means the fix must ship as a new release with
release notes that name the defect, not as a silent correction.

Two currently-published documents actively steer readers into the broken model:
`zeroj-circuit-lib/README.md:51` marks EdDSA-Jubjub "Ready on BLS12-381 Groth16", and
`docs/circuit-annotation-user-guide.md:254` recommends binding keys with
`fromTrustedAffine(...)` after off-circuit checks — the exact contract Decision 1 withdraws.

## Decision

### 0. Downgrade the published safety claims immediately

Before any code change, and ahead of every other milestone: mark EdDSA-Jubjub and the raw
Jubjub point gadgets **not production-ready** in `zeroj-circuit-lib/README.md`, and replace
the `fromTrustedAffine` guidance in `docs/circuit-annotation-user-guide.md` with an explicit
warning that witness points are not curve- or subgroup-checked and that in-circuit EdDSA
verification is forgeable until M1–M4 land. Run the release/adoption audit described under
Blast Radius and record the result.

Documentation that tells users a forgeable gadget is "Ready" is itself a live defect. It is
not M4 work.

### 1. Point well-formedness becomes a gadget-enforced invariant, with one exact mechanism

The "validated off-circuit, trusted in-circuit" contract in `InCircuitJubjub` and
`InCircuitEdDSAJubjub` is withdrawn for witness points. A prover-supplied point is not
validated by anything the caller does off-circuit — the caller never sees the prover's
witness.

**The public raw-extended-`Point` verification overload is removed, and verification moves to
a non-public `verifyCore` that takes affine `u`/`v` wires for `pk` and `R` and constructs the
extended points internally.** It is not enough to offer a safe binder and document it; the
unsafe path has to become unreachable at the API boundary. `verifyCore` is never public — the
only public entry points are the two of Decision 4, so there is no window in which a public
verifier exists with an ambiguous key-trust contract. Internally, for each of `pk` and `R`,
`verifyCore` emits:

- `Z := 1` (the constant wire) and `T := u·v` (one constraint), and
- the affine curve equation `v² − u² == 1 + d·u²·v²`.

Measured cost: **5 constraints per point, 10 for the pair** (legacy `verify` 18,965 →
`verifyCore` 18,975). This single mechanism discharges curve membership, the
extended-coordinate invariant, `Z != 0`, and the projective rescaling of Context item 5 —
the last because `Z` is a constant, so the challenge hash is computed over genuinely affine
coordinates by construction.

`InCircuitJubjub.witnessAffine(api, uWire, vWire)` is exported as the same binder for other
gadgets. `InCircuitJubjub.assertWellFormed(api, point)` is also provided for genuinely
projective values, emitting all **three** of `V² − U² == Z² + d·T²`, `T·Z == U·V`, and
`Z != 0`; it deliberately accepts any nonzero rescaling and is therefore **not** sufficient at
a hashing boundary. The raw four-wire `Point` constructor remains for gadget-internal values
and is documented as unchecked.

**The `Z != 0` conjunct of `assertWellFormed` is not optional.** `(U,V,Z,T) = (0,0,0,0)`
satisfies the other two identically — both reduce to `0 == 0` — propagates through the
addition formula to an all-zero `R + [k]·pk`, and makes both projective-equality assertions
read `0 == 0`, vacuously true for any `S`. A check set carrying only the curve equation and
the `T` invariant leaves the forgery of Context item 1 fully intact; this was confirmed by
executing that exact set against an all-zero witness.

Both the corrected mechanism and its cost were validated before adoption: with affine
binding on `pk` and `R`, the extended-coordinate forgery and the all-zero variant are both
rejected and an honest signature still verifies.

Rationale: ADR-0016 Risk 1's mitigation ("low-level ops are clearly documented as caller's
responsibility") is not a viable control for values that originate in the witness. The
correct boundary is the gadget signature.

### 2. The challenge reduction becomes canonical *and* complete

Witness `kQuotient` and `kModL`, and enforce all three of:

- `kQuotient <= 8`,
- `kModL < l`,
- `kQuotient == 8 ⇒ kModL < δ`  (where `δ = p − 8·l`).

Then `kQuotient·l + kModL < p` unconditionally, so the field equation cannot wrap, the
decomposition is unique, **and** every `kRaw ∈ [0, p)` has a satisfying witness. The earlier
draft of this ADR proposed a flat 3-bit quotient; that is sound but sacrifices completeness
on the `kRaw >= 8l` tail, which contradicts Decision 4's off-circuit-implies-in-circuit
claim and sits at probability `≈ 2^-129` where no randomized corpus can exercise it. The
three-part constraint costs a few hundred constraints and removes an untestable claim.

`witnessComputeKReduction` returns the canonical `(q, kModL)` and is covered by a
**deterministic** boundary test that constructs `kRaw` values straddling `8l` directly,
rather than relying on sampling.

**Comparator operands must carry range constraints; emission order is irrelevant.** R1CS
constraints are declarative, so the earlier framing of this as an "ordering invariant" was
wrong — the property is that the constraints *exist*, not where they appear. Per Context
item 11:

- `CircuitAPI.lessThan(a, b, n)` range-constrains **both** variable operands to `n` bits.
  Constraining only the left operand is insufficient — the `>=` witness above attacks the
  right one. A statically-validated constant operand is exempt and is checked at build time.
- A reuse overload is added, but it takes an **opaque `BitDecomposition` type**, not a bare
  `Variable[]`. A raw array carries no proof that its elements are boolean, so a
  `lessThan(Variable[], Variable[])` overload would either be unsound or have to re-assert
  booleanity — losing the reuse benefit it exists for. `BitDecomposition` has a non-public
  constructor and returns defensively-copied, immutable bits, so the range constraint travels
  with the value and cannot be forged. It **binds the source variable, the width, and the bits
  together**, and the reuse overload consumes that bound object rather than taking a
  decomposition plus a separately-supplied value — otherwise a caller could pass the
  decomposition of `x` while comparing `y`. This is what keeps Decision 7 item 5 from being a
  regression.

  Transition: `CircuitAPI.toBinary` currently returns `Variable[]`
  (`CircuitAPI.java:52`) and changing that return type is source-breaking across every
  caller. We add `CircuitAPI.decompose(Variable, int) -> BitDecomposition` alongside it,
  migrate library gadgets to the new method, and deprecate `toBinary` rather than break it in
  the same release.
- The precondition is documented on `CircuitAPI.lessThan`, `Comparators`, `SignalComparators`,
  and `Signal.lessThan`.
- A repository-wide call-site audit lands with adversarial tests for every public comparison
  facade, exercising an unbounded operand on **each side** — an `a ≈ p` witness for `<` and a
  `b ≈ p` witness for `>=`. `SealedBidCircuit` and `BalanceThresholdCircuit` are fixed by the
  `lessThan` change and gain tests pinning the corrected relation.

### 3. Close the off-circuit verifier and key-handling gaps

- `EdDSAJubjub.verify` rejects `pk.isIdentity()`.
- `EdDSAJubjub.sign` range-checks `sk ∈ (0, l)`, matching `keypairFromSecret`.
- `sign` and `verify` reject `msg >= p` (and negative `msg`) rather than relying on Poseidon's
  internal reduction, removing the `msg`/`msg + p` alias.
- `Keypair` overrides `toString()` to redact `sk`.
- Ship `EdDSAJubjub.generateKeypair(SecureRandom)` performing rejection sampling in `[1, l)`,
  and a documented `hashToField(byte[])` for byte-oriented messages. Not shipping these means
  every integrator re-implements the two easiest things to get wrong.

### 4. Public-key trust becomes an explicit, enforceable model — and verification stays cofactorless

Context item 4 shows that no amount of curve-membership checking rescues a small-order `pk`,
and that cofactoring the verification equation makes it strictly worse. An earlier draft of
this ADR adopted cofactored verification to close the accept/reject asymmetry with the
off-circuit verifier; that is withdrawn. Cofactorless verification forces the accepted `R`
into the prime-order subgroup algebraically — both `[S]·G` and `[k]·pk` lie there when `pk`
does — so the circuit and the strict off-circuit verifier agree on exactly which `R` values
are admissible.

This is canonical *acceptance semantics*, not uniqueness of `R`. A signer who deviates from
the deterministic nonce can produce a different, entirely valid prime-order-subgroup
signature over the same `(pk, msg)`. A protocol that uses `R` as a uniqueness key therefore
still depends on deterministic, single issuance — or, better, should derive its nullifier
from a credential identifier rather than from `R`.

Correcting an earlier draft: this is **not** a public malleability of an issued signature.
Replacing `R` with `R + T` changes the challenge from `H(R, pk, msg)` to `H(R + T, pk, msg)`,
so the original `S` no longer satisfies the equation. Measured: of the 8 torsion variants,
exactly **1 of 8** verifies cofactored when `S` is held fixed — the original. The real
exposure is **signer-controlled non-canonical issuance**: an issuer who knows `sk` can
recompute the challenge and response for each variant and produce **8 of 8** distinct
signatures that all verify under a cofactored equation, while the strict off-circuit verifier
rejects every torsion-bearing one. Under cofactorless verification those variants are simply
invalid, so a malicious issuer cannot mint credentials that the circuit honours and the
off-chain checker disowns. See *Taming the Many EdDSAs* for the general treatment.

Instead, the trust model for `pk` is made explicit in the API, because it is the protocol
shape — not the gadget — that determines whether `pk` is attacker-controlled:

- **`verifyStrict(...)`** performs an in-circuit prime-order subgroup check on `pk`
  (`[l]·pk == O`, ~8,559 constraints). This is the correct entry point whenever `pk` is a
  private witness or is selected by the prover — for example "a credential from *some*
  issuer in this Merkle tree".
- **`verifyWithRegisteredKey(...)`** requires `pk` to be a circuit constant or a public
  input. This requirement is **enforced by the DSL, not by Javadoc.** Today `Variable` is a
  `record(int id, String name)` and `InputVisibility` is a private enum inside
  `CircuitAPIImpl`, so a gadget has no way to tell a public input from a secret witness — a
  documented contract here would be unenforceable, exactly the failure mode Decision 1
  withdraws. Prerequisite for this entry point: add
  `CircuitAPI.requirePublicOrConstant(Variable)`, which throws at circuit-definition time, and
  have `verifyWithRegisteredKey` call it on both `pk` wires.

  **Authorization is set membership over circuit-owned wire IDs, never over any name supplied
  through `Variable`.** `Variable` is a public record, so any caller can construct
  `new Variable(secretWire.id(), "someKnownPublicInputName")`. The existing
  `inputVisibilities` map is keyed by *name* while every emitted constraint references the
  *id*, so it is **not** a usable basis: a name-keyed implementation would classify that
  forgery as public while the circuit wires in the secret value. The check resolves against
  the `publicInputs` wire IDs plus a dedicated constant-wire-ID set that `CircuitAPIImpl`
  maintains as it creates constants. That set must include `oneWire`, which is constructed
  directly in the constructor and never enters `constantCache` — `constantCache.values()`
  alone would omit it.
  Tests must cover: an ordinary secret input; a secret wire carrying a public input's name; a
  derived/intermediate wire; and genuine public and constant wires including `oneWire`.

  The DSL check establishes only that the value is verifier-visible. Binding it to a registry
  entry whose subgroup membership was checked at registration remains a protocol obligation
  on the final verifier, stated in the Javadoc and repeated in the module README.

Both entry points additionally assert `[8]·pk != O` — three doublings plus a non-identity
check, measured at **41 constraints** on top of the affine binder. This rejects the identity
and every pure-torsion key outright. It does not prove subgroup membership (a mixed-order
`pk = pk' + T` passes), which is exactly why it is a backstop rather than the control, and
why `verifyStrict` exists.

There is no public unqualified `verify(...)` at any point in the sequence. M1 deletes the
raw-point overload and leaves `verifyCore` non-public; M3 exposes the two named entry points
above. The ambiguous name is removed rather than left as a trap, and it is never briefly
re-exposed in an interim form.

Note on scalar width, correcting an earlier draft: `8·kModL` is at most `8(l − 1)`, which is
255 bits and less than `p`, so it does **not** exceed `scalarMulFixedBase`'s 255-element
array cap. It does exceed both the 252-bit scalar width used by the legacy verifier (and
retained in `verifyCore`) and `CircuitAPIImpl`'s `MAX_SAFE_BITS = 253` ceiling on `toBinary`,
so it cannot be built through the scalar overload. Where a cofactor multiple is needed
anywhere in this codebase it is applied as three doublings after the scalar multiplication —
cheaper, and it sidesteps the width question entirely.

### 5. Domain-separate the Poseidon uses, with the construction pinned

This ADR does **not** pin the construction — it states what must be pinned and makes doing so
a hard prerequisite of M3. A normative specification document (`docs/specs/jubjub-eddsa-v1`)
must exist and be reviewed before any domain-separation code lands:

- A ZeroJ suite identifier and version string, and the literal field-element tag per use
  (challenge, nonce, `hashToField`), with golden vectors.
- `hashToField(byte[])`: byte ordering, framing/padding, reduction algorithm, and DST, with
  vectors. An underspecified `hashToField` is how two implementations of "the same" scheme
  stop interoperating.
- The `t = 6` Poseidon parameter set itself: generated through the existing
  `PoseidonParamsCodegen` path and cross-checked against the hadeshash Sage reference, on the
  same footing as the `t=3`/`t=5` presets. New Poseidon parameters are a security-relevant
  artifact, not a config change.
- Arity arithmetic, correcting an earlier draft: the challenge absorbs five field elements,
  so with capacity 1 a single permutation needs rate 5, i.e. **`t = 6`** — `t = 5` (rate 4)
  cannot do it, and the earlier "`t=5`/`t=6`" phrasing was wrong. Adding a sixth absorbed
  element for the tag needs `t = 7`, unless the tag instead initialises the capacity cell,
  which is the construction we adopt: **`t = 6` with the domain tag in the capacity cell.**
  Until that lands, the tag costs one extra folded `t=3` permutation (828 constraints).

### 6. Reconcile ADR-0016 and the in-code documentation with what shipped

ADR-0016 is amended (superseded in the affected sections by this ADR) to record that: the
high-level gadget did **not** perform subgroup checks internally as Risk 1 claimed; the
windowed fixed-base table of §3 was not implemented; the "~3,000 constraints per EdDSA
verify" estimate is 6× low; and M6's consolidated cross-verification suite and the
`JubjubCurveTest.assertParameterSquareness` gate named in Risk 4 do not exist. The incorrect
nonce-bias warning at `EdDSAJubjub.java:100-104` is deleted and replaced with the measured
`2^-129` figure. Javadoc constraint estimates on `InCircuitJubjub` and `InCircuitPedersen`
are replaced with measured numbers, pinned by a test.

### 7. Sequence performance work strictly after the soundness gates

Constraint-count work is not a release blocker and must not land before the Decision 1–4
gates are green, because several optimizations touch the same code paths. Planned, in value
order:

1. Assert booleanity once per point-select instead of four times, and skip it entirely for
   `toBinary`-derived bits (−6 to −8 constraints/bit, i.e. up to −2,016 per 252-bit mul).
2. A dedicated constant-addend addition path for fixed-base multiplication (~4 constraints
   instead of 10 per addition).
3. The 3–4 bit windowed fixed-base table ADR-0016 §3 specified.
4. Finish the `t=6` Poseidon so the five-input challenge plus domain tag is one permutation
   (~−2,500 constraints per verify, and it absorbs Decision 5's 828).
5. Reuse the `toBinary` decomposition for the `< l` comparison instead of decomposing twice —
   via the `BitDecomposition` `lessThan` overload of Decision 2, which preserves the range constraint
   rather than dropping it. The `lessThan(p − 1, l, 252)` regression is the gate.

Targets, stated per entry point because they are not comparable: 252-bit fixed-base
multiplication at ~1.5–2k constraints (from 6,049); `verifyWithRegisteredKey` below ~8k; and
`verifyStrict` below ~14k, since its in-circuit subgroup check alone is ~8,559 today and only
partly benefits from items 1–3. An earlier draft quoted a single ≤8k target, which
`verifyStrict` cannot meet by construction.

Off-circuit, a Montgomery or Barrett reduction layer, wNAF scalar
multiplication, Strauss–Shamir for the verify equation, batch inversion, a cached quadratic
non-residue in `modSqrt` (it currently re-searches from 2 on every `fromBytes`), and a
hard-coded Pedersen `H` (currently a Poseidon try-and-increment plus Tonelli–Shanks in a
static initializer, already pinned by a fixture test) are expected to give 3–5× on
`scalarMul` and ~3× on `verify`. Tracked here, scheduled after M1–M3.

### 8. The off-circuit signer is classified non-production for remotely reachable issuers

`JubjubPoint.scalarMul` branches on secret bits over variable-time `BigInteger`, and
`EdDSAJubjub.sign` performs secret-dependent scalar multiplication for both the long-lived
key and the deterministic nonce. Unlike ADR-0021's BLS12-381 posture, there is no native
`blst` fallback to route secrets through.

Documentation is not a mitigation for a remotely reachable or co-resident issuer, so the
classification is explicit rather than advisory: **this signer is not approved for
value-bearing issuance on shared or network-reachable infrastructure.** Approved uses are
local/offline signing and test issuance.

Lifting the restriction requires the **entire** signing computation to be constant-time, not
just the scalar multiplication: branchless conditional select and fixed-length limb scalars
in `scalarMul`, branchless field reduction, **and the nonce hash** — `r = Poseidon(sk, msg)`
feeds the secret key straight through Poseidon's `BigInteger` S-box and MDS arithmetic, which
is variable-time on every operation. A constant-time `scalarMul` over a variable-time
Poseidon leaks the key just as effectively. This is deferred to a separate ADR and the
restriction stands until all of it lands.

Deriving the nonce as `Poseidon(sk, msg)` rather than from a separate hashed prefix of the
secret (RFC 8032 style) is accepted and documented. Jubjub-Merkle (ADR-0016 §7, optional)
stays unimplemented.

## Consequences

### Easier

- The unsafe path stops being reachable: the legacy raw-`Point` verifier is removed and
  neither public named entry point accepts raw extended-coordinate wires, so a caller cannot
  construct a forgeable point at the signature boundary.
- The `pk` trust assumption becomes a choice the caller makes by name (`verifyStrict` vs
  `verifyWithRegisteredKey`) rather than an undocumented default.
- Cofactorless verification keeps the accepted `R` in the prime-order subgroup, so the
  circuit and the off-circuit verifier agree on which signatures are admissible and a
  malicious issuer cannot mint non-canonical variants the circuit honours. This is canonical
  *acceptance semantics*, not a uniqueness guarantee on `R` — see Decision 4 for what a
  nullifier-bearing protocol still has to do for itself.
- Integrators get a safe key-generation and message-encoding surface instead of inventing one.
- The performance roadmap can proceed safely because the Decision 1–4 gates pin behaviour.

### Harder

- **Near-term cost grows by roughly 1,200 constraints, not the ~70 an earlier draft
  claimed**: +10 measured for affine binding of `pk` and `R`, +41 measured for `[8]·pk != O`,
  ~+300 for the canonical three-part reduction, +828 for domain separation until `t = 6`
  lands, and 0–500 for comparator range-constraining depending on whether the
  `BitDecomposition` overload reuses existing decompositions. `verifyWithRegisteredKey` lands
  near 20,100–20,600 before Decision 7 claws back several thousand; `verifyStrict` adds a
  further ~8,559 for the in-circuit subgroup check.
- **Two different breaking changes, with different migration scope.** They are not
  interchangeable and an earlier draft conflated them:
  - *Decision 2 (canonical reduction)* preserves `k = kRaw mod l`, so **signatures and
    credentials stay valid**. It changes the circuit, the witness layout, and therefore
    proofs and verification keys. Migration = recompile, re-run setup, re-prove.
  - *Decision 5 (domain separation)* changes what the challenge *is*, so it changes what a
    valid signature is. **Previously issued signatures and credentials become unverifiable**
    and must be re-issued, on top of everything Decision 2 invalidates.

  The release audit of Decision 0 sets the scope of the re-issuance. Sequencing this now,
  while `AnnotatedPedersenCommitment` is the only in-repository consumer, is what keeps it
  small.
- More test-maintenance surface (negative in-circuit tests, comparator adversarial tests
  across every public facade, constraint-count pins).
- The legacy public `verify` method is removed, so every existing call site must move to a
  named entry point.

### Neutral

- No on-chain verifier change. All Jubjub work stays inside the SNARK, as ADR-0016 §Risks 6
  established.
- The ADR-0016 architecture decisions (Jubjub over BabyJubJub, extended coordinates, Poseidon
  challenge) are unaffected; the enforcement boundary, the trust model, and the cost estimates
  change.

## Test Plan

- **Pre-fix exploit fixtures.** Retain the extended-coordinate and all-zero exploit witness
  vectors together with the accepting legacy circuit. Because M1 deletes the public overload
  those exploits called, the historical circuit is retained as a non-compiled test resource
  or a self-contained test-only reproduction of the legacy relation — never as source that
  still calls the removed method.
- **M1 soundness gates:**
  - `assertWellFormed` rejects the exact malformed points from the retained exploit fixtures,
    and a structural test confirms that no public raw-extended-`Point` verification overload
    exists.
  - The challenge alias `(q + 8, kModL + δ)` for a genuine signature is rejected.
  - `lessThan(p − 1, l, 252)` is rejected standalone and through the `S < l` check;
    `greaterOrEqual` with `b ≈ p` is rejected standalone and through both example circuits.
- **M3 verifier regressions:**
  - `pk = IDENTITY` with `R = [S]·G` and arbitrary `S` is rejected by both public entry
    points.
  - A `pk` of order 2 (`(0, −1)`) or order 8 (`[l]·FULL_GENERATOR`) with `R = [S]·G` is
    rejected by both `verifyStrict` and `verifyWithRegisteredKey`.
  - A **mixed-order** `pk = pk' + T`: `verifyStrict` must reject it; `verifyWithRegisteredKey`
    accepts it, and the test asserts that outcome explicitly so the residual dependence on
    registry binding is visible rather than implied. This needs a **deterministic constructed
    vector, not a random signature**: under cofactorless verification the torsion term cancels
    only when `8 | k`, measured at 51/400 random transcripts — exactly the subset with
    `k ≡ 0 (mod 8)`. The vector is built by searching `msg` for a transcript with `8 | k` and
    pinning it, so the test asserts acceptance rather than flaking at ~7/8.
  - `verifyWithRegisteredKey` called with a secret witness `pk` — asserted to throw at
    circuit-definition time via `requirePublicOrConstant`.
- **Well-formedness gates:** off-curve `(U, V)`; `T·Z != U·V` (the general projective form of
  the invariant — `T = U·V/Z`, so `T != u·v` is only the `Z = 1` special case); `Z = 0`; the
  all-zero point — each asserted rejected against **`assertWellFormed`**, since once
  verification takes affine wires these values are no longer expressible at its boundary.
  Paired with a structural test asserting that **no raw-extended-`Point` verification overload
  exists**, which is what makes the affine-only boundary a property of the API rather than a
  convention. A nonzero projective rescaling `(λU, λV, λZ, λT)` of a valid point must **pass**
  `assertWellFormed` (it is a legitimate representation); an earlier draft wrongly listed it
  as always rejected.
- **Reduction boundary:** deterministic witnesses with `kRaw` immediately below, at, and above
  `8l`, asserting the canonical `(q, kModL)` is accepted and every alias rejected. Not
  sampled — constructed.
- **Verifier relation:** over a randomized corpus, every signature the off-circuit verifier
  accepts is accepted by `verifyStrict`, and vice versa. Divergences are enumerated and
  asserted, never merely observed.
- **Comparator audit:** adversarial tests in both `<` and `>=` directions for
  `CircuitAPI.lessThan`, `Comparators`, `SignalComparators`, and `Signal.lessThan`, plus
  pinning tests for `SealedBidCircuit` and `BalanceThresholdCircuit`.
- **Input validation:** `sign` with `sk = 0`, `sk = l`, `sk > l`; `sign`/`verify` with
  `msg >= p`; `Keypair.toString()` asserted not to contain the secret scalar's digits.
- **Key generation:** `generateKeypair` output asserted in `[1, l)` over many samples, with
  `pk` in-subgroup and non-identity.
- **Domain separation:** golden vectors for the challenge, the nonce, and `hashToField`,
  including byte-ordering and framing cases.
- **Parameter pinning (ADR-0016 Risk 4 debt):** `a` is a QR and `d` is a non-QR; `d` re-derived
  as `-10240/10241 mod p`; `[8]·FULL_GENERATOR == SUBGROUP_GENERATOR`; `l` and `p` primality.
- **Cost pinning:** compiled constraint counts for `add`, `doubled`, fixed-base 252-bit,
  variable-base 252-bit, Pedersen 252-bit, `verifyStrict`, and `verifyWithRegisteredKey`.
- **Regression:** existing `JubjubPointTest` (including the 16 zkcrypto serialization
  vectors), `EdDSAJubjubTest`, `PedersenTest`, `InCircuitJubjubTest`,
  `InCircuitEdDSAJubjubTest`, and `ZkGadgetAdaptersTest` must stay green throughout.

## Implementation Plan

| # | Scope | Gate |
|---|---|---|
| **M0** | Decision 0: downgrade README and user-guide safety claims; run the release/adoption audit for tags `v0.1.0-pre1`–`pre10` | No published document describes a forgeable gadget as ready; audit result recorded |
| **M1** | Capture the pre-fix exploits as fixtures, then Decisions 1 and 2: delete the public raw-`Point` overload, add non-public `verifyCore` on affine wires, `witnessAffine`, three-conjunct `assertWellFormed`, canonical reduction, comparator range-constraining + `BitDecomposition` + repo-wide audit | No public verifier is exposed in this milestone; `assertWellFormed` rejects every captured exploit witness; structural no-raw-overload test green; existing suite green |
| **M2** | Decision 3 (identity `pk` rejection, `sk`/`msg` range checks, `Keypair` redaction, `generateKeypair(SecureRandom)`, `hashToField`) | Input-validation, key-generation, and `hashToField` vector gates green |
| **M3** | Decision 4 (`requirePublicOrConstant` in the DSL, `verifyStrict` / `verifyWithRegisteredKey`, `[8]·pk != O`) and Decision 5 (normative spec `docs/specs/jubjub-eddsa-v1` reviewed and `t = 6` parameters generated + Sage-validated **before** any code) | Small-order and identity `pk` rejected by both entry points; mixed-order outcome asserted per entry point; verifier-relation corpus green with divergences enumerated; spec and Poseidon vectors merged |
| **M4** | Decision 6 (ADR-0016 amendment, Javadoc corrections, constraint-count pins) | No remaining documented claim contradicted by code |
| **M5** | Decision 7 performance work, in order, each re-validated against M1–M3 gates | Fixed-base ≤ ~2k; `verifyWithRegisteredKey` ≤ ~8k; `verifyStrict` ≤ ~14k; all gates still green |

Per ADR-0016's pattern, a review pass runs at each milestone boundary before the next starts.

**M0 is immediate. M1–M3 are necessary hardening, not sufficient for production.** Shipping
EdDSA-Jubjub for value-bearing use additionally requires: the public-key binding model wired
into the consuming protocol and verified end to end, a migration path for artifacts
invalidated by Decisions 2 and 5, a constant-time signing path or acceptance of the Decision 8
restriction, and an external cryptographic review. Those are out of this ADR's scope and
gate the release, not the milestones.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| A caller builds `InCircuitJubjub.Point` from raw witness wires and forges proofs | Critical | Decision 1 removes raw-wire points from the public verification API entirely; the M1 structural test pins it |
| A partial well-formedness fix (curve equation without `Z != 0`) ships and the forgery survives | Critical | Decision 1 mandates the three-conjunct `assertWellFormed`, tested directly, plus the structural test that no raw-`Point` verification overload exists |
| `requirePublicOrConstant` is implemented by name and a forged `Variable(secretId, publicName)` bypasses it | Critical | Decision 4 requires wire-ID set membership against `publicInputs` and the dedicated constant-wire-ID set (including `oneWire`); the forged-name case is an explicit M3 test |
| Small-order or identity `pk` accepted in-circuit | Critical | Decision 4: `[8]·pk != O` in both entry points, plus a real subgroup check in `verifyStrict`; M3 regressions |
| Cofactored verification is reintroduced and silently enables small-order-`pk` forgery and signer-controlled non-canonical issuance | High | Decision 4 records the measured comparison and why cofactorless is retained; any future batch verifier must reproduce the same validation semantics, not a cofactored relaxation |
| `verifyWithRegisteredKey` is called with a prover-controlled `pk` because the contract is only documented | High | Decision 4 makes `requirePublicOrConstant` a DSL-enforced prerequisite; M3 asserts the secret-witness call throws |
| A public comparator operand near `p` forges a `>=` relation in an application circuit | High | Decision 2 constrains both operands; M1 adds `b ≈ p` adversarial tests across every facade and pins both example circuits |
| A performance rewrite drops the range constraint the `< l` checks depend on | High | Decision 2 constrains both operands inside `lessThan` and adds the `BitDecomposition` overload; Decision 7 item 5 is gated on the `s = p − 1` regression |
| Published docs keep steering users into the withdrawn trust model | High | Decision 0 / M0 lands before any code change |
| The challenge alias is composed into a future protocol that binds `kModL` | High | Decision 2 makes the reduction canonical and complete before any such composition exists |
| Integrators roll their own key sampling or message encoding | High | Decision 3 ships both with pinned vectors |
| Released pre-tags carry the forgeable gadget into a downstream consumer | High | M0 release/adoption audit; blast-radius claim not asserted until it completes |
| Decision 5 (domain separation) invalidates persisted signatures and credentials | Medium | Re-issuance path; scope set by the M0 release audit, while `AnnotatedPedersenCommitment` is the only in-repository consumer |
| Decision 2 (canonical reduction) invalidates circuit artifacts — proofs, witnesses, verification keys — but **not** signatures | Low | Recompile, re-run setup, re-prove; no credential re-issuance needed |
| Variable-time signing on a reachable issuer leaks the key | Medium | Decision 8 classifies the signer non-production for that deployment shape rather than documenting a caveat |
| Performance work (M5) silently reintroduces a soundness gap | Medium | M1–M3 gates are hard prerequisites and re-run per M5 step |

## References

- ADR-0014: W3C Verifiable Credential Circuit Support (motivation for in-circuit EdDSA)
- ADR-0015: Standards-compatible Poseidon for BLS12-381
- ADR-0016: Jubjub-in-Circuit for BLS12-381 Cardano Proofs (amended by this ADR)
- ADR-0021: BLS12-381 Implementation Review Outcomes and Hardening Posture (same review
  posture; constant-time contract precedent)
- ADR-0028: DSL Optimization and Hint Soundness (constraint-level soundness precedent)
- Hisil, Wong, Carter, Dawson — *Twisted Edwards Curves Revisited*, 2008
- RFC 8032 §8.8, *Multiplication by Cofactor in Verification* —
  <https://www.rfc-editor.org/rfc/rfc8032.html#section-8.8>
- Chalkias, Garillot, Nikolaenko — *Taming the Many EdDSAs*, 2020 (cofactored vs cofactorless
  verification and small-order key handling)
- zkcrypto/jubjub — <https://github.com/zkcrypto/jubjub>
- Zcash Sapling spec — <https://zips.z.cash/protocol/sapling.pdf> §5.4.8
