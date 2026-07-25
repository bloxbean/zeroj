# ADR-0037: Jubjub Soundness Fixes and Production-Readiness Hardening

## Status
Proposed

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
executable proofs-of-concept for the suspected soundness gaps.

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

4. **In-circuit curve/subgroup enforcement contradicts ADR-0016.** ADR-0016 §4 and Risk 1
   state that the high-level verify gadget "*always* performs subgroup checks internally."
   `InCircuitEdDSAJubjub`'s Javadoc explicitly opts out and delegates to callers. Once item 1
   is fixed the verification equation does incidentally force `R` to be torsion-free (both
   `[S]·G` and `[k]·pk` are), so the residual exposure is `pk`; but the asymmetry means a
   signature the circuit accepts can be rejected by the off-circuit verifier.

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

10. **No negative in-circuit tests.** Every in-circuit test is happy-path or wrong-public-
    output. Nothing asserts that a malformed point, a non-boolean bit, or an aliased quotient
    is *rejected*. This is precisely the test class that would have caught items 1 and 2.

### Blast radius today

The only downstream consumer of these gadgets is
`zeroj-examples/.../AnnotatedPedersenCommitment.java`. EdDSA-Jubjub is not wired into any
shipped usecase. The soundness defects can therefore be fixed before anything depends on
them; no deployed artifact needs revocation.

## Decision

### 1. Point well-formedness becomes a gadget-enforced invariant, not a caller contract

The "validated off-circuit, trusted in-circuit" contract in `InCircuitJubjub` and
`InCircuitEdDSAJubjub` is withdrawn for witness points. A prover-supplied point is not
validated by anything the caller does off-circuit — the caller never sees the prover's
witness. We will:

- Add `InCircuitJubjub.assertOnCurve(api, point)` emitting `V² − U² == Z² + d·(T²)`
  (equivalently the affine form when `Z = 1`), and `assertExtendedConsistent(api, point)`
  emitting `T·Z == U·V`. Together ~4 multiplication constraints per point.
- Make `InCircuitEdDSAJubjub.verify` apply both to `pk` and `R` itself, unconditionally.
  At ~8 constraints against a ~19,000-constraint gadget, the cost is not a reason to defer it
  to callers.
- Add a `witnessAffine(api, uWire, vWire)` constructor that binds `Z` to the constant-1 wire
  and `T` to a constrained `u·v`, and steer all documentation and examples to it. The raw
  four-wire `Point` constructor stays for gadget-internal use but is documented as unchecked.

Rationale: ADR-0016 Risk 1's mitigation ("low-level ops are clearly documented as caller's
responsibility") is not a viable control for values that originate in the witness. The
correct boundary is the gadget.

### 2. The challenge reduction becomes canonical

`kQuotient` is range-checked to **3 bits** (`q < 8`) instead of 4. Then
`q·l + kModL <= 8l − 1 < p`, the field equation cannot wrap, and the decomposition is unique.
Honest completeness is lost only when `kRaw >= 8l`, which occurs with probability
`δ/p ≈ 2^-129`. `ZkEdDSAJubjub.validateInputs` is tightened to `kQuotient.bits() <= 3` to
match.

We also assert `Z == 1` on every point whose coordinates feed the challenge hash, so the
in-circuit and off-circuit challenge computations are provably the same function and the
representation cannot be used to grind Fiat–Shamir.

### 3. Close the off-circuit verifier and key-handling gaps

- `EdDSAJubjub.verify` rejects `pk.isIdentity()`.
- `EdDSAJubjub.sign` range-checks `sk ∈ (0, l)`, matching `keypairFromSecret`.
- `sign` and `verify` reject `msg >= p` (and negative `msg`) rather than relying on Poseidon's
  internal reduction, removing the `msg`/`msg + p` alias.
- `Keypair` overrides `toString()` to redact `sk`.
- Ship `EdDSAJubjub.generateKeypair(SecureRandom)` performing rejection sampling in `[1, l)`,
  and a documented `hashToField(byte[])` for byte-oriented messages. Not shipping these means
  every integrator re-implements the two easiest things to get wrong.

### 4. In-circuit verification adopts the cofactored equation

Rather than an in-circuit `[l]·P` subgroup check (~8,500 constraints per point), the verify
gadget asserts the cofactored equation `[8S]·G == [8]·R + [8·kModL]·pk`, which costs three
extra doublings per side (~60 constraints) and annihilates any order-8 component. The
off-circuit `isInSubgroup()` gate on `pk` at issuer-registration time is retained and
documented as a protocol requirement, not an implementation detail.

This closes the accept/reject asymmetry between `EdDSAJubjub.verify` and
`InCircuitEdDSAJubjub.verify` for torsion-bearing keys.

### 5. Domain-separate the Poseidon uses

The challenge and nonce hashes take a distinct constant domain tag as the first fold input.
If Decision 7's `t=5`/`t=6` Poseidon path lands first, the tag rides along in the wider
permutation at no extra cost; until then it costs one additional 828-constraint permutation
in the challenge, which is accepted.

### 6. Reconcile ADR-0016 and the in-code documentation with what shipped

ADR-0016 is amended (superseded in the affected sections by this ADR) to record that: the
high-level gadget did **not** perform subgroup checks internally as Risk 1 claimed; the
windowed fixed-base table of §3 was not implemented; the "~3,000 constraints per EdDSA
verify" estimate is 6× low; and M6's consolidated cross-verification suite and the
`JubjubCurveTest.assertParameterSquareness` gate named in Risk 4 do not exist. The incorrect
nonce-bias warning at `EdDSAJubjub.java:100-104` is deleted and replaced with the measured
`2^-129` figure. Javadoc constraint estimates on `InCircuitJubjub` and `InCircuitPedersen`
are replaced with measured numbers, with a note that they are pinned by a test.

### 7. Sequence performance work strictly after the soundness gates

Constraint-count work is not a release blocker and must not land before Decision 1–4 gates
are green, because several of the optimizations change the same code paths. Planned, in
value order:

1. Assert booleanity once per point-select instead of four times, and skip it entirely for
   `toBinary`-derived bits (−6 to −8 constraints/bit, i.e. up to −2,016 per 252-bit mul).
2. A dedicated constant-addend addition path for fixed-base multiplication (~4 constraints
   instead of 10 per addition).
3. The 3–4 bit windowed fixed-base table ADR-0016 §3 specified.
4. Finish the `t=5`/`t=6` Poseidon so the five-input challenge is one permutation
   (~−2,500 constraints per verify).
5. Reuse the `toBinary` decomposition for the `< l` comparison instead of decomposing twice.

Targets: 252-bit fixed-base multiplication at ~1.5–2k constraints (from 6,049) and EdDSA
verify below ~8k (from 18,965). Off-circuit, a Montgomery or Barrett reduction layer, wNAF
scalar multiplication, Strauss–Shamir for the verify equation, batch inversion, a cached
quadratic non-residue in `modSqrt` (it currently re-searches from 2 on every `fromBytes`),
and a hard-coded Pedersen `H` (currently a Poseidon try-and-increment plus Tonelli–Shanks in
a static initializer, already pinned by a fixture test) are expected to give 3–5× on
`scalarMul` and ~3× on `verify`. These are tracked here but scheduled after M1–M3.

### 8. Accept the remaining items as documented, not blocking

Variable-time `scalarMul` (secret-dependent branching over variable-time `BigInteger`) is
accepted for prover-side use, consistent with the ADR-0021 posture for `zeroj-bls12381`.
Deriving the nonce as `Poseidon(sk, msg)` rather than from a separate hashed prefix of the
secret (RFC 8032 style) is accepted, documented. Issuer signing services that are remotely
timeable need an environment-specific review; that is called out in the module README rather
than solved here. Jubjub-Merkle (ADR-0016 §7, optional) stays unimplemented.

## Consequences

### Easier

- The in-circuit gadgets become safe to hand to application developers: a witness point that
  is not a well-formed curve point fails the proof instead of forging one.
- The in-circuit and off-circuit verifiers accept exactly the same signature set, so an
  off-chain pre-check is a reliable predictor of in-circuit success.
- Integrators get a safe key-generation and message-encoding surface instead of inventing one.
- The performance roadmap can proceed safely because Decision 1–4 gates pin behaviour.

### Harder

- EdDSA verify grows by roughly 70 constraints (well-formedness + cofactored equation) before
  Decision 7 claws back several thousand.
- The domain-separation change and the canonical `kQuotient` width are **breaking**: proofs,
  verification keys, and witnesses produced under the current gadget will not verify against
  the fixed circuit. Acceptable because nothing in production depends on it yet; it would not
  be acceptable later, which is why this is sequenced now.
- More test-maintenance surface (negative in-circuit tests, constraint-count pins).

### Neutral

- No on-chain verifier change. All Jubjub work stays inside the SNARK, as ADR-0016 §Risks 6
  established.
- The ADR-0016 architecture decisions (Jubjub over BabyJubJub, extended coordinates, Poseidon
  challenge) are unaffected; only the enforcement boundary and the cost estimates change.

## Test Plan

- **Soundness regressions (must fail before the fix, pass after):**
  - The extended-coordinate forgery: arbitrary `R.u`/`R.v`, solved `R.z`/`R.t`, an unsigned
    message, and a valid-looking `S` — assert the witness calculation now throws.
  - The challenge alias: `(q + 8, kModL + δ)` for a genuine signature — assert rejected.
  - Identity public key with `R = [r]·G`, `S = r` — assert off-circuit `verify` returns false.
  - A curve-valid but torsion-bearing `pk` — assert in-circuit and off-circuit agree.
- **Well-formedness gates:** off-curve `(u, v)` with `Z = 1`; `T != u·v` with `Z = 1`; `Z = 0`;
  a rescaled `(λU, λV, λZ, λT)` representation of a valid point — each asserted rejected.
- **Input validation:** `sign` with `sk = 0`, `sk = l`, `sk > l`; `sign`/`verify` with
  `msg >= p`; `Keypair.toString()` asserted not to contain the secret scalar's digits.
- **Key generation:** `generateKeypair` output asserted in `[1, l)` over many samples, and
  `pk` asserted in-subgroup and non-identity.
- **Parameter pinning (ADR-0016 Risk 4 debt):** `a` is a QR and `d` is a non-QR; `d` re-derived
  as `-10240/10241 mod p`; `[8]·FULL_GENERATOR == SUBGROUP_GENERATOR`; `l` and `p` primality.
- **Cost pinning:** a test asserting compiled constraint counts for `add`, `doubled`,
  fixed-base 252-bit, variable-base 252-bit, Pedersen 252-bit, and EdDSA verify, so
  Decision 7 changes are visible and no regression sneaks in.
- **Regression:** existing `JubjubPointTest` (including the 16 zkcrypto serialization
  vectors), `EdDSAJubjubTest`, `PedersenTest`, `InCircuitJubjubTest`,
  `InCircuitEdDSAJubjubTest`, and `ZkGadgetAdaptersTest` must stay green throughout.

## Implementation Plan

| # | Scope | Gate |
|---|---|---|
| **M1** | Land the four soundness regression tests from the Test Plan as failing tests, then Decisions 1 and 2 (well-formedness asserts, `witnessAffine` binder, 3-bit `kQuotient`, `Z == 1` on hashed points) | All four regressions flip to passing; existing suite green |
| **M2** | Decision 3 (identity `pk` rejection, `sk`/`msg` range checks, `Keypair` redaction, `generateKeypair(SecureRandom)`, `hashToField`) | Input-validation and key-generation gates green |
| **M3** | Decision 4 (cofactored in-circuit equation) and Decision 5 (domain separation); parameter-pinning tests | In-circuit and off-circuit accept/reject sets proven identical over a randomized corpus |
| **M4** | Decision 6 (ADR-0016 amendment, Javadoc and README corrections, constraint-count pins) | Documentation states measured numbers; no remaining claim contradicted by code |
| **M5** | Decision 7 performance work, in the listed order, each re-validated against M1–M3 gates | Fixed-base ≤ ~2k, EdDSA verify ≤ ~8k, all gates still green |

Per ADR-0016's pattern, a review pass runs at each milestone boundary before the next starts.
M1–M3 are prerequisites for using EdDSA-Jubjub or Pedersen in any value-bearing usecase; M4
and M5 are not.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| A caller builds `InCircuitJubjub.Point` from raw witness wires and forges proofs | Critical | Decision 1 moves the check into the gadget; M1 regression test pins it |
| The challenge alias is composed into a future protocol that binds `kModL` | High | Decision 2 makes the reduction canonical before any such composition exists |
| Identity or torsion-bearing public keys accepted off-circuit | High | Decision 3 and 4; randomized accept/reject equivalence corpus in M3 |
| Integrators roll their own key sampling or message encoding | High | Decision 3 ships both; README documents them as the supported path |
| Breaking change lands after a usecase depends on the current gadget | Medium | Sequence now, while `AnnotatedPedersenCommitment` is the only consumer |
| Performance work (M5) silently reintroduces a soundness gap | Medium | M1–M3 gates are hard prerequisites and re-run per M5 step |
| ~19k constraints per EdDSA verify limits circuit composition | Medium | Decision 7 targets ≤ ~8k; workable for Groth16 on BLS12-381 in the interim |
| Variable-time scalar multiplication in an issuer signing service | Medium | Accepted and documented (Decision 8); environment-specific review required for high-value issuers |

## References

- ADR-0014: W3C Verifiable Credential Circuit Support (motivation for in-circuit EdDSA)
- ADR-0015: Standards-compatible Poseidon for BLS12-381
- ADR-0016: Jubjub-in-Circuit for BLS12-381 Cardano Proofs (amended by this ADR)
- ADR-0021: BLS12-381 Implementation Review Outcomes and Hardening Posture (same review
  posture; constant-time contract precedent)
- ADR-0028: DSL Optimization and Hint Soundness (constraint-level soundness precedent)
- Hisil, Wong, Carter, Dawson — *Twisted Edwards Curves Revisited*, 2008
- RFC 8032 — *Edwards-Curve Digital Signature Algorithm (EdDSA)*
- zkcrypto/jubjub — <https://github.com/zkcrypto/jubjub>
- Zcash Sapling spec — <https://zips.z.cash/protocol/sapling.pdf> §5.4.8
