# ADR-0021: BLS12-381 Implementation Review Outcomes and Hardening Posture

## Status
Proposed

## Date
2026-06-10

## Context

`zeroj-bls12381` (ADR-0018) is the shared pure-Java BLS12-381 primitive module:
tower fields (`Fp`/`Fp2`/`Fp6`/`Fp12` over `BigInteger` plus a Montgomery
`MontFp381`/`MontFp2_381`/`MontFr381` layer), G1/G2 affine and Jacobian arithmetic, the
optimal ate pairing, ZCash-format point codecs, RFC 9380 hash-to-curve, and a
`Bls12381Provider` SPI. It underpins the Groth16/PlonK verifiers (ADR-0012) and the CFRG
BBS implementation (ADR-0019), and must remain compatible with on-chain (Plutus CIP-0381)
and IETF semantics.

We performed a focused correctness/security/quality review of the module (manual read of
all source + tests, plus an adversarially-verified multi-agent pass that recomputed every
hardcoded constant with exact big-integer arithmetic and re-derived the field/curve/pairing
math). This ADR records what the review concluded and the decisions we are taking as a
result. It does **not** change the module's external architecture (that remains as decided
in ADR-0018/0019); it codifies a hardening posture and a set of gated follow-ups.

### What the review confirmed (no action beyond locking it in)

- **Constants are bit-exact.** `p`, `r`, `INV` for both fields, `R`, `R²`, the G1/G2
  generators (on-curve and in the prime-order subgroup), curve `b = 4`, twist `b' = 4(1+u)`,
  RFC 9380 `h_eff` cofactors, and the SSWU `Z`/`A'`/`B'` and isogeny coefficient tables all
  match canonical values.
- **Arithmetic is correct.** CIOS Montgomery multiply, carry/borrow propagation, the
  `Fp6`/`Fp12` tower, and the Jacobian `dbl-2009-l` / `add-2007-bl` formulas were verified.
  The Montgomery-ladder invariant `R1 − R0 = P` holds.
- **Pairing is correct.** The final exponent `(p²+1)(p⁴−p²+1)/r` composed with `f^(p⁶−1)`
  reduces to `(p¹²−1)/r`; the negative-`x` conjugation is the standard trick. Bilinearity and
  non-degeneracy were confirmed by direct computation.
- **Codecs and hash-to-curve are standards-correct.** Codecs match the ZCash known-answer
  vectors and enforce curve + prime-order-subgroup membership on the checked decoders;
  hash-to-curve matches the official RFC 9380 `QUUX-V01-CS02` G1/G2 RO+NU vectors.

There are **no correctness bugs on the normal factory/arithmetic code paths.**

### What the review surfaced as needing a decision

1. **Overstated constant-time guarantee on a path BBS+ uses for secrets.**
   `JacobianG1/G2BLS381.ctScalarMul` (reached via `PureJavaBls12381Provider.g1/g2SecretScalarMul`)
   is documented as preventing timing side-channels on secret scalars, but it is not
   constant-time: leading-zero scalar bits leave `r0 = INFINITY` and take `add`/`doublePoint`
   early-return fast paths (leaks MSB position), the Montgomery conditional subtraction
   branches on data, and bit selection is a secret-dependent branch over `BigInteger.testBit`
   (not a branchless select). `CfrgBbsCore` routes the BBS **secret signing key**, signature
   scalars, and undisclosed-message scalars through this path. ADR-0019 §5 already flagged the
   JVM path as "fixed-schedule … not a full constant-time guarantee"; the review confirms the
   gap is real and that the in-code documentation currently overstates it.

2. **Latent foot-guns behind public low-level APIs (not reachable on normal paths).**
   - `MontFp381.fromMontLimbs` is public and unchecked; feeding non-canonical limbs (≥ p)
     into `montMul` can violate the reduced-residue invariant and produce a silently wrong
     field element. The package-private `MontFr381.fromMontLimbs` has the same invariant
     shape and should be guarded defensively inside the field package.
   - `JacobianG1/G2BLS381.ctScalarMul` runs a fixed 256-bit ladder with no length guard, so a
     scalar ≥ 2²⁵⁶ is silently truncated to its low 256 bits. Masked today because the
     provider reduces mod `r` first, but the EC-level method is public.

3. **Pairing test coverage cannot detect a regression.** `BLS12381PairingTest` asserts only
   self-consistent identities (`e(P,Q)·e(−P,Q)=1`, conjugate pairs, `finalExp(1)=1`). These
   pass even for a degenerate constant-`1` pairing. There is no bilinearity, non-degeneracy,
   or known-answer assertion. The pairing is exercised end-to-end by the Groth16/PlonK
   verifier modules with real proof vectors, but this module does not independently lock it
   in. Related codec/test gaps: the compressed sign/sort bit (`0x20`) is never checked with a
   discriminating point, the G2 `ctScalarMul`↔`scalarMul` cross-check is absent (G1 has one),
   `Fp6` has no direct test and `Fp12` has only light property coverage, and the
   SHAKE-256/XOF hash-to-curve family + hand-rolled Keccak-f1600 have no direct
   `zeroj-bls12381` known-answer vector. BBS has indirect SHAKE-256 fixture coverage, but the
   primitive module still needs its own gates.

4. **Performance is correctness-first, not optimized.** The final exponentiation hard part
   uses a generic ~4500-bit `BigInteger` square-and-multiply over the non-Montgomery field
   (~100 ms/pairing, ~100× slower than an addition-chain + cyclotomic-squaring
   implementation); subgroup membership is a naive `[r]P` scalar-mul with a `modInverse` per
   step, run by `requireValid` on every checked deserialization and SPI add/negate/scalar-mul.
   The performance-critical pairing/codec paths run on the `BigInteger` field stack while the
   faster Montgomery stack is used only by `ctScalarMul` (dual-stack divergence).

## Decision

### 1. Treat the pure-Java provider as correctness-first, not side-channel-hardened

The pure-Java `zeroj-bls12381` provider is the portable, correctness-validated default for
**public-input** operations (verification, encoding, hashing, public scalar multiplication).
It is explicitly **not** a constant-time implementation. We will:

- Correct the Javadoc on `ctScalarMul` and `g1/g2SecretScalarMul` to state the real, limited
  guarantee (uniform operation schedule only; underlying field/point ops and bit access are
  variable-time on the JVM), removing language that implies timing-side-channel resistance.
- Keep `g1/g2SecretScalarMul` as the secret-scalar boundary (so callers route secrets through
  a named seam), but document that production secret-bearing workloads (BBS+ key generation
  and signing) should select the native `zeroj-blst` provider via
  `BbsProviders.withBlsProvider(...)`, which genuinely overrides these operations.
- Defer a genuinely constant-time pure-Java path (branchless conditional select, fixed-length
  limb scalar, branchless field reduction) to a future ADR; it is not required for the
  verifier-first product and is hard to guarantee under JIT/GC. This reaffirms and tightens
  ADR-0019 §5.

### 2. Guard the public low-level foot-guns

- `MontFp381.fromMontLimbs` (and the package-private `MontFr381` equivalent) must
  canonicalize or reject non-reduced inputs so the `< modulus` invariant every other path
  relies on always holds.
- `JacobianG1/G2BLS381.ctScalarMul` must reduce the scalar mod `r` at entry, or reject
  scalars with `bitLength() > 256`, so the ladder cannot silently truncate.

These are defensive corrections to internal/SPI-adjacent APIs; no public verifier behavior
changes.

### 3. Make pairing correctness a locked-in test gate

Add to `zeroj-bls12381` the tests that pin pairing correctness independently of the verifier
modules: non-degeneracy (`e(G1,G2) ≠ 1`), `e(G1,G2)^r = 1`, bilinearity over non-trivial
scalars (`e([a]G1,G2) = e(G1,G2)^a`, `e([a]G1,[b]G2) = e(G1,G2)^{ab}`), and at least one
hardcoded `e(G1,G2)` Fp12 regression vector in ZeroJ's tower representation. The current
Fp12 vector is self-pinned from the reviewed implementation; an externally sourced
blst/zkcrypto coefficient vector should replace or corroborate it if a compatible
serialization/layout is added. Add a discriminating compressed sign-bit (`0x20`) round-trip
test, a G2 `ctScalarMul`↔`scalarMul` cross-check, direct `Fp6`/`Fp12` property tests, and a
SHAKE-256/Keccak known-answer vector. These become release gates for the module.

### 4. Sequence performance hardening after correctness is locked

Performance work — addition-chain + cyclotomic-squaring final exponentiation, endomorphism-
based (GLV/ψ) subgroup checks, hoisting the recomputed hard-exponent constant, dropping the
redundant `requireValid` after cofactor clearing, and converging the dual field stacks — is a
post-correctness roadmap item, not a release blocker. It must be done only after the Decision
3 gates exist, and re-validated against the Groth16/PlonK real-proof vectors. The currently
unused `FROBENIUS_COEFF_X/Y` constants in `BLS12381Pairing` are either wired into the
optimized final exponentiation or removed as dead code at that time.

### 5. Accept the remaining items as documented, not blocking

The naive-but-correct subgroup check, the dual field stack, the duplicated `r` literal, and
the over-broad `reflect-config.json` are accepted as-is for the current release; they are
quality/performance items tracked for the hardening pass, not correctness or security
defects.

## Consequences

### Easier
- Downstream protocols get an explicit, honest security contract: pure Java for public-input
  verification; native `blst` for secret-bearing operations.
- A future refactor (notably the addition-chain final exponentiation) can proceed safely
  because pairing correctness is pinned by bilinearity/non-degeneracy/KAT tests.
- Public low-level misuse (`fromMontLimbs`, over-large `ctScalarMul`) fails loudly instead of
  producing silently wrong results.

### Harder
- BBS+ production guidance now has an explicit provider-selection requirement for secret-key
  workloads, which callers must follow.
- The module gains additional test-maintenance surface (pairing KAT, SHAKE KAT, tower tests).

### Neutral
- No external API or on-chain verifier behavior changes; the verifier-first architecture
  (ADR-0001) and crypto/policy separation (ADR-0006) are unaffected.
- The performance roadmap is acknowledged but intentionally deferred.

## Test Plan

- **Pairing gates:** non-degeneracy, `e^r = 1`, bilinearity for several scalars, and a
  hardcoded `e(G1,G2)` Fp12 regression vector. Sanity-check that these fail against an
  intentionally degenerate pairing before committing. Prefer an external blst/zkcrypto
  coefficient vector when a compatible Fp12 serialization/layout is available.
- **Codec gate:** compress `P` and `−P`, assert the encodings differ only in `0x20` and each
  decodes to the correct point; flip `0x20` manually and assert negation.
- **Foot-gun gates:** `fromMontLimbs` on limbs ≥ p is rejected/canonicalized; `ctScalarMul`
  on a scalar ≥ 2²⁵⁶ is rejected or reduced (not silently wrong).
- **Coverage:** G2 `ctScalarMul`↔`scalarMul` equality; `Fp6`/`Fp12` mul/square/inverse
  property + cross-validation tests; a SHAKE-256/Keccak and a real `hashToScalar` KAT.
- **Regression:** Groth16/PlonK verifier module tests (real proof vectors in
  `zeroj-test-vectors`) and the BBS provider conformance suite must stay green after any
  Decision 2/4 change.

## Implementation Plan

1. Add regression tests for the confirmed security gates before changing behavior:
   pairing non-degeneracy, `e(G1,G2)^r = 1`, bilinearity, a hardcoded `e(G1,G2)` Fp12
   regression vector, the compressed sign/sort-bit flip, G2 `ctScalarMul`↔`scalarMul`,
   `ctScalarMul(2^256 + 1)`, and a fixed non-canonical `MontFp381.fromMontLimbs`
   multiplication case.
2. Add the `fromMontLimbs` canonicalization/rejection and `ctScalarMul` length guard
   (Decision 2). Prefer rejecting non-reduced Montgomery limbs and rejecting EC-level
   `ctScalarMul` scalars with `bitLength() > 256`; the SPI provider already reduces modulo
   `r` before calling the EC-level method.
3. Correct the constant-time Javadoc/contract and document the blst-for-secrets guidance
   (Decision 1); cross-reference from `zeroj-bbs`.
4. Add the remaining primitive coverage (`Fp6`/stronger `Fp12`, SHAKE/XOF hash-to-curve,
   direct SHAKE/Keccak expander KATs) (Decision 3).
5. Schedule the performance hardening (Decision 4) as a separate, gated effort after the
   correctness/security gates are green.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| Callers assume the pure-Java secret-scalar path is constant-time | High | Correct the Javadoc/contract (Decision 1); route BBS+ secret workloads to `zeroj-blst`; require an environment-specific side-channel review for high-value deployments |
| A future pairing refactor silently breaks correctness | High | Land the bilinearity/non-degeneracy/KAT gates (Decision 3) before any optimization (Decision 4) |
| Public `fromMontLimbs`/`ctScalarMul` misuse yields silently wrong results | Medium | Canonicalize/guard inputs (Decision 2) |
| Performance (~100 ms/pairing) limits multi-pairing verification throughput | Medium | Addition-chain + cyclotomic-squaring final exp and endomorphism subgroup checks on the deferred roadmap (Decision 4) |
| Test-maintenance burden grows | Low | KATs are static vectors; tower/codec tests are small and stable |

## References

- ADR-0001: Verifier-First Architecture
- ADR-0006: Separation of Crypto and Policy Verification
- ADR-0012: Pure Java Provers for Groth16 and PlonK
- ADR-0018: Shared BLS12-381 Primitives and Optional WASM Provider
- ADR-0019: CFRG BBS Pure Java and Optional WASM Providers (see §5, constant-time boundary)
- RFC 9380 hash-to-curve: <https://www.rfc-editor.org/rfc/rfc9380>
- CIP-0381 (Plutus BLS12-381 builtins): <https://cips.cardano.org/cip/CIP-0381>
- ZCash BLS12-381 serialization: <https://github.com/zkcrypto/bls12_381>
