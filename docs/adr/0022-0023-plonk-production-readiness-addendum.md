# Addendum: ADR-0022 & ADR-0023 — PlonK Production-Readiness Gaps

## Status
Follow-up feedback — additions for ADR-0022 and ADR-0023 beyond the hardening
review already incorporated in `0022-0023-plonk-hardening-response.md`.

## Date
2026-06-28

## Purpose

The hardening review and Codex's incorporation made the two ADRs solid **design
specs**. This addendum captures what is still required to take the pure-Java
PlonK path from "ADR-complete" to "production-ready," focusing on items that
**neither updated ADR covers**. It also records two small tightenings within the
current ADR scope.

Verification context: the updated ADRs were read in full and the incorporation
is faithful. The cryptographically load-bearing wording is correct — VK cosets
are stated as "distinct permutation cosets" (0022 §1), infinity rejection is
correctly scoped so a zero-selector commitment may be infinity (0022 §1/§4),
`q`/`r` must be asserted equal to curve constants before use as a modulus
(0022 §4), and the on-chain ADR un-conflated the transcripts and removed the
infeasible 96-byte raw-byte derivation (0023 §2/§4). Codex's decision to retain
canonical-coordinate rejection is endorsed (cleaner boundary; defense in depth).

The single most important conclusion: the largest remaining gap is **trusted-setup
provenance and SRS consistency verification**, which on-curve/subgroup validation
does not cover and which neither ADR currently addresses. The follow-up decision
for bounded multi-public-input on-chain PlonK support and standing fuzzing /
differential CI gates is tracked in ADR-0024.

---

## Part 0 — Two tightenings within current ADR scope

- **0022 §1 — make the coset test membership-based.** "Distinct permutation
  cosets" is correct but easy to mis-implement as `k1 != k2 != 1`. The actual
  condition is `k1 ∉ ⟨ω⟩`, `k2 ∉ ⟨ω⟩`, and `k1·k2⁻¹ ∉ ⟨ω⟩` (the three cosets
  `H`, `k1·H`, `k2·H` must be disjoint). State the membership form so it is not
  reduced to value-distinctness.

- **0023 §4 — state the cross-component consequence of the compressed-point
  transcript.** Choosing a compressed-point transcript is not only an on-chain
  decision: the **off-chain prover and verifier must adopt the same transcript**,
  so existing snarkjs/gnark proofs will not verify on-chain. Make this explicit
  so no one assumes current proofs are reusable on-chain.

---

## Part A — Off-chain trusted setup (highest priority; not in either ADR)

ADR-0022 §4 treats `.ptau`/`.zkey` import as a *well-formedness* problem
(sections, primes, on-curve, subgroup membership). SNARK soundness also depends
on the SRS itself, and the following are unaddressed.

### A.1 SRS pairing-consistency self-check  — **High**

Curve + subgroup validation proves the imported points are valid group elements.
It proves **nothing** about whether they are consecutive powers of a single `τ`.
An imported SRS whose points are all on-curve and in-subgroup but are not a
consistent powers-of-tau sequence breaks KZG binding and therefore soundness.

**Decision to add (0022 §4):** after import and point validation, verify the SRS
is internally consistent before it is used to build a proving/verification key:

- Check `e([τ^i]₁, [1]₂) == e([τ^{i-1}]₁, [τ]₂)` across the powers, batched into
  one or two pairings via a random linear combination (Fiat-Shamir or a fresh
  `SecureRandom` challenge over the indices).
- Check the `[1]₁`, `[1]₂`, and `[τ]₂` anchors are the expected generators / are
  mutually consistent.

This is a standard ceremony-verification step. It is currently **absent** from
both importers (`PtauImporter`, `PlonKZkeyImporter`, and their BLS variants).

### A.2 Ceremony provenance and file-hash pinning — **High**

`PlonKSetup`/`PlonKSetupBLS381` consume an externally imported SRS with no
documented production source and no integrity pin.

**Decisions to add (0022 §4 + docs):**

- Pin the production `.ptau`/`.zkey` artifact by content hash; the importer
  should verify the file hash against a known-good value for production circuits
  and refuse unknown setup material outside an explicit dev/test path.
- Document the ceremony source and its trust assumption (≥1 honest participant,
  toxic waste destroyed). For **BLS12-381 specifically**, note that a legitimate
  universal PlonK SRS is scarce: the Ethereum KZG ceremony is structured for
  KZG/EIP-4844 and may not directly yield `[τ^i]₁` to the required circuit degree
  plus the Lagrange / `[τ]₂` material PlonK needs. The chosen source and any
  self-generated fallback must be stated, and self-generated SRS is trusted only
  as far as ZeroJ's own ceremony.
- Keep the existing dev single-party generation path explicitly non-production
  (already in 0022 §4); never persist or expose `tauScalar`.

**Implementation status for BLS12-381:** the `.ptau` and `.zkey` importers now
support caller-supplied SHA-256 pinning and reject mismatched artifacts before
parsing. The remaining production task is to choose the ceremony source and pin
the exact artifact hashes for each production circuit/release.

---

## Part B — Cross-cutting release gates for core crypto (not in either ADR)

### B.1 Independent cryptographic audit as a named release gate — **High**
A re-implemented PlonK verifier plus field/curve/pairing and transcript code
should pass a third-party cryptographic audit before it secures value. Add it as
an explicit gate in both ADRs' release criteria.

### B.2 Coverage-guided fuzzing of untrusted parsers — **High**
The planned hand-written negative tests are necessary but not sufficient for
parser memory-safety and availability. Add coverage-guided fuzzing (e.g. Jazzer
/ JQF) of `SnarkjsPlonkCodec`, `PtauImporter`, and `PlonKZkeyImporter`, run in CI
with a persisted corpus and a time/iteration budget, as a standing gate.

### B.3 Differential oracle as a standing gate — **Medium-High**
Beyond "more vectors," run ZeroJ-verify against snarkjs/gnark-verify over a
generated circuit corpus (multiple circuit shapes, multiple public inputs,
non-trivial copy constraints, and both accept and reject cases) and assert
identical verdicts on every input. This is the strongest practical assurance for
a re-implementation and should gate releases, not just exist as ad-hoc vectors.

### B.4 GraalVM native-image coverage for the pure-Java PlonK path — **Medium-High**
`zeroj-codec` and `zeroj-verifier-plonk` already have `META-INF/native-image`
configuration, while `zeroj-crypto` does not. The remaining production gap is
coverage and proof: the existing metadata must be reviewed for the full PlonK
parse/import/prove/verify path, and CI must include a native-image smoke test
that actually verifies a proof end-to-end. Without that, the "pure Java, no
native dependencies" property can still fail at native-image build or runtime.
Given the GraalVM target, add:

- reviewed/updated `reflect-config`/`resource-config` (or a
  `@RegisterForReflection`/`jackson-jr` approach) for the codec, verifier,
  importer, and any reflectively accessed types on this path.
- A native-image integration test that imports a VK, parses a proof, and runs a
  full verify, wired into CI.

---

## Part C — Off-chain prover ZK / secret handling (lower priority)

Confirmed good: blinding scalars are drawn from `SecureRandom`
(`PlonKProver.java:50`, `randomFr`), so zero-knowledge randomness is from a
CSPRNG. Add to 0022 §7 (side-channel contract):

- State that blinders **must** come from a CSPRNG, so the contract is explicit
  and cannot silently regress to a seeded `Random`.
- Acknowledge that secret `BigInteger`/Montgomery values (witness, blinders,
  dev-mode `tauScalar`) cannot be zeroized and are GC-copyable — an in-memory
  secret-lifetime limitation that sits alongside the existing variable-time note.

---

## Part D — On-chain positioning (complements ADR-0023)

- **Name Groth16-on-chain as the pragmatic production route today.** ADR-0023's
  go/no-go gate correctly allows deferring on-chain PlonK. Make explicit that
  Groth16-on-chain is already feasible/working (per `OnChainFeasibility`) and is
  the recommended path for value-bearing on-chain verification now, while
  PlonK-on-chain stays experimental until the budget/transcript gates pass.
- **Versioned domain separation.** Bind a transcript/format version tag into both
  the envelope and the Fiat-Shamir transcript so a future rule or transcript
  change cannot enable cross-version proof replay or confusion. This complements
  the envelope/material binding decision (0022 §3) and the transcript-profile
  pinning decision (0023 §2).

---

## Production-readiness checklist (proposed Definition of Done)

Off-chain pure-Java PlonK verifier:

- [x] All ADR-0022 boundary/availability decisions implemented for the
      BLS12-381 code path (point + scalar +
      VK-domain validation, resource bounds, envelope/material binding, typed
      errors).
- [x] BLS12-381 `.ptau`/`.zkey` importer hardened **and** SRS
      pairing-consistency check + file-hash pinning support in place (Part A).
- [x] Focused negative/malformed test gates green for BLS12-381
      prover/setup/importer/codec/off-chain verifier (0022 §6).
- [ ] Parser fuzzing in CI, corpus clean for the agreed budget (B.2).
- [ ] Differential oracle vs snarkjs/gnark green across the circuit corpus (B.3).
- [ ] GraalVM native-image metadata coverage reviewed/updated and smoke test
      verifies a proof end-to-end (B.4; explicitly deferred for now).
- [x] Side-channel + secret-handling contract documented (Part C).
- [ ] Production BLS12-381 ceremony source selected and exact `.ptau`/`.zkey`
      artifact hashes pinned for each value-bearing circuit/release.
- [ ] Independent cryptographic audit completed and findings closed (B.1).

On-chain PlonK validator:

- [x] Renamed/wrapped; `OnChainFeasibility.isFeasible` no longer fail-open
      (0023 §1).
- [x] One transcript profile pinned for the implemented Cardano profile
      (`zeroj-plonk-bls12381-cardano-v1-json`) with ZeroJ prover/verifier
      vectors (0023 §2).
- [x] Full KZG batch-opening predicate implemented and gated for the current
      one-public-input Cardano profile (0023 §3).
- [x] Transcript↔curve-encoding binding proven by hashing the canonical
      compressed G1 bytes that the validator also uncompresses for BLS builtins
      (0023 §4).
- [x] Strict datum/redeemer/params validation for the current one-public-input
      profile (0023 §5).
- [x] CPU / memory go/no-go gates measured and estimator corrected for the
      current profile (0023 §6).
- [x] Applied script-size / redeemer-size measurement for deployment packaging:
      the current one-public-input profile measures `5,283` applied script flat
      bytes and `733` proof redeemer CBOR bytes, both below the 16,384-byte
      inline limit.
- [x] Bounded MPI profile implemented as
      `zeroj-plonk-bls12381-cardano-mpi-v1-json` for 1 through 8 public inputs.
      The 8-input profile measures approximately `4.945B` CPU, `1.357M`
      memory, `5,608` applied script flat bytes, and `944` proof redeemer CBOR
      bytes.
- [x] Initial adversarial test suite green for wrong/extra public input,
      tampered commitment, and over-field evaluation scalar (0023 §7).
- [ ] Broader fuzzing and differential cross-implementation vectors for release
      assurance; see ADR-0024.

## References

- `docs/adr/0022-pure-java-plonk-hardening.md`
- `docs/adr/0023-onchain-plonk-verifier-hardening.md`
- `docs/adr/0022-0023-plonk-hardening-review.md`
- `docs/adr/0022-0023-plonk-hardening-response.md`
- `docs/adr/0024-plonk-release-gates-and-multi-public-input-profile.md`
- ADR-0021: BLS12-381 Implementation Review Outcomes and Hardening Posture
- `zeroj-crypto/src/main/java/com/bloxbean/cardano/zeroj/crypto/plonk/{PtauImporter,PlonKZkeyImporter,PlonKSetup,PlonKProver}.java`
- PlonK paper: <https://eprint.iacr.org/2019/953>
