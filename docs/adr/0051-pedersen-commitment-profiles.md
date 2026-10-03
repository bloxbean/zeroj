# ADR-0051: Pedersen commitment profiles — Jubjub hardening, vector commitments and a G1 on-chain track

## Status
Proposed — design only. No implementation exists for any decision below. Awaiting
maintainer review. Two decisions are R3 and carry their own gates before their milestones
can start: D5 (vector-profile generator derivation) needs its normative spec reviewed, and
D7 (G1 sigma-proof track) has an **escalated conflict between the pinned references and the
Cardano execution environment** that this ADR does not resolve.

This ADR changes no maturity claim. The ADR-0037 production-readiness table remains
authoritative: the in-circuit Pedersen gadgets stay "Ready\*, pending external review" and
off-circuit secret-bearing generation stays offline/isolated only (ADR-0038).

## Date
2026-10-03

## Risk classification
- **R2:** D1 (normative spec of the existing profile), D2 (hiding-safe API), D3 (homomorphic
  building blocks, subgroup assertion, canonical decoding), D4 (public-input encoding).
  These change validation and circuit API at a security boundary but introduce no new
  primitive.
- **R3:** D5 (generator derivation for a new profile) and D7 (sigma-protocol relations and the
  Fiat–Shamir transcript for G1 commitments). Both define curve points or challenge bytes that
  binding and soundness depend on.

## Context

### What already exists

ZeroJ already implements a two-base Pedersen commitment on Jubjub, built under ADR-0016 M4
and hardened by ADR-0037/0038/0039:

```
C(v, r) = [v]·G + [r]·H        over the prime-order subgroup of Jubjub, order l
```

| Piece | Location | State |
|---|---|---|
| Off-circuit `commit` / `verify` | `zeroj-circuit-lib` `jubjub/PedersenCommitment` | Algebra ready\*; `commit` is variable-time `BigInteger`, offline/isolated only (ADR-0038) |
| Low-level gadget | `jubjub/InCircuitPedersen` | 3,020 constraints at two 252-bit scalars (measured); proves the represented bit-vector residues, does **not** assert `< l` |
| Annotation adapter | `zk/ZkPedersen` (`commit`, `commitBits`, `verifyOpening`) | Ready\* pending external review; asserts both scalars `< l` |
| Fixed-limb generation candidate | `jubjub/HardenedPedersen` (package-private) | ADR-0039 M9 candidate; its own timing/platform/external gates |
| Point toolkit | `InCircuitJubjub` (add, double, select, windowed fixed-base and variable-base scalar mul, `witnessAffine`), `JubjubPoint` (encode/decode, negate, subgroup check) | Present |

`G` is `JubjubPoint.SUBGROUP_GENERATOR`. `H` is derived by a Poseidon (ADR-0015, `t = 3`)
try-and-increment from the domain tag `"zeroj.pedersen.v1.H"`, cofactor-cleared, and pinned
by a fixture in `PedersenTest`. The current tests (`PedersenTest` 18, `HardenedPedersenTest`
5, `ZkGadgetAdaptersTest` 28) pass.

The scheme is not the gap. What is missing is the layer that lets applications use it
safely: hiding guard rails, homomorphic operations, multi-value commitments, independent
evidence for the generators, and a path the chain can check natively.

### Why two curves

- **In-circuit, Jubjub is the right curve.** Its base field is the BLS12-381 scalar field, so
  point arithmetic is native in a BLS12-381 Groth16/PlonK circuit. A Pedersen commitment on
  BLS12-381 G1 inside the same circuit needs 381-bit base-field arithmetic emulated over a
  255-bit field, which costs orders of magnitude more constraints.
- **On-chain, G1 is the right curve.** Plutus V3 has BLS12-381 G1 builtins (CIP-0381) and no
  Jubjub builtins. The chain sees a Jubjub commitment only as Groth16 public inputs and cannot
  add two of them natively. `BbsProofVerify` already runs a G1 sigma-protocol verification
  on-chain (about 2.4×10⁹ CPU for its 5-message profile), so the G1 path is demonstrated.

Neither curve substitutes for the other. An application that needs both in-circuit
statements and on-chain homomorphism over the same value needs a bridge, which is out of
scope here.

### Findings

- **F1 — Blinding width is not enforced, and our examples teach narrow blindings.**
  `ZkPedersen` accepts any declared blinding width. `AnnotatedPedersenCommitment`
  (`zeroj-integration-tests`) uses a 16-bit blinding, `zeroj-circuit-lib/README.md` shows
  `ZkPedersen.commit(zk, value, blinding, 64)`, and `ZkGadgetAdaptersTest` uses 16- and 8-bit
  blindings. A `k`-bit blinding and a `j`-bit value are recovered from a public commitment by
  enumerating `2^(j+k)` candidates: trivial at 16+16 bits, within reach of a well-resourced
  attacker at 64 bits. A circuit that declares a narrow blinding makes hiding impossible no
  matter how the committer samples.
- **F2 — No in-circuit negation or subtraction.** Balance relations (`Σ inputs − Σ outputs`)
  need them. Negation on twisted Edwards is linear and costs nothing, but there is no API.
- **F3 — The in-circuit subgroup assertion is package-private.**
  `InCircuitEdDSAJubjub.assertInPrimeOrderSubgroup` exists for `verifyStrict`. A circuit that
  combines commitments it did not compute (another party's commitment, a prior-state
  commitment) cannot reach it.
- **F4 — No safe off-circuit decoder or blinding sampler.** `JubjubPoint.fromBytes` rejects
  non-canonical and off-curve encodings but explicitly does not check subgroup membership.
  There is no `PedersenCommitment`-level decoder that does, and no sampler for a uniform
  blinding in `[0, l)`.
- **F5 — `H` has no independent evidence.** The `H` fixture was produced once by the code under
  test. ADR-0016 M6 ("consolidated cross-verification suite") never landed. The derivation is
  ZeroJ-specific, so no external vector exists; only an independent reimplementation can
  provide evidence.
- **F6 — No multi-value commitment and no G1 track.** Committing to several values at once
  needs several independent bases. On-chain homomorphism needs G1.
- **F7 — Downstream: the `zeroj-usecases` private-voting demo leaks every vote.** Each ballot is
  stored as `Poseidon(vote, nullifier)` and the nullifier is public on-chain, so anyone can
  recover a vote by computing both candidates. `TallyService` does exactly that to tally,
  while the demo README says the proof reveals nothing about how anyone voted. Pedersen hiding
  alone does not fix this: a tally needs someone to learn the sum of the blindings. The fix is a
  ballot protocol and is out of scope here (D8). It is recorded because it is the most
  visible motivation for this ADR.

## Threat model and trust assumptions

- **Untrusted:** the prover and every witness value; commitment points received from other
  parties (as bytes or as public inputs); openings presented for verification; redeemer data
  on-chain.
- **Secret:** the committed value when the application hides it, and every blinding scalar.
  Secret-bearing off-circuit generation keeps the ADR-0038 restriction: variable-time Java is
  approved only for offline or isolated use. The in-circuit gadgets emit constraints and do no
  secret-dependent host arithmetic.
- **Binding** is computational. It rests on the discrete-log problem in the prime-order
  subgroup and on no party knowing a discrete-log relation between the bases. It binds the
  **residue modulo `l`**, not the integer.
- **Hiding** is perfect when `r` is uniform in `[0, l)` and independent of everything else.
  It is a property of the honest committer's sampling. A circuit cannot enforce randomness; it
  can only make full-entropy blindings representable and refuse layouts that cannot hide.
- **No trusted setup.** The bases are nothing-up-my-sleeve outputs. The Groth16/PlonK setup
  for circuits that use them is unchanged (ADR-0031 for production keys).
- **Out of scope:** application authorization, replay protection, nullifiers and
  `ScriptContext` binding (ADR-0006). A valid commitment or opening proof authorizes nothing.

## Pinned normative references

- T. P. Pedersen, *Non-Interactive and Information-Theoretic Secure Verifiable Secret
  Sharing*, CRYPTO '91 — the commitment scheme and its binding/hiding argument.
- *Zcash Protocol Specification*, version v2026.7.0 [NU6.2], §5.4.9.5 "Group Hash into
  Jubjub" (`GroupHash^J`, `FindGroupHash^J`, the URS) and the Jubjub `abst_J`/`repr_J`
  encoding. The exact build string and the `zcash/zips` commit are recorded in the D5 spec at
  M3 entry.
- ZIP 216, *Require Canonical Jubjub Point Encodings*.
- `zcash/sapling-crypto` `src/constants.rs` — `GH_FIRST_BLOCK`
  (`"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0"`), the BLAKE2s
  personalisations (`Zcash_cv`, `Zcash_PH`, `Zcash_G_`, `Zcash_H_`, `Zcash_J_`, …) and the
  derived generator constants used as known answers in D5. The crate version and commit are
  pinned at M3 entry.
- RFC 7693 — BLAKE2s-256 with personalisation, and its test vectors.
- RFC 9380 — `hash_to_curve`, suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`.
- CIP-0381 — Plutus BLS12-381 builtins, including `bls12_381_G1_hashToGroup`.
- CIP-0133 — `bls12_381_G1_multiScalarMul`, scheduled with protocol version 11 ("van
  Rossem"). Its enactment on the target network must be confirmed before any design relies on
  it.
- draft-irtf-cfrg-sigma-protocols-03 (2026-08-17), *Sigma Proofs for Linear Relations* —
  including the `PedersenOpening` relation and AND-composition (§3.4) and the
  `sigma-proofs_Shake128_BLS12381` ciphersuite (§8). OR and threshold composition are
  explicitly outside this document (§1).
- draft-irtf-cfrg-fiat-shamir-03 (2026-08-17) — the duplex-sponge Fiat–Shamir transformation,
  `DeriveSessionID`, and its only instantiations: SHAKE128 (§9.1) and TurboSHAKE128 (§9.2).
- draft-irtf-cfrg-bbs-signatures-10 — already pinned by `zeroj-bbs`; its `hash_to_scalar` is
  ported on-chain as `BbsHashToScalar`.
- D. Bernhard, O. Pereira, B. Warinschi, *How not to Prove Yourself: Pitfalls of the
  Fiat–Shamir Heuristic*, ASIACRYPT 2012 — the strong-Fiat–Shamir requirement in I9.
- Internal: ADR-0006, ADR-0015, ADR-0016, ADR-0037, ADR-0038, ADR-0039, ADR-0044.

## Decision

### D1 — Freeze and specify the existing profile as `pedersen-jubjub-v1` (R2)

The existing two-base scheme becomes the named, frozen profile `pedersen-jubjub-v1`, specified
normatively in `docs/specs/pedersen-jubjub-v1.md`. The spec records exactly what is
implemented, without changing any point or commitment value:

- `G = JubjubPoint.SUBGROUP_GENERATOR`, by pinned affine coordinates.
- `H`: `a = OS2IP(UTF-8("zeroj.pedersen.v1.H")) mod p`; for `counter = 0, 1, …`, take
  `v = Poseidon_{BLS12-381, t=3}(a, counter)`, solve the curve equation for `u²`, skip
  non-residues, take the smaller of `±u` as an integer in `[0, p)`, multiply by the cofactor
  8, and skip the identity. `H` is the first success, recorded by pinned coordinates.
- Scalar semantics: binding to residues mod `l`; the `ZkPedersen` layer asserts both scalars
  `< l`.
- Canonical byte encoding (D3) and public-input encoding (D4).
- The identity-point policy for received commitments, stated explicitly.

`H` gets an independent reproduction: a standalone script using the ADR-0015 Sage reference
Poseidon, not ZeroJ code, must reproduce the pinned coordinates.

### D2 — Hiding-safe API (R2)

- `ZkPedersen.commit`, `commitBits` and `verifyOpening` require the blinding at **full width:
  a declared width of exactly 252 bits**, with the existing `< l` assertion. Narrower widths
  are rejected at circuit-definition time with a message that explains why. The value keeps
  its own caller-chosen width (1–252), which is where the cost savings belong.
- The `scalarBits` overloads are removed. Once the blinding is always 252 bits they constrain
  nothing, and the shared-narrow-width form is how F1 happened.
- `InCircuitPedersen`'s public overloads apply the same blinding rule, as defense in depth.
  There is no escape hatch until a concrete use case justifies one. A commitment that does not
  need hiding should use Poseidon or `[v]·G`.
- A blinding wire that is directly a public input or a circuit constant is rejected, using the
  same provenance resolution as `CircuitAPI.requirePublicOrConstant`, inverted. This is a
  guard rail, not a guarantee: a blinding *derived* from public data is not detected and stays
  the caller's responsibility.
- Off-circuit: `PedersenCommitment.randomBlinding(SecureRandom)` draws 64 bytes from the CSPRNG
  and reduces mod `l` (statistical distance from uniform below 2⁻²⁵⁹; the same width as Zcash
  `ToScalar`, wider than the 48 bytes RFC 9380 `hash_to_field` would use for a 252-bit field at
  128-bit security). The reduction is variable-time `BigInteger` and
  inherits the ADR-0038 offline restriction; a fixed-limb version belongs to the ADR-0039 M9
  candidate.
- Every example, README snippet, guide page and test that uses a narrow blinding is corrected
  in the same milestone.

### D3 — Homomorphic building blocks and validation (R2)

- `InCircuitJubjub.negate` (`(−U, V, Z, −T)`, zero constraints), plus `ZkJubjubPoint.negate()`
  and `subtract(...)`.
- The subgroup assertion is promoted to `InCircuitJubjub.assertInPrimeOrderSubgroup` and
  `ZkJubjubPoint.assertInPrimeOrderSubgroup(zk)`. EdDSA keeps using it. It costs one 252-bit
  variable-base multiplication by `l`, roughly 5,500 constraints by the gap between
  `verifyStrict` and `verifyWithRegisteredKey`; M2 measures it directly.
- `PedersenCommitment.decode(byte[])`: canonical decoding (`v < p`; `u = 0` requires sign bit
  0, per ZIP 216) plus prime-order subgroup membership, applying the D1 identity policy.
- The wrap rule (I6) is written into the spec and the gadgets guide, with a worked balance
  example.

### D4 — Public-input encoding (R2)

A Jubjub commitment is exposed to a verifier as **two public inputs, affine `(u, v)`, in that
order**, bound with `assertAffineEquals`. Jubjub's base field is the BLS12-381 scalar field, so
the affine coordinates are already canonical field elements. The 32-byte compressed form does
not fit in one field element. This is current practice (`AnnotatedPedersenCommitment`);
the ADR makes it the profile.

### D5 — Vector profile `pedersen-jubjub-vector-v1` (R3, spec-gated)

```
C(v_0..v_{n-1}, r) = Σ_{i<n} [v_i]·G_i + [r]·H_V,      1 ≤ n ≤ N_MAX
```

- **Every base comes from Zcash `FindGroupHash^J`** with the 8-byte personalisation
  `"ZeroJ_PV"`: `G_i = FindGroupHash^J("ZeroJ_PV", I2LEOSP_32(i))` (the same indexing Zcash
  uses for its Pedersen-hash generators) and `H_V = FindGroupHash^J("ZeroJ_PV", "r")`.
  `FindGroupHash` appends a one-byte counter, hashes `URS || M || [j]` with BLAKE2s-256 under
  the personalisation, decodes with `abst_J`, multiplies by the cofactor and rejects the
  identity.
- **`N_MAX = 16`** is proposed: enough for multi-asset bundles and attribute vectors while
  keeping the pinned table small. Raising it later is additive, because existing bases never
  change.
- **No runtime hash dependency.** Main code ships the bases as pinned constants. Tests
  re-derive them with an independent BLAKE2s (BouncyCastle `Blake2sDigest`, already a
  `zeroj-circuit-lib` test dependency) and ZeroJ's decoder. The same derivation must reproduce
  Zcash's published generators bit-for-bit, which proves our `FindGroupHash` matches the
  spec rather than matching itself.
- In-circuit: one windowed fixed-base multiplication per value at its own width, a full-width
  blinding leg under D2, and an addition chain. A `ZkPedersen` vector entry point mirrors D2's
  rules.
- The two-base v1 profile is untouched. `pedersen-jubjub-vector-v1` with `n = 1` is a
  different profile with different bases, by design.
- `docs/specs/pedersen-jubjub-vector-v1.md` must be written and reviewed before any code
  (M3 gate).

### D6 — Off-circuit secret-bearing generation (no change)

The vector profile's off-circuit `commit` uses the same restricted path as v1. Promotion of a
constant-time path stays governed by ADR-0039 M9. This ADR approves no new online secret path.

### D7 — G1 commitments with sigma proofs (R3, **open — escalated**)

**Purpose.** Commitments the chain can combine and check natively: running totals or tallies
held in a datum, opening and equality proofs verified by a validator without a SNARK, and blind
credential issuance alongside `zeroj-bbs`.

**Agreed direction (subject to review):**

- Bases from RFC 9380 `hash_to_curve` (`BLS12381G1_XMD:SHA-256_SSWU_RO_`) with a ZeroJ DST
  shorter than 255 bytes. On-chain `bls12_381_G1_hashToGroup` can reproduce them, which also
  gives an off-chain/on-chain differential check.
- Relations from draft-irtf-cfrg-sigma-protocols-03: `PedersenOpening`, equality of committed
  values, and linear combinations. OR-composition (for example, 0/1 bit proofs) is outside
  the -03 draft and would need its own pinned reference.
- Pure-Java and blst providers must agree byte-for-byte (ADR-0044 provider rules).

**The conflict.** The draft's Fiat–Shamir transformation (draft-irtf-cfrg-fiat-shamir-03) is
instantiated only with SHAKE128 or TurboSHAKE128. Plutus V3 provides `sha2_256`, `sha3_256`,
`blake2b_224`, `blake2b_256`, `keccak_256` and `ripemd_160`, but no SHAKE XOF and no Keccak
permutation. **A
CFRG-conformant proof cannot be verified on-chain natively.** The options:

| Option | What it means | Cost |
|---|---|---|
| (a) Off-chain only | Implement the CFRG ciphersuite exactly; no on-chain verification | Loses the main reason for the track |
| (b) ZeroJ Cardano ciphersuite | CFRG -03 relations and protocol; challenge from BBS-10 `hash_to_scalar` (`expand_message_xmd` SHA-256, already on-chain in `BbsHashToScalar`) over a strong-FS transcript (I9) | A composition no spec covers; needs external cryptographic review before any value-bearing use |
| (c) Defer | Wait for a SHA-2-based duplex instantiation in the CFRG drafts or a SHAKE builtin on Plutus | No on-chain sigma proofs for now |

The ADR leans towards (b) because both halves are already reviewed paths, off-chain and
on-chain. **It does not decide.** Per AGENTS.md, a conflict between the references and the
platform is escalated, not resolved in code. M5 and M6 do not start until the maintainers
choose an option and, for (b), an external reviewer accepts the transcript spec.

### D8 — Out of scope (each needs its own ADR)

- A private-ballot protocol (exponential ElGamal with tally decryption and threshold keys, in
  the line of Cramer–Gennaro–Schoenmakers 1997) and the `zeroj-usecases` private-voting fix
  (F7). This ADR supplies the primitives it would use.
- The Pedersen-sum Merkle tree (ADR-0016 §7) for proof of reserves with hidden liabilities.
- Bulletproofs-style range proofs on G1. Range proofs on Jubjub commitments stay in-circuit,
  where a `k`-bit value is range-checked by its own decomposition.
- A Pedersen *hash* (Sapling-style). It is not planned; Poseidon is the hash for circuits.
- A bridge proving that a Jubjub commitment and a G1 commitment open to the same value.

### Alternatives considered

- **Leave the API permissive and document the blinding rule (D2).** Rejected: F1 shows the
  repository's own examples get it wrong; documentation alone has already failed.
- **Re-derive v1 `H` with `FindGroupHash` for uniformity.** Rejected: it changes every existing
  commitment and verification key for no security gain. v1 is frozen and gets independent
  evidence instead (D1).
- **Extend the Poseidon try-and-increment to vector bases.** Rejected for D5: it is
  ZeroJ-specific, so no external known answers exist. `FindGroupHash` has a pinned spec,
  external constants and an independent implementation.
- **Elligator 2 / an RFC 9380-style suite for Jubjub.** Rejected: there is no standardised
  Jubjub suite, so ZeroJ would be choosing curve-mapping parameters itself.
- **Reuse v1 `G` and `H` inside the vector profile.** Rejected: mixing two derivations inside one
  profile makes the "no known relation" argument harder to audit.
- **Put G1 commitments inside the SNARK.** Rejected: non-native arithmetic cost (see Context).

## Security invariants

- **I1 — Bases.** Every base of every profile is in the prime-order subgroup, is not the
  identity, is pairwise distinct from the others, and is produced by the profile's published
  procedure from its published domain string. No base is defined as a known multiple of
  another.
- **I2 — Scalars.** At the `ZkPedersen` layer every scalar leg is constrained `< l`; value
  widths are declared and ≤ 252.
- **I3 — Hiding representability.** No public API layer accepts a blinding narrower than 252
  bits, or a blinding wired directly to a public input or a constant.
- **I4 — Subgroup.** Every point a gadget treats as a commitment is (a) computed in-circuit
  from profile bases, (b) witnessed with `witnessAffine` and asserted in the prime-order
  subgroup in-circuit, or (c) a public input whose subgroup membership the off-chain verifier
  checks before acceptance. On-chain consumers cannot do (c) for Jubjub at practical cost (no
  Jubjub builtins) and must use (a) or (b).
- **I5 — Canonical encoding.** The off-circuit decoder accepts exactly one encoding per point
  and enforces subgroup membership. The public-input form is affine `(u, v)`.
- **I6 — Wrap.** Homomorphic relations hold mod `l`. Any balance or sum check bounds each
  value to `k` bits and the term count to `n` with `n·2^k < l`, or range-checks the sum, so a
  relation mod `l` implies the same relation over the integers.
- **I7 — Versioning.** A change to a domain string, derivation or base is a new profile
  version. v1 bases are frozen.
- **I8 — Secrets.** No new secret-bearing `BigInteger` path is approved for online use. New
  samplers and generators inherit ADR-0038.
- **I9 — Strong Fiat–Shamir (G1).** The challenge binds a session identifier, every base, the
  complete statement and every prover commitment. Weak Fiat–Shamir is forbidden.
- **I10 — Provider and platform parity (G1).** Pure Java and blst produce identical bases and
  verdicts, and on-chain `hashToGroup` reproduces the off-chain bases.

## Consequences

- Applications get a hiding-safe default and the operations they need (subtract, subgroup
  assertion, safe decode, blinding sampler) without touching point internals.
- Multi-value commitments arrive with external known answers instead of self-derived
  fixtures.
- The G1 track is explicitly blocked on a decision instead of being built on an unreviewed
  transcript.
- Circuits that declared narrow blindings stop compiling. That is intended.
- Costs: a subgroup assertion adds about 5,500 constraints when a circuit must consume a
  commitment it did not compute; a vector commitment costs roughly one fixed-base
  multiplication per value at that value's width.

## Compatibility

- **v1 commitments are bit-identical.** `G`, `H`, the golden vector in `PedersenTest` and the
  byte encoding do not change.
- **Circuit API break (pre-1.0):** `ZkPedersen` `scalarBits` overloads are removed, and narrow
  or public/constant blindings are rejected. Circuits that used narrow blindings get new
  constraint systems and must regenerate keys. Circuits that already used 252-bit blindings and
  the two-argument `commit` keep identical constraints. A migration note ships with M1.
- The vector profile, the G1 track and every new method are additive.
- No on-chain verifier changes for M0–M4. M6 adds a new JuLC library and changes no existing
  script hash.

## Implementation milestones

Each milestone is its own PR with a review gate. M3, M5 and M6 have entry gates.

- **M0** — `docs/specs/pedersen-jubjub-v1.md` (D1) and the independent `H` reproduction script.
- **M1** — D2: hiding-safe `ZkPedersen` and `InCircuitPedersen`, `randomBlinding`; examples,
  README, guide and tests corrected; migration note.
- **M2** — D3/D4: `negate`, `subtract`, public subgroup assertion (with measured cost),
  `PedersenCommitment.decode`, wrap rule in spec and guide.
- **M3** — *Entry gate: `docs/specs/pedersen-jubjub-vector-v1.md` reviewed.* D5 constants,
  known-answer and independent-derivation tests, in-circuit gadget, `ZkPedersen` vector entry
  point.
- **M4** — Reference application in `zeroj-integration-tests`: a confidential-balance or
  sealed-bid circuit using commitments as public inputs, Groth16 proof verified by the existing
  JuLC verifier on Yaci DevKit, with invalid-witness and tampering negatives.
- **M5** — *Entry gate: D7 decided; for option (b), transcript spec externally reviewed.* G1
  bases and sigma proofs off-chain, pure Java and blst.
- **M6** — *Entry gate: M5.* JuLC on-chain verifier library, measured budgets, DevKit E2E.

## Verification and test-vector strategy

- **v1 (M0):** golden vectors stay byte-identical; `H` reproduced by an independent script; the
  existing in-circuit/off-circuit random cross-checks keep running.
- **D2 negatives (M1):** every public entry point rejects a blinding narrower than 252 bits and
  a blinding wired to a public input or constant. Boundary witnesses: blinding `l − 1`
  accepted, `l` rejected. One test recovers a 16-bit-blinded commitment by brute force, to
  document why the rule exists.
- **D3 (M2):** `negate`/`subtract` against off-circuit arithmetic. The subgroup assertion
  accepts subgroup points and rejects `P + T` for each non-trivial torsion point `T` (orders 2,
  4 and 8) as invalid witnesses. `decode` rejects `v ≥ p`, `u = 0` with sign bit set, off-curve
  encodings and torsion-shifted points.
- **D5 (M3):** RFC 7693 BLAKE2s vectors for the test-side hash. Known answers: the Zcash
  generators derived with personalisations `Zcash_cv` (`"v"`, `"r"`), `Zcash_PH` (indices
  0–5 and `"r"`), `Zcash_G_`, `Zcash_H_` and `Zcash_J_` must match `sapling-crypto` constants
  bit-for-bit. A standalone script re-derives the `ZeroJ_PV` table. Plus in-circuit vs
  off-circuit cross-checks and invalid-witness tests (wrong `v_i`, wrong `r`, permuted
  indices).
- **D7 (M5/M6):** RFC 9380 vectors for `hash_to_curve`; CFRG -03 vectors for the relation
  algebra where the ciphersuite allows; off-chain vs on-chain base bytes via `hashToGroup`;
  pure Java vs blst parity; tamper tests on every response, commitment, challenge, session id
  and statement element.
- **Module gates:** `:zeroj-circuit-lib:test`, `:zeroj-integration-tests:test`, and from M5
  `:zeroj-onchain-julc:test`; DevKit E2E for M4 and M6.

## Production / audit gates

- Nothing here upgrades a maturity claim. Passing tests, including the known answers, are not
  evidence of security on their own.
- External review is required for: the v1 spec together with D2/D3 (folded into the existing
  Jubjub review scope); the D5 generator derivation; and, before any value-bearing on-chain
  use, the D7 transcript.
- Off-circuit secret-bearing generation stays offline/isolated until the ADR-0039 M9 gates pass.
- Validators that consume commitments still need their own `ScriptContext` binding, replay
  protection and nullifiers.

## Risks

- **Over-trusting D2.** The guard rails stop structurally broken circuits. They cannot detect a
  low-entropy or reused blinding that is passed in as a secret.
- **Spec drift in `FindGroupHash`.** A mistake in `abst_J` or the counter encoding would yield
  bases that still look valid. The Zcash known answers exist to catch exactly that.
- **D7 stays blocked.** If neither the CFRG drafts nor Plutus change, on-chain sigma proofs
  depend on a ZeroJ-specific transcript and its external review.
- **Wrap misuse.** Homomorphic sums that skip I6 can balance mod `l` while the integers do not.
  This is an application error the gadget cannot see; the spec and guide must make it hard to
  miss.
- **CIP-0133 timing.** Vector verification costs on-chain depend on whether the MSM builtin is
  enacted on the target network.
