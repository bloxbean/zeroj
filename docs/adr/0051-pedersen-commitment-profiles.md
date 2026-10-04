# ADR-0051: Pedersen commitment profiles — Jubjub hardening, vector commitments and a G1 on-chain track

## Status
Accepted (design) — 2026-10-03. The reviewer recommended acceptance at `a7ce174` (r4) with no
outstanding findings, and the maintainer accepted the design. Implementation of M0–M4 is in
progress on PR #73, one reviewed step at a time; the "Implementation status" section at the
end tracks it. Acceptance is design acceptance only.

Two decisions are R3 and keep their own gates: D5 (vector-profile generator derivation) needs
its normative spec reviewed before M3 code, and D7 (G1 sigma-proof track) has an **escalated
conflict between the pinned references and the Cardano execution environment** that this ADR
does not resolve. M5 and M6 stay blocked until D7 is decided.

This ADR changes no maturity claim. The ADR-0037 production-readiness table remains
authoritative: the in-circuit Pedersen gadgets stay "Ready\*, pending external review" and
off-circuit secret-bearing generation stays offline/isolated only (ADR-0038).

## Date
2026-10-03

## Revision history

- **r1** (`b3ed909`) — initial proposal.
- **r2** (`bd5837c`) — responds to the PR #73 review of r1:
  - I6 rewritten: every term on both sides of a balance is width-bounded and each side's
    maximum stays below `l`; a range check on the claimed sum alone is insufficient. New D3a
    defines the balance construction and the definition-time check that enforces it.
  - D3: the public subgroup assertion enforces point validity itself; I4 becomes an API
    contract enforced by named constructors; the identity policy is kept separate from
    rejecting invalid `Z = 0` representations.
  - D5: the vector commitment does not bind its length or schema; schema binding moves into the
    authenticated application statement and a typed schema.
  - New "Performance gates" section: complete safe-API cost pins, and end-to-end measurements
    rather than constraint counts alone.
- **r3** (`fae2bfd`) — responds to round 2 (completion of finding 3): a schema held at
  definition time is not a binding. D5/I11 now require a constrained public schema digest,
  checked against a verifier registry, plus authenticated issuance provenance for received
  commitments. Schema-separated bases were made mandatory where provenance cannot be supplied
  (superseded in r4: consumers fail closed instead). M3 and the tests now require cross-schema
  rejection at the real serialised verifier boundary, including width-only differences.
- **r4** — responds to round 3: a valid proof is not provenance. The trust anchor is an
  authenticated application record or authorised issuance event binding the exact commitment
  coordinates to `σ` (on-chain: an exact reference to policy-guarded state). Consumers fail
  closed without it. Schema-separated bases are now a separate future profile, not a fallback.
  New adversarial relabelling test: a fresh valid proof under B for a commitment issued under A
  must be rejected by provenance.

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
| Low-level gadget | `jubjub/InCircuitPedersen` | 3,020 constraints at two 252-bit scalars for the gadget alone (measured); proves the represented bit-vector residues, does **not** assert `< l` |
| Annotation adapter | `zk/ZkPedersen` (`commit`, `commitBits`, `verifyOpening`) | Ready\* pending external review; asserts both scalars `< l` |
| Fixed-limb generation candidate | `jubjub/HardenedPedersen` (package-private) | ADR-0039 M9 candidate; its own timing/platform/external gates |
| Point toolkit | `InCircuitJubjub` (add, double, select, windowed fixed-base and variable-base scalar mul, `witnessAffine`), `JubjubPoint` (encode/decode, negate, subgroup check) | Present |

`G` is `JubjubPoint.SUBGROUP_GENERATOR`. `H` is derived by a Poseidon (ADR-0015, `t = 3`)
try-and-increment from the domain tag `"zeroj.pedersen.v1.H"`, cofactor-cleared, and pinned
by a fixture in `PedersenTest`. The current tests (`PedersenTest` 18, `HardenedPedersenTest`
5, `ZkGadgetAdaptersTest` 28) pass.

The 3,020 figure covers the low-level gadget only. The complete symbolic commitment
(`ZkPedersen`, including both canonical `< l` checks and binding both affine public
coordinates) was measured during review of r1:

| Value / blinding width | R1CS rows | Sparse nonzeros |
|---|---:|---:|
| 64 / 252 | 2,918 | 13,460 |
| 252 / 252 | 4,042 | 19,338 |

A 252-bit windowed fixed-base multiplication is pinned at 1,506 rows (7,865 nonzeros), against
2,513 rows for the bit-by-bit reference (`WindowedFixedBaseTest`).

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
- **A public subgroup assertion that enforces its own preconditions.** The existing
  `InCircuitEdDSAJubjub.assertInPrimeOrderSubgroup` relies on its callers having validated the
  point. Called directly on the raw extended coordinates `(0, 0, 0, 0)` it accepts, because its
  final identity predicate sees `U = 0` and `V = Z` (reproduced during review of r1). That is a
  hazard for a public promotion, not a vulnerability in the current EdDSA entry points. So:
  - `ZkJubjubPoint.assertInPrimeOrderSubgroup(zk)` is the public entry point. `ZkJubjubPoint`
    is the authenticated type: it is constructed only by `witnessAffine` (curve equation,
    `Z = 1`, `T = U·V`), `constant`, or gadget results. The method first calls
    `assertWellFormed()`, which emits the projective curve equation, `T·Z = U·V` and `Z ≠ 0`
    unless they are already established, and only then asserts `[l]·P = O`.
  - If a low-level `InCircuitJubjub.assertInPrimeOrderSubgroup(api, Point)` is exposed, it
    always emits `InCircuitJubjub.assertWellFormed` itself, unconditionally.
  - The existing package-private helper stays as the EdDSA-internal primitive, so EdDSA
    constraint systems and verification keys do not change.
  - **Identity is a separate policy.** A well-formed identity (`U = 0`, `V = Z ≠ 0`) is in the
    prime-order subgroup and passes this assertion. Whether a commitment may equal the identity
    is the D1 policy, enforced at the commitment boundary. Rejecting malformed `Z = 0`
    representations is a validity rule and never depends on that policy.
  - Cost: one 252-bit variable-base multiplication by `l` plus the well-formedness rows,
    roughly 5,500 rows by the gap between `verifyStrict` and `verifyWithRegisteredKey`. M2
    pins the exact rows and nonzeros.
- **I4 as an enforced API contract.** Public Pedersen APIs that consume a commitment the
  circuit did not compute accept it only through named constructors that discharge I4:
  - `witnessInSubgroup(zk, u, v)` — `witnessAffine` plus the subgroup assertion in-circuit
    (case b).
  - `fromVerifierCheckedPublic(zk, u, v)` — the DSL requires both coordinates to be public
    inputs or constants (`CircuitAPI.requirePublicOrConstant`) and asserts the curve equation.
    Subgroup membership becomes the verifier's documented obligation (case c), as with
    `verifyWithRegisteredKey`.

  Raw `InCircuitJubjub.Point` values are never accepted by the public homomorphic APIs.
- `PedersenCommitment.decode(byte[])`: canonical decoding (`v < p`; `u = 0` requires sign bit
  0, per ZIP 216) plus prime-order subgroup membership, applying the D1 identity policy.

### D3a — Balance relations must not wrap (R2)

Pedersen homomorphism proves relations **mod `l`**. The r1 wording of I6 ("bound each value
… or range-check the sum") was insufficient. With canonical openings,

```
C(l − 1, 17) + C(1, 23) = C(0, 40)
```

holds, and a circuit using `ZkPedersen` accepts it even when the claimed total is constrained
to one bit (reproduced during review of r1). The gadgets implement the modular relation
correctly; the error is reading it as integer conservation.

The rule (I6) for any relation `Σ a_i·v_i = Σ b_j·w_j (+ public terms)` that an application
reads as an integer equation:

- **Every term on both sides is width-bounded.** Each committed value's leg is constrained to
  its declared `k`-bit width by its own decomposition. Bounding only the claimed total is not
  enough.
- **Coefficients are small non-negative integers fixed at circuit-definition time**, never
  prover-chosen field elements. Negative coefficients move to the other side first.
- **Each side's maximum integer value is below `l`:** `Σ a_i·(2^{k_i} − 1) < l`, and the same
  for the other side, with public terms counted at their declared bounds. Both sides are then
  integers in `[0, l)`, so equality mod `l` implies integer equality. Because `l < p`, the same
  bound rules out aliasing mod the circuit field `p` when values are added as field elements.

The construction depends on who holds the openings:

- **Inside a circuit that knows the openings**, the supported construction is value-level
  integer accumulation. `ZkPedersen` gains a balance helper that takes only commitments
  computed or opened in the same circuit, so each value is a `ZkUInt` with a known width. It
  computes both side bounds **at
  circuit-definition time** and throws if either reaches `l`, then asserts the relation on the
  opened values as field elements. Point arithmetic is not needed for the relation, and value
  arithmetic is cheaper.
- **Outside a circuit** (an off-chain verifier or a G1 validator combining commitments it
  cannot open), the point-level check is valid only if every term carries a range proof for its
  declared width from the proof that produced it, and the verifier applies the same side-bound
  rule to those declared widths.

The spec and the gadgets guide include this counterexample and a worked balance example.

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
- **The commitment does not bind its length or schema.** All dimensions share the base prefix
  `G_0, G_1, …`, so `C([a], r) = C([a, 0], r)`. The profile defines this explicitly: a
  dimension-`n` commitment uses `G_0..G_{n−1}`, and equals its zero-padded extension to any
  larger dimension. Binding therefore lives in the authenticated application statement:
  - A **vector schema** consists of an identifier and version, the dimension `n`, and for each
    index its meaning and value width. The `ZkPedersen` vector entry point takes the schema
    object rather than a bare list of values.
  - **A schema held at circuit-definition time is not, by itself, part of the cryptographic
    statement.** Two schemas with the same dimension and widths but a different identifier,
    version or index meaning generate identical equations. Unused constants and metadata bind
    nothing, so identical circuits get interchangeable verification keys. Typed Java wrappers
    only constrain cooperative callers; an untrusted prover, or a consumer of serialised
    points, can bypass them. The binding is therefore placed in the proof statement and in
    authenticated provenance, as follows.
  - **Statement binding (required).** Every proof that creates, opens or consumes vector
    commitments carries a canonical **schema digest** `σ = SchemaDigest(schema)` as a public
    input. The circuit constrains that input to equal the schema's constant digest. The
    constraint makes the verification keys of same-shape schemas differ, and it satisfies
    ADR-0045's every-public-wire-constrained rule. The verifier compares the public `σ` with
    the **expected** digest taken from its own trusted configuration: a deployment registry that
    associates each accepted verification key with exactly one expected schema digest. A
    prover-supplied label is never the source. The canonical schema encoding and the digest
    construction (hash, domain tag, reduction into the scalar field) are specified at the M3
    entry gate. Cost: one public input and one linear constraint per proof, plus one extra
    public-input term in the Groth16 verifier, on-chain included.
  - **Provenance binding for received commitments (required).** A proof that a raw point opens
    under schema B does not prove that the point was *issued* under schema B. **A valid proof is
    not provenance.** Anyone who knows an opening can produce a fresh, fully valid proof under
    a same-shape schema B for a commitment originally issued under A. B's digest, key and
    circuit all agree, so neither proof verification nor the digest check reveals the original
    A context.

    The trust anchor is therefore an **authenticated application record or authorised issuance
    event**. It binds the exact commitment coordinates to the schema digest `σ` (and any other
    issuance context the application needs), and the consumer obtains the commitment's expected
    original context from that record, not from anything presented alongside the point:
    - **On-chain:** a referenced output or state guarded by the issuance policy, for example a
      reference input whose datum holds `(commitment, σ)` and which only the issuing validator
      or minting policy can create. The consuming validator checks that **exact** reference and
      that the commitment and `σ` it is given match the referenced record.
    - **Off-chain:** a trusted registry or an authorised issuer's signed record with the same
      binding, checked by the consumer.

    A proof can be evidence inside that trusted issuance flow, for example the issuing
    validator verifies the issuance proof before writing the record. Possession of a newly
    generated valid proof never authorises creating, replacing or reinterpreting the schema of
    an existing commitment. This is a requirement on applications using the profile. This ADR
    does not provide a generic authorisation implementation.
  - **Fail closed.** In this shared-base profile, a consumer that cannot obtain authenticated
    provenance for a received commitment rejects it. There is no fallback.
  - **Schema-separated bases** would bind the schema at the commitment level instead. They are a
    deferred, **separate profile** that requires its own reviewed specification. They are not a
    fallback for missing provenance in this profile.
  - Off-circuit, vector commitments are a typed value carrying their schema, and `add` and
    `subtract` require identical schemas. This is a convenience for cooperative callers, not
    the security boundary: the two required bindings above are.
  - **Homomorphism is defined only within one schema.** Combining commitments across schemas,
    or reinterpreting a commitment under a different schema (for example, treating index 1 of
    an attribute vector as an asset amount), is outside the profile.
  - Alternatives considered: per-schema domain-separated bases would bind the schema
    cryptographically, but need per-schema derivation (a runtime hash, or one pinned table per
    schema) and give up the shared table. They are deferred to a separate profile with its own
    reviewed specification. Applications of this profile that cannot supply authenticated
    issuance provenance fail closed rather than falling back. A schema-tag term (`[tag]·G_tag`) is rejected because it does
    not compose: a sum of `m` commitments carries `m·tag`.
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
  Jubjub builtins) and must use (a) or (b). This is enforced by the API (D3), not left as a
  convention: external commitments enter only through `witnessInSubgroup` (b) or
  `fromVerifierCheckedPublic` (c), and every subgroup assertion first establishes point
  validity (curve equation, `T·Z = U·V`, `Z ≠ 0`).
- **I5 — Canonical encoding.** The off-circuit decoder accepts exactly one encoding per point
  and enforces subgroup membership. The public-input form is affine `(u, v)`.
- **I6 — No wraparound.** Homomorphic relations hold mod `l`. A relation is read as an integer
  equation only if every term on **both** sides is width-bounded by its own decomposition,
  coefficients are small non-negative integers fixed at circuit-definition time, and each
  side's maximum `Σ a_i·(2^{k_i} − 1)` is below `l` (D3a). Range-checking only the claimed sum
  is insufficient. The bound also excludes aliasing mod the circuit field `p`.
- **I7 — Versioning.** A change to a domain string, derivation or base is a new profile
  version. v1 bases are frozen.
- **I8 — Secrets.** No new secret-bearing `BigInteger` path is approved for online use. New
  samplers and generators inherit ADR-0038.
- **I9 — Strong Fiat–Shamir (G1).** The challenge binds a session identifier, every base, the
  complete statement and every prover commitment. Weak Fiat–Shamir is forbidden.
- **I10 — Provider and platform parity (G1).** Pure Java and blst produce identical bases and
  verdicts, and on-chain `hashToGroup` reproduces the off-chain bases.
- **I11 — Vector schema.** A vector commitment binds neither its length nor its schema (the
  point itself; D5). The schema (identifier, version, dimension, per-index meaning and width)
  is bound by (a) a canonical schema digest that is a constrained public input of every proof
  creating, opening or consuming the commitment, checked by the verifier against an expected
  digest from trusted configuration, and (b) for every externally received commitment, an
  authenticated application record or authorised issuance event that binds the exact
  commitment coordinates to `σ`, from which the consumer obtains the expected original context.
  Neither prover-supplied labels, typed host wrappers nor a freshly generated valid proof is a
  binding. Without provenance, the consumer fails closed. Homomorphic operations combine only
  commitments with the same schema digest.
- **I12 — No soundness for budget.** Booleanity, canonicality, point validity, decomposition
  ownership and required subgroup checks are never removed to meet a cost target.

## Consequences

- Applications get a hiding-safe default and the operations they need (subtract, subgroup
  assertion, safe decode, blinding sampler) without touching point internals.
- Multi-value commitments arrive with external known answers instead of self-derived
  fixtures.
- The G1 track is explicitly blocked on a decision instead of being built on an unreviewed
  transcript.
- Circuits that declared narrow blindings stop compiling. That is intended.
- Balance circuits whose declared widths could wrap fail at circuit-definition time rather
  than proving a modular identity that reads as conservation.
- Vector commitments are only meaningful together with their schema. Every vector proof
  carries one extra public input (the schema digest), and deployments maintain a registry
  mapping each accepted verification key to its expected schema digest.
- Costs: a subgroup assertion adds about 5,500 rows when a circuit must consume a commitment
  it did not compute; a vector commitment costs roughly one fixed-base multiplication per value
  at that value's width. Exact pins are a milestone deliverable (see Performance gates).

## Compatibility

- **v1 commitments are bit-identical.** `G`, `H`, the golden vector in `PedersenTest` and the
  byte encoding do not change.
- **Circuit API break (pre-1.0):** `ZkPedersen` `scalarBits` overloads are removed, and narrow
  or public/constant blindings are rejected. Circuits that used narrow blindings get new
  constraint systems and must regenerate keys. Circuits that already used 252-bit blindings and
  the two-argument `commit` keep identical constraints. A migration note ships with M1.
- EdDSA-Jubjub constraint systems and keys do not change: EdDSA keeps the package-private
  subgroup helper, and only the new public entry points add well-formedness rows.
- The vector profile, the G1 track and every new method are additive.
- No on-chain verifier changes for M0–M4. M6 adds a new JuLC library and changes no existing
  script hash.

## Implementation milestones

Each milestone is its own PR with a review gate. M3, M5 and M6 have entry gates.

- **M0** — `docs/specs/pedersen-jubjub-v1.md` (D1) and the independent `H` reproduction script.
- **M1** — D2: hiding-safe `ZkPedersen` and `InCircuitPedersen`, `randomBlinding`; examples,
  README, guide and tests corrected; migration note.
- **M2** — D3/D3a/D4: `negate`, `subtract`; the validity-enforcing public subgroup assertion;
  the `witnessInSubgroup` / `fromVerifierCheckedPublic` constructors; `PedersenCommitment.decode`;
  the balance helper with its definition-time bound check; the wrap rule and counterexample in
  spec and guide.
- **M3** — *Entry gate: `docs/specs/pedersen-jubjub-vector-v1.md` reviewed, including the
  zero-padding semantics, the canonical schema encoding, the `SchemaDigest` construction, the
  verifier-registry contract (verification key → expected digest) and the provenance rule for
  received commitments.* D5 constants, known-answer and independent-derivation tests, the schema
  type and digest, the constrained digest public input, the in-circuit gadget, and the
  `ZkPedersen` vector entry point.
- **M4** — Reference application in `zeroj-integration-tests`: a confidential-balance or
  sealed-bid circuit using commitments as public inputs, Groth16 proof verified by the existing
  JuLC verifier on Yaci DevKit, with invalid-witness, tampering and wraparound negatives.

Every milestone that adds or changes a circuit API also delivers the cost pins listed under
Performance gates.
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
- **D3 (M2):** `negate`/`subtract` against off-circuit arithmetic. The public subgroup
  assertion:
  - accepts subgroup points, including a projectively rescaled `(λU, λV, λZ, λT)` and the
    well-formed identity;
  - rejects, as invalid witnesses: the all-zero `(0, 0, 0, 0)`; `Z = 0` with other coordinates
    non-zero; an inconsistent `T` (`T·Z ≠ U·V`); off-curve points; and `P + T` for each
    non-trivial torsion point `T` (orders 2, 4 and 8).

  The same malformed inputs are rejected through `witnessInSubgroup`, and
  `fromVerifierCheckedPublic` rejects secret or derived coordinates at definition time.
  `decode` rejects `v ≥ p`, `u = 0` with sign bit set, off-curve encodings and torsion-shifted
  points.
- **D3a (M2, M4):** the counterexample `C(l − 1, 17) + C(1, 23) = C(0, 40)` is a required
  negative. A balance over 252-bit value legs is rejected at definition time. With widths that
  pass the bound, the counterexample's witness cannot be expressed. A one-bit claimed total
  does not rescue a wide input. Boundary: each side's maximum exactly `l − 1` is accepted, and
  `l` is rejected. Coefficient cases: a coefficient that pushes a side to `l` is rejected, and a
  negative coefficient is only accepted after moving to the other side. M4 repeats the
  counterexample end to end and expects proving to fail.
- **D5 (M3):** RFC 7693 BLAKE2s vectors for the test-side hash. Known answers: the Zcash
  generators derived with personalisations `Zcash_cv` (`"v"`, `"r"`), `Zcash_PH` (indices
  0–5 and `"r"`), `Zcash_G_`, `Zcash_H_` and `Zcash_J_` must match `sapling-crypto` constants
  bit-for-bit. A standalone script re-derives the `ZeroJ_PV` table. Plus in-circuit vs
  off-circuit cross-checks and invalid-witness tests (wrong `v_i`, wrong `r`, permuted
  indices). Schema tests:
  - `C([a], r) = C([a, 0], r)` is pinned as the documented zero-padding behaviour.
  - **Cross-schema reuse through the real verifier boundary.** Use two schemas with identical
    dimensions and widths that differ only in identifier, version or per-index meaning. Produce
    a proof and serialised commitment under schema A, then present them, as raw serialised
    points, proof bytes and public inputs, to a verifier configured for schema B. This bypasses
    every Java typed wrapper. Rejection is required, and it must come from the specified checks:
    the public `σ` against the registry's expected digest, and the provenance check on the
    received commitment. Repeat with the prover supplying B's digest as the public input to A's
    circuit; the in-circuit constraint must make the proof fail. M4 repeats the scenario end to
    end against the on-chain verifier.
  - **Adversarial relabelling (the provenance gate).** Create and register `C` under schema A
    through the trusted issuance flow, then give the adversary `C`'s opening. The adversary
    generates a fresh, mathematically valid proof under B with B's correct digest and key for
    the same `C`, and every B cryptographic check passes. The consumer of the original A
    artifact must still reject the reinterpretation, and the rejection must come from its
    trusted provenance record or reference. A consumer with no provenance record for `C` must
    also reject (fail closed). M4 repeats this on-chain: the consuming validator must reject a
    transaction that presents the valid B proof without, or with a mismatching, issuance
    reference.
  - Schemas that differ **only in a value width** are incompatible and are rejected the same
    way.
  - The typed host API also rejects cross-schema `add`/`subtract`. This is kept as a usability
    test and is not counted as the security gate.
- **D7 (M5/M6):** RFC 9380 vectors for `hash_to_curve`; CFRG -03 vectors for the relation
  algebra where the ciphersuite allows; off-chain vs on-chain base bytes via `hashToGroup`;
  pure Java vs blst parity; tamper tests on every response, commitment, challenge, session id
  and statement element.
- **Module gates:** `:zeroj-circuit-lib:test`, `:zeroj-integration-tests:test`, and from M5
  `:zeroj-onchain-julc:test`; DevKit E2E for M4 and M6.

## Performance gates

The optimisation strategy is retained: fixed public tables, constrained window selection,
decomposition ownership, and narrow value legs with full-width blindings. I12 applies: no
booleanity, canonicality, point-validity, ownership or required subgroup check is removed to
meet a budget.

- **Pin the complete safe-API cost, not just the gadget.** Each milestone adds regression pins
  for R1CS rows **and** sparse nonzeros of the full `ZkPedersen`-level operation, as a user
  would call it, including canonical checks and public-input binding. Baselines for r2 are the
  review measurements in Context (64/252: 2,918 rows / 13,460 nonzeros; 252/252: 4,042 rows /
  19,338 nonzeros). The 3,020-row low-level figure stays labelled as gadget-only.
- **New pins per milestone:** the M1 commit and opening with the full-width blinding; the M2
  subgroup assertion (with and without already-established well-formedness), `witnessInSubgroup`
  and the balance helper; the M3 vector commitment at representative dimensions (`n` = 1, 4
  and 16) and value widths.
- **End-to-end measurements.** Constraint reductions alone do not establish speedups. For M3
  and M4, record the padded evaluation domain, witness-generation time, proving time and peak
  memory for the representative vector sizes, using the project's standalone benchmark harness
  rather than a Gradle test run.

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
- **Wrap misuse outside the helper.** The D3a helper enforces I6 inside a circuit. A verifier
  that combines commitments itself (off-chain or on G1) must apply the same bounds by hand, and
  nothing stops it from forgetting. The spec, guide and counterexample test exist to make that
  hard to miss.
- **Schema confusion.** Raw points carry no schema, and a holder of an opening can always
  produce a valid proof under another same-shape schema. I11 places the binding in the proof
  statement and in authenticated issuance provenance, and requires consumers to fail closed
  without provenance. An application that skips the provenance check is open to relabelling;
  the profile cannot detect that omission.
- **CIP-0133 timing.** Vector verification costs on-chain depend on whether the MSM builtin is
  enacted on the target network.

## Implementation status

| Milestone | State | Notes |
|---|---|---|
| M0 | Done, in review | `docs/specs/pedersen-jubjub-v1.md`. An independent standard-library Python reproduction, written from the spec and the ADR-0015 Sage Poseidon reference without reading ZeroJ Java code, is in `zeroj-circuit-lib/src/test/resources/pedersen-reference/`. It matched every spec pin; `PedersenReferenceVectorsTest` checks the library against its output (bases, 10 commitments, the wrap example, 12 negative decodes). |
| M1 | Done, in review | `ZkPedersen`/`InCircuitPedersen` require a 252-bit blinding and reject one wired directly to a public input or constant (new `CircuitAPI.requireNotPublicOrConstant`); the shared-width overloads are removed; `PedersenCommitment.randomBlinding(SecureRandom)`; examples, guides and tests corrected; [migration note](../migration/0051-pedersen-hiding-safe-api.md). Complete safe-API pins: 2,918 rows / 13,460 nonzeros (64/252) and 4,042 / 19,338 (252/252), equal to the r1 review measurements, so full-width circuits are unchanged. |
| M2 | Done, in review | `InCircuitJubjub.negate`/`subtract` (0 rows / one addition) and the public `assertInPrimeOrderSubgroup`, which validates the point before `[l]·P = O` (5,556 rows on raw coordinates); EdDSA keeps the unchecked core, and its 8,962/14,500 pins are unchanged. `ZkJubjubPoint.negate`/`subtract`/`assertInPrimeOrderSubgroup` (5,547 rows on an established point). `ZkPedersenCommitment` with origin tracking and the two I4 constructors. `PedersenCommitment.decode`. `ZkPedersen.assertBalanced` with the definition-time side bound (2-in/1-out + fee transfer: 8,808 rows / 40,575 nonzeros). Tests cover the malformed-point set, torsion of orders 2/4/8, the wraparound counterexample, side-bound and coefficient boundaries. |
| M3 | Done, in review (spec gate first) | Spec `docs/specs/pedersen-jubjub-vector-v1.md` with an independent reproduction (all 124 pins matched). `PedersenVectorBases` (pinned; re-derived in tests with BouncyCastle BLAKE2s, reproducing the 12 Zcash generators), `PedersenVectorSchema`, `PedersenVectorCommitment`, `PedersenSchemaRegistry`, `InCircuitPedersenVector`, `ZkPedersenVector` (schema digest bound as a constrained public input; `CircuitAPI.requirePublicInput`). Integration test with real Groth16 proofs at the serialised verifier boundary: same-shape cross-schema reuse and width-only differences rejected; adversarial relabelling (fresh valid proof under B) rejected by provenance. Costs: 2,411 / 3,581 / 8,261 rows at n = 1 / 4 / 16; [end-to-end measurements](../benchmarks/pedersen-vector-2026-10-03.md). |
| M4 | Done, in review | Reference validators `ConfidentialNoteValidator` (owner signature, input commitment from the consumed datum, two continuing output commitments, single script input, canonical inputs; 3.66×10⁹ CPU / 0.56M mem; documented limits: no issuance control, proof bound to commitments rather than to an output) and `VectorCommitmentConsumerValidator` (claim datum `(beneficiary, u, v)`, beneficiary signature, single script input, σ from the script parameter, issuance record = reference input holding the issuer-minted token named `blake2b_256(u ‖ v ‖ σ)` with datum `(u, v, σ)`; 3.07×10⁹ CPU / 0.40M mem). Julc-VM tests: honest flows accepted; tampered proofs, every binding mutation, non-canonical datum coordinates, cross-schema proofs, relabelling, forged or moved records and replay against another claim rejected; unbalanced and wraparound witnesses unprovable; 252-bit balance layouts refused. **`PedersenOnChainDevKitE2ETest` passes on Yaci DevKit**: a note split with a valid proof (tampered proof rejected), A's consumer accepting an issued commitment, B's consumer rejecting the relabelled proof, A's consumer rejecting the cross-schema proof and the claim without its record. End-to-end proving figures for the reference circuit (8,755 rows, 16,384 domain, ~2.0 s pure-Java prove) are in the benchmark note. |
| M5, M6 | Blocked | D7 undecided |
