# ADR-0052: Exponential ElGamal on Jubjub — additively homomorphic encryption for circuits and tallies

## Status
Proposed — 2026-10-05. Design only. Acceptance would be design acceptance; it would certify no
implementation, test or security property.

This ADR changes no maturity claim. The ADR-0037 production-readiness table and the ADR-0039
assurance classes remain authoritative. Every secret-bearing host operation proposed here stays
in the **compatibility/offline** class (ADR-0039 §3.1).

## Date
2026-10-05

## Revision history
- **r1** — initial proposal.

## Risk classification
- **R3:** D1 (the `elgamal-jubjub-v1` profile: the ciphertext, the message encoding and the
  homomorphic semantics), D3 (the in-circuit relations, whose soundness the tally depends on)
  and D4 (the trustee relation and its proof system). These define the scheme's cryptographic
  behaviour, even though the Jubjub arithmetic underneath is not new.
- **R2:** D2 (the host API and its validation), D5 (key aggregation and proof of possession),
  D6 (maturity and assurance labelling) and D7 (encodings and the order of public inputs).

## Context

### Where this comes from

ADR-0051 D8 deferred "a private-ballot protocol (exponential ElGamal with tally decryption and
threshold keys, in the line of Cramer–Gennaro–Schoenmakers 1997)" to its own ADR. The
`zeroj-usecases` private-voting demo has since implemented that protocol inside the usecase.
The repository is `bloxbean/zeroj-usecases`, the issue is #7, the pull request is #8, and the
design is usecases ADR-0005. The implementation has these parts:

| Part | Location in `zeroj-usecases` | Generic? |
|---|---|---|
| Host ElGamal: encrypt, add, joint key with checks, decryption share, unmask, bounded discrete log, subgroup decode | `private-voting/.../voting/crypto/JubjubElGamal.java` | Yes |
| In-circuit encryption relation, and the discrete-log-equality (DLEQ) relation | `private-voting/.../voting/circuit/JubjubElGamalGadget.java` | Yes |
| Independent Python reference, written from the curve definition, and its vectors | `private-voting/src/test/resources/elgamal-reference/` | Yes |
| Ballot circuit (eligibility Merkle path, nullifier), vote list scripts, tally orchestration, manifest | `private-voting/...` | No: application |

The generic parts are reusable for:
- any private sum: weighted or multi-option votes, salary and other surveys, sealed-bid totals;
- encrypted counters held by a contract;
- the threshold-decryption building block of later protocols.

Today each application would have to re-derive them. The usecase also had to drop below ZeroJ's
annotation API. `ZkJubjubPoint` exposes no scalar multiplication, so the gadget wraps
`InCircuitJubjub.scalarMulFixedBase` / `scalarMulVariableBase` itself and re-implements the
affine-equality check. That is exactly the kind of hand-written seam ZeroJ's typed adapters
(ADR-0038, ADR-0051 D3) exist to remove.

### What the usecase established

These results are evidence for the design, not for its security. They were measured at
`zeroj-usecases` `fbc2dc9` / `20a16a8` against ZeroJ `576e5fb`.

- **Independent vectors:** the Java host code matches a Python reimplementation, written from
  the curve definition (`d = −10240/10241`, `G = [8](u₀, 11)`, checked against the pinned
  `pedersen-jubjub-v1` value base), for keys, ciphertexts, sums, decryption shares and the
  tally.
- **Circuit cost:**
  - the DLEQ circuit (`trustee-dleq`) has 6,546 constraints;
  - the ballot circuit has 8,022 constraints at Merkle depth 4 and 9,486 at depth 10. That
    includes Poseidon and the Merkle path.
  - The ElGamal relation alone is not separately measured. Estimate: 1,506 (fixed-base,
    252-bit) + 5,533 (variable-base, 252-bit), plus a select, an addition and two affine
    checks. Both scalar-multiplication figures are pinned in `InCircuitJubjub`'s Javadoc.
- **On-chain:** a Groth16 ballot proof with 9 public inputs verifies at about 4.25e9 CPU and
  0.69M memory in the Plutus VM.
- **Reviews:** two adversarial review rounds, on the design and on the implementation, found no
  issue in the generic cryptographic core.
  - They confirmed that one 252-bit decomposition suffices for both scalar multiplications.
  - They confirmed that `k ≥ l` is harmless, because both bases lie in the prime-order subgroup.
  - The findings were all in application binding: the vote list and the scripts.

## Threat model and trust assumptions

- **Untrusted:**
  - provers and every witness value;
  - ciphertexts and public keys received as bytes or as public inputs;
  - claimed decryption shares;
  - claimed tallies.
- **Secret:**
  - the encryption randomness `k` and the message `m` (for example, a vote);
  - each trustee's key share `sk_j`.

  Host arithmetic on all of these is variable-time `BigInteger` Java, which is the
  compatibility/offline class (ADR-0039 §3.1). The in-circuit gadgets emit constraints only;
  the prover's witness generation is a separate, equally offline-class computation.
- **Security goals:**
  - IND-CPA of each ciphertext, under DDH in the Jubjub prime-order subgroup;
  - soundness of the in-circuit relations: a proof exists only for a well-formed encryption of
    an in-range message under the stated key, and only for a correct decryption share;
  - correct decryption of a bounded homomorphic sum.
- **Trusted:**
  - **The setup.** For circuits proved with Groth16, the setup is trusted: whoever knows its
    toxic waste can forge any relation in this ADR. Production needs keys from an MPC ceremony
    (ADR-0031). The dev setup is development-only.
  - **The trustees.** At least one trustee is honest. With n-of-n sharing, all trustees together
    can decrypt any single ciphertext.
- **Out of scope:**
  - application authorization, replay protection, nullifiers and binding to the
    `ScriptContext` (as in ADR-0006 and ADR-0051);
  - when to decrypt. "Decrypt once, after a deadline", without which differencing two tallies
    reveals one message, is an application rule. ZeroJ documents it but cannot enforce it.

## Pinned normative references

- **[CGS97]** R. Cramer, R. Gennaro, B. Schoenmakers, *A Secure and Optimally Efficient
  Multi-Authority Election Scheme*, EUROCRYPT '97, LNCS 1233, pp. 103–118. The text was
  fetched from the authors' copy, `berry.win.tue.nl/papers/euro97.pdf`, on 2026-10-05.
  - **§2.2:** the ElGamal ciphertext `(x, y) = (g^α, h^α·m)`.
  - **§2.3:** threshold decryption. Each authority broadcasts `w_j = x^{s_j}` and proves in
    zero-knowledge that `log_g h_j = log_x w_j`.
  - **§2.4, Fig. 1:** the Chaum–Pedersen proof of that equality.
  - **§2.5:** "the encryption of a message `m ∈ Z_q` will be the ElGamal encryption of `G^m`",
    so that a product of ciphertexts encrypts `m1 + m2 mod q`, and decryption "can be done
    efficiently for 'small' messages".
  - **§3 and its footnote 3:** the tally is recovered "using O(l) modular multiplications",
    or with Shanks' baby-step giant-step in `O(√l)`.
- **[ElG85]** T. ElGamal, *A public-key cryptosystem and a signature scheme based on discrete
  logarithms*, IEEE Trans. Inf. Theory IT-31(4):469–472, 1985. Bibliographic entry as cited in
  [CGS97]; the paper itself was not fetched (**unverified**).
- **[CP93]** D. Chaum, T. P. Pedersen, *Wallet databases with observers*, CRYPTO '92, LNCS 740,
  pp. 89–105. Bibliographic entry as cited in [CGS97] (**unverified** directly).
- **[RY07]** T. Ristenpart, S. Yilek, *The Power of Proofs-of-Possession: Securing Multiparty
  Signatures against Rogue-Key Attacks*, EUROCRYPT 2007; ePrint 2007/264, fetched 2026-10-05.
  The abstract says: "Multiparty signature protocols need protection against rogue-key attacks,
  made possible whenever an adversary can choose its public key(s) arbitrarily." The paper
  concerns signatures. D5 applies the same principle to additive aggregation of encryption
  keys, as an analogy, not as a result of the paper.
- **[Ped91]** T. P. Pedersen, *A threshold cryptosystem without a trusted party*, EUROCRYPT '91,
  LNCS 547, pp. 522–526. Cited for D5's out-of-scope threshold path; bibliographic entry as
  cited in [CGS97].
- **draft-irtf-cfrg-sigma-protocols-03** (2026-08-17).
  - §3.1 and §3.4 define the `ChaumPedersen(H, X, Y)` relation: "Witness: x Equations:
    X = x * G, Y = x * H".
  - §8 defines only the ciphersuites `sigma-proofs_Shake128_P256` and
    `sigma-proofs_Shake128_BLS12381`. There is **no Edwards or Jubjub ciphersuite**.
  - Fetched 2026-10-05; also pinned by ADR-0051 D7.
- **draft-irtf-cfrg-fiat-shamir-03** (2026-08-17). Its only instantiations are SHAKE128 and
  TurboSHAKE128 (ADR-0051 D7: Plutus has no SHAKE).
- *Zcash Protocol Specification*, v2026.7.0 [NU6.2], for the Jubjub parameters; ZIP 216 for
  canonical point encodings; and ZeroJ `docs/specs/pedersen-jubjub-v1.md`, which pins the value
  base `G` and the 64-byte scalar reduction. All three are already pinned by ADR-0051.
- **Internal:**
  - ADR-0031 (production trusted setup);
  - ADR-0037, ADR-0038, ADR-0039 (Jubjub soundness, the DSL contracts, assurance classes);
  - ADR-0045 (public wires must be bound);
  - ADR-0051 (Pedersen profiles, the provenance types in D3 and the hiding-scalar guard rails
    in D2);
  - `zeroj-usecases` ADR-0005 (the first application).

## Decision

### D1 — Profile `elgamal-jubjub-v1` (R3)

Lifted, or "exponential", ElGamal over the Jubjub prime-order subgroup `𝔾` of order `l`, in the
form of [CGS97] §2.5, written additively.

- **Generator:** `G = JubjubPoint.SUBGROUP_GENERATOR`, the `pedersen-jubjub-v1` value base. It
  serves as both the key base and the message base (see Q3).
- **Keys:** a secret `sk ∈ [1, l)` and its public key `PK = [sk]·G`.
- **Encryption** of an integer `m ∈ [0, 2^w)`, at a width `w` the caller declares:
  ```
  k ← uniform in [0, l)        (64 random bytes reduced mod l, as pedersen-jubjub-v1 §3.1)
  A = [k]·G                    decryption handle
  B = [m]·G + [k]·PK           blinded message
  ```
- **Homomorphism:**
  - `Enc(m1) + Enc(m2) = Enc(m1 + m2)`, by component-wise addition.
  - `[c]·Enc(m) = Enc(c·m)` for a public integer `c ≥ 1`.
  - Plaintexts live mod `l`, so the integer reading of a result requires its bound to stay
    below `l` (I7).
- **Decryption:** `M = B − [sk]·A = [m]·G`. Then `m` is the unique `t ∈ [0, bound]` with
  `[t]·G = M`, found by a bounded search: linear, or baby-step giant-step, as in [CGS97] §3,
  footnote 3. If no `t` matches, decryption fails closed.
- **Distributed decryption** (n-of-n, see D5):
  - each trustee computes `D_j = [sk_j]·A`;
  - `M = B − Σ_j D_j`.

  This is [CGS97] §2.3 with additive shares; Lagrange coefficients are all 1.

`elgamal-jubjub-v1` is versioned like the Pedersen profiles. Any change to the generator, the
encodings or the randomness derivation is a new profile.

### D2 — Host API in `zeroj-circuit-lib` (R2)

Package `org.zeroj.circuit.lib.jubjub`, next to `PedersenCommitment`. The names are
illustrative.

- **`ElGamalPublicKey`:** a validated non-identity subgroup point. It is produced only by the
  validating constructors described in D5, or by `fromSecret`.
- **`ElGamalCiphertext`:** a record of `(A, B)` and a **plaintext bound**. Decoding rejects
  non-canonical, off-curve and non-subgroup points.
- **`encrypt(key, m, width, SecureRandom)`:** refuses `m ≥ 2^width`. The resulting bound is
  `2^width − 1`.
- **`add`, `scale`:** these combine bounds. They refuse a result whose bound reaches `l`.
- **`decryptionShare(secretShare, handle)`.**
- **`combine(ciphertext, shares)`** and **`decrypt(…, maxPlaintext)`:** the bounded search, with
  an explicit maximum. They fail closed.

The API makes no "constant-time" claim. Its secret-bearing methods are named and documented as
compatibility/offline-class (D6). It does not branch on the message: `[m]·G` is computed by
scalar multiplication for every `m`. That removes the most obvious leak of the message, a
different path for `m = 0`, but the operation is still variable-time.

### D3 — In-circuit relations (R3)

A CircuitAPI-level gadget, `InCircuitElGamal`, and a typed annotation adapter, `ZkElGamal`,
with `ZkElGamalPublicKey` and `ZkElGamalCiphertext`, mirroring `ZkPedersenCommitment`.

- **`ZkElGamal.encrypt(zk, ZkUInt message, ZkUInt randomness, ZkElGamalPublicKey key)`** returns
  a ciphertext. `assertAffineEquals(A.u, A.v, B.u, B.v)` binds it to public inputs.
  - `[m]·G` is a fixed-base multiplication over the message's own decomposition, at its declared
    width. One-bit messages may use a selection.
  - `randomness` must be declared 252 bits wide. It is decomposed **once**, and that one
    decomposition drives both `[k]·G` (fixed base) and `[k]·PK` (variable base) (I5).
  - It carries ADR-0051 D2's guard rails: `requireNotPublicOrConstant` and
    `requireHidingRange(252)`.
- **Ways a public key enters a circuit** (I8, after ADR-0051 D3):
  - `ZkElGamalPublicKey.fromVerifierFixedPublic(zk, u, v)` requires both coordinates to be
    declared public inputs. It asserts the curve equation and **non-identity**. Subgroup
    membership is the verifier's obligation, which it discharges when it fixes the key: for
    example, a script parameter whose key shares carry proofs of possession (D5).
  - `ZkElGamalPublicKey.witnessInSubgroup(zk, u, v)` asserts subgroup membership in-circuit, at
    the cost of a full `[l]·P`.
- **`ZkElGamal.assertDiscreteLogEquality(zk, ZkUInt x, ZkField Xu, Xv, Pu, Pv, Du, Dv)`** proves
  `P = [x]·G` and `D = [x]·X`, with one decomposition of `x` and the hiding guard rails. `X` is
  bound by the curve equation. The verifier chooses `X`:
  - `G` for a proof of possession (with `D = P`);
  - the recomputed aggregate handle `ΣA` for a decryption share.

These relations are the same as the usecase's, but now behind typed, provenance-tracking
entry points. No general-purpose `ZkJubjubPoint` scalar multiplication is added (Q5).

### D4 — Trustee proofs: the relation now, the Σ-protocol later (R3, **open — escalated**)

The trustee relation is `log_G P = log_X D` ([CGS97] §2.3 step 1). The usual proof is
Chaum–Pedersen ([CGS97] §2.4, [CP93]), which needs no trusted setup. The CFRG sigma draft
specifies exactly this relation (`ChaumPedersen`, §3.4). But:

1. The draft defines **no Jubjub or Edwards ciphersuite** (§8). Using it on Jubjub means
   defining a ciphersuite: the group encoding, hash-to-scalar and the transcript. That is new
   R3 material the references do not pin.
2. Its Fiat–Shamir instantiations need SHAKE, which Plutus lacks (ADR-0051 D7). This matters
   only if shares are ever verified on-chain.

**Proposal:** ship the relation as the D3 gadget. Applications prove it inside their own circuit
(Groth16 or PlonK), with their own setup. **No Σ-protocol is implemented under this ADR.**
Options for the long term:

| Option | Trusted setup | Spec status | On-chain |
|---|---|---|---|
| (a) The D3 relation in a SNARK (proposed now) | Yes: the application's | Pinned (this ADR and its spec) | Yes (Groth16 on Plutus) |
| (b) A ZeroJ-specified Jubjub ciphersuite for `ChaumPedersen` | No | Invented here; needs external review | Not natively (no SHAKE), unless ADR-0051 D7 picks a SHA-2/BLAKE2 transcript |
| (c) Wait for an Edwards ciphersuite in the CFRG draft | No | Upstream | As (b) |

Lean: (a) now, and (c) for setup-free verification. **This ADR does not decide (b).** Per
AGENTS.md, a new transcript is escalated, not invented in code.

### D5 — Key setup: n-of-n with proof of possession (R2)

- **Aggregation.** `ElGamalPublicKey.aggregate(List<VerifiedKeyShare>)` sums shares into the
  joint key. It refuses:
  - an empty list;
  - duplicate shares;
  - identity or non-subgroup shares;
  - an identity sum.
- **Proof of possession, enforced by type.** A `VerifiedKeyShare` can be constructed only by
  `VerifiedKeyShare.verify(PK_j, proof, verifier)`. The `verifier` is a caller-supplied check of
  the D3 DLEQ relation with `X = G`, `D = P = PK_j`. The library does not pick the proof system
  (D4), but it makes skipping possession impossible without deliberately writing a verifier
  that lies.
  - This blocks the rogue-key attack: a party that publishes `PK_n = [x]·G − Σ_{j<n} PK_j`
    cannot prove knowledge of its discrete log. That is the same principle as [RY07], applied
    to encryption-key aggregation.
- **Ordering, as guidance.** Trustees should publish commitments to their keys before
  revealing them, so that no trustee chooses its key after seeing the others. This limits bias
  of the joint key. It is a protocol obligation, documented but not enforced by the library.
- **Out of scope:** threshold `t-of-n` sharing with distributed key generation ([Ped91] and its
  successors). It needs its own ADR. n-of-n means a single absent trustee blocks decryption.

### D6 — Maturity and assurance labelling (R2)

- Everything in this ADR is **Experimental** in the gadget support matrix.
- The host API's secret-bearing operations are compatibility/offline-class (ADR-0039 §3.1):
  - key generation;
  - encryption, which handles `k` and `m`;
  - decryption shares, which handle `sk_j`.

  Javadoc says so, and no method name implies online approval. A hardened path follows ADR-0039
  Decision 8's pattern, after signing and Pedersen, and is out of scope here.
- Proof generation keeps the existing caveat. The witness converts secrets to `BigInteger`, so
  an end-to-end proving workflow is outside the strongest online profile (ADR-0039 Decision 8).

### D7 — Encodings and public-input order (R2)

- **Bytes:** a ciphertext is `repr_J(A) ‖ repr_J(B)`, 64 bytes (ZIP 216), and a public key is
  `repr_J(PK)`, 32 bytes. Decoding is canonical-only.
- **Public inputs:** a ciphertext is `A.u, A.v, B.u, B.v`, in that order. A key is
  `PK.u, PK.v`. A DLEQ statement is `X.u, X.v, P.u, P.v, D.u, D.v`. This matches ADR-0051 D4's
  affine `(u, v)` convention.
- **Identity:** an identity `A` or `B` decodes as a valid group element. An identity *key* is
  always refused (I1, I8), because encryption under it publishes `[m]·G`.

### D8 — Out of scope

- The ballot protocol, nullifiers, eligibility, deadlines, vote lists and the "decrypt once"
  rule. These stay in applications (usecases ADR-0005).
- Threshold key generation (D5).
- A Σ-protocol and its transcript (D4).
- Verifying decryption shares on-chain.
- Re-encryption, mix-nets and verifiable shuffles.
- Range proofs on plaintexts outside a circuit.
- Constant-time host arithmetic (ADR-0039).

### Alternatives considered

| Alternative | Why not |
|---|---|
| **Leave it in the usecase** | Every application re-derives a security-critical relation by hand and below the typed API. Reviews are not shared. |
| **Twisted ElGamal**, `C = [m]·G + [r]·H` (a `pedersen-jubjub-v1` commitment), `D = [r]·PK` | Attractive, because `C` is exactly a Pedersen commitment. But decryption needs `sk⁻¹`, which does not split additively, so no n-of-n sharing (usecases ADR-0005, alternative 3). It could be a second profile later if a single-key use case needs commitment compatibility. |
| **ElGamal on BLS12-381 G1** | Native on-chain arithmetic, and a CFRG ciphersuite exists for Chaum–Pedersen. But proving well-formedness inside a BLS12-381-scalar-field circuit means non-native field arithmetic, which costs orders of magnitude more. A possible separate track alongside ADR-0051 D7. |
| **Paillier or other additively homomorphic schemes** | No efficient in-circuit relation, and no curve already in ZeroJ. |
| **A general `ZkJubjubPoint.scalarMul`** | It would let applications build any point relation, including unsafe ones: mixed scalars, unchecked bases. Relation-specific APIs keep the invariants enforceable (Q5). |

## Security invariants

| ID | Invariant | Decisions |
|---|---|---|
| I1 | Every public key and key share is a non-identity point of the prime-order subgroup. An aggregated key is never the identity, and shares are pairwise distinct. | D2, D5, D7 |
| I2 | A key share is aggregated only as a `VerifiedKeyShare`, which is constructible only through a possession check. | D5 |
| I3 | Ciphertext decoding is canonical (ZIP 216), on-curve and in the subgroup. | D2, D7 |
| I4 | Host randomness is uniform in `[0, l)`: 64 bytes reduced mod `l`. In-circuit randomness is declared 252 bits, is never public or constant, and is never range-confined below 252 bits. | D1, D2, D3 |
| I5 | Within one relation, every scalar multiplication by the same secret (`k` in encryption, `x` in DLEQ) consumes one bit decomposition. | D3 |
| I6 | Messages are integers of a declared width: refused above it on the host, and proved below it in-circuit. | D1, D2, D3 |
| I7 | Every homomorphic result carries a plaintext bound. Operations refuse a bound `≥ l`, and decryption requires the bound to be within the caller's search limit. | D1, D2 |
| I8 | A key enters a circuit only as a verifier-fixed public input (curve equation and non-identity asserted, subgroup checked by the verifier), or as a witness proved to be in the subgroup. | D3 |
| I9 | In a DLEQ statement, the base `X` is chosen by the verifier and enters as public inputs. A possession proof uses `X = G`. A share proof uses the verifier's own recomputed aggregate. | D3, D4 |
| I10 | Decryption returns the unique `t ∈ [0, bound]` with `[t]·G = M`, or fails. | D1, D2 |
| I11 | Public-input orders and byte encodings are exactly those in D7. | D7 |
| I12 | Secret-bearing host operations are documented as compatibility/offline-class, and make no constant-time or online claim. | D6 |

## Consequences

- Applications get one reviewed relation and API for private sums, with bounds and key
  provenance enforced by types.
- The usecase drops its private gadget and host class (M3), and keeps only its protocol.
- A second Jubjub scheme reuses the Pedersen-era guard rails (D2, D3 and D4 of ADR-0051). Any
  change to those rails now affects two schemes.
- Proofs of possession and of decryption shares still need a trusted setup until D4 is
  resolved.

## Compatibility

All of it is new API, and nothing existing changes. The usecase's ciphertexts and proofs remain
valid after M3, provided the encodings and public-input orders in D7 match those the usecase
already uses. The usecase uses exactly these. A differential check is part of M3.

## Implementation milestones

| Milestone | Scope | Entry gate | Exit criteria |
|---|---|---|---|
| M0 | This ADR. Normative spec `docs/specs/elgamal-jubjub-v1.md`: profile, encodings, relations, public-input orders, and test vectors. | ADR accepted | Spec reviewed. Its vectors come from the independent Python reference, not from the Java code. |
| M1 | Host API (D2, D5, D7) | M0 | I1–I4, I6, I7, I10, I11 tested, including negative decoding (non-canonical, off-curve, small-order). Vectors match the spec. Property tests for homomorphism and bounds. |
| M2 | `InCircuitElGamal` and the `ZkElGamal` adapter (D3) | M1 | Negatives: mismatched scalars, a message above its width, an identity or off-curve key, a wrong share, a wrong base, a public or narrow randomness. Constraint counts pinned. Groth16 prove and verify, with every public input shown to be bound. |
| M3 | Migrate `zeroj-usecases` private-voting onto the library | M2, and a ZeroJ release containing it | Identical ciphertext and proof behaviour (differential). Usecase VM and DevKit end-to-end tests pass. The usecase's private gadget and host class are deleted. |
| M4 | Docs: support matrix (Experimental), gadget guide, annotation guide | M2 | Docs reviewed. |

## Verification and test-vector strategy

- **Independent reference.** Move the usecase's Python reimplementation into ZeroJ's test
  vectors. It is written from the curve definition and derives `d` from `−10240/10241`. It
  produces keys, ciphertexts, sums, shares and tallies for fixed scalars.
- **Spec cross-checks.**
  - `G` must equal `pedersen-jubjub-v1`'s pinned value base.
  - The 64-byte reduction must match that spec's blinding derivation.
- **Negatives.**
  - Decoding: non-canonical, off-curve and small-order inputs.
  - Bounds: overflow of the plaintext bound.
  - Aggregation: identity, duplicate and cancelling shares.
  - Circuits: no witness for every D3 misuse; a proof fails against each changed public input.
- **Differential.** Host encryption against an in-circuit encryption of the same `(m, k)`. The
  usecase before and after M3.
- **Not evidence of security:** passing tests, test counts and benchmarks.

## Production / audit gates

- External review of the spec (M0) and of the in-circuit relations (M2).
- For applications: MPC-generated keys for every circuit using these relations, independent
  trustee custody, and a threshold-DKG ADR if `t-of-n` is needed.
- For online secret handling: an ADR-0039-style hardened path. Until then, compatibility/offline
  only.

## Risks

- **Misuse of "decrypt once".** An application that decrypts running totals leaks individual
  messages by differencing. Mitigation: documentation and examples. The library cannot enforce
  it.
- **Bound mistakes.** An application that decrypts with too small a search limit gets a
  fail-closed error, not a wrong answer. One that disables bound checks could misread a sum.
  Mitigation: I7, enforced in types.
- **Setup trust.** A subverted setup forges ballots and shares (D4). Mitigation: production
  gates; resolve D4 for setup-free shares.
- **Two schemes on shared guard rails.** A regression in ADR-0051's D2 or D3 machinery now
  affects ElGamal too. Mitigation: both suites run on every change.

## Open questions (points needing a maintainer decision)

1. **Q1 (D4): the trustee proof system.**
   - Options: (a) the SNARK relation only, (b) a ZeroJ-specified Jubjub `ChaumPedersen`
     ciphersuite, (c) wait for upstream.
   - Lean: (a) now, (c) later; do not do (b) without external review. **Escalated.**
2. **Q2 (D5): proof of possession enforced by type, or by documentation.**
   - Option (a) is the `VerifiedKeyShare` type, constructed only through a caller-supplied
     check. Option (b) documents the requirement and accepts raw keys.
   - Lean: (a). It is more ceremony, but a forgotten possession check is exactly the rogue-key
     bug.
3. **Q3 (D1): the message base.** [CGS97] uses an independent message base `G` alongside the key
   base `g` (§2.2, §2.5). This ADR uses one generator for both, as lifted ElGamal commonly does.
   - IND-CPA does not depend on independent bases.
   - The SNARK relation fixes the bases, so soundness does not either.
   - Lean: one generator. **Reviewer to confirm.** The alternative is a second NUMS base derived
     like `pedersen-jubjub-v1`'s `H`.
4. **Q4 (D1, D2): the search algorithm and its limit.**
   - Options: (a) linear search only, (b) baby-step giant-step with a caller-supplied maximum
     and a memory cap.
   - Lean: (b), with the maximum always explicit, defaulting to failure when it is omitted.
5. **Q5 (D3): a general scalar multiplication on `ZkJubjubPoint`.** Lean: no, for the reason in
   the alternatives table. Revisit if a third scheme needs it.

## Related findings (out of scope)

- `ZkJubjubPoint` has no scalar multiplication, so applications fall back to
  `InCircuitJubjub` and hand-written affine checks. Q5 records the decision not to widen it here.
- Julc's local evaluator needs a `SlotConfig` for time-dependent scripts. Without one it passes
  raw slot numbers. Found in the usecase; it concerns usecase tooling, not this ADR.
