# ADR-0052: Exponential ElGamal on Jubjub — additively homomorphic encryption for circuits and tallies

## Status
Accepted (design) — 2026-10-05.
- The reviewer approved r3 at `092cf6b` with no outstanding findings, and the maintainer
  accepted the design.
- Acceptance is design acceptance only. It certifies no implementation, test or security
  property.
- Implementation starts at M0, the normative spec, and proceeds milestone by milestone.
- Q1–Q5 remain maintainer decisions. Each is decided before the milestone that needs it.

This ADR changes no maturity claim. The ADR-0037 production-readiness table and the ADR-0039
assurance classes remain authoritative. Every secret-bearing host operation proposed here stays
in the **compatibility/offline** class (ADR-0039 §3.1).

## Date
2026-10-05

## Revision history
- **r1** (`9fe1c11`) — initial proposal.
- **r2** (2026-10-05; responds to the review of `9fe1c11`):
  - F1 → new D2a (admission and plaintext bounds); message width capped at 64 bits in D1 and
    D3; I6, I7 and I10 rewritten; new I16; M1 and M2 negatives.
  - F2 → new D2b (verified decryption shares); D5 gains a registered key context; new I14
    and I15; M1 negatives.
  - F3 → new D2c (key context on every ciphertext); D7 states that the encoding carries
    neither key nor bound; new I13.
  - F4 → Compatibility rewritten to separate ciphertext compatibility from proof and
    verification-key compatibility; M3 gains a compiled-system gate.
- **r3** (2026-10-05; responds to the review of `f1007ff`): F3 completed. Single-key decryption
  now requires a validated `ElGamalSecretKey` whose public key equals the ciphertext's joint
  key, and `decryptionShare` requires the share's public key to be registered in the
  ciphertext's context. I13 and the M1 negatives are extended.
- **Accepted** (2026-10-05): approved at r3 (`092cf6b`); status flipped without changing the
  design text.

## Risk classification
- **R3:** D1 (the `elgamal-jubjub-v1` profile: the ciphertext, the message encoding and the
  homomorphic semantics), D3 (the in-circuit relations, whose soundness the tally depends on)
  and D4 (the trustee relation and its proof system). These define the scheme's cryptographic
  behaviour, even though the Jubjub arithmetic underneath is not new.
- **R2:**
  - D2 (the host API and its validation);
  - D2a, D2b and D2c (ciphertext admission and bounds, verified decryption shares, key context:
    the trust boundaries of the host API);
  - D5 (key aggregation and proof of possession);
  - D6 (maturity and assurance labelling);
  - D7 (encodings and the order of public inputs).

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
  - claimed tallies;
  - any **plaintext bound** or **key association** claimed for a ciphertext received from
    elsewhere. Points that decode correctly prove nothing about the range of the message, nor
    about which key encrypted it.
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
- **Encryption** of an integer `m ∈ [0, 2^w)`, at a width the caller declares, with
  `1 ≤ w ≤ 64` (`MAX_MESSAGE_BITS`). Since `2^64 − 1 < l`, every admitted message is
  canonical, so no two in-range messages share a ciphertext. At `w = 252` they could: `m` and
  `m + l` both fit in 252 bits, and `[m]·G = [m + l]·G` (F1). Decryption by search is
  practical only for small totals anyway (D2).
  ```
  k ← uniform in [0, l)        (64 random bytes reduced mod l, as pedersen-jubjub-v1 §3.1)
  A = [k]·G                    decryption handle
  B = [m]·G + [k]·PK           blinded message
  ```
- **Homomorphism** (only between ciphertexts under the **same key**, D2c):
  - `Enc(m1) + Enc(m2) = Enc(m1 + m2)`, by component-wise addition.
  - `[c]·Enc(m) = Enc(c·m)` for a public integer `c ≥ 1`.
  - Plaintexts live mod `l`, so reading a result as an integer requires every input's bound to
    be **established**, not merely claimed (D2a), and the result's bound to stay below `l` (I7).
    A successful small discrete log does not detect an earlier wraparound: for example,
    `Enc(l − 1) + Enc(1)` decrypts to `0`.
- **Decryption:** `M = B − [sk]·A = [m]·G`. Then `m` is the unique `t ∈ [0, bound]` with
  `[t]·G = M`, found by a bounded search: linear, or baby-step giant-step, as in [CGS97] §3,
  footnote 3. If no `t` matches, decryption fails closed.
- **Distributed decryption** (n-of-n, see D5):
  - each trustee computes `D_j = [sk_j]·A`;
  - `M = B − Σ_j D_j`.

  This is [CGS97] §2.3 with additive shares; Lagrange coefficients are all 1. Each `D_j` is
  used only after its DLEQ proof is verified against the registered `PK_j` and this exact `A`
  (D2b).

`elgamal-jubjub-v1` is versioned like the Pedersen profiles. Any change to the generator, the
encodings or the randomness derivation is a new profile.

### D2 — Host API in `zeroj-circuit-lib` (R2)

Package `org.zeroj.circuit.lib.jubjub`, next to `PedersenCommitment`. The names are
illustrative. The API has a **raw layer** and a **safe layer**, and only the safe layer gives
the guarantees of this ADR.

- **`ElGamalPublicKey`:** a validated non-identity subgroup point. It is produced only by the
  validating constructors in D5, or by `fromSecret`.
- **`ElGamalKeyContext`** (D5, D2c): a joint key together with the registered set of trustee
  key shares that produced it.
- **`RawElGamalCiphertext`:** the result of decoding 64 bytes (D7). Its points are canonical,
  on-curve and in the subgroup. It carries **no key and no plaintext bound**, so it cannot be
  added or decrypted on the safe path.
- **`ElGamalCiphertext`:** the safe-path type. It carries `(A, B)`, its key context and an
  **established** plaintext bound. It can be created only by admission (D2a).
- **`encrypt(context, m, width, SecureRandom)`:** local encryption. It is one of the two ways to
  admit a ciphertext.
- **`add`, `scale`:** these require the same key context (D2c), combine bounds, and refuse a
  result whose bound reaches `l` (I7).
- **`decryptionShare(secretShare, ciphertext)`:**
  - The input is an `ElGamalCiphertext`, so its handle is already a validated subgroup point
    before any secret multiplication (I15).
  - The method refuses a share whose public key `[sk_j]·G` is not registered in the
    ciphertext's key context (I13).
- **`decrypt(ciphertext, verifiedShares, maxPlaintext)`:** distributed decryption (D2b).
- **`decryptWithSecret(ciphertext, secretKey, maxPlaintext)`:** the single-key path.
  - It takes an `ElGamalSecretKey`: a canonical, non-zero secret `sk ∈ [1, l)`, validated
    together with its public key.
  - It refuses unless `[sk]·G` equals the ciphertext's **joint** key. A trustee's individual
    share is not the full secret and is refused; trustees use `decryptionShare`.
  - Without the check, a wrong secret can return a wrong in-range value. For example, `(G, 4G)`
    is `Enc(1; k=1, PK=3G)`, and secret 4 yields `4G − [4]·G = O`, which decrypts to `0`.
- Both decryption paths use a bounded search with an explicit maximum, and both fail closed.

The API makes no "constant-time" claim. Its secret-bearing methods are named and documented as
compatibility/offline-class (D6). It does not branch on the message: `[m]·G` is computed by
scalar multiplication for every `m`. That removes the most obvious leak of the message, a
different path for `m = 0`, but the operation is still variable-time.

### D2a — Ciphertext admission and plaintext bounds (R2; responds to F1)

A plaintext bound is established only when a ciphertext enters the safe layer. There are
exactly two ways in:

1. **Local encryption**, `encrypt(context, m, width, rng)`. The library checks `m < 2^width` and
   `width ≤ 64`, so the bound is `2^width − 1`.
2. **Verified admission**, `admit(raw, context, width, verifier)`. The caller supplies a
   verifier that checks the D3 encryption statement for **exactly** this ciphertext
   `(A.u, A.v, B.u, B.v)`, this key `(PK.u, PK.v)` and this width. The bound is then
   `2^width − 1`.

   This is a **delegated verifier obligation**, and the Javadoc says so. One legitimate
   delegation is an on-chain validator that already verified that statement before the
   ciphertext reached the ledger, for example the usecase's ballot policy. The caller must
   then establish, from chain data, that the ciphertext is one such validator accepted.

There is no constructor from a claimed bound or a claimed key: relabelling a ciphertext after
serialization is impossible on the safe path. No out-of-circuit range proof is invented; a
range is established only by local encryption or by a verified in-circuit statement.

### D2b — Verified decryption shares (R2; responds to F2)

A claimed share is untrusted. Without verification, a trustee who has seen the other shares
can publish `D_bad = B − [t]·G − Σ D_honest` and make the result any in-range `t` it likes.
The bounded search cannot detect this, because the forged result is in range. [CGS97] §2.3
verifies each authority's proof before combining its share.

- **`VerifiedDecryptionShare.verify(ciphertext, trusteeShare, D, proof, verifier)`** is the
  only constructor. The verifier checks the D3 DLEQ statement with:
  - `X` = this ciphertext's handle `A`, taken from the admitted ciphertext and never from the
    share's sender;
  - `P` = the trustee's **registered** key share from the key context;
  - `D` = the claimed share.

  The resulting object is bound to that ciphertext and that trustee.
- **`decrypt(ciphertext, verifiedShares, maxPlaintext)`** requires all of the following, and
  otherwise refuses:
  - every share is bound to this exact ciphertext;
  - every share belongs to a trustee registered in the ciphertext's key context;
  - there is exactly one share per registered trustee: no share missing, none repeated, none
    foreign;
  - the ciphertext's established bound is at most `maxPlaintext`.
- **Raw layer.** An unchecked `unmask(B, shares)` exists only on the raw layer, documented as
  giving no guarantee against a malicious trustee.

### D2c — Key context on every ciphertext (R2; responds to F3)

The homomorphic identities hold only between ciphertexts under the same key. Adding ciphertexts
under different keys need not fail the search; it can return a wrong in-range value. For
example, `Enc(1; k=1, PK=3G) + Enc(1; k=1, PK=2G)` decrypts to `1` under secret 3.

- Every `ElGamalCiphertext` carries its `ElGamalKeyContext`.
- `add`, `scale` and `decrypt` refuse ciphertexts with different contexts. Contexts compare by
  the joint key and the registered share set.
- A secret is tied to the context as well:
  - `decryptWithSecret` requires the secret's public key to equal the context's joint key;
  - `decryptionShare` requires the share's public key to be registered in the context.
- The 64-byte encoding carries no key (D7). A decoded ciphertext gets its context only through
  admission (D2a), and the verified D3 statement includes the key as public inputs. A bare key
  label is therefore never trusted.
- Raw-layer point arithmetic carries a stated precondition (one key) and no guarantee.

### D3 — In-circuit relations (R3)

A CircuitAPI-level gadget, `InCircuitElGamal`, and a typed annotation adapter, `ZkElGamal`,
with `ZkElGamalPublicKey` and `ZkElGamalCiphertext`, mirroring `ZkPedersenCommitment`.

- **`ZkElGamal.encrypt(zk, ZkUInt message, ZkUInt randomness, ZkElGamalPublicKey key)`** returns
  a ciphertext. `assertAffineEquals(A.u, A.v, B.u, B.v)` binds it to public inputs.
  - `[m]·G` is a fixed-base multiplication over the message's own decomposition, at its declared
    width. One-bit messages may use a selection.
  - The width is `1 ≤ w ≤ 64`, and a wider declaration is refused when the circuit is defined.
    At width 252 a witness with `m = l` satisfies the same constraints as `m = 0` (F1).
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
- **Key context.** Aggregation returns an `ElGamalKeyContext`: the joint key together with the
  registered `VerifiedKeyShare`s. The context is the reference point for share verification
  (D2b) and for the same-key rule (D2c).
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
  - The ciphertext encoding carries **neither a key nor a bound**. Decoding yields a
    `RawElGamalCiphertext`.
  - The key and the bound are restored only through admission (D2a, D2c). Serializing an
    admitted ciphertext and decoding it again yields a raw one, which must be admitted again.
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
| I6 | Messages are integers of a declared width `1 ≤ w ≤ 64`. They are refused above it on the host, proved below it in-circuit, and a wider declaration is refused when the circuit is defined. In particular `m = l` is never admitted. | D1, D2a, D3 |
| I7 | Every safe-layer ciphertext carries a bound established at admission. Homomorphic operations combine bounds and refuse a bound `≥ l`. Decryption requires the bound to be at most the caller's search limit. | D1, D2, D2a |
| I8 | A key enters a circuit only as a verifier-fixed public input (curve equation and non-identity asserted, subgroup checked by the verifier), or as a witness proved to be in the subgroup. | D3 |
| I9 | In a DLEQ statement, the base `X` is chosen by the verifier and enters as public inputs. A possession proof uses `X = G`. A share proof uses the verifier's own recomputed aggregate. | D3, D4 |
| I10 | Decryption runs only on an admitted ciphertext. Distributed decryption runs only with a complete, unique set of verified shares (I14). It returns the unique `t ∈ [0, bound]` with `[t]·G = M`, or fails. | D1, D2, D2b |
| I11 | Public-input orders and byte encodings are exactly those in D7. | D7 |
| I12 | Secret-bearing host operations are documented as compatibility/offline-class, and make no constant-time or online claim. | D6 |
| I13 | Homomorphic operations and decryption act only on ciphertexts with the same key context, and refuse mixed contexts. A key association comes only from local encryption or verified admission. A supplied secret must match the context: the full secret's public key equals the joint key for `decryptWithSecret`, and a share's public key is registered in the context for `decryptionShare`. | D2, D2c, D2a |
| I14 | A decryption share is used only as a `VerifiedDecryptionShare`. That means a verified DLEQ statement with `X` = the admitted ciphertext's handle and `P` = a key share registered in its context. Distributed decryption needs exactly one such share per registered trustee: none missing, repeated or foreign. | D2b, D5 |
| I15 | A secret scalar multiplies only a validated subgroup point. A decryption share is computed only on an admitted ciphertext's handle, so a small-order component cannot leak `sk_j mod 8`. | D2, D2b |
| I16 | A plaintext bound is established only by local encryption or by verifying the D3 encryption statement for the exact ciphertext, key and width. No API accepts a claimed bound, and decoding yields an unbounded raw ciphertext. | D2a, D7 |

## Consequences

- Applications get one reviewed relation and API for private sums, with bounds and key
  provenance enforced by types.
- The usecase drops its private gadget and host class (M3), and keeps only its protocol.
- A second Jubjub scheme reuses the Pedersen-era guard rails (D2, D3 and D4 of ADR-0051). Any
  change to those rails now affects two schemes.
- Proofs of possession and of decryption shares still need a trusted setup until D4 is
  resolved.

## Compatibility

All of it is new API, and nothing existing changes.

**Ciphertext compatibility (promised).** The usecase's ciphertexts, keys and encodings are
`elgamal-jubjub-v1`: the same generator, the same `(A, B)` and the same affine public-input
order. After M3 the library admits and decrypts them. A differential test checks this, with
the same `(m, k)` in, the same points out.

**Proof and verification-key compatibility (not promised).** Groth16 keys and proofs are tied
to the exact compiled constraint system: its rows, its matrices and its wire assignment. Equal
encodings or public-input orders do not make an old proof verify under keys from a re-compiled
circuit. Neither do equal row counts. Moving the usecase onto the library's typed gadgets may
change the system even though the relation is unchanged. Therefore:

- Old proofs are accepted under a new verifier **only** with two pieces of evidence: the
  compiled system is identical (an R1CS digest that covers every row's terms, as the usecase's
  key cache already computes), and archived proofs verify at the real verifier boundary. A
  fresh prove-and-verify round-trip is not evidence that old proofs remain valid.
- Otherwise the migration is a **new circuit version**, with new setup artifacts and a new
  verification key. On-chain, that is a new script and a new policy hash. State that already
  exists, such as an election under way, keeps its old circuit, keys and scripts until it ends.
  Only new deployments use the new circuit.

## Implementation milestones

| Milestone | Scope | Entry gate | Exit criteria |
|---|---|---|---|
| M0 | This ADR. Normative spec `docs/specs/elgamal-jubjub-v1.md`: profile, encodings, relations, public-input orders, and test vectors. | ADR accepted | Spec reviewed. Its vectors come from the independent Python reference, not from the Java code. |
| M1 | Host API (D2, D2a–D2c, D5, D7) | M0 | I1–I4, I6, I7, I10, I11 and I13–I16 tested. Vectors match the spec. Property tests for homomorphism and bounds. Negatives: <br>• decoding: non-canonical, off-curve, small-order; <br>• bounds: `m = l` and widths above 64 refused; a serialized and re-decoded ciphertext is raw and cannot be added or decrypted; the wrapped terms `Enc(l−1) + Enc(1)` cannot be admitted with false bounds; <br>• shares: the forged in-range share (`D2 = 36G` for `35G`, trustee keys `3G` and `5G`, `m = 1`, `k = 7`) refused; missing, repeated, foreign-key, wrong-handle and invalid-proof shares refused; <br>• keys: mixed-key `add` refused (`Enc(1;1,3G) + Enc(1;1,2G)`); `decryptWithSecret` refuses secret 4 for `(G, 4G)` under `PK = 3G`; a trustee share passed as the full secret is refused; `decryptionShare` refuses a secret whose public key is not registered. |
| M2 | `InCircuitElGamal` and the `ZkElGamal` adapter (D3) | M1 | Negatives: <br>• mismatched scalars; <br>• a message above its width; <br>• a message width above 64, refused at definition (the `m = 0` / `m = l` alias at width 252); <br>• an identity or off-curve key; <br>• a wrong share or a wrong base; <br>• a public or narrow randomness. <br>Constraint counts pinned. Groth16 prove and verify, with every public input shown to be bound. |
| M3 | Migrate `zeroj-usecases` private-voting onto the library | M2, and a ZeroJ release containing it | Ciphertext compatibility shown by a differential test. Compiled-system decision recorded: either identical R1CS digests and archived proofs verifying at the verifier boundary, or a new circuit version with new setup artifacts and scripts, with existing elections kept on the old ones. Usecase VM and DevKit end-to-end tests pass. The usecase's private gadget and host class are deleted. |
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
  - Admission and bounds: the M1 cases (`m = l`, relabelling after serialization, wrapped
    imported terms).
  - Shares: the forged in-range share and every malformed share set.
  - Keys: mixed-key arithmetic.
  - Circuits: no witness for every D3 misuse; a proof fails against each changed public input.
- **Differential.** Host encryption against an in-circuit encryption of the same `(m, k)`.
  Usecase ciphertexts before and after M3. Proof compatibility is shown only as the
  Compatibility section requires.
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
- **Bound and admission mistakes.**
  - An application that decrypts with too small a search limit gets a fail-closed error, not a
    wrong answer.
  - An application that bypasses admission through the raw layer, or writes a verifier that
    checks the wrong statement, can misread a wrapped or mislabelled sum.
  - Mitigation: I7 and I16, enforced in types, with the delegated verifier obligation
    documented.
- **Malicious trustees.** A trustee that publishes an unverified share chooses the result.
  Mitigation: I14. The safe decryption path cannot run without verified shares.
- **Setup trust.** A subverted setup forges ballots and shares (D4). Mitigation: production
  gates; resolve D4 for setup-free shares.
- **Two schemes on shared guard rails.** A regression in ADR-0051's D2 or D3 machinery now
  affects ElGamal too. Mitigation: both suites run on every change.

## Open questions (points needing a maintainer decision)

1. **Q1 (D4): the trustee proof system.**
   - Options: (a) the SNARK relation only, (b) a ZeroJ-specified Jubjub `ChaumPedersen`
     ciphersuite, (c) wait for upstream.
   - Lean: (a) now, (c) later; do not do (b) without external review. **Escalated.**
2. **Q2 (D5, D2a, D2b): verification enforced by type, or by documentation.** r2 applies the
   same choice to key shares, to admitted ciphertexts and to decryption shares.
   - Option (a) is the `VerifiedKeyShare` type, constructed only through a caller-supplied
     check. Option (b) documents the requirement and accepts raw keys.
   - Lean: (a). It is more ceremony, but a forgotten possession check is exactly the rogue-key
     bug.
3. **Q3 (D1): the message base.** [CGS97] uses an independent message base `G` alongside the key
   base `g` (§2.2, §2.5). This ADR uses one generator for both, as lifted ElGamal commonly does.
   - IND-CPA does not depend on independent bases.
   - The SNARK relation fixes the bases, so soundness does not either.
   - Lean: one generator. The alternative is a second NUMS base derived like
     `pedersen-jubjub-v1`'s `H`.
   - Review r1 assessed one generator as acceptable for IND-CPA under DDH: in the DDH hybrid,
     `[k]·PK` is replaced by a uniform subgroup point, which hides `[m]·G` whatever the message
     base. This is not the two-independent-bases requirement of a binding Pedersen commitment.
     It remains a maintainer decision.
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
