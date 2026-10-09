# ADR-0055: Confidential notes on Jubjub with encrypted opening delivery (`confidential-note-jubjub-v1`)

## Status
Accepted (design) — 2026-10-09.
- The reviewer approved r4 at `f6f7c90` (round 3, no open P0–P2 findings). The maintainer
  decided Q1–Q9 (r5) and accepted the design.
- Acceptance is design acceptance only. It certifies no implementation, test or security
  property. Assumptions A1–A3 remain unproved, and external review of them is a production gate.
- Tracked as #79. M0–M2, M4 and M5a are implemented on PR #82 ("Implementation status" at the
  end). M3 follows as a zeroj-usecases PR. The implementation is Experimental and makes no
  production claim.
- The in-circuit consistency proof (D3) is **deferred** (Q5 (A), decided). It is blocked pending
  a dedicated, accepted follow-up ADR for a pinned and analysed construction, as ADR-0051
  escalated its D7. The rest of the design does not depend on it.
- r2 adds **D3a**: enforced auditor access to the amount, built only from the accepted
  `elgamal-jubjub-v1` profile. It is gated on measuring its on-chain cost (M5a).
- **Q1–Q9 were decided by the maintainer on 2026-10-09** (r5). Each adopts the author's
  recommendation; see "Open questions".

This ADR changes no maturity claim. ADR-0039's assurance classes apply: every secret-bearing
host operation here is **compatibility/offline** class.

## Date
2026-10-09 (proposed); 2026-10-09 (accepted)

## Revision history
- **r1** (`a1154ac`, 2026-10-09): initial proposal.
- **r2** (`edd5d01`, 2026-10-09; the author's recommendations, before the first review):
  - New **D3a**: enforced auditor access to the amount through `elgamal-jubjub-v1`, with two
    32-bit limbs. The same Groth16 proof binds them to `C`, and the auditor key is a public input
    taken from the registry.
  - New I12 and M5a, with an on-chain cost gate.
  - Q5 gains option (D); the lean is now (A) for the general cipher proof plus (D) for auditors.
  - Q4: the sender reader is off by default.
  - Q6: possession is checked at registration, not per transfer, because Plutus has no Jubjub
    builtins.
  - Q7: enforcing generations needs D3a.
  - Q8: grounded in the Conway ledger's 64-bit quantities.
  - The open questions now open with the author's recommendation.
- **r3** (`ff97517`, 2026-10-09; responds to the review of `edd5d01`):
  - F1 → D5 separates the **exact reuse of the three primitives** from the **adapted note
    protocol**, and lists the changed premises. [ZcashSpec] §8.7's partitioning-oracle argument
    is no longer credited: it needs a note commitment that binds the recipient key, and `C` does
    not. The adaptation's claims are now assumptions A1–A3 for external review, with a candidate
    argument for A3. The threat model, D6, gates and references are updated.
  - F2 → D6 step 4 recomputes `C` on the blinded secret-bearing path (`commit`, then compare),
    never `verify`. New I13 (schedule regression gate). I4 is now algebraic equivalence only.
    D9, Consequences, M2 and M4 separate the cost of a failed trial decryption from a full
    acceptance, and M4 must measure both.
  - F3 → D3a now covers **every created output** of a transaction for every required auditor,
    with a fixed output, limb and coordinate order. The points transfer has two outputs, so it
    needs 18 public inputs (2 key + 2 outputs × 2 limbs × 4), estimated at about 9.25e9 steps,
    **above** the 8e9 gate; and 26–28k added constraints. D3a is therefore **conditional**:
    adopted only if M5a measures within the gate, either as specified or with the
    hash-compressed variant it must also evaluate. Auditor coverage is never reduced. I12, M5a,
    Q5, Compatibility and Consequences are updated.
  - Clarifications: D3a uses a **separate `elgamal-jubjub-v1` auditor key**, paired with the
    auditor's viewing key and generation in the registry (D2, I6). The BLAKE2b gadget figure is
    labelled by its measured shape.
- **r4** (`f6f7c90`, 2026-10-09; responds to the review of `ff97517`):
  - F1 (remaining) → A2 and A3 now rest on **computational** binding. A Pedersen commitment has
    an opening for every value, so "only one opening exists" was false. A3's candidate argument
    is restated computationally and stays an explicitly unproved assumption. The
    wallet-observability sentence is now conditional on A3.
  - F4 → D3a's guarantee is scoped to the **proof-enforced transitions** (transfer and redeem).
    Issuance creates notes without a proof, so its audit data rests on **trust in the issuer**.
    That trust is recorded in the threat model, D3a, I12, M5a, the gates and Consequences.
    Making issuance proof-enforced is new Q9.
  - Hash-compressed variant: the M0 spec must pin its serialization, canonical constraints and
    digest split. The in-circuit bytes must be constrained to the `R_enc` coordinates. Its
    vectors and mutations are added to M0 and M5a.
- The reviewer approved r4 at `f6f7c90` (design acceptance, round 3). F1–F4 are resolved.
- **r5** (2026-10-09; maintainer decisions): Q1–Q9 are decided. Each adopts the author's
  recommendation; the "Open questions" section records them. The text that depended on a lean
  now states the decision: D5 (Q1), D7 (Q4), D3a and M5a (Q5's 80% gate). Q2, Q3, Q6 and Q8
  were already written into D2, D6 and D7. No design content changes.
- The reviewer approved r5 and the status change at `3e80d5a` (round 4).
- **r6** (2026-10-09; responds to the review of `3e80d5a`): F5 (P3), wording only. Text that
  still treated Q5 or Q9 as pending now states the decision: Status, D3, D3a, D10, M5, M5a and
  the production gates. D3 is blocked pending a dedicated, accepted follow-up ADR for a pinned
  and analysed construction. The demo uses trusted issuance (Q9 (a)).

## Risk classification
- **R3:** D2 (viewing keys and key agreement), D5 (the ciphersuite: key agreement, KDF and
  symmetric encryption) and D6 (the plaintext and the recipient's acceptance checks). These
  decide whether an opening stays secret and whether a recipient can be made to accept a wrong
  one.
- **R2:** D1 (the note and its delivery), D7 (ephemeral randomness and sender recovery), D8
  (encodings, the datum and validator obligations) and D9 (secret handling on the host).
- **R3, escalated:** D3 (an optional in-circuit proof that each delivery opens the commitment).
- **R2:** D3a (a circuit composing the accepted `elgamal-jubjub-v1` and `pedersen-jubjub-v1`
  relations; it adds no new primitive).
- **Not decided here:** D4 (twisted ElGamal) is recorded as deferred.

## Context

### Where this comes from
ZeroJ's Pedersen demos (zeroj-usecases, `pedersen-commitments/`) hide amounts as
`pedersen-jubjub-v1` commitments in script datums. The confidential-points ledger keeps one note
per UTxO. Its validator, `PointsLedger`, uses the datum `Note(owner, u, v)`, where `owner` is a
28-byte key hash and `(u, v)` are the commitment's affine coordinates. A transfer spends one note
and creates two.

The openings never leave the process that created them. The demo README says: "Openings are
delivered off-chain. The demos hand them over in-process." The usecase ADR-0006 lists "delivery of
openings and credentials, which happens off-chain" as out of scope. Concretely:
- the sender draws the recipient's blinding (`Note.of(owner, amount)`, which calls
  `PedersenCommitment.randomBlinding`);
- the same Java object is then handed to the recipient's prover;
- the web demo's server keeps every wallet's openings on its behalf.

A recipient, or an auditor, therefore cannot recover a note from chain data. And nothing tells a
recipient that a note sent to it can be opened at all.

ZeroJ's reference validator `ConfidentialNoteValidator` (ADR-0051 M4) has the same shape and the
same gap.

### What this ADR proposes
Each confidential value becomes a **note**:
- the commitment `C`, unchanged `pedersen-jubjub-v1`;
- the opening `(v, r)` encrypted **on-chain** to each of the note's readers (the owner, and any
  auditors the application requires), by Diffie–Hellman on Jubjub.

The pieces fit together as follows:

| Need | Tool |
|---|---|
| Notes, each read on its own: points, payments, payroll, solvency entries | **This ADR:** Pedersen commitment plus a DH-delivered opening |
| Trustees jointly decrypt a sum: tallies, voting | `elgamal-jubjub-v1` (ADR-0052), threshold (ADR-0053) |
| One balance updated in place by many parties, read from one ciphertext | Twisted ElGamal: **deferred** (D4) |

### Why not HPKE, as in ADR-0054
ADR-0054 delivers DKG shares with HPKE (RFC 9180) on X25519. Its alternatives table rejected
"ECIES or ElGamal-based encryption on Jubjub" because "No standardized ciphersuite exists; ZeroJ
would be defining new cryptography."

This ADR does not overturn that. It adopts **Zcash Sapling's in-band secret distribution**, which
is a published, specified and deployed construction on this very curve:
- key agreement `KA^Sapling` (Zcash spec §5.4.5.3);
- the KDF `KDF^Sapling` (§5.4.5.4);
- the symmetric encryption `Sym` (§5.4.3);
- encryption and decryption procedures (§4.20).

ZeroJ's Jubjub is the Sapling curve with the same point encoding. A probe on 2026-10-09 passed
all 10 Zcash Sapling note-encryption vectors through ZeroJ's own independent Jubjub reference
(`pedersen-reference/pedersen_jubjub_v1_reference.py`), using Python's BLAKE2b and pyca
`cryptography`'s ChaCha20-Poly1305. The probe checked `Agree` from both sides, `KDF^Sapling` and
`Sym.Encrypt` (see "Verification").

HPKE on X25519 would also work for an off-chain-only delivery. It is rejected here (see
"Alternatives") because it cannot support the in-circuit proof D3, which needs DH in the proof's
native field.

## Threat model and trust assumptions

- **The chain is public and permanent.** Every datum, and so every ciphertext, can be stored
  forever by anyone ("harvest now, decrypt later"). This is the same exposure ADR-0054 analysed
  for its board.
- **Untrusted:**
  - the sender, as seen by a recipient or auditor: it may post a wrong value, a wrong blinding,
    garbage ciphertexts or reused randomness;
  - every reader public key, until validated;
  - every datum field;
  - other chain users. Anyone can create an output that a wallet's scan will try to decrypt.
- **Secret:**
  - each reader's viewing private key `sk`;
  - each ephemeral private key `e_i`;
  - each note's opening `(v, r)`;
  - every shared secret and symmetric key derived from them.
- **Readers:**
  - The **owner** can spend the note; it needs the opening to prove.
  - An **auditor** sees every amount delivered to it, by design. It is honest-but-curious: it
    must not learn anything that lets it spend (it never receives the owner's spending
    authority), and it must not hold the owner's viewing key.
- **What the construction gives.** The Zcash spec §4.1.6 requires that "the asymmetric
  encryption scheme in §4.20 …, constructed from KA^Sapling, KDF^Sapling and Sym …, is required
  to be IND-CCA2-secure and key-private". §4.1.4 requires that Sym be "one-time
  (INT-CTXT ∧ IND-CPA)-secure", where "One-time here means that an honest protocol participant
  will almost surely encrypt only one message with a given key". The spec states these as
  requirements on its instantiation. This ADR relies on them for each single delivery, which is
  one such ciphertext (D5). It does not re-prove them.
- **What the adaptation assumes** (r3, F1). The note protocol around the primitives is ZeroJ's,
  not Sapling's (D5 lists the differences), so Zcash's protocol-level arguments do not carry over
  automatically. This ADR states its claims as assumptions, for external review:
  - **A1 (confidentiality of a delivery).** With `P_i` validated and `e_i` fresh, `(E_i, ct_i)`
    reveals nothing about the plaintext beyond its length to anyone without `sk_i`. This is the
    §4.1.6 requirement applied to a delivery whose base is `G` rather than `g_d`.
  - **A2 (integrity of acceptance).** An accepted `(v, r)` is an opening of `C`, which D6 step 4
    checks directly. That does not make it the only opening: `C` is statistically hiding, so
    for every value `v` there is exactly one `r` with `[r]·H = C − [v]·G` (r4, F1). What
    `pedersen-jubjub-v1` gives is **computational** binding: no efficient party, the sender
    included, can find two distinct openings of one `C` (to residues mod `l`) without the
    discrete logarithm between `G` and `H`. So a sender cannot get two readers to accept
    different openings of the same note.
  - **A3 (no useful multi-key partitioning).** ChaCha20-Poly1305 is not key-committing. A sender
    knows `e_i`, so it can compute several readers' keys and craft one `ct` that decrypts under
    each of them ([LGR2021]-style). **A3 is an unproved assumption**: a delivery passes
    acceptance under at most one reader key, except with negligible probability, against an
    efficient sender. The candidate argument (r4, restated computationally):
    - suppose `ct` passes acceptance under two keys;
    - if the two plaintexts differ, the sender has found two distinct openings of `C`, which
      computational binding (A2) rules out for an efficient sender;
    - if they are equal, the two keystreams agree on 41 bytes for keys the sender cannot choose
      freely, since each comes from the KDF.

    The argument is ZeroJ's and **has not been reviewed**. In particular, the last step's
    reliance on the KDF is not analysed. [ZcashSpec] §8.7's argument does not apply, because `C`
    does not commit to the reader's key. Acceptance outcomes are local to the wallet. **If A3
    holds**, a wallet that acts visibly on them (for example by spending at once) gives an
    observer at most this one-key outcome.
- **What it does not give:**
  - **No forward secrecy with respect to the reader's key.** Anyone who later obtains a viewing
    key decrypts every note ever delivered to it.
  - **Not post-quantum.** A quantum adversary breaks Jubjub DH and reads every delivered
    opening. The commitments themselves stay statistically hiding, but the deliveries do not.
    This is the same limit ADR-0052/0054 accepted.
  - **No hiding of the transaction graph.** Owners stay public in the datum, and the reader
    count and order reveal the application's auditor policy (ADR-0006 already lists owners,
    prices and note counts as not hidden).
- **What "delivered" means without D3.**
  - A validator can check that a ciphertext of the right length exists for each required reader.
    It cannot check that the ciphertext decrypts, or that it decrypts to `C`'s opening.
  - The recipient detects a bad delivery on receipt (D6), but cannot prevent it.
  - An auditor's guarantee is therefore "a ciphertext addressed to me exists", not "I can read
    this transfer". Making it the latter is D3's purpose. D3a gives it for the **amount**, with
    accepted primitives only, but only for notes created by **proof-enforced transitions**
    (r4, F4).
  - **Issuance is trusted.** A note created without a proof (for example `PointsLedger`'s Issue,
    which checks the issuer's signature, the count and the note shape) carries whatever audit
    data the authorized issuer supplied. An auditor relies on the issuer for those notes, and
    detects bad data only on decryption, unless the application makes issuance proof-enforced
    (Q9).
- **Host side channels.** Scanning decrypts attacker-supplied ephemeral keys with the viewing
  key. The arithmetic is ZeroJ's `BigInteger` Jubjub code, ADR-0039's compatibility/offline
  class (D9).

## Pinned normative references

- **[ZcashSpec]** D. Hopwood, S. Bowe, T. Hornby, N. Wilcox, *Zcash Protocol Specification*,
  version v2026.7.0-282-g3af03a [NU6.2], 2026-10-08 (zcash/zips commit
  `3af03aa3ad991874d86b8cf35919bc9b4671e8ba`). Fetched from https://zips.z.cash/protocol/protocol.pdf
  on 2026-10-09.
  - §4.1.4 (the Sym security requirement) and §4.1.6 (IND-CCA2 and key-private).
  - §4.7.2 "Sending Notes (Sapling)": the sender checks that `pk_d` "MUST be a valid ctEdwards
    curve point on the Jubjub curve …, [r_J]pk_d = 𝒪_J, and pk_d ≠ 𝒪_J". The pre-ZIP-212 path
    chooses "a uniformly random ephemeral private key esk ←R KA^Sapling.Private∖{0}".
  - §4.19.1 "Encryption (Sprout)", for the shared-ephemeral alternative (Q2):
    `K^enc_i = KDF^Sprout(i, h_Sig, sharedSecret_i, epk, pk_enc,i)`.
  - §4.20.1–§4.20.2: encryption, and decryption with an incoming viewing key. The decryption
    note reads: "an implementation MUST use the original ephemeralKey field as encoded in the
    transaction as input to KDF^Sapling".
  - §4.5: "cv and epk MUST NOT be of small order".
  - §5.4.1.2: "BLAKE2b-ℓ(p, x) refers to unkeyed BLAKE2b-ℓ in sequential mode, with an output
    digest length of ℓ/8 bytes, 16-byte personalization string p".
  - §5.4.3: Sym is "AEAD_CHACHA20_POLY1305 [RFC-7539] encryption of plaintext P ∈ Sym.P, with
    empty "associated data", all-zero nonce [0]^96, and 256-bit key K".
  - §5.4.5.3: `KA^Sapling.DerivePublic(sk, B) := [sk]B` and `KA^Sapling.Agree(sk, P) := [h_J·sk]P`.
  - §5.4.5.4: `KDF^Sapling(sharedSecret, ephemeralKey) := BLAKE2b-256("Zcash_SaplingKDF",
    LEBS2OSP_256(repr_J(sharedSecret)) ‖ ephemeralKey)`.
  - §5.4.9.3: Jubjub, `h_J = 8`, and `repr_J`/`abst_J`.
  - §8.7: "the checking of note commitments makes partitioning oracle attacks [LGR2021] against
    the transmitted note ciphertext infeasible". Its argument assumes the note commitment "opens
    to a note with pk_d and g_d". It is cited (r3) to explain why it does **not** apply to this
    profile (A3).
- **[ZIP212]** ZIP 212, "Allow Recipient to Derive Ephemeral Secret from Note Plaintext", Final
  (zcash/zips commit `7b9e678ff3eabf8514f9d0e32cfbf11b27e12696`). Fetched 2026-10-09. It is
  cited for the alternative in Q3.
- **[ZTV]** zcash/zcash-test-vectors, commit `78321beacb0e0477e33cd002b56585a107c2708c`
  (2026-07-01), MIT or Apache-2.0:
  - `test-vectors/json/sapling_note_encryption.json`, SHA-256
    `dda3bed301e90915c2bf35209307d6c9e2d0de103a7ca93e5d15a2c00729f294`. It holds 10 vectors with
    fields ovk, ivk, default_d, default_pk_d, v, rcm, memo, cv, cmu, esk, epk, shared_secret,
    k_enc, p_enc, c_enc, ock, op, c_out. They use lead byte `0x01`, so they predate ZIP 212.
- **[BLAKE2]** J.-P. Aumasson, S. Neves, Z. Wilcox-O'Hearn, C. Winnerlein, *BLAKE2: simpler,
  smaller, fast as MD5*, 2013.01.29, https://blake2.net/blake2.pdf (SHA-256 `3adec538…eb75`,
  fetched 2026-10-09).
  - §2.8 "Parameter block", Table 1: the personalization occupies bytes 48–63 of BLAKE2b's
    parameter block.
  - [RFC7693] (fetched 2026-10-09) specifies BLAKE2 but says personalization and salt "use fields
    in the parameter block that are not defined in this document". It is cited for the core
    function and its Appendix A vector only.
- **[LGR2021]** J. Len, P. Grubbs, T. Ristenpart, *Partitioning Oracle Attacks*, USENIX Security
  2021. Cited through [ZcashSpec] §8.7; not fetched (**unverified** directly).
- **[RFC8439]** Y. Nir, A. Langley, *ChaCha20 and Poly1305 for IETF Protocols*, June 2018. It
  obsoletes RFC 7539, which [ZcashSpec] cites. Fetched 2026-10-09.
  - §2.8 (the AEAD).
  - §4: "The most important security consideration in implementing this document is the
    uniqueness of the nonce used in ChaCha20".
- **[ConwayCDDL]** IntersectMBO/cardano-ledger `eras/conway/impl/cddl/data/conway.cddl`, commit
  `56ddee12ec768b85d14c62da049a33fc05114323`. Fetched 2026-10-09. It defines
  `positive_coin = 1 .. max_word64` and `mint = {+ policy_id => {+ asset_name => nonzero_int64}}`.
- **Protocol parameters** (Koios `cli_protocol_params`, fetched 2026-10-09):
  `utxoCostPerByte = 4310`, and `maxTxExecutionUnits = {steps: 10,000,000,000, memory:
  16,500,000}`.
- **ZeroJ:**
  - ADR-0051 and `docs/specs/pedersen-jubjub-v1.md` (§2 the bases, §3 the commitment and §3.1
    the blinding, §4 the encoding and the subgroup rule);
  - ADR-0052 and `docs/specs/elgamal-jubjub-v1.md` (§2 sampling, §3.1 key validation, §3.3
    possession, §4 width, §6 bounded decryption, §9.1 `R_enc`);
  - ADR-0026 (on-chain Groth16 cost at 2 public inputs);
  - ADR-0039 (assurance classes);
  - ADR-0054 (the public-board analysis and the failure classification of its implementation
    notes 7 and 10).
- **Cited for alternatives only:**
  - D. Khovratovich, *Encryption with Poseidon*, 2019-12-26 (an unreviewed two-page note; Google
    Drive copy, SHA-256 `a5568845…3324`).
  - J.-P. Aumasson, D. Khovratovich, B. Mennink, P. Quine, *SAFE: Sponge API for Field Elements*,
    IACR ePrint 2023/522 (2023-04-11). It is cited for Algorithm 7, which gives authenticated
    encryption as an example only. Theorem 1's proof is in "a separate report", which was not
    located (**unverified**).
  - L. Grassi et al., *Poseidon*, ePrint 2019/458 (last revision 2023-07-05) and USENIX Security
    2021, §3 and §4.2.
  - Y. Chen, X. Ma, C. Tang, M. H. Au, *PGC*, ePrint 2019/319 (last revision 2025-09-06) and
    ESORICS 2020; twisted ElGamal in §5.1.
  - RFC 9180 (as pinned by ADR-0054); RFC 9496 (ristretto255).
  - dusk-network/phoenix (`b0778cb`, MPL-2.0). Its CHANGELOG [0.27.0] (2024-04-24) reads "Use
    AES-GCM from the `Encryption` module throughout the code, instead of `PoseidonCipher`".

## Notation

- `G`, `H`: the `pedersen-jubjub-v1` bases (§2). `l`: the prime subgroup order. `𝔾`: the
  prime-order subgroup.
- `C = [v]·G + [r]·H`: the commitment, with `v` the value and `r ∈ [0, l)` the blinding.
- `encode`/`decode`: the 32-byte `pedersen-jubjub-v1` §4 point encoding, which equals Sapling's
  `repr_J`/`abst_J` on canonical inputs.
- Reader `i` has the viewing key pair `(sk_i, P_i = [sk_i]·G)`. Reader 0 is the owner.

## Decision

### D1 — The note and its delivery (R2)

A note is one output whose datum carries:
- `C`, as today: affine `(u, v)` for validators and proofs (`pedersen-jubjub-v1` §5);
- a **delivery** for each reader `i = 0 … k`, in an order the application fixes. The owner comes
  first, then the application's auditors in the registry's order. Each delivery is
  `(E_i, ct_i)`, where:
  - `E_i = encode([e_i]·G)` is a fresh ephemeral public key;
  - `ct_i = Sym.Encrypt(K_i, P)`;
  - `K_i = KDF(encode([8·e_i]·P_i), E_i)`;
  - `P` is the plaintext of D6.

Every reader decrypts the same plaintext `P`. A reader who decrypts it then verifies that it
opens `C` before accepting the note (D6).

The commitment stays `pedersen-jubjub-v1`, so ADR-0051's gadgets and `ZkPedersen.assertBalanced`
are reused unchanged. Applications choose whether the note's owner credential (a key hash, as in
`PointsLedger`) and its viewing key are related. This ADR requires only that they be separate keys
(D2).

### D2 — Readers and viewing keys (R3)

- **Key pair.** `sk ∈ [1, l)` is sampled as in `elgamal-jubjub-v1` §2: 64 CSPRNG bytes, reduced
  mod `l`, resampled at 0. `P = [sk]·G`. This is `KA^Sapling.DerivePublic(sk, G)` with the
  Pedersen base `G` in place of Sapling's diversified base `g_d`.
- **Key validation (sender side).** Before encrypting to `P_i`, the sender requires `P_i` to:
  - decode canonically (`pedersen-jubjub-v1` §4);
  - lie in `𝔾`;
  - not be the identity.

  This is Sapling's `KA^Sapling.PublicPrimeOrder` check (§4.7.2) and `elgamal-jubjub-v1` §3.1's
  rule.
- **Key separation.** A viewing key:
  - is used only for `confidential-note-jubjub-v1`;
  - is never an `elgamal-jubjub-v1` key, an EdDSA key, a spending key or a Zcash key;
  - is not derived from any of them.
- **Proof of possession.** A key in an application registry (auditors, and owners where
  required) comes with a possession proof of the `elgamal-jubjub-v1` §3.3 form (DLEQ with
  `X = G`, `D = P`), made over the viewing key itself (Q6). Only the proof's form is reused; the
  key stays a viewing key (I6). Possession shows that the registrant can decrypt. It does not show that the
  registrant is the auditor the application intends; that is registry governance (D8).
- **A D3a auditor has two keys** (r3). Its viewing key `P` (this profile) receives D5
  deliveries. A separate `elgamal-jubjub-v1` key `PK_a` receives D3a's limb ciphertexts. The
  two are distinct key types (I6); neither is derived from the other.
  - The registry records both as one entry per auditor and generation, each with its own
    possession proof.
  - A transfer uses the pair from one generation.
- **Rotation.** A reader rotates by registering a new key. Notes delivered earlier stay readable
  only by the old key, which the reader must keep for as long as it needs them. Generations of
  auditor keys (one per period) limit what one leaked key exposes (Q7).

### D3 — Optional in-circuit consistency proof (R3; deferred, Q5)

An application may want the transfer proof to also show, for each required reader, that `ct_i`
decrypts under `P_i` to the opening of `C`. That turns "a ciphertext exists" into "the reader can
read this note":
- in payroll, it rules out unreadable salary notes;
- for regulated tokens, the auditor is guaranteed to read every transfer.

**It cannot be built on D5's ciphersuite at a sensible cost.** Proving D5 in R1CS needs, per
reader:
- BLAKE2b over the KDF's 64-byte input. `gadgets.md` gives 76,832 constraints per block. The
  first review measured 76,352 rows for the existing unpersonalized BLAKE2b-256 gadget at a
  64-byte secret input, and 75,808 at 32 bytes; a personalized variant is not built;
- ChaCha20 and Poly1305, for which ZeroJ has no gadgets.

That is an **estimate of the order of 10^5 constraints per reader**, against 7,231 for the whole
current transfer circuit (ADR-0051, measured).

A circuit-friendly profile would need:
- a cipher native to the BLS12-381 scalar field, i.e. Poseidon-based authenticated encryption;
- one fixed-base multiplication per reader (1,506 constraints, measured);
- one variable-base multiplication per reader (5,533, measured);
- a few Poseidon permutations.

The **estimate** is under 10^4 constraints per reader. But no Poseidon AE construction meets this
project's bar for "pinned and analysed":
- Khovratovich's note is a two-page draft. It states no security claim and no nonce rule, and its
  decryption step is ambiguous in the extracted text.
- SAFE's authenticated encryption is an example (Algorithm 7) whose proof is deferred to a report
  that was not located.
- Dusk, the main production user of Jubjub plus a Poseidon cipher, moved its note encryption to
  HKDF plus AES-GCM in 2024. Its current transfer circuit does not prove that the note's value
  encryption decrypts.

So D3 is **deferred** (Q5 (A), decided 2026-10-09). It is **blocked pending a dedicated,
accepted follow-up ADR** for a pinned and analysed construction, which would be a separate
profile (for example `confidential-note-jubjub-poseidon-v1`).

Nothing in D1, D2 and D5–D9 depends on D3. The datum layout reserves no D3 fields: a D3 profile
would be a different profile with its own datum, not an option within this one.

### D3a — Enforced auditor access to the amount (R2; r2; Q5 (D))

The cases that need enforcement are the **auditor's**. An owner is a party to the payment and
detects a bad delivery on receipt (D6). An auditor sees the transfer only through the chain. An
auditor also needs only the amount, not the blinding.

D3a gives each required auditor an amount it is **guaranteed** to decrypt, using only what
ADR-0052 already accepted:
- **Coverage: every note a proof-enforced transition creates** (r3, F3; scoped in r4, F4).
  - In a transition whose validator verifies the transaction's Groth16 proof (in the points
    demo, transfer and redeem), the relation covers **every note output the transaction
    creates**, for **every required auditor**. A transfer with two outputs audits both, and this
    coverage is never reduced to save cost.
  - Transitions without a proof are **not** covered. In the points demo that is issuance. Their
    audit data rests on the authorized issuer, which the validator authenticates but whose
    ciphertexts it cannot check. The demo uses this trusted issuance (Q9 (a), decided).
    Applications whose auditor must not trust the issuer add an issuance proof (Q9 (b)).
- **Limbs.** For each created note `o`, the prover splits `v_o = L_{o,0} + 2^32·L_{o,1}`, with
  each `L_{o,j} < 2^32` constrained in the circuit.
- **Encryption.** It encrypts each limb to the auditor's ElGamal key `PK_a` (D2: a separate key
  from the auditor's viewing key) with `elgamal-jubjub-v1` at width `w = 32` (spec §4), with an
  independent `k` per limb.
- **One proof.** The transfer's Groth16 proof asserts, alongside the existing balance relation:
  - `R_enc(32)` (spec §9.1) for each limb ciphertext;
  - each limb decomposition;
  - that the `v_o` opening note `o`'s `C_o` is the `v_o` its limbs recombine to (one witness,
    one decomposition).
- **Public inputs, in a fixed order.**
  - First, each required auditor's `PK_a` (`u`, then `v`), in registry order. The validator
    takes them from the registry's reference input, one generation per transaction. This makes
    the generation enforceable (Q7).
  - Then, for each created note in transaction output order, for each auditor in registry order,
    for limb 0 then limb 1: `A.u, A.v, B.u, B.v`. The validator takes them from that output's
    datum.
  - No redeemer supplies any of them.
  - `R_enc`'s key-membership rule makes `PK_a ∈ 𝔾` the verifier's obligation. It is discharged
    when the key is registered (Q6).
  - Count: `2·a + 8·a·n_out` for `a` auditors and `n_out` created notes. The points transfer
    (two outputs, one auditor) needs **18**; the redeem (one change note) needs **10**. Four
    16-bit limbs would need 34 for the transfer.
- **Datum.**
  - Each note's limb ciphertexts are stored as affine coordinates, as `C` is, because a
    validator cannot afford Jubjub point decompression.
  - That is 8 field elements per auditor per note, about 270 bytes of CBOR. At 4,310 lovelace
    per byte it adds about 1.2 ADA of minimum ADA per note (estimate).
- **Decryption.** The auditor decrypts each limb by bounded discrete log, `maxPlaintext = 2^32 − 1`.
  The ElGamal benchmark (2026-10-05) measured, at `2^32`, a 21 ms table build (once, reusable)
  and 7–19 ms per solve, so a whole note takes well under 0.1 s.
- **Why 32-bit limbs.** A Groth16 public input costs on-chain work: one G1 multiplication and
  addition each.
  - ZeroJ measured about 2.14e9 CPU at 2 public inputs (ADR-0026) and about 4.25e9 at 9
    (ADR-0052's ballot validator). That is roughly 0.3e9 per extra input, an upper estimate
    because the ballot figure includes validator logic.
  - The points transfer already costs 3.85e9 of the 10e9 per-transaction step limit
    (`maxTxExecutionUnits.steps`, Koios, 2026-10-09).
  - For the two-output transfer, two 32-bit limbs add 18 public inputs: about 3.85e9 +
    18 × 0.3e9 ≈ **9.25e9 steps, above the 8e9 gate** (r3, F3; r2 counted one output only). Four
    16-bit limbs would add 34 inputs, far beyond the 10e9 limit.
  - These are estimates. M5a must measure them.
- **Circuit cost estimate.** About 26–28k added constraints per transfer with one auditor, from
  four `R_enc(32)` instances, each between the measured 6,558 (`w = 1`) and 6,938 (`w = 64`). The
  transfer circuit itself is 7,231.
- **A variant M5a must also evaluate: hash-compressed public inputs.** This reduces cost without
  reducing coverage.
  - The validator hashes the canonical serialization of every audit ciphertext coordinate in the
    transaction with Plutus's `blake2b_256` builtin.
  - It passes the digest as two 128-bit public inputs, beside the `PK_a` coordinates.
  - The circuit recomputes the same BLAKE2b over its witnessed coordinates.
  - The public inputs then drop to `2·a + 2`, which is 4 for the transfer.
  - The cost moves into the prover: about 512 bytes of input is four BLAKE2b blocks, an
    **estimate** of about 3×10^5 more constraints.
  - It uses only pinned primitives and existing gadgets.
  - **Before implementation, the M0 spec must pin** (r4):
    - one unambiguous, ordered serialization (D3a's order), with canonical coordinates
      (`< p`) and a fixed byte width;
    - the exact lossless split of the 256-bit digest into two 128-bit public inputs;
    - in-circuit, the hashed bytes constrained to the coordinates the `R_enc` instances
      actually use.

    It also needs independent serialization and digest vectors, and mutations of either
    output, of the order and of each digest half. A lower public-input count is not evidence
    that the variant fits its budget; M5a measures it like the specified layout.
- **What it does not give.**
  - The auditor learns the amount, not the blinding, and cannot spend.
  - The owner's delivery stays D5 (detect-only).
  - The ciphertexts are IND-CPA ElGamal, under ADR-0052's threat model. They are bound to `C` by
    the proof, not by an AEAD.
  - When D3a is used, the auditor's D5 delivery is optional: it adds the blinding but no
    enforcement.
- **Gate: D3a is conditional** (r3). It is adopted only if M5a measures the **complete**
  transfer (every output audited) within budget with a stated margin (decided, Q5: at most 80%
  of the step and memory limits), as specified or with the hash-compressed variant. By the r3 estimate,
  the configuration as specified does not fit. If neither fits, D3a stays deferred: auditing
  stays detect-only, and the documentation says so plainly.

### D4 — Twisted ElGamal (deferred)

Twisted ElGamal (PGC §5.1: `X = pk^r`, `Y = g^r·h^m`) makes `Y` a Pedersen commitment and lets the
key holder recover a small `m` by discrete log, with no symmetric cipher. It pays off only for an
**account-shaped** balance: one UTxO or map entry that many parties update in place, read from a
single ciphertext without scanning history.

No current ZeroJ usecase has that shape, and on Cardano it also has a concurrency cost, since two
senders contend for one UTxO. Notes avoid that: payments create new outputs, which the owner
merges later.

Its other properties, recorded for if it is ever reconsidered:
- it is IND-CPA only (PGC Theorem 5.1);
- decryption is bounded, so large values need limbs;
- it decrypts with `sk⁻¹`, so ADR-0053's threshold DKG does not apply.

### D5 — Ciphersuite (R3)

ZeroJ uses Sapling's three primitives, unchanged except for two parameters (the base and the
personalization strings, Q1):
- **Key agreement:** `KA^Sapling`.
  - `DerivePublic(e, G) = [e]·G`.
  - `Agree(sk, X) = [8·sk]·X`.

  Every point it takes has been checked to be in `𝔾` (D2, D6), so the cofactor multiplication is
  kept for fidelity to the spec. It is not relied on.
- **KDF:** `KDF(sharedSecret, E) = BLAKE2b-256(pers_KDF, encode(sharedSecret) ‖ E)`.
  - The input `E` is the **received** 32-byte encoding ([ZcashSpec] §4.20.2's rule), not a
    re-encoding.
  - `pers_KDF` is the 16-byte personalization `"ZeroJ_NoteKDF_v1"` (Q1, decided).
- **Symmetric encryption:** `Sym` = AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8) with a 256-bit key,
  empty associated data and the all-zero 96-bit nonce.
  - This is safe **only** because every key is used once (I2).
  - The plaintext is 41 bytes (D6), so `ct` is 57 bytes.

No other suite, mode or negotiation is accepted.

**What is exact, and what is adapted** (r3, F1).
- **Exact: the three primitives and their composition for one ciphertext.** These are
  `DerivePublic`, `Agree`, `KDF` over `(sharedSecret, received epk bytes)` and `Sym` with a fresh
  ephemeral key. They come from one specification, with stated security requirements (§4.1.4,
  §4.1.6) and independent vectors ([ZTV]). Q1's personalization is a parameter that BLAKE2
  provides for exactly this purpose ([BLAKE2] §2.8). The implementation takes the strings as
  parameters, so [ZTV] runs through the same code with Zcash's strings (I10). The vectors show
  primitive conformance, nothing more.
- **Adapted: the note protocol and the acceptance predicate.** The premises that change from
  Sapling are:
  - the base is the fixed Pedersen `G`, not a diversified `g_d`, and there are no diversified
    addresses;
  - the commitment `C = [v]G + [r]H` commits to the opening only. Sapling's note commitment also
    binds the recipient's `g_d` and `pk_d`;
  - a note has several deliveries, one per reader, each with its own ephemeral key;
  - the plaintext is ZeroJ's (D6), not Sapling's note plaintext;
  - the owner credential (D6 step 5) is an application rule, not cryptographically tied to the
    viewing key.

  The adaptation's security claims are therefore stated as assumptions A1–A3 (threat model), not
  inherited from Zcash's protocol arguments. They are an external-review gate.

### D6 — Plaintext and acceptance (R3)

- **Plaintext.** `P = 0x01 ‖ I2OSP_8(v) ‖ I2OSP_32(r)`, 41 bytes.
  - The lead byte is the profile version.
  - `v ∈ [0, 2^64)` is the value. Amounts are 64-bit, as in ADR-0051's gadget convention and both
    demos (Q8).
  - `r ∈ [0, l)` is the blinding, sampled by `pedersen-jubjub-v1` §3.1.
  - The byte order follows ZeroJ's scalar encodings. The M0 spec fixes it, and the reference
    checks it.
- **Opening is explicit** (option (a) of #79). `r` is random and independent of `e_i`, so `C`
  keeps `pedersen-jubjub-v1`'s statistical hiding. The ZIP 212 alternative (derive `r` and `e`
  from a seed in the plaintext) is Q3.
- **Acceptance.** A reader accepts a note only if **all** of these hold:
  1. `E_i` decodes canonically, lies in `𝔾`, and is not the identity. Sapling's consensus rule
     is "epk MUST NOT be of small order" (§4.5); ZeroJ requires full subgroup membership,
     because its blinded multiplication is valid only on subgroup points (D9).
  2. `ct_i` is exactly 57 bytes, and `Sym.Decrypt(K_i, ct_i)` succeeds, with `K_i` computed from
     the received `E_i` bytes.
  3. The lead byte is `0x01`, and `r < l`.
  4. `[v]·G + [r]·H` equals the datum's `C`. The comparison may be of encodings or of affine
     coordinates. The recomputation handles a secret opening, so it uses the blinded
     secret-bearing path: `PedersenCommitment.commit(v, r)`, then a comparison. It **never** uses
     `PedersenCommitment.verify`, which is for disclosed openings and runs unblinded
     variable-time multiplications (r3, F2; I13).
  5. The output's owner credential is the wallet's own, for the owner role, and the output is at
     the application's script address with the application's note token.

  Steps 1–4 are the profile's. Step 5 is the wallet's application rule: without it, a copied
  `(C, deliveries)` placed in someone else's output would look like the wallet's note.
- **Failure is "not mine".** Any failure of steps 1–4 means the delivery did not open, and the
  wallet records nothing from it. A platform fault (an unavailable or erring primitive) is not
  a failure of the delivery. As in ADR-0054's implementation note 7, it fails closed and the scan
  is retried.
- **An owned note that does not open** (step 5 holds, steps 1–4 fail for the owner's delivery)
  is reported to the wallet's user as **unopenable**, not silently skipped. It is value the user
  owns but cannot spend, and it is the evidence of a misbehaving sender.
- **Why check `C`.** The check makes the opening, not the ciphertext, the authenticated object:
  a delivery that decrypts but does not open `C` is rejected (A2). It is also the premise of the
  candidate multi-key argument A3. [ZcashSpec] §8.7's argument is **not** claimed: it relies on
  a note commitment that binds the recipient's key, and `C` binds no key.

### D7 — Ephemeral randomness and sender recovery (R2)

- **Fresh randomness per delivery.** Each `e_i` is sampled independently from a CSPRNG for each
  delivery (as in D2's sampling), so each `K_i` is used once. A repeated `e_i` toward the same
  reader key repeats `K_i` under the fixed nonce. Then "both the one-time Poly1305 key and the
  keystream are identical between the messages" (RFC 8439 §4): the XOR of the two plaintexts
  leaks, and the repeated Poly1305 key allows forgeries.
- **Deterministic `e` is rejected.** Deriving `e` from the sender's key and the spent input would
  let the sender re-derive its outgoing payments. But two conflicting transactions built from the
  same input with different contents would then reuse keys: both are visible in the mempool or to
  relays even though only one confirms. An attempt nonce would avoid that, but it must itself be
  unique, which brings back the randomness requirement.
- **One ephemeral key per reader** (Q2). Each `(E_i, ct_i)` is then exactly one Sapling-style
  ciphertext, inside the analysed single-recipient setting. Sharing one `E` across readers would
  save 32 bytes per extra reader, but Sapling's KDF binds neither the reader's key nor an index;
  Sprout's shared-ephemeral design binds both (§4.19.1). A shared `E` would therefore need a
  ZeroJ-defined KDF.
- **Sender recovery.** A sender that wants to re-read what it sent adds itself as an ordinary
  reader (Q4, decided), and does so **only if it opts in**; the default is off. Sapling's `ovk`/`C^out` mechanism is the alternative. A sender that does not
  keep `e_i`, or add itself, gains forward secrecy against later compromise of its own secrets.

### D8 — Encodings, the datum and validator obligations (R2)

- **Where the deliveries live: the inline datum** (Q7).
  - Plutus V3's `TxInfo` has no metadata field (Julc `org.julclang.ledger.TxInfo` lists inputs,
    reference inputs, outputs, fee, mint, certificates, withdrawals, validity range,
    signatories, redeemers, datums, id, votes, proposals and the treasury fields).
  - So only a datum lets a validator require a delivery for each registered reader.
- **Layout** (illustrative; the M0 spec fixes it): `Note(owner, u, v, deliveries)`, where
  `deliveries` is a list of `(E: bytes 32, ct: bytes 57)` in reader order.
- **Size.** Each reader adds 89 bytes, plus a few bytes of CBOR framing.
  - With the owner and one auditor that is 178 bytes. At mainnet's `utxoCostPerByte` of 4,310
    lovelace (Koios `cli_protocol_params`, fetched 2026-10-09), it raises a note's minimum ADA by
    about 0.8 ADA (estimate).
  - The demo's fixed 2 ADA per note (`ConfidentialPoints.noteAmounts`) must then be computed
    rather than hard-coded.
- **What a validator checks.** For every output note:
  - the datum's shape and exact field lengths;
  - the number of deliveries;
  - for required readers, that a delivery occupies their position.

  It may check that each `E_i` is a canonical encoding. It cannot check decryptability (without
  D3), and should not pretend to.
- **What stays the application's** (no proof or library provides it):
  - binding the proof's public inputs to the datum's `C` (unchanged from today);
  - `ScriptContext` binding, owner authorization and replay (unchanged from ADR-0006);
  - the **integrity of the reader registry**: who may register an auditor key, how a generation
    changes, and which generation a transfer must use. A registry is typically a reference input
    holding the keys, with their possession statements checked off-chain or on-chain.

### D9 — Secret handling on the host (R2)

- Key generation, encryption (`[e_i]·G`, `[8·e_i]·P_i`), decryption (`[8·sk]·E_i`) and the
  acceptance recomputation of `C` (`[v]·G`, `[r]·H`; D6 step 4) run on ZeroJ's `BigInteger`
  Jubjub code, using the blinded best-effort schedule (ADR-0038) on subgroup points only. This is **compatibility/offline class** (ADR-0039 §3.1). There is no
  constant-time claim.
- **Scanning is the sensitive case.** A wallet decrypts attacker-chosen `E_i` with its viewing
  key, once per note. It must run where no attacker can observe its timing: in the user's own
  wallet process. It must never run as a shared or network-facing scanning service.
- BLAKE2b now hashes secrets (the shared secret). ZeroJ's `Blake2bDigest` is documented as
  "hashes public data only" and has no personalization. M1 extends it with the [BLAKE2] §2.8
  parameter block and reviews it for secret input; BLAKE2b's ARX rounds have no data-dependent
  branches or table lookups.
- ChaCha20-Poly1305 comes from the JDK (`Cipher` "ChaCha20-Poly1305"), as in ADR-0054. Lookups
  are algorithm-only, with ADR-0054's input-versus-platform-fault classification.
- Secrets in `byte[]` are wiped after use, best effort. `BigInteger` copies cannot be wiped.
- **Costs** (r3, F2). These are **estimates** from measured components (ElGamal benchmark,
  2026-10-05, Apple M4 Max). M4 must measure both paths.
  - **A failed trial decryption** (a note not for this key): about 1.8 ms per note per viewing
    key, or about 1.8 s per 1,000 notes. That is a 38 µs decode, an 85 µs subgroup check and a
    1,650 µs blinded multiplication; the AEAD rejects, and the hash and AEAD are negligible.
  - **A full acceptance** adds the blinded recomputation of `C`: two more blinded
    multiplications, about 3.3 ms. The first review measured about 2.94 ms for this step alone
    after warm-up. That gives about 5 ms per accepted note.

### D10 — Out of scope
- Hiding owners, the transaction graph, note counts or reader roles.
- Note discovery beyond scanning the application's script address (for example tags or detection
  keys).
- Spending keys and owner authorization, which stay the application's (ADR-0006).
- A post-quantum construction.
- D3, deferred (Q5): blocked pending a dedicated, accepted follow-up ADR.

### Alternatives considered

| Alternative | Why not |
|---|---|
| HPKE (RFC 9180) on X25519, reusing ADR-0054's code | Standard and already implemented, but X25519 is not native to BLS12-381 circuits, so D3 could never be added. Reader keys would be a second curve beside Jubjub. Kept as the fallback if D3 is abandoned for good. |
| A "Sapling-like" design with HKDF-SHA256 in place of BLAKE2b | It mixes primitives into a combination that no pinned specification analyses or provides vectors for. |
| Encrypting only `v` and deriving `r` from the shared secret (option (b) of #79) | `C`'s hiding becomes computational. With several readers, each reader's shared secret would give a different `r`, so it does not work. |
| Openings delivered off-chain (today) | No recovery from chain data, and no evidence of delivery. This is the gap this ADR closes. |
| Transaction metadata for the deliveries | Cheaper in min-ADA, but invisible to Plutus validators (D8), so required readers cannot be enforced. |
| Twisted ElGamal | Deferred (D4). |
| ristretto255 | Not available on Plutus, and not native to BLS12-381 circuits. Revisit only for interoperability if Plutus gains builtins. |

## Security invariants

Each invariant names the decisions it constrains. Tests in M0–M2 check each one.

- **I1 (D5) Fixed suite.**
  - The implementation provides exactly `KA^Sapling`, `KDF^Sapling` with the profile's
    personalization, and `Sym`.
  - No negotiation.
  - A wrong-length `E` or `ct` is a failed delivery, not an exception.
- **I2 (D5, D7) One use per key.** Every delivery uses a fresh `e_i`, so every `K_i` encrypts
  exactly one plaintext under the zero nonce.
  - No API accepts a caller-chosen `e_i` except a package-private test seam.
  - Within one note, reader keys are pairwise distinct.
- **I3 (D6) Acceptance is all-or-nothing.** A note is accepted only after D6 steps 1–4 pass. A
  delivery that decrypts but does not open `C` is never accepted.
- **I4 (D1, D6) The commitment is unchanged.** `C` is exactly `pedersen-jubjub-v1`'s `C(v, r)`.
  In tests, the delivered `(v, r)` also satisfies `PedersenCommitment.verify`, as an algebraic
  cross-check only. The acceptance path itself follows I13.
- **I5 (D2) Reader keys validated.** No encryption to a key that is non-canonical, outside `𝔾`,
  or the identity.
- **I6 (D2) Key separation.** A viewing key is never used by another profile, and no other
  profile's key is accepted as one. This is enforced by distinct key types.
- **I7 (D6, D8) Received points validated.** `E_i` is decoded canonically and subgroup-checked
  before any secret multiplication. The KDF hashes the received bytes.
- **I8 (D6) Uniform failure.** Every input-caused failure in steps 1–4 has the same outcome
  ("not mine") and the same exception-free API result. A platform fault is an exception and never
  "not mine".
- **I9 (D6) Unopenable owned notes are reported**, not dropped.
- **I10 (D5) Conformance.** With Zcash's personalization strings, the KA, KDF and Sym code
  reproduces every [ZTV] Sapling note-encryption vector (`shared_secret`, `k_enc`, `c_enc`, and
  `Agree(ivk, epk)`). With the profile's strings, it reproduces the independent reference.
- **I12 (D3a) Enforced auditor amount, for every note a proof-enforced transition creates.**
  - The scope is transfer and redeem in the points demo. Issuance is excluded and trusted (F4,
    Q9).
  - For each such created note `o` and each auditor, the circuit constrains
    `L_{o,0}, L_{o,1} < 2^32` and `v_o = L_{o,0} + 2^32·L_{o,1}`, with the same `v_o` opening
    `C_o`.
  - Each limb ciphertext satisfies `R_enc(32)`, with its own 252-bit `k`.
  - `PK_a` and every ciphertext coordinate, or their digest in the hash-compressed variant, are
    public inputs in D3a's fixed order. The validator fixes them from the registry reference
    input and each output's datum; no redeemer supplies them.
  - Invalid-witness and mutation tests:
    - a wrong limb, or a limb at `2^32`;
    - swapped ciphertexts, between limbs or between outputs;
    - another key;
    - a recombination that differs from `C_o`'s `v_o`;
    - either output's audit data absent, wrong, or not bound;
    - for the hash-compressed variant: a mutated serialization, order or digest half.
- **I13 (D6, D9) Secret-bearing acceptance path** (r3, F2). The acceptance recomputation of `C`
  uses the blinded schedules for both `v` and `r`, and never an unblinded multiplication by a
  secret scalar. A schedule regression test (in the style of `SecretScalarScheduleTest`) counts
  the blinded schedules on the acceptance path and fails if `verify` or another unblinded path
  is used.
- **I11 (D9) Secret class.** Secret multiplications run on subgroup points only, with the
  blinded schedule. No API or document claims constant time or online suitability.

## Consequences

- Recipients and auditors can recover every note from chain data alone, and they detect bad
  deliveries on receipt.
- Notes get bigger: 89 bytes per reader, and about 0.8 ADA more minimum ADA with one auditor
  (estimate).
- Wallets must scan. The estimates from measured components are about 1.8 ms per note per
  viewing key for a failed trial decryption, and about 5 ms for an accepted note. Scanning needs
  the offline class's isolation.
- The demos' validators, datums and transaction builders change (M3), but their circuits and
  verification keys do not: deliveries are not public inputs.
- ZeroJ gains a personalised BLAKE2b used on secret data, and a second Jubjub key type.
- Without D3 or D3a, auditor access is only as good as the senders' honesty, with detection
  afterwards. With D3a, if M5a admits it, the amount of every note created by a proof-enforced
  transition (transfer, redeem) is enforced; issued notes rest on the issuer (Q9). For the
  points transfer with one auditor, that costs 18 more public inputs (or 4 with the
  hash-compressed variant), 26–28k more constraints (plus about 3×10^5 for the variant), and
  about 1.2 ADA more minimum ADA per note (estimates, M5a).

## Compatibility

- **New profile** `confidential-note-jubjub-v1`. `pedersen-jubjub-v1`, its encodings, gadgets and
  vectors are unchanged.
- **New public API**, Experimental: viewing keys, sealing deliveries and opening them. Names are
  fixed in M2.
- The usecase datum changes from `Note(owner, u, v)` to `Note(owner, u, v, deliveries)`. Old
  notes have no deliveries. Migration is a usecase concern (M3): the demo has no deployed state to
  migrate.
- No change to ADR-0052/0053/0054 profiles.
- D1–D9 leave circuits and verification keys unchanged. D3a, if adopted, changes the transfer
  and redeem circuits, their public-input layouts and their verification keys, and so their
  validators.

## Implementation milestones

| ID | Scope | Entry gate | Exit criteria |
|---|---|---|---|
| M0 | Normative spec `docs/specs/confidential-note-jubjub-v1.md`. An independent Python reference, written from the spec and [ZcashSpec] with no Java read. The vendored [ZTV] file, pinned by commit and SHA-256. | ADR accepted; Q1–Q4 and Q6–Q8 decided | The reference reproduces all 10 [ZTV] vectors (I10) and the [BLAKE2]/RFC 7693 Appendix A vectors. It emits replayable cases: good deliveries for 1–4 readers; every D6 failure (wrong key; tampered `E`/`ct`; `E` non-canonical, small-order, outside `𝔾` or the identity; wrong length; bad lead byte; `r ≥ l`; an opening that does not match `C`); a repeated `e_i` (shown to leak the plaintext XOR); and the copied-note case for D6 step 5. If Q5 (D) is adopted: D3a's public-input order and, for the hash-compressed variant, its serialization, digest split and vectors (r4). Byte-identical output on rerun. |
| M1 | Host primitives: personalised BLAKE2b; `KA`, `KDF`, `Sym` on JDK ChaCha20-Poly1305; the fault classification. | M0 | [ZTV] KATs (I10); a BLAKE2b differential with personalization against BouncyCastle in tests; negatives for every malformed input; a native-image probe with identical output (as ADR-0054 M1). |
| M2 | Note API: viewing keys with the possession statement; sealing for a reader list; scanning and opening with D6's checks; the unopenable report. | M1 | Every reference case replays (I1–I9). An API-surface test: final classes, redacted secrets, no public ephemeral seam (I2, I6). The acceptance-path schedule regression test (I13). |
| M3 | zeroj-usecases: migrate the confidential-points demo to on-chain delivery with one auditor, on Yaci DevKit (solvency optional), in a separate usecases PR. | M2 released or snapshot-pinned | DevKit E2E: issue, transfer and redeem with recovery from chain data by owner and auditor. Validator mutation tests: missing auditor delivery, wrong lengths, extra deliveries. A garbage delivery is reported as unopenable. |
| M4 | Docs: support matrix, gadget/guide section with the D6, D7 and D9 MUSTs, benchmark doc. | M2 | Experimental status. Seal cost measured. Scan cost measured separately for a failed trial decryption and for a full acceptance. |
| M5a | D3a circuit (auditor amount escrow) on the points demo: transfer (both outputs) and redeem (change note). Both the specified layout and the hash-compressed variant are evaluated. | M2 (Q5 (D) is adopted conditionally, gated by this milestone) | Constraints and prover time measured. On-chain CPU and memory measured in the Plutus VM for the **complete** transaction against the aggregate per-transaction limits, within D3a's gate (decided, Q5: ≤ 80%). I12's invalid-witness and mutation tests, including either output's audit data absent, wrong or unbound. The auditor decrypts every note that transfer and redeem create, from chain data. Validator mutation tests: a key not from the registry; ciphertext coordinates not from the datum; for the variant, a mutated serialization, order or digest half. Issuance is out of scope: the demo uses trusted issuance (Q9 (a)). An application that chooses Q9 (b) must also show that an authorized issuer supplying a wrong audit ciphertext is rejected. If neither layout fits, D3a is recorded as deferred. |
| M5 | D3 circuit profile. | **Blocked** pending a dedicated, accepted follow-up ADR for a pinned, analysed construction (Q5 (A)) | Defined by that ADR. |

## Verification and test-vector strategy

- **Independent vectors:**
  - [ZTV] Sapling note encryption covers `KA^Sapling` from both sides, `KDF^Sapling` and `Sym`.
    Run through the implementation with Zcash's strings, they pin the primitives. A pre-ADR probe
    passed all 10 against ZeroJ's own Python Jubjub reference.
  - RFC 7693 Appendix A covers the BLAKE2b core.
  - The [BLAKE2] reference implementation's personalised outputs are checked through Python's
    `hashlib.blake2b(person=…)` and BouncyCastle in tests.
- **Independent reference.** A Python implementation from the M0 spec, as for ADR-0051–0054. No
  expected value comes from the Java code.
- **Cross-checks:** commitments equal the `pedersen-jubjub-v1` reference; key validation equals
  `elgamal-jubjub-v1`'s.
- **Negatives:** the M0 list. Every negative must fail at the intended step, which the reference
  records.
- **Differential:** BouncyCastle's BLAKE2b and ChaCha20-Poly1305 in tests only (main code uses JDK
  primitives and ZeroJ's own BLAKE2b).
- **E2E:** M3 on Yaci DevKit, with validator mutation tests.
- **D3a:** the `elgamal-jubjub-v1` reference vectors for each limb ciphertext, I12's
  invalid-witness tests, Groth16 prove/verify showing that every public input is bound, and an
  on-chain budget measurement (M5a).
- **Not evidence of security:** passing vectors show conformance, not confidentiality.

## Production / audit gates

- External review of D2, D5, D6 and D7, and of the M1 BLAKE2b used on secrets.
- External review of the adaptation's assumptions A1–A3 (r3), in particular A3's candidate
  multi-key argument, which is ZeroJ's own and unreviewed.
- A review of the scanning deployment model against ADR-0039 before any wallet integration.
- The reader-registry design of any real application.
- D3 stays blocked pending a dedicated, accepted follow-up ADR for a pinned and analysed
  construction (Q5 (A)). No document may claim enforced auditor access except for the amount,
  and then only with D3a, after M5a passes its budget gate. Even then, the claim covers only the
  notes of proof-enforced transitions. In the demo, issued notes rest on the issuer (Q9 (a)).

## Risks

- **Sender misbehaviour without D3:** unreadable or wrong deliveries are detected, not prevented.
  Payroll and regulated settings may require D3.
- **Viewing-key compromise** exposes every note ever delivered to that key, forever. An auditor
  key is the most valuable target. Generations (Q7) limit, but do not remove, this.
- **Bad randomness** at a sender repeats `K_i` and exposes plaintexts, and can be invisible until
  exploited.
- **Scanning on shared hosts** could leak viewing keys through timing (D9).
- **Datum growth** raises min-ADA, and accumulates in demos where notes cannot be burned
  (ADR-0006).
- **Metadata:** the reader count and order reveal the application's auditor policy, and owners
  stay public.
- **D3a's budget:** auditing every output of the two-output transfer is estimated above the
  gate (about 9.25e9 of 10e9 steps). The hash-compressed variant moves the cost to the prover.
  The measured cost may rule D3a out (M5a gate).
- **The adaptation (A1–A3) is unreviewed.** Primitive vectors do not cover it.

## Open questions (decided by the maintainer, 2026-10-09)

**Maintainer decisions (r5).** Each adopts the author's recommendation. They were chosen to
avoid ZeroJ-defined cryptography and to fit Cardano's ledger and Plutus limits. The options
and reasons are kept below for the record.

| Q | Decision |
|---|---|
| Q1 | (b) ZeroJ personalization `"ZeroJ_NoteKDF_v1"`. The code is parameterized so [ZTV] runs with Zcash's string. |
| Q2 | (a) One fresh ephemeral key per reader. |
| Q3 | (a) The opening `(v, r)` is encrypted explicitly. No ZIP 212 seed derivation. |
| Q4 | (a) The sender as an ordinary reader, **off by default**. |
| Q5 | (A) The general D3 stays deferred until a pinned, analysed construction exists (a dedicated ADR). **Plus (D), conditional:** D3a is adopted only if M5a measures the complete transaction at **≤ 80%** of the per-transaction step and memory limits, as specified or with the hash-compressed variant. Otherwise it stays deferred. Its coverage within proof-enforced transitions is never reduced. |
| Q6 | (a) The `elgamal-jubjub-v1` §3.3-form possession proof, checked **once at registration**. |
| Q7 | Generations are application policy. Per-period auditor keys are documented, and enforceable only with D3a. |
| Q8 | (a) 64-bit values. |
| Q9 | (a) The demo trusts the authorized issuer for issued notes' audit data. Applications whose auditor must not trust the issuer choose (b), an issuance proof under a budget gate. |

- **Q1 — Personalization strings.**
  - (a) Use Zcash's `"Zcash_SaplingKDF"` verbatim.
  - (b) Use ZeroJ strings (`"ZeroJ_NoteKDF_v1"`, 16 bytes), with the code parameterized so that
    [ZTV] runs with Zcash's.

  **Decided (b).** BLAKE2's personalization exists for domain separation, and (b) keeps a ZeroJ
  ciphertext from ever being a valid Sapling one.
- **Q2 — One ephemeral key per reader, or one per note.**
  - (a) Per reader (D7), adding 32 bytes per extra reader. Each delivery stays a single-recipient
    Sapling ciphertext.
  - (b) One `E` per note, with a ZeroJ KDF that binds reader index and key, as Sprout's does
    (§4.19.1).

  **Decided (a):** no new KDF.
- **Q3 — Opening encoding.**
  - (a) Explicit `(v, r)` with independent random `e_i` (D6).
  - (b) ZIP 212's pattern: a 32-byte `rseed` in the plaintext, with `r` and `e` derived by a
    BLAKE2b-512 PRF, and the recipient checking `E = [e]·G`.
    - With (b), `C`'s hiding becomes computational.
    - Its motivating attack (linking a recipient's diversified addresses) does not arise here:
      there are no diversified addresses.
    - With several readers, (b) also needs a per-reader derivation.

  **Decided (a).**
- **Q4 — Sender recovery.**
  - (a) The sender as an ordinary reader, optional.
  - (b) Sapling's `ovk`/`C^out`.

  **Decided (a), off by default:** no second mechanism, and the cost is 89 bytes when used. A
  sender that does not add itself keeps forward secrecy against later compromise of its own
  keys. Change outputs already go to the sender as the owner.
- **Q5 — D3** (escalated; blocks M5).
  - (A) Defer D3 until a Poseidon AE construction is published with analysis.
  - (B) Accept SAFE Algorithm 7 over ZeroJ's vetted Poseidon `t = 5` BLS12-381 instance
    (ADR-0015) as a separate profile at an explicitly stated, lower assurance level, with ZeroJ
    defining the key absorption, nonce and tag. This is what Dusk shipped, and later replaced.
  - (C) Prove D5's BLAKE2b and ChaCha20-Poly1305 in-circuit, at an estimated 10^5 constraints per
    reader.

  - (D) (r2; corrected in r3; scoped in r4) Enforce only what auditors need, the amount of
    every note a proof-enforced transition creates, with D3a: `elgamal-jubjub-v1` limb ciphertexts bound to each `C_o` in the transaction's
    proof. Accepted primitives only.
    - Estimated cost for the two-output transfer with one auditor: 18 public inputs, about
      9.25e9 steps, which is **above the 8e9 gate**; and 26–28k constraints.
    - The hash-compressed variant needs 4 public inputs, plus an estimated 3×10^5 prover
      constraints.

  **Decided: (A), plus (D) as conditional, with an 80% gate.** Ship D1–D9. Adopt D3a only if M5a measures the
  complete transaction within the gate (as specified or compressed). Otherwise keep it deferred.
  Never narrow its coverage within proof-enforced transitions. Revisit a general D3 only with a
  dedicated ADR.
- **Q6 — Proof of possession for registered keys.**
  - (a) `elgamal-jubjub-v1` §3.3's DLEQ statement.
  - (b) None. Registries rely on governance only.

  **Decided (a), checked once at registration:** it is already pinned and implemented, and
  possession is not authorization.
  - Plutus has builtins for BLS12-381's G1 and G2, not for Jubjub, so a per-transfer on-chain
    DLEQ check is not practical.
  - The registry's governance checks possession off-chain, or through a Groth16 proof of the
    statement when the key is registered. The registry, held as a reference input, then contains
    only checked keys.
  - This also discharges `R_enc`'s `PK ∈ 𝔾` verifier obligation for D3a.
- **Q7 — Auditor key generations.** Should the profile define generations (for example a period
  index stored next to each registry key), or leave them to applications? **Decided:** leave them
  to applications, and document the pattern of per-period auditor keys in the registry.
  - Without D3a, a validator cannot tell which key a delivery was encrypted to, so a sender
    could use a retired key undetected.
  - With D3a, `PK_a` is a public input taken from the registry, so the current generation is
    enforced. The registry pairs it with the auditor's viewing key, per generation (D2).
- **Q8 — Value width.**
  - (a) 64-bit only.
  - (b) Up to 252 bits, as `pedersen-jubjub-v1` allows.

  **Decided (a):** it matches the gadgets' convention, keeps the plaintext fixed-length, and
  matches Cardano.
  - The Conway ledger CDDL bounds output token quantities by `positive_coin = 1 .. max_word64`
    and mint amounts by `nonzero_int64`.
  - Its `coin` is a CBOR `uint`, but lovelace supply is far below `2^64`.
  - So every native quantity fits in 64 bits.

- **Q9 — Issuance under D3a** (r4, F4).
  - (a) Trust the issuer for issued notes' audit data, as recorded.
  - (b) Make issuance proof-enforced: an issuance circuit proving D3a's relation for each issued
    note. Its public inputs grow by `8a` per issued note, so a budget gate bounds the number of
    notes per issuance transaction (M5a would measure it).

  **Decided (a)** for the demo. The issuer is already the authority over supply, and the auditor
  detects bad issuance data on decryption. Applications whose auditor must not trust the issuer
  choose (b).

## Related findings (out of scope)

- `Poseidon.java`'s Javadoc gives "Approximately 330 constraints for 2 inputs"; the measured
  figure is 240 (ADR-0037).
- `jubjub-eddsa-v1` §2.1 says rate cells are zero-padded, while `PoseidonHash.requireExactRate`
  refuses short input. The EdDSA call sites always pass the full rate, so nothing breaks today.
- [ZcashSpec] §5.4.2's security sentence for `PRF^ock` names BLAKE2b-512, while its definition
  uses BLAKE2b-256. This looks like an upstream erratum. It does not affect this ADR, which does
  not use `PRF^ock`.
- zk-kit's `poseidon-cipher` checks zero padding only when the message is longer than 3
  elements, unlike Khovratovich's note. This is relevant to Q5 (B), if it is ever chosen.
- `AliasCheck.check` (zeroj-circuit-lib) only decomposes a value into `nBits` booleans. For
  `nBits ≥ 255` both `x` and `x + p` fit, so it does not enforce a canonical representation, which
  its Javadoc claims. D3a does not use it: §8.3's argument below needs no in-circuit `< p` check.
  It deserves its own fix and issue.

## Implementation notes (refinements recorded during implementation)

These refine the accepted design. They are recorded for maintainer acknowledgement, as AGENTS.md
requires, and each is stated normatively in `docs/specs/confidential-note-jubjub-v1.md`. They
came from the independent reference (its findings S1–S6) and from implementation.

1. **Step numbering** (reference S1). The spec numbers acceptance steps 1–7. D6's steps 1–5 group
   them, and spec §5 maps one to the other.
2. **The commitment's coordinates are canonical, with no reduction** (reference S3; spec §5 step
   7). A reader takes `C` as the affine `(u, v)` the note carries. Coordinates outside `[0, p)`,
   or off the curve, are "not mine". Before this, a reader that reduced mod `p` and one that did
   not could disagree. `NoteScanner.open(delivery, u, v)` checks this before any secret work.
3. **An AEAD known-answer self-test before use** (as ADR-0054 note 7). The platform's
   ChaCha20-Poly1305 is the profile's only platform-dependent primitive. A missing or
   non-conforming provider would make every delivery look like "not mine", so
   `NoteScanner.of` and `ConfidentialNotes.seal` first run the first Zcash Sapling vector's
   `k_enc`/`p_enc`/`c_enc` (14 µs) and fail closed. Any provider exception other than a tag
   failure is a platform fault (`IllegalStateException`), never "not mine".
4. **A test hook for I13.** `JubjubPoint.SecretScheduleObserver` gains a
   `publicMultiplication()` callback, called by the variable-time `scalarMul`. Tests then prove
   that acceptance runs exactly three blinded schedules and no unblinded multiplication. It costs
   one `ThreadLocal` read per `scalarMul`.
5. **A shared AEAD helper.** ChaCha20-Poly1305 moved from `Hpke` into a package-private `Aead`
   class that both profiles use. ADR-0054's RFC 9180 known answers and the Wycheproof suite now run
   through it.
6. **Personalised BLAKE2b on secret input.** `Blake2bDigest` gains the parameter-block
   personalization ([BLAKE2] §2.8) and zeroes its message words, working vector and state before
   returning. It is checked against BouncyCastle's personalised BLAKE2b over lengths 0–300.
7. **The hash-compressed layout needs no in-circuit `< p` check** (spec §8.3).
   - The validator requires every datum coordinate to be canonical, and hashes `I2OSP(c, 32)`.
   - The circuit constrains 32 bytes per coordinate (8 bits each) whose big-endian value equals
     the `R_enc` coordinate in the field, and hashes them.
   - A prover that serialized `c + p` instead would produce a different digest, and its proof
     would not verify. Equal digests force equal bytes (collision resistance of BLAKE2b-256), and
     so the canonical encoding.
8. **D3a passed M5a's gate, so Q5's condition is met** (see "Implementation status").
   - Both layouts were measured on a two-output transfer with one auditor, in ZeroJ's reference
     validator: 72.9% (direct) and 46.8% (hash-compressed) of the step limit, each under 10% of
     the memory limit.
   - **Recommended use (for acknowledgement):** the direct layout when its measured cost fits the
     gate. It has 34,184 constraints and proves in 3.9 s. The hash-compressed layout fits where the
     direct one does not: more auditors or outputs. It has 355,514 constraints and proves in 16.6 s.
   - An application that runs another script in the same transaction, such as the points demo's
     minting policy, must measure its own total. M3 does this for the demo.
9. **Allocation.** Each blinded scalar multiplication allocates about 3.7 MB of short-lived
   `BigInteger` garbage, so a failed trial decryption allocates about 4 MB. That is ADR-0039's
   approved compatibility path. The allocation-free fixed-limb kernel is an unapproved candidate
   (ADR-0039 M9), and moving this profile to it would be a separate reviewed decision. The
   profile's own code allocates only fixed-size buffers.
10. **Test-key tags** (reference S2). Spec §9.1 lists every tag the reference uses, and every
    derived scalar is emitted with the vectors.

## Implementation status

| Milestone | State | Notes |
|---|---|---|
| M0 | Done | Spec `docs/specs/confidential-note-jubjub-v1.md`. An independent Python reference (`zeroj-circuit-lib/src/test/resources/confidential-note-reference/`), written from the spec and the Zcash specification with no Java read. It runs over 300 checks and emits more than 110 replayable vectors, reproducing all 10 Zcash Sapling vectors, RFC 7693 and RFC 8439, and catching 28 of 29 seeded defects. The one it cannot catch (KDF over the re-encoded `E` alone) is unobservable under canonical decoding. The Zcash vectors are vendored, pinned by commit and SHA-256. |
| M1 | Done | `Blake2bDigest` personalization, `Aead`, `SaplingNoteCrypto`, the AEAD self-test. `ConfidentialNoteKnownAnswerTest` covers all 10 Zcash vectors (Agree both ways, KDF, encryption and decryption), decoding refusals and fault classification. Also run: the personalised BLAKE2b differential against BouncyCastle 1.83, and Wycheproof ChaCha20-Poly1305 through `Aead`. `NoteNativeProbe` gives output identical to the JVM in a GraalVM native image. |
| M2 | Done | `NoteViewingKey`, `NoteReaderKey`, `NoteOpening`, `ConfidentialNotes`, `NoteScanner`. Tests: `ConfidentialNotesTest` (I1–I11, platform faults, API surface), `NoteScheduleTest` (I13) and `ConfidentialNoteReferenceVectorsTest` (every reference vector, byte for byte, including sealing). Eight guards were each reverted to confirm a test fails. |
| M4 | Done | Benchmark `docs/benchmarks/confidential-note-jubjub-2026-10-09.md`. A failed trial decryption costs 2.2 ms and an acceptance 7.2 ms; scanning runs at 2,049 notes/s on 16 threads. README, support matrix and gadget-guide rows and section, with the D6, D7 and D9 rules. |
| M5a | Done; **D3a passed its gate** | `AuditedConfidentialNoteOnChainTest` and `AuditedConfidentialNoteValidator` (Plutus V3, Julc VM). Direct layout: 24 public inputs, 7.29e9 steps (72.9%). Hash-compressed layout: 10 public inputs, 4.68e9 steps (46.8%). I12's invalid witnesses and the validator mutations are rejected, and the auditor recovers every created note's amount from the datum. |
| M3 | Not started | A separate zeroj-usecases PR: the points demo on Yaci DevKit, with its minting policy in the measured total. |
| M5 | Blocked | Q5 (A): pending a dedicated, accepted follow-up ADR. |
