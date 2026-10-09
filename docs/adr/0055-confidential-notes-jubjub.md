# ADR-0055: Confidential notes on Jubjub with encrypted opening delivery (`confidential-note-jubjub-v1`)

## Status
Proposed — 2026-10-09.
- Tracked as #79. This is a design-only ADR; no implementation accompanies it.
- Acceptance would be design acceptance only. It would certify no implementation, test or
  security property.
- The decision on the in-circuit consistency proof (D3) is **escalated and blocked** (Q5), in
  the way ADR-0051 escalated its D7. The rest of the design does not depend on it.

This ADR changes no maturity claim. ADR-0039's assurance classes apply: every secret-bearing
host operation here is **compatibility/offline** class.

## Date
2026-10-09

## Revision history
- **r1** (2026-10-09): initial proposal.

## Risk classification
- **R3:** D2 (viewing keys and key agreement), D5 (the ciphersuite: key agreement, KDF and
  symmetric encryption) and D6 (the plaintext and the recipient's acceptance checks). These
  decide whether an opening stays secret and whether a recipient can be made to accept a wrong
  one.
- **R2:** D1 (the note and its delivery), D7 (ephemeral randomness and sender recovery), D8
  (encodings, the datum and validator obligations) and D9 (secret handling on the host).
- **R3, escalated:** D3 (an optional in-circuit proof that each delivery opens the commitment).
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
  requirements on its instantiation. This ADR relies on them, and on their analysis by the Zcash
  designers. It does not re-prove them.
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
    this transfer". Making it the latter is D3's purpose.
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
    the transmitted note ciphertext infeasible".
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
- **[RFC8439]** Y. Nir, A. Langley, *ChaCha20 and Poly1305 for IETF Protocols*, June 2018. It
  obsoletes RFC 7539, which [ZcashSpec] cites. Fetched 2026-10-09.
  - §2.8 (the AEAD).
  - §4: "The most important security consideration in implementing this document is the
    uniqueness of the nonce used in ChaCha20".
- **ZeroJ:**
  - ADR-0051 and `docs/specs/pedersen-jubjub-v1.md` (§2 the bases, §3 the commitment and §3.1
    the blinding, §4 the encoding and the subgroup rule);
  - ADR-0052 and `docs/specs/elgamal-jubjub-v1.md` (§2 sampling, §3.1 key validation, §3.3
    possession);
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
- **Rotation.** A reader rotates by registering a new key. Notes delivered earlier stay readable
  only by the old key, which the reader must keep for as long as it needs them. Generations of
  auditor keys (one per period) limit what one leaked key exposes (Q7).

### D3 — Optional in-circuit consistency proof (R3; escalated and blocked)

An application may want the transfer proof to also show, for each required reader, that `ct_i`
decrypts under `P_i` to the opening of `C`. That turns "a ciphertext exists" into "the reader can
read this note":
- in payroll, it rules out unreadable salary notes;
- for regulated tokens, the auditor is guaranteed to read every transfer.

**It cannot be built on D5's ciphersuite at a sensible cost.** Proving D5 in R1CS needs, per
reader:
- one BLAKE2b block for the KDF, measured at 76,832 constraints per block (`gadgets.md`);
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

So D3 is **escalated (Q5) and blocked**. It needs either:
- a maintainer decision that accepts a named Poseidon AE construction at a stated assurance
  level, as a separate profile (for example `confidential-note-jubjub-poseidon-v1`); or
- a follow-up ADR once such a construction is published with analysis.

Nothing in D1, D2 and D5–D9 depends on D3. The datum layout reserves no D3 fields: a D3 profile
would be a different profile with its own datum, not an option within this one.

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
  - `pers_KDF` is the 16-byte personalization (Q1, lean `"ZeroJ_NoteKDF_v1"`).
- **Symmetric encryption:** `Sym` = AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8) with a 256-bit key,
  empty associated data and the all-zero 96-bit nonce.
  - This is safe **only** because every key is used once (I2).
  - The plaintext is 41 bytes (D6), so `ct` is 57 bytes.

No other suite, mode or negotiation is accepted.

**Why exact Sapling rather than a "Sapling-like" design.** Every primitive and its composition
come from one specification, with stated security requirements (§4.1.4, §4.1.6) and independent
test vectors ([ZTV]). Q1's personalization change is a parameter that BLAKE2 provides for exactly
this purpose ([BLAKE2] §2.8). The implementation takes the strings as parameters, so the [ZTV]
vectors run through the same code with Zcash's strings (I10).

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
  4. `encode([v]·G + [r]·H)` equals the datum's `C` (equivalently, the affine coordinates are
     equal).
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
  a delivery that decrypts but does not open `C` is rejected. It is also what [ZcashSpec] §8.7
  credits with making partitioning-oracle attacks infeasible.

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
  reader (lean, Q4). Sapling's `ovk`/`C^out` mechanism is the alternative. A sender that does not
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

- Key generation, encryption (`[e_i]·G`, `[8·e_i]·P_i`) and decryption (`[8·sk]·E_i`) run on
  ZeroJ's `BigInteger` Jubjub code, using the blinded best-effort schedule (ADR-0038) on
  subgroup points only. This is **compatibility/offline class** (ADR-0039 §3.1). There is no
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
- **Measured costs** (ElGamal benchmark, 2026-10-05, Apple M4 Max) give an **estimate** for
  scanning: about 1.8 ms per note per viewing key, or about 1.8 s per 1,000 notes. That is a
  38 µs decode, an 85 µs subgroup check and a 1,650 µs blinded multiplication; the hash and
  AEAD are negligible.

### D10 — Out of scope
- Hiding owners, the transaction graph, note counts or reader roles.
- Note discovery beyond scanning the application's script address (for example tags or detection
  keys).
- Spending keys and owner authorization, which stay the application's (ADR-0006).
- A post-quantum construction.
- D3, until Q5 is decided.

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
- **I4 (D1, D6) The commitment is unchanged.** `C` is exactly `pedersen-jubjub-v1`'s `C(v, r)`,
  and the delivered `(v, r)` verifies with `PedersenCommitment.verify`.
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
- **I11 (D9) Secret class.** Secret multiplications run on subgroup points only, with the
  blinded schedule. No API or document claims constant time or online suitability.

## Consequences

- Recipients and auditors can recover every note from chain data alone, and they detect bad
  deliveries on receipt.
- Notes get bigger: 89 bytes per reader, and about 0.8 ADA more minimum ADA with one auditor
  (estimate).
- Wallets must scan: about 1.8 ms per note per viewing key (estimate from measured components).
  Scanning needs the offline class's isolation.
- The demos' validators, datums and transaction builders change (M3), but their circuits and
  verification keys do not: deliveries are not public inputs.
- ZeroJ gains a personalised BLAKE2b used on secret data, and a second Jubjub key type.
- Without D3, auditor access is only as good as the senders' honesty, with detection afterwards.

## Compatibility

- **New profile** `confidential-note-jubjub-v1`. `pedersen-jubjub-v1`, its encodings, gadgets and
  vectors are unchanged.
- **New public API**, Experimental: viewing keys, sealing deliveries and opening them. Names are
  fixed in M2.
- The usecase datum changes from `Note(owner, u, v)` to `Note(owner, u, v, deliveries)`. Old
  notes have no deliveries. Migration is a usecase concern (M3): the demo has no deployed state to
  migrate.
- No change to ADR-0052/0053/0054 profiles.

## Implementation milestones

| ID | Scope | Entry gate | Exit criteria |
|---|---|---|---|
| M0 | Normative spec `docs/specs/confidential-note-jubjub-v1.md`. An independent Python reference, written from the spec and [ZcashSpec] with no Java read. The vendored [ZTV] file, pinned by commit and SHA-256. | ADR accepted; Q1–Q4 and Q6–Q8 decided | The reference reproduces all 10 [ZTV] vectors (I10) and the [BLAKE2]/RFC 7693 Appendix A vectors. It emits replayable cases: good deliveries for 1–4 readers; every D6 failure (wrong key; tampered `E`/`ct`; `E` non-canonical, small-order, outside `𝔾` or the identity; wrong length; bad lead byte; `r ≥ l`; an opening that does not match `C`); a repeated `e_i` (shown to leak the plaintext XOR); and the copied-note case for D6 step 5. Byte-identical output on rerun. |
| M1 | Host primitives: personalised BLAKE2b; `KA`, `KDF`, `Sym` on JDK ChaCha20-Poly1305; the fault classification. | M0 | [ZTV] KATs (I10); a BLAKE2b differential with personalization against BouncyCastle in tests; negatives for every malformed input; a native-image probe with identical output (as ADR-0054 M1). |
| M2 | Note API: viewing keys with the possession statement; sealing for a reader list; scanning and opening with D6's checks; the unopenable report. | M1 | Every reference case replays (I1–I9). An API-surface test: final classes, redacted secrets, no public ephemeral seam (I2, I6). |
| M3 | zeroj-usecases: migrate the confidential-points demo to on-chain delivery with one auditor, on Yaci DevKit (solvency optional), in a separate usecases PR. | M2 released or snapshot-pinned | DevKit E2E: issue, transfer and redeem with recovery from chain data by owner and auditor. Validator mutation tests: missing auditor delivery, wrong lengths, extra deliveries. A garbage delivery is reported as unopenable. |
| M4 | Docs: support matrix, gadget/guide section with the D6, D7 and D9 MUSTs, benchmark doc. | M2 | Experimental status; scan and seal costs measured. |
| M5 | D3 circuit profile. | **Blocked on Q5** | Defined by the follow-up decision. |

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
- **Not evidence of security:** passing vectors show conformance, not confidentiality.

## Production / audit gates

- External review of D2, D5, D6 and D7, and of the M1 BLAKE2b used on secrets.
- A review of the scanning deployment model against ADR-0039 before any wallet integration.
- The reader-registry design of any real application.
- D3 stays blocked until Q5 is decided; no document may claim enforced auditor access before
  then.

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

## Open questions (points needing a maintainer decision)

- **Q1 — Personalization strings.**
  - (a) Use Zcash's `"Zcash_SaplingKDF"` verbatim.
  - (b) Use ZeroJ strings (`"ZeroJ_NoteKDF_v1"`, 16 bytes), with the code parameterized so that
    [ZTV] runs with Zcash's.

  **Lean (b):** BLAKE2's personalization exists for domain separation, and (b) keeps a ZeroJ
  ciphertext from ever being a valid Sapling one.
- **Q2 — One ephemeral key per reader, or one per note.**
  - (a) Per reader (D7), adding 32 bytes per extra reader. Each delivery stays a single-recipient
    Sapling ciphertext.
  - (b) One `E` per note, with a ZeroJ KDF that binds reader index and key, as Sprout's does
    (§4.19.1).

  **Lean (a):** no new KDF.
- **Q3 — Opening encoding.**
  - (a) Explicit `(v, r)` with independent random `e_i` (D6).
  - (b) ZIP 212's pattern: a 32-byte `rseed` in the plaintext, with `r` and `e` derived by a
    BLAKE2b-512 PRF, and the recipient checking `E = [e]·G`.
    - With (b), `C`'s hiding becomes computational.
    - Its motivating attack (linking a recipient's diversified addresses) does not arise here:
      there are no diversified addresses.
    - With several readers, (b) also needs a per-reader derivation.

  **Lean (a).**
- **Q4 — Sender recovery.**
  - (a) The sender as an ordinary reader, optional.
  - (b) Sapling's `ovk`/`C^out`.

  **Lean (a):** no second mechanism; the cost is 89 bytes when used.
- **Q5 — D3** (escalated; blocks M5).
  - (A) Defer D3 until a Poseidon AE construction is published with analysis.
  - (B) Accept SAFE Algorithm 7 over ZeroJ's vetted Poseidon `t = 5` BLS12-381 instance
    (ADR-0015) as a separate profile at an explicitly stated, lower assurance level, with ZeroJ
    defining the key absorption, nonce and tag. This is what Dusk shipped, and later replaced.
  - (C) Prove D5's BLAKE2b and ChaCha20-Poly1305 in-circuit, at an estimated 10^5 constraints per
    reader.

  **Lean (A):** ship D1–D9, and revisit D3 with a dedicated ADR.
- **Q6 — Proof of possession for registered keys.**
  - (a) `elgamal-jubjub-v1` §3.3's DLEQ statement.
  - (b) None. Registries rely on governance only.

  **Lean (a):** it is already pinned and implemented. Possession is not authorization.
- **Q7 — Auditor key generations.** Should the profile define generations (for example a period
  index stored next to each registry key), or leave them to applications? **Lean:** leave them
  to applications, and document the pattern.
- **Q8 — Value width.**
  - (a) 64-bit only.
  - (b) Up to 252 bits, as `pedersen-jubjub-v1` allows.

  **Lean (a):** it matches the gadgets' convention and keeps the plaintext fixed-length.

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
