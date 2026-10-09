# ZeroJ Confidential Notes on Jubjub v1 — Normative Specification

**Profile identifier:** `confidential-note-jubjub-v1`
**Status:** Normative. Required by ADR-0055 (milestone M0).
**Date:** 2026-10-09

This document pins every value, encoding and rule that a second implementation needs to seal
and open `confidential-note-jubjub-v1` deliveries, and to build the D3a auditor relation.
Anything not written here is not part of the profile. Any change needs a new profile
identifier (`-v2`), not an edit to this file.

**Conventions:**
- `‖` is byte concatenation.
- `I2OSP(x, n)` is the `n`-byte big-endian encoding of the integer `x < 256^n`.
- `OS2IP` is its inverse.
- `ASCII(s)` is the bytes of an ASCII string.
- `l` is the Jubjub prime subgroup order and `p` the BLS12-381 scalar field prime, as in
  `pedersen-jubjub-v1` §1.
- `𝔾` is the prime-order subgroup of Jubjub.
- `G` and `H` are the `pedersen-jubjub-v1` §2 bases.
- `encode`/`decode` are the 32-byte point encoding of `pedersen-jubjub-v1` §4.
- `x[a..b]` is bytes `a` through `b` of `x`, inclusive and 0-based.
- Index bases: deliveries and readers are numbered from 0 (§3.3); in §8, created notes and
  auditors are numbered from 1, and limbs are 0 and 1.

---

## 1. Suite

| Item | Value | Reference |
|---|---|---|
| Curve | Jubjub (`pedersen-jubjub-v1` §1); cofactor `h = 8` | [ZcashSpec] §5.4.9.3 |
| Key agreement | `KA.DerivePublic(sk, B) = [sk]·B`; `KA.Agree(sk, X) = [8·sk]·X` | [ZcashSpec] §5.4.5.3 |
| KDF | `KDF(pers, sharedSecret, E) = BLAKE2b-256(pers, encode(sharedSecret) ‖ E)` | [ZcashSpec] §5.4.5.4, [BLAKE2] §2.8 |
| Personalization | `pers = ASCII("ZeroJ_NoteKDF_v1")` (16 bytes) | ADR-0055 Q1 |
| Symmetric encryption | AEAD_CHACHA20_POLY1305 with a 32-byte key, the all-zero 12-byte nonce, and empty associated data | [ZcashSpec] §5.4.3, [RFC 8439] §2.8 |
| Commitment | `C = [v]·G + [r]·H` (`pedersen-jubjub-v1` §3), unchanged | ADR-0051 |

`BLAKE2b-256(pers, x)` is unkeyed BLAKE2b in sequential mode with a 32-byte digest and the
16-byte personalization `pers` in bytes 48–63 of the parameter block ([BLAKE2] §2.8, Table 1).
The salt is all zero. This is the function [ZcashSpec] §5.4.1.2 calls `BLAKE2b-256(p, x)`.

The suite is fixed. Nothing is negotiated, and no other suite, personalization or nonce is
accepted.

**Conformance parameterization.** An implementation takes the personalization as a parameter
of its KDF, so that the same code reproduces the Zcash Sapling vectors (§9.2) with
`pers = ASCII("Zcash_SaplingKDF")`. Only `ASCII("ZeroJ_NoteKDF_v1")` is part of the profile.

---

## 2. Keys

### 2.1 Sampling
`sample(rng)` draws 64 bytes from a cryptographically secure random generator and returns
`OS2IP(bytes) mod l`, as in `elgamal-jubjub-v1` §2.
- A viewing secret key `sk` uses `sample`, resampled while the result is 0, so `sk ∈ [1, l)`.
- An ephemeral secret `e` uses `sample`, resampled while the result is 0, so `e ∈ [1, l)`.
- A blinding `r` uses `pedersen-jubjub-v1` §3.1, so `r ∈ [0, l)`.

### 2.2 Viewing keys
A reader's viewing key pair is `(sk, P = [sk]·G)`. The reader key `P` is published as
`encode(P)` (32 bytes).

A received reader key is **valid** only if:
1. `decode` succeeds (`pedersen-jubjub-v1` §4);
2. `P ∈ 𝔾`, that is, `[l]·P` is the identity;
3. `P` is not the identity.

A sender encrypts only to valid reader keys. This is [ZcashSpec] §4.7.2's
`KA.PublicPrimeOrder` check.

**Key separation.** A viewing key is used only by this profile. It is never an
`elgamal-jubjub-v1` key, an EdDSA key, a spending key or a Zcash key, and it is never derived
from one.

**Possession.** A reader key held in an application registry is registered with a
possession proof of the `elgamal-jubjub-v1` §3.3 form, checked once at registration: the DLEQ
statement with `X = G` and `P = D = P_reader`. Only the form of the statement is reused; the
key stays a viewing key. Possession is not authorization. The statement carries no context:
it shows that someone knows the key's discrete logarithm, and a published proof can be replayed
to register the same key elsewhere. It is also the same statement as an `elgamal-jubjub-v1` key's.
A registry therefore binds each registration to its registrant and to this profile itself (for
example by the registrant's signature over the profile identifier, the key and the registry),
and governs which keys it admits, and in which generation.

**Storage.** A reader keeps its viewing secret, as `I2OSP(sk, 32)`, for as long as it needs to
read the notes delivered to it. Restoring requires exactly 32 bytes encoding `1 ≤ sk < l`.

---

## 3. Encodings

### 3.1 Plaintext
`plaintext(v, r) = 0x01 ‖ I2OSP(v, 8) ‖ I2OSP(r, 32)`, 41 bytes, where:
- `0x01` is the profile version byte;
- `v ∈ [0, 2^64)` is the value;
- `r ∈ [0, l)` is the blinding.

### 3.2 Delivery
`delivery = E ‖ ct`, 89 bytes, where `E = encode([e]·G)` (32 bytes) and `ct` is the 57-byte
AEAD output (41 bytes of ciphertext followed by the 16-byte Poly1305 tag).

### 3.3 Notes (informative)
A note carries `C` (as affine `(u, v)` coordinates, `pedersen-jubjub-v1` §5) and one delivery
per reader, in the order the application fixes: the owner first, then the application's
auditors in registry order. The on-chain container (for example a Plutus datum
`Note(owner, u, v, [delivery_0, …, delivery_k])`) is the application's. This profile fixes
only the bytes of each delivery and the meaning of their order.

---

## 4. Sealing

Input: an opening `(v, r)` with `v ∈ [0, 2^64)` and `r ∈ [0, l)`, and an ordered list of
reader keys `P_0, …, P_k`.

1. Each `P_i` must be valid (§2.2). The `P_i` must be pairwise distinct, compared as encodings.
2. `pt = plaintext(v, r)`.
3. For each reader `i`, in order:
   1. `e_i = sample(rng)`, resampled while 0, freshly for this reader;
   2. `E_i = encode([e_i]·G)`;
   3. `shared_i = KA.Agree(e_i, P_i) = [8·e_i]·P_i`;
   4. `K_i = KDF(pers, shared_i, E_i)`;
   5. `ct_i = ChaCha20-Poly1305-Encrypt(K_i, nonce = 0^12, aad = empty, pt)`;
   6. `delivery_i = E_i ‖ ct_i`.
4. Output `delivery_0, …, delivery_k`, in reader order.

**One use per key.** Each `e_i` is drawn once and used for one reader of one note only. The
zero nonce is safe only because each `K_i` encrypts exactly one plaintext. A repeated `e_i`
toward the same reader key repeats `K_i`. "Both the one-time Poly1305 key and the keystream
are identical between the messages" ([RFC 8439] §4), which leaks the XOR of the plaintexts.

`e_i`, `shared_i`, `K_i` and `pt` are secret. An implementation wipes their byte forms after
use, best effort.

---

## 5. Opening and acceptance

Input: a viewing key `sk`, one delivery (the reader's position in the note), and the note's
commitment `C`, given as the affine coordinates `(u, v)` the note carries. A note is
**accepted** for this reader only if every step succeeds, in order:

1. The delivery is exactly 89 bytes. Split it into `E` (bytes 0–31) and `ct` (bytes 32–88).
2. `X = decode(E)` succeeds, `X ∈ 𝔾`, and `X` is not the identity.
3. `shared = KA.Agree(sk, X) = [8·sk]·X`.
4. `K = KDF(pers, shared, E)`, using the **received** bytes `E`, not a re-encoding of `X`
   ([ZcashSpec] §4.20.2).
5. `pt = ChaCha20-Poly1305-Decrypt(K, nonce = 0^12, aad = empty, ct)` succeeds (the tag
   verifies).
6. `pt[0] = 0x01`. Let `v = OS2IP(pt[1..8])` and `r = OS2IP(pt[9..40])`; require `r < l`.
7. The note's coordinates satisfy `0 ≤ u < p` and `0 ≤ v < p`, with no reduction, and
   `[v]·G + [r]·H` is the point `(u, v)`.

The output is `(v, r)`.

**Step numbering.** ADR-0055 D6 groups these steps. Its step 1 is steps 1–2 here, its step 2
is steps 3–5, its step 3 is step 6, its step 4 is step 7, and its step 5 is the application's
owner-credential check below.

**Defence in depth.** Step 4 hashes the received bytes of `E`. While step 2 accepts canonical
encodings only, every accepted `E` re-encodes to itself, so the rule cannot change an outcome.
It is kept so that a lenient decoder cannot introduce a second accepted encoding.

**The application's step.** The wallet also checks that the note's owner credential is its own
before it counts an owned note, and that the note sits at the application's script address
with the application's token. Without that check, a copied `(C, deliveries)` placed in someone
else's output would look like the wallet's note. The profile does not define the owner
credential.

**Secret handling in step 7.** `(v, r)` is a secret opening. Step 7 recomputes `C` on the
implementation's secret-bearing path (blinded best-effort scalar multiplication in ZeroJ), never
on a path meant for disclosed openings.

**Failure is "not mine".** If any of steps 1, 2, 5, 6 or 7 fails, the delivery is not for this
reader, and the reader records nothing from it. Every such failure has the same outcome. If the
wallet's own check shows the note is owned by it, it reports an **unopenable owned note** to
its user rather than skipping it silently.

**A local fault is not a failed step.** A step fails only because of the input:
- a wrong length;
- a point that does not decode, lies outside `𝔾` or is the identity;
- a tag that does not verify;
- a wrong version byte, `r ≥ l`, a non-canonical commitment coordinate, or an opening that does
  not match `C`.

If the reader's own platform fails instead (a primitive is unavailable or errs), the reader must
not treat the delivery as "not mine". It stops, and may retry later.

**Order of work.** Steps 1 and 2 use public data only, and an implementation may perform them
before any secret operation. Step 7, the costliest step, runs only after step 5 succeeds.

---

## 6. What the chain reveals

- Every delivery and commitment is public and permanent. Anyone who later obtains a viewing key
  decrypts every delivery ever made to it. There is no forward secrecy with respect to the
  reader's key.
- The number of deliveries and their order reveal the application's reader policy. Owners stay
  public in the note container.
- A quantum adversary that computes discrete logarithms on Jubjub reads every delivery.
  Commitments stay statistically hiding.

---

## 7. Assumptions

These are ADR-0055's assumptions. They are not proved here, and they require external review.
- **A1 (confidentiality of a delivery).** With `P_i` valid and `e_i` fresh, a delivery reveals
  nothing about `pt` beyond its length to anyone without `sk_i`. This is the [ZcashSpec] §4.1.6
  requirement applied with base `G`.
- **A2 (integrity of acceptance).** An accepted `(v, r)` is an opening of `C`. By the
  computational binding of `pedersen-jubjub-v1`, no efficient sender can get two readers to
  accept different openings of the same `C`.
- **A3 (no useful multi-key partitioning).** A delivery passes acceptance under at most one
  reader key, except with negligible probability, against an efficient sender. ADR-0055 records
  a candidate argument, which has not been reviewed.

---

## 8. D3a auditor relation

D3a is adopted only if ADR-0055 M5a measures it within its gate. This section pins its
encodings so that the measurement and any later implementation agree.

### 8.1 Statement
For a transaction whose validator verifies a Groth16 proof, with created notes `o = 1 … n` in
transaction output order and auditors `a = 1 … m` in registry order, the proof additionally
asserts, for every pair `(o, a)`:
- `v_o = L_{o,0} + 2^32·L_{o,1}` with `L_{o,0}, L_{o,1} ∈ [0, 2^32)`, where `v_o` is the same
  value that opens `C_o`;
- for `j ∈ {0, 1}`, `(A_{o,a,j}, B_{o,a,j})` is an `elgamal-jubjub-v1` encryption of `L_{o,j}`
  under `PK_a` at width 32 (`R_enc(32)`, `elgamal-jubjub-v1` §9.1), with its own randomness.

`PK_a` is the auditor's `elgamal-jubjub-v1` key. It is a separate key from the auditor's
viewing key (§2.2).

**Fresh randomness.** Each limb encryption uses its own randomness. The circuit cannot force the
randomness of different limbs to differ, and a repeated `k` would reveal the difference of the two
limbs (`B0 − B1 = [L0 − L1]·G`). A validator therefore requires the handles `A` of all limb
encryptions in a transaction to be pairwise distinct.

**The auditor key's source.** A validator takes `PK_a` from exactly one registry entry. A second
entry for the same token, a token quantity other than one, or a datum of another shape is
refused, so that the submitter cannot choose an older generation's key.

### 8.2 Public inputs (direct layout)
After the application's own public inputs, the order is:
1. for each auditor `a`, in registry order: `PK_a.u`, `PK_a.v`;
2. for each created note `o`, in output order; for each auditor `a`, in registry order; for
   `j = 0`, then `j = 1`: `A.u`, `A.v`, `B.u`, `B.v` of `(A_{o,a,j}, B_{o,a,j})`.

That adds `2·m + 8·m·n` public inputs. Every coordinate is canonical (`< p`).

### 8.3 Public inputs (hash-compressed layout)
After the application's own public inputs:
1. for each auditor `a`, in registry order: `PK_a.u`, `PK_a.v`;
2. `digest_hi`, then `digest_lo`, where:
   - `bytes` is the concatenation of `I2OSP(c, 32)` over every ciphertext coordinate `c` of
     §8.2 item 2, in the same order. That is `32·8·m·n` bytes; each `c < p` is required;
   - `digest = BLAKE2b-256(bytes)`, unkeyed, unpersonalized, 32-byte output. This is Plutus's
     `blake2b_256` builtin;
   - `digest_hi = OS2IP(digest[0..15])` and `digest_lo = OS2IP(digest[16..31])`, each
     `< 2^128 < p`. The split is lossless.

The circuit constrains `bytes` to be exactly the coordinates that its `R_enc` instances use.
The serialization has no tag and no length prefix. The coordinate count is fixed by the circuit,
and so by its verification key.

---

## 9. Test vectors

### 9.1 Test keys
Test-vector scalars are derived as

```
scalar(tag) = OS2IP(SHA-256(ASCII("zeroj.confidential-note.v1.test." ‖ tag))) mod l
```

This derivation is for test vectors only; real keys and randomness use §2.1. A vector set whose
secret key or ephemeral derived to zero would be invalid, not resampled. Tags:
- `reader.<name>` for viewing keys (for example `reader.owner`, `reader.auditor1`);
- `ephemeral.<case>.<i>` for the ephemeral of reader `i` in a case. A case that needs a
  particular kind of point retries with `ephemeral.<case>.<i>.retry<k>`, `k = 1, 2, …`, and uses
  the first that qualifies;
- `blinding.<case>` for a case's blinding, and `blinding.<case>.1`, `blinding.<case>.2` for a
  case with two plaintexts;
- `elgamal.<name>` for a D3a auditor's `elgamal-jubjub-v1` secret key;
- `d3a.<case>.k.<o>.<a>.<j>` for the randomness of limb `j` of note `o` to auditor `a`.

Every derived scalar is emitted with the vectors, so replay does not depend on the tags.

### 9.2 Required external vectors
- [ZTV] `test-vectors/json/sapling_note_encryption.json`, commit
  `78321beacb0e0477e33cd002b56585a107c2708c`, SHA-256
  `dda3bed301e90915c2bf35209307d6c9e2d0de103a7ca93e5d15a2c00729f294`. With
  `pers = ASCII("Zcash_SaplingKDF")`, all 10 vectors must reproduce:
  - `shared_secret = encode([8·esk]·pk_d)`;
  - `encode([8·ivk]·epk) = shared_secret`;
  - `k_enc = KDF(pers, shared_secret, epk)`;
  - `c_enc = ChaCha20-Poly1305-Encrypt(k_enc, 0^12, empty, p_enc)`, and its decryption.
- [RFC 7693] Appendix A, BLAKE2b-512("abc"), for the BLAKE2b core.
- [RFC 8439] §2.8.2, for the AEAD.

### 9.3 Profile vectors
The independent reference (`zeroj-circuit-lib/src/test/resources/confidential-note-reference/`)
emits the profile vectors: deliveries, every acceptance failure, and the §8 serializations.
They are replayed against the library at every build.

---

## 10. References

- **[ZcashSpec]** *Zcash Protocol Specification*, v2026.7.0-282-g3af03a [NU6.2], 2026-10-08,
  zcash/zips commit `3af03aa3ad991874d86b8cf35919bc9b4671e8ba`. Sections:
  - §4.1.4, §4.1.6, §4.7.2;
  - §4.20.1–§4.20.2;
  - §5.4.1.2, §5.4.3, §5.4.5.3, §5.4.5.4;
  - §5.4.9.3.
- **[ZTV]** zcash/zcash-test-vectors, commit `78321beacb0e0477e33cd002b56585a107c2708c`.
- **[BLAKE2]** J.-P. Aumasson, S. Neves, Z. Wilcox-O'Hearn, C. Winnerlein, *BLAKE2: simpler,
  smaller, fast as MD5*, 2013.01.29, §2.8.
- **[RFC 7693]** The BLAKE2 Cryptographic Hash and Message Authentication Code, Appendix A.
- **[RFC 8439]** ChaCha20 and Poly1305 for IETF Protocols, §2.8, §2.8.2, §4.
- ZeroJ: ADR-0055; `pedersen-jubjub-v1` (§1–§5); `elgamal-jubjub-v1` (§2, §3.3, §8, §9.1).
