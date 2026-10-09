# ZeroJ DKG Share Delivery with HPKE v1 — Normative Specification

**Profile identifier:** `dkg-share-delivery-hpke-v1`
**Status:** Normative. Required by ADR-0054 (milestone M0).
**Date:** 2026-10-09

This document pins every value, message, rule and encoding that a second implementation needs to
deliver the private `SHARE` messages of [`elgamal-jubjub-threshold-v1`](elgamal-jubjub-threshold-v1.md)
over the same public board as the rest of the key generation. Each `SHARE` is encrypted with
HPKE [RFC 9180] to a per-attempt recipient key announced in a transport round 0 (ADR-0054 D1–D8).
Anything not written here is not part of the profile. Any change needs a new identifier (`-v2`).

This is a **transport profile**. It changes nothing in `elgamal-jubjub-threshold-v1`: not its
messages, rules, transcript, digest, admission or outputs (ADR-0054 Q1). A run that uses this
transport produces exactly the transcript a run with ideal private channels would produce, given
the same shares.

Conventions:
- `u8` is one unsigned byte. `‖` is concatenation.
- `I2OSP(x, k)` writes `x` as `k` big-endian bytes, as in RFC 9180 §3.
- `p = 2^255 − 19`. X25519 values are 32-byte strings, little-endian, as in [RFC 7748] §5.
- `session`, `n`, `t`, the identifiers `1 … n`, the roster keys `key_j`, `SHARE`,
  `COMMITMENTS` and the rounds are those of `elgamal-jubjub-threshold-v1` (§1–§5).
- `ASCII(s)` is the byte string of the ASCII characters of `s`, without a terminator.

---

## 1. Suite and mode

| Item | Value | Reference |
|---|---|---|
| Mode | `mode_base = 0x00`, single-shot | RFC 9180 §5.1.1, §6.1 |
| KEM | `0x0020` DHKEM(X25519, HKDF-SHA256): `Nsecret = 32`, `Nenc = 32`, `Npk = 32`, `Nsk = 32` | §4.1, §7.1 |
| KDF | `0x0001` HKDF-SHA256: `Nh = 32` | §7.2, [RFC 5869] |
| AEAD | `0x0003` ChaCha20Poly1305: `Nk = 32`, `Nn = 12`, `Nt = 16` | §7.3, [RFC 8439] §2.8 |

This one suite and this one mode are the only ones produced or accepted. There is no
negotiation. `SealBase` and `OpenBase` are RFC 9180 §6.1 exactly, with the key schedule of §5.1,
`psk = ""` and `psk_id = ""`. A single-shot context uses sequence number 0 only. The export
interface (§5.3) is not used.

**Validation (RFC 9180 §7.1.4).** Every Diffie–Hellman output is checked. If `DH(sk, pk)` is the
all-zero string, the operation fails. This is required of both the sender (`Encap`) and the
recipient (`Decap`), whatever the underlying X25519 implementation does.

---

## 2. X25519 encodings

### 2.1 Canonical public values

A 32-byte string `b` is a **canonical X25519 public value** if:
1. bit 255 of `b` (the most significant bit of `b[31]`) is 0; and
2. the little-endian integer `u` that `b` encodes satisfies `u < p`.

Every X25519 public value carried in a message of this profile, the announced key `pkR` (§3) and
the encapsulation `enc` (§4), must be canonical. A non-canonical value makes its message
**malformed**. This is checked on the bytes before any X25519 computation (ADR-0054 D8, Q4).

The X25519 function itself is unchanged. [RFC 7748] §5 requires implementations of the function
to "accept non-canonical values". This profile only refuses such values earlier, at the message
format, so that each message has one accepted encoding.

### 2.2 Small-order announced keys

An announced key `pkR` must also have **non-zero DH output** with a fixed probe scalar:

```
PROBE = 0x09 ‖ 0^31            (a 32-byte X25519 private scalar, clamped as in RFC 7748 §5)
X25519(PROBE, pkR) ≠ 0^32
```

Clamping makes every X25519 scalar `k` a multiple of 8, with `k = 8k'` and
`2^251 ≤ k' < 2^252`. So `k'` is never a multiple of either large prime factor:
- the curve's subgroup order `q = 2^252 + 27742317777372353535851937790883648493`;
- the twist's `q' = 2^253 − 55484635554744707071703875581767296995`.

Hence `X25519(k, u) = 0^32` exactly when the point with u-coordinate `u` has order dividing 8
(curve, cofactor 8) or 4 (twist, cofactor 4), whatever the scalar. That is, `u` is of small
order. One fixed scalar decides it for all. A small-order key would make every dealer's `Encap` fail (§1). Refusing it in the
announcement gives every participant the same directory (§3.2).

### 2.3 Private keys

A recipient private key `skR` is 32 bytes from a cryptographically secure generator: RFC 9180
§4's `GenerateKeyPair`, which for X25519 is 32 random bytes used as the scalar. It is clamped by
X25519 itself. `DeriveKeyPair` (§7.1.3) is used only to reproduce the RFC's test vectors.
`pkR = X25519(skR, 9)`, which is `SerializePublicKey`. The same applies to the ephemeral key `skE`: fresh for every envelope, and
never reused (RFC 9180 §9.2.3).

---

## 3. Round 0 — key announcements

### 3.1 Message

Before round 1 of the key generation, each participant `j` posts one announcement for the
attempt:

```
ANNOUNCE_j = TAG_A ‖ session (32) ‖ u8(j) ‖ pkR_j (32)
TAG_A      = ASCII("zeroj.dkg-share-delivery-hpke.v1.announce")      (41 bytes)
```

Its length is exactly 106 bytes. `pkR_j` is a fresh key for this session (§7).

An announcement is **well-formed** for a configuration only if all of the following hold:
- its length is exactly 106 bytes and it starts with `TAG_A`;
- `session` equals the configuration's session;
- `1 ≤ j ≤ n`;
- `pkR_j` is canonical (§2.1) and passes the small-order probe (§2.2).

It is **delivered** only if it is also authenticated as sent by participant `j` under `key_j`,
by the application's authenticator (`elgamal-jubjub-threshold-v1` §8), and it is in the final
round-0 window (§5).

### 3.2 The key directory

For each `j`, consider the delivered announcements from `j`. Byte-identical copies count once.
- Exactly one distinct announcement: `j`'s key is its `pkR_j`.
- None, or two or more distinct ones (a **conflict**): `j` has **no key**.

The directory is a deterministic function of the final round-0 window, so every honest
participant computes the same one.

### 3.3 Abort T1 — own key missing

A participant `j` whose directory gives **no key for `j` itself**, or a key other than its own
(the public key of the private key `j` holds), aborts the attempt before round 1 (ADR-0054 D4). It does not deal, complain,
answer, confirm or post anything further for the attempt.
- This covers an announcement that is missing, malformed, unauthenticated or in conflict.
- A different key can be there only if someone authenticated as `j` posted it. That cannot
  happen to an honest participant.

T1 ensures that an honest participant never complains about missing shares because its own key
went missing. Such complaints would make every dealer publish that participant's shares.

---

## 4. Round 1 — envelopes

### 4.1 Sealing

For each recipient `j ≠ i` that has a key in the directory, dealer `i` seals its `SHARE_ij`, the
canonical 100-byte `SHARE` message of `elgamal-jubjub-threshold-v1` §4 (header included):

```
info        = TAG_I ‖ session (32) ‖ u8(i) ‖ u8(j)
TAG_I       = ASCII("zeroj.dkg-share-delivery-hpke.v1.info")         (37 bytes)
(enc, ct)   = SealBase(pkR_j, info, aad = "", pt = SHARE_ij)          (RFC 9180 §6.1)
ENVELOPE_ij = TAG_E ‖ session (32) ‖ u8(i) ‖ u8(j) ‖ enc (32) ‖ ct (116)
TAG_E       = ASCII("zeroj.dkg-share-delivery-hpke.v1.envelope")     (41 bytes)
```

- `ENVELOPE_ij` is exactly 223 bytes, and `ct` is exactly `100 + 16 = 116` bytes.
- `info` is 71 bytes. All binding is in `info`, as RFC 9180 §8.1 recommends for single-shot
  use, and `aad` is the empty string.
- A dealer seals **no envelope to itself**: it keeps `(s_ii, s'_ii)`.
- It seals none to a recipient without a key.

None of the three tags is a prefix of any other, or of any `elgamal-jubjub-threshold-v1`
message. Those all begin with a 32-byte session, which a fixed ASCII tag matches only with
negligible probability, so the threshold profile's decoding refuses every message of this
profile.

### 4.2 Opening

Recipient `j` processes every envelope in the final round-1 window (§5) whose header names `j`
as recipient. An envelope is **accepted** only if every step succeeds:
1. its length is exactly 223 bytes and it starts with `TAG_E`;
2. `session` equals the configuration's session, `1 ≤ i ≤ n`, the header recipient is `j`, and
   `i ≠ j`;
3. it is authenticated as sent by participant `i` under `key_i`;
4. `enc` is canonical (§2.1);
5. `pt = OpenBase(enc, skR_j, info_ij, aad = "", ct)` succeeds, including the all-zero DH check
   (§1) and AEAD verification;
6. `pt` is a well-formed `SHARE` of this session, with sender `i` and subject `j`
   (`elgamal-jubjub-threshold-v1` §4). The recipient then submits it as a private delivery from
   `i`.

Byte-identical envelopes count once. Envelopes are de-duplicated only **after** authentication
(step 3), so an unauthenticated copy can never shadow the genuine post.
- Two accepted envelopes from `i` to `j` whose plaintexts are byte-identical deliver one `SHARE`.
- Two whose plaintexts differ deliver two different `SHARE`s, which the threshold profile treats
  as a conflict (§5, R2: a complaint).

**Failure is absence.** If any step fails, that envelope delivers nothing. The participant
publishes nothing about the failure and no other message. The only public consequence of a
missing or invalid share is the threshold profile's usual round-2 `COMPLAINT` (ADR-0054 D6, I4).

**A local fault is not a failed step.** A step fails only because of the envelope:
- a malformed header (steps 1, 2, 4);
- an authentication result of "not authentic" (step 3);
- a small-order `enc`, refused by X25519 or giving the all-zero value (step 5);
- an AEAD verification failure (step 5);
- a plaintext that is not the expected `SHARE` (step 6).

If the recipient's own platform fails instead (a primitive is unavailable or errs, or the
authenticator cannot answer), the recipient must not treat the envelope as absent. It stops
processing, keeps its key and does not close round 1; it may then process the same final window
again. Treating such a fault as absence would turn every honest dealer's share into a complaint,
and so into a public answer.

---

## 5. Windows, the processing barrier and posting order

A **window** is the board's set of posts for one round of this profile or of the threshold
profile, delivered under the per-window rule of `elgamal-jubjub-threshold-v1` §5. That set
contains the posts made while the round was open, before its cutoff, and final. An early or late
post belongs to no window.

With this profile, **round 0 precedes round 1**:
- Round 1's window opens when round 0's window closes. This refines the threshold profile's
  "for round 1, once the session started".
- A threshold-profile message posted during round 0 is early and belongs to no window.
- Rounds 2–7 are unchanged.

**Atomic posting** (§5.2) is a property of the board: all of a set of posts are included in one
window, or none are. For example, they share one ledger transaction. This profile defines no
wire format for it. Each contained message is authenticated and processed exactly as if posted
alone.

### 5.1 Processing barrier (ADR-0054 D6a)

A participant advances only after the window is final, retrieved and fully processed:
- **After round 0:** it builds the directory (§3.2), applies T1 (§3.3) and only then seals
  (§4.1).
- **After round 1:** it delivers its round-1 broadcasts to the threshold participant, opens and
  processes **every** envelope addressed to it (§4.2), and only then closes round 1 of the
  threshold profile.

A participant must never close round 1 while an envelope in the final window is unprocessed. The
window's cutoff decides what was delivered; how long processing takes does not.

### 5.2 Posting order (ADR-0054 D7a)

Dealer `i` posts its round-1 `COMMITMENTS` **only after all its envelopes are final on the board
within the round-1 window**. Alternatively, it posts the envelopes and `COMMITMENTS` atomically,
in one post that the board includes entirely or not at all.

If its envelopes cannot be made final before the cutoff, the dealer posts no `COMMITMENTS`. R1
then disqualifies it, and it is never asked to answer an honest complaint. Recipients perform no
check of this rule.

### 5.3 Delivery contract (ADR-0054 D7)

The secrecy argument of ADR-0054 assumes:
- **(P1) bounded publication:** an honest participant's posts are included before their window's
  cutoff;
- **(P2) agreement and finality:** every honest participant obtains the same final window;
- **(P3) the barrier of §5.1.**

With T1 (§3.3) and the posting order (§5.2), secrecy does not depend on P1. P1 then affects only
liveness.

---

## 6. What the board reveals

This section is informative: it records consequences, not rules.

- The board reveals who sent envelopes to whom and when, but no share (RFC 9180 §9.9).
- **No self-envelope.** A leaked `skR_j` reveals only the pairs `(s_ij, s'_ij)` with `i ≠ j`,
  never `j`'s own evaluation or final share.
- **Exposure counting rule (ADR-0054 threat model).** Dealer `i`'s contribution is exposed when
  the distinct evaluation indices known for `f_i` reach `t + 1`. The known indices are:
  - leaked recipient keys `j ≠ i` for which an authentic envelope from `i` is on the board. This
    includes one posted outside its window: it delivered nothing, but it is public and permanent;
  - corrupted participants;
  - public answers for `i`;
  - the pairs published in rounds 5–6 for `i` (extraction complaints and reconstruction); a
    dealer reconstructed in round 6 is entirely public;
  - every recipient of an envelope from `i`, if the ephemeral randomness `i` used for sealing is
    predictable or leaked (§7): with it, anyone can derive each envelope's key. That is at least
    `n − 1 ≥ t + 1` indices, so `i`'s contribution is exposed;
  - all of them, if `i` is corrupted.

  The joint key is exposed when every qualified dealer's contribution is exposed.
- **Answers.** Corrupted participants may still complain about any dealer. A dealer that has not
  aborted answers every delivered complaint; a participant that aborted with T1 answers nothing
  (§3.3). Under §5, every answer by an honest qualified dealer goes to a corrupted complainer's
  index (ADR-0054 I15).

---

## 7. Key lifecycle

- **Per attempt.** A recipient key pair is generated for exactly one `(session, j)` and is used
  only for that session.
- **Separation.** It is never the roster key `key_j` and is not derived from it.
- **Destroy.** The private key is needed only until round 1 is processed (§5.1), and should then
  be destroyed, as it should when the attempt aborts or is abandoned. Implementations can only
  make this best-effort; it is offline class (ADR-0039).
- **Fresh randomness.** Every envelope uses a fresh ephemeral key from a cryptographically
  secure generator.

---

## 8. Assumption A1

The [GJKR07] proof assumes ideal private channels. This profile relies on the following
assumption, which ADR-0054 states and does not prove (an external-review gate):

> Against a static adversary, New-DKG with ideal private channels can be replaced by New-DKG
> whose private messages are encrypted under an IND-CCA2-secure public-key encryption scheme
> to per-attempt honest recipient keys. Secrecy then holds computationally, under the security
> of that scheme plus [GJKR07]'s discrete-log assumption.

RFC 9180 §9.1 and §9.1.2 describe HPKE Base mode's chosen-ciphertext security goal, and its
analysis.

---

## 9. Test vectors

### 9.1 Test keys

Test keys are deterministic. Test X25519 private keys are

```
sk(tag) = SHA-256( ASCII("zeroj.dkg-share-delivery-hpke.v1.test.") ‖ ASCII(tag) )
```

used as 32-byte scalars, clamped by X25519. Production keys must come from a secure generator.

Tag scheme of the profile vectors (§9.3):
- `<prefix>.recipient.<j>` is participant `j`'s recipient key;
- `<prefix>.ephemeral.<i>.<j>` is the ephemeral key of envelope `i → j`;
- `envelope.ephemeral.<case>` is the ephemeral key of a single envelope case.

The prefix is the fixture name (`honest-2of3`, `honest-3of5`, `honest-4of7`), `timing.<case>`,
`directory…`, `envelope…` or `announce`. The reference's README lists every tag. No tag is used
twice.

### 9.2 Required external vectors

- RFC 9180 Appendix A.2.1: every Base-mode encryption, sequence numbers 0–256 as listed in the
  CFRG `test-vectors.json` at commit `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb`.
- [RFC 7748] §5.2 and §6.1, and Wycheproof `x25519_test.json`.
- [RFC 8439] §2.8.2, and Wycheproof `chacha20_poly1305_test.json`.
- [RFC 5869] A.1–A.3, and Wycheproof `hkdf_sha256_test.json`.

The Wycheproof files are taken at commit `12fd3aaf33eb5fa1f52e026912ee00c054f9d984` of
`C2SP/wycheproof`.

### 9.3 Profile vectors

They are produced by the independent reference in
`zeroj-circuit-lib/src/test/resources/dkg-share-delivery-reference/`. Pinned values:

Configuration `honest-2of3`: `t = 1`, `n = 3`, `ctx = "zeroj.test.honest"`, attempt 1, the
standard roster. Recipient 2's key is `sk("envelope.recipient.2")`. Dealer 1's share to
participant 2 is sealed with `skE = sk("envelope.ephemeral.good")`.

| Item | Value |
|---|---|
| `pkR` (recipient 2) | `504988081ce259944f19570f5e350690a094ec9d519d9c41e20c355c4939d96a` |
| `info` (1 → 2) | `7a65726f6a2e646b672d73686172652d64656c69766572792d68706b652e76312e696e666f` ‖ session ‖ `01` ‖ `02` (71 bytes) |
| `enc` | `b9886d82301676564de05a8ace89f381e6421f55d634db0194093db4bc733d12` |
| `shared_secret` | `0af8f73bda0aa3472c9dfc33df93d80647bdd1612bfd2316d83c3c46022bd8e7` |
| `key` | `a50c772753344ab621250e97d7be47778df5114d1703a701e0ab16c1703e3e6f` |
| `base_nonce` | `a13c0a5653e198c69e43a28b` |
| `ct` (116 bytes) | `d898640e561c28fa2f1256ff43dbb3f03b61fe44f15577bcf715434119db5be2faf267425d83e29475d62b7a3f82fdd98994c385fb537b1d595b67021e048fa21bb4e467e4432ed55d8282edbe3c735ae7e28b54322539f3df54d7d31ce761da2028a60045b07987e39b92e44acd84f34431cbf7` |

Full encrypted runs, with recipient keys `<fixture>.recipient.<j>` and ephemerals
`<fixture>.ephemeral.<i>.<j>`, give exactly the threshold profile's §11 outputs. Encrypted delivery
leaves the key generation unchanged:

| Run | Transcript digest | `y` |
|---|---|---|
| `honest-2of3` | `2af7f7eae154833d51861bae276448b396eae5479a074a833a31a9fb9aa46023` | `14acdc488055720e853cbb6b613d2c7f52aee2fa8e7f37b410b1fa9093082658` |
| `honest-3of5` | `edd7aa9f589992e9801d76987611d293ff921e046da81c3790121d767ffdcf71` | `89eeef65017eb8f1a18e38a5b9fc0efb971386181e0db4649c60941cd5a6c425` |
| `honest-4of7` | `9b6a52fe5b0fb06feb875b82cb37871e64bc235b01de384ba54a06f96c24431b` | `ba8011aef2b5f23231919caf1c3c901626e7c970436e98386d46b01713616a63` |

The reference's `reference-output.txt` holds every vector: 110 replayable cases (announce,
envelope, directory, timing, run and exposure), each documented in its README.

---

## 10. References

- **[RFC 9180]** R. Barnes, K. Bhargavan, B. Lipp, C. Wood, *Hybrid Public Key Encryption*,
  February 2022:
  - §3: notation;
  - §4: labeled HKDF;
  - §4.1: DHKEM;
  - §5.1: key schedule;
  - §5.1.1: Base mode;
  - §5.2: encryption and sequence numbers;
  - §6.1: single-shot;
  - §7.1–§7.3: identifiers;
  - §7.1.3: DeriveKeyPair;
  - §7.1.4: validation;
  - §8.1: `info`;
  - §9: security considerations;
  - Appendix A.2: test vectors.
- **[RFC 7748]** *Elliptic Curves for Security*, January 2016: §5 (X25519, decoding), §5.2 and
  §6.1 (test vectors).
- **[RFC 8439]** *ChaCha20 and Poly1305 for IETF Protocols*, June 2018: §2.8 (AEAD).
- **[RFC 5869]** *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, May 2010,
  including Appendix A.
- **[GJKR07]** Gennaro, Jarecki, Krawczyk, Rabin, J. Cryptology 20:51–83 (2007), §2.1 and Fig. 2.
- **ZeroJ:** ADR-0053, ADR-0054, [`elgamal-jubjub-threshold-v1`](elgamal-jubjub-threshold-v1.md).
