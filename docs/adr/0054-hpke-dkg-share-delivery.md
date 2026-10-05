# ADR-0054: Encrypted DKG share delivery with HPKE (`dkg-share-delivery-hpke-v1`)

## Status
Proposed — 2026-10-05.
- Design only. This ADR adds no implementation, test or build file. Accepting it would be design
  acceptance only; it would certify no implementation, test or security property.
- It answers ADR-0053's Q1 ("how are the private channels realized?") with an **optional**
  ZeroJ-provided transport. Application-provided channels (ADR-0053 D3) stay supported.
- It also bears on ADR-0053's Q7 (late shares under partial synchrony); see D7 and Q6.
- Tracked as #77. Stacked on PR #76, which implements ADR-0052 and ADR-0053.

This ADR changes no maturity claim. ADR-0039's assurance classes apply: every secret-bearing
host operation here is **compatibility/offline** class.

## Date
2026-10-05

## Revision history
- **r1** (2026-10-05): initial proposal.

## Risk classification
- **R3:** D1 (the ciphersuite and mode), D2 (the composition that replaces [GJKR07]'s ideal
  private channels) and D5 (recipient key lifecycle). These decide whether a share stays secret.
- **R2:** D3 (the envelope and its binding), D4 (key announcement), D6 (failure handling and the
  interface to `DkgParticipant`), D7 (relation to ADR-0053's delivery precondition) and D8
  (encodings and canonicality).

## Context

[GJKR07] §2.1 assumes that the trustees "are connected by a complete network of private (i.e.,
untappable and authenticated) point-to-point channels", in addition to "a dedicated broadcast
channel". ADR-0053 implements New-DKG over Jubjub and leaves both to the application (D3), with Q1
escalated. PR #76's `DkgParticipant` takes private deliveries through
`receivePrivate(authenticatedSender, message)`, so the transport is pluggable.

Leaving the private channels to every application has costs:
- Each application must build and review its own confidential, authenticated channel. That is
  exactly the kind of security-critical code ZeroJ exists to provide once, reviewed.
- Point-to-point channels such as TLS between trustees need trustees to be online together and
  reachable, and leave no evidence of delivery.
- ADR-0053's implementation review found that **timely private delivery is a secrecy
  precondition** (spec §5.2, Q7). A `SHARE` that misses its round draws a complaint. The
  dealer's answer then publishes the pair, and with the `t` shares the faulty participants hold,
  that determines the dealer's polynomial. If that happens for every honest dealer, the joint key
  is exposed with no abort.

Cardano gives a natural alternative. The trustees already need a broadcast board with agreement
and round closure (ADR-0053 D3, D4a), for example transactions. If each dealer **encrypts each
share to its recipient's key and posts the ciphertext on that board**, then:
- delivery is provable: everyone sees whether, and when, an encrypted share was posted;
- trustees need not be online together or reach each other;
- a share is delivered exactly when the board delivers the dealer's post, which the broadcast
  model already requires to be timely and agreed.

The scheme must be a pinned standard used exactly as specified. HPKE (RFC 9180) is the standard
construction for encrypting one message to a public key, and Java 25 provides every building
block (D1).

The [GJKR07] Appendix, "Committing Encryption on a Broadcast Channel", shows that encrypting
shares on the broadcast channel **does not fix the bias attack on JF-DKG** (Fig. 1). The attack
works because a JF-DKG dealer's contribution is still undecided when complaints are filed. It
does not say that encryption is unsafe for New-DKG. New-DKG's two-phase structure, with Pedersen
commitments fixed before `QUAL` is decided and extraction only afterwards, is what prevents bias,
and this ADR leaves New-DKG unchanged.

## Threat model and trust assumptions

This extends ADR-0053's threat model, which still applies in full.

- **Adversary:** static and rushing, corrupting up to `t < n/2` trustees ([GJKR07] §2.1), as in
  ADR-0053. Adaptive corruption stays out of scope (ADR-0053 D8).
- **The board is public and permanent.** Every ciphertext posted on it can be stored forever by
  anyone ("harvest now, decrypt later").
- **Broadcast with agreement and round closure** is still provided by the application
  (ADR-0053 D3). Board posts are authenticated under the roster keys (ADR-0053 D4a).
- **Untrusted:** every announced encryption key, every envelope, and the plaintext inside it,
  until it passes ADR-0053's `SHARE` checks.
- **Secret:**
  - each trustee's HPKE private key `skR` for the attempt;
  - every share pair `(s_ij, s'_ij)` before the dealer publishes it in an answer;
  - each dealer's encapsulation randomness.
- **HPKE's guarantees and limits (RFC 9180):**
  - §9.1 and §9.1.2: Base mode targets message secrecy against chosen-ciphertext attacks.
    [CS01] shows that a hybrid scheme of essentially this form is IND-CCA2 secure when its KEM
    and AEAD are. The RFC notes that the extra KDF calls in HPKE need their own analysis
    ([HPKEAnalysis]).
  - §9.1 and §9.7.4: **no forward secrecy with respect to recipient compromise.** "In the Base
    and Auth modes, the secrecy properties are only expected to hold if the recipient private
    key skR is not compromised at any point in time."
  - §9.7.5: with bad encapsulation randomness, Base mode can lose confidentiality completely.
  - §9.1.3: the analyses are classical; X25519 is not post-quantum.
- **Consequence of recipient-key compromise.** A leaked `skR_j` exposes every share ever sent to
  trustee `j` under that key. Leaked keys of `t + 1` or more trustees expose the joint key, and
  with it every ballot ever encrypted to it. D5 limits the window to one attempt.
- **Post-quantum.** A quantum adversary could decrypt the envelopes. It could equally compute
  discrete logarithms on Jubjub and decrypt the `elgamal-jubjub-v1` ballots directly, so X25519
  adds no weaker link than the one the election already has. A post-quantum design is out of
  scope (see Related findings).

## Pinned normative references

- **[RFC9180]** R. Barnes, K. Bhargavan, B. Lipp, C. Wood, *Hybrid Public Key Encryption*,
  RFC 9180, February 2022. The text was fetched from rfc-editor.org on 2026-10-05.
  - §4.1: DHKEM.
  - §5.1.1: `SetupBaseS`/`SetupBaseR`.
  - §5.2: encryption and decryption.
  - §6.1: single-shot `SealBase`/`OpenBase`.
  - §7.1: KEM `0x0020` DHKEM(X25519, HKDF-SHA256). §7.2: KDF `0x0001` HKDF-SHA256.
    §7.3: AEAD `0x0003` ChaCha20Poly1305 (and `0x0001` AES-128-GCM, the Q3 alternative).
  - §7.1.4: "recipients MUST check whether the Diffie-Hellman shared secret is the all-zero value
    and abort if so."
  - §8.1: applications that use only the single-shot APIs "should use the Setup info parameter".
  - §9.1, §9.1.1, §9.1.2, §9.1.3, §9.2.3 (encapsulation randomness "MUST NOT be reused"),
    §9.7.3 (no replay protection), §9.7.4, §9.7.5.
  - Appendix A.2: test vectors for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
    A.2.1 covers Base mode.
- **[RFC7748]** Langley, Hamburg, Turner, *Elliptic Curves for Security*, RFC 7748, January 2016.
  Fetched 2026-10-05.
  - §5: X25519 implementations "MUST mask the most significant bit in the final byte" and "MUST
    accept non-canonical values and process them as if they had been reduced modulo the field
    prime".
  - §6.1: the optional all-zero check.
- **[RFC8439]** ChaCha20 and Poly1305 for IETF protocols, §2.8 (AEAD). Fetched 2026-10-05.
- **[RFC5869]** HKDF. Fetched 2026-10-05.
- **[GJKR07]** as pinned by ADR-0053: §2.1 (the channel and adversary model) and the Appendix
  ("Committing Encryption on a Broadcast Channel", an attack on JF-DKG's bias).
- **[CS01], [HPKEAnalysis]**: cited through RFC 9180 §9.1.2; not fetched (**unverified**
  directly).
- **ZeroJ:**
  - ADR-0053 (D3, D4a, D6, D8; Q1, Q7);
  - `docs/specs/elgamal-jubjub-threshold-v1.md` (§4 messages, §5 delivery windows, §5.2, §8);
  - ADR-0039 (assurance classes).

## Notation

- `n`, `t`, trustee identifiers `1 … n`, `session`: as in `elgamal-jubjub-threshold-v1`.
- `SHARE_ij`: the canonical 100-byte `SHARE` message of spec §4 from dealer `i` to recipient `j`
  (header and `I2OSP32(s_ij) ‖ I2OSP32(s'_ij)`).
- `(skR_j, pkR_j)`: trustee `j`'s X25519 key pair for one attempt.
- `SealBase`/`OpenBase`: RFC 9180 §6.1.

## Decision

### D1 — Ciphersuite and mode (R3)

ZeroJ uses **HPKE Base mode, single-shot** (RFC 9180 §5.1.1, §6.1) with one fixed ciphersuite:
- KEM `0x0020`, DHKEM(X25519, HKDF-SHA256);
- KDF `0x0001`, HKDF-SHA256;
- AEAD `0x0003`, ChaCha20Poly1305 (lean; Q3).

No other mode, suite or negotiation is accepted. A fixed suite leaves nothing to downgrade
(RFC 9180 §9.7.2).

**Base, not Auth.** Sender authentication comes from the board: every post is authenticated under
the dealer's roster key (ADR-0053 D4a). HPKE's Auth mode would add a second sender key, and its
DHKEM variant is subject to key-compromise impersonation (§9.1.1).

**The implementation is assembled from the RFC on JDK primitives.** Java 25 has no HPKE `Cipher`.
A probe on GraalVM JDK 25.0.2 (2026-10-05) found:
- `KeyAgreement` X25519 from SunEC;
- `javax.crypto.KDF` HKDF-SHA256 from SunJCE;
- `Cipher` ChaCha20-Poly1305 and AES/GCM from SunJCE.

SunEC refuses small-order inputs with `InvalidKeyException: Point has small order`. That
includes `u = 0`, `u = 1` and their non-canonical forms `p` and `p + 1`, which covers §7.1.4's
all-zero check. The ZeroJ code also checks the shared secret explicitly, so the rule does not
depend on the provider. ZeroJ's main code uses no third-party cryptography library.

### D2 — Replacing ideal channels by encryption (R3; security argument stated, not proven)

The [GJKR07] proof assumes ideal private channels. Here, each private channel is replaced by HPKE
encryption of `SHARE_ij` to `pkR_j`, posted on the board. The assumption this rests on is stated
explicitly:

> **Assumption A1 (to be reviewed externally).** Against a static adversary, New-DKG with ideal
> private channels can be replaced by New-DKG whose private messages are encrypted under an
> IND-CCA2-secure public-key encryption scheme to per-attempt honest recipient keys. Secrecy then
> holds computationally, under the security of that scheme plus [GJKR07]'s discrete-log
> assumption.

The intuition, which is **not** a proof:
- A simulator for the ideal-channel proof knows every share between an honest and a corrupted
  party, and can replace each honest-to-honest ciphertext by an encryption of a fixed dummy
  plaintext.
- IND-CCA2 covers the adversary's ability to post envelopes to honest recipients and watch
  whether they complain, which amounts to a one-bit decryption oracle (D6).
- Non-committing encryption would be needed only against adaptive corruption, which is out of
  scope.

ZeroJ does not supply a proof of A1. It is an explicit **external-review gate**, and the spec
must state it.

Robustness and the complaint flow are unchanged. A dealer still answers a complaint by publishing
the pair in the clear ([GJKR07] Fig. 2, Step 1(c)), so no party ever needs to prove what a
ciphertext decrypts to (Q5).

### D3 — The envelope and its binding (R2)

Dealer `i` sends `SHARE_ij` by posting an **envelope** on the board in round 1:

```
envelope = header ‖ enc (32 bytes) ‖ ct (116 bytes)
header   = PROFILE_TAG ‖ session (32 bytes) ‖ u8(sender i) ‖ u8(recipient j)
info     = INFO_TAG ‖ session ‖ u8(i) ‖ u8(j)
(enc, ct) = SealBase(pkR_j, info, aad = empty, pt = SHARE_ij)
```

The illustration is not normative; the spec (M0) fixes the tags, lengths and order. Its
properties are fixed here:
- **Everything is bound in `info`**, as RFC 9180 §8.1 recommends for single-shot use: the
  profile, the session, the sender and the recipient. HPKE also binds `enc` and `pkR_j` through
  its key schedule. `aad` is empty.
- **The plaintext is the full canonical `SHARE_ij`**, header included. After decryption,
  ADR-0053's existing `SHARE` checks apply unchanged: the session, round, sender, subject and
  scalar ranges.
- **Fixed length.** 100-byte plaintext and 116-byte ciphertext, so length reveals nothing
  (RFC 9180 §9.7.6).
- **Not a DKG message.** The header starts with a tag that is not a session prefix, so
  `DkgMessage.decode` refuses envelopes and `DkgTranscript.deliveredRound` drops them as junk.
  The DKG transcript, digest and admission (ADR-0053 D4a) are unchanged.
- **Replay** is refused by the binding: an envelope opens only for its own session, sender and
  recipient. RFC 9180 provides no replay protection itself (§9.7.3). Byte-identical repeats count
  once. Two different envelopes from one dealer to one recipient deliver two `SHARE`s, which
  ADR-0053's conflict rules already handle.

### D4 — Key announcement (R2)

Before round 1, a transport round 0 publishes the attempt's encryption keys:
- Each trustee `j` posts `ANNOUNCE_j = header ‖ pkR_j`, authenticated under its roster key, like
  every board post.
- Trustee `j`'s key is the **unique** well-formed, authenticated announcement from `j` delivered
  in round 0, under the per-window delivery rule of spec §5.
- Two different announcements from `j` are a conflict, and `j` then has **no key**. So does a
  trustee that posts no announcement.
- A dealer posts no envelope to a recipient without a key. That recipient complains or stays
  silent, and either way only a faulty trustee's own shares can become public.
- Round 1 opens when round 0 closes. The DKG's round numbering and rules (spec §5) are unchanged.

No proof of possession is required for these keys. Copying another trustee's public key only
makes the copier's own shares unreadable to itself. HPKE binds `pkR` in its key schedule, so the
victim cannot be made to accept the copier's shares as its own. The copier's complaints then
publish only its own shares. Rogue-key attacks matter for key aggregation, which this
construction does not use.

Alternative (Q2): put the encryption keys in the trusted configuration instead.

### D5 — Recipient key lifecycle (R3)

- **Per attempt.** Each trustee generates a fresh X25519 key pair for every `(session, j)`, from
  a `SecureRandom`. The API binds a key pair to the session it was generated for, and refuses to
  seal or open under another session.
- **Separation.** The encryption key is never the roster authentication key, nor derived from
  it.
- **Deletion.** The private key is needed only until round 1 closes and the envelopes are opened.
  The API provides a best-effort destroy, after which opening is refused. Java cannot guarantee
  erasure of key material, so this is an offline-class property, not a guarantee.
- **Encapsulation randomness** is fresh per envelope from a `SecureRandom` and never reused
  (RFC 9180 §9.2.3, §9.7.5).
- **Harvest now, decrypt later.** Per-attempt keys deleted after round 1 bound the exposure to
  the DKG window. Long-lived encryption keys would expose every past attempt to one later
  compromise.

### D6 — Failure handling and the `DkgParticipant` interface (R2)

Every failure to obtain a valid `SHARE_ij` is treated **as absence**, and leads to the same
public consequence as today: a Fig. 2 complaint in round 2. The failures are:
- no envelope;
- a malformed envelope or header;
- a non-canonical or invalid `enc`;
- an all-zero shared secret;
- AEAD failure;
- a plaintext that fails ADR-0053's `SHARE` checks.

The recipient publishes no other signal, and the library exposes no error detail to other
parties. Locally, the reason may be logged for diagnosis.

The interface is a thin layer over the existing participant:
- **Open:** the recipient decrypts and calls `DkgParticipant.receivePrivate(i, SHARE_ij)`.
- **Seal:** the dealer takes the `SHARE` messages from `DkgParticipant.start()` and seals each
  one into an envelope.

`DkgParticipant`, `DkgRules`, `DkgTranscript` and `ThresholdKeyContext.admit` are unchanged.

### D7 — Relation to ADR-0053's delivery precondition (R2; Q6)

With this transport, a `SHARE` is delivered when the board delivers its envelope in round 1, by
the same mechanism and deadline as the dealer's `COMMITMENTS`. The board assumption of
ADR-0053 D3 (agreement, closure, partial synchrony) already makes that timely for every honest
dealer. An honest recipient that reads the board and holds its key then never complains about an
honest dealer. So the §5.2 precondition, "timely private delivery", **reduces to the broadcast
assumption the protocol already needs**.

This is an argument, not a theorem, and it is flagged for review. It does not cover an honest
recipient that loses its key during the run, which is a local fault like losing its share.
ADR-0053's Q7 note stays in force for application-provided channels.

### D8 — Encodings and canonicality (R2; Q4)

- Announcements and envelopes have exact lengths.
- Every X25519 public value on the board (`pkR_j`, `enc`) must be the **canonical** 32-byte
  little-endian encoding: bit 255 clear and `u < 2^255 − 19`. A non-canonical value makes the
  announcement or envelope malformed, so the key or share is absent.
- The X25519 function itself stays RFC 7748 conformant. This is a message-format rule, applied
  before any X25519 call. It keeps one accepted encoding per message, as AGENTS.md requires.
  Because RFC 7748 §5 says implementations "MUST accept non-canonical values", Q4 asks the
  maintainer to confirm that a protocol message format may refuse them.

### D9 — Out of scope

- Post-quantum or hybrid KEMs.
- Adaptive security and non-committing encryption.
- Publicly verifiable secret sharing, which proves share validity in zero knowledge and would
  remove the complaint round.
- HPKE PSK, Auth and AuthPSK modes; the export interface.
- Key storage between attempts.
- Delivery for anything other than DKG `SHARE`s.

### Alternatives considered

| Alternative | Why not chosen |
|---|---|
| Application-provided channels only (ADR-0053 status quo) | Kept as an option, but every application must build and review its own. Point-to-point channels give no evidence of delivery, and they leave the §5.2 precondition on the application. |
| TLS or Noise between trustees | Needs simultaneous online presence and reachability. Delivery is not provable on the board, and it is application infrastructure rather than a library primitive. |
| ECIES or ElGamal-based encryption on Jubjub | No standardized ciphersuite exists; ZeroJ would be defining new cryptography. |
| HPKE Auth mode | Redundant with board authentication, and DHKEM Auth is subject to key-compromise impersonation (RFC 9180 §9.1.1). |
| Committing encryption with recipient proofs of decryption | Not needed: Fig. 2's public answers resolve disputes. The [GJKR07] Appendix shows it does not help JF-DKG, and proofs about decryption would be new constructions. |
| PVSS with zero-knowledge share proofs | Would remove complaints and answers, but is a research-level protocol change with new proofs and circuits. Possible future work. |
| Amending `elgamal-jubjub-threshold-v1` to carry envelopes as DKG messages | Changes a format under review in PR #76 and puts transport into the DKG transcript. Kept as Q1's alternative. |

## Security invariants

- **I1 (D1, D2, D5) Confidentiality.** `SHARE_ij` is recoverable only with `skR_j` of that
  attempt, under HPKE Base IND-CCA2 and Assumption A1. Tested only for functional behaviour
  (wrong-key failure); the security claim is an assumption.
- **I2 (D3) Binding.** An envelope opens only under the profile, session, sender `i` and recipient
  `j` it was sealed for. Changing any of them, `enc`, `ct` or the recipient key makes it fail.
- **I3 (D3, D6) DKG unchanged.** A decrypted plaintext enters only through
  `receivePrivate(i, ·)` and must pass every ADR-0053 `SHARE` check. No transport message is ever
  accepted by `DkgMessage.decode`. The transcript digest and admission are identical to an
  application-channel run with the same shares.
- **I4 (D6) Uniform failure.** Every envelope failure is equivalent to absence: no exception,
  return value or public message distinguishes the failure kinds.
- **I5 (D4) Announcement rule.** A trustee's key is its unique authenticated round-0
  announcement. A conflict or absence gives no key, and dealers send no envelope to it.
- **I6 (D8) Canonical encodings.** Exact lengths, and canonical X25519 values, are enforced
  before cryptographic use. All-zero shared secrets are refused independently of the provider.
- **I7 (D5) Key lifecycle.** Keys are fresh per session, refused for any other session, never the
  roster key, and destroyable. Opening after destroy is refused.
- **I8 (D5) Randomness.** Encapsulation uses fresh `SecureRandom` output per envelope. Determinism
  exists only in a test seam for RFC known-answer tests.
- **I9 (D1) Single suite.** Only `(0x0020, 0x0001, 0x0003)` in Base mode is produced or accepted.
- **I10 (D1) Provider.** Main code uses JDK primitives only, with identical results on the JVM and
  in a GraalVM native image.

## Consequences

- Applications get confidential share delivery without building channels, and delivery becomes
  evidence on the board.
- The DKG gains a transport round 0 and per-attempt key generation; round 1 waits for round 0 to
  close.
- Each trustee posts one announcement and `n − 1` envelopes of about 182 bytes plus the profile
  tag each (34-byte header, 32-byte `enc`, 116-byte `ct` in D3's illustrative layout; the spec
  fixes the length). That is `n(n − 1)` envelopes per attempt,
  4,032 at `n = 64`. Board cost scales quadratically, as the `SHARE` count already does.
- Secrecy now rests computationally on HPKE and Assumption A1, not on ideal channels.
- Recipient key compromise during the window exposes that recipient's shares (no forward secrecy,
  RFC 9180 §9.7.4).

## Compatibility

- **No change** to `elgamal-jubjub-v1`, `elgamal-jubjub-threshold-v1`, their encodings,
  transcripts or admission, under the Q1 lean. Under that lean, PR #76's release gate ("don't
  ship the threshold profile until ADR-0054 settles its wire format") can be lifted; Q7 asks the
  maintainer to confirm.
- A new profile, `dkg-share-delivery-hpke-v1`, and a new public API in
  `org.zeroj.circuit.lib.jubjub`.
- Application-provided channels remain valid.

## Implementation milestones

| ID | Scope | Entry gate | Exit criteria |
|---|---|---|---|
| M0 | Normative spec `docs/specs/dkg-share-delivery-hpke-v1.md`: tags, announcement and envelope formats, `info`, the suite, canonicality, absence rules, key lifecycle, Assumption A1, test vectors. An independent Python reference written from the spec and RFC 9180 on pyca `cryptography` primitives (X25519, HKDF, ChaCha20Poly1305) with no Java read; it reproduces RFC 9180 A.2.1 and emits replayable vectors | ADR accepted | Spec reviewed. The reference passes A.2.1 and its own vectors. |
| M1 | Package-private HPKE (Base, single-shot, the D1 suite) on JDK primitives, with a deterministic-ephemeral test seam | M0 | Every RFC 9180 A.2.1 Base encryption matches. Differential against BouncyCastle 1.83's HPKE on random inputs. Negatives: small-order and all-zero inputs, non-canonical `enc`, tampered `enc`/`ct`, wrong `info`/key. A GraalVM native-image probe produces identical results (I10). |
| M2 | Delivery layer: key generation per session, round-0 announcement, seal/open, wiring to `DkgParticipant` | M1, and ADR-0053 M2 (merged with PR #76) | ADR-0053's honest and adversarial DKG suites rerun with encrypted delivery and identical transcripts (I3). Negatives for I2, I4–I7: wrong session, sender or recipient; cross-attempt replay; conflicting or missing announcements; copied keys; opening after destroy. The §5.2 late-share scenario does not arise under board closure (D7). The Python reference replays. |
| M3 | Docs: support matrix and guide; ADR-0053 Q1/Q7 notes pointing here | M2 | Docs reviewed. |

## Verification and test-vector strategy

- **Published vectors:** RFC 9180 Appendix A.2.1 (Base mode), all encryptions.
- **Independent implementations:**
  - BouncyCastle 1.83's `org.bouncycastle.crypto.hpke.HPKE`, already a test dependency;
  - a Python reference from the RFC text on pyca `cryptography` 46, which has X25519, HKDF and
    ChaCha20Poly1305 but no HPKE, so it is written independently. Its reproduction of A.2.1 is
    checked before Java exists.
- **Adversarial and negative cases:** every invariant's failure mode, run through the real
  `DkgParticipant` state machine.
- **Expected values never come from the code under test.**

## Production / audit gates

- External review of Assumption A1 and D7, together with ADR-0053's DKG review.
- External review of key storage, deletion and `SecureRandom` use on the deployment platform.
- Native-image verification on each released platform.
- Not production-ready until those gates pass; experimental, like ADR-0053.

## Risks

- **The composition argument is wrong or incomplete.** Mitigation: it is stated as an
  assumption, with an external-review gate.
- **Recipient key compromise** while a key exists exposes that trustee's shares. Mitigation:
  per-attempt keys and deletion (D5).
- **Assembly errors in HPKE.** Mitigation: RFC known-answer tests, a BouncyCastle differential
  and an independent Python reference.
- **Provider differences** between the JVM and native image. Mitigation: I10, tested in M1.
- **Metadata:** the board reveals who sent envelopes to whom and when (RFC 9180 §9.9). This
  matches the public DKG structure and reveals no share.

## Open questions (points needing a maintainer decision)

1. **Q1 (D3, Compatibility): layering.**
   - Options:
     - (a) a separate transport profile; envelopes and announcements are board posts outside the
       DKG transcript, and `elgamal-jubjub-threshold-v1` is unchanged;
     - (b) amend the threshold profile with envelope and announcement message kinds in its
       transcript.
   - Lean: (a). The DKG stays untouched and #76's release gate can lift. Admission does not need
     envelopes, because outputs do not depend on them.
2. **Q2 (D4): where encryption keys come from.**
   - Options:
     - (a) per-attempt keys announced in a round 0 under the roster keys;
     - (b) keys in the trusted configuration, such as an election manifest.
   - Lean: (a). Fresh keys per attempt bound harvest-now-decrypt-later exposure. (b) saves a
     round, but tends toward long-lived keys.
3. **Q3 (D1): the AEAD.**
   - Options: (a) ChaCha20Poly1305 (`0x0003`); (b) AES-128-GCM (`0x0001`).
   - Lean: (a). Its software implementation uses no table-based S-box, so it does not depend on
     AES hardware support for timing behaviour. Both have RFC 9180 test vectors (A.2 and A.1).
     This is not a constant-time claim.
4. **Q4 (D8): canonical X25519 encodings versus RFC 7748 §5.**
   - Options:
     - (a) refuse non-canonical values at the message layer, before X25519;
     - (b) accept them, as the X25519 function must, and canonicalize.
   - Lean: (a). The RFC's MUST governs the X25519 function, and ZeroJ's message formats require
     one accepted encoding. Escalated because it narrows inputs that RFC 7748 says
     implementations accept.
5. **Q5 (D2): complaint evidence.**
   - Options:
     - (a) keep [GJKR07] Fig. 2's public answers only;
     - (b) add recipient proofs of what an envelope decrypts to.
   - Lean: (a). It is sufficient for disputes, and (b) would be new cryptography.
6. **Q6 (D7): ADR-0053's Q7.** Should ADR-0053 record Q7 as resolved, for deployments using this
   transport, once ADR-0054 is accepted? Lean: yes, as a note in ADR-0053, keeping the
   precondition for application-provided channels.
7. **Q7 (Compatibility): PR #76's release gate.** If Q1's lean is adopted, lift it. Lean: yes.

## Related findings (out of scope)

- A post-quantum or hybrid KEM (outside RFC 9180's registry) would matter only alongside a
  post-quantum replacement for Jubjub ElGamal itself.
- PVSS-style DKGs with zero-knowledge share proofs could remove complaint rounds. That would be a
  separate ADR.
