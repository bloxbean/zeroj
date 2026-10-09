# ADR-0054: Encrypted DKG share delivery with HPKE (`dkg-share-delivery-hpke-v1`)

## Status
Accepted (design) — 2026-10-09.
- The reviewer approved r3 at `cc63762` with no outstanding findings, and the maintainer
  accepted the design.
- Acceptance is design acceptance only. It certifies no implementation, test or security
  property.
- Q1–Q8 were decided by the maintainer on 2026-10-09: each recorded lean is adopted (see "Open
  questions").
- It answers ADR-0053's Q1 ("how are the private channels realized?") with an **optional**
  ZeroJ-provided transport. Application-provided channels (ADR-0053 D3) stay supported.
- It bears on ADR-0053's Q7 (late shares under partial synchrony); see D7 and Q6.
- Tracked as #77. M0–M3 are implemented on PR #80 and reviewed internally (per milestone and in
  a final whole-PR pass); the PR awaits external review. The "Implementation status" section at
  the end records the state. The implementation is Experimental and makes no production claim.

This ADR changes no maturity claim. ADR-0039's assurance classes apply: every secret-bearing
host operation here is **compatibility/offline** class.

## Date
2026-10-05 (proposed); 2026-10-09 (accepted)

## Revision history
- **r1** (`eb8ddd6`, 2026-10-05): initial proposal.
- **r2** (`9a2f7ab`, 2026-10-05; responds to the review of `eb8ddd6`):
  - F1 → new D6a (a processing barrier: a window is final, retrieved and fully processed before
    a participant seals or closes round 1); D7 rewritten as an explicit contract P1–P3; new D7a
    (a dealer's `COMMITMENTS` only after its envelopes are final, or atomically); new transport
    abort T1 in D4 (own announcement missing); a timing bullet in the threat model; new I11–I13;
    M0/M2 tests for late-processed envelopes, delayed announcements and envelopes excluded by the
    cutoff; Q6 rescoped; new Q8.
  - F2 → the threat model's key-compromise bullet is replaced by exposure accounting that
    separates leaked recipient keys, full trustee state and public disclosures, with per-dealer
    evaluation-index counting (no dealer sends itself an envelope). New I14; M0/M2 exposure tests;
    D5 and Risks updated.
  - Review note on key import → D8 and M1: the 32-byte-to-key adapter decodes explicitly and does
    not rely on provider masking.
- **r3** (2026-10-05; responds to the review of `9a2f7ab`): F3 → the disclosure guarantee is
  scoped. D7 now says what answers can still reveal: corrupted trustees may complain, and dealers
  answer before their own-qualification check, at corrupted indices only. D7a and I13 no longer
  claim "no answer"; a dealer without `COMMITMENTS` is excluded from `QUAL` and draws no honest
  complaint. New I15 (answer scope). M2 and the timing harness include both adversarial-complaint
  traces. The threat model's public-answer example is scoped to honest indices. No change to
  Fig. 2's rules.
- **Accepted** (2026-10-09): approved at r3 (`cc63762`); status flipped without changing the
  design text.
- **Decisions recorded** (2026-10-09): the maintainer adopted the leans of Q1–Q8. No design text
  changes.

## Risk classification
- **R3:** D1 (the ciphersuite and mode), D2 (the composition that replaces [GJKR07]'s ideal
  private channels) and D5 (recipient key lifecycle). These decide whether a share stays secret.
- **R2:** D3 (the envelope and its binding), D4 (key announcement and abort T1), D6 (failure
  handling and the interface to `DkgParticipant`), D6a (the processing barrier), D7 and D7a
  (the delivery contract and the dealer's posting order) and D8 (encodings and canonicality).

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
- the board decides which shares were delivered. With a processing barrier, a commitments-last
  posting order and an abort for a missing own announcement (D6a, D7, D7a, D4), secrecy no longer
  depends on private-delivery timing.

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
- **Timing and processing (r2, F1).** Secrecy also needs bounded publication, finality,
  retrieval and local processing of the round-0 and round-1 board posts before each participant
  advances: the contract P1–P3 of D7, with the barrier of D6a. Closure evidence (ADR-0053 D4a)
  proves which posts a window contains. It does not prove that a participant processed them before
  it closed its round.
- **Exposure accounting (r2, F2).** Three kinds of compromise must be kept apart:
  - **(a) a leaked HPKE private key `skR_j`.** It reveals what was sent to `j` in envelopes: the
    pairs `(s_ij, s'_ij)` for dealers `i ≠ j`. A dealer keeps its own evaluation `f_j(j)` and
    never sends itself an envelope (threshold spec §3; `DkgParticipant.start()`), so `skR_j`
    alone does not reveal `j`'s final share `x_j`;
  - **(b) a trustee's complete state:** its polynomials, received shares and `x_j`. That is a
    corruption, counted in `t`;
  - **(c) public disclosures:** complaint answers (round 3), and the pairs published to
    reconstruct marked dealers (rounds 5–6).

  **Counting rule.** Dealer `i`'s contribution `z_i` is exposed when the distinct evaluation
  indices known for `f_i` reach `t + 1`. The known indices are:
  - the leaked recipient keys other than `i`;
  - the corrupted trustees;
  - the public answers for `i`;
  - all of them, if `i` itself is corrupted.

  The joint key `x = Σ z_i` is exposed when every `z_i`, `i ∈ QUAL`, is exposed. For example
  (`n = 3`, `t = 1`, no corruption), leaking `skR_1` and `skR_2` exposes `z_3` but not `z_1` or
  `z_2`, since only `f_1(2)` and `f_2(1)` are in envelopes.

  An enumeration over `(n, t) ∈ {(3, 1), (5, 2), (7, 3)}` (2026-10-05) gives, **in this counting
  model** (not a security proof):
  - **Recipient keys alone:** `t + 1` leaked keys never expose `x`, because each leaked trustee's
    own dealing has only `t` known points. `t + 2` always do.
  - **With the static adversary's `t` corrupted trustees:** one leaked honest key does not expose
    `x`; two always do.
  - **Public answers add points and lower these numbers:** `t` corrupted trustees, one leaked key
    and one answer at an honest index against that trustee's dealing exposed `x` at `n = 5`,
    `t = 2`. Under the delivery contract, an honest qualified dealer never answers at an honest
    index (D7, I15).

  This is **not** a stronger guarantee. Deployments must assume that a few leaked recipient keys,
  together with corruptions and disclosures, can expose the key and every ballot encrypted to it.
  D5 limits the window to one attempt.
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
- A dealer posts no envelope to a recipient without a key.
- **Transport abort T1 (r2).** A trustee whose own announcement is absent from the final round-0
  set, or conflicts there, aborts the attempt before round 1. It stays silent: it neither deals
  nor complains.

  Without T1, an honest trustee whose announcement missed the cutoff would complain against
  every dealer. The answers would then publish its shares, which is the §5.2 exposure in another
  form. T1 mirrors A9, under which a participant's own broadcasts are delivered to itself.

  A recipient without a key that does complain is therefore faulty. The answers give it only the
  shares a corrupted trustee holds in [GJKR07]'s model anyway.
- Round 1's window opens on schedule after round 0's. A dealer seals only after processing the
  final round-0 set (D6a). The DKG's round numbering and rules (spec §5) are unchanged.

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
  compromise. How many leaked keys suffice depends on corruptions and disclosures; the threat
  model's exposure accounting gives the count.

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

### D6a — Processing barrier (R2; r2, responds to F1)

A participant advances past round 0 or round 1 only when all three hold:
1. **The window is final.** Its cutoff has passed, and the set of posts up to the cutoff is final
   and complete, on the same closure evidence admission uses (ADR-0053 D4a).
2. **Every post is retrieved.** It has every post in that window.
3. **Every post is processed.**
   - Round 0: the announcements are applied to the key directory (D4, including T1).
   - Round 1: every envelope is opened and validated, and each accepted plaintext is submitted
     through `receivePrivate` (D6).

Only then does it seal its envelopes (after round 0) or call `DkgParticipant.closeRound()` (for
round 1).

- **The cutoff decides delivery, not processing time.** Slow processing delays the participant,
  a liveness cost. It never turns a delivered share into an absent one.
- **Never close round 1 on a timer while envelopes in the final window are unprocessed.** That is
  the failure the review demonstrated with the unchanged state machine (`n = 3`, `t = 1`).
  Envelopes `1→2` and `2→1` were processed after round 1 closed. That drew two complaints and two
  public answers, and corrupted participant 3 recovered `x` from its own shares plus the answers.
- **The API enforces the order.** The delivery layer takes a final window's posts and returns
  only after every accepted plaintext has been submitted. It offers no close after partial
  processing.

### D7 — Relation to ADR-0053's delivery precondition (R2; Q6; rewritten in r2 for F1)

With this transport, a `SHARE` is delivered when the final round-1 set contains its envelope and
the recipient has processed it. The §5.2 argument needs an explicit **delivery contract**:
- **(P1) Bounded publication.** An honest trustee's round-0 announcement and round-1 posts are
  included on the board before their window's cutoff. This is [GJKR07] §2.1's "received by their
  recipients within some specified time bound", applied to board inclusion. Its budget must
  include processing the previous window, sealing and posting.
- **(P2) Agreement and finality.** Every honest participant obtains the same final set of posts
  for each window (ADR-0053 D3, D4a).
- **(P3) The processing barrier** of D6a.

Under P1–P3, an honest recipient holds its key, so T1 never fires for it. It receives every honest
dealer's envelope in the final round-1 set, and processes it before closing round 1. It never
complains about a dealer whose `COMMITMENTS` is absent: `closeDeal` skips such a dealer, which
R1 disqualifies regardless. So an honest active recipient never makes a false absence complaint
about an honest qualified dealer.

**What answers can still reveal (r3, F3).** Fig. 2 is unchanged, so corrupted trustees may still
complain about any dealer. A dealer answers every delivered complaint in round 3 (`closeComplaints`)
before it checks its own qualification (`closeAnswers`). Such an answer publishes the pair at the
**complainer's** index. That is a corrupted index, already inside the corruption budget of the
threat model's counting rule, so it adds no new evaluation index.

The guarantee is therefore scoped:
- for every honest dealer in `QUAL`, every answer it publishes is addressed to a corrupted
  complainer (I15);
- so the known indices of its polynomial stay within the corrupted set.

It is **not** that honest dealers publish no answers. The §5.2 precondition, in this scoped form,
then **reduces to P1–P3**.

Closure evidence alone is not enough. It proves what a window contains (part of P2). It proves
neither that honest posts made the cutoff (P1) nor that they were processed in time (P3).

#### D7a — A dealer's `COMMITMENTS` only after its envelopes (R2; r2; Q8)

An honest dealer posts its round-1 `COMMITMENTS` **only after all its envelopes are final on the
board within the round-1 window**. Posting them all atomically in one post, for example one
transaction, satisfies the same rule. Recipients need no new check: this constrains honest
dealers only. A dealer whose `COMMITMENTS` arrives without a recipient's envelope is faulty, and
the recipient's complaint makes it publish a point on its own polynomial.

With T1 and D7a, **secrecy no longer depends on P1**:
- An honest dealer whose envelopes miss the cutoff never posts `COMMITMENTS`. R1 disqualifies it,
  so its contribution is not part of the joint key. Honest participants do not complain about it,
  because `closeDeal` skips a dealer without `COMMITMENTS`. Corrupted trustees still may: under the
  unchanged Fig. 2 rule it answers them in round 3, and only then aborts with A2 (`closeAnswers`).
  Those answers concern a polynomial excluded from `QUAL`, at corrupted indices.
- An honest trustee whose announcement misses round 0 aborts (T1) and never complains.

P1 then matters only for liveness, through ADR-0053's A1 bound on `|QUAL|`. Without D7a, an
envelope that misses the cutoff while its `COMMITMENTS` makes it reproduces the §5.2 exposure for
that dealer. Hence Q8.

This is an argument, not a theorem, and it is flagged for review. It does not cover an honest
recipient that loses its key during the run, which is a local fault like losing its share.
ADR-0053's Q7 note stays in force for application-provided channels, and for deployments that do
not meet P2, P3, T1 and D7a.

### D8 — Encodings and canonicality (R2; Q4)

- Announcements and envelopes have exact lengths.
- Every X25519 public value on the board (`pkR_j`, `enc`) must be the **canonical** 32-byte
  little-endian encoding: bit 255 clear and `u < 2^255 − 19`. A non-canonical value makes the
  announcement or envelope malformed, so the key or share is absent.
- The X25519 function itself stays RFC 7748 conformant. This is a message-format rule, applied
  before any X25519 call. It keeps one accepted encoding per message, as AGENTS.md requires.
  Because RFC 7748 §5 says implementations "MUST accept non-canonical values", Q4 asks the
  maintainer to confirm that a protocol message format may refuse them.
- **Explicit decoding (r2, from the review).** The adapter from 32 bytes to a provider key
  implements RFC 7748 §5's decoding itself: little-endian, then the Q4 policy (refuse, under the
  lean) for bit 255 and for `u ≥ 2^255 − 19`. It does not rely on a provider API to decide. The
  review observed that SunEC's encoded-key import masks bit 255, while building an
  `XECPublicKeySpec` from the unmasked integer did not give the same result.

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
- **I10 (D1, D8) Provider.** Main code uses JDK primitives only, with identical results on the JVM
  and in a GraalVM native image. The byte-to-key adapter decodes explicitly (D8). *(Refined
  during implementation, note 10: lookups name the algorithm only, so the JDK providers compute
  under the default provider order. Under a preferred third-party provider, that provider
  computes; absence is still decided by ZeroJ.)*
- **I11 (D6a) Processing barrier.** A participant seals only after the final round-0 window is
  processed, and closes round 1 only after every envelope in the final round-1 window is processed
  and submitted. An envelope inside the cutoff but opened late draws no complaint.
- **I12 (D4) Abort T1.** A trustee whose own announcement is absent or conflicting in the final
  round-0 set aborts before round 1 and never deals or complains.
- **I13 (D7a) Commitments last.** An honest dealer's `COMMITMENTS` is released for posting only
  after all its envelopes are final in the round-1 window, or together with them atomically.
  Envelopes excluded by the cutoff therefore leave the dealer disqualified, with its contribution
  outside the joint key and no complaint from any honest participant. It may still answer
  complaints from corrupted trustees before its A2 abort (r3, F3).
- **I14 (threat model, F2) No self-envelope.** A dealer never seals an envelope to itself, so a
  leaked recipient key reveals only the pairs `(s_ij, s'_ij)`, `i ≠ j`. Exposure follows the
  counting rule of the threat model.
- **I15 (D7; r3, F3) Answer scope.** Under P1–P3, T1 and D7a, every answer that an honest dealer
  in `QUAL` publishes is addressed to a corrupted complainer. Answers therefore add no evaluation
  index beyond the corruption budget. Honest active recipients make no false absence complaint
  about an honest qualified dealer. Fig. 2's complaint and answer rules are unchanged.

## Consequences

- Applications get confidential share delivery without building channels, and delivery becomes
  evidence on the board.
- The DKG gains a transport round 0 and per-attempt key generation; round 1 waits for round 0 to
  close.
- Each trustee posts one announcement and `n − 1` envelopes of about 182 bytes plus the profile
  tag each (34-byte header, 32-byte `enc`, 116-byte `ct` in D3's illustrative layout; the spec
  fixes the length). That is `n(n − 1)` envelopes per attempt,
  4,032 at `n = 64`. Board cost scales quadratically, as the `SHARE` count already does.
- Round 1 includes one finality wait: envelopes first, then `COMMITMENTS` (D7a), unless both are
  posted atomically.
- Secrecy now rests computationally on HPKE and Assumption A1, not on ideal channels, and
  operationally on the contract of D7.
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
| M0 | Normative spec `docs/specs/dkg-share-delivery-hpke-v1.md`: tags, announcement and envelope formats, `info`, the suite, canonicality and explicit decoding, absence rules, abort T1, the processing barrier, the delivery contract P1–P3 and the posting order of D7a, key lifecycle, exposure accounting, Assumption A1, test vectors. An independent Python reference written from the spec and RFC 9180 on pyca `cryptography` primitives (X25519, HKDF, ChaCha20Poly1305) with no Java read. It reproduces RFC 9180 A.2.1, models the barrier and the exposure counting rule, and emits replayable vectors | ADR accepted | Spec reviewed. The reference passes A.2.1 and its own vectors. |
| M1 | Package-private HPKE (Base, single-shot, the D1 suite) on JDK primitives, with a deterministic-ephemeral test seam and the explicit byte-to-key adapter (D8) | M0 | Every RFC 9180 A.2.1 Base encryption matches. Differential against BouncyCastle 1.83's HPKE on random inputs. Negatives: small-order and all-zero inputs; non-canonical `enc`, both bit 255 set and `u ≥ p`; tampered `enc`/`ct`; wrong `info`/key. A GraalVM native-image probe produces identical results (I10). |
| M2 | Delivery layer: key generation per session, round-0 announcement and T1, the processing barrier, seal/open with the D7a posting order, wiring to `DkgParticipant` | M1, and ADR-0053 M2 (merged with PR #76) | ADR-0053's honest and adversarial DKG suites rerun with encrypted delivery and identical transcripts (I3). Negatives for I2, I4–I7: wrong session, sender or recipient; cross-attempt replay; conflicting or missing announcements; copied keys; opening after destroy. **Timing (I11–I13):** envelopes posted before the cutoff but opened later draw no complaint; delayed announcements are processed before sealing; an own announcement missing triggers T1 with no complaint; envelopes excluded by the cutoff leave the dealer's `COMMITMENTS` unposted and the dealer disqualified, with no complaint from any honest participant. The review's late-processing scenario (`n = 3`, `t = 1`) is reproduced as a negative control without the barrier and refused with it. **Adversarial complaints (I15):** (i) with timely delivery, a corrupted trustee's complaint against an honest dealer draws one answer at the corrupted index, `QUAL` is unchanged, and the exposure count is unchanged; (ii) under D7a, a corrupted trustee's complaint against an honest dealer whose `COMMITMENTS` was withheld draws an answer at the corrupted index, after which the dealer aborts with A2 and is excluded from `QUAL`. **Exposure (I14):** no envelope is addressed to its sender; leaked-key exposure matches the counting rule. The Python reference replays. |
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
- **Timing harness:** a board model with window cutoffs, finality and delayed processing. It
  drives the barrier (I11), T1 (I12), the posting order (I13) and the answer scope (I15). It
  includes:
  - the review's late-processing counterexample, as a negative control;
  - both adversarial-complaint traces of review round 2. Every answer by an honest qualified
    dealer must be at a corrupted index.
- **Exposure accounting:** vectors that leak chosen recipient keys, with and without corruptions
  and public answers. Reconstruction must succeed exactly when the counting rule says it does.
- **Expected values never come from the code under test.**

## Production / audit gates

- External review of Assumption A1, D7 and D7a (the contract P1–P3, T1 and the posting order),
  together with ADR-0053's DKG review.
- External review of key storage, deletion and `SecureRandom` use on the deployment platform.
- Native-image verification on each released platform.
- Not production-ready until those gates pass; experimental, like ADR-0053.

## Risks

- **The composition argument is wrong or incomplete.** Mitigation: it is stated as an
  assumption, with an external-review gate.
- **Recipient key compromise** while a key exists exposes that trustee's received shares; with
  corruptions and public answers, a few leaked keys can expose the joint key (threat model).
  Mitigation: per-attempt keys and deletion (D5).
- **An application closes rounds on a timer**, before processing finishes. Mitigation: the API's
  order (D6a), documentation, and the negative control in M2.
- **Board finality is slow** relative to the window, so honest dealers miss the cutoff under D7a.
  This costs liveness (A1 aborts), not secrecy. Mitigation: size the windows for finality.
- **Assembly errors in HPKE.** Mitigation: RFC known-answer tests, a BouncyCastle differential
  and an independent Python reference.
- **Provider differences** between the JVM and native image. Mitigation: I10, tested in M1.
- **Metadata:** the board reveals who sent envelopes to whom and when (RFC 9180 §9.9). This
  matches the public DKG structure and reveals no share.

## Open questions (points needing a maintainer decision)

**Decided 2026-10-09 (maintainer): the lean of every question below is adopted.** The
questions stay as written for the record.

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
6. **Q6 (D7): ADR-0053's Q7.** Should ADR-0053 record Q7 as resolved once ADR-0054 is accepted?
   Lean: yes, but **only for deployments that use this transport and meet P2, P3, T1 and D7a**.
   ADR-0053 keeps the precondition, and the documented limitation, for application-provided
   channels and for deployments without that contract.
7. **Q7 (Compatibility): PR #76's release gate.** If Q1's lean is adopted, lift it. Lean: yes.
8. **Q8 (D7a): must a dealer's `COMMITMENTS` follow its final envelopes?**
   - Options:
     - (a) a MUST of the profile, either commitments after the envelopes are final, or one atomic
       post;
     - (b) optional, with the §5.2 exposure documented for dealers whose envelopes miss the
       cutoff.
   - Lean: (a). It removes secrecy's dependence on publication timing, at the cost of one
     finality wait in round 1. Recipients need no new check.

## Related findings (out of scope)

- A post-quantum or hybrid KEM (outside RFC 9180's registry) would matter only alongside a
  post-quantum replacement for Jubjub ElGamal itself.
- PVSS-style DKGs with zero-knowledge share proofs could remove complaint rounds. That would be a
  separate ADR.

## Implementation notes (refinements recorded during implementation)

These refine the accepted design and are recorded for maintainer acknowledgement, as AGENTS.md
requires. Each is stated normatively in `docs/specs/dkg-share-delivery-hpke-v1.md`. They came
from the independent reference (findings S1–S7) and the M1/M2 reviews.

1. **De-duplicate only after authentication** (spec §4.2; reviews M-1 and S-1, P0). The first
   implementation dropped byte-identical posts before authenticating them. A corrupted
   participant could then front-run unauthentic copies of honest envelopes, or of a
   `COMMITMENTS`. The genuine posts were skipped, honest participants complained about each
   other, and the answers exposed the joint key; both reviewers demonstrated this end to end.
   Fixed: every post is authenticated first, and the participant counts identical copies once.
   Front-running vectors and a mutant-killing regression test are included.
2. **"Process before closing" is enforced by binding the participant** (D6a; review S-2).
   `DkgShareDelivery.start` replaces `DkgParticipant.start()` for this transport. It applies T1
   and binds the participant, whose public `closeRound()` then refuses round 1, so round 1
   closes only through `closeRound1`. `DkgParticipant` gains package-private hooks for this; its
   protocol is unchanged.
   - **What binding does not enforce** (final review X-4): that the window passed to
     `closeRound1` is complete, that is, taken after the cutoff and finality.
   - A snapshot taken before finality reproduces the late-processing failure, so this part of
     the barrier stays the application's, like D7a's posting order.
   - Closure evidence checked through the verifier could enforce it. That needs a spec
     addition for rounds 0 and 1, and is a possible follow-up.
3. **Fail closed on verifier exceptions** (review M-4). An exception from the application's
   authenticator leaves the participant at round 1 with its keys, so `closeRound1` can be
   retried. It is not treated as "unauthentic", which would turn a transient failure into
   false complaints.
4. **T1 also on a key other than one's own** (spec §3.3). If the directory holds a key for `j`
   other than the public key of the private key `j` holds, someone authenticated as `j`
   announced it, so `j` is faulty; it aborts.
5. **Spec clarifications from the reference** (S1–S7):
   - round 1's window opens when round 0's closes;
   - the counting rule counts only envelopes actually sent, plus the round 5–6 disclosures;
   - the `GenerateKeyPair` citation is fixed;
   - atomic posting is a board property;
   - the test-key tag scheme is pinned;
   - byte-identical plaintexts count once;
   - a T1 participant answers nothing.
6. **The all-zero DH check is unreachable on SunEC** (review M-6). SunEC refuses small-order
   inputs before returning a shared secret, so the explicit check is defence in depth. Its
   mutant cannot be killed without a stub provider. It is kept for providers that return
   `0^32`.
7. **A platform fault is never absence** (spec §4.2; final security review Z-1, P1). Before the
   fix, any exception from the JDK primitives counted as a failed open. A missing or failing
   HKDF/AEAD provider at an honest recipient made it complain about every honest dealer, and
   the answers then exposed their contributions. Now only input-caused failures are absence:
   - small order (decided as note 10 says);
   - AEAD tag failure;
   - wrong length.

   Everything else is an `IllegalStateException` that fails closed, like verifier exceptions
   (note 3). Note 10 refines how small order is decided. `start` and `closeRound1` also run a seal-and-open self-test with the participant's
   own keys before judging any input. The small-order probe no longer reports a fault as small
   order. Tests remove the SunJCE or SunEC provider at each entry point.
8. **The keys and directory are bound by instance** (final Codex review C-1). `closeRound1`
   refuses any keys or directory other than the instances given to `start`, so substituting
   either cannot turn genuine shares into absences.
9. **Key lifecycle on failure paths** (Z-4). Keys are destroyed when round 1 closes or the
   participant aborts. Any other failure keeps them, for the documented retry. An application
   that abandons the attempt calls `destroy()`. HPKE wipes its intermediate secrets in `finally`.
   - **Also on failure (external Codex review, F4):** the key schedule wipes `eae_prk` and
     `secret` on every path. It also wipes `key` and `base_nonce` unless they passed to the
     returned context.
   - **Tests:** `HpkeFailureWipeTest` injects HKDF failures through a package-private
     `Hpke.Hkdf` seam, which runs on any JDK. It also injects them through a delegating JCA
     provider; that variant runs on OpenJDK builds, while Oracle JDK and GraalVM accept only
     signed JCE providers and skip it.
10. **Small order is decided without the provider** (security round 2, R2-1, and spec↔code
    round 2, X-9; P2).
    - **The bug:** after note 7, small order was recognised by SunEC's `InvalidKeyException`.
      With BouncyCastle preferred, which is common in Java stacks, a small-order `enc` or
      announced key raised a different exception. It was classified as a platform fault, so one
      corrupted trustee could stall every honest participant.
    - **The fix:** small order is now decided before the provider is called, by membership in
      the five canonical small-order u-coordinates (spec §2.2, informative note). The set is
      checked against Wycheproof, and the all-zero check is kept.
    - A test runs a whole DKG with BouncyCastle as the preferred provider.
    - **Provider selection stays algorithm-only.** Pinning `SunEC`/`SunJCE` by name was tried
      and broke the GraalVM native image, which registers a provider only when an
      algorithm-only lookup reaches it. With BouncyCastle preferred, BouncyCastle computes
      X25519 and the AEAD. The outcome does not change: small order is decided by ZeroJ, and BC
      reports tag failures as `AEADBadTagException`. I10's "JDK primitives" therefore holds for
      the default provider order. Provider policy is listed as a review gate.
    - The self-test in `start` and `closeRound1` also opens the RFC 9180 A.2.1 sequence-0
      ciphertext (security round 3, R3-1). A provider that is consistent with itself but does not
      conform to the RFC is therefore refused, rather than turning every honest envelope into a
      complaint.

11. **Lifecycle checks before anything changes** (external review of `914b68c`, two P3s).
    - **`start` on an ineligible participant.** T1 used to run before the lifecycle check. So a
      second `start` on a running participant, with a missing or conflicting own-key
      announcement, aborted it and destroyed its keys. `start` now refuses an ineligible
      participant first, changing nothing:
      - one already started gets an `IllegalStateException`;
      - an aborted one throws its own abort again.

      A legitimate first `start` still applies T1.
    - **The identical-window retry is enforced** (spec §4.2, "A local fault is not a failed
      step"). The first `closeRound1` that reaches delivery binds the participant to the
      window's SHA-256 digest. The digest covers every post's message and authenticator, each
      length-prefixed, in the given order, with repeats counted. A retry with any other window
      is refused with `IllegalArgumentException`, before T1 or any delivery.
    - **What this does not establish:** binding checks only that a retry repeats the first
      window. It is no evidence that the window is final or complete, or that participants
      agree on it. Those stay the application's (P1, P2; note 2).
    - **Tests:**
      - `startAgainRefusedBeforeT1` covers a missing and a conflicting own key.
      - `retryNeedsIdenticalWindow` refuses, after a partial delivery: changed message bytes,
        changed authenticator bytes, an added post, a removed post and a reordered window. Each
        refusal leaves the participant's shares, round and keys as they were. An identical
        retry then succeeds.
      - `windowDigestFraming` checks the framing.

      Each fix's mutant is killed. No design decision changes.

### Proposed amendment awaiting a maintainer decision (not implemented)

- **T2: a dealer's own D7a self-check** (final security review Z-2, P2). Suppose `closeRound1`
  finds the dealer's own authenticated `COMMITMENTS` in the final window, but an envelope from it
  to some keyed recipient missing; the application broke D7a. Honest recipients will then
  complain, and the dealer's answers make those shares public.
  - **Proposal:** the dealer aborts with a new reason before closing round 1. An aborted dealer
    answers nothing and is disqualified, so nothing is exposed.
  - **Why it is not implemented:** it is a new normative abort. It changes the expected outcome
    of the reference's D7a negative control and contradicts spec §5.2's "Recipients perform no
    check of this rule" only in spirit, since it is the dealer's own check. It therefore needs a
    spec amendment and an update to the independent reference, which is ADR scope, not
    implementation scope.
  - **Lean:** adopt it in a follow-up.

## Implementation status

| Milestone | State | Notes |
|---|---|---|
| M0 | Done, reviewed | Spec `docs/specs/dkg-share-delivery-hpke-v1.md`. An independent Python reference (`zeroj-circuit-lib/src/test/resources/dkg-share-delivery-reference/`, 294 checks, 110 replayable vectors), written from the spec and RFC 9180 with no Java read. It reproduces RFC 9180 A.2.1 (all 257 encryptions), Wycheproof X25519, ChaCha20-Poly1305 and HKDF-SHA256, and RFC 7748, RFC 8439 and RFC 5869. Its two revisions raised S1–S7 and R2-1/R2-2, all resolved in the spec. Standard vectors are vendored, pinned by commit and SHA-256, in `src/test/resources/standard-vectors/`. |
| M1 | Done, reviewed (adversarial and security, 2 rounds) | `Hpke` (Base, single-shot, the D1 suite) and `X25519Bytes` (explicit RFC 7748 decoding, canonicality, small-order probe, all-zero check) on JDK primitives. Tests: `HpkeKnownAnswerTest` (A.2.1, Wycheproof, RFC 7748/8439/5869) and `HpkeDifferentialTest` (BouncyCastle 1.83 both ways, byte-identical with the same ephemeral). The GraalVM native-image probe (`HpkeNativeProbe`) gives output identical to the JVM. Seal 114 µs, open 59 µs. |
| M2 | Done, reviewed (adversarial and security, 2 rounds; one P0 found and fixed, implementation note 1) | `DkgShareDeliveryKeys`, `DkgKeyDirectory` (T1), `DkgShareDelivery` (`start` binds the participant; `closeRound1` is the barrier, authenticates before anything else, and fails closed). Tests: `DkgShareDeliveryTest` (I2–I15, front-running, binding, fail-closed retry, copied key, cross-session, platform faults). It reruns several of ADR-0053's adversarial suites over encrypted delivery and compares each with private channels, asserting that each attack took effect: more than `t` complaints; a bad answer; the Feldman cheat; conflicting `COMMITMENTS` or `EXTRACTION`; withheld `EXTRACTION`; and A5. Other board-expressible suites are not rerun: a single unanswered complaint, A3, the rushing order and A7's lying confirmations. They act only on broadcasts, which the transport does not touch. Suites that need per-recipient views (A6, A9) cannot be posted on an agreed board. `DkgShareDeliveryReferenceVectorsTest` replays every reference vector. Honest participants and HPKE run through production code. The reference's negative controls (no barrier, D7a ignored) and corrupted participants run through test code, and the §6 counting rule is re-implemented in the test from the spec. Integration test `AnnotatedElGamalTest.thresholdEndToEndOverEncryptedBoard`: encrypted DKG, admission from the board, Groth16-proved tally. |
| M3 | Done, reviewed in the final pass | Support matrix and `zeroj-circuit-lib` README rows, a gadget-guide section with the MUST rules, the annotation guide, ADR-0053's Q1/Q7 notes, a threshold spec §5.2 pointer, and `docs/benchmarks/dkg-share-delivery-hpke-2026-10-09.md`. |

**Final whole-PR review (2026-10-09).** Three independent reviews ran: spec↔code (Claude),
security (Claude) and Codex.
- **Codex:** approved, with C-1 to C-4.
- **The two Claude reviews:** requested changes.

All findings are addressed except Z-2:
- **C-1:** instance binding (note 8).
- **C-2:** a retry after partial progress.
- **C-3:** HPKE sequence tests.
- **C-4, Z-5, X-7:** documentation precision.
- **Z-1 (P1):** a platform fault is never absence (note 7).
- **Z-3:** the encapsulation-randomness exposure source (spec §6).
- **Z-4, X-8:** the key lifecycle on failure paths (note 9).
- **X-1:** the exposure replay now reaches its HPKE reconstruction, guarded by a coverage check.
- **X-2:** the shape of `broadcasts()`.
- **X-3:** `generate` uses its generator.
- **X-4, X-6:** what binding does not enforce, and the round-1 window rule.
- **X-5:** authenticated junk in the round-1 window.
- **Z-2** (a dealer's own D7a self-check) awaits a maintainer decision; see "Proposed amendment"
  above.
- **External Codex review of `a3b67a1`:** F4 (P2), wiping intermediate HPKE secrets when HKDF
  fails part-way (note 9), is fixed.
- **Round 2:** both reviews found the same regression from the Z-1 fix (R2-1/X-9, note 10). It
  is fixed. Also in round 2:
  - X-10: the T1 re-check in `closeRound1` is documented as defence in depth;
  - X-11: each adversarial rerun asserts that its attack took effect;
  - spec §3.2: a fault while building the directory is not a missing key.
