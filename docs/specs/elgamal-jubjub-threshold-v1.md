# ZeroJ ElGamal-Jubjub Threshold v1 — Normative Specification

**Profile identifier:** `elgamal-jubjub-threshold-v1`
**Status:** Normative. Required by ADR-0053 (milestone M0).
**Date:** 2026-10-05

This document pins every value, message, rule and encoding that a second implementation needs
to take part in, recompute, admit and use a threshold key generation for
[`elgamal-jubjub-v1`](elgamal-jubjub-v1.md). The protocol is New-DKG of [GJKR07] Fig. 2 over
Jubjub (ADR-0053 D1, D1a), plus admission (D4a) and threshold decryption (D5, D5a). Anything not
written here is not part of the profile. Any change needs a new identifier (`-v2`).

Ciphertexts encrypted to a key from this profile are ordinary `elgamal-jubjub-v1` ciphertexts.
Only the key generation and the combination of decryption shares differ.

Conventions:
- `x mod l` is the least non-negative residue.
- `u8`, `u16`, `u32` and `u64` are unsigned **big-endian** integers of 1, 2, 4 and 8 bytes.
- `I2OSP32(x)` writes `x` as 32 big-endian bytes. A scalar is decoded only if it is `< l`.
- `encode(P)` is the 32-byte little-endian point encoding of
  [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §4.
- **BLAKE2b-256** is unkeyed BLAKE2b ([RFC 7693]) with a 32-byte digest and no salt or
  personalisation.

---

## 1. Parameters and bases

- Threshold `t` and participant count `n`: `t ≥ 1`, `n ≥ 2t + 1` (so `t < n/2`, as [GJKR07]
  Theorem 1 requires), and `n ≤ 64`. Any `t + 1` participants can decrypt; at most `t` may be
  faulty.
- Identifiers are the integers `1 … n`. Used as scalars they are non-zero mod `l`.
- **Bases:** `G` and `H` of [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §2.1 and §2.3.
  Nobody knows `log_G H`, which is exactly [GJKR07]'s requirement on `h`.
- **Roster:** `n` authentication keys, `key_1 … key_n`. Each is an opaque byte string of 1 to
  65535 bytes, used only by the application's authenticator (§8). The keys must be pairwise
  distinct; a roster with two equal keys is rejected. One key that authenticates for two
  identifiers would let one party act as two participants, outside the count of `t` faulty
  participants the protocol tolerates. The check compares bytes: if the application's key format
  has more than one encoding of a key, the application must give every key in one canonical
  encoding, or otherwise ensure that no key authenticates for two identifiers.

---

## 2. Session identifier

Each **attempt** of a key generation has its own session:

```
session = BLAKE2b-256( DST_S ‖ u16(len(ctx)) ‖ ctx ‖ u64(attempt) ‖ u8(t) ‖ u8(n)
                       ‖ u16(len(key_1)) ‖ key_1 ‖ … ‖ u16(len(key_n)) ‖ key_n )
DST_S = UTF-8("zeroj.elgamal-jubjub-threshold.v1.session")
```

- `ctx` is the application context, 0 to 65535 bytes: for example an election identifier.
- `attempt` is an integer the application never reuses for the same `ctx`.
- This refines the ADR-0053 Q5 lean (`ctx ‖ attempt ‖ roster ‖ t ‖ n`) with a domain tag and
  length prefixes, so that no two configurations share an encoding.

The configuration `(t, n, roster, ctx, attempt)` is immutable once the session is derived.

---

## 3. Dealing

Each participant `i` acts as a dealer.

1. Sample `2(t + 1)` coefficients `a_i0 … a_it`, `b_i0 … b_it` with the sampler of
   [`elgamal-jubjub-v1.md`](elgamal-jubjub-v1.md) §2 (64 bytes reduced mod `l`). They define
   ```
   f_i(z)  = a_i0 + a_i1·z + … + a_it·z^t   (mod l)
   f'_i(z) = b_i0 + b_i1·z + … + b_it·z^t   (mod l)
   ```
   The dealer's contribution to the key is `z_i = a_i0`.
2. The commitments are `C_ik = [a_ik]·G + [b_ik]·H` and the extraction values are
   `A_ik = [a_ik]·G`, for `k = 0 … t`.
3. The shares are `s_ij = f_i(j)` and `s'_ij = f'_i(j)` for every `j = 1 … n`, including the
   dealer's own `j = i`, which is kept rather than sent.

The two checks of [GJKR07] Fig. 2, for the pair `(s, s')` held by participant `j` from dealer
`i`:

```
(4)   [s]·G + [s']·H  =  Σ_{k=0..t} [j^k mod l]·C_ik
(5)   [s]·G           =  Σ_{k=0..t} [j^k mod l]·A_ik
```

The right-hand sides depend only on public values. Implementations may evaluate them by Horner's
rule in `j`.

---

## 4. Messages

Every message is `header ‖ payload`:

```
header = session (32 bytes) ‖ u8(round) ‖ u8(kind) ‖ u8(sender) ‖ u8(subject)
```

| Round | Kind | Name | Delivery | `subject` | Payload |
|---|---|---|---|---|---|
| 1 | 1 | `COMMITMENTS` | broadcast | 0 | `encode(C_i0) ‖ … ‖ encode(C_it)` |
| 1 | 2 | `SHARE` | private | recipient `j ≠ sender` | `I2OSP32(s_ij) ‖ I2OSP32(s'_ij)` |
| 2 | 3 | `COMPLAINT` | broadcast | accused dealer `i ≠ sender` | empty |
| 3 | 4 | `ANSWER` | broadcast | complainer `j ≠ sender` | `I2OSP32(s_ij) ‖ I2OSP32(s'_ij)` |
| 4 | 5 | `EXTRACTION` | broadcast | 0 | `encode(A_i0) ‖ … ‖ encode(A_it)` |
| 5 | 6 | `EXTRACTION_COMPLAINT` | broadcast | accused dealer `i ≠ sender` | `I2OSP32(s_ij) ‖ I2OSP32(s'_ij)` held by the sender |
| 6 | 7 | `RECONSTRUCTION` | broadcast | reconstructed dealer `i ≠ sender` | `I2OSP32(s_ij) ‖ I2OSP32(s'_ij)` held by the sender |
| 7 | 8 | `CONFIRMATION` | broadcast | 0 | `digest (32 bytes) ‖ encode(y)` (§7) |

**Well-formed.** A message is well-formed only if all of the following hold:
- its length is exact for its kind;
- `session` equals the configuration's;
- `round` and `kind` match a row of the table;
- `1 ≤ sender ≤ n`;
- `subject` satisfies its column: either 0, or an identifier in `1 … n` different from the
  sender;
- every scalar is `< l`;
- every point decodes and lies in the prime-order subgroup. The identity is allowed: `C_ik` and
  `A_ik` may legitimately be `O`.

**Identity and duplicates.** A message's identity is `(round, kind, sender, subject)`. Within a
round's delivered set:
- byte-identical copies count once;
- two **different** well-formed messages with the same identity are a **conflict**.

**Authentication and channels.** Only messages authenticated as coming from their header's
`sender` are delivered (§8). A participant refuses:
- a message whose header `sender` differs from what its authenticated channel says;
- a `SHARE` whose `subject` is not the participant itself;
- a `SHARE` arriving on the broadcast channel;
- any other kind arriving on the private channel.

A message delivered privately to one participant must never be treated as broadcast: that
would split the honest participants' views.

---

## 5. Round rules

Rounds close by deadline (ADR-0053 D3). The **delivered set** of round `r` is every
authenticated, well-formed message **of round `r`** that arrived while round `r` was open: after
round `r − 1` closed (for round 1, once the session started) and before round `r` closed. A
message that is late, early or malformed counts as **absent**. An early message, sent while an
earlier round was open, is dropped and not carried forward into its own round; honest
participants send round `r`'s messages only while round `r` is open. Every rule below is a deterministic function of the delivered broadcast sets, so all
honest participants, and anyone recomputing a transcript, take the same decisions.

**R1.** Dealer `i` is **disqualified** if its `COMMITMENTS` is absent or in conflict.

**R2.** `Complaints(i)` is the set of senders with a `COMPLAINT` whose subject is `i`.

**R3.** Dealer `i` is **disqualified** if any of these holds:
- `|Complaints(i)| > t`;
- for some `j ∈ Complaints(i)`, the `ANSWER` from `i` with subject `j` is absent, in conflict, or
  fails (4) for `(i, j)`.

An `ANSWER` without a matching complaint has no effect.

**QUAL** is `{1 … n}` minus every dealer disqualified in R1 or R3, fixed when R3 closes.

**R4.** Dealer `i ∈ QUAL` is **marked** for reconstruction if its `EXTRACTION` is absent or in
conflict.

**R5.** An `EXTRACTION_COMPLAINT` from `j` with subject `i ∈ QUAL` is **valid** if dealer `i` has
a well-formed, non-conflicting `EXTRACTION` and the pair:
- satisfies (4) for `(i, j)`;
- fails (5) for `(i, j)`.

Each valid complaint marks `i`. Invalid complaints have no effect.

Every delivered `EXTRACTION_COMPLAINT` is evaluated on its own, **including messages in
conflict**. A valid complaint is evidence against the dealer whoever sent it.

**R6, reconstruction.** For each marked dealer `i`, the **valid pairs** are the `RECONSTRUCTION`
messages with subject `i` that are not in conflict and whose pair satisfies (4) for
`(i, sender)`.
- Take the `t + 1` valid pairs with the lowest senders. Interpolate the coefficients of `f_i` and
  `f'_i` (degree at most `t`) by Lagrange interpolation mod `l`.
- Then check two things:
  - every other valid pair lies on the interpolated polynomials;
  - `[a_ik]·G + [b_ik]·H = C_ik` for every `k`. This is implied by (4) on the chosen pairs
    (interpolation is linear) and is kept as a defensive check.
- Set `A_ik = [a_ik]·G`. The dealer's contribution is **kept** ([GJKR07] §4.2).

**Outputs.**

```
y   = Σ_{i ∈ QUAL} A_i0
Y_j = Σ_{i ∈ QUAL} Σ_{k=0..t} [j^k mod l]·A_ik        for every j = 1 … n
```

Here `A_ik` is the published `EXTRACTION` value, or the reconstructed one for a marked dealer.
`Y_j` is participant `j`'s **verification key**: it may be `O`, and two participants may have
equal `Y_j`.

**Private outputs of participant `j`.** The secret share is `x_j = Σ_{i ∈ QUAL} s_ij mod l`. This
includes `j`'s own `s_jj` when `j ∈ QUAL`. For `i ≠ j`, `s_ij` is the pair received privately
when it satisfied (4), or else the pair from `i`'s `ANSWER` to `j`'s complaint. The participant also emits these messages:
- **R2:** a `COMPLAINT` against every dealer whose `SHARE` was absent, in conflict, or failed
  (4). There is no complaint against a dealer whose `COMMITMENTS` is absent or in conflict: R1
  already disqualifies it.
- **R5:** an `EXTRACTION_COMPLAINT` against every dealer in `QUAL` whose `EXTRACTION` fails (5)
  for its pair;
- **R6:** a `RECONSTRUCTION` for every marked dealer `i ≠ j`.

**R7, confirmation.** Every member of `QUAL` broadcasts `CONFIRMATION(digest, y)` (§7).

### 5.1 Aborts

A participant aborts with **"fault assumption violated"**, and never silently excludes a dealer
or restarts within the session, when any of these holds:

| # | Condition | Why it cannot happen under the assumptions |
|---|---|---|
| A1 | `|QUAL| < n − t` | Honest dealers are never disqualified, and at least `n − t` participants are honest. |
| A2 | The participant's own dealing is disqualified (participant check) | It answered every complaint correctly. |
| A3 | A marked dealer has fewer than `t + 1` valid pairs | At least `t + 1` honest participants hold valid pairs. |
| A4 | Valid pairs do not lie on one polynomial pair, or the interpolation does not match `C_ik` | Equation (4) binds pairs unless `log_G H` is known. |
| A5 | `y = O` | Probability about `2⁻²⁵²`. |
| A6 | `[x_j]·G ≠ Y_j` (participant check) | It follows from (4), (5) and reconstruction. |
| A7 | At least `t + 1` distinct members of `QUAL` sent authenticated `CONFIRMATION`s whose digest or `y` differ from the participant's own (an equivocator counts as differing), **or** fewer than `t + 1` distinct members sent one equal to it (counting the participant's own confirmation only if it was delivered back to it, like any other) | At most `t` participants are faulty, so `t + 1` differing confirmations include an honest participant who saw a different board. Fewer than `t + 1` matching means the honest participants did not confirm this view. Up to `t` lies are ignored. |
| A8 | The participant's own dealing is marked for reconstruction (participant check) | It broadcast a correct `EXTRACTION` in time, and no valid complaint exists against a correct vector. |
| A9 | The participant's own `COMPLAINT` is missing from its delivered round-2 set (participant check) | Its own broadcasts are delivered, to itself as to everyone. |

**When each check runs.** Checks run as rounds close, and a participant that aborts sends
nothing afterwards:

| Round closing | Checks |
|---|---|
| R2 | A9 |
| R3 | A1, A2 |
| R5 | A8, before any `RECONSTRUCTION` is sent |
| R6 | A3, A4, A5, A6 |
| R7 | A7 (an equivocating member, with two different confirmations, counts as differing) |

A8 matters outside the synchronous model of [GJKR07]. If an honest dealer's `EXTRACTION` is
merely late, R4 marks it, and without A8, R6 would publish its polynomial and reveal `z_i`.
- **Every honest dealer late:** A8 makes them all fall silent before R6, so nothing is
  published. The faulty participants alone hold at most `t` pairs per dealer, and the run ends
  in A3.
- **Some honest dealers late:** an unmarked honest contribution keeps `x` secret.

Either way, a marked honest dealer does not confirm. A8 trades liveness for secrecy: each late
honest dealer is one fewer confirmation towards the `t + 1` that admission needs. A8 covers
**late extraction vectors only**. A late private `SHARE` is not covered (§5.2).

A participant that aborts with A9 at R2 stays in `QUAL` if nobody complained against it, and
falls silent. Its `EXTRACTION` is then absent, so the others reconstruct its polynomial in R6,
which makes its `z_j` public. As in A8's partial case, the key stays secret as long as one
honest contribution remains unpublished.

### 5.2 Timely delivery is a secrecy precondition

[GJKR07] assumes synchronous, reliable private channels and broadcast. Missing a deadline is not
only a liveness failure:
- **A late private `SHARE` between honest participants.** The recipient complains, and the
  honest dealer must answer by broadcasting that pair. The `t` faulty participants already hold
  `t` points of the dealer's polynomials, so this public pair is the `(t + 1)`-th and determines
  `f_i` and `z_i`.
  - If that happens to every honest dealer, the key is revealed, and no abort fires.
  - A rushing adversary that sees these answers before deciding its own dealers' behaviour also
    regains the bias of [GJKR07] §3.
- **A late `EXTRACTION`.** It is handled by A8 (§5.1).

The library cannot tell a late honest share from a withheld one. The application's transport
must therefore deliver private `SHARE`s between honest participants before the round-1
deadline, with deadlines chosen accordingly. How an honest dealer should respond to a complaint
it believes is caused by late delivery is an open maintainer question (ADR-0053 Q7). This
profile does not change Fig. 2's rule.

A4 cannot be triggered without knowing `log_G H`. Pairs that pass (4) but disagree with the
polynomial require that discrete logarithm. So A4 is a defensive check, and the independent
reference exercises it only with a test-only trapdoor base.

A new attempt needs a new session (§2).

---

## 6. Transcript

The **transcript** is the configuration plus the delivered broadcast sets of rounds 1–6. It
excludes `SHARE` messages, which are private, and the R7 confirmations. Its canonical encoding:

```
transcript = DST_T ‖ session ‖ u8(t) ‖ u8(n)
             ‖ for r = 1 … 6:  u32(count_r) ‖ for each message m of round r, in order:
                                   u16(len(m)) ‖ m
DST_T = UTF-8("zeroj.elgamal-jubjub-threshold.v1.transcript")
```

Within a round, messages are ordered by `(kind, sender, subject)` and then by their bytes in
unsigned lexicographic order. Byte-identical duplicates appear once. Conflicting messages both
appear: they are the evidence. The order does not depend on arrival order.

`digest = BLAKE2b-256(transcript)`.

Every well-formed delivered broadcast is part of the transcript, including messages that have
no effect on the outputs (for example an `ANSWER` nobody asked for). A round with no messages
contributes `u32(0)`.

Recomputing the outputs of §5 from a transcript is pure algebra. It is **not** evidence that the
run happened (§8).

---

## 7. Confirmation

`CONFIRMATION` carries `digest ‖ encode(y)` for the participant's own view of the run. A
participant sends it only if it did not abort.

---

## 8. Admission (ADR-0053 D4a)

A threshold key context is created only in two ways:
- **by admission**, as specified below;
- **by a participant from its own run**, whose authenticated rounds it observed directly.

Admission takes the following inputs:
- the configuration `(t, n, roster, ctx, attempt)`, from a trusted source;
- the transcript's messages, each with an **authenticator**;
- **round-closure evidence** for rounds 1–7. Round 7 is the set of confirmations, so a submitter
  cannot leave out differing ones;
- `CONFIRMATION` messages, each with an authenticator.

The library performs these steps:

1. Validates the parameters (§1) and derives `session` (§2).
2. Decodes every transcript message and requires it to be well-formed for this session (§4).
   Every transcript message must be a broadcast message of rounds 1–6: a well-formed `SHARE` or
   `CONFIRMATION` among them is **refused**, like a malformed one. The submitter builds the
   transcript from the delivered sets, which never contain either kind, so a misplaced message
   is a submitter error, not board noise. Confirmations are submitted separately (step 6).
   Byte-identical duplicates among the submitted messages count once, as on the board (§6);
   they are not refused.
3. Asks the application verifier, for every transcript message,
   `authenticate(sender, key_sender, message bytes, authenticator)`, and refuses on any `false`.
4. Asks, for each round `r = 1 … 6`,
   `roundClosed(config, r, the round's canonical message list, evidence_r)`, and refuses on any
   `false`. This is how omitted or truncated rounds are refused.
   - The application compares the list with the round's **delivered set** (§5): the board's
     posts made while round `r` was open, after dropping anything malformed, for another session
     or round, a `SHARE`, or failing authentication, with byte-identical duplicates once, in §6
     order. A post made during an earlier round's window is not part of round `r`'s board.
   - Computing it this way means a faulty participant's junk posts cannot veto admission. The
     library provides this computation (`DkgTranscript.deliveredRound`).
5. Recomputes `QUAL`, the marks, `y` and every `Y_j` (§5), and refuses on A1, A3, A4 or A5.
6. Builds the expected bytes `CONFIRMATION(digest, y)` for each member of `QUAL`, and counts:
   - **matching:** distinct senders in `QUAL` whose submitted confirmation equals those bytes and
     authenticates;
   - **differing:** distinct senders in `QUAL` whose authenticated, well-formed confirmation for
     this session carries another digest or `y`.

   A sender that equivocated, sending two different confirmations, counts as **differing** and
   not as matching. The library also asks
   `roundClosed(config, 7, the canonical list of submitted well-formed CONFIRMATIONs for this session, evidence_7)`.
   That list contains every authenticated such confirmation from any sender, members of `QUAL`
   or not. It is
   ordered by the rule of §6: by `(kind, sender, subject)` and then by bytes, with
   byte-identical duplicates once.

   It refuses unless matching ≥ `t + 1` and differing ≤ `t`. Differing ≥ `t + 1` means an honest
   participant confirmed another record, the condition of abort A7. Up to `t` differing
   confirmations may be lies by faulty participants, and they do not veto the run. Anything that
   is malformed, for another session, not a `CONFIRMATION`, unauthenticated or from outside
   `QUAL` is ignored.

With at most `t` faulty participants, step 6 guarantees that an honest participant vouched for
exactly this record.

The honest-majority and transport assumptions stay **assumptions**. The application's verifier
is responsible for authenticity and round closure. Signatures under keys outside the roster, or
the inclusion of selected messages alone, do not discharge that responsibility.

---

## 9. Threshold context and decryption (ADR-0053 D5, D5a)

**Context.** A threshold key context consists of:
- the configuration and `session`;
- `QUAL`;
- the joint key `y ≠ O`;
- the verification keys `Y_1 … Y_n`.

Two contexts are equal iff their sessions, `QUAL`, `y` and `Y_j` are equal. Contexts from
different attempts are therefore never equal. Encryption and admission of ciphertexts are those
of [`elgamal-jubjub-v1.md`](elgamal-jubjub-v1.md) §4 and §10.1, under the key `y`.

**Shares.** A decryption share of participant `j ∈ QUAL` for an admitted ciphertext `(A, B)` is
`D_j = [x_j]·A`. It is verified by the DLEQ statement `(X = A, P = Y_j, D = D_j)` of
[`elgamal-jubjub-v1.md`](elgamal-jubjub-v1.md) §9.2. `P` and `D` may be `O`. Shares are keyed by
identifier, never by point value.
- A participant's secret is valid for its share only if `[x_j]·G = Y_j`.
- Only members of `QUAL` contribute decryption shares (ADR-0053 D5). A participant outside
  `QUAL` was disqualified as a dealer, so it is faulty under the assumptions. At least `t + 1`
  members of `QUAL` are honest, so this costs no liveness.
- Single-key decryption is **not defined**: no full secret exists.

**Combine.** Given verified shares from distinct `j ∈ QUAL`, with at least `t + 1` of them:

```
S   = the t + 1 smallest identifiers among the shares
λ_j = Π_{m ∈ S, m ≠ j}  m · (m − j)⁻¹          (mod l)
M   = B − Σ_{j ∈ S} [λ_j]·D_j
```

For every extra share `e ∉ S`, the combiner checks
`D_e = Σ_{j ∈ S} [L_{j,S}(e)]·D_j`, where `L_{j,S}(e) = Π_{m ∈ S, m ≠ j} (e − m)·(j − m)⁻¹`. A
mismatch is an error. With verified shares it cannot happen, so this is a defensive check that
every subset gives the same result. The plaintext is then recovered as in
[`elgamal-jubjub-v1.md`](elgamal-jubjub-v1.md) §6.3.

`Σ_{j ∈ S} λ_j·x_j = x mod l` for every `(t + 1)`-subset `S`.

---

## 10. Secret handling

The following are secret and **compatibility/offline class** (ADR-0039 §3.1), with no
constant-time claim:
- the coefficients `a_ik` and `b_ik`, and the commitments and extraction values computed from
  them;
- the received pairs and the left-hand sides of (4) and (5) on them;
- `x_j`;
- the check `[x_j]·G = Y_j`;
- decryption shares;
- the plaintext search.

Everything computed from broadcast data is public: the right-hand sides of (4) and (5),
published pairs (R3, R5, R6), `QUAL`, `y`, `Y_j` and the combination.

---

## 11. Test vectors

Test scalars are
`scalar(tag) = OS2IP(SHA-256(UTF-8("zeroj.elgamal.threshold.v1.test." + tag))) mod l`. Numbers
in tags are decimal and unpadded. The coefficients of dealer `i` are `a_ik = scalar("a." + i + "." + k)`
and `b_ik = scalar("b." + i + "." + k)`, unless a fixture overrides them.

| Fixture | Content |
|---|---|
| `session` | `ctx = UTF-8("zeroj.test.election")`, `attempt = 1`, `t = 1`, `n = 3`, `key_j` = 32 bytes each equal to `j` |
| `honest-2of3`, `honest-3of5`, `honest-4of7` | `ctx = UTF-8("zeroj.test.honest")`, `attempt = 1`, roster as above (`key_j` = 32 bytes each equal to `j`, for `j = 1 … n`). Contents: every commitment, extraction value, share, `x_j`, `y` and `Y_j`; the transcript digest (rounds 2, 3, 5 and 6 are empty, since no complaints occur); the Lagrange coefficients of every `(t + 1)`-subset; and the threshold decryption of `Enc(5; scalar("enc.k"), y)` at width 3 for every subset. |
| `zero-share` (2-of-3) | `ctx = UTF-8("zeroj.test.zero-share")`, `attempt = 1`. `a_i0 = 1` for all `i`; slopes `a_11 = 1`, `a_21 = 2`, `a_31 = l − 6`; `b_ik` from the tags. Then `F(z) = 3 − 3z`, `x_1 = 0` and `Y_1 = O`. Every pair of participants decrypts `Enc(1; scalar("enc.k"), y)` at width 1. |
| `equal-shares` (2-of-3) | `ctx = UTF-8("zeroj.test.equal-shares")`, `attempt = 1`. `a_i0 = 1`; slopes `1`, `2`, `l − 3`. Then `F(z) = 3` and `Y_1 = Y_2 = Y_3 = [3]·G`. Every pair decrypts as above. |
| `adversarial-4of7` | The script below. |

The `adversarial-4of7` fixture: `t = 3`, `n = 7`, `ctx = UTF-8("zeroj.test.adversarial")`,
`attempt = 7`, roster as above, coefficients from the tags.
- Exactly three participants deviate (`= t`): dealers 1, 3 and 5. Apart from the deviations
  listed below, **every participant follows §5**.
- A participant that aborts (§5.1) sends nothing afterwards.

1. **R1.** Every dealer broadcasts `COMMITMENTS` and sends every `SHARE`, with two exceptions:
   - dealer 1 sends participant 2 the pair `(s_12 + 1 mod l, s'_12)`;
   - dealer 3 sends participant 4 the pair `(s_34 + 1 mod l, s'_34)`.
2. **R2.** Following §5, participant 2 complains against dealer 1 and participant 4 complains
   against dealer 3.
3. **R3.** Dealer 1 answers participant 2 with the correct pair. Dealer 3 does not answer, so it
   is disqualified: `QUAL = {1, 2, 4, 5, 6, 7}`. Participant 3 aborts with A2.
4. **R4.**
   - Dealer 1 withholds its `EXTRACTION`. It is not delivered to anyone, dealer 1 included.
   - Dealer 5 broadcasts `EXTRACTION` with `A_51` replaced by `A_51 + G`.
   - The other members of `QUAL` broadcast correct vectors.
5. **R5.** Following §5, participants 1, 2, 4, 6 and 7 complain against dealer 5: the forged
   vector fails (5) for each of them. Dealers 1 and 5 are marked, and both abort with A8 when
   R5 closes.
6. **R6.** Following §5, participants 2, 4, 6 and 7 broadcast `RECONSTRUCTION` for dealers 1 and
   5: 8 messages, `t + 1 = 4` per dealer.
7. **Outputs.**
   - `y = Σ_{i ∈ {1,2,4,5,6,7}} [a_i0]·G`: the marked dealers keep their contributions.
   - Every `Y_j` equals the value computed from the true `A_ik`.
   - Participants 2, 4, 6 and 7 confirm.
   - The fixture includes the bytes of every broadcast message, the two bad `SHARE` messages,
     the transcript digest, the four `CONFIRMATION`s, the outputs, and the message counts per
     round: 7 / 2 / 1 / 5 / 5 / 8.

| Case | Value |
|---|---|
| `session` fixture: session id | `27ee85d2f50e766a65a3bd49b4dd532f7ad7967bde49c912b2e6b6b5c932af0c` |
| `honest-2of3`: session | `a86eca15ae74ef0f48adbf82186ad6eee552c578c3ffa1dcd3f6a0f0ed73ea03` |
| `honest-2of3`: `encode(y)` | `14acdc488055720e853cbb6b613d2c7f52aee2fa8e7f37b410b1fa9093082658` |
| `honest-2of3`: transcript digest | `2af7f7eae154833d51861bae276448b396eae5479a074a833a31a9fb9aa46023` |
| `honest-3of5`: `encode(y)` | `89eeef65017eb8f1a18e38a5b9fc0efb971386181e0db4649c60941cd5a6c425` |
| `honest-4of7`: transcript digest | `9b6a52fe5b0fb06feb875b82cb37871e64bc235b01de384ba54a06f96c24431b` |
| `zero-share`: `encode(Y_1)` (the identity) | `0100000000000000000000000000000000000000000000000000000000000000` |
| `zero-share`: transcript digest | `8864e81db8467449ab695f59e82ca31608edf753370c46b912b2b936e43fd43d` |
| `equal-shares`: `encode(Y_1) = encode(Y_2) = encode(Y_3)` | `c5295dd1cb37a4ae58005ac7019c958df01d0e5256e17e81ba9d94a2db339cc7` |
| `adversarial-4of7`: `QUAL`, marked | `1, 2, 4, 5, 6, 7; marked 1, 5` |
| `adversarial-4of7`: message counts R1–R6 | `7 / 2 / 1 / 5 / 5 / 8` |
| `adversarial-4of7`: `encode(y)` | `0b881774fb4c7fd67485a8c737cb78d787a46c87c7d2d6af3b588b4409ceec54` |
| `adversarial-4of7`: transcript digest | `92ddd0e587537bec6cfcffdc0d4d90d8fa4145bdfa5200107f6c3766caa134a0` |

An independent reproduction of §1–§9 and of these vectors, written from this document, the
[GJKR07] Fig. 2 text and the Jubjub definition, is at
`zeroj-circuit-lib/src/test/resources/elgamal-threshold-reference/`. Its pinned output is
checked against the library at every build.

---

## 12. Non-goals

- How private channels are built (ADR-0053 Q1, escalated; #77).
- Adaptive adversaries; changing the trustee set (resharing or proactive refresh);
  asynchronous key generation.
- Verifying a key generation on-chain.
- A trusted dealer. It exists only as a test fixture (ADR-0053 Q3).
- Thresholds with `t ≥ n/2` (ADR-0053 Q2).

## 13. References

- **[GJKR07]** R. Gennaro, S. Jarecki, H. Krawczyk, T. Rabin, *Secure Distributed Key Generation
  for Discrete-Log Based Cryptosystems*, J. Cryptology 20:51–83 (2007): §2.1 (model), Fig. 2
  (New-DKG), §4.2 (keeping a misbehaving dealer's contribution), Theorem 1.
- **[CGS97]** §2.3 (threshold decryption with Lagrange coefficients).
- **[RFC 7693]** The BLAKE2 Cryptographic Hash and Message Authentication Code.
- [`elgamal-jubjub-v1.md`](elgamal-jubjub-v1.md), [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md);
  ADR-0052, ADR-0053.

[RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693
