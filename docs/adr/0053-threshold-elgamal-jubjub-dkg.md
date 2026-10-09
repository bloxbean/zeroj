# ADR-0053: Threshold key generation and decryption for `elgamal-jubjub-v1` (t-of-n)

## Status
Accepted (design) — 2026-10-05.
- The reviewer approved r2 at `e3fbb4e` with no outstanding findings, and the maintainer
  accepted the design.
- Acceptance is design acceptance only. It certifies no implementation, test or security
  property.
- Implementation of M0–M4 is in progress on PR #76, one reviewed step at a time. The
  "Implementation status" section at the end tracks it.
- Q2–Q6 were decided by the maintainer on 2026-10-05: each recorded lean is adopted. Q1 (the
  private channels) stays escalated and does not block the library, whose transport is
  pluggable (#77).
- **2026-10-09:** Q1 is answered by ADR-0054 (Accepted), which provides an optional ZeroJ
  transport for the private shares: HPKE-encrypted envelopes on the board. Q7 is resolved for
  deployments that use that transport and meet its delivery contract (ADR-0054 Q6). Neither
  changes this ADR's protocol, encodings or admission.

This ADR builds on ADR-0052 (Accepted). It changes no maturity claim. ADR-0039's assurance
classes apply: every secret-bearing operation here is **compatibility/offline** class.

## Date
2026-10-05

## Revision history
- **r1** (`7f7a0d8`) — initial proposal.
- **r2** (2026-10-05; responds to the review of `7f7a0d8`):
  - F5 → new D1a (round-by-round transitions, omissions, retention of contributions, abort
    semantics); I3 and I5 rewritten; new I13; M2 omission tests.
  - F6 → new D4a (admitting a run, kept separate from recomputing it from the transcript):
    roster, configuration, per-attempt session, authenticated messages, round closure, and
    confirmations from at least `t + 1` trustees. I7 rewritten; new I14 and I16; new Q6;
    rejection tests.
  - F7 → new D5a (threshold-context and share rules, keyed by identifier). ADR-0052's n-of-n
    share invariants are scoped to n-of-n contexts. Zero and equal shares are supported.
    New I15; the fixtures go into M1–M3.
  - F8 → Verification uses admitted parameter sets and an independent fixture oracle.
- **Accepted** (2026-10-05): approved at r2 (`e3fbb4e`); status flipped without changing the
  design text.
- **Decisions recorded** (2026-10-05): the maintainer adopted the leans of Q2–Q6. Q1 stays
  escalated. No design text changes.

## Risk classification
- **R3:** D1 (the distributed key generation protocol), D2 (the adversary and threshold model)
  and D5 (threshold decryption and its combination rule). These decide who can learn the key
  and whether a tally is correct.
- **R2:** D3 (transport requirements), D4 (library structure and transcript recomputation),
  D4a (admitting a run), D5a (threshold contexts and share rules), D6 (session binding and
  encodings) and D7 (maturity and assurance labelling).
- D1a (round transitions, omissions and aborts) is R3, as part of D1.

## Context

ADR-0052 shares the election key **n-of-n**: every trustee must take part to decrypt. That
gives the strongest privacy (all n must collude to open one ballot) and the weakest liveness:
one lost, offline or uncooperative trustee blocks the result forever.

Real deployments usually want a **threshold**: any `t + 1` of `n` trustees can decrypt, and up
to `t` can be lost or malicious. This is how [CGS97] §2.3 sets up its election.
- The key is generated jointly with Pedersen's protocol [Ped91].
- It is shared Shamir-style, so "the secret `s` can be reconstructed from any set `Λ` of `t`
  shares using appropriate Lagrange coefficients". [CGS97] counts that set as `t`; this ADR uses
  GJKR's `t + 1` (see Notation).
- Decryption raises each authority's published value to its Lagrange coefficient,
  `m = y / ∏_{j∈Λ} w_j^{λ_{j,Λ}}`.

The ballot is unchanged: voters still encrypt to one public key `y`. Only key generation and
the combination of decryption shares change.

The hard part is **key generation without a dealer**. A dealer who generates and splits the
key knows it, and so can decrypt everything. The trustees must instead run a distributed key
generation (DKG) protocol, so that no party ever holds the key. [GJKR07] shows two things:
- The widely used joint-Feldman protocol of [Ped91] (JF-DKG) lets an active attacker **bias
  the generated key**.
- Their **New-DKG** protocol fixes this, and is proved secure for any `t < n/2`.

## Threat model and trust assumptions

All of this follows [GJKR07] §2.1.

- **Parties:** `n` trustees `P_1 … P_n`, identified by the scalars `1 … n`.
- **Adversary:** static. It corrupts up to `t` trustees at the start, with `t < n/2`, and the
  corrupted trustees may deviate arbitrarily. It is **rushing**: in every round it sees the
  honest messages before sending its own. Adaptive corruption is out of scope (see D8).
- **Communication:**
  - every pair of trustees has a private, authenticated channel;
  - all trustees share a broadcast channel;
  - rounds are synchronized, with known delivery bounds (partial synchrony).

  The application provides all of these (D3).
- **Untrusted:**
  - every message from another trustee;
  - every claimed share, commitment, complaint and complaint answer;
  - claimed decryption shares;
  - every claimed transcript. A transcript is untrusted until it is admitted with authenticated
    evidence (D4a). Algebraic consistency alone proves nothing about a run: a single party can
    write a perfectly consistent record whose key it knows.
- **Secret:** each trustee's polynomial coefficients and the shares it receives, and its final
  share `x_j`. Host arithmetic on these is variable-time `BigInteger` Java, which is the
  compatibility/offline class (ADR-0039 §3.1). Each trustee runs on its own isolated host.
- **Guarantees, under the discrete-log assumption ([GJKR07] Theorem 1 and §4.1):**
  - **(C1, C1′)** any `t + 1` correct shares define the same key `x`, and it can be
    reconstructed even if up to `t` shares are faulty;
  - **(C2)** all honest trustees output the same public key `y = [x]·G`;
  - **(C3)** `x` is uniformly distributed;
  - **secrecy:** the adversary learns nothing about `x` beyond `y`.
- **Privacy of ciphertexts** (with ADR-0052):
  - at most `t` colluding trustees learn nothing about any plaintext;
  - **`t + 1` colluding trustees can decrypt any single ciphertext**.

  This is the price of liveness, and applications choose `t` with it in mind.
- **Out of scope:**
  - application authorization;
  - when to decrypt (ADR-0052's "decrypt once" rule still applies);
  - how the transport is realized (D3).

## Pinned normative references

- **[GJKR07]** R. Gennaro, S. Jarecki, H. Krawczyk, T. Rabin, *Secure Distributed Key Generation
  for Discrete-Log Based Cryptosystems*, J. Cryptology 20:51–83 (2007), DOI
  10.1007/s00145-006-0347-3. The full text was fetched 2026-10-05.
  - **§2.1:** the communication and adversary model: private and broadcast channels, partial
    synchrony, a rushing adversary, "up to t of the n parties … for any value of t < n/2".
  - **§2.2:** Shamir sharing, Feldman-VSS (equation 1) and Pedersen-VSS (equation 2). Pedersen
    VSS assumes "the adversary cannot compute `log_g h`".
  - **§3:** the bias attack on JF-DKG.
  - **§4.1:** the requirements (C1), (C1′), (C2), (C3) and secrecy.
  - **§4.3, Fig. 2:** **Protocol New-DKG**, Steps 1–4, quoted in D1. **Theorem 1:** "Under the
    Discrete-Log Assumption, Protocol New-DKG from Fig. 2 is a secure protocol for distributed
    key generation … for any t < n/2".
  - **§4.4:** "The crucial property for h is that the adversary should not know `log_g h`."
    There is "no requirement for h to be chosen with uniform probability".
  - **§5:** JF-DKG is shown adequate only for "threshold variants of other cryptosystems which
    enjoy a proof of security solely based on the hardness of the discrete-logarithm problem"
    (Schnorr signatures).
  - **Appendix:** JF-DKG variants with signatures, initial commitments or committing encryption
    remain insecure.
- **[CGS97]** Cramer, Gennaro, Schoenmakers, EUROCRYPT '97, §2.3 (already pinned by ADR-0052).
  It gives Shamir `(t, n)` sharing via [Ped91] key generation, and threshold decryption with
  Lagrange coefficients over any qualified set.
- **[Ped91]** T. P. Pedersen, *A threshold cryptosystem without a trusted party*, EUROCRYPT '91,
  LNCS 547, pp. 522–526. Bibliographic entry as cited in [CGS97] and [GJKR07]; not fetched
  (**unverified** directly). This is the JF-DKG origin.
- **ZeroJ:**
  - `docs/specs/pedersen-jubjub-v1.md` §2.1 (value base `G`) and §2.3 (blinding base `H`, a
    nothing-up-my-sleeve derivation);
  - ADR-0051 (the Pedersen profiles);
  - ADR-0052 (`elgamal-jubjub-v1`: D2b verified decryption shares, D5 key context);
  - ADR-0039 (assurance classes).

## Notation

- `𝔾`, `l`, `G` as in ADR-0052.
- `H` is the `pedersen-jubjub-v1` blinding base.
- Scalars live in `ℤ_l`. Trustee identifiers are the scalars `1 … n`.
- **`t` is the maximum number of corrupted trustees**, as in [GJKR07]. Decryption needs `t + 1`
  shares. A "k-of-n" scheme in everyday terms has `k = t + 1`.

## Decision

### D1 — Protocol: New-DKG of [GJKR07] over Jubjub (R3)

Instantiate [GJKR07] Fig. 2 with these groups and bases:

| GJKR07 | ADR-0053 |
|---|---|
| `G` (subgroup of `ℤ_p*`), order `q` | `𝔾`, the Jubjub prime-order subgroup, order `l` |
| generator `g` | `G` (pedersen-jubjub-v1 §2.1) |
| `h` with unknown `log_g h` | `H` (pedersen-jubjub-v1 §2.3, nothing-up-my-sleeve) |
| `g^a h^b mod p` | `[a]·G + [b]·H` |

The protocol, as in Fig. 2, written additively:

1. **Pedersen-VSS of a random `z_i`.** Each `P_i`:
   - chooses random degree-`t` polynomials `f_i(z) = a_i0 + … + a_it·z^t` and
     `f'_i(z) = b_i0 + … + b_it·z^t`, with `z_i = a_i0`;
   - broadcasts `C_ik = [a_ik]·G + [b_ik]·H` for `k = 0 … t`;
   - privately sends `P_j` the pair `s_ij = f_i(j)`, `s'_ij = f'_i(j)`.

   Each `P_j` checks equation (4), `[s_ij]·G + [s'_ij]·H = Σ_k [j^k]·C_ik`, and broadcasts a
   **complaint** against `P_i` if it fails. A dealer who receives a complaint broadcasts the
   pair for the complainer. A dealer is **disqualified** if it received more than `t`
   complaints, left one unanswered, or answered one with a pair that fails (4). D1a gives the
   complete round-by-round rules.
2. **`QUAL`** is the set of non-disqualified trustees. It is a function of the broadcast
   transcript only.
3. Each `P_j` sets `x_j = Σ_{i∈QUAL} s_ij` and `x'_j = Σ_{i∈QUAL} s'_ij`. The key
   `x = Σ_{i∈QUAL} z_i` is never computed.
4. **Extraction (Feldman-VSS).** Each `P_i ∈ QUAL` broadcasts `A_ik = [a_ik]·G`. Each `P_j`
   checks equation (5), `[s_ij]·G = Σ_k [j^k]·A_ik`.
   - On failure, `P_j` broadcasts the pair `(s_ij, s'_ij)`. That pair satisfies (4) but not
     (5), which makes it a **valid complaint**.
   - For every `P_i` with a valid complaint, or with a missing or malformed extraction vector
     (D1a), the others run Pedersen-VSS reconstruction. They publish shares that satisfy (4),
     and recover `z_i`, `f_i` and `A_ik` in the clear.
   - Finally `y = Σ_{i∈QUAL} A_i0`.

**Why New-DKG and not JF-DKG.** [GJKR07] §3 shows that JF-DKG lets the adversary bias `x`.
§5 shows JF-DKG is still adequate for schemes whose security reduces to the discrete-log
problem alone. ElGamal's IND-CPA security rests on **DDH**, which §5 does not cover.
`elgamal-jubjub-v1` therefore needs a DKG that meets (C3) and the secrecy requirement, which
Theorem 1 gives New-DKG.

### D1a — Round transitions, omissions and aborts (R3; responds to F5)

The protocol runs in fixed rounds, each closed by a deadline under the broadcast mechanism of D3.
A message that arrives after its round closes counts as **absent**. Every rule below depends
only on what the broadcast shows, so all honest trustees apply it identically.

| Round | Content | Failure, and what happens |
|---|---|---|
| R1 deal | Each dealer broadcasts `C_i` (exactly `t + 1` canonical subgroup points) and privately sends `(s_ij, s'_ij)`. | A missing, malformed or **conflicting** `C_i` (two different vectors from the same dealer) disqualifies the dealer. A missing pair, or one that fails (4), makes the recipient complain in R2. |
| R2 complaints | Each trustee broadcasts its complaints, at most one per dealer. | Repeated complaints from the same trustee against the same dealer count once. |
| R3 answers | For every complaint, the accused dealer broadcasts a pair that satisfies (4) for the complainer, and the complainer adopts it. | The dealer is **disqualified** if it received more than `t` complaints, left **any complaint unanswered** when R3 closed, gave any answer that fails (4), or gave conflicting answers. |
| QUAL | `QUAL` is the set of dealers not disqualified, fixed once R3 closes. | Under the assumptions, no honest dealer is ever disqualified: it answers every complaint correctly, and at most `t` complaints come from corrupt trustees. |
| R4 extract | Each dealer in `QUAL` broadcasts `A_i` (`t + 1` points). | A missing, malformed or conflicting `A_i` marks the dealer for **reconstruction**. |
| R5 complaints | Any trustee holding a pair that satisfies (4) but fails (5) broadcasts it. | Each such valid complaint marks the dealer for reconstruction. |
| R6 reconstruction | For every marked dealer, each trustee broadcasts its pair `(s_ij, s'_ij)`. Any `t + 1` pairs that satisfy (4) determine `f_i` and `f'_i`, and so `z_i` and `A_i`. | The dealer's contribution is **kept**. |

**After `QUAL` is fixed, no contribution is ever dropped.** A dealer who withholds or falsifies
its extraction vector is reconstructed instead. [GJKR07] §4.2: "if a party `P_i` misbehaves at
this point (for example by refusing to carry on the Feldman-VSS …), the honest parties can
recover the polynomial `f_i` … Pi's contribution to the secret key x will still be included (if
we did not include it, we would allow the adversary to bias the distribution of x)."

**Aborts.** Some situations cannot arise under the assumptions (more than `t` faults, or
broadcast without agreement):
- an honest trustee's own dealing is disqualified, as seen from its own view;
- fewer than `t + 1` valid pairs exist to reconstruct a marked dealer;
- the broadcast shows disagreement.

In any of these the participant **aborts**, with an explicit "fault assumption violated"
result. It never silently excludes a dealer or restarts within the same session. A new attempt
needs a new session (D4a).

### D2 — Threshold model and parameters (R3)

- `t ≥ 1` and `n ≥ 2t + 1`, that is `t < n/2`, as Theorem 1 requires.
- The decryption threshold is `t + 1`. Supported examples: 2-of-3, 3-of-5, 4-of-7.
- **Not supported:** a threshold above a majority, such as 4-of-5. Theorem 1 does not cover
  it: the protocol's disqualification and reconstruction rely on an honest majority (Q2).
- `n ≤ N_MAX` (lean 64, Q4).
- Identifiers are `1 … n` and are pairwise distinct. As scalars in `ℤ_l` they are non-zero,
  because `n < l`.
- If `y = O` the run aborts (probability negligible). ADR-0052 refuses an identity key. A new
  attempt needs a new session (D4a, I13).

### D3 — Transport: the application provides it, with stated requirements (R2)

ZeroJ provides the cryptography of each round. It does not provide the network. The
application must provide the [GJKR07] §2.1 model:

- **Broadcast with agreement.** Every honest trustee receives the same broadcast messages, in
  the same rounds. An append-only bulletin board works: for example a Cardano transaction or
  datum per message, or an authenticated off-chain board that all trustees read.
- **Private, authenticated point-to-point channels** for the `(s_ij, s'_ij)` pairs.
- **Rounds with deadlines.** A message that misses its round counts as absent. A share that is
  not delivered leads to a complaint. Because the answer then publishes that share, timely
  private delivery is a secrecy precondition (implementation note 4; spec §5.2; Q7). The mechanism must also give **evidence that each round
  is closed and complete**, for admission (D4a).

**How the private channels are built is not specified here** (Q1). Per the [GJKR07] appendix,
encrypting shares onto the broadcast channel does not make JF-DKG variants secure. Any
construction must deliver the private-channel model the proof assumes, and must be reviewed on
its own.

### D4 — Library structure (R2)

All of this lives in `zeroj-circuit-lib`, package `org.zeroj.circuit.lib.jubjub`. The names are
illustrative.

- **VSS primitives.**
  - `PedersenVss` and `FeldmanVss`: deal, check (equations 4 and 5), and reconstruct from at
    least `t + 1` checked shares.
  - `Lagrange` coefficients mod `l` for an exact set of identifiers.
- **`DkgParticipant`.** A deterministic, transport-agnostic state machine for one trustee.
  - It consumes the round's messages and produces that trustee's broadcast and private
    messages, following Fig. 2 exactly.
  - It holds its secrets only in memory, in the compatibility/offline class.
- **`DkgTranscript`.** The ordered public record of all broadcast messages, in rounds R1–R6
  (D1a).
- **`DkgTranscript.recompute()`.** Pure, deterministic algebra over a run's round contents. It
  yields `QUAL`, `y` and every verification key `Y_j = Σ_{i∈QUAL} Σ_k [j^k]·A_ik`. This is
  [GJKR07] (C1′): `g^{x_j}` "can be computed from publicly available information". The private
  messages are not needed for this. Recomputation is **not** evidence that the run happened
  (D4a).
- **`ThresholdKeyContext`.** Created only by admission (D4a). It contains the configuration,
  `QUAL`, `y` and `{j → Y_j}`. It is a distinct key-context type with its own share rules
  (D5a). Encryption and ciphertext admission work with it as ADR-0052 specifies.
- **Decryption shares.** These are ADR-0052's DLEQ statement and verified-share type,
  specialised to threshold contexts (D5a), with `P = Y_j` taken from the context by identifier.

### D4a — Admitting a DKG run (R2; responds to F6)

Recomputing a transcript and admitting a run are separate steps. A
`ThresholdKeyContext.admit(config, roundContents, evidence, verifier)` requires all of the
following:

1. **An immutable configuration:**
   - the profile id `elgamal-jubjub-threshold-v1`;
   - `t` and `n`;
   - a **roster** mapping each identifier `1 … n` to that trustee's authentication key;
   - a **session id** that is unique **per attempt**: for example
     `blake2b_256(application context ‖ attempt number ‖ roster ‖ t ‖ n)`. An election-id hash
     alone cannot tell retries apart, and the application must never reuse an attempt.
2. **Authenticated messages.** Every broadcast message and every complaint answer verifies
   under its sender's roster key, through the application-supplied verifier: for example
   Cardano transactions signed by trustee keys on an on-chain board. Every message is bound to
   the session, sender, round and target (D6).
3. **Round closure.** Evidence, under the agreed broadcast mechanism, that every round's
   contents are final and complete: nothing omitted or truncated. For an on-chain board, that
   means the chain's finality.
4. **Confirmations.** At least `t + 1` trustees in `QUAL` broadcast an authenticated
   confirmation of `(session, transcript digest, y)`. With at most `t` corrupt trustees, at
   least one honest trustee then vouches that this record is the run it took part in (Q6).

A participant may also create its context directly from its own run, since it saw the
authenticated rounds itself. The **honest-participation and transport assumptions stay
assumptions.** Admission checks the evidence those assumptions rely on; the public algebra does
not prove them.

### D5 — Threshold decryption (R3)

For an admitted ciphertext `(A, B)` under a `ThresholdKeyContext`:

1. Each participating trustee `j ∈ QUAL` publishes `D_j = [x_j]·A`, with a DLEQ proof. The
   statement is ADR-0052 D3's, with `X = A` and `P = Y_j`.
2. `decrypt(ciphertext, verifiedShares, maxPlaintext)` refuses unless the shares come from **at
   least `t + 1` distinct members of `QUAL`**, each verified for this exact ciphertext. It then
   takes any set `S` of exactly `t + 1` of them, ordered by identifier, and computes:
   ```
   λ_j = Π_{m∈S, m≠j} m / (m − j)   (mod l)
   M   = B − Σ_{j∈S} [λ_j]·D_j
   ```
   This is [CGS97] §2.3, written additively. The result is the bounded search of ADR-0052.
3. If more than `t + 1` verified shares are present, the result must be the same for every
   `(t + 1)`-subset that is checked. A mismatch is an error, not a choice. This cannot happen
   with verified shares, so it is a defensive check.
4. Malformed share sets are refused: duplicate identifiers, foreign identifiers, shares for
   another ciphertext, or fewer than `t + 1`.

### D5a — Threshold contexts and share rules (R2; responds to F7)

Shamir verification keys `Y_j = [x_j]·G` are values of one polynomial, not additive
contributions. In general their sum is not `y`, one of them can be the identity, and two
identifiers can share the same value. Both cases occur in valid runs:
- a 2-of-3 run with aggregate polynomial `F(z) = 3 − 3z` has `x_1 = 0`, so `Y_1 = O`;
- a run whose slopes cancel has `F(z) = 3`, so `Y_1 = Y_2 = Y_3 = [3]·G`.

In both, every 2-of-3 subset decrypts correctly. The rules are therefore:

- **Scope of ADR-0052's rules.** ADR-0052's I1 (non-identity, pairwise-distinct key shares), I2
  (proof-of-possession admission) and I14 (exactly one share per registered trustee) govern
  **n-of-n contexts only**. Threshold contexts follow this section.
- **Joint key.** The joint key `y` must not be the identity (ADR-0052's rule for the joint key
  is kept).
- **Verification keys.** Each `Y_j` may be any subgroup point, **including `O`**, and may equal
  another trustee's. Shares are keyed and deduplicated **by identifier**, never by point value.
- **Supported, not rejected.** A zero share gives `D_j = O`, and the DLEQ statement with
  `P = O` and `D = O` is valid. A verification key therefore enters the trustee relation as a
  DLEQ statement point (`P` in ADR-0052 D3's `assertDiscreteLogEquality`), never through a
  key-entry path that asserts non-identity, such as `fromVerifierFixedPublic` (ADR-0052 I8,
  which governs encryption keys). No run is rejected or retried because of these values, and no
  share is discarded. Both events have negligible probability in honest runs, but correctness
  does not depend on that.
- **Secrets and keys** (ADR-0052 I13, specialised):
  - `decryptionShare` requires `[x_j]·G = Y_j` for the trustee's own identifier;
  - `decryptWithSecret` is refused for threshold contexts, because no full secret exists.
- **Proof of possession.** None is used. The VSS checks and admission (D4a) take its place.

### D6 — Session binding and encodings (R2)

- **Session binding.** Every DKG message carries a 32-byte session identifier, together with
  the sender's identifier, the round, and the target identifier for private messages. The
  session is unique **per attempt** and commits to the configuration (D4a, Q5); an election id
  alone is not enough, because it cannot tell retries apart. Participants refuse messages for
  another session, round or target. This is engineering binding over the authenticated
  channels of D3. It does not change the cryptography.
- **Encodings.** Scalars are `I2OSP32` of a canonical value `< l`. Points are `repr_J` (ZIP 216,
  32 bytes). The canonical transcript encoding, with fixed message order and field order, is
  normative in the M0 spec. Decoding refuses non-canonical scalars and points, and points
  outside the subgroup.

### D7 — Maturity and assurance (R2)

- Experimental.
- All secret-bearing operations are compatibility/offline-class (ADR-0039 §3.1). These are
  dealing, holding shares, computing `x_j`, and computing decryption shares.
- No online or constant-time claim. Each trustee should run on its own isolated host.

### D8 — Out of scope

Each of these needs its own decision:
- **Adaptive adversaries.** [GJKR07] §4.4 points to a modified protocol for this (CGJ+).
- **Changing the trustee set:** proactive refresh, resharing, and adding or removing trustees.
  Changing the set means a new DKG and a new key.
- **Asynchronous DKG.**
- **Specifying the private channels** (Q1).
- **Verifying the DKG on-chain.**
- **A dealer-based key split,** except as a test fixture (Q3).

### Alternatives considered

| Alternative | Why not |
|---|---|
| **JF-DKG** [Ped91], or its variants with signatures, initial commitments or committing encryption | The key can be biased ([GJKR07] §3 and Appendix). It is shown adequate only for discrete-log-only schemes (§5), and ElGamal's IND-CPA rests on DDH. |
| **A trusted dealer** | The dealer knows the key and can decrypt every ballot, which defeats the purpose. At most a gated test fixture (Q3). |
| **Keeping n-of-n only** (ADR-0052) | Strongest privacy, no liveness. It stays available, and applications choose. |
| **Thresholds above a majority** | Not covered by the pinned theorem (Q2). |

## Security invariants

| ID | Invariant | Decisions |
|---|---|---|
| I1 | Parameters satisfy `1 ≤ t`, `2t + 1 ≤ n ≤ N_MAX`. Identifiers are `1 … n`, distinct and non-zero mod `l`. | D2 |
| I2 | The two bases are `G` and `H` from `pedersen-jubjub-v1`, so nobody knows `log_G H`. No other second base is accepted. | D1 |
| I3 | Share checks are exactly equations (4) and (5) of Fig. 2. A dealer is disqualified if and only if one of these holds: its commitment vector is missing, malformed or conflicting; it received more than `t` complaints; it left a complaint unanswered when R3 closed; or it answered with a pair that fails (4), or with conflicting pairs. | D1, D1a |
| I4 | `QUAL`, `y` and every `Y_j` are deterministic functions of the broadcast transcript alone. Every honest verifier of the same transcript computes the same values. | D1, D4 |
| I5 | After `QUAL` is fixed, a missing, malformed or conflicting extraction vector, or a valid phase-2 complaint (a pair that satisfies (4) and fails (5)), triggers reconstruction from at least `t + 1` pairs that satisfy (4). The dealer's contribution is **kept**, so the final key equals that of a run without withholding. | D1, D1a |
| I6 | `y = Σ_{i∈QUAL} A_i0`, with reconstructed values where needed. `y ≠ O`, otherwise the run aborts. | D1, D2 |
| I7 | A `ThresholdKeyContext` is constructible only by admission (D4a), or by a participant from its own run. Recomputation from a transcript alone never creates one. | D4, D4a |
| I8 | Threshold decryption uses at least `t + 1` verified shares from distinct `QUAL` members, each verified against `Y_j` and this exact ciphertext. Lagrange coefficients are computed for the exact subset used, and malformed share sets are refused. | D5 |
| I9 | When more than `t + 1` verified shares exist, every checked subset gives the same result, or decryption fails. | D5 |
| I10 | Every message is bound to its session, sender, round and (for private messages) target. Messages for anything else are refused. | D6 |
| I11 | Scalars and points are canonical on decode, and points are in the subgroup. The transcript encoding is canonical. | D6 |
| I12 | Secret-bearing operations are documented as compatibility/offline-class, with no online or constant-time claim. | D7 |
| I13 | A situation that cannot arise under the assumptions aborts with an explicit "fault assumption violated" result. Dealers are never silently excluded, and runs never restart within the same session. | D1a |
| I14 | Admission requires all of: the immutable configuration (profile, `t`, `n`, roster, session); authenticated messages bound to session, sender, round and target; evidence of round closure and completeness; and authenticated confirmations from at least `t + 1` trustees in `QUAL`. | D4a |
| I15 | In threshold contexts, shares are keyed by identifier; each `Y_j` may be any subgroup point, including `O`; the joint key `y ≠ O`; `decryptionShare` requires `[x_j]·G = Y_j` for its own identifier; `decryptWithSecret` is refused. A `Y_j` enters the trustee relation only as a DLEQ statement point. ADR-0052's I1, I2 and I14 apply to n-of-n contexts only. | D5a |
| I16 | The session id is unique per attempt, and messages or contexts from another attempt are refused. | D4a, D6 |

## Consequences

- Applications can choose liveness (t-of-n) or maximal privacy (n-of-n) with the same ballots
  and the same APIs for encryption and admission.
- Anyone holding the admission evidence can verify a key generation (D4a). Anyone can recompute
  every trustee's verification key from the transcript.
- Applications take on real protocol work: a broadcast board, private channels and round
  deadlines. The library cannot supply the network.
- The added cost is host-side only. Each trustee performs about `2(t + 1)` commitments when
  dealing, and checks `n − 1` shares of `t + 1` terms each. This is an estimate, to be measured
  at M2. Circuits are unchanged.

## Compatibility

- **New API only.** ADR-0052's ciphertexts, encodings and n-of-n contexts are unchanged. Its
  share invariants I1, I2 and I14 are scoped to n-of-n contexts (D5a). Threshold contexts are a
  separate type with their own rules.
- **Ballots are unchanged.** Ballots encrypted to a `y` from a DKG are ordinary
  `elgamal-jubjub-v1` ciphertexts.
- **The ballot circuit and its proofs are unaffected**, because the key enters the ballot
  relation as public inputs.
- **Moving an application from n-of-n to t-of-n needs a new key**, generated by the DKG, and so a
  new election. Existing ciphertexts stay under their original key.

## Implementation milestones

| Milestone | Scope | Entry gate | Exit criteria |
|---|---|---|---|
| M0 | Normative spec `docs/specs/elgamal-jubjub-threshold-v1.md`: parameters, message formats, transcript encoding, verification algorithm, threshold combine, and test vectors | ADR accepted | Spec reviewed. Its vectors come from an independent Python reference of Fig. 2, not from the Java code. |
| M1 | VSS primitives and Lagrange (D4) | M0 | Equations (4) and (5) and reconstruction match the spec vectors. Property tests: any `t + 1` shares reconstruct the same value, and `t` shares do not determine it (the simulation check of [GJKR07] §2.2, on small parameters). The F7 fixtures (`F(z) = 3 − 3z` and `F(z) = 3`) reconstruct correctly from every subset. |
| M2 | `DkgParticipant` and `DkgTranscript` (D1, D4, D6) | M1 | **Honest runs:** every `(t, n)` up to small bounds; all participants agree on `QUAL`, `y` and `Y_j` (I4). **Adversarial simulations**, one test each: <br>• a bad share; <br>• a false complaint; <br>• more than `t` complaints; <br>• a bad complaint answer; <br>• a phase-2 Feldman cheat, with reconstruction; <br>• a missing message; <br>• a message replayed from another session, round or target; <br>• a non-canonical or non-subgroup point; <br>• a rushing-order run. <br>**Omissions**, one test per round: <br>• a missing commitment vector; <br>• a single unanswered complaint (`n = 3`, `t = 1`), after which the dealer is disqualified; <br>• conflicting messages; <br>• a withheld extraction vector, after which the final key **equals the run without withholding**; <br>• too few reconstruction pairs, which aborts with "fault assumption violated". <br>**Admission (D4a)**, each rejected: <br>• a fabricated record without authentication; <br>• an omitted complaint or answer; <br>• a truncated round; <br>• a conflicting roster or configuration; <br>• a replay from another attempt; <br>• fewer than `t + 1` confirmations. |
| M3 | Threshold decryption (D5, D5a) on ADR-0052's safe API | M2 and ADR-0052 M1 | I8, I9 and I15. Negatives: fewer than `t + 1` shares, duplicates by identifier, a foreign identifier, the wrong ciphertext, an invalid proof, an inconsistent subset, `decryptWithSecret` on a threshold context. The F7 fixtures decrypt through the safe context, including identity-valued shares and equal `Y_j`. Every `(t + 1)`-subset decrypts identically. |
| M4 | Docs: support matrix (Experimental) and a guide | M3 | Docs reviewed. |

The user has asked for ADR-0053's implementation to follow in this PR. Because M3 needs
ADR-0052's host API, ADR-0052's own M0 and M1 come first (see the PR description).

## Verification and test-vector strategy

- **Independent reference.** A standalone Python implementation of Fig. 2, written from the
  [GJKR07] text and the Jubjub curve definition, produces vectors for fixed polynomials:
  commitments, shares, `QUAL`, `y`, `Y_j`, and threshold-decrypted results.
- **Spec cross-checks.** `G` and `H` must equal the bases pinned in `pedersen-jubjub-v1`.
- **Adversarial simulation.** The M2 list, with each corrupted behaviour scripted against
  honest participants.
- **Differential.** Java participants and transcript recomputation against the Python reference.
  - Threshold decryption uses admitted parameter sets only: 2-of-3, 3-of-5 and 4-of-7.
  - Results are compared with an independent fixture oracle, and with the Lagrange-weighted
    additive shares of the chosen subset (`Σ_{j∈S} λ_j·x_j = x`).
  - Small fixtures exercise every `(t + 1)`-subset.
  - Arithmetic-only tests are kept separate from safe-context integration tests.
  - (`t + 1 = n` is not an admitted setting: with `n ≥ 2t + 1` it would need `t ≤ 0`.)
- **Not evidence of security:** passing tests and benchmarks. Theorem 1 is the argument; the
  tests check that the implementation follows Fig. 2.

## Production / audit gates

- External review of the spec (M0) and of the participant implementation (M2).
- Security review of the application's transport: broadcast agreement, private channels and
  deadlines.
- Isolated trustee hosts (ADR-0039 offline class), and procedures for trustee availability.
- An adaptive-security assessment, if the deployment's threat model needs one (D8).

## Risks

- **Transport mistakes.** Broadcast without agreement, or a channel that is not private, voids
  the proof. Mitigation: D3's stated requirements, the transport review gate, and Q1.
- **Honest-majority assumption.** With more than `t` corrupt trustees, both secrecy and
  correctness can fail. Mitigation: parameter guidance and the I1 checks.
- **Lower collusion bar than n-of-n.** `t + 1` trustees can decrypt any single ballot.
  Mitigation: applications choose `t`, and documentation states the trade-off.
- **Implementation complexity.** The protocol has several rounds and a complaint logic.
  Mitigation: a deterministic state machine, an independent reference and adversarial
  simulations.

## Open questions (points needing a maintainer decision)

1. **Q1 (D3): the private channels.**
   - Options:
     - (a) the application provides them, for example TLS between trustees, under D3's stated
       requirements;
     - (b) ZeroJ specifies an encrypted-channel construction, which is new cryptography and
       would need its own pinned references and review.
   - Lean: (a). **Escalated**, and still open; tracked in #77. The library takes no position:
     the transport is the application's.
   - **Answered 2026-10-09 by ADR-0054 (Accepted).** It adds an optional transport,
     `dkg-share-delivery-hpke-v1`: each `SHARE` is HPKE-encrypted (RFC 9180) to a per-attempt
     recipient key and posted on the board. It is a pinned standard used as specified, not new
     cryptography, and replacing ideal channels by encryption is stated there as Assumption A1,
     for external review. Option (a) stays available.
2. **Q2 (D2): thresholds above a majority**, such as 4-of-5.
   - Lean: unsupported. Theorem 1 covers only `t < n/2`.
   - **Decided 2026-10-05 (maintainer): lean adopted.**
3. **Q3 (D8): a dealer-based fixture for tests.**
   - Lean: test fixtures only, behind the same insecure opt-in as dev trusted setups. Never a
     public API.
   - **Decided 2026-10-05 (maintainer): lean adopted.** Fixed polynomials exist only as
     package-private test seams.
4. **Q4 (D2): `N_MAX`, and round deadlines.**
   - Lean: `N_MAX = 64`. Deadlines are application configuration.
   - **Decided 2026-10-05 (maintainer): lean adopted.**
5. **Q5 (D4a, D6): the session identifier.**
   - It must be unique **per attempt**.
   - Lean: `blake2b_256(application context ‖ attempt number ‖ roster ‖ t ‖ n)`, with the
     attempt never reused.
   - **Decided 2026-10-05 (maintainer): lean adopted.** The spec adds a domain tag and length
     prefixes to the encoding (spec §2).
6. **Q6 (D4a): confirmations.**
   - Options: (a) require authenticated confirmations of the transcript from at least `t + 1`
     trustees in `QUAL`; (b) rely on round-closure evidence alone.
   - Lean: (a). With at most `t` corrupt trustees, it guarantees an honest trustee vouched for
     the record.
   - **Decided 2026-10-05 (maintainer): lean adopted.**
7. **Q7 (D1, D3; raised in implementation review): honest dealers and late shares.**
   - Under partial synchrony, a complaint against an honest dealer can come from a late
     `SHARE`, and Fig. 2's answer then publishes the pair (spec §5.2).
   - Options:
     - (a) keep Fig. 2 and make timely private delivery an explicit transport requirement
       (current);
     - (b) let an honest dealer that can prove delivery decline to answer and accept
       disqualification. This changes `QUAL` semantics and needs analysis;
     - (c) use a construction from the asynchronous-DKG literature (out of scope, D8).
   - Lean: (a), with the transport review gate covering deadlines. **Escalated.**
   - **Resolved 2026-10-09, scoped (ADR-0054 Q6).** For deployments that use
     `dkg-share-delivery-hpke-v1` and meet its contract, a share is delivered when its envelope
     is in the final round-1 window. Three rules then apply:
     - the processing barrier (ADR-0054 D6a);
     - abort T1 for a missing own key (D4);
     - a dealer's `COMMITMENTS` only after its envelopes are final (D7a).

     Together they make an honest recipient's false absence complaint impossible, and keep every
     answer by an honest qualified dealer at a corrupted index. Secrecy then no longer depends on
     publication timing. The precondition, and this question, stay as stated above for
     application-provided channels.

## Related findings (out of scope)

- ADR-0052's open Q1 (the trustee proof system) applies equally to threshold decryption shares.

## Implementation notes (refinements recorded during implementation)

These refine the accepted design and are recorded for maintainer acknowledgement, as AGENTS.md
requires. Each is stated normatively in `docs/specs/elgamal-jubjub-threshold-v1.md`. They came
from the independent reference of M0 and the implementation reviews.

1. **Abort A8: own dealing marked** (spec §5.1). D1a lists aborts for situations the
   assumptions exclude. An honest dealer is never *marked* any more than it is disqualified (A2).
   Outside [GJKR07]'s synchronous model, a merely late `EXTRACTION` would otherwise cause R6 to
   publish an honest dealer's polynomial. If that hit every honest dealer, the key would be
   public, with no abort. Under A8 those dealers abort and withhold their confirmations, so
   admission (at least `t + 1` confirmations) fails. This is invariant I13 applied to marking.
2. **A7 and admission need `t + 1` differing confirmations** (spec §5.1, §8 step 6). D1a
   lists "the broadcast shows disagreement" as an abort; this makes it mechanical without
   breaking I13. A single differing confirmation may be a faulty participant's lie, which the
   assumptions allow, so it must not abort the run. If it did, any one faulty member could veto
   every attempt. With `t + 1` or more differing, an honest participant saw another board, so
   participants abort and admission refuses. Malformed or other-session confirmations are
   ignored, not treated as a veto. The independent reference raised this (finding N2).
   Admission also requires round-closure evidence for round 7, the confirmation set, so a
   submitter cannot leave out differing confirmations (N6). A member that equivocates counts as
   differing only (N7).
3. **R5 evaluates every extraction complaint**, conflicting ones included. A valid complaint is
   evidence against the dealer, whoever sent it. The independent reference and the Java
   implementation first differed here; the rule is now pinned.
4. **Timely private delivery is a secrecy precondition** (spec §5.2; review finding R1).
   - D3 says an undelivered share "leads to a complaint". The review showed the consequence:
     an honest dealer then publishes the pair, and with the `t` faulty shares that determines
     its polynomial. Missed delivery for every honest dealer reveals the key without any abort.
   - The code follows Fig. 2 exactly; the synchronous model excludes the case. The spec now
     states the precondition normatively, and A8's rationale is limited to late extractions.
   - Any behavioural mitigation is escalated as Q7, not invented here.
5. **Abort hygiene and channels** (review findings R2–R5):
   - an abort is final for the participant;
   - A9, "own complaint missing from the round-2 view";
   - broadcast and private delivery are separate entry points;
   - A7 also fires when fewer than `t + 1` qualified participants confirmed the participant's
     own view, so a participant on a minority view cannot finish with an unadmittable context.
6. **Shares only from `QUAL`** (D5) is kept. Participants outside `QUAL` hold an `x_j` they cannot
   use; they are faulty under the assumptions, so this costs no liveness (spec §9).
7. **Misplaced transcript messages are refused** (spec §8 step 2; reference finding N10). A
   well-formed `SHARE` or `CONFIRMATION` submitted among the transcript messages refuses
   admission, like a malformed one: the submitter builds the transcript from delivered sets, which
   never hold either kind. Byte-identical duplicates count once and are not refused.
8. **Roster keys are pairwise distinct** (spec §1; review finding R10). A key that authenticates
   for two identifiers lets one party act as two participants, outside the `t` faulty
   participants the protocol tolerates. `DkgConfig` already refused such a roster; the spec and
   the reference now require it too. Distinctness is on bytes, so an application whose key format
   has several encodings must canonicalize its keys (reference finding N11).
9. **Delivery windows** (spec §5, §8 step 4; reference finding N12). Round `r`'s delivered set
   holds only messages of round `r` that arrived while round `r` was open. An early message is
   dropped, not carried forward. [GJKR07]'s synchronous model has no early messages; honest
   participants never send one, so dropping it affects only the faulty sender. `DkgParticipant`
   already refused a message of a round other than the open one.

## Implementation status

| Milestone | State | Notes |
|---|---|---|
| M0 | Done, reviewed (round 2: approve; rounds 3–5 on the vector replay, R7–R17: approve) | Spec `docs/specs/elgamal-jubjub-threshold-v1.md`. An independent Python reference of [GJKR07] Fig. 2, written from the paper and the spec (`zeroj-circuit-lib/src/test/resources/elgamal-threshold-reference/`, 514 checks), went through seven revisions. It found A8, the A7 veto, the R5 divergence, the admission completeness gaps, N10, N11 and N12, all resolved in the spec. `ThresholdReferenceVectorsTest` reproduces every fixture byte for byte through the Java participants, including the adversarial 4-of-7 script. It also replays all 134 of the reference's `case.*` vectors (abort, rule, finding, admission with the refusal step, combine, parameter and well-formedness; review finding R7). The two A4 vectors built on a trapdoor base `H'` replay through a test-side (4) filter under `H'`. The 20 participant-side A7 cases need a participant's own round-7 view and stay internal to the reference; `DkgParticipantTest` covers A7 in Java. |
| M1 | Done, reviewed (rounds 1–2: approve) | `ThresholdMath` (evaluation, interpolation, Lagrange), `ThresholdVss` (dealing, checks (4) and (5) on secret and public paths, reconstruction), `Blake2bDigest` (RFC 7693, checked against BouncyCastle and Cardano's `Blake2bUtil`). |
| M2 | Done, reviewed (round 1: two P1s, fixed; round 2: approve; rounds 3–5, admission hardening R8–R17: approve) | `DkgConfig`, `DkgMessage`, `DkgRules` (public rules shared with recomputation), `DkgParticipant` (separate broadcast/private delivery, final aborts A1–A9), `DkgTranscript` (with `deliveredRound`), `ThresholdKeyContext.admit` (library-computed admission, round-7 closure), `ThresholdKeyShare.restore`, `FaultAssumptionViolatedException`. Measured per-participant cost: 21 ms (2-of-3), 49 ms (4-of-7), 214 ms (11-of-21). |
| M3 | Done, reviewed (round 2: approve; round 5: approve) | Threshold decryption on ADR-0052's safe API: `ElGamal.decryptionShare(ThresholdKeyShare, …)`, `VerifiedDecryptionShare.verify(ct, id, …)`, and a Lagrange combine that checks every extra share. Groth16 end-to-end test in `AnnotatedElGamalTest`. |
| M4 | Done | Support matrix and `zeroj-circuit-lib` README rows (Experimental), gadget guide section "Encryption: ElGamal and threshold keys" (with the delivery precondition), annotation guide, `docs/benchmarks/elgamal-jubjub-2026-10-05.md`. |
