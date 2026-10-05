# ADR-0053: Threshold key generation and decryption for `elgamal-jubjub-v1` (t-of-n)

## Status
Proposed — 2026-10-05. Design only. Acceptance would be design acceptance; it would certify no
implementation, test or security property.

This ADR builds on ADR-0052 (Accepted). It changes no maturity claim. ADR-0039's assurance
classes apply: every secret-bearing operation here is **compatibility/offline** class.

## Date
2026-10-05

## Revision history
- **r1** — initial proposal.

## Risk classification
- **R3:** D1 (the distributed key generation protocol), D2 (the adversary and threshold model)
  and D5 (threshold decryption and its combination rule). These decide who can learn the key
  and whether a tally is correct.
- **R2:** D3 (transport requirements), D4 (library structure and transcript verification),
  D6 (session binding and encodings) and D7 (maturity and assurance labelling).

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
- **Untrusted:** every message from another trustee; every claimed share, commitment, complaint
  and complaint answer; claimed transcripts; claimed decryption shares.
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
   complaints, or answered one with a pair that fails (4).
2. **`QUAL`** is the set of non-disqualified trustees. It is a function of the broadcast
   transcript only.
3. Each `P_j` sets `x_j = Σ_{i∈QUAL} s_ij` and `x'_j = Σ_{i∈QUAL} s'_ij`. The key
   `x = Σ_{i∈QUAL} z_i` is never computed.
4. **Extraction (Feldman-VSS).** Each `P_i ∈ QUAL` broadcasts `A_ik = [a_ik]·G`. Each `P_j`
   checks equation (5), `[s_ij]·G = Σ_k [j^k]·A_ik`.
   - On failure, `P_j` broadcasts the pair `(s_ij, s'_ij)`. That pair satisfies (4) but not
     (5), which makes it a **valid complaint**.
   - For every `P_i` with a valid complaint, the others run Pedersen-VSS reconstruction. They
     publish shares that satisfy (4), and recover `z_i`, `f_i` and `A_ik` in the clear.
   - Finally `y = Σ_{i∈QUAL} A_i0`.

**Why New-DKG and not JF-DKG.** [GJKR07] §3 shows that JF-DKG lets the adversary bias `x`.
§5 shows JF-DKG is still adequate for schemes whose security reduces to the discrete-log
problem alone. ElGamal's IND-CPA security rests on **DDH**, which §5 does not cover.
`elgamal-jubjub-v1` therefore needs a DKG that meets (C3) and the secrecy requirement, which
Theorem 1 gives New-DKG.

### D2 — Threshold model and parameters (R3)

- `t ≥ 1` and `n ≥ 2t + 1`, that is `t < n/2`, as Theorem 1 requires.
- The decryption threshold is `t + 1`. Supported examples: 2-of-3, 3-of-5, 4-of-7.
- **Not supported:** a threshold above a majority, such as 4-of-5. Theorem 1 does not cover
  it: the protocol's disqualification and reconstruction rely on an honest majority (Q2).
- `n ≤ N_MAX` (lean 64, Q4).
- Identifiers are `1 … n` and are pairwise distinct. As scalars in `ℤ_l` they are non-zero,
  because `n < l`.
- If `y = O` the run is aborted and restarted (probability negligible). ADR-0052 refuses an
  identity key.

### D3 — Transport: the application provides it, with stated requirements (R2)

ZeroJ provides the cryptography of each round. It does not provide the network. The
application must provide the [GJKR07] §2.1 model:

- **Broadcast with agreement.** Every honest trustee receives the same broadcast messages, in
  the same rounds. An append-only bulletin board works: for example a Cardano transaction or
  datum per message, or an authenticated off-chain board that all trustees read.
- **Private, authenticated point-to-point channels** for the `(s_ij, s'_ij)` pairs.
- **Rounds with deadlines.** A message that misses its round counts as absent. A share that is
  not delivered leads to a complaint.

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
- **`DkgTranscript`.** The ordered public record of all broadcast messages. Verifying it
  **deterministically** yields `QUAL`, `y` and every verification key
  `Y_j = Σ_{i∈QUAL} Σ_k [j^k]·A_ik`. This is [GJKR07] (C1′): `g^{x_j}` "can be computed from
  publicly available information". The private messages are not needed for this.
- **`ThresholdKeyContext`.** Produced only from a verified transcript. It contains `(t, n,
  QUAL, y, {Y_j})`. It plays the key-context role of ADR-0052 D2c, so encryption, admission and
  key binding are unchanged.
- **Decryption shares.** ADR-0052's `decryptionShare` and `VerifiedDecryptionShare` are reused,
  with `P = Y_j` taken from the context (D5).

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
4. Malformed share sets are refused: duplicates, foreign identifiers, shares for another
   ciphertext, or fewer than `t + 1`.

ADR-0052's n-of-n contexts keep its I14 rule (exactly one share per registered trustee). This
ADR adds the threshold rule for threshold contexts only.

### D6 — Session binding and encodings (R2)

- **Session binding.** Every DKG message carries a 32-byte session identifier, chosen by the
  application (for example a hash of the election id), together with the sender's identifier,
  the round, and the target identifier for private messages. Participants refuse messages for
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
| I3 | Share checks are exactly equations (4) and (5) of Fig. 2. A dealer is disqualified if and only if it received more than `t` complaints, or answered one with a pair that fails (4). | D1 |
| I4 | `QUAL`, `y` and every `Y_j` are deterministic functions of the broadcast transcript alone. Every honest verifier of the same transcript computes the same values. | D1, D4 |
| I5 | A phase-2 complaint is valid only if its pair satisfies (4) and fails (5). Reconstruction of `z_i` uses at least `t + 1` published pairs that satisfy (4). | D1 |
| I6 | `y = Σ_{i∈QUAL} A_i0`, with reconstructed values where needed. `y ≠ O`, otherwise the run aborts. | D1, D2 |
| I7 | A `ThresholdKeyContext` is constructible only from a verified transcript. | D4 |
| I8 | Threshold decryption uses at least `t + 1` verified shares from distinct `QUAL` members, each verified against `Y_j` and this exact ciphertext. Lagrange coefficients are computed for the exact subset used, and malformed share sets are refused. | D5 |
| I9 | When more than `t + 1` verified shares exist, every checked subset gives the same result, or decryption fails. | D5 |
| I10 | Every message is bound to its session, sender, round and (for private messages) target. Messages for anything else are refused. | D6 |
| I11 | Scalars and points are canonical on decode, and points are in the subgroup. The transcript encoding is canonical. | D6 |
| I12 | Secret-bearing operations are documented as compatibility/offline-class, with no online or constant-time claim. | D7 |

## Consequences

- Applications can choose liveness (t-of-n) or maximal privacy (n-of-n) with the same ballots
  and the same APIs for encryption and admission.
- Anyone can verify a key generation from its public transcript, and recompute every trustee's
  verification key.
- Applications take on real protocol work: a broadcast board, private channels and round
  deadlines. The library cannot supply the network.
- The added cost is host-side only. Each trustee performs about `2(t + 1)` commitments when
  dealing, and checks `n − 1` shares of `t + 1` terms each. This is an estimate, to be measured
  at M2. Circuits are unchanged.

## Compatibility

- **New API only.** ADR-0052's ciphertexts, encodings and n-of-n contexts are unchanged.
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
| M1 | VSS primitives and Lagrange (D4) | M0 | Equations (4) and (5) and reconstruction match the spec vectors. Property tests: any `t + 1` shares reconstruct the same value, and `t` shares do not determine it (the simulation check of [GJKR07] §2.2, on small parameters). |
| M2 | `DkgParticipant` and `DkgTranscript` (D1, D4, D6) | M1 | **Honest runs:** every `(t, n)` up to small bounds; all participants agree on `QUAL`, `y` and `Y_j` (I4). **Adversarial simulations**, one test each: <br>• a bad share; <br>• a false complaint; <br>• more than `t` complaints; <br>• a bad complaint answer; <br>• a phase-2 Feldman cheat, with reconstruction; <br>• a missing message; <br>• a message replayed from another session, round or target; <br>• a non-canonical or non-subgroup point; <br>• a rushing-order run. |
| M3 | Threshold decryption (D5) on ADR-0052's safe API | M2 and ADR-0052 M1 | I8 and I9. Negatives: fewer than `t + 1` shares, duplicates, a foreign identifier, the wrong ciphertext, an invalid proof, an inconsistent subset. Every `(t + 1)`-subset decrypts identically. |
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
- **Differential.** Java participants and transcript verification against the Python reference.
  Threshold decryption against ADR-0052's n-of-n path on the same message, where `t + 1 = n`.
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
   - Lean: (a). **Escalated.**
2. **Q2 (D2): thresholds above a majority**, such as 4-of-5.
   - Lean: unsupported. Theorem 1 covers only `t < n/2`.
3. **Q3 (D8): a dealer-based fixture for tests.**
   - Lean: test fixtures only, behind the same insecure opt-in as dev trusted setups. Never a
     public API.
4. **Q4 (D2): `N_MAX`, and round deadlines.**
   - Lean: `N_MAX = 64`. Deadlines are application configuration.
5. **Q5 (D6): the session identifier.**
   - Lean: 32 bytes chosen by the application, for example `blake2b_256` of the election id.

## Related findings (out of scope)

- ADR-0052's open Q1 (the trustee proof system) applies equally to threshold decryption shares.
