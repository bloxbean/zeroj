# ElGamal-Jubjub threshold v1 independent reference

An independent reproduction of the `elgamal-jubjub-threshold-v1` profile (New-DKG of [GJKR07]
Fig. 2 over Jubjub, with admission and threshold decryption). It was written from the
normative specs and the paper alone, so its output can serve as evidence against ZeroJ's Java
implementation (ADR-0053 milestone M0).

## Files

- `elgamal_jubjub_threshold_v1_reference.py`: Python 3, standard library only (`hashlib`
  BLAKE2b and SHA-256). It implements:
  - Jubjub affine twisted-Edwards arithmetic (`a = −1`): unified addition with modular
    inverses, double-and-add, Tonelli–Shanks, and the pedersen-jubjub-v1 §4 encoding and
    canonical decoding (ZIP 216). It re-derives `d = −10240/10241 mod p` and `G = [8]·G_full`
    and compares both with the pins. `H` is taken from the pins of pedersen-jubjub-v1 §2.3 and
    checked to decode, lie on the curve and in the subgroup.
  - §2 session, §11 test scalars, §3 dealing, and equations (4) and (5). The right-hand sides
    are summed term by term, `Σ_k [j^k mod l]·C_ik`, never by Horner's rule.
  - §4 message encodings and well-formedness for all 8 kinds, plus byte-identical
    deduplication and conflict detection.
  - §5 R1–R6 as a public recomputation from the delivered broadcast sets. The
    reconstruction step interpolates the coefficients with modular-inverse Lagrange.
  - The participant-side logic of §5, with §5.1 aborts:
    - §4 channels: on the private channel only a `SHARE` addressed to the recipient is
      accepted, and a `SHARE` on the board is ignored;
    - complaints, including on a conflicting `SHARE`;
    - adopting answered pairs;
    - `EXTRACTION_COMPLAINT`, `RECONSTRUCTION` and `x_j`;
    - the participant checks, each run when its round closes: A9 at R2, A2 at R3, A8 at R5,
      A6 at R6, and both A7 clauses at R7. The participant's own confirmation counts only if
      it was delivered back.

    A participant that aborts sends nothing afterwards. Deviations come from a per-fixture
    script.
  - §6 transcript and digest, and §7 confirmation bytes.
  - §8 steps 2 and 4–6:
    - step 4's delivered set (`delivered_round`), and `roundClosed(config, r, list)` for rounds
      1–7, modelled as "the list equals the delivered set of the true board";
    - step 6 counts matching and differing `QUAL` confirmations; an equivocating sender counts
      as differing only; it refuses if `t + 1` or more differ, and otherwise requires at least
      `t + 1` matching.
  - Replayable `case.*` vectors for every rule, admission, combine, parameter and
    well-formedness case, for every abort case except A7, and for every finding except the
    combined summary `finding.N6_round7_closure`. The cases without a vector are listed under
    "Notes on the vectors". Each vector is replayed from its emitted keys alone as a
    self-check.
  - §9 Lagrange coefficients, combining with the extra-share consistency check, and a
    linear plaintext search.
- `reference-output.txt`: the script's output, as `key=value` lines under a `#` header.

## Independence rules followed

Read:

- `docs/specs/elgamal-jubjub-threshold-v1.md` (the spec under test), in its first version
  and again after each of its seven revisions (see below).
- `docs/specs/elgamal-jubjub-v1.md` and `docs/specs/pedersen-jubjub-v1.md` (curve, `G`, `H`,
  the point encoding, the sampler, `Enc`, plaintext recovery, the DLEQ statement).
- The GJKR07 paper text: §2.2 (Feldman-VSS, Pedersen-VSS, Lemma 1), §3 (JF-DKG, as context),
  and §4, including Fig. 2 (New-DKG), the §4.2 prose on misbehaviour at the extraction stage,
  the correctness proof and the simulator (Fig. 3).
- `../pedersen-reference/README.md`, only for README and output conventions.

Not read: any `.java` file, any other `.py` file, `../pedersen-reference/reference-output.txt`
(the spec pins `H` directly), build output, and every other file in the repository. The
repository was not searched.

The values the specs pin (`d`, `G`, `encode(G)`, `H`, `encode(H)`, `scalar("sk")`, the
single-key `PK`, `Enc(1; scalar("k1"), PK)` of elgamal-jubjub-v1 §12, and `C(42, 12345)` of
pedersen-jubjub-v1 §8) appear only as comparison targets. `H` is the one exception: it is used
as an input, after checks that it decodes and lies in the subgroup. The other pins are never
inputs. The elgamal-v1 and pedersen-v1 cross-checks confirm the scalar-multiplication,
encoding, `Enc` and test-scalar conventions against independently pinned values.

Where a spec was unclear, the script implements the most literal reading and records the issue
below. It does not resolve the issue from code.

## Running

```
cd zeroj-circuit-lib/src/test/resources/elgamal-threshold-reference
python3 elgamal_jubjub_threshold_v1_reference.py
```

The run takes about 10 s. The script prints to stdout and rewrites `reference-output.txt`.
Apart from the `# Python:` header line, the output is deterministic: two runs were compared
byte for byte.

| Exit status | Meaning |
|---|---|
| 0 | Every check passed. |
| 1 | A check or a `spec_match.*` comparison failed, or the script crashed. The output is still written, ending in `result=fail`, and the failing keys go to stderr. |

The script was also run in mutated copies to confirm that it fails. Each of these mutations
was detected:
- the sign of the Lagrange denominator;
- `j^(k+1)` in (5) or in `Y_j`;
- `≥ t` instead of `> t` in R3;
- the encoding parity bit;
- accepting a conflicting message as unique, in R1 and in R6;
- dropping the R5 guard on an absent `EXTRACTION`;
- no deduplication of byte-identical messages;
- arrival-order transcripts;
- ignoring `y` in the A7 check;
- removing the extra-share check;
- removing A2 or A8;
- evaluating A8 when R4 closes instead of R5;
- complaining against a dealer without unique `COMMITMENTS`;
- A7 firing on any differing confirmation, or on `t` of them;
- admission without the differing rule, or refusing on any differing confirmation;
- admission counting a confirmation from another session;
- removing A9;
- counting the participant's own confirmation when it was not delivered back;
- dropping A7's matching clause;
- accepting any kind on the private channel;
- keeping a `SHARE` in the delivered set;
- counting an equivocator as matching;
- dropping the distinct-key rule, or step 3;
- a wrong refusal-step mapping;
- closure ignoring authentication;
- refusing duplicate transcript messages;
- counting unauthenticated confirmations as differing;
- a round-7 list that drops confirmations from senders outside `QUAL`.

## Output format

Each line is `key=value`:

- Field elements and scalars are `0x` plus 64 lowercase hex digits.
- Small integers (`t`, `n`, `attempt`, counts, plaintexts) are decimal.
- Byte strings (encodings, messages, sessions, digests, transcripts) are bare lowercase hex.
- Lists are comma-separated, and empty lists are empty.
- Booleans are `true` or `false`.

| Key family | Content |
|---|---|
| `profile`, `curve.*`, `G.*`, `H.*`, `spec_match.*`, `check.*` (top level) | Constants, re-derivations and comparison with the pins. |
| `session.<fixture>` | The §2 session of every fixture. `session.session.preimage` is the full preimage, and `session.session.key_1` the roster bytes. |
| `<F>.t`, `.n`, `.ctx`, `.attempt`, `.session` | The configuration. |
| `<F>.qual`, `.disqualified` (`i:rule`), `.marked`, `.marked_by` (`i:R4` or `i:R5`) | The public decisions. |
| `<F>.a.<i>.<k>`, `.b.<i>.<k>` | The coefficients actually used. |
| `<F>.C.<i>.<k>`, `.A.<i>.<k>` | Encodings of the true commitments and extraction values. |
| `<F>.s.<i>.<j>`, `.sp.<i>.<j>` | `s_ij` and `s'_ij` for every `i, j`, own shares included. |
| `<F>.x.<j>`, `.y`, `.Y.<j>`, `.Y.<j>.identity` | The outputs. `x_j` is listed for every `j`, including participants that aborted. |
| `<F>.msg.<round>.<kind>.<sender>.<subject>` | Every broadcast message of the transcript, in transcript order. |
| `<F>.count.<KIND>`, `<F>.counts` | Messages per kind, and per round 1–6 as a list. |
| `<F>.transcript`, `.digest`, `.confirmation.<j>` | §6 and §7. Confirmations come only from `QUAL` members that did not abort. |
| `<F>.participant_abort.<j>` | The participant-side outcome: `none` or `A1`–`A9`. |
| `<F>.lagrange.<S>.<j>`, `.enc.{m,width,A,B}`, `.D.<j>`, `.decrypt.<S>`, `.decrypt.all` | §9 for every `(t + 1)`-subset `S` of `QUAL`, written as ids joined by dashes. `decrypt.all` uses all of `QUAL` and so exercises the extra-share check. |
| `<F>.F_coeffs` | `F(z) = Σ f_i(z)`: zero-share and equal-shares. |
| `adversarial-4of7.share.1.2`, `.share.3.4` | The two bad `SHARE` messages. |
| `adversarial-4of7.A_broadcast.5.1` | The forged `A_51 + G`. |
| `adversarial-4of7.recon.<i>.{valid_senders,used_senders,a.<k>,b.<k>,A.<k>}` | The reconstruction of dealers 1 and 5. |
| `adversarial-4of7.y_equals_reference` | `y` equals `Σ_{i ∈ {1,2,4,5,6,7}} [a_i0]·G`, computed directly. |
| `<F>.check.*` | Per-fixture checks (see below). |
| `abort.<name>`, `check.abort.<name>` | The §5.1 abort cases: the outcome and its check. |
| `rule.<name>`, `check.rule.<name>` | R1–R6, combine, admission and §1 parameter cases. Admission cases are `admit` or `refuse`, with the reason in `info.rule.<name>.reason`. Only `admit`/`refuse` is meant for comparison. |
| `wf.<name>`, `check.wf.<name>`, `info.wf.<name>.reason` | §4 well-formedness: `accept` or `reject`. The reason is informative only, since the spec sets no precedence among reasons. |
| `finding.<name>`, `check.finding.<name>` | Demonstrations for F14 and A8, round-7 closure (N6), and the §5.2 limitation (`S52_late_shares_reveal_key`). |
| `case.<name>.*` | Replayable vectors (next table). |
| `scalar.<tag>` | Every §11 test scalar used. |
| `info.*` | Informative values, which are not checks. |
| `result` | `pass` or `fail`. |

Replayable vectors, `case.<family>.<name>.*`, where `<family>.<name>` is the name of the internal
case (`abort.*`, `rule.*`, `finding.*`, `wf.*`):

| Key | Content |
|---|---|
| `config` | `t,n,ctx-hex,attempt`. Unless a `roster` key says otherwise, the roster is the standard one: `key_j` is 32 bytes, each equal to `j`. |
| `H` | Present only on the two A4 trapdoor vectors: the substitute base `H' = [w]·G`. A replay must use it in place of the profile's `H`, or skip the vector. |
| `order` | Absent: `msg.*` is in §6 order. `submission`: `msg.*` is as submitted, which is used when a message cannot be parsed (malformed, other session) and for duplicate submissions. |
| `msg.<i>` | The case transcript (broadcasts of rounds 1–6, §6 order, `i` from 1), or for admission cases the submitted transcript messages. In the two misplaced-kind cases, `msg.*` also holds the misplaced `SHARE` or `CONFIRMATION`, sorted by `(kind, sender, subject, bytes)`. |
| `raw.<i>` | Present only when the posted broadcasts differ from the transcript (malformed, duplicate or `SHARE` posts): the posts in arrival order. Replaying them must give the same outcome. |
| `confirmation.<i>` | Admission cases: the submitted confirmations, in submission order. |
| `unauthenticated.<i>` | Admission cases with a modelled `authenticate`: `authenticate(bytes)` is false iff `bytes` is in this list. It applies to transcript messages (step 3 refuses), confirmations (ignored) and board posts (dropped). Absent: everything authenticates. |
| `closure`, `board.<r>.<i>` | Closure cases (`closure=board`): the raw board of round `r = 1 … 7` (round 7 holds the posted confirmations), with posts in arrival order and junk included. `roundClosed(config, r, list)` is true iff `list` equals the delivered set (§8 step 4) of `board.<r>.*`: well-formed, this session, header round `r`, not a `SHARE`, authenticated, byte-identical copies once, §6 order. Without `closure`, `roundClosed` is always true. |
| `expect` | One of: `qual=<ids>;marked=<ids>;y=<hex>` (public recomputation, no abort); `abort=A1\|A3\|A4\|A5`; `admit` or `refuse` (admission); `error`, `plaintext:<m>` or `not_plaintext:<m>` (combine; `not_plaintext:5` means the combine must not return 5, so an error or any other value passes). |
| `step` | Admission vectors with `expect=refuse`: the §8 step at which the reference refuses. 2 is decode or kind, 3 authenticate, 4 closure of rounds 1–6, 5 a recomputation abort, and 6 counting or round-7 closure. |
| `qual`, `bound`, `ciphertext`, `share.<j>` | Combine cases: `QUAL`, the search bound, `encode(A) ‖ encode(B)`, and each decryption share `encode(D_j)`. |
| `decode` | `wf.*` cases: `accept` or `reject` for the single message `msg.1`. |
| `roster`, `params`, `session` | `rule.param_*` cases. The `roster` key takes one of three forms: `standard`; `lengths:<l1,l2,…>`, where `key_j` is the byte `j` repeated `l_j` times, so the keys are pairwise distinct; or `hex:<k1>,<k2>,…`, with the keys given in hex. `params` is `accept` or `reject`, and an accepting case also carries the derived `session`. |

Notes on the vectors:
- Every abort case except A7 has a vector, including the participant-only aborts (A2, A6, A8,
  A9). For those, `expect` is the public outcome of the case transcript.
- Cases with no vector (`info.case_internal_only` lists them):
  - **The 20 `abort.A7_*` cases.** A7 is a participant-side check. Its inputs are the checking
    participant's identity and its own delivered round-7 view, including whether its own
    confirmation was delivered back, and none of the vector formats carry them. These cases
    could become vectors if the replay gained a participant-side A7 entry point (inputs:
    transcript, participant id, round-7 view).
  - **`finding.N6_round7_closure`.** It is a combined summary of two A7 outcomes and two
    admissions. The admissions are vectors (`finding.N6_round7_closure_full_set` and
    `finding.N6_round7_closure_subset`); the A7 parts are participant-side, as above.
- Vector counts: abort 15, rule 81, finding 7, wf 31, so 134 in all (`info.case_count`,
  `info.case_count.<family>`). `check.case_vectors_replay_self_consistent` replays each one,
  using every key above. `check.rule.admission_refusal_steps` checks the `step` values
  independently.

The per-fixture checks are:
- `y` and every `Y_j` against the true polynomials of `QUAL`, and `x_j` against `Σ f_i(j)`;
- `[x_j]·G = Y_j` for every `j`;
- every message well-formed, every point round-tripped and in the subgroup;
- the digest and outputs unchanged under three shuffles with injected byte-identical
  duplicates;
- confirmations sent exactly by the `QUAL` members that did not abort, with no A7;
- admission accepted;
- decryption of every subset, `Σ λ_j x_j = x`, and the DLEQ relations of the shares.

The negative cases (most on a 3-of-5 base) are:

| Case | Construction | Outcome |
|---|---|---|
| `A1_t_plus_1_dealers_silent` | dealers 1–3 send no `COMMITMENTS` | every participant `A1`; admission refuses |
| `A1_boundary_t_dealers_silent` | dealers 1–2 silent, so `|QUAL| = n − t` | `none` (participant 1: `A2`) |
| `A2_own_answer_not_delivered` | dealer 1's correct `ANSWER` to participant 2 is lost | participant 1 `A2` and sends nothing afterwards |
| `A3_*` | dealer 5 withholds `EXTRACTION`; only `t` valid `RECONSTRUCTION`s | `A3` (control with `t + 1`: `none`, dealer 5 `A8`) |
| `A4_trapdoor_*` | reference-only base `H' = [w]·G`; a pair `(s − w, s' + 1)` satisfies (4) but is off the polynomial | `A4` |
| `A4_same_construction_under_profile_H` | the same pair under the real `H` | it fails (4) and is excluded: `none` |
| `A5_constant_terms_sum_to_zero` | 2-of-3, `a_i0 = 1, 2, l − 3` | `A5` |
| `A6_extraction_complaints_not_delivered` | dealer 5 publishes `A_51 + G`; no complaint is delivered | every participant `A6` |
| `A7_*` | 2-of-3, 3-of-5 and a test-only 2-of-4: up to `t` lies, `t + 1` differing `QUAL` confirmations (digest, `y` or both), one liar sending twice, too few matching (silent members, own confirmation not delivered back), stale-session, malformed or unauthenticated confirmations, equivocating senders | `A7` if `t + 1` distinct members differ or fewer than `t + 1` match; an equivocator counts as differing only; anything not well-formed, for another session or unauthenticated is ignored |
| `A9_own_complaint_not_delivered` | participant 2's `COMPLAINT` against dealer 1 (bad `SHARE`) is not delivered | participant 2 `A9`, falls silent; it stays in `QUAL`, is marked (no `EXTRACTION`), and `z_2` is published by reconstruction; the others confirm and admission accepts |
| `channel_*` | a `SHARE` on the board; an `ANSWER` on the private channel; a `SHARE` addressed to another recipient | the board `SHARE` is ignored (digest unchanged); the other two count as an absent `SHARE`, so the recipient complains |
| `A8_withheld_extraction_dealer_aborts`, `A8_timing_*` | dealer marked by R4 or R5 | `A8` when R5 closes; an R4-marked dealer still sends its R5 complaints |
| `R1_*`, `R2_*`, `R3_*`, `R4_*`, `R5_*`, `R6_*` | conflicting or malformed `COMMITMENTS`, conflicting `SHARE`, duplicate complaints, more than `t` complaints, missing, bad, conflicting or unsolicited answers, conflicting `EXTRACTION`, invalid or conflicting extraction complaints, conflicting reconstruction | as named |
| `finding.F14_*` | all, or some, `EXTRACTION`s late; with and without A8 | see F14 below |
| `finding.S52_late_shares_reveal_key` | faulty `{1, 2}` (`t`); one `SHARE` per honest dealer late (3→4, 4→5, 5→3) | **documented model limitation (§5.2)**: nothing aborts and admission accepts, while the coalition recovers every `z_i` (its own two shares plus the public answer) and so `x` |
| `combine_*` | a bad extra share, fewer than `t + 1` shares, a share from outside `QUAL` | error |
| `admission_*` | §8 steps 2–6 (`authenticate` false only for listed bytes; `roundClosed` true unless the board model applies) | One lie, or `t` lies, are ignored and the run is admitted. `t + 1` differing refuse; with `n = 2t + 1` this is isolated only by the test-only 2-of-4 configuration (N8). Fewer than `t + 1` matching refuse. An equivocator counts as differing only (refuse where the superseded "both sets" reading would admit). A submitted set that omits confirmations, or an omitted round, fails round closure. Junk board posts do not veto. Stale-session, malformed, non-`CONFIRMATION` and unauthenticated confirmations are ignored. A malformed or other-session transcript message, or a misplaced `SHARE` or `CONFIRMATION`, refuses (step 2). An unauthenticated transcript message refuses (step 3). Byte-identical duplicate transcript messages count once. |
| `param_*` (sixth revision) | Duplicate roster keys (`hex:01,01,03`, and a standard roster with key 5 equal to key 1); distinct hex keys; `attempt = 2^64 − 1` | reject; accept; accept. Accepting cases carry `session`. |
| `param_*` | §1 bounds on `t`, `n`, key lengths, `ctx` and `attempt` | accept or reject |

## Result

All 514 checks pass. That includes 22 `spec_match` comparisons:
- Nine compare against independently pinned values: `G`, `encode(G)`, `encode(H)` and
  `decode(encode(H))` against the threshold spec's references, and `scalar("sk")`, `PK`,
  `Enc(1; scalar("k1"), PK)` and `C(42, 12345)` against the elgamal-v1 and pedersen-v1 pins.
- Thirteen are `spec_match.table.*` drift checks against the §11 table, whose values were
  copied from this reference.

`d = −10240/10241 mod p` matches the pin. BLAKE2b-256 matches the known answer for `"abc"`
and differs from truncated BLAKE2b-512. All 134 `case.*` vectors replay to their expected
outcome.

| Fixture | `QUAL` | Marked | Counts r1–r6 | `digest` |
|---|---|---|---|---|
| `honest-2of3` | 1–3 | — | 3/0/0/3/0/0 | `2af7f7ea…aa46023` |
| `honest-3of5` | 1–5 | — | 5/0/0/5/0/0 | `edd7aa9f…7ffdcf71` |
| `honest-4of7` | 1–7 | — | 7/0/0/7/0/0 | `9b6a52fe…6c24431b` |
| `zero-share` | 1–3 | — | 3/0/0/3/0/0 | `8864e81d…e43fd43d` |
| `equal-shares` | 1–3 | — | 3/0/0/3/0/0 | `cee46443…933f041e` |
| `adversarial-4of7` | 1,2,4,5,6,7 | 1 (R4), 5 (R5) | 7/2/1/5/5/8 | `92ddd0e5…caa134a0` |

`adversarial-4of7` reproduces the §11 script:
- the bad shares 1→2 and 3→4;
- the complaints 2→1 and 4→3;
- dealer 1's correct answer, and dealer 3 disqualified (`R3_answer_absent_or_conflict`);
  participant 3 aborts with A2;
- dealer 1 withholds its `EXTRACTION`, and dealer 5 forges `A_51 + G`;
- valid extraction complaints from 1, 2, 4, 6 and 7;
- dealers 1 and 5 marked, both aborting with A8 when R5 closes;
- `RECONSTRUCTION`s from 2, 4, 6 and 7 for both dealers (exactly `t + 1` each);
- confirmations from 2, 4, 6 and 7;
- `y` and every `Y_j` equal to the values from the true polynomials, with dealers 1 and 5
  keeping their contributions.

The deviators' lies are ignored by A7 and by admission, and the run is admitted. Two of
them come from `QUAL` members 1 and 5; the third comes from participant 3, which is outside
`QUAL`. Admission refuses with only three matching confirmations. Four differing `QUAL`
confirmations (`t + 1`) trigger A7. So does losing any one of the four honest
confirmations: fewer than `t + 1` then match. Every 4-subset of `QUAL` decrypts `Enc(5)`.

In zero-share (width 1), `x_1 = 0`, `Y_1 = O` and `D_1 = O`. In equal-shares (width 1),
`Y_1 = Y_2 = Y_3 = [3]·G`. In both, every pair decrypts `Enc(1)`.

## Spec ambiguities and findings

### Findings against the original spec (1–18)

These are kept as written when they were raised. The next section maps each one to the
spec's first revision.

1. **§11, the roster.** "`key_j` = 32 bytes of value `j`" was read as 32 bytes each equal to
   `j`. `I2OSP32(j)` would give a different session.
2. **§11, zero-share and equal-shares had no `ctx` or `attempt`.** Reusing the honest values
   made their session identical to `honest-2of3`'s, against §2.
3. **§11, zero-share and equal-shares gave no width** for `Enc(1; …)`.
4. **Adversarial step 5 contradicted the §5 participant logic.** Only participants 1 and 2
   complained, though §5 makes participants 3 and 4 complain too.
5. **Adversarial step 6, "every participant `j ≠ i`".** This included the disqualified
   participant 3, which would have aborted under A2, and the marked dealers.
6. **`EXTRACTION` from a disqualified dealer** was not addressed.
7. **The adversarial fixture had 4 deviating participants against `t = 2`.**
8. **R6 and A4.**
   - The `C_ik` clause is implied by (4) on the chosen pairs: interpolation is linear.
   - A4 is reachable only with `log_G H`. There is no profile vector; a trapdoor base
     exercises it.
9. **§4, the subject range `1 … n`** was implied but not stated.
10. **R5 did not say how conflicting `EXTRACTION_COMPLAINT`s are treated.**
11. **R2, the participant logic, was undefined when `COMMITMENTS` is absent or in conflict.**
12. **§5, the `x_j` wording left out the participant's own `s_jj`.**
13. **§8 step 6 against A7.** Admission accepted a record that honest participants had
    abandoned because of a differing confirmation.
14. **A late `EXTRACTION` revealed the key with no abort.** If every `EXTRACTION` was late, R6
    published every `f_i`, nothing aborted, and admission accepted.
15. **§9, shares only from `QUAL`.** `Y_j` was defined for every `j`, but shares came only from
    `QUAL`; the spec gave no explanation.
16. **§6, what the transcript contains.** Ineffective broadcasts are included, and "rounds 1
    and 4 only" still encodes `u32(0)` for the empty rounds; neither was stated.
17. **§9, the extra-share check covers only extras.** An unverified bad share in `S` goes
    undetected. This is informative.
18. **The BLAKE2b-256 pitfall.** Truncating BLAKE2b-512 gives different values. This is
    informative.

### Spec revision after this run

#### First revision

`docs/specs/elgamal-jubjub-threshold-v1.md` was revised after the first run. The script was
updated and re-run against the revised spec with the same independence rules. Both runs give
the same values for `honest-*`, the sessions of `session` and `honest-*`, the scalars and the
constants. The other values changed:
- the zero-share and equal-shares sessions, messages and digests;
- the adversarial fixture, which is replaced (`adversarial-3of5` became `adversarial-4of7`);
- the admission outcomes, which are now `admit` or `refuse` with a separate reason.

| Finding | Resolution in the revised spec | Reference now |
|---|---|---|
| 1. Roster | §11 states 32 bytes each equal to `j` | Unchanged reading; the alternative-session key was removed. |
| 2. Session collision | zero-share: `ctx "zeroj.test.zero-share"`; equal-shares: `"zeroj.test.equal-shares"`; both `attempt 1` | Uses them; `check.sessions_distinct`. |
| 3. Width | `Enc(1)` at width 1 | Uses width 1. |
| 4, 5, 7. Adversarial script | Replaced by `adversarial-4of7`: `t = 3`, `n = 7`, exactly 3 deviators (1, 3, 5); everyone else follows §5; an aborting participant sends nothing afterwards | Implemented literally. Counts 7/2/1/5/5/8; aborts A8 (1), A2 (3), A8 (5). The alternative-reading digests were removed. |
| 6. `EXTRACTION` from a disqualified dealer | Implicit: only `QUAL` members broadcast, and participant 3 aborts with A2 | Unchanged. |
| 8. R6 and A4 | R6 notes the `C_ik` clause is implied by (4) and kept as a defensive check; §5.1 notes A4 is unreachable without `log_G H` | The trapdoor exercise is kept. |
| 9. Subject range | §4 states it | Unchanged. |
| 10. R5 conflicts | Every `EXTRACTION_COMPLAINT` is evaluated on its own, conflicting ones included | Unchanged; adds `rule.R5_conflicting_complaints_each_evaluated`. |
| 11. R2 without `COMMITMENTS` | No complaint against such a dealer | Unchanged; adds `check.rule.R2_no_complaint_*`. Also implements "a `SHARE` … in conflict" (`rule.R2_conflicting_share_complaint`). |
| 12. `x_j` wording | Includes own `s_jj` | Unchanged. |
| 13. Admission against A7 | §8 step 6 refused outright on any authenticated, differing `QUAL` confirmation; confirmations from outside `QUAL` were ignored | Implemented, then superseded by the threshold rule of the second revision (N2). |
| 14. Late `EXTRACTION`s | New abort A8, "own dealing marked for reconstruction" (participant check) | Implemented, checked when R5 closes. `finding.F14_all_extractions_late`: every dealer aborts with A8, no reconstruction, no confirmation, admission refuses. The pre-revision behaviour is kept as `finding.F14_all_extractions_late_pre_revision_without_A8` (key public, admitted). |
| 15. `QUAL`-only shares | §9 explains them | Unchanged. |
| 16. Transcript contents | §6 states that ineffective broadcasts are included and that empty rounds contribute `u32(0)` | Unchanged. |
| 17, 18. Informative | — | Unchanged. |

#### Second revision

The spec was revised again after findings N1–N5 below. Only the A7 and admission outputs
changed. All other output, including every digest, is byte-identical to the first-revision
run.

| Finding | Resolution in the second revision | Reference now |
|---|---|---|
| N1. When checks run; silence after abort | §5.1 "When each check runs": R3 runs A1 and A2; R5 runs A8, before any `RECONSTRUCTION`; R6 runs A3–A6; R7 runs A7. An aborted participant sends nothing afterwards. | Already implemented this way; unchanged. |
| N2. One faulty member could veto | A7 is now a threshold: abort only if at least `t + 1` distinct `QUAL` members confirm another digest or `y`; up to `t` differing are ignored. §8 step 6 mirrors it: refuse if differing ≥ `t + 1`, and require matching ≥ `t + 1`. | Implemented: `abort.A7_*`, `rule.admission_one_lie_ignored`, `rule.admission_t_lies_ignored_N2`, `rule.admission_t_plus_1_differing_3of5`, `rule.admission_2of4_*`, `adversarial-4of7.check.{A7,admission}_*`. |
| N3. Malformed or stale confirmations | §8: malformed, other-session, non-`CONFIRMATION`, unauthenticated or non-`QUAL` inputs are ignored | Implemented: `rule.admission_{stale_session,malformed,non_confirmation}_*`, `abort.A7_3of5_{stale_session,malformed}_*`. |
| N4. The A8 explanation | Corrected: with every honest dealer late, nothing is published and the run ends in A3; with some late, an unmarked honest contribution keeps `x` secret | Matches `finding.F14_*`; unchanged. |
| N5. A8 liveness | §5.1: "A8 trades liveness for secrecy" | Unchanged. |

#### Third revision

The spec was revised a third time after findings N6–N8 below. Only the equivocation,
admission and round-7 outputs changed. Every digest and all fixture data are unchanged.

| Finding | Resolution in the third revision | Reference now |
|---|---|---|
| N6. Submitted R7 set | §8 requires round-closure evidence for rounds 1–7. Round 7 is the canonical list of submitted, well-formed `CONFIRMATION`s for this session, passed to `roundClosed(7, …)`. | Implemented: `round7_list` (byte-identical copies once, ordered by sender then bytes as in §6), and a modelled `roundClosed(7, …)` that accepts only the list actually broadcast. In `finding.N6_round7_closure`, participants 1 and 2 abort with A7, the full set is refused (`differing_t_plus_1`), and the subset is refused (`round7_not_closed`). |
| N7. Equivocation in R7 | An equivocating `QUAL` member, with two different confirmations, counts as differing only, never as matching, for both A7 and admission | Implemented. Cases: `rule.admission_2of4_equivocator_differing_only=refuse` (the old reading would admit), `rule.admission_2of4_two_equivocators_t_plus_1_differing=refuse`, `rule.admission_2of4_one_equivocator_ignored=admit`, `rule.admission_3of5_equivocators_differing_only=refuse` (formerly `..._counted_in_both_sets_N7=admit`), `rule.admission_3of5_one_equivocator_among_all=admit`, `abort.A7_3of5_equivocators_count_as_differing=A7`, `abort.A7_2of4_one_equivocator_ignored=none`. |
| N8. Differing rule unobservable at `n = 2t + 1` | No new spec vector; the Java side tests `n = 2t + 2` directly | The test-only 2-of-4 configuration is kept. |

#### Fourth revision (after an independent review)

Every fixture value and digest is unchanged. The A7 and admission outputs changed, and new
cases and the `case.*` vectors were added. The `admission_*` keys that ended in `_N2` and
`_F13` were renamed.

| Change | Spec | Reference now |
|---|---|---|
| (a) A9 | New participant abort: own `COMPLAINT` missing from the delivered R2 set, checked when R2 closes. An A9-aborted dealer stays in `QUAL` if uncomplained; its `z_j` is published by reconstruction, and `x` stays secret. | Implemented. `abort.A9_own_complaint_not_delivered` reproduces the §5.1 paragraph. |
| (b) A7 matching clause | A7 also fires when fewer than `t + 1` distinct `QUAL` members sent a confirmation equal to the participant's own. The participant's own counts only if delivered back. An equivocator is differing, never matching. | Implemented. New cases: `A7_2of3_only_own_delivered_too_few_matching`, `A7_2of3_own_not_delivered_back_*`, `A7_3of5_two_silent_members_too_few_matching`, `A7_3of5_equivocator_not_matching`, `adversarial-4of7.check.A7_on_fewer_than_t_plus_1_matching`. Existing A7 cases now include the checking participant's own confirmation. |
| (c) §4 channels | A `SHARE` only on the private channel, addressed to the recipient; every other kind only on broadcast | Implemented: `rule.channel_*`. |
| (d) §8 delivered set and `roundClosed` | `roundClosed(config, r, list)`; the delivered set drops malformed, other-session, other-round, `SHARE` and unauthenticated posts; the round-7 list holds authenticated confirmations only, from any sender, in §6 order | Implemented: `delivered_round`, `round7_list`, `rule.admission_junk_posts_do_not_veto`, `rule.admission_round_omitted_refused`, `check.rule.delivered_round_drops_junk`, unauthenticated cases. N9 (round-7 order and non-`QUAL` senders) is resolved by this text. |
| (e) §5.2 | Late private `SHARE`s are a secrecy precondition; descriptive, no rule change | `finding.S52_late_shares_reveal_key`: a documented model limitation, not a defect. |
| Review finding R7 | Java replays only the 6 fixtures | Rule, abort, finding, well-formedness, admission, combine and parameter cases emit `case.*` vectors (109 at this revision). The sixth revision lists the cases that still have none. |
| §11 table | The spec now pins values in its §11 table | `spec_match.table.*` compares them. The pins were copied from this reference's earlier output, so these are drift checks, not independent evidence. |

#### Fifth revision

| Finding | Resolution in the fifth revision | Reference now |
|---|---|---|
| N10. `SHARE` or `CONFIRMATION` among the transcript messages | §8 step 2: every transcript message must be a broadcast message of rounds 1–6. A well-formed `SHARE` or `CONFIRMATION` among them is **refused**, like a malformed one. | Implemented (reason `non_broadcast_transcript_message`). `admission_share_in_transcript_ignored_N10=admit` was replaced by `rule.admission_share_in_transcript_refused=refuse`, and `rule.admission_confirmation_in_transcript_refused=refuse` was added. Both are replay vectors (111 in all). |

#### Sixth revision (round-3 review of the Java replay)

| Item | Spec / request | Reference now |
|---|---|---|
| R10. Distinct roster keys | §1: roster keys must be pairwise distinct; a roster with equal keys is rejected | `validate_params` rejects duplicates. New cases `rule.param_duplicate_keys` (`roster=hex:01,01,03`, reject), `rule.param_duplicate_keys_standard_length` (reject) and `rule.param_distinct_hex_keys` (accept). The `lengths:` format now means "`key_j` is the byte `j` repeated", so its keys are distinct. The replay no longer builds `b"a"` twice. |
| R11. Parameter sessions | Replay should compare the derived session | Every accepting `param_*` vector carries `session`. New case `rule.param_attempt_2_64_minus_1` (accept). |
| R8. Refusal step | §8 steps 2–3 now say "every transcript message" | Every admission vector with `expect=refuse` carries `step`. Step 3 is modelled, with a new vector `rule.admission_unauthenticated_transcript_message_refused` (`step=3`). `check.rule.admission_refusal_steps` checks the mapping independently. |
| R9(a) | Malformed or other-session transcript messages | Vectors with `order=submission` (`step=2`). |
| R9(b) | Participant-only aborts | Vectors for `abort.A2_boundary_silent_dealer_1_participant_check` and `abort.A8_withheld_extraction_dealer_aborts` (public outcome). |
| R9(c) | Unverified bad share | `rule.combine_unverified_bad_share_in_S_not_5`, `expect=not_plaintext:5`. |
| R9(d) | Closure cases | `closure=board` with `board.<r>.<i>` for `r = 1 … 7` and the board model. Vectors cover the junk-posts case, the omitted round, the round-7 honest run, a new omitted confirmation (`step=6`), and N6 (split into `finding.N6_round7_closure_full_set` and `_subset`). |
| R9(e) | Unauthenticated cases | `unauthenticated.<i>`, with `authenticate(bytes)` false iff listed. |
| R9(f) | What cannot be replayed | Listed under "Notes on the vectors": the 20 A7 cases and the N6 summary, with reasons. |
| §8 step 2: duplicates | "Byte-identical duplicates among the submitted messages count once … not refused" | New vector `rule.admission_duplicate_transcript_messages_count_once` (`order=submission`, admit). |
| N11. Byte-level key distinctness (raised here; resolved in the spec) | §1 now says the check compares bytes and that an application with several key encodings must canonicalize | No change: the reference already compares bytes. |
| N12. Early posts (raised here; resolved in the spec) | §5 and §8 step 4 now define round `r`'s delivered set as messages of round `r` that arrived while round `r` was open; an early message is dropped, not carried forward | No change: the per-window reading is the one the board vectors encode (`admission_junk_posts_do_not_veto` drops an early round-2 `COMPLAINT` posted on `board.1`). |

#### Seventh revision (round-4 review)

| Item | Spec | Reference now |
|---|---|---|
| R14. Unauthenticated confirmations are ignored, not differing | §8 step 6 | `rule.admission_t_plus_1_unauthenticated_lies_ignored` (admit). The setup is 3-of-5: all five matching confirmations, plus well-formed differing confirmations from `QUAL` members 1, 2 and 3 (`t + 1`) listed in `unauthenticated.*`. Counting them as differing would refuse. The control, `rule.admission_t_plus_1_authenticated_lies_refused`, has the same lies authenticated: 1, 2 and 3 equivocate, so `t + 1` differ (refuse, `step=6`). |
| R15. The round-7 list includes non-`QUAL` senders | §8 step 6 | On adversarial-4of7, participant 3 is outside `QUAL`. `rule.admission_adversarial_4of7_round7_list_includes_non_qual` (`closure=board`) has `board.7` holding the four `QUAL` confirmations plus participant 3's, and the submitted `confirmation.*` include it: admit. The control, `rule.admission_adversarial_4of7_round7_non_qual_omitted_refused`, omits participant 3's confirmation from `confirmation.*` while `board.7` keeps it, so the round-7 list differs from the delivered set (refuse, `step=6`). |

Case count 134 (rule 81); check count 514. The other values are unchanged.

### Findings against the first revision (N1–N5, resolved by the second revision)

- **N1. §5.1 does not say when each check is evaluated, or that an aborted participant falls
  silent.**
  - Only the §11 fixture says "aborts with A8 when R5 closes" and "a participant that aborts
    sends nothing afterwards". Yet the fixture's bytes depend on both.
  - Dealer 1 knows when R4 closes that its own `EXTRACTION` is absent. If A8 fired then,
    dealer 1 would not send its R5 complaint, and the round-5 count would be 4, not 5.
    Firing A8 only after R6 instead would let dealers 1 and 5 reconstruct each other, making
    the round-6 count 10.
  - The reference evaluates A1 and A2 when R3 closes, A8 when R5 closes (before R6), A3–A6
    after R6, and A7 in R7, and an aborted participant sends nothing afterwards. Mutation
    testing confirms that the fixture detects the R4 timing.
  - §5.1 should state the timing and the silence rule normatively.
- **N2. A single faulty `QUAL` member can veto any run** (design question, escalate).
  - Under R7 with A7, and now §8 step 6, one authenticated, differing `CONFIRMATION` from any
    `QUAL` member makes honest participants abort and admission refuse. A participant that
    aborted can still send one.
  - The demonstrations are `admission_n_minus_1_good_plus_differing_veto_N2=refuse` and
    `adversarial-4of7.check.admission_refuses_differing_qual_confirmation`.
  - GJKR07 New-DKG is robust: with at most `t` faults it always produces output (C1′). The
    spec gives up guaranteed output for agreement checking, and since every retry needs a new
    attempt, a faulty member can veto every attempt.
  - This is a defensible trade-off, but the spec should state it, for example as a §12
    non-goal or a §5.1 note.
- **N3. Malformed or wrong-session confirmations at admission.**
  - §8 step 6 refuses on any authenticated `QUAL` confirmation that "differs from the expected
    bytes". Read literally, that includes a malformed message, or a valid confirmation from
    another attempt of the same roster. A stale confirmation could then veto admission.
  - The reference ignores anything that is not a well-formed `CONFIRMATION` for this session,
    as A7 does (such messages are never delivered).
  - Demonstrations: `admission_wrong_session_confirmation_ignored_N3=admit` and
    `admission_malformed_confirmation_ignored_N3=admit`.
  - §8 should say so.
- **N4. The A8 paragraph slightly misdescribes the all-late case.**
  - It says R6 publishes the late dealers' polynomials and admission then fails for lack of
    confirmations. But because A8 fires when R5 closes, before R6, in the all-late case every
    honest participant has aborted before R6. The at most `t` faulty participants hold only
    `t` pairs per dealer, so **nothing is published**: the recomputation ends in A3 (and see
    `finding.F14_all_late_only_t_faulty_reconstruct`).
  - Polynomials are published only when some honest dealer was not marked
    (`finding.F14_partial_two_honest_late`: dealers 3 and 4 are reconstructed and the run is
    admitted). The unmarked honest dealer's contribution then keeps `x` secret.
  - The guarantee holds, but the explanation should say this.
- **N5. A8 costs liveness when an honest `EXTRACTION` is late.**
  - Every honest dealer whose `EXTRACTION` was late stops confirming. Admission needs `t + 1`
    matching confirmations, and in `adversarial-4of7` exactly `t + 1 = 4` participants
    confirm. One more late honest `EXTRACTION` would make that run unadmittable.
  - This is consistent with "assumptions stay assumptions", but it is worth one sentence.
    This is informative.

### Findings against the second revision (N6–N8, resolved by the third revision)

These are kept as written; the key names they cite were later renamed (see the table above).

- **N6. Admission's differing rule depends on which R7 confirmations are submitted** (design
  question, escalate).
  - A7 runs when R7 closes, after a participant has already sent its own `CONFIRMATION`. A
    matching confirmation can therefore come from an honest participant that then aborts
    under A7.
  - §8 asks for round-closure evidence only for rounds 1–6, so a submitter can omit
    differing confirmations.
  - Outside the agreement assumption, admission can then accept a run that every honest
    participant abandoned. The demonstration is
    `finding.N6_admission_depends_on_submitted_R7_set` on a test-only 2-of-4 configuration:
    - honest 1 and 2 saw one board; honest 3 and faulty 4 confirm another;
    - participants 1 and 2 abort with A7;
    - admission refuses when given all four confirmations, but admits when given only the two
      matching ones.
  - Step 6 still guarantees that an honest participant vouched for the record, but not that
    it kept it.
  - Options: require `roundClosed(7, …)` evidence for the confirmation set, or state that the
    differing rule protects only against complete inputs.
- **N7. Equivocation within R7 is not defined.** Rounds 1–6 define conflicts; R7 does not. The
  literal text counts a sender that sends both a matching and a differing confirmation in
  both of §8's sets, and as differing for A7. The reference implements that
  (`rule.admission_equivocators_counted_in_both_sets_N7=admit`,
  `abort.A7_3of5_equivocators_count_as_differing=A7`). With at most `t` faulty participants
  the guarantee is unaffected, but an implementation that drops conflicting senders would
  count differently. The spec should say which reading applies.
- **N8. With `n = 2t + 1`, the differing rule is not observable.** Matching ≥ `t + 1` leaves at
  most `t` other senders, so "differing ≤ `t`" holds automatically unless someone
  equivocates. Every §11 fixture has `n = 2t + 1`, so none of them can tell an implementation
  that skips the differing rule from a correct one. This reference isolates the rule with a
  test-only 2-of-4 configuration (`ctx "zeroj.test.reference-only.2of4"`, which is not a spec
  vector). §11 could add an admission vector with `n ≥ 2t + 2`.

### Notes on the third revision

- **N9 (minor wording, resolved by the fourth revision).** §8 said "the canonical list" for
  round 7, but §6 defined the ordering only for rounds 1–6 of the transcript. It also did not
  say whether `CONFIRMATION`s from senders outside `QUAL` belong in the list. The reference
  applied §6's rule and included non-`QUAL` senders, which is what the spec now says.

### Notes on the fourth revision

- **N10 (resolved by the fifth revision: refused).** §8 step 2 required each transcript
  message to be well-formed for this session, and a `SHARE` or `CONFIRMATION` is well-formed.
  The reference first read such an input as ignored. The spec now refuses it, like a malformed
  message. See the table above.

Not covered here:
- the real application callbacks `authenticate` and `roundClosed` of §8. They are modelled:
  authentication per input, and closure as "equals the delivered set of the true board";
- context equality (§9);
- DLEQ proofs: the shares are local, so they count as verified;
- the in-circuit relations.

## GJKR07 Fig. 2 against the spec

**Agrees.**
- Pedersen-VSS commitments `C_ik = [a_ik]·G + [b_ik]·H`, and checks (4) and (5).
- Disqualification for more than `t` complaints, or for an answer that falsifies (4).
- `QUAL`, and `x_j = Σ_{i∈QUAL} s_ij`.
- Feldman extraction `A_ik`, and the extraction complaint "values that satisfy (4) and not
  (5)".
- Public Pedersen-VSS reconstruction of every dealer with a valid complaint.
- `y = Σ_{i∈QUAL} A_i0`, and keeping a reconstructed dealer's contribution (§4.2).
- `t < n/2`.
- The verification keys `Y_j` are the paper's `g^{x_j}` of (C1′).

**The spec adds** (none of it contradicts Fig. 2):
- **Absent or conflicting messages.** R1 conflicts, a missing `ANSWER` meaning
  disqualification, and R4 marking on an absent `EXTRACTION`. R4 comes from the §4.2 prose
  ("refusing to carry on the Feldman-VSS"); Fig. 2 step 4(c) itself reconstructs only after a
  valid complaint.
- **Deterministic reconstruction.** The `t + 1` lowest senders, consistency of the rest, and
  the A3 and A4 aborts.
- **Everything else outside Fig. 2.**
  - aborts A1–A8;
  - confirmation;
  - transcript, digest and admission;
  - threshold decryption, which comes from [CGS97], not GJKR07.

**The spec omits** `x'_j = Σ s'_ij` (Fig. 2 step 3), which no output needs. Reconstruction
uses only `RECONSTRUCTION` messages, not the pairs already published in R3 answers or R5
complaints. Fig. 2 is silent on that point, so this is not a contradiction.

**The model differs.** GJKR07 assumes a synchronous network with reliable broadcast and private
channels, and its protocol always produces output. The spec closes rounds by deadline, treats
late messages as absent, and aborts rather than exclude a participant. Under the paper's model
the two produce the same outputs. Outside it:
- A8 closes the key-exposure gap of finding 14 for **late `EXTRACTION`s only**.
- Late private `SHARE`s remain the documented §5.2 limitation: the honest dealer's public
  answer gives the faulty coalition the `(t + 1)`-th point (`finding.S52_late_shares_reveal_key`).
- A9 makes a participant whose own complaint was lost fall silent.
- The threshold A7 restores robustness against up to `t` lying confirmations (N2).
- Round-7 closure and the equivocation rule (N6, N7) govern R7, which is the spec's own
  addition.

No statement of the spec contradicts Fig. 2.
