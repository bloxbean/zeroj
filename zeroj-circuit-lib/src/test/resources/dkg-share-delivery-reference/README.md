# DKG share delivery with HPKE v1: independent reference

This is an independent reproduction of the `dkg-share-delivery-hpke-v1` transport profile
(ADR-0054, milestone M0). It covers HPKE Base mode from RFC 9180, the announcements, the key
directory, abort T1, the envelopes, the processing barrier, the D7a posting order and the
exposure counting rule. It was written from the spec, the RFC texts and the existing Python
reference of the threshold DKG. Its output is evidence for checking ZeroJ's Java implementation.
It is not a security proof. The composition argument (Assumption A1) stays an external-review
gate.

## Files

- `dkg_share_delivery_hpke_v1_reference.py`: Python 3. It uses pyca `cryptography` 46.0.5 for
  four things only: X25519, HMAC-SHA256, ChaCha20Poly1305, and HKDF (HKDF only as a
  differential). Everything else uses the standard library. It contains:
  - **HPKE, from the RFC 9180 text:**
    - LabeledExtract and LabeledExpand (§4);
    - DHKEM(X25519, HKDF-SHA256): Encap, Decap, ExtractAndExpand and `kem_context` (§4.1);
    - DeriveKeyPair (§7.1.3);
    - KeySchedule, with VerifyPSKInputs (§5.1);
    - a context with a sequence number, ComputeNonce, the overflow error and Export (§5.2, §5.3);
    - SealBase and OpenBase (§6.1);
    - the all-zero DH check (§7.1.4), for both sender and recipient.

    HKDF Extract and Expand are written from RFC 5869 on pyca's HMAC. A pure-Python X25519
    ladder, transcribed from RFC 7748 §5, is used as a differential. It also evaluates
    small-order inputs, which pyca refuses.
  - **The profile:**
    - canonicality and the small-order probe (§2);
    - announcements, the directory and T1, including its key-mismatch clause (§3);
    - `info`, sealing, and the 6-step opening rule, with de-duplication only after
      authentication (§4);
    - a board with windows, cutoffs, processing lags, the barrier and D7a (§5);
    - the counting rule (§6);
    - session-bound, destroyable recipient keys (§7);
    - the test keys `sk(tag)` (§9.1).
  - **DKG mechanics:** imported from
    `../elgamal-threshold-reference/elgamal_jubjub_threshold_v1_reference.py`, not
    reimplemented. That covers `Config`/session, the §11 dealings, `SHARE`/`COMMITMENTS`
    encodings, `parse`, `simulate` (rounds 1–7, `QUAL`, complaints, answers, aborts),
    `delivered_round` and the transcript digest. Decrypted `SHARE`s enter `simulate` only
    through its private channel (`Script.private_raw`). No transport message enters a DKG
    round.
- `reference-output.txt`: the output, one `key=value` per line, sorted by key, with no header.

## Running

```
cd zeroj-circuit-lib/src/test/resources/dkg-share-delivery-reference
python3 dkg_share_delivery_hpke_v1_reference.py
```

The run takes about 10 s. It prints the output and rewrites `reference-output.txt`.
- **Exit status:** 0 if every check passes. Otherwise 1, with the failing keys on stderr; a crash
  also gives 1.
- **Determinism:** the output depends only on the code and the vendored inputs. It contains no
  Python version and no timing. Two runs, and runs with `PYTHONHASHSEED` set to 0, 1 and 12345,
  gave byte-identical files (SHA-256 at the end of this README).

## Independence

Read:
- `docs/specs/dkg-share-delivery-hpke-v1.md`, `docs/adr/0054-hpke-dkg-share-delivery.md` and
  `docs/specs/elgamal-jubjub-threshold-v1.md`. During the work, an informative paragraph about
  this profile was added to §5.2 of that spec; it changes no rule;
- the RFC texts: RFC 9180, RFC 7748, RFC 8439 and RFC 5869;
- the vendored vectors in `../standard-vectors/` and their README;
- the threshold reference's README and Python source.

The spec was read again at its second revision (resolving S1–S7), with the same rules.

Not read: any Java source (`*/src/main/java`, `*/src/test/java`) and any other ZeroJ code. A
`git diff --stat` printed some Java file names, but no Java content was opened.

Every expected value of the primitives comes from published vectors: the RFC texts, the CFRG
A.2.1 JSON and Wycheproof. The profile vectors are this reference's own outputs. Where the code
could have got one of them wrong, a hand-written intent check states the outcome the case was
built to show (see "Checks").

## Results

This README describes the run against the **second revision** of the spec, which resolves
findings S1–S7 of the first run (see "Spec findings").

All 294 checks pass. There are 110 replayable vectors, and each replays from its own keys.

| Area | Result |
|---|---|
| RFC 9180 A.2.1 | `DeriveKeyPair(ikmE)` and `DeriveKeyPair(ikmR)` give `skEm`/`pkEm` and `skRm`/`pkRm`. `enc`, `shared_secret` (Encap and Decap), `key_schedule_context`, `secret`, `key`, `base_nonce` and `exporter_secret` all match. **All 257 encryptions (sequence numbers 0–256) match**, sealed and opened through one sender context and one receiver context, with each nonce checked against `base_nonce XOR seq`. All 3 exported values match on both sides. Single-shot SealBase/OpenBase matches. Wrong `info`, wrong `aad`, wrong key and an out-of-sequence ciphertext are refused, and sequence overflow raises. |
| RFC 7748 | §5.2: both vectors and the 1-iteration and 1,000-iteration results match, through pyca and through the ladder. The 1,000,000-iteration result is not run, for cost. §6.1: Alice's and Bob's public keys and `K` match. |
| Wycheproof X25519 (518 tests) | All 518 pass. See "Handling of acceptable cases" below. |
| RFC 8439 §2.8.2, Wycheproof ChaCha20-Poly1305 (325 tests) | The KAT seals and opens, and a modified tag is refused. Wycheproof: 256 valid tests seal to `ct‖tag` and open. 69 invalid tests fail to open: 60 have a modified tag, and 9 have a wrong nonce size. |
| RFC 5869 A.1–A.3, Wycheproof HKDF-SHA256 (86 tests) | PRK and OKM match. 83 valid tests match, both in this reference's HKDF and in pyca's. 3 invalid tests (`SizeTooLarge`) are refused by both. |
| §2.2 claim | Verified independently (see "Small-order points"). |

### Handling of "acceptable" Wycheproof X25519 cases

The file has 264 `valid` tests, 254 `acceptable` tests and no `invalid` ones.

| Category | Count | Handling |
|---|---|---|
| `valid` | 264 | pyca, the ladder and the HPKE `DH` all give `shared`. Every public value is canonical. |
| `acceptable`, non-zero `shared` (twist, non-canonical or edge-case public values) | 223 | **Computed.** pyca and the ladder both give `shared`, as RFC 7748 §5 requires the X25519 function to accept these values. At the profile layer, the 13 with a non-canonical public value would be refused before any X25519 call (§2.1). The other 210, including twist points, are canonical and pass the probe. |
| `acceptable`, all-zero `shared` (`ZeroSharedSecret`) | 31 | **Refused.** The ladder gives `0^32`, pyca raises, and the HPKE `DH` raises `ValidationError` (RFC 9180 §7.1.4). At the profile layer, all 31 public values fail canonicality or the probe. |

pyca raises exactly on the all-zero output. That was checked against the ladder on every
Wycheproof input and every small-order point.

### Small-order points (§2.2)

There are exactly 5 canonical small-order u-coordinates: `0`, `1`, the two order-8 values, and
`p − 1`. They were found two independent ways:
- **From Wycheproof:** reduce every public value with an all-zero shared secret (mask bit 255,
  then reduce mod `p`).
- **Algebraically:** the order-2 points (`x = 0`, and the roots of `x² + Ax + 1`, which have none
  in `F_p`). Then repeated x-only halving, solving `x(2P) = c` through `w = x + 1/x`.

The two sets are equal (`check.small_order.algebraic_equals_wycheproof_set`). There are no
order-16 points.

The spec's claim was then checked in both directions:
- `X25519(k, u) = 0^32` for `PROBE` and for five other test scalars, on every small-order `u`;
- `X25519(PROBE, u) ≠ 0` for every other public value in the file.

The reason, in brief: a clamped `k` is `8m` with `2^251 ≤ m < 2^252`, which is below both the
curve's prime order `l` and the twist's `l'`. So `[k]P = O` exactly when the order of `P`
divides 8.

## Output keys

| Key | Content |
|---|---|
| `profile`, `profile.*` | The suite, `TAG_A`, `TAG_I` and `TAG_E` with their lengths, `PROBE`, and the §9.1 prefix. |
| `session.<config>` | The threshold-profile sessions used: `honest-2of3`, `honest-3of5` and `honest-4of7` (`ctx = "zeroj.test.honest"`, attempt 1, threshold §11 roster). `*-attempt2` is the same configuration at attempt 2. |
| `small_order.*` | The Wycheproof-derived and algebraic sets, in hex of the big-endian integer. |
| `check.*` | Checks, each `true` or `false`. |
| `info.*` | Informative values, which are not checks. Among them: the Wycheproof counts per category (`info.wycheproof.*.count.*`), the failed test ids (empty), `info.rfc9180.a21.encryptions.*`, the per-trace values `info.timing.*`, `info.case_count.*`, `info.check_count` and `info.failed_checks`. |
| `case.<family>.<name>.*` | Replayable vectors (below). |
| `result` | `pass` or `fail`. |

Value conventions:
- byte strings are bare lowercase hex;
- lists of ids are comma-separated and may be empty;
- `i->j` pairs are comma-separated, sorted, and mean (sender, subject):
  - a complaint `j->i` is "participant `j` complains about dealer `i`";
  - an answer `i->j` is "dealer `i` answers complainer `j`".

## Test keys

All keys are `sk(tag)` of spec §9.1: `SHA-256("zeroj.dkg-share-delivery-hpke.v1.test." ‖ tag)`.
The tag scheme below is normative since the second revision (§9.1).
The 32 bytes are used directly as an X25519 scalar, which X25519 clamps; they are **not** passed
through DeriveKeyPair. Then `pk = X25519(sk, 9)`. Production keys must come from a secure
generator (§2.3).

| Tag | Use |
|---|---|
| `<prefix>.recipient.<j>` | Participant `j`'s recipient key. The prefix is the fixture (`honest-2of3`, …), `timing.<case>`, `directory`, `directory.conflicts`, `envelope`, `envelope.attempt2` or `announce`. |
| `<prefix>.ephemeral.<i>.<j>` | The ephemeral key of envelope `i → j` in a board scenario. |
| `envelope.ephemeral.<case>` | The ephemeral key of a sealed `envelope` case. The good case uses `envelope.ephemeral.good`. |
| `directory.recipient.3.second`, `directory.forged.2`, `directory.other_session.1`, `directory.recipient.1.late`, `directory.conflicts.recipient.<j>.second`, `directory.<case>.substitute.2` | Extra announced keys in the directory cases. |
| `small-order.scalar.<k>` | The extra scalars used for the §2.2 claim. |

Every ephemeral tag is used once, and every test key is distinct
(`check.lifecycle.ephemeral_tags_never_reused`, `check.lifecycle.all_test_keys_distinct`).

## Replayable vectors

Counts: `announce` 21, `envelope` 42, `directory` 4, `run` 3, `timing` 16, `exposure` 24, so
110 in all. `config` is always `t,n,ctx-hex,attempt`, and the roster is the threshold §11 standard
one (`key_j` = 32 bytes, each equal to `j`).

### `case.announce.<name>.*` (§3.1 well-formedness)

| Key | Content |
|---|---|
| `config` | The configuration the announcement is checked against (`honest-2of3`). |
| `bytes` | The announcement. |
| `expect` | `accept` or `reject`. |
| `reason` | Informative: `length_or_tag`, `session`, `index`, `non_canonical`, `small_order` or `none`. The spec sets no precedence among reasons. |
| `u` | `small_order_<k>` only: the small-order `u`. |

Cases:
- accepted: `well_formed_j1`, `well_formed_j_n`, `canonical_u_p_minus_2` (the largest canonical
  value that is not small-order) and `canonical_base_point_u_9`;
- rejected:
  - `wrong_tag_first_byte`, `tag_of_envelope`, `length_105`, `length_107`;
  - `other_session` (attempt 2), `j_zero`, `j_n_plus_1`;
  - `non_canonical_bit255_set`, `non_canonical_u_p`, `non_canonical_u_p_plus_1`,
    `non_canonical_u_p_plus_9`, `non_canonical_u_2_255_minus_1`;
  - `small_order_1` … `small_order_5`, all five canonical small-order points.

Authentication and windows are not part of well-formedness. The directory vectors cover them.

### `case.envelope.<name>.*` (§4.2 acceptance)

| Key | Content |
|---|---|
| `config` | Mostly `honest-2of3`. The cross-attempt cases use attempt 2. |
| `recipient` | `j`, the participant that opens the envelope. |
| `recipient_key_tag` | `j`'s key, `sk(tag)`, bound to `(config session, j)`. |
| `auth`, `bytes` | One envelope and the participant its post is authenticated as (`none`: unauthenticated). Multi-envelope cases use `auth.<k>` and `bytes.<k>`. |
| `expect` | Envelopes are processed in the listed order. `share:<hex>` (one `SHARE` delivered), `absent`, or `shares:<hex>,<hex>` (two different `SHARE`s, which the threshold profile treats as a conflict, so `j` complains). |
| `step` | Informative: the first §4.2 step that fails (1–6), or `none` (for several envelopes: `none` if any is accepted). |
| `good` only: `info`, `enc`, `ct`, `plaintext`, `pkR`, `ephemeral_tag`, `shared_secret`, `key`, `base_nonce`, `key_schedule_context` | Intermediate values, for debugging. |

The cases are listed below. Dealer 1 seals to recipient 2 unless the name says otherwise. The
step that fails is in parentheses.
- Delivered:
  - `good`;
  - `duplicate_byte_identical`: one share;
  - `duplicate_unauthentic_copy_first`: a byte-identical copy authenticated as 3 is listed before
    the genuine envelope. Each is authenticated on its own (step 3) before de-duplication, so the
    copy fails and the genuine one delivers the share.
    `check.envelope.duplicate_unauthentic_copy_first.dedup_before_auth_would_lose_share` shows
    that de-duplicating first would lose it;
  - `reencrypted_same_share`: two different envelopes of the same `SHARE` give one share (§4.2);
  - `canonical_enc_u_9_control`: `enc = 9`, so the DH output is `pkR`, which is public. It is
    accepted: a dealer can always reveal its own share.
- Two shares: `two_different_shares_conflict`.
- Absent:
  - (1) `truncated_222`, `extended_224`, `wrong_tag_first_byte`, `tag_of_announce`,
    `plaintext_99_bytes`;
  - (2) `wrong_session_header`, `sender_zero`, `sender_n_plus_1`, `self_envelope_i_equals_j`,
    `wrong_recipient_header_seen_by_2`, `cross_attempt_replay` (an attempt-1 envelope seen in
    attempt 2);
  - (3) `wrong_sender_header_auth_mismatch`, `unauthenticated`;
  - (4) `non_canonical_enc_bit255_set`, `non_canonical_enc_u_p_plus_9`,
    `non_canonical_small_order_enc_u_p`, `non_canonical_small_order_enc_u_p_plus_1`;
  - (5) `reposted_by_other_sender` (header and authentication say 3), `wrong_recipient_key`,
    `wrong_recipient_header_opened_by_3`, `tampered_enc_byte0`, `tampered_ct_byte0`,
    `tampered_tag_last_byte`, `small_order_enc_1` … `_5`, `cross_attempt_replay_header_rewritten`
    and `cross_attempt_replay_header_rewritten_key_reused` (the attempt-1 key reused, against
    §7);
  - (6) `plaintext_answer_message`, `plaintext_random_100_bytes`, `plaintext_share_wrong_sender`,
    `plaintext_share_wrong_subject`, `plaintext_share_other_session`,
    `plaintext_share_scalar_not_below_l`.

The adversarial `enc` cases are built so that only the check named refuses them:
- the non-canonical ones encrypt under the `kem_context` of the non-canonical bytes;
- `u = p + 9` uses the DH output `X25519(skR, 9) = pkR`;
- the small-order ones encrypt under a DH output of `0^32`.

`check.envelope.*.opens_without_step4` and
`check.envelope.small_order_enc.all_open_without_zero_check` show that OpenBase would deliver
the share if step 4, or the all-zero check, were skipped.

### Board vectors: `case.directory.*`, `case.timing.*`

The board model:
- Times are integers. Round 0 is the window `[0, cut0)`, and round 1 is `[cut0, cut1)` (`cut0 =
  10`, `cut1 = 20`). A post's time is its inclusion and finality time. A post outside its round's
  window belongs to no window; in particular round 1 opens when round 0 closes (§5).
- In each window, every post is first authenticated on its own (announcements §3.1, envelopes
  §4.2 step 3, `COMMITMENTS` threshold §4–§5), and only then are byte-identical copies counted
  once. With `dedup_before_auth=true` (negative control only), posts are de-duplicated by bytes
  first, keeping the earliest, which is the defect the spec forbids.
- Participant `j` finishes processing post `p` at `p.time + lag(j, p)`. The default lag is 0.
- With `barrier=true` (§5.1), each participant uses every post of the final window. With
  `barrier=false` (negative control), it closes at the cutoff and uses only the posts it
  finished processing before then.
- Rounds 2–7 are run by the threshold reference's `simulate`, with timely broadcast. Each
  participant's private deliveries are the `SHARE`s accepted by §4.2 from the envelopes it
  processed.
- T1 (§3.3) fires when the participant's directory has no key for it, or a key other than the
  one it holds (`recipient_key_tag.<j>`). A T1 participant posts nothing after round 0: no
  complaint and no answer. Participants in `t1_ignored_by` are corrupted and deviate: they do
  not apply T1.
- `extra_complaint` entries are additional round-2 `COMPLAINT`s posted by corrupted
  participants.

| Key | Content |
|---|---|
| `config`, `cut0`, `cut1` | The configuration and the window cutoffs. |
| `barrier`, `d7a`, `t1_rule` | `true` or `false`; `false` marks a negative control. `d7a` affects only how the board was generated: the posts are given, and replay does not need it. |
| `corrupted` | The adversary's set, for the coalition analysis and for I15. |
| `t1_ignored_by` | Deviating participants that do not apply T1. |
| `dedup_before_auth` | `true` only in the two front-running negative controls. |
| `withhold_extraction` | Dealers whose round-4 `EXTRACTION` is not delivered. |
| `recipient_key_tag.<j>` | Each participant's recipient key. |
| `post.<k>` | `time,author,label,hex`. `author` is the authenticated sender. `label` names the post (`announce.<j>[.<variant>]`, `envelope.<i>.<j>`, `commitments.<i>[.early]`; a front-running copy is `<label>.copy_by_<c>`, one tick before the original) and keys the lags. Labels are informative apart from lags. Posts are sorted by (time, author, label, bytes). |
| `lag.<j>.<label>` | A non-zero processing lag. |
| `extra_complaint.<k>` | `c->d`: corrupted `c` complains about dealer `d`. |
| `expect.directory.<j>` | `j`'s key in the directory of the final round-0 window, or `none`. |
| `expect.t1` | The participants that abort with T1. |
| `expect.commitments` | The dealers with a `COMMITMENTS` in the round-1 window. |
| `expect.complaints`, `expect.answers` | The delivered round-2 and round-3 messages. |
| `expect.marked` | The dealers marked for reconstruction (R4, R5). |
| `expect.qual`, `expect.public_abort` | `QUAL`, and `none` or the public abort (A1, A3, A4, A5). |
| `expect.aborts` | `j:outcome` for every participant: `T1`, `none` or `A1`–`A9`. |
| `expect.digest`, `expect.y` | The threshold transcript digest and `encode(y)`, or `none`. |
| `expect.coalition_recovers_x` | Whether the corrupted set can compute `x`. It uses the shares the corrupted participants hold (received or answered), the public answers, and their own polynomials. Every recovered `z_i` is checked against the true value. |
| `expect.honest_answers_at_corrupted_indices_only` | I15: every answer from an honest dealer in `QUAL` goes to a corrupted index. |

The ephemeral key of `envelope.<i>.<j>` is `<prefix>.ephemeral.<i>.<j>`, where the prefix is
the `recipient_key_tag` prefix. Replaying the posts needs no ephemeral key.

Directory cases:
- **`mixed_window_3of5`** (`honest-3of5`, corrupted `{5}`). The posts:
  - participant 2 posts its announcement twice, byte for byte;
  - participant 1 posts a forged announcement with header `j = 2`, which authentication refuses;
  - participant 3 posts two different well-formed keys;
  - participant 4's only announcement arrives at time 12, after the cutoff;
  - participant 5 posts a malformed announcement (bit 255 set) and a well-formed one that
    copies participant 1's key;
  - participant 1 also posts an announcement for another session, and one more after the cutoff.

  The result:
  - directory `1:pk1, 2:pk2, 3:none, 4:none, 5:pk1`; 3 and 4 abort with T1;
  - copier 5 cannot open its envelopes, so it complains about 1 and 2, and the answers go to
    index 5;
  - `QUAL = {1, 2, 5}`.

  The copied-key checks show that participant 1 can decrypt an envelope sent to 5 but cannot be
  made to accept it as its own (D4).

  Under the second revision's T1, the directory's key for 5 (`pk1`) is not the key 5 holds, so
  an honest participant in 5's position would abort with T1. Participant 5 is corrupted and does
  not follow the rule: the vector keeps that behaviour and marks it with `t1_ignored_by=5`.
- **`two_conflicts_2of3_A1`.** Participants 2 and 3 each post two keys. Both abort with T1,
  `QUAL = {1}`, and A1 fires (`n − t = 2`). This is liveness only, with no complaints.
- **`substituted_key_T1_2of3`** (§3.3, second revision). Participant 2's genuine announcement
  misses the cutoff, and a different key authenticated as 2 (a misused roster key) is in the
  window. The directory gives 2 a key it does not hold, so 2 aborts with T1: `QUAL = {1, 3}`, no
  complaint.
- **`substituted_key_without_T1_negative_control`.** The same board without T1: 2 cannot open
  any envelope, complains about 1 and 3, and honest dealer 1 answers at honest index 2.

Timing cases (ADR-0054 M2):

| Case | Construction | Outcome |
|---|---|---|
| `late_processing_with_barrier` (2-of-3, corrupted 3) | Envelopes 1→2 and 2→1 included at 18 (`< cut1`), processed at 28 | No complaint. The digest equals the ideal-channel digest. 3 cannot recover `x`. |
| `late_processing_without_barrier_negative_control` | The same, closed by timer | Complaints `1->2, 2->1`, answers `1->2, 2->1` at honest indices. **Corrupted 3 recovers `x`** (the ADR-0054 review counterexample). |
| `delayed_announcement_with_barrier` | 2's announcement at 9, processed at 14 by 1 and 3 | The dealers seal after processing it. No complaint; the digest is the ideal one. |
| `delayed_announcement_without_barrier_negative_control` | Sealed at the cutoff without 2's key | 2 complains about 1 and 3. Answers `1->2, 3->2`: honest dealer 1 answers at an honest index. |
| `own_announcement_missing_T1` | 2's announcement at 10 (late) | 2 aborts with T1 and posts nothing more. `QUAL = {1, 3}`, no complaint. |
| `own_announcement_missing_without_T1_negative_control` | The same, without T1 | 2 deals, then complains about 1 and 3. Answers at index 2. |
| `envelopes_excluded_by_cutoff_D7a` (3-of-5, corrupted 3, 4) | Dealer 5's envelopes to 1 and 2 included at 22 | Under D7a, 5 posts no `COMMITMENTS`. R1 disqualifies it, no honest participant complains, and dealer 5 aborts with A2. `QUAL = {1, 2, 3, 4}`. |
| `envelopes_excluded_by_cutoff_without_D7a_negative_control` | `COMMITMENTS` posted on time | 1 and 2 complain, and 5 answers at 1 and 2. 5 stays in `QUAL`, and **`z_5` is exposed** to {3, 4}. `x` is not. |
| `adversarial_complaint_timely_I15` (trace i) | Timely delivery. Corrupted 3 complains about honest dealer 1. | One answer, `1->3`, at the corrupted index. `QUAL` is unchanged, and so is the exposure count. |
| `adversarial_complaint_withheld_commitments_I15` (trace ii) | 2's envelope to 1 is late, so under D7a there is no `COMMITMENTS`. Corrupted 3 complains about 2. | Dealer 2 answers `2->3` in round 3, then aborts with A2 when R3 closes. It is excluded from `QUAL = {1, 3}`, and 1 does not complain. |
| `front_run_envelope_copies` (2-of-3, corrupted 3) | At time 10, before the genuine envelopes 1→2 and 2→1 (time 11), 3 posts byte-identical copies authenticated as 3 | The copies fail authentication. No complaint, no answer, the ideal digest, and 3 cannot recover `x`. |
| `front_run_envelope_copies_dedup_before_auth_negative_control` | The same, de-duplicating before authentication | The copies shadow the originals. Complaints `1->2, 2->1`, answers at honest indices, and **3 recovers `x`**. |
| `front_run_commitments_copy` (2-of-3, corrupted 3) | At time 11, before dealer 1's genuine `COMMITMENTS` (time 12), 3 posts a byte-identical copy | Dealer 1 stays in `QUAL = {1, 2, 3}`. Ideal digest, no abort. |
| `front_run_commitments_copy_dedup_before_auth_negative_control` | The same, de-duplicating before authentication | Dealer 1's `COMMITMENTS` is lost for everyone. R1 disqualifies it, `QUAL = {2, 3}`, and dealer 1 aborts with A2. |
| `early_commitments_in_round0_S1` (2-of-3) | Dealer 1's only `COMMITMENTS` is posted at time 5, during round 0 | It is early and belongs to no window (§5). `QUAL = {2, 3}`, and dealer 1 aborts with A2. |
| `extraction_withheld_dealer_reconstructed` (2-of-3) | Dealer 3's `EXTRACTION` is withheld | R4 marks 3, which aborts with A8. 1 and 2 publish `RECONSTRUCTION` pairs, and `y` keeps `z_3`. The exposure family uses this trace. |

`check.timing.counting_rule_matches_actual_recovery_on_every_trace` confirms, on every trace
without a marked dealer, that the §6 rule applied to the corrupted set and the answers agrees
with what the coalition actually recovers. The trace with a marked dealer is covered by the
exposure family.

### `case.run.<fixture>.*` (full encrypted runs)

The fixtures are `honest-2of3`, `honest-3of5` and `honest-4of7`, with the §11 dealings.

| Key | Content |
|---|---|
| `config`, `coefficients` | The configuration. The coefficients come from the threshold spec's §11 tags. |
| `recipient_key_tag.<j>`, `pk.<j>`, `announce.<j>` | Round 0. |
| `ephemeral_tag.<i>.<j>`, `envelope.<i>.<j>`, `share.<i>.<j>` | Every envelope (`n(n − 1)` of them) and its decrypted `SHARE`. |
| `expect.digest`, `expect.qual`, `expect.y`, `expect.Y.<j>` | The outputs of the encrypted run. |
| `expect.ideal_channels_equal` | `true`: the digest equals that of the same run with ideal private channels. |

The checks also show:
- every plaintext equals the ideal `SHARE` byte for byte;
- `QUAL`, `y`, every `Y_j`, every `x_j` and the confirmations equal the ideal run's;
- the digest and `y` match the threshold spec's §11 pins (2-of-3 digest and `y`, 3-of-5 `y`,
  4-of-7 digest);
- the threshold `parse` and `delivered_round` refuse every announcement and envelope (I3).

### `case.exposure.<name>.*` (spec §6 counting rule, second revision)

The rule: dealer `i`'s known indices are:
- leaked recipient keys `j ≠ i` to which `i` actually sent an envelope;
- the corrupted participants;
- the public answers for `i`;
- the pairs published for `i` in rounds 5–6 (`EXTRACTION_COMPLAINT` and `RECONSTRUCTION`);
- every index, if `i` was reconstructed in round 6 or is corrupted.

`i` is exposed at `t + 1` known indices, and `x` when every dealer in `QUAL` is.

| Key | Content |
|---|---|
| `config`, `qual` | The configuration and `QUAL`. |
| `leaked`, `corrupted` | The chosen leaked recipient keys and corrupted participants. |
| `answers` | The public answers (`i->j`): chosen for the run cases, from the transcript for board cases. |
| `sent` | `i->j` for every authentic envelope posted by `i` to `j`, in or out of a window (reading R2-1). |
| `published` | `i->j`: a pair for dealer `i` at index `j` published in round 5 or 6. |
| `reconstructed` | The dealers reconstructed in round 6. |
| `source` | The vector whose board and keys the cross-check uses (`case.run.*` or `case.timing.*`). |
| `known.<i>` | The known evaluation indices of `f_i` under the rule. |
| `expect.dealer.<i>`, `expect.x` | `exposed` or `unexposed`. |

The run scenarios over `(n, t)` ∈ {(3, 1), (5, 2), (7, 3)} cover:
- `t + 1` and `t + 2` leaked keys alone;
- `t` corruptions with one or two leaked honest keys;
- one answer at an honest index, against one answer at a corrupted index;
- the ADR examples (`keys_1_2_adr_example`, which exposes `z_3` only, and
  `corrupt_4_5_key_1_answer_1_at_honest_2_adr_example`).

New with the second revision:
- `late_extraction.no_leak`: the former S2 example. With no leak and no corruption, dealer 3
  (reconstructed) is exposed with `known.3 = 1,2,3`, and `x` is not.
- `late_extraction.key_1_leaked`: still only dealer 3.
- `late_extraction.corrupt_1_key_3`: one corruption and one leaked key expose `x`, because
  dealer 3 is public. The same inputs on the plain run (`honest-2of3.corrupt_1_key_3`) leave `x`
  unexposed.
- `t1_participant_key_leaked_reveals_nothing`: on the T1 trace, participant 2 has no key, so no
  dealer sealed to it. Leaking its private key adds nothing: dealer 1 has only index 3 and is
  unexposed. The first revision's rule would have counted index 2 and called it exposed.

For every scenario, `check.exposure.*.rule_matches_reconstruction` recovers the actual shares:
- it opens the board's authentic envelopes with each leaked or corrupted recipient's key;
- it adds the answers and the pairs published in rounds 5–6;
- it interpolates every dealer the rule calls exposed, and checks the constant term, every known
  point, and `x` when exposed, against the dealing.

The late-extraction and T1 cases also carry an `intended_outcome` check written by hand,
including `known.3 = 1,2,3` on `no_leak`.

`check.exposure.enumeration.*` checks ADR-0054's claims over every subset, in the counting model
with every envelope sent:
- `t + 1` leaked keys never expose `x`, and `t + 2` always do;
- with `t` corruptions, one leaked honest key never exposes `x`, and two always do;
- adding one honest-index answer always exposes `x`, and answers at corrupted indices only never
  do.

## Checks

The checks fall into four groups:
- **Published known answers:** `rfc*`, `wycheproof.*`.
- **Drift checks:** `spec_match.s9_3.*` compares the 13 values of the spec's §9.3 table (the
  good envelope's `pkR`, `info`, `enc`, `shared_secret`, `key`, `base_nonce`, `ct`, and each run's
  digest and `y`). They were copied from this reference, so they guard against drift only.
- **Independent derivations:** `small_order.*`.
- **Intent checks:** each profile case states the outcome it was built for, by hand, and
  `check.<family>.<name>[.intended_outcome]` compares it with what the code computes. For
  envelopes, the intended §4.2 step is part of that.
- **Self-consistency:** `check.case_vectors_replay_self_consistent` replays every vector from its
  emitted keys alone. The `lifecycle.*`, `profile.*` and `run.*` checks cover lengths, tags, I3,
  I14 and §7.

Mutation testing was run on copies of the script, each with one defect. Every one of these was
detected, by a failing check or by a crash, which also gives exit 1:
- step 4 skipped;
- the ladder used as DH without the zero check;
- the barrier ignored;
- T1 removed;
- D7a ignored;
- `I2OSP(L, 2)` dropped from LabeledExpand;
- the probe removed;
- a conflict giving a key;
- step 3 skipped;
- self-envelopes allowed;
- the rule counting a dealer's own leaked key;
- a little-endian sequence number;
- `info` without the sender;
- a canonicality check that masks bit 255 before comparing with `p`;
- byte-identical announcements counted as a conflict;
- step 6 without the subject check;
- T1 without its key-mismatch clause (second revision);
- de-duplication before authentication, everywhere;
- the rule ignoring round-6 reconstruction (detected by the `known.3` intent; on outcomes alone
  it is equivalent, because the published round-6 pairs already reach `t + 1`);
- the rule counting leaked keys without an envelope.

Dropping only the explicit bit-255 rule, while comparing all 256 bits with `p`, is an
equivalent mutation (note N2).

**Limits.** These checks cannot detect a defect that the reference and a second implementation
share, such as a wrong `info` layout used on both sides. The Java implementation is meant to be
the independent check: it must reproduce these vectors byte for byte.

## Spec findings

### First run (S1–S7), resolved by the second revision

| Finding | Second revision | Reference now |
|---|---|---|
| S1. When round 1 opens | §5: round 1 opens when round 0 closes; a threshold message posted during round 0 is early and belongs to no window | Same reading as before. The demonstration is now a vector, `timing.early_commitments_in_round0_S1`. |
| S2. Counting rule omits rounds 5–6 | **Changed** §6: leaked keys count only where an envelope was sent; pairs published in rounds 5–6 count; a dealer reconstructed in round 6 is entirely public | Rule and exposure family updated. `rule_matches_reconstruction` holds on the late-extraction example (`late_extraction.*`). |
| S3. GenerateKeyPair citation | §2.3: GenerateKeyPair is RFC 9180 §4, 32 random bytes; DeriveKeyPair only for the RFC vectors | No change: `sk(tag)` is the scalar. |
| S4. Atomic posting | §5: a board property with no wire format; each contained message is authenticated and processed as if posted alone | No change: only the sequential option is modelled. |
| S5. Tag scheme | §9.1: the reference's tag scheme is normative | No change. |
| S6. Identical plaintexts; **de-duplication after authentication** | §4.2: identical plaintexts deliver one `SHARE`; **new**: de-duplicate only after step 3 | De-duplication was already per (authentication, bytes). Now explicit, with a negative-control mode and new vectors: `envelope.duplicate_unauthentic_copy_first`, `timing.front_run_*`. |
| S7. T1 and answers | §6: a participant that aborted with T1 answers nothing | No change. |
| — | **Changed** §3.3: T1 also fires on a key other than the one `j` announced | Implemented: T1 compares the directory key with the key `j` holds. New `directory.substituted_key_*` vectors. The corrupted copier in `mixed_window_3of5` keeps its deviating behaviour (`t1_ignored_by=5`). |

### Second revision (new)

- **R2-1. §6, "leaked recipient keys `j ≠ i` to which `i` actually sent an envelope": in a window
  or not?**
  - An envelope posted after the cutoff is not delivered, but it is on the public board, and a
    leaked key decrypts it all the same.
  - **Example:** in `timing.envelopes_excluded_by_cutoff_without_D7a_negative_control`, dealer 5
    stays in `QUAL`, and its envelopes to 1 and 2 are posted at time 22, after the cutoff. If
    `skR_1` leaks, `f_5(1)` is known.
  - **Reading used:** "sent" means any authentic envelope posted by `i` to `j`, in a window or
    not. Unauthentic copies carry the same ciphertext and add nothing.
  - The spec could say "posted (in any window or none)". **Resolved:** spec §6 now says so.
- **R2-2. §3.3, "a key other than the one `j` announced".**
  - Literally, the copier in `mixed_window_3of5` announced `pk1`, and the directory holds `pk1`,
    so T1 would not fire. The purpose of the rule, which is that `j` can open its envelopes, is
    about the key `j` holds.
  - The two readings differ only for a participant that announces a key it does not hold, which
    is a deviation in any case.
  - **Reading used:** compare with the key `j` holds (its `recipient_key_tag`). The copier is
    marked as not applying T1.
  - "Other than its own" (the key whose private key `j` holds) would remove the ambiguity.
    **Resolved:** spec §3.3 now says "other than its own".
- **R2-3. §6, round-5 and round-6 pairs (note; no change needed).**
  - Corrupted senders can publish pairs that are not on `f_i`, failing (4). They sit at
    corrupted indices, which are counted anyway, so counting them changes nothing.
  - "A dealer reconstructed in round 6 is entirely public" follows from the at least `t + 1`
    valid round-6 pairs. It changes the known set (all indices), not the exposed or unexposed
    outcome.

### Notes (no change needed)

- **N1.** RFC 9180 §7.1.2 says SerializePrivateKey "MUST clamp its output". The A.2.1 `skRm`
  and `skEm` are the raw DeriveKeyPair outputs and are not clamped
  (`info.rfc9180.a21.sk*_is_clamped=false`). The profile never serializes private keys.
- **N2.** In §2.1, rule 1 (bit 255 clear) is implied by rule 2 when `u` is decoded from all 256
  bits. It is needed when `u` is decoded with RFC 7748's mask. The vectors have bit-255 cases
  for both enc and pkR, so an implementation that masks and forgets rule 1 fails them.
- **N3.** RFC 7748 §5.2's second u-coordinate has bit 255 set: it is non-canonical for this
  profile, while the X25519 function computes it correctly.

## Not covered

- Real `authenticate` and `roundClosed` callbacks. Authentication is modelled per post, as the
  `author` field.
- Board timing after round 1. Rounds 2–7 are timely in every trace.
- Key storage and erasure. `destroy` is an API model: `check.lifecycle.open_after_destroy_refused`.
- The atomic posting option (§5: a board property; each contained message behaves as if posted
  alone).
- RFC 7748's 1,000,000-iteration vector.
- Any security argument for Assumption A1.

Output SHA-256 at this revision: `ce507fb8fdd38975a5a4d337bb350325b57fed89f37e67f0c390fa149da61b1f`. Two consecutive runs gave the same value.
