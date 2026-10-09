# Confidential notes on Jubjub v1: independent reference

This is an independent reproduction of the `confidential-note-jubjub-v1` profile (ADR-0055,
milestone M0). It covers the Sapling-style key agreement, the personalised KDF, the
ChaCha20-Poly1305 delivery, sealing for a reader list, the 7-step opening and acceptance rule,
reader-key validation, and the D3a auditor encodings (§8). It was written from the spec, the
Zcash protocol specification, the BLAKE2 paper, RFC 7693 and RFC 8439, and the existing Python
references. Its output is evidence for checking ZeroJ's Java implementation.

It is not a security proof. Assumptions A1–A3 (spec §7) stay external-review gates.

## Files

- `confidential_note_jubjub_v1_reference.py`: Python 3. It contains:
  - **Third-party primitive:** pyca `cryptography` 46.0.5, for ChaCha20Poly1305 only.
  - **Standard-library primitives:** `hashlib` for SHA-256 and for BLAKE2b with `person=`.
  - **Pure-Python BLAKE2b (differential):** written from RFC 7693 §2–§3, with the full
    parameter block of [BLAKE2] §2.8 Table 1. The personalization sits in bytes 48–63. It is
    used only as a differential against `hashlib`.
  - **Jubjub:** the arithmetic and `encode`/`decode` (all five `pedersen-jubjub-v1` §4 rules)
    are **copy-adapted** from `../pedersen-reference/pedersen_jubjub_v1_reference.py`. That
    file is itself an independent reference.
  - **What is imported from the pedersen reference:** that module is imported, never modified,
    for its Tonelli–Shanks square root and its Poseidon port. `H` is **derived** through its
    `derive_h`, then compared with the hand-transcribed pins of `pedersen-jubjub-v1` §2.3.
  - **The profile:** `KA.Agree`, `KDF`, `Sym`, `plaintext`, `seal` (§4), `open_delivery`
    (§5, which records the first failing step), reader-key validity (§2.2), the test scalars
    (§9.1), and the D3a ElGamal limb encryption and both public-input layouts (§8).
- `reference-output.txt`: the output, one `key=value` per line, sorted by key, with no header.

## Running

```
cd zeroj-circuit-lib/src/test/resources/confidential-note-reference
python3 confidential_note_jubjub_v1_reference.py
```

Run it without `-I`, so that the user site-packages (pyca `cryptography`) load. The run takes
about 6 s. It prints the output and rewrites `reference-output.txt`. It sets
`sys.dont_write_bytecode`, so it leaves no `__pycache__`.
- **Exit status:** 0 if every check passes. Otherwise it exits 1 and lists the failing keys on
  stderr. A crash also gives 1.
- **Determinism:** the output depends only on the code and the vendored inputs. It contains no
  Python version and no timing. Two consecutive runs, and runs with `PYTHONHASHSEED` set to 0, 1
  and 12345, gave byte-identical output (SHA-256 at the end of this README).

## Independence

Read:
- `docs/specs/confidential-note-jubjub-v1.md` (the spec under test) and
  `docs/adr/0055-confidential-notes-jubjub.md`;
- `docs/specs/pedersen-jubjub-v1.md` and `docs/specs/elgamal-jubjub-v1.md`;
- the Zcash protocol specification text: §4.20.2, §5.4.1.2, §5.4.3, §5.4.5.3 and §5.4.5.4;
- the BLAKE2 paper (§2.8, Table 1), RFC 7693 (Appendix A) and RFC 8439 (§2.8.2);
- `../standard-vectors/README.md` and `zcash-sapling-note-encryption.json`;
- the Python references `../pedersen-reference/` (source), `../elgamal-reference/` (as a
  pointer only) and `../dkg-share-delivery-reference/` (README and script, as the format
  template).

The spec was read again at its revision resolving S1–S6, under the same rules.

Not read: any Java source (`*.java`, `src/main/java`, `src/test/java`). No Java file was opened
or searched. A `git status` printed the names of some Java files being written in parallel,
but no Java content was read.

Expected values:
- **Primitives:** every expected value comes from published vectors. Those are the 10 [ZTV]
  vectors, RFC 7693 Appendix A and RFC 8439 §2.8.2. The RFC 8439 vector was quoted from the RFC
  text, not from Wycheproof.
- **Curve and bases:** these values are hand-transcribed pins from `pedersen-jubjub-v1`.
- **ElGamal:** these values are hand-transcribed pins from `elgamal-jubjub-v1` §12.
- **Profile vectors:** these are this reference's own outputs. Where the code could have got
  one wrong, a hand-written intent check states the outcome the case was built to show (see
  "Checks").

## Results

All 324 checks pass. There are 116 replayable vectors.

| Area | Result |
|---|---|
| [ZTV] Sapling note encryption (10 vectors, `pers = "Zcash_SaplingKDF"`) | The file's SHA-256 matches the spec §9.2 pin. All 10 vectors reproduce: `encode([8·esk]·pk_d) = shared_secret`, `encode([8·ivk]·epk) = shared_secret`, `KDF = k_enc`, `Sym.Encrypt(p_enc) = c_enc` (580 bytes) and its decryption. With the profile personalization, the KDF differs from `k_enc` in all 10. |
| RFC 7693 Appendix A | BLAKE2b-512("abc") matches, both through `hashlib` and through the pure-Python BLAKE2b. |
| Personalised BLAKE2b | An all-zero personalization equals the unpersonalised hash. Each personalization changes the output. `hashlib` and the pure implementation agree on 13 KDF vectors, including 0, 127, 128, 129 and 300-byte inputs, and on every D3a digest. BLAKE2b-256 is not BLAKE2b-512 truncated ([ZcashSpec] §5.4.1.2 note). |
| RFC 8439 §2.8.2 | Seal and open match the RFC text. A modified tag is refused. |
| Drift | `p` and `l` match the pins. `d = −10240/10241`. `G` and `H` (derived; first success at counter 1) match the `pedersen-jubjub-v1` pins. `C(42, 12345)` matches the §8 pin. The torsion points have orders 2, 4 and 8. The copied arithmetic agrees with the pedersen reference's. |
| `elgamal-jubjub-v1` §12 | `scalar("sk")`, `encode(PK)`, `Enc(1; k1)` and `Enc(12345; k16)` match the pins, so the D3a limb encryption is the profile's. |

## Output keys

| Key | Content |
|---|---|
| `profile`, `profile.pers`, `profile.test_prefix`, `profile.delivery_length`, `profile.plaintext_length` | The profile identifier, the personalization (hex), the §9.1 prefix, 89 and 41. |
| `curve.p`, `curve.l`, `base.g.*`, `base.h.*` | The field, the subgroup order, and `G` and `H` (`u`, `v`, `encoding`). |
| `key.<name>.sk`, `key.<name>.pk` | The viewing keys (`0x` scalar; `encode(P)` as hex). |
| `elgamal_key.<name>.sk`, `.pk`, `.u`, `.v` | The D3a auditor ElGamal keys. |
| `check.*` | Checks, each `true` or `false`. |
| `info.*` | Informative values: `info.check_count`, `info.failed_checks`, `info.case_count`, `info.case_count.<family>` and `info.ztv.vector_count`. |
| `case.<family>.<name>.*` | Replayable vectors (below). |
| `result` | `pass` or `fail`. |

Value conventions:
- **Bytes** are bare lowercase hex.
- **Integers** below `2^64` are decimal.
- **Field elements and scalars** are `0x` plus 64 lowercase hex digits.
- **Lists** are comma-separated.
- **Booleans** are `true` or `false`.
- **Names** are case and family names, made only of `[a-z0-9_]`.
- **`config`:** every case has one, a short human description.

## Test keys

All test scalars are `scalar(tag) = OS2IP(SHA-256(ASCII("zeroj.confidential-note.v1.test." ‖
tag))) mod l` (spec §9.1). None derived to zero.

| Tag | Use |
|---|---|
| `reader.<name>` | The viewing keys of `owner`, `auditor1`, `auditor2`, `auditor3` and `other` (spec §9.1). |
| `ephemeral.<case>.<i>` | The ephemeral of reader `i` (0-based, §4 order) in a `deliver` case, or of the single sealed delivery of an `open` case (`i = 0`). |
| `ephemeral.<case>.0.retry<k>` | Listed in spec §9.1 since its revision. Only for `e_noncanonical_v_plus_p` (`retry8`) and `e_noncanonical_reencoded_kdf` (`retry2`). These cases need a point whose `v + p` still fits in 255 bits, which about 10% of points satisfy. The reference tries the plain tag first, then `retry1`, `retry2`, …, as spec §9.1 says. The tag is emitted as `case.open.<case>.ephemeral_tag`. |
| `ephemeral.readerkey_<case>.0`, `ephemeral.duplicate_readers.<i>` | Ephemerals for the sealing attempts of the `readerkey` family. A refused seal never uses them. |
| `blinding.<case>` | The blinding of a case (§9.1). `r1_blinding0` and `r1_zero_opening` use the literal blinding 0, and `r_l_minus_1`, `r_equals_l`, `r_l_plus_5` and `r_max_256` use literal blindings. |
| `blinding.<case>.1`, `blinding.<case>.2` | Listed in spec §9.1 since its revision. The two plaintexts of a `reuse` case. |
| `elgamal.<name>` | Listed in spec §9.1 since its revision. The D3a auditor ElGamal secrets (`elgamal.auditor1`, `elgamal.auditor2`). They are separate from the viewing keys (`reader.<name>`). |
| `d3a.<case>.k.<o>.<a>.<j>` | Listed in spec §9.1 since its revision. The ElGamal randomness of limb `j` of note `o` for auditor `a` (`o` and `a` 1-based, as in §8.1). |

Every ephemeral tag is used once, except the deliberate reuse family
(`check.lifecycle.ephemeral_tags_never_reused`, `check.lifecycle.ephemerals_distinct`).

## Replayable vectors

Counts: `deliver` 6, `open` 53, `readerkey` 12, `reuse` 2, `kdf` 13, `d3a` 3 and `d3a_mut`
27, so 116 in all.

### `case.deliver.<case>.*` (§3, §4)

| Key | Content |
|---|---|
| `readers` | Key names, in reader order. |
| `value`, `blinding` | The opening `(v, r)`. |
| `commitment`, `commitment_u`, `commitment_v` | `encode(C)` and the affine coordinates. |
| `plaintext` | The 41-byte plaintext. |
| `ephemeral.<i>`, `delivery.<i>` | `e_i` and the 89-byte delivery for reader `i`. |

The cases are:
- `r1_value0`: 1 reader, `v = 0`;
- `r1_blinding0`: 1 reader, `v = 42`, `r = 0`;
- `r1_zero_opening`: `(0, 0)`, so `C` is the identity;
- `r2_value1`: 2 readers, `v = 1`;
- `r3_value_max`: 3 readers, `v = 2^64 − 1`;
- `r4_value_mid`: 4 readers, `v = 123456789012345`.

For each case, the checks show:
- each `E_i = encode([e_i]·G)`, and the `E_i` are distinct;
- the plaintext layout, written by hand for three cases;
- every reader accepts its own delivery;
- **every other test key refuses every delivery at step 5**.

### `case.open.<case>.*` (§5)

| Key | Content |
|---|---|
| `reader` | The key name used to open. |
| `delivery` | The delivery bytes, of any length. |
| `commitment_u`, `commitment_v` | **The authoritative input:** the note's affine `(u, v)`, as integers taken with no reduction (spec §5, revised). Replay uses these. |
| `commitment` | `encode(C)`, for convenience. Present only where `(u, v)` is a canonical curve point; absent in `c_u_plus_p`, `c_v_plus_p` and `c_not_on_curve`. |
| `expect`, `step` | `accept` with step `0`, or `reject` with the first failing §5 step (1, 2, 5, 6 or 7). |
| `reason` | Informative: `length`, `decode_<rule>`, `not_in_subgroup`, `identity`, `aead`, `lead_byte`, `r_not_below_l`, `commitment_noncanonical`, `commitment_mismatch` or `none`. The spec defines no sub-reasons. |
| `value`, `blinding` | For `accept` only. |
| `plaintext`, `ephemeral`, `ephemeral_tag` | For freshly sealed (crafted) cases. |
| `app_note` | `copied` for the copied-note case. |

The cases are listed below, with the failing step in parentheses.
- **Accepted (14):**
  - all 12 reader/delivery pairs of the deliver family (`<deliver>_reader<i>`);
  - `r_l_minus_1`, the control with `r = l − 1`;
  - `copied_note`: the same `(C, delivery)` placed in another output still opens. The
    owner-credential check is the application's (§5), so `app_note=copied`.
- **(1) Length:** `len_88_truncated`, `len_90_extended`, `len_0`, `len_57_ct_only`,
  `len_32_e_only`, and `len_90_valid_aead` (a 42-byte plaintext sealed with a valid tag).
- **(2) `E`:**
  - non-canonical: `e_noncanonical_v_plus_p`, `e_noncanonical_reencoded_kdf` and
    `e_v_all_ones`;
  - the ZIP 216 rule: `e_identity_sign_set` and `e_order2_sign_set` (`u = 0` with the sign
    bit set);
  - no point: `e_not_on_curve` (`u²` is a non-square);
  - small order: `e_small_order2`, `e_small_order4` and `e_small_order8`;
  - outside `𝔾`: `e_mixed_order` and `e_mixed_order_no_cofactor` (`[e]G` plus an order-8
    point);
  - the identity: `e_identity`.
- **(5) AEAD:**
  - the wrong key: `wrong_reader_key` (`other`), `other_readers_index` (auditor1 opens the
    owner's delivery) and `other_readers_index_r4` (auditor2 opens auditor3's delivery);
  - tampering: `tampered_ct_byte0`, `tampered_ct_byte28`, `tampered_tag`,
    `tampered_e_valid_point` (`E + G`), `tampered_e_negated` (sign bit flipped, giving `−E`)
    and `swapped_ct_between_readers`.
- **(6) Plaintext, with a valid AEAD:**
  - the lead byte: `lead_byte_00` and `lead_byte_02`;
  - `r ≥ l`: `r_equals_l`, `r_l_plus_5` and `r_max_256` (`r = 2^256 − 1`).
- **(7) Commitment:**
  - mismatches: `opening_mismatch_value` (`C` commits to `v + 1`),
    `opening_mismatch_other_note`, `opening_mismatch_negated_c` (`−C`) and
    `opening_mismatch_identity_c`;
  - non-canonical coordinates, each with a valid AEAD and the correct opening: `c_u_plus_p`
    (`u + p`) and `c_v_plus_p` (`v + p`);
  - off the curve: `c_not_on_curve` (`(u + 1, v)`, with the correct opening).

  `check.open.c_{u,v}_plus_p.opening_would_match_c_with_reduction` shows that a reader that
  reduced the coordinates mod `p` would accept them. `check.open.c_not_on_curve.is_off_curve`
  confirms the off-curve point.

The adversarial cases are built so that **only the named check refuses them**:
- **Encryption key:** each adversarial `E` is sealed under the key a defective reader would
  derive:
  - non-canonical: the true shared secret, with the KDF over the received non-canonical bytes.
    `e_noncanonical_reencoded_kdf` uses the KDF over the canonical re-encoding instead;
  - small-order, identity and `u = 0` cases: `shared = O`;
  - `e_mixed_order`: `[8e]·P` (what `[8·sk]·E` gives);
  - `e_mixed_order_no_cofactor`: `[sk]·E`.

  `check.open.<case>.lenient_reader_would_accept` shows that a reader without the step 2 check
  would accept each one.
- **Commitment:** for the lead-byte and `r ≥ l` cases, `C` is the commitment of `(v, r mod l)`.
  `check.open.<case>.opening_would_match_c_without_step6` shows that step 7 alone would pass.

### `case.readerkey.<case>.*` (§2.2, §4 step 1)

`pk`, `expect` (`valid` or `invalid`) and `reason`.
- Valid: `owner` and `auditor1`.
- Invalid:
  - the identity: `identity`;
  - small order: `order2`, `order4` and `order8`;
  - outside `𝔾`: `mixed_order`;
  - non-canonical: `noncanonical_v_plus_p` (the owner's key written with `v + p`, the same
    point);
  - no point: `not_on_curve`;
  - the ZIP 216 rule: `identity_sign_set`;
  - length: `length_31` and `length_33`.

Sealing to each invalid key is refused (`check.readerkey.<case>.seal_refused`). So is sealing
to a duplicated reader key (`check.seal.refuses_duplicate_reader_keys`).

### `case.reuse.<case>.*` (§4, one use per key)

`reader`, `ephemeral`, `plaintext1`, `plaintext2`, `delivery1`, `delivery2` and `xor`
(`pt1 ⊕ pt2`, 41 bytes). The cases are `same_e_owner` and `same_e_auditor1`. The checks show:
- both deliveries carry the same `E`;
- `ct1 ⊕ ct2` over the first 41 bytes equals `xor`;
- `pt2` is recovered from `pt1`;
- both deliveries still open. This is a forbidden construction, shown for the negative only.

### `case.kdf.<case>.*` (§1)

`pers` (16 bytes, hex), `input` and `output` (BLAKE2b-256 with that personalization).
- `zeroj_len<n>` and `zcash_len<n>` for `n` = 0, 64, 127, 128, 129 and 300. The input bytes are
  `i mod 256` for `i = 0 … n−1`.
- `profile_shape_r1_value0`: the exact input `encode(shared) ‖ E` of `r1_value0`'s delivery,
  equal from the sender's and the reader's side.

### `case.d3a.<case>.*` (§8)

| Key | Content |
|---|---|
| `auditors` | ElGamal key names, in registry order. |
| `pk.<a>.u`, `pk.<a>.v` | Auditor `a` (1-based). |
| `notes` | `n`. |
| `note.<o>.value`, `.limb0`, `.limb1` | Note `o` (1-based) and its 32-bit limbs. |
| `k.<o>.<a>.<j>` | The ElGamal randomness. |
| `ct.<o>.<a>.<j>` | `A.u,A.v,B.u,B.v` (`A = [k]G`, `B = [L]G + [k]PK`). |
| `public_inputs` | §8.2: the auditor keys, then `(o, a, j)` blocks. |
| `bytes`, `digest`, `digest_hi`, `digest_lo` | §8.3: big-endian 32-byte coordinates, unpersonalised BLAKE2b-256, and its 128-bit halves. |

The cases are:
- `o2_a1` (transfer: 2 outputs, 1 auditor; values `2^64 − 1` and `2^32 + 12345`);
- `o1_a1` (redeem: 1 output, 1 auditor);
- `o2_a2` (2 outputs, 2 auditors; values 0 and `2^32`).

For each case, the checks show:
- every limb ciphertext decrypts to its limb;
- `A` and `B` lie in `𝔾`;
- the limbs recombine to the value;
- every coordinate is canonical;
- the public-input count is `2m + 8mn` (18, 10 and 36, as ADR-0055 D3a states);
- the byte length is `256·m·n` (512 bytes for the transfer);
- the split is lossless.

An index formula written independently of the emitting loops checks the §8.2 order. A
hex-string check written independently of `I2OSP` checks the big-endian byte order.

### `case.d3a_mut.<case>.<mutation>.*`

`digest_hi` and `digest_lo` of a mutated serialization or digest, plus `config`. Each mutation
gives a different pair, and the mutations differ from one another
(`check.d3a.<case>.mutation_digests_distinct`). The mutations are:
- `swap_outputs` (2 outputs only);
- `swap_limbs_note1`;
- `swap_auditors_note1` (2 auditors only);
- `coord0_plus_one` and `last_coord_plus_one`;
- `little_endian_i2osp`;
- `personalized_blake2b` (with the profile's personalization);
- `blake2b512_truncated`;
- `swap_digest_halves`;
- `with_public_keys_prefixed` (the `PK` coordinates also hashed).

## Checks

The checks fall into five groups:
- **Published known answers:** `ztv.*`, `rfc7693.*`, `rfc8439.*`, `blake2.*`.
- **Drift checks:** `drift.*` and `elgamal_pin.*`. They compare against values hand-transcribed
  from `pedersen-jubjub-v1` and `elgamal-jubjub-v1`, and the profile personalization against
  its hand-written hex.
- **Differentials:** the pure-Python BLAKE2b against `hashlib`, and the copied arithmetic
  against the pedersen reference's.
- **Intent checks:**
  - `open.<case>.intended_outcome` compares the hand-written expected outcome and step with
    the computed one;
  - `readerkey.<case>.intended_outcome` does the same, including the reason;
  - the hand-written plaintexts, the D3a counts and the byte order are also intent checks.
- **Construction checks:** `lenient_reader_would_accept`,
  `opening_would_match_c_without_step6` and `open.accepted_e_reencodes_to_itself`.

### Mutation testing

Mutation testing was run on copies of the script, one defect per copy. The copies were kept in
a scratch directory and used symlinks to the vendored inputs. Every mutation below was
detected, by failing checks or by a crash (exit 1):

| Mutation | Detected by |
|---|---|
| KDF unpersonalised (`person` dropped) | `ztv.*.kdf`, `blake2.*` (27 checks) |
| Personalization passed as the salt | `ztv.*.kdf`, the pure differential (23) |
| Personalization flipped to `"ZeroJ_NoteKDF_v2"` | `drift.pers_hand_transcribed` (1) |
| Pure BLAKE2b with the personalization at bytes 40–55 | the pure differentials (13) |
| KDF input order `E ‖ encode(shared)` | `ztv.*.kdf` (10) |
| KDF without `E` | `ztv.*.kdf` (10) |
| Non-zero nonce | `ztv.*.sym_*` (20) |
| `r < l` check skipped | `open.r_equals_l`, `open.r_l_plus_5`, `open.r_max_256` (3) |
| Identity `E` accepted | `open.e_identity` (1) |
| Cofactor-less `Agree` on both sides | `ztv.*.*agree*` and the KDF (33) |
| Cofactor-less `Agree` in opening only, or in sealing only | `deliver.*.each_reader_accepts_own` and the open intents (34 each) |
| Subgroup check skipped in opening | `open.e_small_order{2,4,8}`, `open.e_mixed_order*` (5) |
| Decoder reduces `v ≥ p` mod `p` | `readerkey.noncanonical_v_plus_p`, `open.e_noncanonical_*`, `open.accepted_e_reencodes_to_itself` (5) |
| Lenient decoder **and** KDF over the re-encoded `E` | `open.e_noncanonical_reencoded_kdf` among 5 |
| ZIP 216 rule (`u = 0`, sign set) dropped | `readerkey.identity_sign_set` (reason), `open.e_identity_sign_set` (3) |
| Lead-byte check skipped | `open.lead_byte_00`, `open.lead_byte_02` (2) |
| Step 7 skipped | `open.opening_mismatch_*`, `open.c_not_on_curve` (5) |
| Step 7 reducing the coordinates mod `p` | `open.c_u_plus_p`, `open.c_v_plus_p` (2) |
| Little-endian `I2OSP` in the plaintext | the plaintext layout and intents, and all accepts (45) |
| Length check `< 89` only | `open.len_90_extended`, `open.len_90_valid_aead` (2: step 5 instead of 1) |
| Sealing without reader-key validation | crash (an undecodable key reaches `Agree`) |
| Sealing allows duplicate reader keys | `seal.refuses_duplicate_reader_keys` (1) |
| D3a little-endian serialization | `d3a.*.bytes_are_big_endian_hex_of_coordinates`, `d3a_mut.*.little_endian_i2osp` (6) |
| D3a limb order `j = 1` before `j = 0` | `d3a.*.public_input_index_formula` (4) |
| D3a limbs swapped in the split | `d3a.*.limbs_recombine` (3) |
| D3a digest personalised | `d3a.*.digest_pure_differential`, `d3a_mut.*.personalized_blake2b` (6) |
| D3a digest halves swapped | `d3a.*.digest_split_lossless` (3) |
| ElGamal `B = [m]G + [k]G` | `elgamal_pin.*`, `d3a.*.limb_ciphertexts_decrypt` (5) |

**Equivalent mutation:** using the re-encoded `E` in the KDF (step 4) **on its own** is not
detected, and cannot be. Step 2's decoder accepts exactly one encoding per point, so every
accepted `E` re-encodes to itself (`check.open.accepted_e_reencodes_to_itself`). The rule has an
effect only together with a lenient decoder, and that combination is detected (above). Spec
§5 now records this as defence in depth (S4).

**Limits:** these checks cannot detect a defect that this reference and a second
implementation share, such as the same wrong plaintext layout on both sides. The Java
implementation must reproduce these vectors byte for byte, and the [ZTV] vectors pin the
primitives independently.

## Spec findings

The first run reported S1–S6 without resolving them silently. The spec's revision of
2026-10-09 resolves each one, and this reference was re-run against the revised spec (the
Java implementation was still not read).

| Finding | Spec revision | Reference now |
|---|---|---|
| S1. Step numbering | §5 adds a "Step numbering" paragraph that maps the spec's steps to ADR-0055 D6's: D6 step 1 = steps 1–2, 2 = 3–5, 3 = 6, 4 = 7, 5 = the application's owner-credential check. | No change. Vectors keep the spec's 1–7 numbering. |
| S2. Tag scheme | §9.1 now lists `ephemeral.<case>.<i>.retry<k>`, `blinding.<case>.1` and `.2`, `elgamal.<name>` and `d3a.<case>.k.<o>.<a>.<j>`, and states that replay does not depend on the tags. | No change. The readerkey sealing tags (`ephemeral.readerkey_<name>.0`, `ephemeral.duplicate_readers.<i>`) already have the `ephemeral.<case>.<i>` form. |
| S3. Received `C` | §5 takes `C` as the note's affine `(u, v)`. Step 7 requires `0 ≤ u < p` and `0 ≤ v < p` with no reduction, and `[v]·G + [r]·H = (u, v)`. Otherwise the delivery is "not mine" at step 7. | Step 7 implements the revised rule. New open cases `c_u_plus_p`, `c_v_plus_p` and `c_not_on_curve` all reject at step 7. `commitment_u` and `commitment_v` are the authoritative replay input. A new mutation (reduction mod `p`) is detected. |
| S4. Step 4 under a canonical decoder | §5 adds a "Defence in depth" note. | No change. The mutation stays equivalent, as expected. |
| S5. `x[a..b]` | The conventions define it as bytes `a` through `b`, inclusive and 0-based. | Same reading as before. |
| S6. Index bases | The conventions state them: deliveries and readers from 0; §8 notes and auditors from 1. | Same as before. |

The first-run text of each finding follows, for the record.

- **S1. Step numbering differs between the spec and ADR-0055.**
  - Spec §5 numbers the acceptance steps 1–7: length, `E`, `Agree`, KDF, AEAD, plaintext,
    commitment.
  - ADR-0055 D6 numbers them 1–5. There, step 2 includes the 57-byte length, step 4 is the
    commitment, and **step 5 is the application's owner-credential check**. I3 and I8 refer to
    "D6 steps 1–4", and M0 asks for "the copied-note case for D6 step 5".
  - **Reading used:** the spec's numbers in `.step` (1, 2, 5, 6, 7). The copied-note case is
    an `accept` with `app_note=copied`.
  - **Suggestion:** the ADR could cite the spec's numbering, or give the mapping.
- **S2. The §9.1 tag scheme does not cover every vector.**
  - These tags are not defined:
    - the D3a ElGamal auditor secrets and the per-limb randomness `k`;
    - the second plaintext of a key-reuse case;
    - adversarial constructions that need a point with a property: here, `v + p < 2^255`;
    - the sealing attempts of reader-key negatives.
  - **Reading used:** `elgamal.<name>`, `d3a.<case>.k.<o>.<a>.<j>`, `blinding.<case>.1` and
    `.2`, and `ephemeral.<case>.0.retry<k>`. All are under this profile's prefix; see "Test
    keys".
  - **Options:**
    - (a) §9.1 lists these tags;
    - (b) §9.1 states that the reference's tag scheme is normative, as the
      `dkg-share-delivery-hpke-v1` spec did in its second revision.

    Replay does not depend on the tags, because every scalar is emitted.
- **S3. The form and validation of the received `C` in step 7 are not specified.**
  - §3.3 says a note carries `C` as affine `(u, v)` (`pedersen-jubjub-v1` §5). §5 step 7 says
    only `[v]·G + [r]·H = C`. ADR-0055 D6 says "the comparison may be of encodings or of affine
    coordinates".
  - For datum coordinates with `u ≥ p` or `v ≥ p`, a reader that reduces mod `p` would accept,
    while one that compares canonical encodings or applies `elgamal-jubjub-v1` §7.4 rule 1
    ("no reduction mod p") would refuse. The wallet would then count a note whose datum
    coordinates are not the ones a validator or proof uses as canonical public inputs.
  - A `C` off the curve fails step 7 under every reading.
  - **Reading used in the first run:** `C` compared as a point, with no non-canonical vector.
    Superseded by the revised step 7 (table above).
  - **Options:**
    - (a) require `0 ≤ u, v < p` with no reduction, a failure being step 7 (or a new step);
    - (b) define the comparison on canonical encodings only.
- **S4. §5 step 4's "received bytes, not a re-encoding" is unobservable under step 2 (note).**
  - The rule comes from [ZcashSpec] §4.20.2, where Sapling's `abst_J` accepts non-canonical
    encodings. Here, step 2 refuses every non-canonical `E`, so `encode(decode(E)) = E`
    whenever step 4 runs. The rule is defence in depth: the equivalent mutation above.
  - No change is needed. The spec could say so, so that nobody reads it as an independent
    guarantee.
- **S5. `x[a..b]` notation is not defined in the conventions (note).**
  - `pt[1..8]`, `pt[9..40]` (§5) and `digest[0..15]` (§8.3) are read as inclusive byte
    indices. That gives 8, 32 and 16 bytes, which agrees with the stated lengths.
- **S6. Index bases are mixed (note).**
  - Readers and deliveries are 0-based (`P_0 … P_k`, §4). D3a notes and auditors are 1-based
    (`o = 1 … n`, `a = 1 … m`, §8.1), and limbs are `j ∈ {0, 1}`. The vectors follow the spec
    in each place.
  - An implementer replaying both families must not assume one base.

## Not covered

- **§5 platform faults:** "a local fault is not a failed step" is not modelled. A primitive
  that errs is not simulated.
- **§2.2 possession:** the possession proof at registration (the `elgamal-jubjub-v1` §3.3
  form).
- **Secret handling:** wiping, and the blinded secret-bearing path of step 7 (I11, I13).
- **Sampling:** `sample(rng)` and production randomness. Every scalar here comes from §9.1.
- **The D3a circuit:** the `R_enc(32)` constraints, the in-circuit BLAKE2b, and the budget
  measurement (M5a). Only the encodings, order, digest and split are covered.
- **Sapling beyond the primitives:** note-plaintext parsing, `cmu`, `ock`/`C_out` and
  diversified bases.
- **The Wycheproof ChaCha20-Poly1305 suite:** the RFC 8439 vector is used here. The
  `dkg-share-delivery-reference` covers Wycheproof.
- **Security arguments:** any argument for Assumptions A1–A3.

Output SHA-256 at this revision: `818709c4252bf7162ab457ae5ab07d9d3ad01d7842d5a35e581dee39819a46af`
