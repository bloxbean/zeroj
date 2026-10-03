# pedersen-jubjub-vector-v1 — independent reference

`pedersen_jubjub_vector_v1_reference.py` is an independent Python 3 reimplementation of the
profile `pedersen-jubjub-vector-v1`
([`docs/specs/pedersen-jubjub-vector-v1.md`](../../../../../docs/specs/pedersen-jubjub-vector-v1.md)).
Its output, `reference-output.txt`, is evidence that can be checked against ZeroJ's Java
implementation. It is not derived from that implementation.

It covers:

- Jubjub affine arithmetic (a = −1, complete unified addition), scalar multiplication,
  cofactor clearing, the prime-order subgroup check, the Tonelli–Shanks square root, and the
  `pedersen-jubjub-v1` §4 encoding with ZIP 216 strict decoding;
- `GroupHash` / `FindGroupHash` (spec §1), checked against the 12 Zcash Sapling known answers
  (§1.1);
- the 17 bases `G_0..G_15` and `H_V` (§2): counters, coordinates, encodings, subgroup
  membership, non-identity, pairwise distinctness, and distinctness from `pedersen-jubjub-v1`'s
  `G` and `H`;
- the commitment (§3) and its §3.1 vectors, plus extra cases: identity for n = 1 and n = 16, a
  full 16-value commitment, homomorphism, and reduction of out-of-range and negative inputs
  mod `l`;
- the schema encoding (§4.1), a strict decoder, the digest σ (§4.2), the four §4.3 vectors,
  a boundary-maximum schema, and 16 negative decode vectors;
- cross-checks against the values pinned in `pedersen-jubjub-v1` (`G = [8]·G_full`,
  `encode(G)`, `encode(H)`, and the §8 vector `C(42, 12345)`), which exercise the same
  arithmetic and encoding through an independent set of pinned values.

The arithmetic is variable time. This is a test oracle and must not be used with secrets.

## Independence rules followed

- Only two repository files were read:
  `docs/specs/pedersen-jubjub-vector-v1.md` (primary, normative) and
  `docs/specs/pedersen-jubjub-v1.md` (§1 curve constants and §4 point encoding, which the vector
  profile incorporates, plus its pinned `G`, `H` and §8 vector for cross-checks).
- No `.java` file, build output or other repository file was opened or searched. The existing
  `../pedersen-reference/` script was not read. All Jubjub arithmetic here was written fresh
  from the spec text.
- **External references consulted: none.** The spec text was enough. In particular,
  `sapling-crypto`'s `group_hash.rs` / `constants.rs` were not consulted. The §1.1 note that the
  table coordinates are "the integers whose little-endian 64-bit limbs appear in
  `constants.rs`" was not checked against that file. The table values were reproduced from
  first principles. BLAKE2s personalisation uses Python's `hashlib.blake2s(person=...)`
  (RFC 7693 parameter block). Reproducing all 12 Zcash known answers is the evidence that
  this matches Zcash's usage.
- `pedersen-jubjub-v1`'s `H` is not re-derived, because that needs the Poseidon instance and
  is out of scope. Its pinned coordinates are used for the distinctness check. They are
  validated indirectly: on the curve, in the subgroup, `encode(H)` equal to the pinned
  encoding, and `C(42, 12345)` equal to the pinned vector.

## Running

```
python3 pedersen_jubjub_vector_v1_reference.py
```

Standard library only (needs Python ≥ 3.6 for `hashlib.blake2s(person=...)`; produced with
3.13.5). It runs in about 2 s. It prints the `key=value` lines and writes them, with a `#`
header, to `reference-output.txt` next to the script. The exit status is 0 iff every
`spec_match_*` and `check_*` key is `true`. Otherwise each mismatch is printed to stderr as
`MISMATCH ...` and the exit status is 1. The output is deterministic. Only the
`# Python <version>` header line depends on the machine.

## Output format

One `key=value` per line, in fixed program order. Lines starting with `#` are comments.

- Field elements (coordinates, σ): `0x` + exactly 64 lowercase hex digits.
- Other integers (counters, scalars, `p`, `l`): `0x` + minimal lowercase hex (`0x0` for zero).
- Byte strings (encodings, inputs, personalisations): bare lowercase hex, empty for empty.
- Checks: `true` / `false`.
- `spec_match_<name>`: the computed value equals the value pinned in a spec. There are 124
  such keys: 7 `pjv1`, 36 Zcash (counter, u, v × 12), 68 bases (counter, u, v, encode × 17),
  5 commitment and 8 schema.
- `check_<name>`: a property or self-test that holds (130 keys).
- `result=pass|fail`: the last line.

### Key families

| Family | Keys |
|---|---|
| `const_*` | `p`, `l`, `d`, cofactor, URS, counter bound, `D_PV`, `N_MAX`, schema tag |
| `check_curve_*` | `−1` square, `d` non-square, `d·v²+1 ≠ 0`, `[l]G_full ≠ O`, `[8l]G_full = O` |
| `pjv1_*` | `pedersen-jubjub-v1` cross-check: `C(42, 12345)` `_u/_v/_encode`; `spec_match_pjv1_*`, `check_pjv1_*` |
| `point_decode_neg_<case>_{input,reason}` | point-decoding rejections, each with `check_point_decode_neg_<case>_rejected` |
| `point_*`, `check_point_*` | identity encoding/round trip, order-2 point decodes but is not in the subgroup, sign bit negates |
| `check_grouphash_*`, `check_findgrouphash_*` | stub-driven checks: ⊥ on decode failure, ⊥ when cofactor clearing gives identity, `[8]` applied, counters `0..254` appended as one byte, failure after 254, success at 254 |
| `zcash_<constant>_{personalisation,message,counter,u,v,encode}` | §1.1 known answers; `spec_match_zcash_<constant>_{counter,u,v}` |
| `base_<G_i\|H_V>_{counter,u,v,encode}` | §2 bases; `spec_match_base_*`, `check_base_*_{on_curve,in_subgroup,not_identity,spec_encode_decodes_to_spec_point}`, `check_bases_*` |
| `commit_<case>_{u,v,encode}` | §3.1 vectors and extras (see below); `spec_match_commit_*`, `check_commit_*` |
| `schema_<case>_{encode,digest}` | §4.3 vectors (full encodings), `_elided_prefix` for the three abbreviated rows; `spec_match_schema_*`, `check_schema_*` |
| `schema_boundary_max_*` | not spec-pinned: id of 64 bytes, version `0xffff`, 16 entries, widths 1…252, 32-byte labels |
| `schema_literal_label_leading_punct_*` | informational, see ambiguity 1 |
| `schema_neg_<case>_{input,reason}` | schema decode rejections, each with `check_schema_neg_<case>_rejected` |
| `result` | `pass` / `fail` |

Commitment extras: `commit_zero_n1_r0`, `commit_zero_n16_r0` (identity);
`commit_seq16` = `C(1, 2, …, 16; r)` with
`r = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd mod l` (the values and
`r` are printed as `commit_seq16_values` / `commit_seq16_r`); `commit_hom_*` for
`C([3,4],5) + C([10,20],30) = C([13,24],35)`; `check_commit_residue_reduction` and
`check_commit_negative_inputs_reduce` for inputs outside `[0, l)`.

Negative schema vectors: `trailing_byte`, `wrong_tag` (`...-v2\0`), `tag_separator_nonzero`
(`...-v1\1`), `id_uppercase`, `id_leading_dot`, `id_empty`, `id_65_bytes`, `n_0`, `n_17` (17
well-formed entries follow), `width_0`, `width_253`, `duplicate_label`, `label_33_bytes`,
`label_empty`, `label_uppercase`, `truncated` (last byte removed). Each input breaks exactly one
rule, so the accept/reject verdict is unambiguous. The reason strings (`trailing_bytes`,
`bad_tag`, `id_bad_char`, `id_bad_first_char`, `id_length`, `n_range`, `width_range`,
`duplicate_label`, `label_length`, `label_bad_char`, `truncated`) are this reference's own
names, not spec terms.

Negative point vectors: lengths 31 and 33; `v = p` with the sign bit clear and set;
`v = 2^255 − 1`; the smallest `v` whose `u²` is a non-square (`v = 2`); `(0, 1)` and
`(0, −1)` with the sign bit set (ZIP 216).

## Results

All 124 spec-pinned values match, and `result=pass`.

The spec abbreviates three §4.3 encodings with "…". The elided part is the 48-byte prefix
`tag ‖ 0x00 ‖ u8(21) ‖ id`, identical to the first row through the id. The full encodings are:

| Schema | `encode` |
|---|---|
| v2 | `706564657273656e2d6a75626a75622d766563746f722d763100157a65726f6a2e6578616d706c652e62616c616e63650002024006616d6f756e7420056173736574` |
| v1, labels swapped | `706564657273656e2d6a75626a75622d766563746f722d763100157a65726f6a2e6578616d706c652e62616c616e6365000102400561737365742006616d6f756e74` |
| v1, `asset` width 33 | `706564657273656e2d6a75626a75622d766563746f722d763100157a65726f6a2e6578616d706c652e62616c616e63650001024006616d6f756e7421056173736574` |

### The checks can fail

The script was checked against 37 mutated copies, run in a scratch directory and not
committed. Every mutant exits non-zero. They covered:

- **Group hash:** wrong personalisation; personalisation passed as BLAKE2s key or salt; URS
  after the message or omitted; counter prepended, two bytes, starting at 1, or bounded at
  253/255; no cofactor clearing; `[4]` instead of `[8]`; identity not rejected; big-endian
  `LE32`; wrong `H_V` message.
- **Curve and encoding:** `a = +1`; sign bit taken from `v`; ZIP 216 rule removed; `v ≥ p`
  reduced instead of rejected; inverted root parity.
- **Commitment:** bases reversed; no reduction mod `l`.
- **Schema digest:** little-endian digest; digest not reduced mod `p`; SHA-512 truncated.
- **Schema encoding and decoding:** tag without `0x00`; little-endian version; label before
  width; trailing-byte, duplicate-label and id-first-character checks removed; off-by-one
  bounds on width, label length, id length and `n`.

Three observations from this exercise:

- **The strict `v < p` rule is pinned by the vectors.** Reducing instead of rejecting changes
  `PEDERSEN_HASH_GENERATORS[0]` (counter 5), `G_0` (counter 2) and every commitment that uses
  `G_0`.
- **ZIP 216's zero-`u` rule cannot affect `GroupHash`.** The only encodings it rejects decode
  to `(0, ±1)`, which clear to the identity and give ⊥ either way. Only the
  `point_decode_neg_zero_u_*` vectors cover it.
- **The counter bound is checked only structurally.** No real input reaches counter 254, so
  only the stub tests in `check_findgrouphash_*` detect a wrong bound.

## Spec ambiguities and observations

No spec value was found to be wrong. Points that a reviewer may want to tighten:

1. **Label first character (§4).** `id` must start with `[a-z0-9]`, but labels have no
   first-character rule. Read literally, a label may start with `.`, `-` or `_`. This
   reference implements the literal reading. `schema_literal_label_leading_punct_accepted=true`
   records that `.amount`, `-asset` and `_memo` are accepted, together with that schema's
   encoding and digest. If the asymmetry is unintended, the spec should say so, and an
   implementation that rejects these labels diverges from the literal text.
2. **Rejection precedence (§4.1).** The decoder's rejection categories are listed but not
   their order, so the *reason* for an input that breaks several rules is
   implementation-defined. This reference checks in wire order: tag; id length, id charset,
   id first character; version; `n`; then per entry width, label length, label charset and
   duplicate; and finally trailing bytes. An input shorter than the tag is `truncated` only if
   it is a prefix of the tag, and `bad_tag` otherwise. The accept/reject verdict does not
   depend on this order.
3. **"…" in §4.3.** The elision is not defined in the text. It stands for the 48-byte prefix
   above, which runs through the id and ends just before the version.
4. **§4.3 closing sentence (editorial).** "The last three share dimension and, for the first
   two, widths with the first schema" means the first two *of the last three* (version 2 and
   labels swapped, both widths 64/32). It could be misread as table rows 1–2. The computed
   values agree with the intended reading.
5. **§1 counter bound.** The loop `j = 0..254` is unambiguous. The parenthetical claim about
   when `sapling-crypto` panics was not checked against its source (see above), and no pinned
   vector reaches the bound.
6. **Version 0.** "unsigned 16-bit integer" admits 0, and this reference accepts it. No vector
   uses it.

## Spec revision after this run

`docs/specs/pedersen-jubjub-vector-v1.md` was clarified after this reference was written. No
pinned value changed.

| Item | Resolution in the spec |
|---|---|
| Label first character | §4 now states explicitly that a label may start with any allowed character, matching the literal reading implemented here (`schema_literal_label_leading_punct_accepted=true`) |
| Rejection order | §4.1: whether an input is rejected is normative; which rule is reported first is not |
| `…` elision | §4.3 defines it as the 48-byte prefix shared with the first row |
| "for the first two" | §4.3 rewritten to name the schemas with identical shape |
| Panic remark | §1 cites `find_group_hash`'s `assert!(tag[i] != u8::MAX)` in `sapling-crypto` 0.9.0 `src/constants.rs`, checked by the author against that source |
