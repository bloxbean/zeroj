# Pedersen-Jubjub Bytes v1 independent reference

An independent reproduction of the `pedersen-jubjub-bytes-v1` profile, written from the
normative spec and RFC 9380 alone so that its output can serve as evidence against ZeroJ's Java
implementation (ADR-0058 milestone M0).

## Files

- `pedersen_jubjub_bytes_v1_reference.py`: Python 3, standard library only (`hashlib` for
  SHA-256 and, in one mutation, SHA-512). It implements:
  - RFC 9380 `I2OSP`, `OS2IP` and `expand_message_xmd` (§5.3.1) with SHA-256, checked against
    all ten Appendix K.1 SHA-256 vectors.
  - `HashBytesToScalar` (spec §3.1) in three independently written forms: generic RFC 9380
    `hash_to_field` with `msg = B ‖ I2OSP(n, 8)`, the spec's octet-by-octet restatement, and a
    single-pass incremental form fed in chunks (spec §6.1). All three must agree.
  - The `MAX_PAYLOAD_BYTES` gate, tested without allocation through an object that reports a
    huge length. The gate must fire before any octet is hashed.
  - Twenty mutated variants of the hash. Each is a separate function, not a flag on the real
    one.
  - Jubjub arithmetic in extended twisted-Edwards coordinates with the unified HWCD addition.
    This formulation differs deliberately from the sibling's affine arithmetic.
  - Tonelli–Shanks square roots, the §4 encoding and decoding of `pedersen-jubjub-v1`, and the
    §4.1 prime-order subgroup check for received points.
  - A deliberately lenient decoder that reduces `v` mod `p` (`receive_with_v_reduced_mod_p`).
    It is not the profile. It exists only to show that the `v ≥ p` alias of the identity is
    rejected by rule 2 alone.
  - An order-8 torsion point derived analytically from the curve equation, cross-checked
    against the torsion component `[l]·G_full`.
  - `C_bytes(B, r)` (spec §4), which rejects `r` outside `[0, l)` instead of reducing it.
- `reference-output.txt`: the script's output.

The bases `G` and `H` come from the sibling reference
`../pedersen-reference/pedersen_jubjub_v1_reference.py`, which is imported, not copied. The
script uses its Poseidon parameter generation, its derivation of `H`, and its affine arithmetic
as a differential for `C(s, r)`. Before the import the script sets
`sys.dont_write_bytecode = True`, so no `__pycache__` is created. The sibling's `main()` sits
behind `if __name__ == "__main__"`, so the import neither runs it nor rewrites its
`reference-output.txt`. The script then compares `G`, `H` and `C(42, 12345)` with the values
that `pedersen-jubjub-v1.md` pins.

## Independence rules followed

Read:

- `docs/specs/pedersen-jubjub-bytes-v1.md` (primary source).
- `docs/specs/pedersen-jubjub-v1.md` (curve, `G`, `H`, commitment, encoding, §4/§4.1 rules,
  §8 pin).
- `docs/specs/jubjub-eddsa-v1.md` §1 only.
- `../pedersen-reference/README.md`, `pedersen_jubjub_v1_reference.py` and the first 20 lines
  of its `reference-output.txt` (to match the output style).
- RFC 9380, fetched as plain text from <https://www.rfc-editor.org/rfc/rfc9380.txt> into a
  scratch directory outside the repository. Sections read: §3.1, §4, §5 (introduction), §5.2,
  §5.3, §5.3.1, §5.3.3 and Appendix K.1. All ten K.1 SHA-256 vectors were extracted from that
  text, by a small parser that also confirmed the `q128_`/`a512_` message lengths (133 and 517
  octets), and then typed into the script.
- For the extension run: the revised `docs/specs/pedersen-jubjub-bytes-v1.md`, read again in
  full, and the reviewer's expected hex for `neg_v_ge_p_alias_identity`, which the script
  verifies independently.

Not read: any `.java` file, any build output, the ADR, git history, and any other repository
file. The repository was not searched. Incidental exposure was limited to file names: a
directory listing of `src/test/resources/` and `git status`. The latter showed that Java files
exist in the working tree, and none of them was opened. Where the spec was unclear, the most
literal reading was implemented and the issue is recorded below, not resolved from code.

The values the spec pins are typed into the script by hand only as comparison targets, never as
inputs. These are the DST, its length, `L`, `MAX_PAYLOAD_BYTES`, the `b0` overhead of 122, `G`,
`H` and `C(42, 12345)`. The revised spec's §10 inline known answers (`SPEC10`) are handled the
same way. Those §10 values were copied into the spec from an earlier run of this script, so
`check_spec10_*` guards the spec text and later runs rather than giving independent evidence.
The RFC 9380 K.1 expected values were copied from the fetched RFC text.

## Running

```
cd zeroj-circuit-lib/src/test/resources/pedersen-bytes-reference
python3 -B pedersen_jubjub_bytes_v1_reference.py     # or python3 -I
```

The run takes about 1.6 s, most of it the sibling's Poseidon constant generation. The script
prints to stdout and rewrites `reference-output.txt`.

### Provenance header

The `#` header records:

- the Python implementation and version;
- the SHA-256 backend: `hashlib OpenSSL (<constructor>; <ssl.OPENSSL_VERSION>)` when
  `hashlib.sha256` is OpenSSL-backed (its type comes from `_hashlib`), or
  `hashlib builtin (<module>.<type>)` otherwise;
- the script name and the spec path;
- the SHA-256 content hashes of this script, of the imported sibling
  `../pedersen-reference/pedersen_jubjub_v1_reference.py`, and of
  `docs/specs/pedersen-jubjub-bytes-v1.md`. A hash is `unavailable` if the file cannot be read.

The `# Python:` and `# SHA-256 backend:` lines depend on the interpreter. The three content
hashes change only when those files change. Every `key=value` line is deterministic. The run
recorded here used CPython 3.13.5 with OpenSSL 3.0.16 (11 Feb 2025).

| Exit status | Meaning |
|---|---|
| 0 | Every check passed (`result=pass`). |
| 1 | A `check_*` key, a spec comparison, a negative vector or an internal agreement check (the three hash forms) failed. The output is still written, and the failing keys go to stderr. |
| 2 | The RFC 9380 Appendix K.1 `expand_message_xmd` self-check failed. The run stops before any fixture is computed, and the partial output ends with `result=fail`. |

## Output format

The output is `key=value` lines under `#` provenance lines (Python version, script name, spec
path). Field elements and scalars are `0x` plus 64 lowercase hex digits. Octet strings are bare
lowercase hex; an empty payload is an empty value. Integers are decimal and booleans are
`true` or `false`. The last line is `result=pass` or `result=fail`.

| Key family | Content |
|---|---|
| `check_k1_*` | RFC 9380 K.1: `DST_prime` and all ten SHA-256 vectors (`msg` = `""`, `abc`, `abcdef0123456789`, `q128_` + 128 × `q` and `a512_` + 512 × `a`, each for `len_in_bytes` `0x20` and `0x80`). Failure gives exit 2. |
| `dst_ascii`, `dst_hex`, `dst_prime_hex`, `L`, `max_payload_bytes`, `l`, `p` | The profile constants as computed. |
| `check_spec_*` | Comparison with spec §2 (DST length and hex, `DST_prime` length, `ceil(log2 l) = 252`, `L = 48`, `MAX_PAYLOAD_BYTES`, the 122-octet overhead, the `2^61` bound, the bias bound `l/2^384 < 2^-132`, `l < p`). Also `G`, `H` and the sibling's `C(42, 12345)` against `pedersen-jubjub-v1.md` §2 and §8. |
| `check_spec10_*` | The inline known answers of spec §10: empty `n`, `b0`, `uniform_bytes` and `s`; `s` for `zero1` and `utf8_text`; `encode(C_bytes(empty, 0))`, `encode(C_bytes(empty, l − 1))` and `encode(C_bytes(utf8_text, l − 1))`. |
| `g_*`, `h_*`, `check_g_h_in_subgroup`, `check_sibling_constants_match`, `check_ext_arith_c_42_12345_matches_sibling` | The bases, plus a check that the extended-coordinate arithmetic agrees with the sibling's affine arithmetic. |
| `<name>_n`, `_payload` or `_recipe`, `_b0`, `_b1`, `_b2`, `_uniform`, `_s` | Positive fixtures for 35 payloads. `_uniform` is the 48-octet `uniform_bytes` (the key name predates the spec's rename). `_payload` is given for payloads of 64 octets or fewer, and `_recipe` for longer ones. |
| `check_octet_form_matches_all`, `check_streaming_chunks_match` | Agreement of the three hash forms. Chunk sizes are 1, 7, 64 and 4096. |
| `check_padding_boundary_lengths` | `(n + 122) mod 64` for the boundary patterns (see the payload table). |
| `check_nfc_nfd_differ`, `check_empty_zero1_differ`, `check_lead_trail_zero_differ`, `check_empty_equals_pattern_0`, `check_all_s_distinct`, `check_rejects_n_above_max` | Relations between the fixtures. |
| `r1`, `r2`, `check_r2_lt_l` | The fixed test blindings. `R1 = l − 1`, and `R2` needs no reduction because it is below `l`. |
| `<name>_c_r1_{u,v,encode}`, `<name>_c_r2_{u,v,encode}`, `empty_c_r0_{u,v,encode}` | Commitments for `empty`, `zero1`, `utf8_text`, `all_bytes` and `pattern_8193`, plus `empty` with `r = 0`. |
| `check_c_bytes_equals_sibling_numeric_c`, `check_commitments_in_subgroup_and_roundtrip`, `check_empty_c_r0_not_identity`, `check_empty_c_r0_equals_s_g`, `check_c_bytes_rejects_r_eq_l`, `check_c_bytes_rejects_r_negative` | Commitment relations, including the rule that an out-of-range `r` is rejected rather than reduced. |
| `mut_payload`, `mut_true_s`, `mut_<name>_s`, `check_mut_<name>_differs` | Mutation fixtures on `utf8_text`. `signed` is handled differently, as described in the next row. |
| `mut_signed_s`, `mut_signed_utf8_text_u_top_bit_set`, `check_mut_signed_equal_on_utf8_text`, `mut_signed_alt_payload`, `mut_signed_alt_true_s`, `mut_signed_alt_s`, `check_mut_signed_differs_on_alt`, `check_mut_signed_differs_iff_top_bit_set_all_fixtures` | The signed mutation (observation 2 below). |
| `neg_<name>_input`, `neg_<name>_expected=reject`, `neg_<name>_reason`, `check_neg_<name>_rejected`, plus `neg_off_curve_v`, `neg_small_order_4_u`, `neg_mixed_order_{u,v}`, `neg_small_order_8_{u,v}` and `neg_mixed_order_8_{u,v}` | Received-point negatives. |
| `check_neg_v_ge_p_alias_identity_matches_expected`, `check_neg_v_ge_p_alias_identity_reason_v_ge_p`, `check_neg_v_ge_p_alias_identity_reduced_would_accept` | The `v = p + 1` identity alias matches the reviewer's hex. Its only rejection reason is rule 2, and reducing `v` mod `p` would give the accepted identity. |
| `neg_wrong_length_note`, `check_neg_length_{31,33,0}_rejected` | Wrong lengths. They are checked but not emitted as fixtures. |
| `check_t2_*`, `check_t4_*`, `check_t8_*`, `check_mixed_*`, `check_g_plus_t8_order_8l`, `check_v_ge_p_max_is_ge_p` | Each negative point is constructed and its order verified, independently of the decoder. |
| `pos_identity_input`, `pos_identity_expected=accept`, `check_pos_identity_accepted` | The identity `(0, 1)` is accepted. |

Payloads:

| Name | Octets |
|---|---|
| `empty` | (none) |
| `zero1` | `00` |
| `lead_zero` / `trail_zero` | `00 00 01` / `01 00 00` |
| `all_bytes` | `00 01 … ff` (256 octets; recipe) |
| `nul_embedded` | `61 00 62` |
| `invalid_utf8` | `c3 28` |
| `utf8_text` | UTF-8 of `Hello, ZeroJ ✓` = `48656c6c6f2c205a65726f4a20e29c93` |
| `nfc_e` / `nfd_e` | `c3 a9` / `65 cc 81` |
| `bom` | `ef bb bf 61` |
| `pattern_N`, N ∈ {0, 1, 5, 6, 7, 55, 56, 60, 61, 62, 63, 64, 65, 119, 120, 125, 126, 127, 128, 8191, 8192, 8193, 65536, 1048576} | `payload[i] = (131·i + 17) mod 256`. `_payload` is emitted for N ≤ 64 and `_recipe` for larger N. |

The input to `b0` is `n + 122` octets, and SHA-256 fits its padding into the last block only
while the length mod 64 is at most 55. The boundary lengths, measured on `b0`'s input, are:

| `n` | `n + 122` | mod 64 | Meaning |
|---|---|---|---|
| 5 | 127 | 63 | One octet short of a full block |
| 6 | 128 | 0 | Exactly two blocks; padding takes a block of its own |
| 7 | 129 | 1 | One octet into the third block |
| 60 | 182 | 54 | Padding fits the final block, with one octet to spare |
| 61 / 125 | 183 / 247 | 55 | Largest length whose padding fits the final block |
| 62 / 126 | 184 / 248 | 56 | Smallest length that needs an extra padding block |
| 63 | 185 | 57 | One octet past the padding transition |

The original N = 55, 56 and 64 measure the boundaries on `B` alone, which is not what
SHA-256 sees. N = 63 does both jobs.

Mutations, all computed on `utf8_text`:

| Name | Change |
|---|---|
| `dst_lowercase` | DST lower-cased |
| `dst_sha512_label` | DST text says `SHA-512`, still hashed with SHA-256 |
| `length_prefix` | `I2OSP(n,8) ‖ B` |
| `length_le` | 8-octet little-endian suffix |
| `no_length` | `msg = B` |
| `no_zpad` | 64 zero octets omitted |
| `zpad128` | 128 zero octets |
| `len64` | `len_in_bytes = 64` (`u` = `b1 ‖ b2`, 64 octets), then reduced mod `l` |
| `sha512` | Whole XMD with SHA-512 (`b = 64`, `s = 128`, `ell = 1`), `L = 48` |
| `no_xor` | `b2 = SHA-256(b1 ‖ 0x02 ‖ DST_prime)` |
| `b0_slice` | `u = b0 ‖ b1[:16]` |
| `first48_wrong` | `u = b2 ‖ b1[:16]` |
| `mod_p` | Reduced mod `p` |
| `signed` | `u` read as a two's-complement signed big-endian integer, then mod `l` (non-negative) |
| `b1_counter_zero` | `b1 = SHA-256(b0 ‖ 0x00 ‖ DST_prime)`, with `b2` built from that `b1` |
| `b2_counter_one` | `b2 = SHA-256((b0 XOR b1) ‖ 0x01 ‖ DST_prime)` |
| `b1_only` | `uniform_bytes = b1` (32 octets), then mod `l` |
| `no_separator` | The `I2OSP(0, 1)` octet is omitted from `b0`'s input |
| `lib_le` | `l_i_b_str` written little-endian (`0x30 0x00`) |
| `dst_prime_no_len` | `DST_prime = DST`, without the length octet |

Negative received-point vectors (pedersen-jubjub-v1 §4/§4.1):

| Name | Construction | Rejected by |
|---|---|---|
| `v_ge_p` | `v = p`, sign 0 | rule 2 |
| `v_ge_p_max` | `ff…ff7f` (`2^255 − 1 ≥ p`) | rule 2 |
| `identity_sign_alias` | `(0, 1)` with the sign bit set | rule 5 (ZIP 216) |
| `off_curve` | `v = 2`, the first `v ≥ 2` with non-square `u²` | rule 4 |
| `small_order_2` | `(0, −1)`, order 2 | §4.1 subgroup |
| `small_order_4` | `(√−1, 0)` with even `u`, order 4. Derived from the curve: `v = 0` forces `u² = −1`, and `[2](u, 0) = (0, −1)`. The encoding is all zero octets. | §4.1 subgroup |
| `small_order_4_odd` | The other order-4 point (odd `u`), `00…0080` | §4.1 subgroup |
| `mixed_order` | `G + (0, −1)`, order `2l` | §4.1 subgroup |
| `v_ge_p_alias_identity` | The identity `(0, 1)` written with `v = p + 1` and sign 0: `02000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73` | rule 2 only; reducing `v` mod `p` would give the accepted identity |
| `small_order_8` | `T8`, order 8. From the doubling formula, `[2](u, v)` has `v = 0` iff `u² = −v²`. With the curve equation this gives `d·v⁴ + 2v² − 1 = 0`, so `v² = (−1 ± √(1 + d))/d`. The script takes the first root for which `v²` is a square, then `v = min(v, p − v)` and the even `u`. It checks that `T8` has order 8, that `[2]T8` has `v = 0`, and that `T8` is one of the multiples of `[l]·G_full`. | §4.1 subgroup |
| `mixed_order_8` | `G + T8`, order `8l` (`[8l]` is the identity, `[4l]` is not) | §4.1 subgroup |

## Results

`result=pass` with exit status 0, under CPython 3.13.5. The run takes about 1.6 s. The output has
464 key lines, including `result`:

- 99 `check_*` keys, all `true`.
- 245 positive-fixture keys (35 payloads × 7).
- 33 commitment coordinate and encoding keys (11 points).
- 20 mutation fixtures (`mut_<name>_s`), plus `mut_true_s` and the `signed` alt values.
- 11 negative point vectors, plus the identity as a positive vector.

| Payload | `s` |
|---|---|
| `empty` | `0x061f05a7e9920513846bc5f0dd366c71a5ed2c35c6cdc88ba6f71d0f355f4181` |
| `zero1` | `0x0dca70c85ae4d9c8e22f6ff09a66fd81291c89763679c0c4acc2957942b53294` |
| `utf8_text` | `0x01021bce20e1ca8d71cc9ce2bbe988eee0335a559a8e7e65574e1049224d674f` |

All ten K.1 vectors match, and so do all nine §10 inline values. `G`, `H` and `C(42, 12345)` match `pedersen-jubjub-v1.md`. Every
mutation except `signed` differs from the true `s` (see observation 2 for `signed`). Every
negative vector is rejected, and the identity is accepted.

## Mutated-copy check

Fourteen mutated copies of the script were made in a scratch directory outside the repository, each
with the sibling import path rewritten to an absolute path. Each was run with `python3 -I -B`.
Every copy exited non-zero, and an unmutated control copy exited 0. The copies were then
deleted.

| Mutation | Exit | Detected by |
|---|---|---|
| Length prefix instead of suffix in the real path | 1 | three-form agreement (`internal_*`) |
| Wrong DST byte (`SHA-257`) | 1 | `check_spec_dst_hex` |
| Reduction mod `p` in the real path | 1 | three-form agreement |
| Missing XOR in `expand_message_xmd` | 2 | K.1 `0x80` vectors |
| One wrong K.1 expected digit | 2 | K.1 |
| One wrong digit in the `C(42, 12345).u` spec pin | 1 | `check_spec_sibling_c_42_12345` |
| Subgroup check removed from `receive` | 1 | `check_neg_small_order_*`, `check_neg_mixed_order_rejected` |
| ZIP 216 rule (`u = 0` with sign set) removed | 1 | `check_neg_identity_sign_alias_rejected` |
| `L = 64` in the real path | 1 | `check_spec_L_48` and three-form agreement |
| `u = b1 ‖ b2[16:]` (wrong half of `b2`) | 1 | three-form agreement |
| `v ≥ p` range check removed from `decode` | 1 | `check_neg_v_ge_p_alias_identity_rejected` and `check_neg_v_ge_p_alias_identity_reason_v_ge_p`, and nothing else (see the extension notes) |
| `l_i_b_str` little-endian in `expand_message_xmd` | 2 | K.1 |
| One wrong digit in the §10 pin for `zero1`'s `s` | 1 | `check_spec10_zero1_s` |
| One wrong digit in the K.1 `q128_` `0x80` expected value | 2 | K.1 |

## Spec ambiguities and observations

1. *(Superseded by the spec revision; see "Spec revision after this run".)*
   **§5, "No payload is defined to map to the identity".** Read literally, this conflicts with
   §3.1 rule 4 and §4. `s = 0` is a valid result and `r = 0` is algebraically allowed, so any
   `B` with `HashBytesToScalar(B) = 0` committed with `r = 0` gives the identity. Such a `B`
   is infeasible to find, at about `2^-252` per trial, but it is not excluded by definition.
   The sentence most likely means "the profile does not special-case any payload to the
   identity". Suggested wording: "No payload is special-cased to the identity; reaching it
   with `r = 0` requires a preimage of `s = 0`."
2. **The `signed` mutation cannot be distinguished on `utf8_text`.** The first octet of `u` is
   `0x14`, so its top bit is clear and the two's-complement reading equals the unsigned one.
   `mut_signed_s` therefore equals the true `s`. The output states this
   (`check_mut_signed_equal_on_utf8_text=true`) and shows the difference on `lead_zero`, the
   first fixture whose `u[0] ≥ 0x80` (`check_mut_signed_differs_on_alt=true`). Across all
   fixtures the mutation differs exactly when the top bit is set. A consumer test must not
   assert that `mut_signed_s` differs for `utf8_text`. It should use the `alt` values, or
   another payload whose `u[0] ≥ 0x80`.
3. **Mutations that touch only `b2` change only the low 128 bits of `u`.** `u = b1 ‖ b2[:16]`,
   so `mut_no_xor_s` shares its leading ~128 bits with the true `s`. A test that compares
   only high limbs or a prefix would miss such a bug. Compare full values.
4. **The length suffix is a profile-specific frame, not plain RFC 9380.** RFC 9380's
   `msg_prime` is already injective in `msg`, because the suffix after `msg` has a fixed
   length. The extra `I2OSP(n, 8)` adds no injectivity, but it does mean that a stock RFC 9380
   `hash_to_field(B)` with this DST does not give `s`. It must be called on
   `B ‖ I2OSP(n, 8)`. The spec states this clearly, and the note is for implementers who reuse
   an RFC 9380 library.
5. **No known answers for `s` exist outside this directory.** The spec pins the constants but
   no `s` value. The external anchors are therefore K.1, which tests `expand_message_xmd` with
   a different DST, and the spec's own octet-by-octet restatement. The `s` values here have not
   been cross-checked against a third, unrelated RFC 9380 implementation. Doing that, for
   example with a Go or Rust `hash_to_field` called on `B ‖ I2OSP(n,8)` with this DST and
   modulus `l`, would strengthen the evidence.
6. **§6 and §6.1 are only partly modelled.** Python has no `null`, and the declared-length and
   bounded read-to-end stream semantics are not modelled: the one extra read, the failure on
   an extra octet and the failure on early end of stream. Only two things are covered:
   read-boundary independence (`check_streaming_chunks_match`) and the validation order of
   `r` before payload length in `C_bytes`. The stream error contract needs Java-side tests.
7. **`MAX_PAYLOAD_BYTES` cannot be exercised for real.** The gate is tested with a fake length
   object only. The bound itself checks out: `n + 122 ≤ 2^61 − 134 < 2^61` octets, which is the
   FIPS 180-4 bound of fewer than `2^64` bits.
8. **Constants.** `ceil(log2 l) = 252` (`2^251 < l < 2^252`), so `L = ceil(380/8) = 48`. The
   bias bound `l/2^384 < 2^-132` holds. The DST is 46 octets, so `DST_prime` ends in `0x2e`.
   `R2 < l`, so no reduction was needed.
9. **Inherited from `pedersen-jubjub-v1`.** Rule 3 of §4 (`d·v² + 1 = 0`) is unreachable on
   Jubjub, so no vector exists for it. The even-`u` order-4 point encodes to 32 zero octets,
   which makes it a natural all-zero input test.
10. **DST format.** The DST follows the requirements of RFC 9380 §3.1: it is non-empty, at
    least 16 octets, carries an application prefix and a version, and is ASCII without a
    terminator. It does not follow the §8 Suite ID naming (`…_XMD:SHA-256_…`), which applies
    to hash-to-curve suites. This is not a defect.

## Spec revision after this run

The spec was revised after this reference was produced, in response to the M0 review rounds.
No revision changed a constant, the frame, the expander, the reduction or the encoding, so the
output above remains valid; it was re-checked against the revised text.

| Revision | Effect on this reference |
|---|---|
| §4/§5 identity wording replaced (observation 1 above): the identity occurs iff `[s]G + [r]H = O`, which for `r = 0` means `s = 0` | Wording only; `check_empty_c_r0_not_identity` still holds |
| Expander output renamed `u` → `uniform_bytes` (the key family here was already `_uniform`) | None |
| Added §6.1 reading rules, §6.2 Java binding, §7 implementation requirements, §9 compatibility, §10 inline known answers (observation 5) | Stream and API rules are exercised by the Java tests, not this script; §10's values are copied from this output |
| §10 said 27 payloads; the extension below adds eight, for 35 | Done: §10 now says 35 |

### Extension after review (same independence rules)

The reviewer asked for the following additions. None of them changes an earlier fixture value.

- All ten K.1 SHA-256 vectors are now checked, instead of six.
- New patterns `n` = 5, 6, 7, 60, 61, 62, 125 and 126 put the boundaries on `b0`'s input
  (`n + 122` octets), which is what SHA-256 hashes. The existing `n = 63` also lies on one.
  5, 6 and 7 straddle a full-block end, and 60 to 63 straddle the 55/56 padding transition.
  This was requested by a second reviewer.
- The output header now records the SHA-256 backend and the content hashes of the script, the
  sibling and the spec (second reviewer).
- Six new mutations: `b1_counter_zero`, `b2_counter_one`, `b1_only`, `no_separator`, `lib_le`
  and `dst_prime_no_len`. All of them differ from the true `s` on `utf8_text`.
- New negatives: `v_ge_p_alias_identity`, `small_order_8` and `mixed_order_8`.
- `check_spec10_*` now compares the output with the spec's §10 inline values.

New observations:

1. **The earlier negative set did not detect a missing `v ≥ p` check.** Without rule 2, the
   `v = p` input reduces to `v = 0`, an order-4 point, and the subgroup check still rejects
   it. `v_ge_p_max` is likewise rejected by a later rule. A decoder with no range check would
   therefore have passed every earlier vector. The `v = p + 1` identity alias is the first
   vector that only rule 2 rejects, because its reduction is the accepted identity. The
   mutated copy without the range check fails on exactly the two alias checks. Java tests
   should include this vector.
2. **`b2_counter_one` also changes only the low 128 bits of `uniform_bytes`**, like `no_xor`
   (observation 3). `mut_b2_counter_one_s` shares its leading 128 bits with the true `s`.
3. **`T8` is a canonical choice made for this fixture.** There are four order-8 points. The
   script picks `v = min(v, p − v)` and even `u` from the first square root of `v²`. The
   spec's rejection rule does not depend on which one is chosen.
4. **The §10 values are not independent evidence.** They were copied from this script's
   output, as the spec says, so `check_spec10_*` only guards against drift.
