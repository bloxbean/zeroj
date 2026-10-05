# ElGamal-Jubjub v1 independent reference

This is an independent reproduction of the `elgamal-jubjub-v1` profile, written from the
normative spec alone. Its output serves as evidence against ZeroJ's Java implementation
(ADR-0052 milestone M0).

## Files

- `elgamal_jubjub_v1_reference.py`: Python 3, standard library only. It implements:
  - Jubjub affine twisted-Edwards arithmetic (`a = −1`). It uses the unified addition law with
    one Fermat inversion per addition, and doubling goes through the same law. Scalar
    multiplication is right-to-left double-and-add on the raw, unreduced integer. The
    subgroup check is `[l]·P == O`.
  - The derivation of `d = −10240/10241 mod p` and `G = [8]·G_full`, which are then compared
    with the pinned values.
  - Generic Tonelli–Shanks square roots, and the point encoding and decoding of
    `pedersen-jubjub-v1` §4.
  - §3.2 key contexts with every refusal rule, and the registered share order.
  - §4 encryption, and §5 `add` and `scale` with the context rule and the bound rule.
  - §6 single-key and n-of-n decryption, with plaintext recovery by linear search
    (published limit `2^18` steps).
  - §7 ciphertext, public-key and affine-coordinate validation.
  - §8 public-input orders.
  - The R_dleq relation, checked directly with the witness. There are no proofs.
  - The §12 test vectors, the ADR counterexamples and a cross-check of the prototype output.
- `reference-output.txt`: the script's output, as `key=value` lines under a `#` header.

## Independence rules followed

Read:

- `docs/specs/elgamal-jubjub-v1.md`, the spec under test.
- `docs/specs/pedersen-jubjub-v1.md`, for `p`, `l`, `a`, the cofactor, `G_full` and `G`
  (§1, §2.1) and the point encoding (§4).
- `../pedersen-reference/README.md`, only for the README and output conventions.
- `zeroj-usecases/private-voting/src/test/resources/elgamal-reference/reference-output.txt`,
  the prototype's output values, only for the cross-check.

Not read: any `.java` file, any other `.py` file (including the prototype script next to
that output), any build output, and any other file in either repository. Neither repository
was searched. Where the spec was unclear, the most literal reading was implemented and the
issue is recorded below, not resolved from code.

The script takes `p`, `l`, the cofactor and `G_full` from the spec as inputs. It derives
`d` and `G` itself. The pinned `d`, `G` and `encode(G)` are typed in by hand only as
comparison targets. The BLS12-381 parameter `z = −0xd201000000010000` is used only to check
that `p = z⁴ − z² + 1`.

## Running

```
cd zeroj-circuit-lib/src/test/resources/elgamal-reference
python3 elgamal_jubjub_v1_reference.py                    # embedded prototype copy
python3 elgamal_jubjub_v1_reference.py --prototype PATH   # parse a prototype file instead
```

The run takes about 10 s, mostly the linear search that recovers `37035`. The script prints
to stdout and rewrites `reference-output.txt`. Apart from the `# Python:` header line, the
output is deterministic.

| Status | Meaning |
|---|---|
| 0 | Every `check.*` and `spec_match.*` is `true`, and every negative vector's `observed` equals its `expected`. |
| 1 | Something failed. The output is still written, ending in `result=fail`, and the failing keys go to stderr. An unexpected exception also gives status 1, with an `error=` line. |

Mutated copies of the script were run to confirm that it fails. Each of these was detected:

- a wrong pinned `G.u`;
- big-endian `v` in the encoding;
- an inverted parity choice in decoding;
- reducing `v mod p` instead of rejecting `v ≥ p`;
- dropping the ZIP 216 rule;
- dropping the subgroup check;
- a wrong sign of `d`;
- reducing affine coordinates mod `p`;
- dropping the §6.1 key check;
- dropping the §5 bound rule;
- one changed hex digit in the prototype's `M`;
- sorting shares by the encoding read as a little-endian integer.

The last one was caught only by the supplementary `sortvec` vector (finding 10).

## Output format

Each line is `key=value`:

- Field elements and coordinates are `0x` plus 64 lowercase hex digits. This also applies to
  `curve.p`, `curve.l`, the scalars, and the out-of-range affine integers such as `G.u + p`.
  The one negative integer, `affine_neg.u_negative_alias.u`, is written `-0x` plus 64 hex
  digits.
- These integers are decimal: `.m`, `.w`, `.bound`, `.dec`, `nofn.tally`, the small `cx.*`
  integers (`secret_*`, `k`, `m`, `result_*`, `dec*`), `bound.*`, `sortvec.multiples` and the
  `info.*` counters. The exception is `cx.wrap.m1`, which is `l − 1` in hex.
- Byte strings are bare lowercase hex: point encodings (64 hex characters), ciphertext
  encodings (128 hex characters) and negative-decode inputs.
- Lists, such as `publicInputs`, `registered_order` and `registered_encodings`, are
  comma-separated.
- Checks are `true` or `false`.

| Key family | Content |
|---|---|
| `profile`, `curve.{p,l,d,cofactor}`, `G_full.*`, `G.{u,v,encoding}` | Constants, with `d` and `G` derived here. |
| `spec_match.{d,G,G_encoding}` | Comparison with the values the spec pins. |
| `scalar.<tag>` | §12 `scalar(tag)` for `sk`, `k0`, `k1`, `k16`, `k64`, `share1..3` and `ballot1..5`, plus the reference-local `wrap1` and `wrap2`. |
| `single.pk.*`, `single.enc.<c>.*` (`c` ∈ `m0w1`, `m1w1`, `m12345w16`, `mmaxw64`) | Single-key vectors: `m`, `w`, `k`, `A.u/v`, `B.u/v`, `encoding`, `bound`, `dec_point_ok`, and `dec` except for `mmaxw64`. |
| `single.add01.*`, `single.scale3_12345.*` | `add(Enc(0), Enc(1))` (bound 2, dec 1) and `scale(3, Enc(12345))` (bound 196605, dec 37035). |
| `nofn.share<j>.*`, `nofn.pk.*`, `nofn.registered_order`, `nofn.registered_encodings` | Three trustees, the joint key and the §3.2 sorted order. |
| `nofn.ballot<i>.*`, `nofn.sum.*`, `nofn.D<j>.*`, `nofn.M.*`, `nofn.tally` | Five ballots `1,0,1,1,0` at `w = 1`, their sum (bound 5), the decryption shares on `sumA`, `M = 3G` and the tally `3`. |
| `nofn.dleq<j>.publicInputs`, `nofn.pop<j>.publicInputs`, `nofn.encstmt.ballot1.{w,publicInputs}` | §8 orders: the share statement `(X = sumA, P = PK_j, D = D_j)`, the proof of possession `(G, PK_j, PK_j)`, and the encryption statement `(PK, A₁, B₁)` under the joint key. |
| `sortvec.*`, `info.sortvec.*` | A supplementary sort vector over `[1]G`, `[2]G` and `[4]G`, with the orders that four wrong comparators would give (finding 10). |
| `cx.wrongsecret.*` | `(G, 4G)` under `PK = 3G`: secret 4 gives `M = O` and dec 0, secret 3 gives dec 1, and §6.1 refuses secret 4. |
| `cx.mixed.*` | `Enc(1; 1, 3G) + Enc(1; 1, 2G) = (2G, 7G)` decrypts to 1 under secret 3. The context rule refuses the `add`. |
| `cx.forged.*` | Keys `3G` and `5G`, `m = 1`, `k = 7`: `A = 7G`, `B = 57G`, `D1 = 21G`, `D2 = 35G` and the forged `36G`. The honest result is 1, the forged result 0, and the forged share fails the DLEQ relation. |
| `cx.wrap.*` | The raw sum of `Enc(l − 1)` and `Enc(1)` under `single.pk` has `M = O` and dec 0. `l − 1` does not fit at `w = 64`, §4 refuses it, and the §5 bound rule refuses the `add`. |
| `bound.w64.*` | The largest `c` that `scale(c, ·)` accepts on a `w = 64` ciphertext, and the smallest it refuses. |
| `decode_neg.<name>.{input,kind,expected,observed}` | Byte-level vectors (§7.2, §7.3). `kind` is `ciphertext` or `publickey`. |
| `affine_neg.<name>.{u,v,kind,expected,observed}` | §7.4 integer-coordinate vectors. `kind` is `point` (a ciphertext component, where the identity is allowed) or `publickey`. |
| `check.prototype.<name>`, `check.prototype.tally` | Every prototype point, recomputed under this spec. |
| `check.*` | Internal checks, including `roundtrip.*` for every positive encoding. |
| `info.*` | Diagnostics that are not pass/fail. |
| `result` | `pass` or `fail`. Always the last line. |

`expected` takes these values. The spec requires rejection but does not name outcome
categories (finding 7), so the labels are this reference's own.

| Label | Rule |
|---|---|
| `reject_length` | The length is not 32 (a point) or 64 (a ciphertext). |
| `reject_noncanonical_v` | Pedersen §4 rule 2: `v ≥ p`. |
| `reject_non_square` | Rule 4. |
| `reject_u_zero_sign_set` | Rule 5 (ZIP 216). |
| `reject_not_in_subgroup` | §7.2 or §7.3: the point is not in `𝔾`. |
| `reject_identity_key` | §7.3: `PK = O`. |
| `reject_noncanonical`, `reject_off_curve` | §7.4 rules 1 and 2. |
| `accept` | The input is valid. |

The non-canonical `v` vectors are aliases of valid points:

- `ct_A_noncanonical_v` and `pk_noncanonical_v` encode `v([4]G) + p`. A decoder that reduces
  `v mod p` would accept `[4]G`.
- `ct_B_noncanonical_v_identity_alias` encodes `v = p + 1`, which reduces to the identity.
- `affine_neg.u_plus_p`, `affine_neg.v_plus_p` and `affine_neg.u_negative_alias` are
  aliases of `G` mod `p`.

## Result

`result=pass`. Every check passes, and every value the spec pins (`d`, `G` and `encode(G)`)
matches. Each counterexample in spec §6.1, §10.2 and §12 reproduces exactly as stated.

## Prototype cross-check

The prototype's `reference-output.txt` (in `zeroj-usecases/private-voting`) is embedded in
the script verbatim, and a run confirmed it is byte-identical to that file. The script parses
the prototype's scalars `sk1..3` and `k1..5` and its votes `v1..5`. Under this spec it
recomputes:

- `PK_j = [sk_j]·G` and `PK = Σ PK_j`;
- `A_i = [k_i]·G` and `B_i = [v_i]·G + [k_i]·PK`;
- `sumA` and `sumB`;
- `D_j = [sk_j]·sumA` and `M = sumB − Σ D_j`;
- the tally, by linear search.

**The cross-check passed.** All 21 listed points (`A1..A5`, `B1..B5`, `G`, `PK1..PK3`, `PK`,
`sumA`, `sumB`, `D1..D3`, `M`) match, and the tally is `3`. A second run with `--prototype`
pointed at the live file gave identical output, apart from the `info.prototype_source` line.

The prototype's scalars are not the §12 `scalar(tag)` values
(`info.prototype_scalars_equal_spec12_scalars=false`). The two vector sets are therefore
independent.

## Spec ambiguities and findings

1. **§12, no values are pinned.** The "Pinned values" table is empty ("filled from the
   reference output at M0"). Only `d`, `G` and `encode(G)`, from §1 and pedersen §2.1, can be
   compared with the spec. A wrong tag prefix, tag spelling or byte order in `scalar(tag)`
   would pass every check here. Until the table is filled from this output, the §12 vectors
   rest on this reference agreeing with the Java code, not on the spec.
2. **§12, tag construction.** The spec writes `"share" + j` and `"ballot" + i` without saying
   how the integer becomes text. *Interpretation:* decimal ASCII, no padding, 1-based:
   `share1..share3` and `ballot1..ballot5`. Ballot `i` carries the `i`-th message of the list
   `1, 0, 1, 1, 0`.
3. **§12, a zero secret from `scalar(tag)`.** §2 resamples secret keys until they are
   non-zero, but the §12 derivation has no such step. *Interpretation:* the derived secrets
   are used as they are. All four (`sk`, `share1..3`) are non-zero
   (`check.secret_scalars_nonzero`), so the point is moot for these tags. The spec could say
   so, or define a fallback.
4. **§12, `Enc(m; k, PK)` notation.** The counterexamples write `Enc(1; 1, 3G)`, but §4 never
   defines an argument order. *Interpretation:* `Enc(m; k, PK)`, which reproduces the stated
   `(G, 4G)` and the stated results.
5. **§12, expected values not stated.** §12 lists the cases but not the results they should
   give. *Interpretations:*
   - The decryption shares are taken on the **sum**: `D_j = [sk_j]·Σ A_i`, not per ballot.
   - The bounds follow §5: 2 for `add01`, `3·(2¹⁶ − 1) = 196605` for the scale case and 5
     for the sum.
   - The pinned statements are the DLEQ share statement on `sumA`, the proof of possession
     for each `PK_j`, and the encryption statement for ballot 1 under the joint key.
   - For `m = 2⁶⁴ − 1`, only `B − [sk]·A = [m]·G` is asserted. Recovering it by search is
     beyond any linear-search limit, and §6.3 lets an implementation refuse it.
6. **§10.1 conflicts with §5 (most significant).** §10.1 says a ciphertext obtains a key
   context and a bound "in exactly two ways": local encryption or verified admission. It adds
   that "no other way to attach a bound or a key exists". But §5 gives the result of
   `add`/`scale` a bound, and §12 and §6.2 decrypt such a result, the five-ballot sum. That
   sum was neither encrypted locally nor admitted. §10.2 also requires `A` to come "from the
   admitted ciphertext". *Interpretation:* the result of a §5 operation on admitted
   ciphertexts is admitted, inherits their common context and carries the §5 bound. §10.1
   should say this explicitly, or limit "exactly two ways" to raw ciphertexts.
7. **§7, outcome categories and precedence.** The spec lists rejection conditions but no
   distinguishable outcomes. It also gives no precedence when several apply: both halves of a
   ciphertext bad, or a half that fails to decode against one that fails the subgroup check.
   *Interpretation:* the `expected` labels are this reference's classification, and halves
   are examined in the order `A` then `B`, each decoded and then subgroup-checked. Every
   vector here violates exactly one rule, so no precedence question arises. A consumer should
   assert reject versus accept, and treat the category as informative.
8. **§7.4, signed integers.** Ledger datum integers are signed, and rule 1 (`0 ≤ u`)
   correctly covers negative values. A vector with `u = G.u − p` (≡ `G.u`) is included, which
   an implementation that reduces mod `p` would accept as `G`. This is not an ambiguity. It
   is noted because the value is serialised with a `-0x` prefix, which a consumer must parse.
9. **§3.2, context equality.** "Equal if and only if their joint keys are equal and their
   sorted share encodings are equal": the first condition follows from the second, since
   `PK = Σ PK_j`. A consequence worth confirming: the single-key context `{PK}` and the
   3-share context with the same `PK` are **different** contexts, so their ciphertexts cannot
   be combined.
10. **§3.2, sort-order pitfall.** "Unsigned lexicographic byte order" applies to the
    **little-endian** encodings, so the first byte compared is the least significant byte of
    `v`. The §12 shares give the order `2,3,1`, which separates it from numeric-`v` order
    (`3,1,2`) and from signed-byte order (`3,1,2`). They do **not** separate it from "the 32
    bytes read as a little-endian integer" (`2,3,1` again), because the sign bit at `2²⁵⁵`
    dominates. The supplementary vector `sortvec` (`[1]G`, `[2]G`, `[4]G` → `2,4,1`) separates
    all four wrong comparators, including numeric `u`. *Recommendation:* pin a sort vector.
11. **§2, `k = 0` is allowed (informational).** `k ∈ [0, l)` admits `k = 0`, which gives
    `A = O` and `B = [m]·G` and so reveals `m`. The probability is `1/l ≈ 2⁻²⁵²`, so this is
    harmless. It is consistent with §7.2 accepting an identity `A`. Unlike `sk`, `k` is not
    resampled. The spec could say that this is deliberate.
12. **§3.3, the proof of possession is not bound to a context (informational).** The PoP
    statement `(X = G, P = PK_j, D = PK_j)` carries no election or trustee identifier, so one
    proof is valid for that key in every context. This still prevents rogue keys: a copied
    key is a duplicate within one context, and a party that copies a key into another context
    cannot decrypt with it. But a PoP does not authenticate who registered the key. That is
    protocol-level, outside this profile.
13. **§5, the wrap example is outside the profile.** "The raw sum of encryptions of `l − 1`
    and `1`" cannot be produced by §4, because `l − 1 ≥ 2⁶⁴`. The reference builds it with the
    raw formula `([k]·G, [m]·G + [k]·PK)`, using the reference-local tags `wrap1` and `wrap2`,
    which are not §12 tags. It confirms that §4 and the §5 bound rule each refuse it.

Everything else checked agrees with the spec's stated claims:

- `d` is a non-square, and `−1` is a square;
- pedersen §4 rule 3 is unreachable;
- `G_full` has order `8l`, and `#E = 8l` by the Hasse bound;
- `2⁶⁴ − 1 < l` and `2²⁵¹ < l < 2²⁵²`;
- the §2 sampler bias is below `2⁻²⁵⁹`;
- the §6.1, §10.2 and §12 counterexample arithmetic is correct.

## Spec revision after this run

The findings were resolved in `docs/specs/elgamal-jubjub-v1.md` before any library code was
checked against this output. The reference output did not change.

| Finding | Resolution in the spec |
|---|---|
| 1. §12 pins no values | §12 now pins `scalar("sk")`, both public keys, four ciphertext encodings, the registered order, `D_1`, the tally and the forged-share result. All are copied from this output. |
| 2. Tag spelling | §12: decimal, unpadded, 1-based (`share1`, `ballot5`). |
| 3. Zero test secret | §12: a vector set whose secret derives to zero is invalid. It is not resampled; none does. |
| 4. `Enc(m; k, PK)` | Defined in §4. |
| 5. Expected results unstated | §12 states the bounds, `D_j = [sk_j]·A_sum`, and which statements are pinned. |
| 6. §10.1 vs §5 | §10.1 gains a third way in: a §5 combination of admitted ciphertexts under one context, carrying the §5 bound. |
| 7. Rejection precedence | §7.2: a decoder rejects if any rule fails; no precedence among reasons is defined. Consumers compare accept versus reject only. |
| 8. Signed affine integers | No change: §7.4 rule 1 already rejects negatives. |
| 9. Context equality | §3.2: equality by sorted share encodings. A single key and a share set with the same sum are different contexts. |
| 10. Sort comparator | §3.2 pins byte-0-first unsigned comparison, and §12 adds the `sortvec` order. |
| 11. `k = 0` | §4 states it is deliberate, with probability about `2⁻²⁵²`. |
| 12. Possession is context-free | §3.3 states it. Applications authenticate key registration separately. |
| 13. Wrap example | No change: §5 already presents it as the case the bound rule excludes. |
