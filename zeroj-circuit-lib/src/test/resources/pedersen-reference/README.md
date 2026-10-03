# Pedersen-Jubjub v1 independent reference

An independent reproduction of the `pedersen-jubjub-v1` commitment profile, written from the
normative spec alone so its output can serve as evidence against ZeroJ's Java implementation
(ADR-0051 milestone M0).

## Files

- `pedersen_jubjub_v1_reference.py`: Python 3, standard library only. It implements:
  - Poseidon (`t = 3`, `α = 5`, `RF = 8`, `RP = 57` over the BLS12-381 scalar field), with
    Grain LFSR constant generation. Both are ported from
    `../poseidon-sage/poseidon_bls12_381_reference.sage`.
  - Jubjub affine twisted-Edwards arithmetic (`a = −1`): unified addition, dedicated
    doubling, double-and-add scalar multiplication, cofactor clearing and the subgroup check.
  - Tonelli–Shanks square roots, and the §4 encoding and decoding.
  - The §2.1 base `G`, the §2.3 derivation of `H` and the §3 commitments.
- `reference-output.txt`: the script's output, as `key=value` lines under a `#` header.

## Independence rules followed

Read:

- `docs/specs/pedersen-jubjub-v1.md` (the primary source).
- `docs/specs/jubjub-eddsa-v1.md` §1 (shared curve constants).
- `../poseidon-sage/poseidon_bls12_381_reference.sage`, `sage-reference-output.txt` and
  `README.md` in that directory.

Not read: any `.java` file, any build output, and any other file in the repository. The
repository was not searched. Where the spec was unclear, the most literal reading was
implemented and the issue is recorded below, not resolved from code.

The values the spec pins (`G`, the Poseidon known answers, `a`, the counter, `H` and
`C(42, 12345)`) are typed into the script by hand only as comparison targets, never as inputs.
The Poseidon self-check parses `../poseidon-sage/sage-reference-output.txt` at run time.

## Running

```
cd zeroj-circuit-lib/src/test/resources/pedersen-reference
python3 pedersen_jubjub_v1_reference.py
```

The run takes about 2 s. The script prints to stdout and rewrites `reference-output.txt`.
Apart from the `# Python:` header line, the output is deterministic.

Exit status:

| Status | Meaning |
|---|---|
| 0 | Every check passed. |
| 1 | An internal check, a negative vector or a `spec_match_*` comparison failed. The output is still written, and the failing keys go to stderr. |
| 2 | The Poseidon self-check failed: the first 6 round constants, the MDS matrix, or the 3 known answers differ from the Sage output. |

The script was also run in mutated copies to confirm it fails. A wrong pinned value, the
transposed MDS orientation, and `max(u, p − u)` in the `H` derivation were each detected.

## Output format

Each line is `key=value`:

- Field elements and coordinates are `0x` plus 64 lowercase hex digits.
- Other integers (scalars, counters, orders) are `0x` plus minimal lowercase hex.
- Byte strings, such as encodings and decode inputs, are bare lowercase hex.
- Checks are `true` or `false`.

| Key family | Content |
|---|---|
| `curve.*`, `check.d_*`, `check.minus_one_is_square`, `check.decode_rule3_unreachable` | Constants and their sanity checks. |
| `poseidon.*`, `poseidon2.*`, `selfcheck.poseidon_*`, `info.poseidon_state_times_m_matches_kat` | Poseidon constants, known answers and self-check results. |
| `g_full.*`, `g.*`, `check.g_*`, `selfcheck.*` | The generator `G` and arithmetic self-checks. |
| `h.*` (including `h.attempt.<n>.v/outcome`), `check.h_*` | The `H` derivation, with a trace of every counter tried. |
| `commit.<case>.{value,blinding,value_mod_l,blinding_mod_l,u,v,encoding}` | The commitment cases. |
| `check.c_*`, `check.homomorphic_*`, `check.residue_*`, `check.commits_in_subgroup` | Relations between the commitments. |
| `roundtrip.<point>` | `decode(encode(X)) == X` for every computed point. |
| `decode_neg.<name>.{input,expected,observed,match}`, plus `u`, `v` and `order` for the subgroup cases | Negative decode vectors. |
| `spec_match_<name>` | Comparison with each value pinned in the spec. |
| `result` | `pass` or `fail`. |

The commitment cases are:

| Key | `(v, r)` |
|---|---|
| `c_42_12345` | `(42, 12345)` |
| `c_0_0` | `(0, 0)` |
| `c_1_0` | `(1, 0)` |
| `c_0_1` | `(0, 1)` |
| `c_lm1_17` | `(l − 1, 17)` |
| `c_1_23` | `(1, 23)` |
| `c_0_40` | `(0, 40)` |
| `c_2p64m1_bigr` | `(2⁶⁴ − 1, 0x0123…abcd mod l)` |
| `c_l_5` | `(l, 5)` |
| `c_0_5` | `(0, 5)` |

Each negative decode vector expects one of these outcomes:

| Expected outcome | Spec rule | Vectors |
|---|---|---|
| `reject_length` | 1 | 31 bytes; 33 bytes |
| `reject_noncanonical_v` | 2 | `v = p`; `v = p + 1`; all bytes `0xff` |
| `reject_non_square` | 4 | `v = 2`, the smallest `v ≥ 2` that gives a non-square |
| `reject_u_zero_sign_set` | 5 | The identity with the sign bit set; `(0, −1)` with the sign bit set |
| `decodes_fails_subgroup` | §4.1 | Points of order 2, 4 and 8, and `G + T8`, where `T8 = [l]·G_full` |

No vector exists for rule 3, as explained under the spec findings below.

## Result

Every value the spec pins matches. That covers `G`, `encode(G)`, the three Poseidon known
answers, `a`, the counter, `H`, `encode(H)` and `C(42, 12345)` with its encoding. The
derivation fails at counter 0, where `w` is a non-residue, and succeeds at counter 1.

## Spec ambiguities and findings

1. **§2.2, MDS orientation.** The phrase "multiplies the state by `M`" does not say whether
   the result is `M·s` (`new[i] = Σⱼ M[i][j]·s[j]`) or `s·M`. The Cauchy matrix is not
   symmetric, so the two give different results. This script follows the Sage reference
   (`M·s`), and the known answers confirm that choice: `s·M` fails them, as
   `info.poseidon_state_times_m_matches_kat=false` shows. The spec should state the formula,
   with `M[i][j] = (xᵢ + yⱼ)⁻¹`.
2. **§2.2, the name `Poseidon2`.** The name can be read as the different Poseidon2
   permutation (Grassi, Khovratovich and Schofnegger, 2023). Here it means the original
   Poseidon with two inputs. A different name, or a one-line disclaimer, would avoid the
   confusion.
3. **§2.2, the generator lives outside the spec.** The spec says that anything not written in
   it is not part of the profile. Yet the Grain bit order, the rejection sampling and the
   Cauchy MDS construction are defined only by reference to the external hadeshash script.
   The upstream script may also run MDS security checks and resample `M` when they fail. The
   Sage port here omits any such checks, and this was not verified against upstream.
   Because the known answers match, the pinned `M` is the first matrix sampled.
4. **§2.3, the name `a`.** The derivation's `a` reuses the name of the Edwards parameter `a`
   (`−1`) from §1. The intent is clear from context, but `seed` or a similar name would be
   safer.
5. **§2.3, wording.**
   - "Non-zero quadratic non-residue" is redundant, since a non-residue is never zero.
   - "`min(u, p − u)` compared as integers in `[0, p)`" puts `p − u` outside `[0, p)` when
     `u = 0`. Either reading still gives 0, so this does not change the result.
6. **§4, rule 3 is unreachable on Jubjub.** `d` is a non-square and `−1` is a square, since
   `p ≡ 1 mod 4`. So `−1/d` is a non-square, and no `v` satisfies `d·v² + 1 = 0`. The rule is
   harmless as a defensive check, but no negative vector can exist for it. The spec could say
   so.
7. **§3, negative inputs.** `C(v, r)` is defined "for integers `v` and `r`" using `v mod l`.
   The spec does not say whether negative integers are allowed, or that `mod` means the least
   non-negative residue. Java's `BigInteger.mod` and `remainder` differ on negative inputs.
   This script uses only non-negative cases.

## Spec revision after this run

`docs/specs/pedersen-jubjub-v1.md` was revised after this reference was written, to resolve
the ambiguities listed above. The pinned values did not change, and re-running the script
against the revised spec gives byte-identical output apart from the `# Python:` header line.

| Item | Resolution in the spec |
|---|---|
| 1. MDS orientation | §2.2 now states `s'[i] = Σ_j M[i][j]·s[j]` |
| 2. "Poseidon2" name | renamed `PoseidonT3`, with an explicit note that it is not the Poseidon2 design |
| 3. Generator outside the spec | §2.2 names the pinned hadeshash commit as the definition and points to the Sage golden file and the committed parameter class as by-value records |
| 4. `a` name clash | renamed `tagInt` |
| 5. min wording | `u = min(u, (p − u) mod p)`, both reduced into `[0, p)` |
| 6. Rule 3 unreachable | §4 marks it unreachable on Jubjub and keeps it as a defensive check |
| 7. Negative integers | §3 allows negative inputs and defines `mod l` as the least non-negative residue |

The key names in `reference-output.txt` (for example `poseidon2.*`) are kept as written.
