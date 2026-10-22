# Independent Python reference: Pedersen over BLS12-381 G1 (ADR-0060)

`bls12_381_g1_reference.py` is a stand-alone reference for the ADR-0060 profiles
`pedersen-bls12-381-g1-v1` and `pedersen-bls12-381-g1-bytes-v1` and the basis set
`pedersen-bls12-381-g1-basis-v1`. It is the "stand-alone Python implementation, written from
RFC 9380 without reading the Java" that ADR-0060 D2 asks for. It also recomputes the D4 byte
mapping, the D3 strict decoder and the commitment `C = [m]·G + [r]·H`.

It is a **public test reference**. It is not constant-time and must not handle real secrets.

## Independence rules

What the author read while writing it, and nothing else:

- RFC 9380 (hash-to-curve) text: §3, §3.1, §4, §4.1, §5.2, §5.3.1, §6.6.2, §6.6.3, §7, §8,
  §8.8.1, Appendix E.2 (11-isogeny), Appendix J.9.1 (`BLS12381G1_XMD:SHA-256_SSWU_RO_` vectors)
  and Appendix K.1 (`expand_message_xmd` SHA-256 vectors).
- CIP-0381 text: the Zcash serialization rules for G1, the generator's compressed byte list,
  and the curve parameters (base field modulus, `B = 4`, subgroup order, G1 generator `X`, `Y`).
- ADR-0060 "Decision" sections D1–D5 (notation, basis derivation, strict decoding, byte mapping,
  scalars and encodings). These act as the spec.

What the author did **not** read: any `.java` file, any other file in the repository (including
the other Python references under `src/test/resources`), repository search results, and the web.
No third-party Python package (such as `py_ecc`) is used; only the standard library (`hashlib`,
`json`, `sys`).

Every constant the code relies on (`P_381`, `q`, `b = 4`, `Z = 11`, `A'`, `B'`, the 55 isogeny
coefficients (53 explicit RFC constants and the two implicit leading 1s), `h_eff`, the generator and the Zcash flag rules) was copied from the RFC or the CIP.
During development every transcribed RFC/CIP hex value (114 RFC items, including all J.9.1 and
K.1 expected values, plus the CIP constants) was checked by string match against the
whitespace-stripped source text; none differed. That check script is not part of this directory.
The generator's compressed hex was written from the author's knowledge and is cross-checked
against the CIP-0381 byte list, on-curve and `[q]·g1 = O`.

## How to run

Python 3.13, standard library only. Run it in isolated mode:

```bash
python3 -I -B bls12_381_g1_reference.py --self-test   # exits 0 only if every check passes
python3 -I -B bls12_381_g1_reference.py               # prints the JSON report (sorted keys, indent 2)
```

The script is also importable (`hash_to_curve`, `expand_message_xmd`, `strict_decode`,
`compress`, `derive_basis`, `hash_bytes_to_scalar_g1_trace`, `commit`, ...). Both runs take a few
seconds and their output is deterministic.

## What `--self-test` checks

It prints one `PASS`/`FAIL` line per check and a `SUMMARY` line, and exits non-zero on any failure.

- RFC 9380 Appendix K.1: all ten `expand_message_xmd` SHA-256 vectors (`len_in_bytes` `0x20` and
  `0x80`, five messages each, DST `QUUX-V01-CS02-with-expander-SHA256-128`). `DST_prime` and
  `uniform_bytes` are compared for all ten. `msg_prime` is compared for the three short messages.
- `expand_message_xmd` ABORT conditions: `ell > 255`, `len_in_bytes > 65535`, `len(DST) > 255`,
  and an empty DST (RFC 9380 §3.1), plus the accepted boundaries `ell = 255` and `len(DST) = 255`.
- RFC 9380 Appendix J.9.1: all five vectors (`""`, `"abc"`, `"abcdef0123456789"`,
  `"q128_" + "q"*128`, `"a512_" + "a"*512`). For each: `u[0]`, `u[1]`, `Q0`, `Q1` (after the
  isogeny), `P`, `P` on the curve and in the subgroup, and a compress/strict-decode round trip.
- Generator `g1`: on the curve, `[q]·g1 = O`, compressed form equal to the CIP-0381 bytes,
  decode back to the CIP-0381 `(X, Y)`, and `-g1` differs only in the sort flag.
- ADR-0060 D3 decoder: the identity `0xC0‖0^47` (positive); infinity with the sort flag
  (`0xE0‖0^47`), infinity with a nonzero coordinate bit (last octet, and octet 0) → step 4;
  `0x80‖0^47` and `0xA0‖0^47` (`x = 0`, order-3 points) → `NOT_IN_SUBGROUP`; 0-, 47- and
  49-octet inputs → step 2; compression flag clear (`g1` with the top bit cleared, `0x40‖0^47`,
  `0^48`) → step 3; `x = P_381`, `x = P_381 + 1` and `x = 2^381 − 1` → step 5; the smallest
  `x` with `x³ + 4` a non-square (`x = 1`) → step 6; `None` raises. Two cases were added by the
  ADR author after the review of the spec's decoder table, using only this module's own decoder
  and arithmetic: `x = 4` (a curve point outside the subgroup) and the mixed-order point
  `G + (0, 2)`, both → `NOT_IN_SUBGROUP`.
- Check 1 on scalars: `m = q`, `r = q`, `m = −1`, `r = −1` and a `bool` are rejected, never reduced.
- Mutation sanity (outputs must change, not exact values): DST `-v1-` → `-v2-` changes `G`, `H`
  and `s`; swapping the messages swaps `G` and `H`; payload change changes `s`; dropping the
  length suffix changes `s`; plus a homomorphism check and `commit_bytes(B, r) = commit(s(B), r)`.

## What the default run outputs

A JSON object with:

- `pythonVersion`, `DST_B`, `DST_S`;
- `G` and `H`: `compressedHex` (48-octet Zcash compressed) and the affine `xHex`, `yHex`
  (48-octet big-endian, lowercase);
- `checks`: the basis and consistency checks run for the report (identity, on-curve, `[q]·P = O`,
  `G ≠ ±H`, round trips, the summary of the full self-test, which runs first and must pass);
- `bytesMap`: the D4 mapping for the empty payload, the pattern payloads of lengths 1, 55, 56,
  64, 129 and 1024 (octet `i` = `(131·i + 17) mod 256`), and ASCII `"abc"`. Each entry has
  `label`, `length`, `payloadSha256Hex`, the full 32-octet `b0Hex`, `b1Hex`, `b2Hex` of
  `expand_message_xmd(B ‖ I2OSP(len(B), 8), DST_S, 48)`, the 48-octet `uniformHex`
  (`b1 ‖ b2[0:16]`), and `scalar` = `OS2IP(uniform) mod q` as a decimal string;
- `commitments`: `commit(0,0)` (the identity `0xC0‖0^47`), `commit(1,0)` (`= G`),
  `commit(0,1)` (`= H`), `commit(q−1, q−1)` (`= −(G + H)`) and `commit(12345, 67890)`, each with
  decimal `m`, `r` and `compressedHex`.

## Limits

Passing these checks is evidence of agreement with RFC 9380's published vectors and of internal
consistency. It is not a security proof and does not make the profiles production-safe; ADR-0060
admission still needs its other reproductions and review gates.

## Vector emitter (ADR-0060 M3)

`emit_g1_commitment_vectors_v1.py` writes the two cross-language vector files of
[`commitment-profiles-v1.md`](../../../../../docs/specs/commitment-profiles-v1.md) §13
(`zeroj-commitment-vectors-v1`) for the G1 profiles:

```
zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/
    pedersen-bls12-381-g1-v1.json          # scalar
    pedersen-bls12-381-g1-bytes-v1.json    # bytes
```

The files are evidence against the Java implementation, so their expected values must not come
from it.

### Running

Python 3 standard library only, from this directory:

```bash
python3 -I -B emit_g1_commitment_vectors_v1.py                  # write both files
python3 -I -B emit_g1_commitment_vectors_v1.py --out-dir DIR    # write them to DIR instead
python3 -I -B emit_g1_commitment_vectors_v1.py --check          # compare with the files on disk
python3 -I -B emit_g1_commitment_vectors_v1.py --self-test      # re-verify + mutations; no writes
```

`--repo-root DIR` overrides the repository root (default: five directories above this file).
`--check` and `--self-test` read the files from `--out-dir` (default: the repository location). A
write or `--check` takes about a second, `--self-test` about 20 seconds. Output is deterministic:
fixed constants only, no randomness, stable case order, generated twice in-process and required
identical.

Every run, in every mode, first:

1. decodes the pinned `G` and `H` (spec §2.2) with this script's own decoder and compares the
   affine coordinates; recomputes both with the reference's RFC 9380 `hash_to_curve` under `DST_B`
   and requires equality; checks `G ≠ O`, `H ≠ O`, `G ≠ ±H`, `[q]G = [q]H = O`;
2. checks the spec's test tables, transcribed by hand into the script: every §10.2 row
   (`uniform_bytes`, `s`), every §10.3 commitment, `C(q − 1, q − 1) = −(G + H)`, and every §10.4
   decoder outcome;
3. runs every case through this script's own implementation and requires the outcome the case
   was written to pin (each case carries an intended `ok` or error class);
4. checks the §13 format: no JSON numbers, lowercase hex in `…Hex` fields, decimal integers, only
   the operations and input fields §13.3 defines for the profile's kind, the G1 `decodePoint`
   forms (`xHex`/`yHex` of 48 octets, or `{"identity": "true"}`), `relation` cardinality,
   `expectedProfileId` equal to the file's profile, and the §13.3 "Streams" rule.

The header records provenance as the Jubjub files do: each specification's path, revision (where
the document has one; pinned in the script as the revision the vectors implement: `r6` and `r1`),
date and SHA-256, and the generator's path, SHA-256 and Python version.

**`--check`** regenerates in memory and compares **byte for byte** with the files on disk. Any
difference exits 1, including a provenance-only one (a different Python version, or a later
revision of a specification, which changes its SHA-256); each difference is named, with the case
name, and provenance fields are marked as such. This is stricter than the Jubjub emitter, which
treats provenance differences as warnings. A six-copy regression (one hex digit, trailing newline,
Python version, a removed case, an extra `null` key, and the untouched text) checks the comparator
first.

**`--self-test`** writes nothing and fails on any problem:

- *Independent re-verification.* Every case of the regenerated files, and of the files on disk
  when present, is re-run from its JSON with the reference's primitives instead of this script's:
  the reference's strict decoder (`strict_decode`), its affine double-and-add arithmetic and
  `commit`, its generic `expand_message_xmd` trace for `hashToScalar` (this script uses the
  octet-by-octet form of spec §5), `commit_bytes` (checked equal to `C(s, r)`), and for
  `publicDelta` the residue path `C + [δ mod q]·G` (this script uses `[|δ|]·G`, negated for
  `δ < 0`). Every positive's `expected` must equal the recomputation and every negative's class
  must be the class the recomputation reaches. In addition: the §10.3 identities (`C(0,0) = O`,
  `C(1,0) = G`, `C(0,1) = H`, `C(q−1,q−1) = −(G+H)`, `C(q−1,0) = −G`, `C(0,q−1) = −H`) by the
  reference; each `relation` and `publicDelta` positive whose input points were built from known
  openings must equal the reference's `C` of the combined opening (homomorphism path); the
  `hashToScalar` and `commit` cases of the §10.2 and §10.3 inputs must equal the spec tables; and
  a list of required case names covers §13.4 and the ADR-0060 test list.
- *Mutations.* 30 deliberate defects in this script's implementation are switched on one at a
  time (case inputs fixed; only outcomes may change). Each must change at least one emitted case.
  They cover check 1 (accept `q`, reduce), every decoder step (skip subgroup, cofactor-clear,
  lenient infinity, reduce `x`, ignore the sort flag, no compression check), the encoder's sort
  flag, the envelope (no identifier compare, any version, length before identifier),
  `amountBits`/`deltaBits` (255 accepted, validated before the point), check 2 (inclusive, before
  check 1), the delta rule (bound before width, inclusive bound, no negation), swapped `G`/`H`, the
  byte mapping (length prefix, no length, modulo Jubjub `l`, no zero prefix), little-endian
  openings, reversed `subtract`, the bytes equation before check 1, and the opening decoder
  checking `r` before the length. All 30 are killed.

### Independence

Files read while writing the emitter, and nothing else:

- `docs/specs/pedersen-bls12-381-g1-v1.md` and `docs/specs/commitment-profiles-v1.md` (in full);
  `docs/specs/pedersen-jubjub-bytes-v1.md` §3 and §6; `docs/adr/0060-pedersen-bls12-381-g1-profiles.md`
  (Status, D3–D5, Verification and test strategy, milestones, design questions);
- `bls12_381_g1_reference.py` and this README (the reference is imported by path and unmodified;
  SHA-256 when the files were generated:
  `67d27395cbbdb6cc1209a4174a87e9f9692998b45083096889ae47841706e35a`);
- the Jubjub emitter `zeroj-circuit-lib/src/test/resources/commitment-vectors-reference/` (script
  and README) and the Jubjub JSON files, only to match the file format, field names and
  conventions.

No `.java` file, Java test resource or build output was opened, and Gradle and Java were not run.

The primary implementation in the emitter (Jacobian-coordinate arithmetic, the §4 decoder, the
octet-form §5 mapping, checks, openings, envelope, §13.3 order) is separate code from the
reference; the reference supplies the hash-to-curve derivation of `G` and `H` and the
re-verification path. An error shared by the specification text and both Python implementations
would not be caught here.

### Cases

| File | Positive | Negative |
|---|---|---|
| `pedersen-bls12-381-g1-v1.json` | 88 | 172 |
| `pedersen-bls12-381-g1-bytes-v1.json` | 58 | 124 |

Both files: every §13.4 G1 point negative under `decodePoint` and `decodeEnvelope` (lengths 0, 32,
47, 49, 96; compression flag clear; infinity with the sort flag, with a nonzero bit in the last
octet or in octet 0, and on `G`'s coordinate; `x = P_381`, with the sort flag, `P_381 + 1`,
`2^381 − 1`; `x = 1` non-square with and without the sort flag; the order-3 points `0x80‖0^47` and
`0xA0‖0^47`; `x = 4` with both `y`; `G + (0, 2)` and `H + (0, P_381 − 2)`), the identity as a
positive, envelope negatives (empty, version only, versions `0x00`/`0x02`/`0xff`, truncations, a
trailing octet, point lengths 0/32/47/49/96, identifier length too large/±1/zero, the other G1
profile, the basis-set identifier, the three Jubjub identifiers with a Jubjub point and one with a
G1 point, a one-octet change, an upper-case first octet) and envelope order cases.

Scalar: `commit` and `verifyOpening` at `0`, `1`, `q − 1` (all §10.3 rows), `2^254 − 1`, `2^254`;
check 1 at `q`, `q + 1`, `−1` for `m` and `r` on `commit`, `verifyOpening` and `encodeOpening`,
`q`/`q + 1`/all-ones on `decodeOpening`, unreduced `m + q`/`r + q`/`1 − q`; `amountBits`
`1, 64, 252, 253, 254` with `2^k − 1` (positive) and `2^k` (`OUT_OF_RANGE`), and `0, 255, 256, −1`,
`2^31 − 1`, `−2^31` (`INVALID_CONFIGURATION`); `OPENING_MISMATCH` for a wrong value, blinding, swap,
negated point and swapped bases; openings of the wrong length (0, 32, 63, 65, 96 and 128
octets); `relation` with
wrap-around, subtract to a negative residue, doubling (`P + P`), `P + (−P) = O`, identity operands,
and its negatives; `publicDelta` with `deltaBits` `1, 64, 252, 253, 254` at `±(2^k − 1)` (positive)
and `±2^k` (`OUT_OF_RANGE`), `δ = 0`, wrap-around both ways, identity input, a result equal to the
identity, `±q` and `±2^300`, `deltaBits` `0, 255, −1, 2^31 − 1, −2^31`, and order cases; a bytes
commitment verified as the scalar opening of its `s`; multi-defect order cases.

Bytes: `hashToScalar` for the empty payload, `0x00`, ASCII `abc` and pattern payloads of 1, 55, 56,
63, 64, 65, 119, 120, 128, 129, 1024 and 65536 octets (all §10.2 rows included; `b0`'s input is
`n + 128` octets, so 55/56 and 119/120 cross SHA-256 padding block boundaries); `commit` in array,
`declaredLength` and `maxBytes` forms (including `maxBytes = MAX_PAYLOAD_BYTES`); declared length
and maximum at `−1`, `MAX_PAYLOAD_BYTES + 1`, `−2^63`, `2^63 − 1` (`LENGTH_OUT_OF_RANGE`);
`verifyOpening` negatives for a changed, extended or truncated payload, a wrong blinding, an
off-by-one pattern length, and the ADR-0060 seeded faults as points (length suffix dropped, length
as prefix, reduction modulo Jubjub `l`, zero prefix dropped, `G`/`H` swapped); blinding encodings
of the wrong length (0, 31, 33, 48 and 64 octets); multi-defect order cases.

### Limits of the format

These are not file cases (see the M3 report): the §8 bytes order "blinding check 1 before the
declared length" (a fixture with both defects would break §13.3 "Streams"); `LENGTH_OUT_OF_RANGE`
on `verifyBytes`/`verifyBytesToEnd` (the §13.3 bytes `verifyOpening` row has no `declaredLength` or
`maxBytes`); stream I/O failures, nulls, the provider capability probe and the scalar snapshot
(Java tests); envelope step 6. `expectedProfileId` is always the file's own profile.
