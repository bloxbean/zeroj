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
  `x` with `x³ + 4` a non-square (`x = 1`) → step 6; `None` raises.
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
