# ZeroJ Pedersen BLS12-381 G1 v1 — Normative Specification

**Identifiers:** basis set `pedersen-bls12-381-g1-basis-v1`; commitment profiles
`pedersen-bls12-381-g1-v1` (scalar) and `pedersen-bls12-381-g1-bytes-v1` (bytes).
**Status:** Normative (ADR-0060 milestone M0). The registry lists all three entries as `reserved`
until ADR-0060 M5 admits them ([`commitment-profiles-v1`](commitment-profiles-v1.md) §2.3).
Experimental: not approved for value-bearing or mainnet use. "Normative" fixes the constants,
bytes, checks, check order and error behaviour; it is not a maturity or security claim. This
document governs if it and an implementation disagree.
**Date:** 2026-10-22 (r1)

This document defines two Pedersen commitment profiles over the prime-order subgroup of the
BLS12-381 curve `E: y² = x³ + 4` over `GF(P_381)`: a commitment to a scalar and a commitment to an
octet string. Both use one basis set derived with RFC 9380 hash-to-curve, so a Cardano validator
can reproduce the bases with `bls12_381_G1_hashToGroup` and open commitments with the CIP-0381
builtins. The rationale is in [ADR-0060](../adr/0060-pedersen-bls12-381-g1-profiles.md); the shared
contract (expected-profile rule, check names, envelope, error classes, vector format) is
[`commitment-profiles-v1`](commitment-profiles-v1.md), whose rules apply unless this document
narrows them. Changing any constant, tag, procedure or encoding here produces a different basis
set or profile and requires a new identifier.

The key words MUST, MUST NOT and MAY are normative.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `P_381` | the BLS12-381 base-field modulus, `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab` (381 bits) |
| `E` | `y² = x³ + 4` over `GF(P_381)` |
| `q` | the order of the prime-order subgroup `𝔾₁` of `E(GF(P_381))`, `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` (255 bits, `⌊log₂ q⌋ = 254`). It equals the BLS12-381 scalar-field order, which `commitment-profiles-v1` §1 calls `p`; this document always writes `q` |
| `h` | the cofactor `#E(GF(P_381)) / q = 0x396c8c005555e1568c00aaab0000aaab` |
| `O` | the identity (point at infinity) |
| `B`, `n` | a payload (a finite octet string) and its length in octets |
| `I2OSP`, `OS2IP` | RFC 9380 §4: unsigned big-endian conversion |
| `a ‖ b` | octet concatenation |

`q` is used only as the group order and the scalar modulus. `P_381` is used only for coordinates.
Neither is ever the Jubjub order `l`.

---

## 2. Basis set `pedersen-bls12-381-g1-basis-v1`

### 2.1 Derivation

```text
DST_B = "ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"   (ASCII, 68 octets)
G     = hash_to_curve("G", DST_B)
H     = hash_to_curve("H", DST_B)
```

- `hash_to_curve` is RFC 9380 §3 with the suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` (§8.8.1:
  `expand_message_xmd` with SHA-256, `L = 64`, `k = 128`, simplified SWU on the 11-isogenous curve
  with `Z = 11`, the 11-isogeny map of Appendix E.2, and `clear_cofactor` by `h_eff`).
  CIP-0381's `bls12_381_G1_hashToGroup` implements the same suite.
- `"G"` and `"H"` are the single octets `0x47` and `0x48`.
- `DST_B` (hex):
  `5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62617369732d76312d424c53313233383147315f584d443a5348412d3235365f535357555f524f5f`.
  It has nonzero length and is shorter than 255 octets (RFC 9380 §3.1, §5.3.1; CIP-0381).

### 2.2 Pinned values

| Base | 48-octet compressed encoding (§4) |
|---|---|
| `G` | `80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e` |
| `H` | `92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65` |

Affine coordinates (48-octet big-endian):

| Base | `x` | `y` |
|---|---|---|
| `G` | `00453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e` | `0ab307006d17731edfeef508a959c6c43f6ad8f72d27af8aa0645356ffe864fd0ced6dfa806e5b2b63c8850f7cfb691c` |
| `H` | `12e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65` | `01e0f1bf4e0e4e344cb2779b2dc6adec8b0b07caf8a9812c3b6f4b056af2d0fda0e7b05ffb16008ca855ffe55686184e` |

### 2.3 Rules

1. A deriver MUST check that `G ≠ O`, `H ≠ O`, `G ≠ H` and `G ≠ −H`, and that both are in `𝔾₁`.
   If any check fails, this basis set is invalid and a new version with new messages is required;
   no implementation continues silently. (All checks pass for the values above.)
2. Implementations use the pinned encodings and do not hash at run time. A test recomputes them.
3. Both bases are random-oracle outputs, so no one, including the deriver, knows `log_H(G)`.
   Binding rests on the discrete-logarithm problem in `𝔾₁` between `G` and `H`.
4. Independent reproductions (ADR-0060 D2): the Java `Bls12381Hash.hashToG1`; a stand-alone
   Python implementation written from RFC 9380 without reading the Java
   (`zeroj-bls12381/src/test/resources/pedersen-g1-reference/`), which also passes all five RFC
   9380 Appendix J.9.1 vectors; and on-chain `bls12_381_G1_hashToGroup` (ADR-0060 M4).
5. A different tag, message or suite is a different basis set and therefore new profile versions.

---

## 3. Profiles

Both profiles use the basis set of §2. Domain separation between them comes from the message map:
a bytes commitment to `B` with blinding `r` is the same point as a scalar commitment to
`s = HashBytesToScalarG1(B)` with the same `r`, so a point never identifies its profile
(`commitment-profiles-v1` §6.3). Kind and profile come only from the verifier's configuration.

### 3.1 `pedersen-bls12-381-g1-v1`

| Field | Value |
|---|---|
| Kind | `scalar` |
| Group | `𝔾₁`, order `q`, cofactor `h`; identity accepted (§4) |
| Basis set | `pedersen-bls12-381-g1-basis-v1` |
| Message map | `C(m, r) = [m]·G + [r]·H` |
| Scalar domain | check 1 on `m` and `r` (`m, r ∈ [0, q)`, never reduced) on every operation; check 2 (`m < 2^k`, `1 ≤ k ≤ 254`) only when requested; homomorphic results are residues mod `q` |
| Point encoding | 48 octets, §4 |
| Circuit public-input encoding | none |
| Opening encoding | §6.1 |

### 3.2 `pedersen-bls12-381-g1-bytes-v1`

| Field | Value |
|---|---|
| Kind | `bytes` |
| Group | as §3.1 |
| Basis set | `pedersen-bls12-381-g1-basis-v1` (shared with §3.1) |
| Message map | `s = HashBytesToScalarG1(B)` (§5), then `C = [s]·G + [r]·H` |
| Scalar domain | check 1 on `r`; `s` is recomputed from `B` by the verifier, is in `[0, q)` by construction and is never range-checked or accepted as part of an opening |
| Point encoding | as §3.1 |
| Circuit public-input encoding | none |
| Opening encoding | §6.2 |

**No scalar-only mode.** This profile offers no operation that accepts a supplied `s` instead of
`B`. A check of `(s, r)` against a bytes commitment is a `pedersen-bls12-381-g1-v1` opening of
`s`: check 1 applies to `s`, and the check authenticates only that scalar, not any payload
(`commitment-profiles-v1` §4.4).

### 3.3 Envelope lengths

Under `commitment-profiles-v1` §9: `pedersen-bls12-381-g1-v1` envelopes are `1 + 1 + 24 + 48 = 74`
octets and `pedersen-bls12-381-g1-bytes-v1` envelopes `1 + 1 + 30 + 48 = 80` octets.

---

## 4. Point encoding and strict decoding

The encoding is the 48-octet Zcash compressed form CIP-0381 uses. The three most significant
bits of octet 0 are flags: compression `0x80`, infinity `0x40`, sort `0x20`. A finite point
`(x, y)` encodes as `I2OSP(x, 48)` with `0x80` set, and `0x20` set iff `y` is lexicographically
largest (`y > (P_381 − 1) / 2`). The identity encodes as exactly `0xC0 ‖ 0^47`. The 96-octet
uncompressed form is not accepted.

The strict decoder applies, in this order, and stops at the first failure:

| Step | Rule | Outcome |
|---|---|---|
| 1 | input absent (null) | `NullPointerException` |
| 2 | length ≠ 48 | `MALFORMED_ENCODING` |
| 3 | compression flag `0x80` clear | `MALFORMED_ENCODING` |
| 4 | infinity flag `0x40` set | the encoding MUST be exactly `0xC0 ‖ 0^47`: if so, **return `O` and stop**; any other encoding with the infinity flag (sort flag set, or any nonzero bit below the flags) is `MALFORMED_ENCODING` |
| 5 | finite encodings only: `x` (the 381 bits below the flags) `≥ P_381` | `MALFORMED_ENCODING` |
| 6 | finite encodings only: `x³ + 4` is not a square in `GF(P_381)` | `MALFORMED_ENCODING` |
| 7 | finite encodings only: the point `(x, y)`, `y` chosen by the sort flag, is not in `𝔾₁` (`[q]·P ≠ O`) | `NOT_IN_SUBGROUP` |

- Steps 5–7 never run on an infinity encoding. The finite encoding `0x80 ‖ 0^47` has `x = 0` and
  decodes to `(0, 2)`, a point of order 3, so it is rejected at step 7.
- The decoder never clears the cofactor and never reduces a coordinate.
- **Identity policy.** `O` is accepted, as in every Jubjub profile: it is `C(0, 0)` and the sum of
  commitments whose messages and blindings cancel. A verifier that refuses it does so as
  application policy. Hiding is the committer's job.
- For every accepted input `b`, re-encoding the decoded point gives exactly `b`, so the encoding is
  canonical.

---

## 5. Byte mapping `HashBytesToScalarG1`

```text
DST_S = "ZeroJ-pedersen-bls12-381-g1-bytes-v1-H2S-XMD:SHA-256"      (ASCII, 52 octets)
msg   = B ‖ I2OSP(n, 8)
s     = OS2IP(expand_message_xmd(msg, DST_S, 48)) mod q
```

- `DST_S` (hex):
  `5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62797465732d76312d4832532d584d443a5348412d323536`.
- `expand_message_xmd` is RFC 9380 §5.3.1 with SHA-256 (`b_in_bytes = 32`, `s_in_bytes = 64`),
  `len_in_bytes = 48`, `ell = 2`, `DST_prime = DST_S ‖ 0x34`. This is RFC 9380 `hash_to_field`
  (§5.2) with `count = 1`, `m = 1`, target field `GF(q)` and `L = ceil((255 + 128) / 8) = 48`,
  applied to the framed `msg`, not to `B`.
- Octet by octet:

  ```text
  b0 = SHA-256( 0x00 × 64 ‖ B ‖ I2OSP(n, 8) ‖ 0x00 0x30 ‖ 0x00 ‖ DST_S ‖ 0x34 )
  b1 = SHA-256( b0 ‖ 0x01 ‖ DST_S ‖ 0x34 )
  b2 = SHA-256( (b0 XOR b1) ‖ 0x02 ‖ DST_S ‖ 0x34 )
  uniform_bytes = b1 ‖ b2[0..16)                      # 48 octets
  s = OS2IP(uniform_bytes) mod q
  ```

- It is `pedersen-jubjub-bytes-v1` §3 with the modulus `q` in place of `l` and its own tag. The
  rules of that section apply unchanged: the 8-octet big-endian length is a suffix; `n` is the
  number of octets actually hashed; reduction happens once, modulo `q`, with no rejection
  sampling or clamping; `s = 0` is valid and never retried; the 64-octet zero prefix is part of
  `b0`'s input.
- `MAX_PAYLOAD_BYTES = 2^61 − 256 = 2305843009213693696`. The bound keeps `b0`'s input
  (`n + 128` octets) below SHA-256's message bound.
- The reduction is within statistical distance `q / 2^384 < 2^-129` of uniform on `[0, q)`.

### 5.1 Payload sources and stream rules

The three payload sources of `pedersen-jubjub-bytes-v1` §6.1 apply unchanged and produce the
same `s` for the same octets: in-memory octets; a declared-length stream (exactly `length`
octets, then one probe); a bounded read-to-end stream (at most `maxBytes` octets, then one probe
if `maxBytes` were read). All reading rules of that section are normative here, including:

- An array longer than `MAX_PAYLOAD_BYTES`, and a declared length or maximum outside
  `[0, MAX_PAYLOAD_BYTES]`, are rejected with `LENGTH_OUT_OF_RANGE` before any read, digest
  acquisition or curve work.
- Stream content is bounded by counting: at most `length + 1` or `maxBytes + 1` octets are read.
  Excess content found by the probe, a stream that ends before a declared length, or a read that
  reports a count outside `[−1, requested]` fails with `IOException`. The probe octet is never
  hashed.
- A bulk read returning zero octets is not end of stream; the implementation falls back to a
  single-octet read.
- `I2OSP(n, 8)` is appended only after end of stream has been observed and every check has
  passed; no result and no curve work is produced before then.
- The implementation never closes, resets, marks, skips, seeks or reopens the stream, never
  queries `available()` and never retries.

---

## 6. Scalars, openings and public relations

### 6.1 Scalar opening

```text
opening = I2OSP(m, 32) ‖ I2OSP(r, 32)          # 64 octets
```

Decoding order: length other than 64 → `MALFORMED_ENCODING`; `m ≥ q` → `NON_CANONICAL_SCALAR`;
`r ≥ q` → `NON_CANONICAL_SCALAR`.

### 6.2 Bytes blinding

```text
blinding = I2OSP(r, 32)                         # 32 octets
```

The payload travels separately as its exact octets. Decoding order: length other than 32 →
`MALFORMED_ENCODING`; `r ≥ q` → `NON_CANONICAL_SCALAR`.

### 6.3 Checks

- **Check 1** (`commitment-profiles-v1` §7) applies to `m` and `r` on every strict path: an
  integer outside `[0, q)` is `NON_CANONICAL_SCALAR`, never reduced. `q − 1` is accepted; `q`,
  `q + 1` and `−1` are rejected.
- **Check 2** is optional on `m`: `m < 2^k` for a configured `1 ≤ k ≤ 254`. A `k` outside that range
  is `INVALID_CONFIGURATION`; a violation is `OUT_OF_RANGE`. It never applies to `r` or `s`, and
  opening decoders never apply it.

### 6.4 Public relations (V3)

- **Public delta.** `C_new = C_old + [δ]·G` for a signed integer `δ` with an application bound
  `|δ| < 2^{k_δ}`, `1 ≤ k_δ ≤ 254`. A `k_δ` outside that range is `INVALID_CONFIGURATION`; a
  `|δ| ≥ 2^{k_δ}` is `OUT_OF_RANGE`. The implementation computes `[|δ|]·G` with the canonical
  scalar `|δ|` and negates the point when `δ < 0`. It never passes a negative or out-of-range
  integer to a scalar multiplication, off-chain or on-chain.
- **Sums.** `add`, `subtract` and `negate` combine commitments of this profile only. Coefficients
  of a sum are small non-negative integers fixed by the verifier, never supplied by the prover.
- Results are residues mod `q`. An integer reading (balances, conservation) needs the
  application's own bounds (ADR-0051 D3a); a relation proves residues, not balances.
- The bytes profile has no arithmetic.

---

## 7. Generation and secrets

**Secret until the committer discloses it:** `m`, `B`, `r`, `s`, the digest state, `b0`, `b1`,
`b2`, `uniform_bytes`, and every buffer holding payload octets.

- Generation computes `[x]·G` and `[r]·H` (with `x = m` or `x = s`) through the provider's
  secret-scalar multiplication only, never through a public multiplication, a multi-scalar
  multiplication or a table indexed by secret bits. The byte mapping and its reduction run inside
  the same boundary.
- **No constant-time claim.** Neither the pure-Java provider (a uniform operation schedule with
  data-dependent branches and `BigInteger` arithmetic; ADR-0021) nor the blst provider (whose
  secret-scalar method is its public method, with no documented side-channel contract) is
  constant-time. Generation is therefore **offline/isolated only** for every provider
  (`commitment-profiles-v1` §6.2, V2).
- **Blinding sampler:** 64 octets from the caller's cryptographically secure generator, read
  unsigned big-endian, reduced mod `q`; statistical distance below `2^-257` from uniform. The
  buffer is wiped on every exit. Entropy failure propagates; there is no fallback. `r` is never
  derived from the message and never reused across independent commitments.
- Owned buffers and digest outputs are wiped on every exit; the operation-owned digest is reset
  and never reused; nothing is cached, pooled or kept in thread-local storage. No secret appears in
  a log or exception message. `BigInteger` values cannot be wiped; this is best effort.
- **Disclosed verification (V1)** recomputes the commitment with public, variable-time
  arithmetic. It is appropriate only where the opening is already public or no party from whom it
  is still secret can observe the verifier's timing (`commitment-profiles-v1` §6.2).

---

## 8. Java binding (`zeroj-bls12381`, package `org.zeroj.bls12381.pedersen`)

All types are final, not records, not `Serializable`, with no public or protected constructor.
Commitments are created only by their decoders, by generation and by same-type arithmetic, and
hold only the validated point and its encoding. Opening holders have a redacted `toString` and do
not override `equals`/`hashCode`. Error classes are those of `commitment-profiles-v1` §11, carried
by `CommitmentFormatException`.

| Type or member | Contract |
|---|---|
| `G1PedersenCommitment` | `pedersen-bls12-381-g1-v1`. `PROFILE` (`== CommitmentProfiles.PEDERSEN_BLS12_381_G1_V1`), `CODEC` (empty key context); `static decode(byte[])` (§4); `profile()`; `toPointBytes()`; `add`, `subtract`, `negate` on this type only; `withPublicDelta(BigInteger delta, int deltaBits)` (§6.4); value equality over the encoding |
| `G1PedersenBytesCommitment` | `pedersen-bls12-381-g1-bytes-v1`. `PROFILE` (`== CommitmentProfiles.PEDERSEN_BLS12_381_G1_BYTES_V1`), `CODEC`; `static decode(byte[])`; `profile()`; `toPointBytes()`; value equality over the encoding; no arithmetic |
| `G1PedersenOpening` | `static of(BigInteger value, BigInteger blinding)`; `static decode(byte[])` (§6.1); `encode()`; `value()`; `blinding()` |
| `G1PedersenBlinding` | `static byte[] encode(BigInteger r)`; `static BigInteger decode(byte[])` (§6.2) |
| `G1Pedersen` | `static pureJava()`, `static withProvider(Bls12381Provider)`, `provider()`; `commitScalar(BigInteger value, BigInteger blinding)`; `verifyScalar(G1PedersenCommitment, BigInteger value, BigInteger blinding)` and the 4-argument form with `int amountBits`; `static randomBlinding(SecureRandom)`; `commitBytes(byte[], BigInteger)`, `commitBytes(InputStream, long length, BigInteger)`, `commitBytesToEnd(InputStream, long maxBytes, BigInteger)` and the matching `verifyBytes`/`verifyBytesToEnd` |
| `Bls12381Codecs.scalarFromBigEndian32(byte[])`, `scalarToBigEndian32(BigInteger)` | canonical 32-octet big-endian scalar codec: wrong length or a value outside `[0, q)` is an `IllegalArgumentException`, never reduced |

**Strict paths and check order.** Argument checks precede any curve operation on the inputs,
digest acquisition or stream read, and no input is reduced:

| Path | Order |
|---|---|
| `commitScalar` | nulls → `value` check 1 → `blinding` check 1 → generate |
| `verifyScalar` (3 args) | nulls → `value` check 1 → `blinding` check 1 → equation (`false` on mismatch) |
| `verifyScalar` (4 args) | nulls → `amountBits ∈ [1, 254]` (`INVALID_CONFIGURATION`) → `value` check 1 → `blinding` check 1 → check 2 (`OUT_OF_RANGE`) → equation |
| `withPublicDelta` | nulls → `deltaBits ∈ [1, 254]` (`INVALID_CONFIGURATION`) → `|δ| < 2^{deltaBits}` (`OUT_OF_RANGE`) → arithmetic |
| `G1PedersenOpening.of` / `decode` | nulls / §6.1 → `value` check 1 → `blinding` check 1 |
| `G1PedersenBlinding.encode` / `decode` | nulls → `r` check 1 / §6.2 |
| `commitBytes*`, `verifyBytes*` | nulls → `blinding` check 1 → declared length or maximum (`LENGTH_OUT_OF_RANGE`) → read and hash (§5.1) → curve work |
| point decoders (`decode`, `CODEC.decodePoint`) | §4 |
| `withProvider` | null → `NullPointerException` |

**Providers.** `G1Pedersen` takes an explicit `Bls12381Provider`; `pureJava()` uses the pure-Java
provider. Decoding is shared code and identical for every provider. Generation and verification
give byte-identical commitments and identical verdicts for every provider that implements the
secret-scalar method; a provider without one fails generation with the provider's
`UnsupportedOperationException` before any secret is used.

---

## 9. On-chain verification (Cardano, CIP-0381)

A validator that opens or combines these commitments:

1. checks that a received commitment is exactly 48 octets **before** `bls12_381_G1_uncompress`;
2. relies on CIP-0381's normative element contract ("can only be generated with byte arrays that
   represent a point which is part of the prime order subgroup") for curve and subgroup validity,
   and on `uncompress` failing the script otherwise;
3. checks `bls12_381_G1_compress(point) == bytes` after `uncompress` and before the point is used
   (canonicality; CIP-0381 does not specify which encodings `uncompress` accepts). The identity
   `0xC0 ‖ 0^47` is accepted;
4. applies check 1 to `m` and `r`, check 2 when requested, and the delta rule, **before** any
   `scalarMul` or `multiScalarMul` sees the value;
5. for a bytes opening, recomputes `s` from the payload with §5 using `sha2_256`;
6. compares with `bls12_381_G1_equal`.

The bases are pinned compressed constants (§2.2), decompressed in the script. A multi-scalar
multiplication, if used, always has two non-empty lists of equal length. Builtin behaviour on
inputs the CIPs leave unspecified (negative or `≥ q` scalars, non-canonical encodings, list
lengths) is recorded as evidence and never relied on. Every check maps to script failure.

A validator still provides none of: authorization, replay protection, UTxO and context binding,
non-negative balances. Every opened value is public forever.

---

## 10. Test values

All values below were computed by the Java implementation and by the independent Python
reference (§2.3 rule 4), and agree byte for byte.

### 10.1 Bases

`G` and `H` as §2.2. `G ≠ O`, `H ≠ O`, `G ≠ ±H`, both in `𝔾₁`.

### 10.2 `HashBytesToScalarG1`

Pattern payloads: octet `i` is `(131·i + 17) mod 256` (`commitment-profiles-v1` §13.2).

| Payload | `n` | `uniform_bytes` | `s` (decimal) |
|---|---|---|---|
| empty | 0 | `62afac35dff21f5a55ff2569ca3c589ef5401cfc94aafe1110981e7c11b89a13d931cede053d24094deda3524a53b80e` | `36315447437668222813564192209050807153821375512821708312164585800119004767398` |
| pattern | 1 | `8bf9523b8cfad53f2a64e7c124b637a4a7dc7665d60ccf16e2f3e260b04ddbf366a510869c7e787d331c35a9222f28cc` | `17446826573447758279414620354847772216162392386874241427805739007456445167270` |
| pattern | 55 | `e219c89968b49b2d930e377d427b7e56c65473ea36c92f6ce02e5efc83974e69fbba34909f18fe9c76d6147d1a65c7cc` | `4769885727161205208895793752532058125538937305946508790125793345496789763442` |
| pattern | 56 | `91f731ee2e033609f3f27e1fcfac8202c8d415cc5ac5597eee949f5a96dfb4965d739d0a583b4273d5dae005a9cc45e0` | `44447803342360626358699221713325796379764762051949152351159963802212607565535` |
| pattern | 64 | `d4acbd20d83ed5a47394b62c6e2301b5cdca43e1dabcbe10a0999adb71f7becdcc3fc44e845702440a04e54975607dfd` | `21158407019535989839516034496492483749423603674815396635618901986493989358291` |
| pattern | 129 | `90293fbe6622a3d8ed03f6f733dd36eba35919771d85be7e2dc88aac08c8c365a6eeaaee7a536bc38b40d5eac62c06df` | `10636700515201835153547363743684853122590858874478588016559740395075199699391` |
| pattern | 1024 | `d968d99d55ccb4300830c9ca5bf4a5e7e352e71f2b43a1e7357487eab5259b1b7a1540a8bb690e50009d8b4b2fa12797` | `51032631804351372587695208740820262018544153677477339797817422801122177762967` |
| ASCII `abc` | 3 | `0648a88bce794163caa6686ba5d3bbf550c02d8e842a550642ef33832468ead60428b888e585dfe40c33f79db5f2b3e7` | `425016933681726855004915202875618514367841089254790273686098534787449164925` |

The reference output and the M3 vector files also record `b0`, `b1` and `b2` for these payloads.

### 10.3 Commitments

| `m` | `r` | `C(m, r)`, compressed |
|---|---|---|
| 0 | 0 | `c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` |
| 1 | 0 | `80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e` |
| 0 | 1 | `92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65` |
| q − 1 | q − 1 | `830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68cb2688ad276369b8650` |
| 12345 | 67890 | `8c5b1e42a3912ecf2a2fc27a26ef67afd30799614ebfbd5dc7a2cb00e43b063a60a4d516007352cddecd632d2b758fc4` |

`C(0, 0) = O`, `C(1, 0) = G`, `C(0, 1) = H` and `C(q − 1, q − 1) = −(G + H)`.

### 10.4 Decoder cases

| Input | Outcome |
|---|---|
| `c0` ‖ `00`×47 | identity |
| `e0` ‖ `00`×47 (infinity with sort flag) | `MALFORMED_ENCODING` (step 4) |
| `c0` ‖ `00`×46 ‖ `01` (infinity with a coordinate bit) | `MALFORMED_ENCODING` (step 4) |
| `80` ‖ `00`×47 (`x = 0`) | `NOT_IN_SUBGROUP` (step 7; order 3) |
| `00` ‖ … (compression flag clear) | `MALFORMED_ENCODING` (step 3) |
| 47 or 49 octets | `MALFORMED_ENCODING` (step 2) |
| `x = P_381` with the compression flag | `MALFORMED_ENCODING` (step 5) |

---

## 11. Revision history

- **r1 (2026-10-22):** initial specification (ADR-0060 M0).

---

## 12. References

- RFC 9380, *Hashing to Elliptic Curves* (August 2023): §3, §3.1, §4, §5.2, §5.3.1, §6.6.2, §8.8.1,
  Appendix E.2, Appendix J.9.1, Appendix K.1.
- [CIP-0381](https://github.com/cardano-foundation/CIPs/blob/86b89208d3b2aabb5dcc5b778dfbe09096b4e114/CIP-0381/README.md)
  and [CIP-0133](https://github.com/cardano-foundation/CIPs/blob/86b89208d3b2aabb5dcc5b778dfbe09096b4e114/CIP-0133/README.md)
  at `86b89208d3b2aabb5dcc5b778dfbe09096b4e114`.
- draft-irtf-cfrg-bbs-signatures-10 §4.1.1 (one tag, distinct messages) and §4.2.2
  (`hash_to_scalar`, 48-octet expansion).
- [ADR-0060](../adr/0060-pedersen-bls12-381-g1-profiles.md); ADR-0021; ADR-0038; ADR-0051;
  ADR-0058; ADR-0059.
- [`commitment-profiles-v1`](commitment-profiles-v1.md); [`pedersen-jubjub-bytes-v1`](pedersen-jubjub-bytes-v1.md).
