# ZeroJ Pedersen-Jubjub Bytes v1 — Normative Specification

**Profile identifier:** `pedersen-jubjub-bytes-v1`
**Status:** Normative for `pedersen-jubjub-bytes-v1` (ADR-0058 milestone M0). Experimental: not
approved for value-bearing or mainnet use, and production remains gated as ADR-0058 states.
"Normative" fixes the bytes and behaviour; it is not a maturity or security claim. The spec
governs if it and the implementation disagree.
**Date:** 2026-10-16

This document defines a Pedersen commitment to an arbitrary sequence of octets on Jubjub. The
octets are mapped to a scalar with RFC 9380 `hash_to_field`, and the scalar is committed with
the unchanged two-base commitment of [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md). Changing
any constant, tag, procedure or encoding produces a different profile and requires a new
identifier.

This document fixes the profile's bytes, operations and error behaviour. The implementation
requirements of ADR-0058 D3 (typed surface), D5 (secret handling) and D6 (bounded memory) are
restated in §7 and remain binding; nothing here relaxes them.

The curve, field, bases `G` and `H`, point encoding, received-point validation and identity
policy are those of [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §1, §2, §4 and §4.1. This
profile derives no new base and changes no numeric commitment.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `l` | Jubjub prime-order subgroup order, `0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7` ([`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §1) |
| `p` | Jubjub base field order. **Never** used as the reduction modulus in this profile |
| `B` | The payload: a finite sequence of octets |
| `n` | The number of octets in `B` |
| `I2OSP(x, k)` | `x` as a `k`-octet unsigned **big-endian** string (RFC 9380 §4) |
| `OS2IP(s)` | The unsigned **big-endian** integer value of octet string `s` (RFC 9380 §4) |
| `a ‖ b` | Octet concatenation |
| `SHA-256` | FIPS 180-4 §6.2 |
| `0x..` | A single octet, or the listed octets in order |

`B` is octets only. It is never an integer, a string, a JSON value, a file path or a digest
supplied by the caller. Every octet is significant, including leading and trailing zeroes,
NUL, invalid UTF-8 and byte-order marks. No normalization, decompression or decoding occurs.
The empty sequence is a valid payload.

---

## 2. Constants

| Name | Value |
|---|---|
| Profile identifier | `pedersen-jubjub-bytes-v1` (ASCII) |
| `DST` | ASCII `ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-256`, exactly 46 octets, no terminator |
| `DST` (hex) | `5a65726f4a2d706564657273656e2d6a75626a75622d62797465732d76312d4832532d584d443a5348412d323536` |
| `DST_prime` | `DST ‖ 0x2e` (47 octets; `0x2e` = 46 = `I2OSP(len(DST), 1)`) |
| `L` | 48 = `ceil((ceil(log2(l)) + k) / 8)` with `ceil(log2(l)) = 252` and `k = 128` |
| `MAX_PAYLOAD_BYTES` | `2^61 − 256` = `2305843009213693696` |

There is no caller-supplied DST, digest, length encoding or modulus.

---

## 3. Hash to scalar

`HashBytesToScalar(B)` is RFC 9380 `hash_to_field` (§5.2) with `count = 1`, extension degree
`m = 1`, target field `GF(l)`, `L = 48`, and `expand_message_xmd` (§5.3.1) instantiated with
SHA-256 (`b_in_bytes = 32`, `s_in_bytes = 64`). Its message is not `B` itself but `B` framed by
its length as a suffix, so a stock `hash_to_field(B, DST)` call does not produce `s`.

### 3.1 Algorithm

Input: `B` with `0 ≤ n ≤ MAX_PAYLOAD_BYTES`. Output: an integer `s` with `0 ≤ s < l`.

```text
msg           = B ‖ I2OSP(n, 8)
b0            = SHA-256( I2OSP(0, 64) ‖ msg ‖ I2OSP(48, 2) ‖ I2OSP(0, 1) ‖ DST_prime )
b1            = SHA-256( b0 ‖ I2OSP(1, 1) ‖ DST_prime )
b2            = SHA-256( (b0 XOR b1) ‖ I2OSP(2, 1) ‖ DST_prime )
uniform_bytes = b1 ‖ (first 16 octets of b2)          # 48 octets
s             = OS2IP(uniform_bytes) mod l
```

Equivalently, octet by octet:

```text
b0 = SHA-256( 0x00 × 64 ‖ B ‖ I2OSP(n,8) ‖ 0x00 0x30 ‖ 0x00 ‖ DST ‖ 0x2e )
b1 = SHA-256( b0 ‖ 0x01 ‖ DST ‖ 0x2e )
b2 = SHA-256( (b0 XOR b1) ‖ 0x02 ‖ DST ‖ 0x2e )
```

`XOR` is octet-wise over the two 32-octet strings. `ell = ceil(48/32) = 2`.

Rules:

1. The length is a fixed 8-octet big-endian **suffix**, after the last payload octet. It is
   not a prefix and no terminator is added.
2. `n` is the number of payload octets actually hashed.
3. Reduction happens exactly once, modulo **`l`**, on the 48-octet `uniform_bytes` read as an
   unsigned big-endian integer. There is no rejection sampling, clamping, sign interpretation
   or modulo-`p` reduction.
4. `s = 0` is a valid result. It is never retried or rejected.
5. The 64-octet zero prefix is part of `b0`'s input. A plain SHA-256 digest of `msg` is not
   `b0`.
6. If `n > MAX_PAYLOAD_BYTES`, the mapping is undefined and the input is rejected (§6).

The bound keeps `b0`'s input, `n + 122` octets (64 + `n` + 8 + 2 + 1 + 47), below `2^61`
octets, i.e. below the `2^64`-bit message bound of SHA-256 (FIPS 180-4 §1 and §5.1.1). It is a
normative limit, not an estimate of feasible sizes.

### 3.2 Properties and limits

- The frame is injective: given `b0`'s input, the trailing 50 octets are the constant
  `I2OSP(48,2) ‖ 0x00 ‖ DST_prime`, the 8 octets before them are `n`, and everything between
  the 64-octet prefix and those 8 octets is `B`. The finite map to `[0, l)` is not injective.
- Binding of a commitment to `B` rests on both the discrete-log binding of `G`, `H`
  ([`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §2) and the collision resistance of the
  reduced map; the group size limits both to about 126 bits of generic security.
- Under the uniform-expander model, `OS2IP(uniform_bytes) mod l` is within statistical distance
  `l / 2^384 < 2^-132` of uniform on `[0, l)`.
- A single pass over `B` suffices for every input, including inputs whose length is unknown
  until the end: `n` is appended after the last octet.

---

## 4. Commitment

For a payload `B` and a blinding scalar `r`:

```text
C_bytes(B, r) = [HashBytesToScalar(B)]·G + [r]·H
```

with `G`, `H` from [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §2 and the group law of its
§1. Equivalently `C_bytes(B, r) = C(HashBytesToScalar(B), r)` with `C` the numeric commitment of
that profile's §3.

**Blinding.** `r` is an integer with `0 ≤ r < l`. Values outside that range are rejected, not
reduced (§6). `r = 0` is algebraically valid but gives no hiding. For hiding, `r` is sampled as
in [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §3.1: 64 octets from a cryptographically
secure generator, read unsigned big-endian, reduced mod `l`. `r` is never derived from `B`,
from `s`, or reused across independent commitments.

**No disjointness from numeric commitments.** A byte commitment is a point of the same group
under the same bases. Anyone who knows `(B, r)` also knows the numeric opening `(s, r)`. The
point does not identify its profile; see §8.

**Homomorphism.** Adding two byte commitments relates the derived scalars modulo `l` only. It
is not concatenation, merging, or any arithmetic on the original octets.

**Identity.** There is no special case: `C_bytes(B, r)` is the identity iff
`[s]·G + [r]·H = O`. Because `H = [h]·G` for some nonzero `h` whose discrete logarithm is
assumed unknown ([`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §2), every `s` has
exactly one cancelling `r = −s·h⁻¹ mod l`. For `s = 0` that is `r = 0`; for `s ≠ 0`, finding it
requires the discrete logarithm of `H`.
Only when `r = 0` is the condition equivalent to `s = 0`, and finding a payload with `s = 0` is
a preimage problem. The empty payload's `s` is nonzero, so `C_bytes(empty, 0)` is not the
identity (§10). An identity point, like any other, is accepted only after the full equation
check.

---

## 5. Encoding and received commitments

The wire encoding of a byte commitment is exactly the 32-octet point encoding of
[`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §4. No profile identifier, tag, length or
version octet is serialized with it.

A received byte commitment is accepted only under the rules of
[`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §4.1. It must be canonical (ZIP 216) and in
the prime-order subgroup. Small-order, mixed-order and off-curve encodings are rejected, never
cofactor-cleared. The identity is accepted as a point. Accepting a point never accepts an
opening: verification (§6) still checks the equation. A received point is validated once, when
it is decoded; decoding consults no caller-supplied profile label.

---

## 6. Operations and error contract

An implementation provides generation and disclosed-opening verification. Both validate all
arguments **before obtaining a digest or reading or hashing any payload octet**, in this order:
missing (null) arguments, then `0 ≤ r < l`, then the declared length or maximum. (The order is
observable only through which failure is reported.)

| Condition | Result |
|---|---|
| A required argument is missing | Rejected as a programming error (Java: `NullPointerException`) |
| `r < 0` or `r ≥ l` | Rejected (Java: `IllegalArgumentException`); the message never contains `r` |
| Declared length or maximum `< 0` or `> MAX_PAYLOAD_BYTES` | Rejected before any read (Java: `IllegalArgumentException`) |
| In-memory payload with `n > MAX_PAYLOAD_BYTES` | Rejected (unreachable for Java arrays) |
| Received point bytes fail §5 | Rejected (Java: `IllegalArgumentException`) |
| Stream ends before a declared length | Failure (Java: `IOException`); no commitment, no success |
| Stream has an octet beyond the declared length or maximum | Failure (Java: `IOException`); the extra octet is not hashed |
| A read reports a count outside `[−1, requested]`, or a single-octet read a value outside `[−1, 255]` | Failure (Java: `IOException`) |
| Underlying read fails | Failure propagated (Java: `IOException`) |
| SHA-256 unavailable | Platform failure (Java: `IllegalStateException`, with the provider's exception as cause); never a fallback hash |
| The digest fails during use | The provider's unchecked exception propagates unchanged; never success, never a fallback |
| Well-formed opening that does not satisfy §4 | Verification returns false |

No row turns a failure into a result: a commitment is produced, or `true` returned, only after
the complete payload has been hashed and every check above has passed.

**Generation** computes `s` and the commitment through the secret-bearing path (§7). **Disclosed-
opening verification** recomputes `s` from the supplied payload and checks
`C = [s]·G + [r]·H`. It may use variable-time arithmetic because the opening is disclosed to the
verifier. A party checking a still-private payload or opening recomputes the commitment with
generation and compares points instead.

### 6.1 Payload sources

Three payload sources produce the **same** `s` for the same octets:

1. **In-memory octets.** `n` is their length.
2. **Declared-length stream.** The caller declares `length` with
   `0 ≤ length ≤ MAX_PAYLOAD_BYTES`. The stream must deliver exactly `length` octets. End of
   stream before that is a failure. After `length` octets the implementation probes once;
   end of stream is success and any octet is a failure.
3. **Bounded read-to-end stream.** The caller supplies a maximum `maxBytes` with
   `0 ≤ maxBytes ≤ MAX_PAYLOAD_BYTES`. The implementation reads until end of stream. End of
   stream at any count `≤ maxBytes` is success and `n` is that count. If `maxBytes` octets have
   been read, it probes once; any octet is a failure.

Reading rules for both stream sources:

- **End of stream** is only the source's explicit end indication (Java: a read returning −1).
  A bulk read returning zero octets is **not** end of stream: the implementation then performs
  a single-octet read, which blocks until an octet, end of stream or a failure.
- A bulk read is never issued for more octets than the remaining budget, and never with a
  remaining budget of zero. Any reported count outside `[−1, requested]` is a failure.
- The **probe** is a single-octet read. Its only outcomes are end of stream (success), one
  octet (failure; the octet is consumed and not hashed) or a read failure.
- `n` is the count of octets actually read and hashed. The suffix `I2OSP(n, 8)` is appended
  only after end of stream has been observed and every check has passed.
- At most `length + 1` or `maxBytes + 1` octets are read.
- Read boundaries are not part of the input; any division of the same octets into reads gives
  the same `s`.
- The implementation does not close, reset, mark, skip, seek, reopen or query the available
  size of the stream, and does not retry a partially consumed stream, on any exit. The caller
  owns the stream, its deadlines and its limits. The probe can block.
- No result is produced until the stream has been fully consumed and checked; curve work
  happens only after that.

### 6.2 Java binding (ZeroJ, `org.zeroj.circuit.lib.jubjub`)

This is the reviewed API contract for ADR-0058 D3 (Q2: additive methods on the existing facade).

On `PedersenCommitment` (static; the existing numeric methods are unchanged):

```java
PedersenBytesCommitment commitBytes(byte[] payload, BigInteger blinding);
PedersenBytesCommitment commitBytes(InputStream payload, long length, BigInteger blinding) throws IOException;
PedersenBytesCommitment commitBytesToEnd(InputStream payload, long maxBytes, BigInteger blinding) throws IOException;
boolean verifyBytes(PedersenBytesCommitment commitment, byte[] payload, BigInteger blinding);
boolean verifyBytes(PedersenBytesCommitment commitment, InputStream payload, long length, BigInteger blinding) throws IOException;
boolean verifyBytesToEnd(PedersenBytesCommitment commitment, InputStream payload, long maxBytes, BigInteger blinding) throws IOException;
```

The name selects the meaning of the `long`: `commitBytes`/`verifyBytes` take an exact declared
length, the `ToEnd` forms a maximum. Neither meaning is ever inferred from the value.

`PedersenBytesCommitment` is a final, immutable class:

- `public static final String PROFILE_ID = "pedersen-jubjub-bytes-v1"` and `profileId()`:
  metadata for configuration and documentation, never serialized and never proof of provenance.
- `static PedersenBytesCommitment decode(byte[] pointBytes)`: §5; the only way to build one
  from received bytes.
- `byte[] toPointBytes()`: a fresh copy of the 32-octet encoding.
- Equality and hash code are those of the point encoding, within this type only; an instance is
  never equal to a bare point.
- No public or protected constructor, no record, not `Serializable`; no addition, subtraction,
  negation or balance methods.
- It holds only the validated, normalized point. It never retains `B`, `s`, `r`, a digest or a
  stream.

---

## 7. Implementation requirements (ADR-0058 D5, D6)

**Secret values during generation:** the payload `B`, the digest state, `b0`, `b1`, `b2`,
`uniform_bytes`, `s`, `r`, and every buffer holding payload octets. Any of `b0`, `b1`, `b2`,
`uniform_bytes` or `s` lets an observer test candidate payloads.

- Hashing, reduction and both scalar multiplications run inside the same offline or isolated
  boundary required for `pedersen-jubjub-v1` generation. Both `[s]·G` and `[r]·H` use the
  implementation's secret-scalar path with fresh internal blinding on every call (in ZeroJ,
  the blinded fixed schedule of `PedersenCommitment.commit`); never a public variable-time
  multiplication, multi-scalar multiplication or secret-indexed table.
- Owned buffers, digest outputs and scalar octet temporaries are wiped on every exit, including
  failures, and the operation-owned digest is reset and never reused. The caller's payload
  array or stream is never wiped or modified. This cleanup is best effort: it cannot erase
  copies held by immutable big-integer values, the cryptographic provider, the JIT or the
  garbage collector.
- No secret value appears in logs or exception messages. Nothing is cached, pooled or kept in
  thread-local storage between operations.
- Blinding generation propagates entropy-source failure; there is no deterministic fallback.
- **Memory:** the payload is fed to the digest once. The implementation never copies it, builds
  `msg` in memory, encodes it, or allocates by its length; stream buffers have a fixed size
  independent of `n` (ZeroJ: 8 KiB, at most 64 KiB, non-normative). Auxiliary memory is
  `O(1)` in `n`.
- None of this is a constant-time claim. Disclosed-opening verification is not covered by
  these secrecy rules because its inputs are public to the verifier.

---

## 8. Profile and context authentication

The decoder is specific to this profile, so it never consults a caller-supplied label. A
verifier chooses `pedersen-jubjub-bytes-v1` from trusted configuration. When an application
depends on where or under which profile a point was issued, it authenticates the association
of the exact point, the profile and its context separately (for example, an issuer-signed
record or policy-guarded state) and rejects when that association is missing or does not
match. A successful opening check is not evidence of issuance profile or context.

A byte commitment is not encryption, does not store or recover the payload, and does not
provide availability, authorization, provenance, replay protection or transaction binding.
If `s`, `r` or any of `b0`, `b1`, `b2`, `uniform_bytes` is exposed, small payload spaces can be
enumerated against the commitment.

---

## 9. Compatibility

- `pedersen-jubjub-v1`, `pedersen-jubjub-vector-v1`, `jubjub-eddsa-v1` and
  `confidential-note-jubjub-v1` are unchanged: their bases, encodings, vectors, circuits,
  public-input order and keys. No setup, key regeneration or reissuance is needed.
- The numeric `commit`/`verify` keep their modular acceptance of negative and out-of-range
  integers; only the new byte operations require canonical `r`.
- Nothing substitutes a byte commitment for a numeric one automatically, for example by input
  length. A byte-derived scalar is never a confidential-note amount.

---

## 10. Test vectors

The values below were produced by an independent reference written from this document and
RFC 9380 only (`zeroj-circuit-lib/src/test/resources/pedersen-bytes-reference/`). From
ADR-0058 M1 its full output is checked against the library at every build. RFC 9380 Appendix
K.1 tests `expand_message_xmd` with its own DST and output lengths, not this profile.

| Case | Value |
|---|---|
| empty: `n` | `0` |
| empty: `b0` | `d8a576b8db82c95dac7246e17f5cee19e4aa715e06e0c6a7f26b8c30aec62481` |
| empty: `uniform_bytes` | `0806e94e86b0513631c07b6aba359c462afe5fae6338f2b8a9f8f9070c67b61fc8b5cd7a9ee1f3d2739001762e0b7f17` |
| empty: `s` | `0x061f05a7e9920513846bc5f0dd366c71a5ed2c35c6cdc88ba6f71d0f355f4181` |
| `0x00`: `s` | `0x0dca70c85ae4d9c8e22f6ff09a66fd81291c89763679c0c4acc2957942b53294` |
| `48656c6c6f2c205a65726f4a20e29c93` (UTF-8 `Hello, ZeroJ ✓`): `s` | `0x01021bce20e1ca8d71cc9ce2bbe988eee0335a559a8e7e65574e1049224d674f` |
| `encode(C_bytes(empty, 0))` (not the identity) | `9f0d942a712d02e78959e4899908bfd3d8fff8f871f42ae4ace3d1f336e9789d` |
| `encode(C_bytes(empty, l − 1))` | `0f2b6778c98d4623d8312c6d7cb02dc7892ce94927c04dd064adcfb7e7912489` |
| `encode(C_bytes(Hello…✓, l − 1))` | `4e66485131af3603f96f18003966a30793f1c78492c27d644c1e12d0a941852d` |

The fixture set also includes `n`, `b0`, `b1`, `b2`, `uniform_bytes` and `s` for 35 payloads
(including lengths at the padding and block boundaries of `b0`'s `n + 122`-octet input, up to 1 MiB), commitments under fixed test
blindings, rejected point encodings, and mutations of the algorithm that the fixtures must
distinguish. Mutations of the length frame are checked on a nonempty payload: for `n = 0` a
length prefix and a length suffix give the same `msg`. Fixed test blindings are not hiding
blindings (§4).

---

## 11. Non-goals

- Any circuit or proof that `s` was derived from particular octets. Existing scalar gadgets
  constrain an opening of `s` only.
- A self-describing envelope, profile tag or generic opening codec (ADR-0058 defers these to
  issue #94).
- Commitments to text, JSON or other structured data beyond their exact octets. Applications
  that canonicalize such data define and version that step themselves.
- Any statement about constant-time generation. Secret-bearing off-circuit generation remains
  restricted to offline or isolated use, as for `pedersen-jubjub-v1`.

---

## 12. References

- RFC 9380, *Hashing to Elliptic Curves*, August 2023: §4 (`I2OSP`/`OS2IP`), §5 and §5.2
  (`hash_to_field`; "also suitable for securely hashing to scalars"), §5.3.1
  (`expand_message_xmd`), Appendix K.1 (`expand_message_xmd` SHA-256 test vectors).
- FIPS 180-4, *Secure Hash Standard*, August 2015: §1 and §5.1.1 (input-length bound), §6.2
  (SHA-256).
- [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md): curve, bases, commitment, encoding and
  received-point rules.
- ZIP 216, *Require Canonical Jubjub Point Encodings*.
- ADR-0058 (this profile), ADR-0051 (Pedersen profiles).
