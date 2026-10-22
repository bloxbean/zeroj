# ZeroJ Commitment Profiles v1 — Registry and Contract Specification

**Document identifier:** `commitment-profiles-v1`
**Status:** Normative (ADR-0059 milestone M0; G1 entries ADR-0060, admitted at milestone M5). Experimental: not approved for value-bearing or
mainnet use. "Normative" fixes identifiers, bytes, checks, check order and error behaviour; it
is not a maturity or security claim. This document governs if it and an implementation
disagree.
**Date:** 2026-10-22 (r7)

This document is the registry of ZeroJ commitment profiles, basis sets and proof protocols, and
the contract every implementation of them follows: the expected-profile rule, scalar checks,
opening encodings, the envelope, error classes, the Java binding, the cross-language vector
format and the verification matrix. The rationale is in
[ADR-0059](../adr/0059-commitment-profiles-and-verification-strategy.md).

The per-profile specifications stay authoritative for their algorithms:
[`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md),
[`pedersen-jubjub-vector-v1.md`](pedersen-jubjub-vector-v1.md) and
[`pedersen-jubjub-bytes-v1.md`](pedersen-jubjub-bytes-v1.md) for Jubjub, and
[`pedersen-bls12-381-g1-v1.md`](pedersen-bls12-381-g1-v1.md) for the BLS12-381 G1 basis set and
profiles. Nothing here changes a constant,
base, hash, point encoding, circuit or key defined there. Two editorial interactions are noted
where they arise: the envelope (§9) serializes a profile identifier next to a point, which
`pedersen-jubjub-bytes-v1.md` §6.2 and §11 describe as out of that profile's own wire form; and
the V1 timing rule (§6.2) qualifies the "disclosed" wording of `pedersen-jubjub-v1.md` §3.2 and
`pedersen-jubjub-bytes-v1.md` §6. ADR-0059 M3 adds non-normative pointers in those sections.

The key words MUST, MUST NOT and MAY are normative.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `q` | the prime order of a profile's group; for every Jubjub profile `q = l`; for the BLS12-381 G1 profiles `q` is the order of the G1 prime-order subgroup (255 bits, `pedersen-bls12-381-g1-v1.md` §1), numerically equal to `p` |
| `l` | `0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7` (252 bits; `2^251 < l < 2^252`) |
| `p` | the BLS12-381 scalar field order (Jubjub base field), `pedersen-jubjub-v1.md` §1 |
| `a ‖ b` | concatenation of octet strings |
| `u8(x)` | one octet holding the integer `0 ≤ x ≤ 255` |
| `I2OSP(x, n)` | `x` as an `n`-octet unsigned big-endian string; defined only for `0 ≤ x < 2^{8n}` |
| `ASCII(s)` | the octets of the ASCII string `s` |

---

## 2. Identifiers

### 2.1 Grammar

An identifier is an ASCII string of 4 to 64 octets whose **entire** content matches

```
[a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*
```

(no leading, trailing or embedded line break or other character is permitted; implementations
use a whole-string match, not a search anchored with `$`). The shortest valid identifier is
`a-v1`. Identifiers compare octet-for-octet; there is no case folding, trimming or Unicode
normalization.

### 2.2 One namespace

Commitment profiles (§4), proof protocols (§5) and basis sets (§3) share one namespace. An
identifier names exactly one registry entry of one type, forever. Admission MUST reject an
identifier equal to any existing or withdrawn entry or to a reserved document name (below). A
**reserved** registry entry (§2.3) may be admitted only under the issue or ADR named in its
reservation, which turns it active; every other admission of a reserved identifier is rejected.
A withdrawn entry stays listed.

To prevent collisions, the document names of ZeroJ's other specifications and formats are
reserved and never admissible as registry entries: `commitment-profiles-v1`,
`zeroj-commitment-vectors-v1`, `confidential-note-jubjub-v1`, `elgamal-jubjub-v1`,
`elgamal-jubjub-threshold-v1`, `dkg-share-delivery-hpke-v1`, `jubjub-eddsa-v1` (the document
name of the suite `ZeroJ-JubjubEdDSA-v1`) and `jubjub-eddsa-hedged-v1` (the candidate
document).

### 2.3 Registry

| Identifier | Type | Status | Definition |
|---|---|---|---|
| `pedersen-jubjub-basis-v1` | basis set | active | §3.1 |
| `pedersen-jubjub-vector-basis-v1` | basis set | active | §3.2 |
| `pedersen-jubjub-v1` | commitment profile | active | §4.2 |
| `pedersen-jubjub-vector-v1` | commitment profile | active | §4.3 |
| `pedersen-jubjub-bytes-v1` | commitment profile | active | §4.4 |
| `pedersen-bls12-381-g1-basis-v1` | basis set | active | §3.3; admitted under ADR-0060 (issue #95) |
| `pedersen-bls12-381-g1-v1` | commitment profile | active | §4.6; admitted under ADR-0060 (issue #95) |
| `pedersen-bls12-381-g1-bytes-v1` | commitment profile | active | §4.7; admitted under ADR-0060 (issue #95) |

The three G1 entries have their parameters fixed by
[`pedersen-bls12-381-g1-v1.md`](pedersen-bls12-381-g1-v1.md). r7 admits them after ADR-0060
milestone M5 checked every admission prerequisite (§2.4 and ADR-0060 D1): the accepted ADR, the
normative specification, the three reproductions of the bases (Java, the independent Python
reference, and on-chain `bls12_381_G1_hashToGroup` in the Julc VM and on Yaci DevKit), the §13
vectors with their independent recomputation, the descriptors, and the M4 on-chain parity results.
Admission does not change their maturity: like every profile, they are experimental.

No proof protocol is registered.

**Protocols using a profile** (not commitment profiles; their identifiers are reserved, §2.2):

| Protocol | Uses | How |
|---|---|---|
| `confidential-note-jubjub-v1` | `pedersen-jubjub-v1` | note amount commitments and their openings |
| `elgamal-jubjub-v1` | `pedersen-jubjub-v1` | the auditor relation of `confidential-note-jubjub-v1` §8 |

### 2.4 Admission and updates

A commitment profile, basis set or proof protocol is admitted only with:

1. an accepted ADR, recorded by a named human maintainer;
2. a normative specification;
3. an independent reproduction of its constants (bases, domain strings, transcript labels),
   written without reading the implementation under test;
4. vectors in the format of §13;
5. for a commitment profile or proof protocol, one public Java constant carrying its
   identifier: a `CommitmentProfile` descriptor (§12.1) for a profile; for a proof protocol, a
   descriptor type fixed when the first protocol is admitted, holding an identifier validated by
   §2.1.

Lifecycle metadata (§4.5) changes only by a reviewed revision of this document, recorded in the
revision history (§16) with its evidence. A revision MUST NOT change a cryptographic core field
(§4.1), a basis-set definition or a proof protocol's transcript.

---

## 3. Basis sets

A basis set is an ordered list of bases. Every base:

- is a validated element of the group's prime-order subgroup and is not the identity;
- is distinct from every other base of the set;
- has no known discrete-log relation to another base of the set, and is not defined as a known
  multiple of one;
- has a pinned definition that an independent implementation reproduces.

A reviewed profile MAY reference an existing basis set instead of deriving its own; its domain
separation then comes from its message map, and its points coincide with those of the other
profiles using the set (§6.3). A newly derived set MUST come from a published hash-to-group
procedure under a domain string specific to that set.

### 3.1 `pedersen-jubjub-basis-v1`

`(G, H)` exactly as [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §2 defines them:

- `G = [8]·G_full`, the pinned standard Jubjub subgroup generator (§2.1); `encode(G) =
  cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7`. It is not hash-derived.
- `H`, derived by Poseidon try-and-increment from `"zeroj.pedersen.v1.H"` (§2.3);
  `encode(H) = 7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60`.

Independent reproduction: `zeroj-circuit-lib/src/test/resources/pedersen-reference/`. Used by
`pedersen-jubjub-v1` and `pedersen-jubjub-bytes-v1`.

### 3.2 `pedersen-jubjub-vector-basis-v1`

`(G_0, …, G_15, H_V)` exactly as [`pedersen-jubjub-vector-v1.md`](pedersen-jubjub-vector-v1.md)
§2 defines them, by Zcash `FindGroupHash^J` under the personalization `"ZeroJ_PV"`.

Independent reproduction: `zeroj-circuit-lib/src/test/resources/pedersen-vector-reference/`.
Used by `pedersen-jubjub-vector-v1`.

### 3.3 `pedersen-bls12-381-g1-basis-v1`

`(G, H)` exactly as [`pedersen-bls12-381-g1-v1.md`](pedersen-bls12-381-g1-v1.md) §2 defines them:
RFC 9380 `hash_to_curve` with the suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` applied to the messages
`"G"` and `"H"` under the tag
`ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_`. Both are hash-derived.

- `encode(G) = 80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e`
- `encode(H) = 92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65`

Independent reproduction: `zeroj-bls12381/src/test/resources/pedersen-g1-reference/` (Python,
written from RFC 9380 without reading the Java); on-chain `bls12_381_G1_hashToGroup` is the third
reproduction ADR-0060 requires before admission. Used by `pedersen-bls12-381-g1-v1` and
`pedersen-bls12-381-g1-bytes-v1`.

---

## 4. Commitment profiles

### 4.1 Cryptographic core

Every commitment profile states these fields. They are immutable: changing any of them requires
a new identifier.

1. **Kind** — `scalar`, `bytes` or `vector` (§6.1).
2. **Group** — curve, prime order `q`, cofactor, identity element.
3. **Basis set** — an identifier from §3.
4. **Message map** — how the committed message becomes scalars.
5. **Scalar domain** — which operations accept integers mod `q` and which require `[0, q)`.
6. **Point encoding** — length, canonical-encoding rule, subgroup rule, identity policy.
7. **Circuit public-input encoding** — where the profile is used in circuits.
8. **Opening encoding** — §8.

### 4.2 `pedersen-jubjub-v1`

| Field | Value |
|---|---|
| Kind | `scalar` |
| Group | Jubjub prime-order subgroup; `q = l`; cofactor 8; identity `(0, 1)` |
| Basis set | `pedersen-jubjub-basis-v1` |
| Message map | `C(m, r) = [m]·G + [r]·H` |
| Scalar domain | Legacy `PedersenCommitment.commit`/`verify` reduce any integer mod `l` (unchanged). `commitScalar`, `verifyScalar`, the opening codec and every wire format require `m, r ∈ [0, l)` (§7, check 1) |
| Point encoding | 32 octets, `pedersen-jubjub-v1.md` §4 (ZIP 216 canonical); received points MUST be in the prime-order subgroup (§4.1); the identity is accepted |
| Public inputs | affine `u`, then `v` (`pedersen-jubjub-v1.md` §5) |
| Opening encoding | §8.1 |

### 4.3 `pedersen-jubjub-vector-v1`

| Field | Value |
|---|---|
| Kind | `vector` |
| Group | as §4.2 |
| Basis set | `pedersen-jubjub-vector-basis-v1` |
| Message map | `C(v_0..v_{n−1}, r) = Σ [v_i]·G_i + [r]·H_V` under a schema of dimension `1 ≤ n ≤ 16` (`pedersen-jubjub-vector-v1.md` §3–§4) |
| Scalar domain | Legacy `commit` validates each `v_i` against its schema width and reduces `r` mod `l`; legacy `verify` returns `false` for malformed values, reduces `r`, and throws only for a null blinding (all unchanged). `verifyOpening`, `PedersenVectorOpening` and every wire format require `v_i, r ∈ [0, l)` and the configured bound policy (§7, checks 1 and 3) |
| Point encoding | as §4.2 |
| Public inputs | affine `u`, `v`, and the schema digest `σ` (`pedersen-jubjub-vector-v1.md` §5) |
| Opening encoding | §8.3 |

The schema is not part of the point. A vector commitment is meaningful only with the schema
taken from the consumer's trusted configuration or issuance record
(`pedersen-jubjub-vector-v1.md` §6). In this document the schema is part of the vector
profile's **context**: a different schema is a `PROFILE_MISMATCH`.

### 4.4 `pedersen-jubjub-bytes-v1`

| Field | Value |
|---|---|
| Kind | `bytes` |
| Group | as §4.2 |
| Basis set | `pedersen-jubjub-basis-v1` (shared with `pedersen-jubjub-v1`) |
| Message map | `s = HashBytesToScalar(B)` (`pedersen-jubjub-bytes-v1.md` §3), then `C = [s]·G + [r]·H` |
| Scalar domain | `r ∈ [0, l)` on every operation; `s` is recomputed by the verifier, never accepted as part of a bytes opening, and is in `[0, l)` by construction |
| Point encoding | as §4.2 |
| Public inputs | none (no byte-hashing circuit) |
| Opening encoding | §8.2 |

A validator that accepts a supplied scalar instead of the payload is performing a `scalar`
opening of `s`, not a bytes opening: check 1 applies to the supplied scalar, and the check
authenticates only that scalar, not any octets. The G1 bytes profile offers no such mode
(`pedersen-bls12-381-g1-v1.md` §3.2).

### 4.5 Lifecycle metadata

Maintained separately from the core (§2.4).

| Profile | Status | Maturity | Governing ADRs | Evidence | Implementations / providers |
|---|---|---|---|---|---|
| `pedersen-jubjub-v1` | active | experimental; generation offline/isolated only | ADR-0051, ADR-0059 | `pedersen-reference/`; `zeroj-test-vectors/.../commitment-profiles-v1/pedersen-jubjub-v1.json` (§13; independent generator `commitment-vectors-reference/`) | pure Java, `zeroj-circuit-lib` |
| `pedersen-jubjub-vector-v1` | active | experimental; generation offline/isolated only | ADR-0051, ADR-0059 | `pedersen-vector-reference/`; `zeroj-test-vectors/.../commitment-profiles-v1/pedersen-jubjub-vector-v1.json` (§13; independent generator `commitment-vectors-reference/`) | pure Java, `zeroj-circuit-lib` |
| `pedersen-jubjub-bytes-v1` | active | experimental; generation offline/isolated only | ADR-0058, ADR-0059 | `pedersen-bytes-reference/`; `zeroj-test-vectors/.../commitment-profiles-v1/pedersen-jubjub-bytes-v1.json` (§13; independent generator `commitment-vectors-reference/`) | pure Java, `zeroj-circuit-lib` |
| `pedersen-bls12-381-g1-v1` | active | experimental; generation offline/isolated only | ADR-0060, ADR-0059 | `pedersen-g1-reference/` (independent Python reproduction of the bases and test values); `zeroj-test-vectors/.../commitment-profiles-v1/pedersen-bls12-381-g1-v1.json` (§13; independent generator `pedersen-g1-reference/emit_g1_commitment_vectors_v1.py`); [measurements](../benchmarks/pedersen-g1-2026-10-22.md) | `zeroj-bls12381` (pure Java and blst providers); `zeroj-onchain-julc` `PedersenG1Lib` |
| `pedersen-bls12-381-g1-bytes-v1` | active | as above | ADR-0060, ADR-0059 | as above, with `pedersen-bls12-381-g1-bytes-v1.json` | as above |

### 4.6 `pedersen-bls12-381-g1-v1`

| Field | Value |
|---|---|
| Kind | `scalar` |
| Group | BLS12-381 G1 prime-order subgroup; `q` as §1; cofactor `0x396c8c005555e1568c00aaab0000aaab`; identity `0xC0 ‖ 0^47` accepted |
| Basis set | `pedersen-bls12-381-g1-basis-v1` |
| Message map | `C(m, r) = [m]·G + [r]·H` |
| Scalar domain | `m, r ∈ [0, q)` on every operation (§7, check 1); homomorphic results are residues mod `q` |
| Point encoding | 48-octet Zcash compressed, strict decoder `pedersen-bls12-381-g1-v1.md` §4 (received points MUST be in the prime-order subgroup; never cofactor-cleared) |
| Public inputs | none |
| Opening encoding | §8.4 |

### 4.7 `pedersen-bls12-381-g1-bytes-v1`

| Field | Value |
|---|---|
| Kind | `bytes` |
| Group | as §4.6 |
| Basis set | `pedersen-bls12-381-g1-basis-v1` (shared with `pedersen-bls12-381-g1-v1`) |
| Message map | `s = HashBytesToScalarG1(B)` (`pedersen-bls12-381-g1-v1.md` §5), then `C = [s]·G + [r]·H` |
| Scalar domain | `r ∈ [0, q)` on every operation; `s` is recomputed by the verifier, never accepted as part of a bytes opening, and is in `[0, q)` by construction |
| Point encoding | as §4.6 |
| Public inputs | none |
| Opening encoding | §8.4 |

---

## 5. Proof protocols

A proof protocol over commitments is its own registry entry with its own identifier. Its record
states:

1. the commitment profile(s) it consumes;
2. the statement proved;
3. the exact transcript: domain strings, absorbed items and their order, challenge derivation
   and proof encoding;
4. its binding rule (§6.4).

Changing any transcript element requires a new protocol identifier; a transcript is never
replaced under an existing identifier. Adding a protocol does not change or rename the
commitment profile it consumes.

No proof protocol is registered. G1 sigma protocols (ADR-0051 D7, escalated) and range proofs
(issue #96) will be admitted under §2.4.

---

## 6. Semantics and verification

### 6.1 Kinds

| Kind | Opens to | Homomorphism means | Never presented as |
|---|---|---|---|
| `scalar` | a residue mod `q` | addition of residues mod `q` | integer arithmetic, unless every term satisfies ADR-0051 D3a |
| `bytes` | an exact octet string | addition of hash-derived scalars mod `q` | arithmetic, concatenation, merge or comparison of the original octets |
| `vector` | `n` residues under one schema | component-wise addition under one schema digest | anything across schemas |

Implementations MUST expose homomorphic operations only on concrete profile types, accepting
only the same concrete type (and, for vectors, the same schema), and MUST NOT expose arithmetic
on `bytes` commitments or on the shared contract types (§12.1).

### 6.2 Verification classes

| Class | Discloses to the verifier | Establishes | Does not establish | Java (Jubjub) |
|---|---|---|---|---|
| **V1** disclosed opening | message and `r` | the commitment opens to the message under the expected profile | an integer range beyond check 2; provenance; authorization | `verifyScalar`, `verifyBytes*`, `verifyOpening` |
| **V2** private recomputation | nothing | the same, for the holder only | as V1 | `commitScalar`, `commitBytes*`, vector `commit` (schema-width openings only), then compare encodings; for a derived vector commitment, recompute each term with `commit` and combine with `add`/`subtract` |
| **V3** public relation | coefficients and deltas | a linear relation between hidden residues mod `q` | non-negativity; integer conservation; knowledge of an opening | typed `add`/`subtract`/`negate` |
| **V4** proof | the proof's public inputs | the proof system's statement | anything outside the statement | Groth16/PlonK with `ZkPedersen` |
| **P** policy | application data | expected profile, schema, provenance, context, replay rules | (not cryptographic) | `CommitmentAcceptance` provenance callback |

**Timing rule for V1.** "Disclosed to this verifier" is not "public". A V1 check MAY use
variable-time arithmetic only if the opening is already public (for example, published
on-chain) or no party from whom it is still secret can observe the verifier's timing. Otherwise
the V2 restriction applies: offline or isolated execution only.

**Hiding is the committer's job.** Hiding needs a fresh, uniform blinding per commitment
(`PedersenCommitment.randomBlinding`). Two commitments with the same blinding reveal
`[m₁ − m₂]·G`, so small differences can be enumerated. A disclosed opening over a low-entropy
message space (votes, small amounts, short strings) discloses the message.

### 6.3 Expected-profile rule

A verifier takes the expected profile, and for vectors the expected schema, from its own trusted
configuration. It MUST NOT select a profile, kind or schema from a label, envelope, datum field
or proof that travels with the input. A label that disagrees with the expected profile is
rejected (`PROFILE_MISMATCH`). A label that agrees is not evidence of provenance. Where
provenance matters, the application authenticates the association of the exact point, profile
and context, and rejects when it is missing (`PROVENANCE_MISSING`) or does not match
(`PROVENANCE_MISMATCH`).

A point never identifies its profile: profiles that share a basis set produce the same points
(`C_bytes(B, r) = C(s, r)`).

### 6.4 Proof-context binding

A proof about commitments binds its full statement. In Groth16/PlonK circuits this is the
verification key together with constrained public inputs (the affine coordinates, and the schema
digest for vectors; ADR-0045). In Fiat–Shamir proofs the transcript absorbs the proof protocol
identifier, the commitment profile identifier, every base, every commitment and the application
context. A proof verified under one profile or context is never accepted under another.

---

## 7. Scalar checks

Three checks are distinct and MUST NOT be conflated.

1. **Canonical residue (always).** Every scalar used as a residue — a `scalar` message `m`, each
   vector component `v_i`, and every blinding `r` — is an integer in `[0, q)`. Anything else is
   rejected with `NON_CANONICAL_SCALAR`, never reduced. `q − 1` is accepted; `q`, `q + 1` and
   `−1` are rejected.
2. **Application amount bound (only when requested).** An application that reads `m` as an
   amount MAY additionally require `m < 2^k` for a configured `1 ≤ k ≤ ⌊log₂ q⌋` (for Jubjub,
   `k ≤ 251`; for BLS12-381 G1, `k ≤ 254`). A violation is `OUT_OF_RANGE`; a `k` outside that range is
   `INVALID_CONFIGURATION`. This bound may reject a valid residue. It never applies to `r` or to
   a bytes-derived `s`, and opening decoders never apply it.
3. **Vector bound policy.** A vector opening is checked under exactly one explicitly configured
   policy bound to one schema:
   - `schema-widths`: each `v_i < min(2^{k_i}, q)` for the schema widths `k_i`. Recommended for
     commitments issued under the schema.
   - `residue-only`: check 1 only. For derived commitments, including differences whose negative
     components open to residues `q − x`.
   - `widened(n)`: for the sum of `n` commitments under the schema, `2 ≤ n ≤ 65536`, each
     `v_i < 2^{k_i + ⌈log₂ n⌉}`. Configuration fails with `INVALID_CONFIGURATION` if `n` is
     outside `[2, 65536]` or any `2^{k_i + ⌈log₂ n⌉} > q`. (The upper limit refines ADR-0059,
     which states none; a sum of more than 65536 terms is checked with `residue-only`.)

   A violation is `OUT_OF_RANGE`. The policy is never inferred from the data, and its schema MUST
   equal the commitment's schema (`PROFILE_MISMATCH` otherwise). Legacy `verify` keeps its own
   behaviour (§4.3).

**Public deltas and coefficients (V3).** A delta `δ` in `C_new = C_old + [δ]·G` is a signed
integer with an application bound `|δ| < 2^{k_δ}`, `2^{k_δ+1} − 1 ≤ q` (so the bounded range holds
no two integers that are congruent mod `q`: a delta is unique mod `q`); its residue is `δ mod q`. An
implementation computes `[|δ|]·G` with a canonical scalar and negates the point when `δ < 0`; it
never passes a negative or out-of-range integer to a scalar-multiplication primitive.
Coefficients of a sum are small non-negative integers fixed by the verifier, never supplied by
the prover; a negative coefficient moves its term to the other side. A verifier that reads a
combination of commitments as integer conservation applies the side-bound rule of ADR-0051 D3a
to declared widths.

**On-chain.** A validator performs check 1 on every opening scalar it receives, check 2 only when
its application requires a numeric range, and the delta rule, before any builtin sees the value.
CIP-0381 does not specify how `bls12_381_G1_scalarMul` treats out-of-range or negative integers.
CIP-0133 states that MSM scalars are reduced modulo the group order before blst is called, and
that `bls12_381_G1_multiScalarMul` fails unless its two lists are non-empty and of equal length.
Builtin behaviour is evidence, never the guard.

---

## 8. Opening encodings

Every serialized opening satisfies check 1, and check 3 for vectors: every opening encoder
validates (or encodes an already validated holder) and emits only canonical values. Check 2 is an
application check on top of a decoded opening; encoders and decoders do not apply it. Decoders
reject trailing or missing octets with `MALFORMED_ENCODING`.

### 8.1 `scalar` (Jubjub)

```
opening = I2OSP(m, 32) ‖ I2OSP(r, 32)          # 64 octets
```

Decoding order: length other than 64 → `MALFORMED_ENCODING`; `m ≥ l` → `NON_CANONICAL_SCALAR`;
`r ≥ l` → `NON_CANONICAL_SCALAR`.

### 8.2 `bytes`

```
blinding = I2OSP(r, 32)                         # 32 octets
```

The payload travels separately as its exact octets: no transcoding and no added length beyond the
carrier's own framing. Decoding order: length other than 32 → `MALFORMED_ENCODING`; `r ≥ l` →
`NON_CANONICAL_SCALAR`.

### 8.3 `vector`

```
opening = u8(n) ‖ I2OSP(v_0, 32) ‖ … ‖ I2OSP(v_{n−1}, 32) ‖ I2OSP(r, 32)   # 33 + 32·n octets
```

Decoding is under a configured bound policy (and its schema), in this order:

1. length `< 1`, `n` different from the schema dimension, or total length other than
   `33 + 32·n` → `MALFORMED_ENCODING`;
2. each `v_i ≥ l` in index order, then `r ≥ l` → `NON_CANONICAL_SCALAR`;
3. each `v_i` in index order outside the policy → `OUT_OF_RANGE`.

### 8.4 G1 profiles

`pedersen-bls12-381-g1-v1.md` §6: the layouts of §8.1 (scalar, 64 octets) and §8.2 (bytes,
32 octets) with `q` in place of `l`. Decoding order: wrong length → `MALFORMED_ENCODING`; then
`m ≥ q` (scalar only), then `r ≥ q` → `NON_CANONICAL_SCALAR`.

---

## 9. Envelope v1

An envelope is an off-chain container for one commitment. It is never used in datums, redeemers
or circuit public inputs, which carry the profile's raw form fixed by their validator or circuit.

```
envelope = 0x01                    # envelope format version
         ‖ u8(len(id)) ‖ ASCII(id) # the profile identifier
         ‖ point                   # the profile's raw point encoding, exactly
```

| Profile | Envelope length |
|---|---|
| `pedersen-jubjub-v1` | 52 octets |
| `pedersen-jubjub-vector-v1` | 59 octets |
| `pedersen-jubjub-bytes-v1` | 58 octets |
| `pedersen-bls12-381-g1-v1` | 74 octets |
| `pedersen-bls12-381-g1-bytes-v1` | 80 octets |

**Encoding** writes the commitment's own profile identifier and raw point. It trusts its input
(producer side).

**Decoding** takes the expected profile's codec from the caller's trusted configuration — for
vectors, a codec bound to the expected schema — and applies, in this order:

1. length `< 2`, or first octet not `0x01` → `MALFORMED_ENCODING`;
2. `2 + len(id)` greater than the length → `MALFORMED_ENCODING`;
3. identifier octets not identical to the expected profile's identifier → `PROFILE_MISMATCH`;
4. remaining length different from the expected point-encoding length → `MALFORMED_ENCODING`;
5. the expected profile's strict point decoder (§10) → `MALFORMED_ENCODING` or
   `NOT_IN_SUBGROUP`;
6. the decoded object's concrete class and descriptor are checked against the codec as in
   `CommitmentKey.of` (§12.1) → `PROFILE_MISMATCH`.

There is no decoder that selects a profile from the embedded identifier. The envelope prevents
accidental mix-ups and makes stored data self-describing; it is not authentication.

---

## 10. Point decoding

A profile's strict point decoder applies its encoding rules **before** the subgroup check:

1. a null input → `NullPointerException`;
2. a wrong length, a non-canonical encoding (including both `u = 0` sign aliases), an off-curve
   encoding, or any encoding its profile spec rejects (for Jubjub, `pedersen-jubjub-v1.md` §4
   rules 1–5, in that order) → `MALFORMED_ENCODING`;
3. a valid curve point outside the prime-order subgroup (small-order and mixed-order points) →
   `NOT_IN_SUBGROUP`.

It never cofactor-clears a received point. It applies the identity policy (Jubjub profiles accept
the identity). For Jubjub, the two `u = 0` sign aliases are the identity alias
`0100000000000000000000000000000000000000000000000000000000000080` and the order-2 point alias
`00000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7edf3`; both are
`MALFORMED_ENCODING` by rule 5, never `NOT_IN_SUBGROUP`.

For the BLS12-381 G1 profiles the decoder is `pedersen-bls12-381-g1-v1.md` §4: its steps 2–6 are
rule 2 here (`MALFORMED_ENCODING`) and its step 7 is rule 3 (`NOT_IN_SUBGROUP`). Exactly
`0xC0 ‖ 0^47` is the identity and is returned without coordinate recovery; every other encoding
with the infinity flag is `MALFORMED_ENCODING`. The finite encoding `0x80 ‖ 0^47` decodes to a
point of order 3 and is `NOT_IN_SUBGROUP`.

---

## 11. Error classes

| Class | Meaning | Java | On-chain |
|---|---|---|---|
| `MALFORMED_ENCODING` | a structural, length or curve-encoding defect | `CommitmentFormatException` | script fails |
| `NOT_IN_SUBGROUP` | a valid curve point outside the prime-order subgroup | `CommitmentFormatException` | script fails |
| `NON_CANONICAL_SCALAR` | check 1 failed | `CommitmentFormatException` | script fails |
| `OUT_OF_RANGE` | check 2 or check 3 failed | `CommitmentFormatException` | script fails |
| `LENGTH_OUT_OF_RANGE` | a `bytes` declared length or maximum outside `[0, MAX_PAYLOAD_BYTES]` | `CommitmentFormatException` | script fails |
| `PROFILE_MISMATCH` | a label, codec, class, descriptor or schema other than the expected one | `CommitmentFormatException` | script fails |
| `INVALID_CONFIGURATION` | an invalid identifier string, amount-bound width, bound policy, descriptor point-encoding length or duplicate descriptor | `CommitmentFormatException` | (configuration; not on-chain) |
| `OPENING_MISMATCH` | a well-formed opening that does not satisfy the commitment equation | verification returns `false` | script fails |
| `PROVENANCE_MISSING` | the application has no authenticated issuance record | `CommitmentCheck` only | script fails |
| `PROVENANCE_MISMATCH` | the record does not bind this point, profile and context | `CommitmentCheck` only | script fails |

`CommitmentFormatException` extends `IllegalArgumentException`, so callers catching
`IllegalArgumentException` keep working. It carries only the seven format classes above it in the
table (`MALFORMED_ENCODING` through `INVALID_CONFIGURATION`); constructing one with
`OPENING_MISMATCH` or a `PROVENANCE_*` class is itself an `IllegalArgumentException`. It retains
no secret value, and no message contains one.

A missing argument on a strict path (§12.3) is a `NullPointerException`. Stream failures stay
`IOException`, and an unavailable hash provider stays `IllegalStateException`
(`pedersen-jubjub-bytes-v1.md` §6).

Off-chain implementations MUST report the class this table assigns on every strict path. A
validator can only succeed or fail: every class it can encounter maps to script failure.

---

## 12. Java binding

### 12.1 `zeroj-api`, package `org.zeroj.api.commitment`

No dependencies. Value, key, profile and result types are final, not records, not
`Serializable`, and have no public or protected constructor beyond the factories listed.
`CommitmentCheck` has no public factory at all: only `CommitmentAcceptance` creates one, so no
caller can fabricate an accepted result. Enums
and `CommitmentFormatException` are inherently `Serializable` (Java's `Enum` and `Throwable`);
they hold no secret.

| Type | Contract |
|---|---|
| `CommitmentProfileId` | `static of(String)` validates §2.1 (`INVALID_CONFIGURATION` otherwise); `value()`; `toAsciiBytes()` returns a fresh copy; value equality |
| `CommitmentKind` (enum) | `SCALAR`, `BYTES`, `VECTOR` |
| `CommitmentGroup` (enum) | `JUBJUB`, `BLS12_381_G1` |
| `CommitmentProfile` | `static define(CommitmentProfileId id, CommitmentKind kind, CommitmentGroup group, int pointEncodingLength)` with `1 ≤ pointEncodingLength ≤ 255` (else `INVALID_CONFIGURATION`); accessors `id()`, `kind()`, `group()`, `pointEncodingLength()`. The registry is a static set in `CommitmentProfile`, so its scope is that class's defining class loader. The descriptors of the built-in profiles are created and registered while `CommitmentProfile` is initialised (ADR-0060 D8), so they exist before any caller can reach `define`. `define` rejects an identifier already defined through the same loaded class, built-in or not (`INVALID_CONFIGURATION`): the duplicate rule protects the built-ins rather than threatening them, and each profile has exactly one descriptor per loaded `zeroj-api`. These guarantees hold against callers of the public API; in-process reflection can bypass any Java access rule and is outside the threat model. No ZeroJ module calls `define` outside `zeroj-api` (the build's `verifyNoBuiltinProfileDefine` scans compiled non-test classes for a method or method-handle reference to `define`; string-based reflection is not detected). `define` is for profiles that are not built in, and tests use test-only identifiers that are unique per JVM. A profile that is not built in and defines its descriptor in a static initialiser can still be disabled, fail-closed, by an earlier `define` of its identifier; such a profile defines its descriptor before untrusted code runs, or is added to the built-ins. A profile module from a release before ADR-0060 M1 still calls `define` for its own built-in identifier and fails class initialization (`ExceptionInInitializerError`) against this `zeroj-api`; mixed versions are unsupported, and `zeroj-api`, `zeroj-circuit-lib` and `zeroj-bls12381` are upgraded together. **Identity equality**: checks compare descriptors with `==` |
| `CommitmentProfiles` | final constant holder, no public constructor or method: `PEDERSEN_JUBJUB_V1`, `PEDERSEN_JUBJUB_BYTES_V1`, `PEDERSEN_JUBJUB_VECTOR_V1`, `PEDERSEN_BLS12_381_G1_V1`, `PEDERSEN_BLS12_381_G1_BYTES_V1`, the built-in descriptors (point-encoding lengths 32, 32, 32, 48, 48). The profile modules' `PROFILE` constants are these instances. A constant for a `reserved` profile is not admission (§2.3) |
| `Commitment` (interface) | `CommitmentProfile profile()`; `byte[] toPointBytes()` (fresh copy of the raw encoding). No arithmetic and no equality contract |
| `CommitmentCodec<C extends Commitment>` (interface) | `profile()`; `Class<C> commitmentType()` (the exact concrete class); `C decodePoint(byte[])` (strict, §10; never returns null); `default byte[] keyContext()` (empty; the vector codec returns `I2OSP(σ, 32)`); `default void requireContext(C)` (no-op; the vector codec rejects a different schema with `PROFILE_MISMATCH`) |
| `CommitmentEnvelope` | `public static byte[] encode(Commitment)`; `public static <C extends Commitment> C decode(byte[] envelope, CommitmentCodec<C> expected)` (§9) |
| `CommitmentKey` | `public static CommitmentKey of(Commitment c, CommitmentCodec<?> expected)`: nulls; then `c.getClass() == expected.commitmentType()` **before** calling any method of `c` (else `PROFILE_MISMATCH`); then `c.profile() == expected.profile()` (else `PROFILE_MISMATCH`); then the codec's context check on `c` (implemented with a private generic capture helper that casts `c` with `expected.commitmentType().cast(c)` after the exact-class check, because `requireContext` cannot be called directly through `CommitmentCodec<?>`). Value equality over the identifier, the raw point and `keyContext()`. An in-memory value only: it has no serialized form |
| `CommitmentError` (enum) | the classes of §11 |
| `CommitmentFormatException` | final; `extends IllegalArgumentException`; `CommitmentFormatException(CommitmentError reason, String message)`; `CommitmentError reason()` (§11 restrictions) |
| `CommitmentCheck` | `boolean accepted()`; `Optional<CommitmentError> reason()` (empty iff accepted); `boolean policyRejected()` (true iff the reason is a `PROVENANCE_*` class) |
| `ProvenancePolicy<C>` (interface) | `Result check(C commitment)`, with nested enum `Result { OK, MISSING, MISMATCH }` |
| `OpeningCheck<C>` (interface) | `boolean matches(C commitment) throws IOException` |
| `CommitmentAcceptance` | `public static <C extends Commitment> CommitmentCheck accept(byte[] envelope, CommitmentCodec<C> expected, ProvenancePolicy<? super C> provenance, OpeningCheck<? super C> opening) throws IOException` |

**`CommitmentAcceptance.accept` accepts if and only if** envelope decoding (§9, including step 6)
returns a commitment, `provenance.check` returns exactly `OK`, and `opening.matches` returns
`true` — evaluated in that order. Otherwise it returns the first failure:

- a `CommitmentFormatException` from envelope decoding, or from the opening check with a reason
  other than `INVALID_CONFIGURATION` → its reason;
- `MISSING` → `PROVENANCE_MISSING`; `MISMATCH` → `PROVENANCE_MISMATCH`;
- `false` → `OPENING_MISMATCH`.

A null argument, or a null `Result` from the provenance callback, is a `NullPointerException`.
Every other throwable propagates unchanged: `IOException`, `IllegalStateException`, a plain
`IllegalArgumentException`, any other runtime exception, **any** exception thrown by the
provenance callback (including a `CommitmentFormatException`), and a `CommitmentFormatException`
with `INVALID_CONFIGURATION` from the opening check (a verifier misconfiguration, not a data
verdict). Implementations map exceptions per step, not with one handler around all three steps.
No path converts a failure or an exception into acceptance. `accept` does not return the decoded
commitment; decoding the same envelope again with the same codec is deterministic: it yields the
same profile, context and point octets and an equal `CommitmentKey`. (It need not yield an
`equals` instance: vector commitments keep reference equality.)

### 12.2 `zeroj-circuit-lib`, package `org.zeroj.circuit.lib.jubjub`

**Closure properties for every new type below:** final; not a record; not `Serializable`; no
public or protected constructor; commitments are created only by their decoders, generation
methods and same-type `add`/`subtract`/`negate`; opening holders defensively copy inputs and outputs, have a redacted `toString`, and do
not override `equals`/`hashCode`. Immutable `BigInteger` secrets cannot be wiped from memory; the
Javadoc says so.

| Type or member | Contract |
|---|---|
| `PedersenScalarCommitment` (new) | `pedersen-jubjub-v1` typed commitment. `PROFILE`, `CODEC`; `static decode(byte[])` (§10); `profile()`; `toPointBytes()`; `add`, `subtract`, `negate` on this type only; value equality over the encoding. `toString` shows the profile and point only |
| `PedersenScalarOpening` (new) | `static of(BigInteger value, BigInteger blinding)`; `static decode(byte[])` (§8.1); `encode()`; `value()`; `blinding()` |
| `PedersenCommitment.commitScalar(BigInteger value, BigInteger blinding)` (new) | V2 generation through the existing two blinded schedules; returns `PedersenScalarCommitment` |
| `PedersenCommitment.verifyScalar(PedersenScalarCommitment, BigInteger value, BigInteger blinding)` (new) | V1 disclosed verification (§6.2 timing rule); `false` on mismatch |
| `PedersenCommitment.verifyScalar(PedersenScalarCommitment, BigInteger, BigInteger, int amountBits)` (new) | as above with check 2 |
| `PedersenBlinding` (new) | `static byte[] encode(BigInteger r)` and `static BigInteger decode(byte[])` (§8.2) |
| `PedersenBytesCommitment` | implements `Commitment`; gains `PROFILE`, `CODEC`, `profile()`. `PROFILE_ID` and `profileId()` stay; `PROFILE_ID` is still not part of this type's own encoding (`toPointBytes()`), but the envelope (§9) carries it |
| `PedersenVectorCommitment` | implements `Commitment`; gains `PROFILE`, `static codec(PedersenVectorSchema)`, `profile()`, `toPointBytes()` (same octets as the existing `toBytes()`), and `verifyOpening(List<BigInteger> values, BigInteger blinding, PedersenVectorBoundPolicy policy)`. Its legacy equality (reference identity) is unchanged |
| `PedersenVectorBoundPolicy` (new) | `static schemaWidths(PedersenVectorSchema)`, `static residueOnly(PedersenVectorSchema)`, `static widened(PedersenVectorSchema, int addedTerms)` (`2 ≤ addedTerms ≤ 65536`); `schema()` |
| `PedersenVectorOpening` (new) | `static of(PedersenVectorBoundPolicy, List<BigInteger> values, BigInteger blinding)`; `static decode(byte[], PedersenVectorBoundPolicy)` (§8.3); `encode()`; `values()` (an unmodifiable snapshot taken at construction); `blinding()`; `policy()` |

**The exact public surface added** (the reviewed set for API-surface tests):

- `PedersenCommitment`: methods `commitScalar[BigInteger, BigInteger]`,
  `verifyScalar[PedersenScalarCommitment, BigInteger, BigInteger]`,
  `verifyScalar[PedersenScalarCommitment, BigInteger, BigInteger, int]`.
- `PedersenBytesCommitment`: method `profile`; fields `PROFILE`, `CODEC`.
- `PedersenVectorCommitment`: methods `profile`, `toPointBytes`, `codec`, `verifyOpening`; field
  `PROFILE`.
- New types as listed. Existing assertions of `PedersenBytesApiSurfaceTest` (final, not a record,
  not `Serializable`, no public constructor, no `BigInteger` field, package-private internals) are
  kept; only its method-name and public-field allowlists grow by the items above.

### 12.3 Strict paths and check order

On these paths the error classes of §11 are mandatory, argument checks precede any curve
operation on the inputs, digest acquisition or stream read (a point decoder's own validation is
itself curve arithmetic on public data), and no input is reduced:

| Path | Order |
|---|---|
| `commitScalar` | nulls → `value` check 1 → `blinding` check 1 → generate |
| `verifyScalar` (3 args) | nulls → `value` check 1 → `blinding` check 1 → equation (`false` on mismatch) |
| `verifyScalar` (4 args) | nulls → `amountBits` in `[1, 251]` (`INVALID_CONFIGURATION`) → `value` check 1 → `blinding` check 1 → check 2 (`OUT_OF_RANGE`) → equation |
| `PedersenScalarOpening.of` / `decode` | nulls / §8.1 → `value` check 1 → `blinding` check 1 |
| `PedersenBlinding.encode` / `decode` | nulls → `r` check 1 / §8.2 |
| `PedersenVectorCommitment.codec` | nulls |
| `verifyOpening` (vector) | nulls → bounded snapshot of the list (below) → policy schema equals commitment schema (`PROFILE_MISMATCH`) → dimension (`MALFORMED_ENCODING`) → each `v_i` check 1 in index order → `blinding` check 1 → each `v_i` check 3 in index order → equation |
| `PedersenVectorOpening.of` / `decode` | as `verifyOpening` without the schema comparison / §8.3 |
| `PedersenVectorBoundPolicy` factories | nulls → `widened`: `2 ≤ addedTerms ≤ 65536` and every `2^{k_i + ⌈log₂ n⌉} ≤ q` (`INVALID_CONFIGURATION`) |
| `commitBytes*`, `verifyBytes*` (six methods) | `pedersen-jubjub-bytes-v1.md` §6 order: nulls → `blinding` check 1 (`NON_CANONICAL_SCALAR`) → declared length or maximum (`LENGTH_OUT_OF_RANGE`) → read and hash |
| Point decoders: `CODEC.decodePoint`, `codec(schema).decodePoint`, `PedersenScalarCommitment.decode`, `PedersenBytesCommitment.decode`, `PedersenVectorCommitment.decode`, `PedersenCommitment.decode` | §10 (the legacy `PedersenCommitment.decode` and `PedersenVectorCommitment.decode(schema, null)` keep throwing `IllegalArgumentException` for a null array, as today) |
| `CommitmentEnvelope.encode` / `decode`, `CommitmentKey.of`, `CommitmentProfileId.of`, `CommitmentProfile.define` | nulls → §9 / §12.1 |

**Bounded snapshot.** The strict vector list paths (`verifyOpening`, `PedersenVectorOpening.of`)
copy the caller's list once, reading its elements in index order and stopping after the 17th
(`MAX_DIMENSION + 1`); each element read MUST be non-null (else `NullPointerException`) and is
copied to a plain `BigInteger`, and every later check and the equation use only the copy. Work and
memory are therefore bounded by 17 elements whatever the list's size. A list of more than 17
elements yields a 17-element copy, which no schema dimension (`1..16`) matches, so it fails the
dimension check (`MALFORMED_ENCODING`), after the policy-schema comparison on `verifyOpening`
(`PROFILE_MISMATCH` takes precedence, as for any other list). Consequently a null element at index
17 or later is never read: such a list is rejected by the schema or dimension check instead of
with `NullPointerException`. Every list of at most 17 elements is checked exactly as before.

The strict vector `verifyOpening` computes `Σ [v_i]·G_i + [r]·H_V` itself after its checks, using
the disclosed (variable-time) path; it MUST NOT delegate to the legacy `verify`, whose width
check would reject valid `residue-only` and `widened` openings (this refines ADR-0059 D5's
"validate first, then delegate" for the vector path). The scalar paths delegate to the existing
generation (two blinded schedules) and disclosed-verification code after their checks.

**BLS12-381 G1.** The G1 Java binding (`zeroj-bls12381`, package `org.zeroj.bls12381.pedersen`)
and its strict paths are [`pedersen-bls12-381-g1-v1.md`](pedersen-bls12-381-g1-v1.md) §8, which
governs them. They follow the rows above with `q` for `l`, `amountBits` in `[1, 254]` and
`deltaBits` in `[1, 253]` (§7: a bounded delta must be unique mod `q`), plus two steps of their own (the scalar snapshot of `BigInteger` arguments, and the
provider capability check on generation), the same
closure properties as §12.2, and the same rule that argument checks precede curve work, digest
acquisition and stream reads.

Legacy methods not listed here keep their behaviour, including their exception types; where one
already threw `IllegalArgumentException` for malformed input it MAY throw the subclass with the
§11 class. Nothing outside the Pedersen types of this package (for example `JubjubPoint` or the
ElGamal types) changes.

---

## 13. Cross-language vectors (`zeroj-commitment-vectors-v1`)

One JSON file per profile at
`zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/<profileId>.json`.

### 13.1 File

```json
{
  "schema": "zeroj-commitment-vectors-v1",
  "profileId": "pedersen-jubjub-v1",
  "spec": [ { "path": "docs/specs/commitment-profiles-v1.md", "revision": "r3", "date": "2026-10-17", "sha256": "..." } ],
  "generator": { "script": "...", "scriptSha256": "...", "python": "..." },
  "positive": [ ],
  "negative": [ ]
}
```

`spec` lists every specification the generator implemented, each with its revision (where the
document has one), date and SHA-256. These are provenance only: a later metadata-only revision of
a specification changes its hash without invalidating the vectors, and loaders need not check
them.

### 13.2 Value conventions

- All JSON values are strings, arrays or objects; there are no JSON numbers.
- Integers are signed decimal strings (`"-1"` is valid). Negative or out-of-range integers occur
  only in logical-input fields; a `…Hex` field always holds a valid octet string.
- Octet strings are lowercase hex, in fields whose name ends in `Hex`.
- A **payload** is `{"hex": "…"}` or `{"pattern": "131i+17", "length": "65536"}`, where octet
  `i` of the pattern is `(131·i + 17) mod 256`; no other pattern is defined.
- A **schema** is `{"id": "…", "version": "1", "entries": [{"label": "amount", "width": "64"}, …]}`
  (`pedersen-jubjub-vector-v1.md` §4).
- A **policy** is `{"kind": "schema-widths" | "residue-only" | "widened", "addedTerms": "2"}`;
  `addedTerms` appears only for `widened`. A policy always applies to the case's `schema`, or to
  `policySchema` when present.
- **Domains.** Every schema in a file is valid (`pedersen-jubjub-vector-v1.md` §4); schema
  construction failures are not file cases. `version`, `width`, `amountBits`, `deltaBits` and
  `addedTerms` are within the signed 32-bit range, and `declaredLength` and `maxBytes` within the signed
  64-bit range (a value outside these ranges is an invalid fixture); a value outside the domain that §7 or §12 assigns is a
  negative case with that class (for example `addedTerms` `"65537"` → `INVALID_CONFIGURATION`),
  never a value a consumer must parse beyond the field's stated 32- or 64-bit range. `delta` is a
  signed decimal integer of arbitrary size. `expectedProfileId` is a valid identifier
  (§2.1). `relation` has exactly two points `P₀ = pointsHex[0]`, `P₁ = pointsHex[1]` for `add`
  (`P₀ + P₁`) and `subtract` (`P₀ − P₁`), and one point `P₀` for `negate` (`−P₀`); any other cardinality is an invalid fixture, not a case, and a consumer
  rejects the file.

### 13.3 Cases

A positive case is `{"name", "operation", "input", "expected"}`. A negative case is
`{"name", "operation", "input", "error"}` with an `error` from §11. `OPENING_MISMATCH` cases are
negative cases of `verifyOpening`.

| Operation | Kinds | `input` | `expected` |
|---|---|---|---|
| `decodePoint` | all | `pointHex` (+ `schema` for vector) | Jubjub: `uHex`, `vHex` (32-octet big-endian affine coordinates). G1: `xHex`, `yHex` (48-octet big-endian affine coordinates), or `{"identity": "true"}` for the identity, which has no affine coordinates |
| `commit` | scalar | `value`, `blinding` (strict `commitScalar`) | `pointHex` |
| `commitLegacy` | Jubjub scalar | `value`, `blinding` (legacy `commit`, any integers) | `pointHex` |
| `commit` | bytes | `payload`, `blinding`; optional `declaredLength` (declared-length stream form) or `maxBytes` (`ToEnd` form) | `pointHex` |
| `commit` | vector | `schema`, `values` (array), `blinding` (legacy `commit`, canonical inputs only) | `pointHex` |
| `hashToScalar` | bytes | `payload` | `b0Hex`, `b1Hex`, `b2Hex`, `uniformBytesHex`, `scalar` |
| `verifyOpening` | scalar | `pointHex`, `value`, `blinding`; optional `amountBits` | `{"result": "true"}` |
| `verifyOpening` | bytes | `pointHex`, `payload`, `blinding` | `{"result": "true"}` |
| `verifyOpening` | vector | `pointHex`, `schema`, `policy`, `values`, `blinding`; optional `policySchema` (a different schema for the policy) | `{"result": "true"}` |
| `encodeOpening` | all | scalar `value`, `blinding`; bytes `blinding`; vector `schema`, `policy`, `values`, `blinding` | `openingHex` |
| `decodeOpening` | all | `openingHex` (+ `schema`, `policy` for vector) | the `encodeOpening` input fields |
| `encodeEnvelope` | all | `pointHex` (+ `schema` for vector, to build the typed commitment; the schema is not written to the envelope) | `envelopeHex` |
| `decodeEnvelope` | all | `envelopeHex`, `expectedProfileId` (+ `schema` for vector) | `pointHex` |
| `relation` | scalar, vector | `op` (`add`, `subtract`; `negate` for scalar only), `pointsHex` (array; one for `negate`) (+ `schema`) | `pointHex` |
| `configurePolicy` | vector | `schema`, `policy` | `{"result": "ok"}` |
| `publicDelta` | G1 scalar | `pointHex`, `delta` (signed), `deltaBits` | `pointHex` (`C + [δ]·G`, `pedersen-bls12-381-g1-v1.md` §6.4) |

**Execution order.** A consumer executes each case in this order, and the expected `error` of a
case with several defects is the first failure:

1. configuration: `schema`, then `policySchema` when present, then `policy` (`configurePolicy`,
   the vector `verifyOpening`, `encodeOpening` and `decodeOpening`), then `amountBits` or
   `deltaBits` is read (it is validated in step 3), then the codec;
2. points: `pointHex`, then `pointsHex` in index order, under §10 (or `envelopeHex` under §9);
3. the operation's own order (§8 for opening decoding, §12.3 and `pedersen-bls12-381-g1-v1.md`
   §8 for the strict methods, including `amountBits` before the scalars in `verifyOpening` and
   `deltaBits` before `delta` in `publicDelta`);
4. the equation or arithmetic.

Each file contains at least two multi-defect cases that pin this order, for example a bad
`pointHex` with a non-canonical `value` (→ the point's class) and, for `relation`, a canonical
order-2 point followed by an empty encoding (→ `NOT_IN_SUBGROUP`).

**Streams.** Stream I/O failures (a payload shorter than `declaredLength`, or longer than
`declaredLength` or `maxBytes`) yield `IOException`, which has no error class; they are covered by
the Java tests of `pedersen-jubjub-bytes-v1`, not by these files. In a file, `declaredLength`
equals the payload length and `maxBytes` is at least the payload length, except in
`LENGTH_OUT_OF_RANGE` cases, where the value is outside `[0, MAX_PAYLOAD_BYTES]` and the payload is
empty.

### 13.3.1 Example records

The identity encoding opens to all-zero values with a zero blinding under every Jubjub profile's
bases, so these records are complete and exact:

```json
{
  "name": "vector-verify-identity-zero",
  "operation": "verifyOpening",
  "input": {
    "pointHex": "0100000000000000000000000000000000000000000000000000000000000000",
    "schema": { "id": "zeroj.example.balance", "version": "1",
                "entries": [ { "label": "amount", "width": "64" }, { "label": "asset", "width": "32" } ] },
    "policy": { "kind": "schema-widths" },
    "values": [ "0", "0" ],
    "blinding": "0"
  },
  "expected": { "result": "true" }
}
```

```json
{
  "name": "vector-verify-policy-schema-mismatch",
  "operation": "verifyOpening",
  "input": {
    "pointHex": "0100000000000000000000000000000000000000000000000000000000000000",
    "schema": { "id": "zeroj.example.balance", "version": "1",
                "entries": [ { "label": "amount", "width": "64" }, { "label": "asset", "width": "32" } ] },
    "policySchema": { "id": "zeroj.example.balance", "version": "2",
                      "entries": [ { "label": "amount", "width": "64" }, { "label": "asset", "width": "32" } ] },
    "policy": { "kind": "schema-widths" },
    "values": [ "0", "0" ],
    "blinding": "0"
  },
  "error": "PROFILE_MISMATCH"
}
```

### 13.4 Minimum sets

Every file contains at least:

- **Positive:** `decodePoint` of the identity and of a commitment; `commit` and `verifyOpening`
  with scalars at `0` and `q − 1` (for vector, `q − 1` components under `residue-only`, since
  `commit` is the legacy width-checked method — such points are built with `relation`); `encodeOpening`/`decodeOpening` round trips;
  `encodeEnvelope`/`decodeEnvelope` round trips.
- **Point negatives** (`decodePoint`, and `decodeEnvelope` for the subgroup cases): lengths 0, 31
  and 33; `v ≥ p`; both `u = 0` sign aliases (§10); off-curve; points of order 2, 4 and 8; a
  mixed-order point (a subgroup point plus an order-8 point).
- **Scalar negatives** (`NON_CANONICAL_SCALAR`): `r` at `q`, `q + 1` and `−1`; for scalar and
  vector, the same for `value` and each `v_i`. They apply to the strict operations only: scalar
  `commit`, `verifyOpening` and `encodeOpening`; bytes `commit`, `verifyOpening` and
  `encodeOpening`; vector `verifyOpening` and `encodeOpening`; and, for `q` and `q + 1` (which are
  encodable), `decodeOpening`. Never to vector `commit` or `commitLegacy`, which are legacy.
- **Envelope negatives:** version `0x00` and `0x02`; truncated; a trailing octet; the identifier
  of another registered profile; an identifier differing in one octet; a point-length mismatch.
- **Opening negatives:** a wrong message (`OPENING_MISMATCH`); a wrong length for
  `decodeOpening`.

Per kind, additionally:

- **scalar:** `verifyOpening` with `amountBits` `k` and value `2^k − 1` (positive) and `2^k`
  (`OUT_OF_RANGE`); `amountBits` `0` and `⌊log₂ q⌋ + 1` (`INVALID_CONFIGURATION`: `252` for
  Jubjub, `255` for G1). Jubjub only: `commitLegacy` showing `value = q` equals `value = 0` (G1
  has no legacy reducing method).
- **bytes:** `hashToScalar` for the empty payload and at least one pattern payload; `commit` with
  `declaredLength` `"-1"` and `MAX_PAYLOAD_BYTES + 1` (`LENGTH_OUT_OF_RANGE`).
- **G1 (both profiles):** the point negatives above are replaced by lengths 0, 47 and 49; the
  compression flag clear; infinity with the sort flag; infinity with a nonzero coordinate bit;
  `x ≥ P_381`; an `x` with `x³ + 4` not a square (all `MALFORMED_ENCODING`); `0x80 ‖ 0^47` (order
  3), another curve point outside the subgroup, and a mixed-order point (a subgroup point plus the
  order-3 point) (`NOT_IN_SUBGROUP`); the identity `0xC0 ‖ 0^47` is a positive. Envelope
  negatives include a Jubjub identifier under a G1 codec and the other G1 profile's identifier
  (`PROFILE_MISMATCH`).
- **G1 scalar:** `verifyOpening` with `amountBits` `254` accepted; `publicDelta` with `deltaBits`
  `k ≤ 253` and `δ = ±(2^k − 1)` (positive), `±2^k` (`OUT_OF_RANGE`), and `deltaBits` `0`, `254`
  and `255` (`INVALID_CONFIGURATION`; at 254 a delta and its alias `δ − q` would both pass).
- **G1 bytes:** `hashToScalar` for the empty payload, a pattern payload and one longer than a
  SHA-256 block.
- **vector:** a dimension mismatch (`MALFORMED_ENCODING`); a component of `2^{k_i}` under
  `schema-widths` (`OUT_OF_RANGE`) that is accepted under `residue-only` and under `widened`; a
  difference opened under `residue-only`; `policySchema` different from `schema`
  (`PROFILE_MISMATCH`); `configurePolicy` with `widened` reaching `q` and with `addedTerms` `1`
  (`INVALID_CONFIGURATION`); `configurePolicy` with `addedTerms` `65536` accepted for a narrow
  width and `65537` rejected (`INVALID_CONFIGURATION`); a `decodeEnvelope` under a codec bound to
  another schema decodes (the envelope carries no schema) — schema enforcement is
  `requireContext` and `verifyOpening`, not the envelope.

Expected values come from an implementation independent of the code under test, with the
generator provenance recorded in the header. JuLC tests (ADR-0060 M4, G1 profiles only) use the
operations a validator performs (`decodePoint`, `verifyOpening`, `relation`, `publicDelta`, and
`hashToScalar` through the on-chain byte mapping) and assert script failure for each such negative
case and success for each such positive case; envelope, opening-codec and configuration cases are
off-chain only.

---

## 14. Verification matrix

"Native" means ledger builtins directly; "in a proof" means a Groth16/PlonK verifier with the
commitment as public inputs. "M1" marks typed adapters added by ADR-0059 M1. Every cell leaves
authorization, replay protection and context binding to the application.

| Profile | Class | Java off-chain | Cardano L1 (JuLC) | Public after the check |
|---|---|---|---|---|
| `pedersen-jubjub-v1` | V1 | existing `verify`; `verifyScalar` (M1) | not native (no Jubjub builtins); possible only as a proof statement | message and `r` |
| | V3 | existing raw-point arithmetic; typed `add`/`subtract`/`negate` (M1); ADR-0051 D3a for integer readings | in a proof only (reference validators are test sources) | deltas |
| | V4 | Groth16/PlonK with `ZkPedersen` | `Groth16BLS12381Lib.verify` with affine `(u, v)` public inputs | the public inputs |
| `pedersen-jubjub-vector-v1` | V1 | existing `verify`; strict `verifyOpening` (M1) | not native | values and `r` |
| | V3 | existing `add`/`subtract` (same schema) | in a proof only | deltas |
| | V4 | Groth16/PlonK with `ZkPedersenVector` | `Groth16BLS12381Lib.verify` with `σ` as a public input and an issuance record | the public inputs, including `σ` |
| `pedersen-jubjub-bytes-v1` | V1 | existing `verifyBytes*`, streaming to `2^61 − 256` octets | not native; not provided in a proof | payload and `r` |
| | V3, V4 | not offered | not offered | — |
| `pedersen-bls12-381-g1-v1` | V1 | implemented (experimental): `G1Pedersen.verifyScalar` (ADR-0060 M2) | implemented (experimental): `PedersenG1Lib.verifyScalarOpening`/`verifyScalarOpeningBounded`: length check, `uncompress`, canonical round trip, check 1 on `m` and `r` and check 2 if requested, then two `scalarMul` (cheaper than a two-term MSM, measured), `add`, `equal` | message and `r` |
| | V3 | implemented (experimental): `withPublicDelta`, `add`/`subtract`/`negate` | implemented (experimental): `applyPublicDelta` with the signed-delta rule, `add`/`subtract`/`negate`; sums with verifier-fixed coefficients | deltas |
| | V4 | blocked (ADR-0051 D7; #96) | blocked / feasibility (#96) | — |
| `pedersen-bls12-381-g1-bytes-v1` | V1 | implemented (experimental): `G1Pedersen.verifyBytes*`, streaming to `2^61 − 256` octets | implemented (experimental): `PedersenG1Lib.verifyBytesOpening` recomputes the mapping with `sha2_256`; the payload is bounded by the transaction size, not the budget: about 14 KB in a redeemer with the script inline, 15 KB with a reference script, in a minimal transaction ([measurements](../benchmarks/pedersen-g1-2026-10-22.md)). No scalar-only mode: checking a supplied `(s, r)` is a `pedersen-bls12-381-g1-v1` opening and authenticates only `s` (§4.4) | payload and `r` |

Disclosed openings on-chain are public forever. Relations prove residues, not balances: integer
conservation needs a range proof per term or a circuit. Documents larger than the on-chain limit
can only be committed and opened off-chain; on-chain references them by commitment.

---

## 15. Benchmark methodology

Benchmarks are records, not assertions, and never remove a check to improve a number.

- **Java:** a standalone harness (not a Gradle test run for timing claims); warm-up and measured
  iterations over several forks; p50 and p95; allocation per operation (`ThreadMXBean`); one and
  eight threads; JVM and GraalVM native image; aarch64 and x86-64, recording any platform that is
  unavailable. Operations: commit, decode, V1 verify, V3 relation, envelope round trip, and the
  bytes mapping at 0 B, 1 KiB, 1 MiB and 16 MiB.
- **Cardano:** CPU steps and memory per operation under a named cost model (Julc VM), then
  confirmed on Yaci DevKit; script size in octets; the fee
  `txFeePerByte × txSize + txFeeFixed + ⌈priceMemory × mem + priceSteps × steps⌉` plus the
  reference-script fee, with the epoch whose parameters were used; each figure as a fraction of
  `maxTxExecutionUnits`. Operations: G1 V1 scalar opening, V3 delta update, an `n`-term sum, and
  the bytes opening at payload sizes up to the largest that fits.
- **Proofs (#96):** proof size in octets, prover and verifier time, verifier memory.

---

## 16. Revision history

- **r1 (2026-10-17):** initial registry and contract (ADR-0059 M0).
- **r2 (2026-10-17):** responds to the M0 Claude and Codex reviews: complete check order and
  error classes for every strict path (§12.3), `INVALID_CONFIGURATION`, policy/schema equality,
  strict vector verification no longer delegated to the legacy verifier, closure properties of
  every new type, the "if and only if" acceptance rule, duplicate-free descriptors, reserved
  specification identifiers, a precise vector-file format with minimum sets, the disclosure
  column and consequences in the matrix, point-decoder precedence and the sign aliases, the
  benchmark methodology, and corrected cross-references.
- **r3 (2026-10-17):** responds to the second M0 review round: reserved registry entries are
  admissible under their named issue, and every published document name is reserved; opening
  encoders (`PedersenBlinding.encode`) and `codec(schema)` are strict paths; vector-file
  execution order with multi-defect cases, stream cases constrained, strict-operation scope of the
  scalar negatives, `maxBytes`, scalar-only `negate`; `widened` limited to `2 ≤ n ≤ 65536`;
  derived vector V2 by recomputing terms; descriptor-length and duplicate-descriptor behaviour;
  per-step acceptance exception mapping (provenance exceptions and `INVALID_CONFIGURATION`
  propagate), empty reason on acceptance; the `CommitmentKey` capture helper; list snapshot;
  provenance-only spec hashes with a revision label; the G1 bytes limit and off-chain consequence.
  Round-3 follow-ups: fixture integer domains, `INVALID_CONFIGURATION` meaning, complete example
  records, `policySchema` order, the 65536 limit noted as a refinement, and `CommitmentCheck`
  having no public factory; vector `encodeEnvelope` carries `schema`; `relation` operand
  cardinality; repeated-decoding wording; explicit `add`/`subtract` equations; signed 64-bit
  domain for `declaredLength` and `maxBytes`.
- **r4 (2026-10-17, metadata and a contract clarification; ADR-0059 M3):** §4.5 evidence now
  names the §13 vector files of M2; §12.2 clarifies that `PedersenVectorOpening.values()` returns
  an unmodifiable snapshot taken at construction rather than a per-call copy (callers still cannot
  modify the opening, so the guarantee is unchanged). No identifier, byte, check, check
  order or error class changes, so the r3 vectors stay valid (§13.1). Recorded follow-up for a
  later revision: §12.1 maps a codec's `INVALID_CONFIGURATION` during envelope decoding to a
  rejected verdict, while the opening step propagates it; aligning the two would change
  behaviour and needs its own review.
- **r5 (2026-10-20, responds to the Codex implementation review of `455da47`, finding F6):**
  §12.3 bounds the vector list snapshot to 17 elements, so an oversized list (for example a
  constant-size `Collections.nCopies` view of 20 million elements) is rejected with bounded work
  and memory instead of being copied in full first. Precedence change, for lists longer than 17
  elements only: a null element at index 17 or later is no longer read, so the list is rejected
  by the policy-schema (`PROFILE_MISMATCH`) or dimension (`MALFORMED_ENCODING`) check rather than
  with `NullPointerException`. No identifier, byte, scalar check or error class changes. The r3
  vectors stay valid: their value lists have at most 16 elements and the §13.2 format has no null
  elements, so no case's outcome changes; only their provenance hash differs (§13.1).
- **r6 (2026-10-22, ADR-0060 M0):** fixes the parameters of the BLS12-381 G1 entries by reference
  to the new [`pedersen-bls12-381-g1-v1.md`](pedersen-bls12-381-g1-v1.md): a new basis set
  `pedersen-bls12-381-g1-basis-v1` (§2.3, §3.3) and the core records of
  `pedersen-bls12-381-g1-v1` and `pedersen-bls12-381-g1-bytes-v1` (§4.6, §4.7), all three
  `reserved` until ADR-0060 M5 admits them. Also: §1 notation for the G1 `q`; §4.4 records that G1
  has no scalar-only bytes mode; §4.5 lifecycle rows; §7 the G1 check-2 bound `k ≤ 254`; §8.4 the
  G1 opening encodings; §9 the G1 envelope lengths 74 and 80; §10 the G1 decoder and its identity
  branch; §12.1 built-in descriptors owned by `zeroj-api` (`CommitmentProfiles`, ADR-0060 D8,
  issue #99), with the duplicate rule now protecting them and the coordinated-upgrade requirement;
  §12.3 the G1 binding; §13 G1 point fields, the `publicDelta` operation and G1 minimum sets; §14
  cells still planned. No Jubjub identifier, byte, check, check order or error class changes, so
  the Jubjub vectors stay valid. Before publication, the M0 review round scoped `commitLegacy` and
  the `amountBits` `252` rejection to Jubjub (G1 rejects `255`), added `deltaBits` and `delta` to
  the §13.2 domains and the execution order, added `publicDelta` and `hashToScalar` to the JuLC
  operations, removed the scalar alternative from the G1 bytes row of §14, and stated in §12.1 what
  the build check covers, that the guarantees are against public-API callers, and how a profile
  that is not built in can still be disabled.
- **r7 (2026-10-22, ADR-0060 M5):** admits `pedersen-bls12-381-g1-basis-v1`,
  `pedersen-bls12-381-g1-v1` and `pedersen-bls12-381-g1-bytes-v1` as `active` (experimental), after
  ADR-0060 M5 checked every prerequisite (§2.3), effective when ADR-0060's PR (#103) merges, which
  records the maintainer's acceptance of the delta-width amendment; records their evidence and
  implementations (§4.5)
  and the implemented V1/V3 cells, the measured on-chain payload bound and the choice of two
  `scalarMul` over a two-term MSM (§14). The public-delta rule now requires `2^{k_δ+1} − 1 ≤ q`, so a
  bounded delta is unique mod `q` (§7, public deltas; for G1 `k_δ ≤ 253`,
  `pedersen-bls12-381-g1-v1.md` r2), and the G1 minimum set adds `deltaBits` `254` as
  `INVALID_CONFIGURATION` (§13.4). No Jubjub identifier, byte, check, check order or error class
  changes.

---

## 17. References

- [ADR-0059](../adr/0059-commitment-profiles-and-verification-strategy.md);
  [ADR-0060](../adr/0060-pedersen-bls12-381-g1-profiles.md); ADR-0051 (D3a, D5, D7, I11);
  ADR-0058; ADR-0045; ADR-0006.
- [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md), [`pedersen-jubjub-vector-v1.md`](pedersen-jubjub-vector-v1.md),
  [`pedersen-jubjub-bytes-v1.md`](pedersen-jubjub-bytes-v1.md),
  [`pedersen-bls12-381-g1-v1.md`](pedersen-bls12-381-g1-v1.md).
- RFC 9380, *Hashing to Elliptic Curves* (August 2023).
- [CIP-0381](https://github.com/cardano-foundation/CIPs/blob/86b89208d3b2aabb5dcc5b778dfbe09096b4e114/CIP-0381/README.md)
  and [CIP-0133](https://github.com/cardano-foundation/CIPs/blob/86b89208d3b2aabb5dcc5b778dfbe09096b4e114/CIP-0133/README.md)
  at `86b89208d3b2aabb5dcc5b778dfbe09096b4e114`.
- ZIP 216, *Require Canonical Jubjub Point Encodings*.
