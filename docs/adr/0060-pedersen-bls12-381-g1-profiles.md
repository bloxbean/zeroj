# ADR-0060: BLS12-381 G1 Pedersen profiles and direct Cardano verification

## Status

**Accepted (design), 2026-10-22, by maintainer Satya.** Q1–Q6 are decided as leaned (option (a)
in each; see "Design questions for the maintainer"). Implementation proceeds under the milestones
below, with a maintainer sign-off after M0. Codex approved r2 (`d1c31ca`) as design review on
2026-10-22 with no finding open. M0 received Codex SPEC READY at `2b7e9c5` and the maintainer's
sign-off on 2026-10-22, which opened M2.

**Implemented (M0–M5), experimental.** M2–M5 are implemented on PR #103; registry r7 admits
`pedersen-bls12-381-g1-basis-v1`, `pedersen-bls12-381-g1-v1` and `pedersen-bls12-381-g1-bytes-v1`
as `active` after the M5 admission check, effective when PR #103 merges. One design amendment
was made during implementation (the public-delta width is at most 253, r5), under the maintainer's
standing instruction to finish without waiting; it awaits the maintainer's explicit acceptance on
the PR. See "Implementation evidence". Admission is not a
maturity or security claim: everything stays experimental until external review. Acceptance is design acceptance only: it certifies no
implementation, test or security property, and no AI verdict upgrades a maturity or security claim
(AGENTS.md).

Addresses [issue #95](https://github.com/bloxbean/zeroj/issues/95), phase 3 of the #93–#96
Pedersen roadmap, and folds in [issue #99](https://github.com/bloxbean/zeroj/issues/99) (built-in
profile identifiers can be pre-empted through `CommitmentProfile.define`). It specifies the two
identifiers ADR-0059 reserved, `pedersen-bls12-381-g1-v1` and `pedersen-bls12-381-g1-bytes-v1`, and
admits them at M5 once the evidence exists (D1 lifecycle).

**Risk: R3** for the basis set (D2), the byte-to-scalar mapping (D4) and secret handling in
generation (D6); **R2** for point and opening encodings, validation, the Java API, the registry
change (D8), vectors and the on-chain library (D9).

## Date

2026-10-21 (r1); 2026-10-21 (r2: review round 1); 2026-10-22 (r3: accepted, Q1–Q6 decided);
2026-10-22 (r4: wording); 2026-10-23 (r5: implementation, delta-width amendment, evidence)

## Context

ADR-0059 defined the commitment-profile registry, the shared Java contracts in
`org.zeroj.api.commitment`, the scalar checks, the envelope, the vector format and a verification
matrix. It reserved two G1 identifiers and left their parameters to #95:

- "Reservation fixes only the names; #95's ADR and spec define the basis set, the byte mapping
  and the encodings, and admit the entries." (ADR-0059 D1)
- The registry spec (`commitment-profiles-v1` r5) leaves to #95: the G1 opening encodings (§8.4),
  the identity policy and what `bls12_381_G1_uncompress` does with the infinity encoding (ADR-0059
  D1), whether the bytes profile offers a scalar-only mode (§4.4), evidence vectors for builtin
  behaviour (§7), the on-chain payload limit (§14) and the G1 benchmarks (§15).

Its §14 matrix lists the G1 cells this ADR must make real:

| Profile | Class | Java | Cardano L1 (planned) |
|---|---|---|---|
| `pedersen-bls12-381-g1-v1` | V1 disclosed opening | planned (#95) | check 1 on `m` and `r`, check 2 if requested, then `uncompress`, two `scalarMul` or one non-empty MSM, `add`, `equal` |
| `pedersen-bls12-381-g1-v1` | V3 public relation | planned (#95) | `C_new = C_old + [δ]·G` with the signed-delta rule; sums with verifier-fixed coefficients |
| `pedersen-bls12-381-g1-v1` | V4 proof | blocked (ADR-0051 D7; #96) | blocked |
| `pedersen-bls12-381-g1-bytes-v1` | V1 | planned (#95) | native only if the validator recomputes the mapping with `sha2_256`; limited by the budget and the carrying redeemer or datum |

Jubjub has no Plutus builtins, so Jubjub commitments reach the chain only through Groth16
proofs. BLS12-381 G1 has native builtins (CIP-0381, and CIP-0133 MSM since protocol version 11),
so a G1 commitment can be opened and combined by a validator directly. That is the reason for
this profile.

### Facts this design depends on

All paths are at `d2dcc23` (the merge of ADR-0059).

**Off-chain primitives (`zeroj-bls12381`, `zeroj-blst`).**

- `Bls12381Codecs.g1FromCompressed` decodes the 48-octet Zcash compressed form in this order:
  length 48; compression flag set; if the infinity flag is set, the sort flag clear and every
  other bit zero (so only `0xC0 ‖ 0^47` is infinity); `x < p`; `x³ + 4` a square; `y` chosen by
  the sort flag; then `requireValid` (on curve, `[r]P = O`). It accepts the identity
  (`Bls12381Codecs.java:80-106, 221-230`). The uncompressed form is a separate method.
- `Bls12381Provider` documents its scalar methods as reducing mod `r` and being for public
  scalars, with separate `g1SecretScalarMul` methods (`spi/Bls12381Provider.java:14-17, 50-60`).
  It has no MSM. The pure-Java provider's secret method is the `G1Point.ctScalarMul` ladder, whose
  Javadoc says it "has a uniform operation schedule, but it is not a JVM constant-time
  guarantee" (`ec/G1Point.java:87-107`). ADR-0021 Decision 1 states the pure-Java provider "is
  explicitly **not** a constant-time implementation".
- `BlstBls12381Provider.g1SecretScalarMul` returns `g1ScalarMul` (`BlstBls12381Provider.java:121-123`);
  the class documents no side-channel contract. It does not override compressed decoding, so both
  providers decode with the same code.
- RFC 9380 hash-to-curve for G1 exists (`Bls12381Hash.hashToG1`, `Bls12381HashToCurve.java:105-108`)
  but is tested against only two of the five RFC 9380 Appendix J.9.1 vectors, and
  `expandMessageXmdSha256` has no Appendix K.1 known-answer test
  (`Bls12381HashToCurveTest.java:18-67`). Hash-to-curve can return the identity; BBS rejects it
  explicitly (`CfrgBbsCore.java:100`).
- There is no public canonical BLS12-381 scalar decoder (`BbsCodec.scalarFromBytes` is internal to
  `zeroj-bbs`) and no shared blinding sampler. `zeroj-bls12381` and `zeroj-api` have no project
  dependencies.

**On-chain (`zeroj-onchain-julc`, JuLC `0.1.0-pre18`).**

- `BbsHashToScalar` already implements `expand_message_xmd` (SHA-256, 48 octets) and `OS2IP mod r`
  on-chain, differentially tested against `CfrgBbsCore` (`bbs/lib/BbsHashToScalar.java:36-51`,
  `BbsHashToScalarVmTest.java:28-47`); ADR-0050 records 14.2M steps / 45.8k memory.
- `Groth16BLS12381Lib` rejects scalars outside `[0, r)` before any `scalarMul`, and rejects
  non-canonical G1 encodings with `compress(uncompress(b)) == b` because "CIP-0381 does not define
  uncompress rejections" (`groth16/lib/Groth16BLS12381Lib.java:291-318, 334-354`). `BbsProofVerify`
  passes redeemer scalars to `scalarMul` unchecked.
- No ZeroJ code uses `bls12_381_G1_hashToGroup`, `bls12_381_G1_equal` or `bls12_381_G1_multiScalarMul`.
  JuLC's `BlsLib.g1MultiScalarMul` documents "the shorter of the two lists (extra entries
  ignored, an empty list gives the identity)", which disagrees with the CIP-0133 text quoted in
  ADR-0059 ("fails unless its two lists are non-empty and of equal length").
- The JuLC test VM's `scalarMul` accepts negative and large scalars (it negates for negative `k`
  and calls blst `P1.mult`); whether the node behaves identically is unverified (ADR-0056 notes
  the blst-version gap).
- The Jubjub Pedersen validators are test sources in `zeroj-integration-tests`; DevKit E2E runs
  under `@Tag("e2e")` via `:zeroj-integration-tests:e2eTest`, which no CI workflow runs.
- Mainnet parameters (epoch 661, recorded in ADR-0059): `maxTxExecutionUnits` 16,500,000 memory /
  10,000,000,000 steps; `maxTxSize` 16,384; G1 `uncompress` 52,948,122 steps; G1 `scalarMul`
  intercept 76,433,006 steps.

**Registry (`zeroj-api`).** `CommitmentProfile.define` is public and rejects an identifier
already defined through the same loaded class (`CommitmentProfile.java:47-62`; spec §12.1). The
Jubjub descriptors are created in static initialisers in `zeroj-circuit-lib`
(`PedersenScalarCommitment.PROFILE` and peers). Code that defines `pedersen-jubjub-v1` first makes
those classes fail initialisation for the rest of the JVM (#99). It fails closed, since
descriptors are compared by identity, but it lets any caller disable a built-in profile.

**ADR-0051 D7.** ADR-0051's milestone M5 bundles "G1 bases and sigma proofs off-chain" behind
D7, the escalated G1 sigma-proof transcript. Its agreed direction for bases is the one this ADR
takes: "Bases from RFC 9380 `hash_to_curve` (`BLS12381G1_XMD:SHA-256_SSWU_RO_`) with a ZeroJ DST
shorter than 255 bytes. On-chain `bls12_381_G1_hashToGroup` can reproduce them". Commitments,
openings and public relations do not need a Fiat–Shamir transcript; proofs (V4) do.

## Threat model and trust assumptions

**Untrusted:** every commitment encoding, envelope, disclosed opening (`m`, `r`, payload `B`),
public delta and sum operand an application receives; on-chain, every redeemer, datum and
reference-input datum.

**Secret (until the committer discloses them):** `m`, `B`, `r`, the mapped scalar `s`, and the
hash state and intermediate octets of the byte mapping. Any of them lets an observer test
candidate messages.

**Trusted:** the verifier's configuration (which profile it expects, the pinned basis constants
and domain strings); the selected `Bls12381Provider` as code; the Cardano node's builtins as an
implementation of CIP-0381 and CIP-0133. Builtin behaviour on inputs the CIPs leave unspecified is
treated as evidence, never as a guard.

**Adversaries and goals:**

- A committer who wants to open one commitment two ways. Binding rests on the discrete-log
  problem in G1 between `G` and `H`, so neither base may be a known multiple of the other (D2).
- A prover who sends `m + q`, `−1` or another alias of an accepted residue, or a delta outside
  its bound. Check 1 and the delta rule reject them before arithmetic (D5).
- An attacker who substitutes a commitment of another profile or curve, a bytes commitment for a
  scalar one, or a non-canonical, off-curve, small-order or non-subgroup point (D3, D5).
- An attacker who exhausts resources with an oversized payload or stream (D4).
- An observer of the committer's timing, memory access or allocation during generation (D6).
- On-chain: an attacker who relies on unspecified builtin behaviour (negative scalars,
  non-canonical encodings, MSM list lengths) to pass a check (D9).

**Not provided by any profile:** authorization, replay protection, context or UTxO binding,
integer (non-wrapping) balances, or a range on a committed value without disclosing it. These
remain the application's job, as the §14 header states.

## Pinned normative references

1. **RFC 9380**, *Hashing to Elliptic Curves* (August 2023), retrieved 2026-10-20: §3.1
   (domain-separation requirements, including "Tags MUST have nonzero length"), §5.2
   (`hash_to_field`, with `L = ceil((ceil(log2(p)) + k) / 8)`), §5.3.1 (`expand_message_xmd`,
   "ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255"), §8.8.1 (suite
   `BLS12381G1_XMD:SHA-256_SSWU_RO_`: `expand_message_xmd`, SHA-256, `L: 64`, `k: 128`), and the
   test vectors of Appendix J.9.1 and Appendix K.1.
2. **CIP-0381** at commit `86b89208d3b2aabb5dcc5b778dfbe09096b4e114` (2026-06-04): the G1
   builtins, "`bls12_381_G1_hashToGroup` … using `BLS12381G1_XMD:SHA-256_SSWU_RO_`", "We limit the
   DST to be at most 255 bytes", the Zcash serialization ("The most-significant three bits of a G1
   or G2 encoding should be masked away …") and "`bls12_381_G1_element` … can only be generated
   with byte arrays that represent a point which is part of the prime order subgroup". CIP-0381
   cites the hash-to-curve draft; RFC 9380 is its final form and defines the same suite. M4
   confirms agreement with an off-chain/on-chain differential test (D2).
3. **CIP-0133** at the same commit: `bls12_381_G1_multiScalarMul`, as quoted in ADR-0059.
4. **draft-irtf-cfrg-bbs-signatures-10**, §4.2.2 `hash_to_scalar` (`expand_message` with
   `expand_len = 48`, then `OS2IP mod r`): the precedent for the 48-octet scalar expansion this ADR
   uses for the BLS12-381 scalar field, and the algorithm `BbsHashToScalar` implements on-chain.
5. **ZeroJ specifications:** `commitment-profiles-v1` r5 (all sections cited), and
   `pedersen-jubjub-bytes-v1` §2–§3 and §6–§7, whose framing, streaming and secret rules D4 reuses
   with a different modulus and domain string.
6. **ZeroJ ADRs:** ADR-0021 (BLS12-381 hardening; the pure-Java provider is not constant-time),
   ADR-0038 (offline/isolated restriction for variable-time secret paths), ADR-0051 (D7 and its
   M5 gate), ADR-0056 (on-chain cost measurement method), ADR-0058 (byte commitments) and
   ADR-0059 (registry, contracts and matrix).

## Decision

Notation: `q` is the order of the BLS12-381 G1 prime-order subgroup,
`q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` (255 bits, so
`⌊log₂ q⌋ = 254`). It equals the BLS12-381 scalar field order, which the registry spec's §1 calls
`p` (the Jubjub base field). This ADR always writes `q` for the G1 group order and never `p` or
`l`. `P_381` is the base-field modulus of the curve `E: y² = x³ + 4`.

### D1 — Two profiles and one basis set (R2)

Specify the following entries, and admit them under `commitment-profiles-v1` §2.4 once the evidence
exists. The lifecycle is given at the end of this decision.

| Identifier | Type | Kind | Message map |
|---|---|---|---|
| `pedersen-bls12-381-g1-basis-v1` | basis set (new) | — | — |
| `pedersen-bls12-381-g1-v1` | commitment profile | `scalar` | `C = [m]·G + [r]·H`, `m ∈ [0, q)` |
| `pedersen-bls12-381-g1-bytes-v1` | commitment profile | `bytes` | `C = [s]·G + [r]·H`, `s = HashBytesToScalarG1(B)` (D4) |

Both profiles use the basis set's `G` and `H`, as ADR-0059 Q3 decided; domain separation between
them comes from the message map, as for the Jubjub scalar and bytes profiles. Core records
(§4.1), fixed for each version:

| Field | `pedersen-bls12-381-g1-v1` | `pedersen-bls12-381-g1-bytes-v1` |
|---|---|---|
| Kind | `scalar` | `bytes` |
| Group | BLS12-381 G1 prime-order subgroup, order `q`, cofactor `0x396c8c005555e1568c00aaab0000aaab`; identity accepted (D3) | same |
| Basis set | `pedersen-bls12-381-g1-basis-v1` | same |
| Message map | `m` | `HashBytesToScalarG1(B)` |
| Scalar domain | check 1 on `m` and `r`; homomorphic results are residues mod `q` | check 1 on `r`; `s` is canonical by construction and never range-checked |
| Point encoding | 48-octet Zcash compressed, strict (D3) | same |
| Circuit public-input encoding | none | none |
| Opening encoding | `I2OSP(m, 32) ‖ I2OSP(r, 32)` (D5) | `I2OSP(r, 32)`; the payload travels separately (D5) |

Envelope v1 lengths (§9): `pedersen-bls12-381-g1-v1` is `1 + 1 + 24 + 48 = 74` octets and
`pedersen-bls12-381-g1-bytes-v1` is `1 + 1 + 30 + 48 = 80` octets.

The registry rule that the point sets of two profiles over one basis set are not disjoint holds
here too: a bytes commitment is also a valid scalar commitment to `s`. Kind and profile come only
from the verifier's configuration, never from a point.

**Lifecycle.** Approving the spec, reserving a descriptor, implementing a profile and admitting it
are separate steps:

1. **Spec approval (M0).** The registry spec r6 records the parameters and points to the new spec.
   The two profiles stay `reserved`. The basis set is added as `reserved`, with this ADR named as
   the one that may admit it.
2. **Descriptor reservation (M1).** `zeroj-api` creates and registers the descriptors of both G1
   identifiers (D8), so nothing can pre-empt them. Holding a descriptor does not make an entry
   active.
3. **Implementation (M2–M4).** Java, vectors and on-chain code are built against the reserved
   entries and carry the same experimental status as every profile.
4. **Admission (M5).** A registry revision (r7) turns the basis set and both profiles `active`, and
   only after M5 has checked every prerequisite:
   - the accepted ADR;
   - the normative spec;
   - all three base reproductions of D2;
   - the §13 vectors and their independent recomputation;
   - the descriptors;
   - the M4 on-chain parity results.

   If any prerequisite is missing, the entries stay `reserved`.

### D2 — Basis derivation (R3)

```
DST_B = "ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"   (ASCII, 68 octets)
G = hash_to_curve(msg = "G", DST_B)                (RFC 9380 §3, suite BLS12381G1_XMD:SHA-256_SSWU_RO_)
H = hash_to_curve(msg = "H", DST_B)
```

`"G"` and `"H"` are the single ASCII octets `0x47` and `0x48`. The tag follows RFC 9380 §3.1:
nonzero length, an application prefix, a version and the suite ID; it is under the 255-octet
limit of RFC 9380 §5.3.1 and CIP-0381. Using one tag with distinct messages is how BBS derives its
generators (draft-10 §4.1.1): one random oracle evaluated at two inputs.

Rules:

- The spec pins `G` and `H` as 48-octet compressed constants and states the derivation. A
  deriver MUST check that each output is not the identity, that `G ≠ H` and that `G ≠ ±H`; on
  failure the basis set is invalid, and a new version with new messages is required. The
  probability of failure is negligible; the check is there so that no implementation silently
  continues.
- Implementations use the pinned constants and do not hash at run time. A test recomputes them.
- No one, including the deriver, knows `log_H(G)`: both bases are random-oracle outputs, which is
  what binding requires (registry spec §3).
- Three independent reproductions are required before admission (§2.4 item 3, which asks for
  one). This ADR asks for three, so admission waits for M5 (D1 lifecycle):
  - the existing Java `hashToG1` (M0);
  - a stand-alone Python implementation, written from RFC 9380 without reading the Java and
    validated against all five Appendix J.9.1 vectors (M0);
  - on-chain `bls12_381_G1_hashToGroup`, run in the JuLC VM and on Yaci DevKit (M4).
- A different tag, message or suite is a different basis set and therefore new profile versions
  (registry spec §2.4; ADR-0051 I7).

**Value base.** Both bases are hashed (Q2). The alternative uses the standard generator `g₁` as
`G`. It is equally binding, since `H` is still a random-oracle output, but it treats the two bases
asymmetrically and makes `[m]·g₁` a value that other protocols on the same curve also compute.

### D3 — Point encoding and strict decoding (R2)

The point encoding is the 48-octet Zcash compressed form that CIP-0381 uses. The uncompressed
form is not accepted. The strict decoder (registry spec §10) applies, in order:

| Step | Rule | Outcome |
|---|---|---|
| 1 | null | `NullPointerException` |
| 2 | length ≠ 48 | `MALFORMED_ENCODING` |
| 3 | compression flag (`0x80`) clear | `MALFORMED_ENCODING` |
| 4 | infinity flag (`0x40`) set: the encoding must be exactly `0xC0 ‖ 0^47` | if exact, **return the identity and stop**; any other encoding with the infinity flag (sort flag `0x20` set, or any nonzero coordinate bit) is `MALFORMED_ENCODING` |
| 5 | finite encodings only, coordinate `x` (the 381 bits below the three flag bits): `x ≥ P_381` | `MALFORMED_ENCODING` |
| 6 | finite encodings only: `x³ + 4` not a square in `GF(P_381)` (no curve point) | `MALFORMED_ENCODING` |
| 7 | finite encodings only: the recovered point (`y` chosen by the sort flag) is outside the prime-order subgroup | `NOT_IN_SUBGROUP` |

Steps 5–7 never run on an infinity encoding. Without that rule, the masked coordinate of
`0xC0 ‖ 0^47` would read as `x = 0`. The finite encoding `0x80 ‖ 0^47` does have `x = 0`; it
decodes to `(0, 2)` (the sort flag is clear, so `y` is the smaller root), a point of order 3, and is
rejected at step 7. With the sort flag, `0xA0 ‖ 0^47` decodes to `(0, P_381 − 2)`, also of order 3. The decoder never
clears the cofactor.

This is the order `Bls12381Codecs.g1FromCompressed` already implements: it returns
`G1Point.INFINITY` at step 4. M2 splits its single `IllegalArgumentException` into these classes
in a package-private strict decoder, as ADR-0059 M1 did for Jubjub. M2 adds unit tests for steps
3–5, which have none today, plus three cases:
- the identity, as a positive;
- infinity with the sort flag set, as a negative;
- infinity with a nonzero coordinate bit, as a negative.

**Identity policy.** The identity `0xC0 ‖ 0^47` is accepted, as in every Jubjub profile. It is a
legitimate commitment (`m = r = 0`, or a sum whose blindings cancel), and rejecting it would make
some sums unrepresentable. Hiding is the committer's job (registry spec §14 consequences); a
verifier that wants to refuse it does so as application policy. M4 records what
`bls12_381_G1_uncompress` returns for `0xC0 ‖ 0^47` and for every step-2–7 negative, including
both infinity negatives and `0x80 ‖ 0^47`. The on-chain verdict must equal the off-chain verdict
on each of them (D9).

### D4 — The byte mapping `HashBytesToScalarG1` (R3)

```
DST_S = "ZeroJ-pedersen-bls12-381-g1-bytes-v1-H2S-XMD:SHA-256"      (ASCII, 52 octets)
msg   = B ‖ I2OSP(n, 8)                                              (n = len(B) in octets)
s     = OS2IP(expand_message_xmd(msg, DST_S, 48)) mod q              (RFC 9380 §5.2, count = 1, m = 1, k = 128)
```

This is `pedersen-jubjub-bytes-v1`'s mapping with the modulus `q` in place of `l` and its own tag:
the same SHA-256 instance, the same 48-octet expansion (`L = ceil((255 + 128) / 8) = 48`), the
same length suffix, and the same streaming, maximum-length and secret rules. Its reduction has
statistical distance below `q / 2^384 < 2^-129` from uniform. `s = 0` is valid and never retried.
`MAX_PAYLOAD_BYTES = 2^61 − 256`, as in the Jubjub profile, because the SHA-256 input bound is the
same. The three Java sources (array, declared-length stream, bounded stream) produce identical
`s`.

**What can be rejected before any read, and what cannot.** The rules are those of
`pedersen-jubjub-bytes-v1` §6.1 and ADR-0058 D6:

- **Before any read or digest work.** An array longer than `MAX_PAYLOAD_BYTES`, and a declared
  length or caller maximum outside `[0, MAX_PAYLOAD_BYTES]`, are rejected with
  `LENGTH_OUT_OF_RANGE`.
- **Stream content, by counting.** The actual length of a stream is unknown until it is read, so
  stream content is checked as it is read:
  - A declared-length stream may be read for `length` octets plus one end-of-stream probe.
  - A bounded stream may be read for `maxBytes` octets plus one probe.
  - Excess content found by the probe, or a stream that ends before a declared length, fails
    with `IOException`.
  - The probe octet is never hashed.
  - No result and no curve work is produced until the source has been consumed successfully.

On-chain, the same expansion is `BbsHashToScalar`'s algorithm with this tag and the framed
message. The library recomputes `s` from the payload (D9).

**Scalar-only mode (Q3).** The bytes profile offers no API that accepts a supplied `s` instead of
`B`. A check of `(s, r)` against a bytes commitment is a `pedersen-bls12-381-g1-v1` opening of
`s`. It authenticates only that scalar, not any payload (registry spec §4.4), and the docs say
so where a validator might be tempted to use it.

### D5 — Scalars, openings and public relations (R2)

- **Check 1** (registry spec §7) applies to `m` and `r` on every strict path: `[0, q)`, never
  reduced, otherwise `NON_CANONICAL_SCALAR`.
- **Check 2** is optional on `m`, with `1 ≤ k ≤ 254`; a `k` outside that range is
  `INVALID_CONFIGURATION`, and a violation is `OUT_OF_RANGE`. It never applies to `r` or `s`.
- **Opening encodings:** scalar `I2OSP(m, 32) ‖ I2OSP(r, 32)` (64 octets); bytes `I2OSP(r, 32)`
  (32 octets). These are the same layouts as the Jubjub profiles, since `q < 2^256`. Decoders
  reject a wrong length with `MALFORMED_ENCODING`, then `m ≥ q`, then `r ≥ q` with
  `NON_CANONICAL_SCALAR`.
- **V3 public delta:** `C_new = C_old + [δ]·G` for a signed `δ` with an application bound
  `|δ| < 2^{k_δ}`, `1 ≤ k_δ ≤ 253` (253, not 254, so a bounded delta is unique mod `q`; spec r2).
  The implementation multiplies `G` by the canonical `|δ|` and
  negates the result when `δ < 0`; it never passes a negative or out-of-range integer to a scalar
  multiplication, off-chain or on-chain. Sums use coefficients the verifier fixes, never ones the
  prover supplies. The result is a residue mod `q`. An integer reading needs the application's own
  bounds (ADR-0051 D3a).
- **Arithmetic:** `add`, `subtract` and `negate` exist only on the scalar commitment type and
  accept only that type. The bytes type has none (registry spec §6.1).

### D6 — Generation, secrets and providers (R3)

- **Generation** (`commitScalar`, `commitBytes*`) computes `[x]·G` and `[r]·H` through the
  provider's `g1SecretScalarMul`, never through `g1ScalarMul`, MSM or a precomputed table indexed
  by secret bits. The byte mapping and its reduction run inside the same boundary.
- **No constant-time claim**, for either provider:
  - The pure-Java ladder has a uniform operation schedule but data-dependent branches, special
    cases and `BigInteger` arithmetic (ADR-0021).
  - The blst provider's secret method is its public method, and ZeroJ has no evidence for a
    side-channel contract of the `blst-java` binding.

  Generation is therefore **offline/isolated only** for both providers, inheriting ADR-0038 and
  ADR-0051 I8. This is the V2 restriction of the registry spec §6.2.
- **Blinding sampler:** 64 octets from the caller's `SecureRandom`, reduced mod `q`. Statistical
  distance is below `2^-257`. The reduction is variable-time `BigInteger` arithmetic on a secret,
  so it sits in the same boundary, and the buffer is wiped in `finally`. A zero blinding is
  accepted by check 1, as for Jubjub, and is never produced by the sampler in practice.
- **V1 disclosed verification** uses public scalar multiplication and is variable-time. The
  registry spec's timing rule applies: only where the opening is already public or no party from
  whom it is still secret can observe the verifier's timing.
- **Secret hygiene** follows ADR-0059 I8 and `pedersen-jubjub-bytes-v1` §7:
  - Opening holders are final, not records, not `Serializable`, with no `equals`/`hashCode` and a
    redacted `toString`.
  - A `BigInteger` subclass is copied once.
  - Owned buffers are wiped.
  - No secret appears in messages, logs, caches or `ThreadLocal`s.
  - The Javadoc states that `BigInteger` values cannot be wiped.
- **Providers:** the G1 entry point takes an explicit `Bls12381Provider` (default pure Java).
  - Decoding is shared code and identical across providers.
  - Generation and verification MUST give byte-identical commitments and identical verdicts on
    every vector for the pure-Java and blst providers.
  - The optional WASM provider is a differential oracle in assurance tests only.

### D7 — Java API and placement (R2)

- **Placement (Q1).** A new package `org.zeroj.bls12381.pedersen` in `zeroj-bls12381`, which gains
  a dependency on `zeroj-api`. That module is dependency-free, and ADR-0059 chose it for exactly
  this case. No new artifact is created (ADR-0044). The module's native-image resources are
  updated if a type needs them.
- **Types, mirroring the Jubjub binding of the registry spec §12.2:**

  | Type | Role | Contents |
  |---|---|---|
  | `G1PedersenCommitment` | `pedersen-bls12-381-g1-v1` commitment | `PROFILE`, `CODEC`, `decode`, `toPointBytes`, `add`, `subtract`, `negate`, `withPublicDelta(BigInteger delta, int deltaBits)`, value equality over the encoding |
  | `G1PedersenBytesCommitment` | `pedersen-bls12-381-g1-bytes-v1` commitment | `PROFILE`, `CODEC`, `decode`, `toPointBytes`; no arithmetic |
  | `G1PedersenOpening`, `G1PedersenBlinding` | openings | the D5 encodings, with check 1 at construction and decoding |
  | `G1Pedersen` | entry point | `pureJava()`, `withProvider(Bls12381Provider)`, `provider()`, `supportsGeneration()`, `commitScalar`, `verifyScalar` (3 and 4 arguments), `randomBlinding`, `commitBytes`/`verifyBytes` (array, declared-length stream, bounded stream). The exact signatures, the provider capability check and the check order are `pedersen-bls12-381-g1-v1` §8 |

  All types are final with no public constructor. The strict check order of the registry spec
  §12.3 applies, with G1 rows that use `amountBits ∈ [1, 254]`.
- **Contracts:** the commitment types implement `Commitment`, and the codecs implement
  `CommitmentCodec` with an empty key context. `CommitmentEnvelope`, `CommitmentKey` and
  `CommitmentAcceptance` work unchanged. A scalar envelope decoded with the bytes codec, or a
  Jubjub envelope with a G1 codec, is `PROFILE_MISMATCH`.
- **Public scalar helper:** a canonical 32-octet G1 scalar decoder, so callers stop borrowing
  `BbsCodec`.

### D8 — Built-in descriptors owned by `zeroj-api` (R2; folds in #99)

- `zeroj-api` gains a final class `CommitmentProfiles` whose constants are the descriptors of every
  built-in profile: the three Jubjub profiles and the two G1 profiles. They are created and
  registered while `CommitmentProfile` itself is being initialised, so they exist before any caller
  can reach `define`.
- A caller's `define` of a built-in identifier is then always rejected
  (`INVALID_CONFIGURATION`, as for any duplicate), and no class initialisation in ZeroJ can be made
  to fail by defining first.
- The existing `PROFILE` fields of the Jubjub types and the new G1 types refer to the same
  instances (`PedersenScalarCommitment.PROFILE == CommitmentProfiles.PEDERSEN_JUBJUB_V1`). They
  are source-compatible and keep comparison by identity.
- The registry spec §12.1 is revised (r6) to say that built-in descriptors are defined by
  `zeroj-api`, and that the duplicate rule now protects them rather than threatening them.
- **Coordinated upgrade; mixed versions are unsupported.** Today every Jubjub `PROFILE`
  initialiser calls the public `define`. A pre-M1 `zeroj-circuit-lib` binary run against a
  post-M1 `zeroj-api` therefore fails class initialisation with `ExceptionInInitializerError`,
  because its own built-in identifier is already registered. Any later use then fails with
  `NoClassDefFoundError`. The PR #103 review reproduced this with the unchanged baseline classes.
  The failure is closed and immediate, not a silent misbehaviour, but it is a break.
  - `zeroj-api`, `zeroj-circuit-lib` and `zeroj-bls12381` must come from the same ZeroJ release.
    Applications align them with the ZeroJ BOM (`zeroj-bom-core`, which manages all three) or by pinning one version for all three, and must
    check that transitive dependency resolution does not mix them.
  - The release notes of the M1 release say so.
  - M1 adds a check that every profile module obtains its descriptor from `CommitmentProfiles`
    and that none calls `define`.
- **Alternative rejected.** `define` could return the existing built-in instance when called
  with exactly a built-in's parameters. Old binaries would then keep working, and nothing could
  still pre-empt a built-in. It is rejected because it changes `define` from "always a new
  descriptor" to "sometimes an existing one", which every caller would have to reason about, in
  order to support a mixed classpath that ZeroJ does not otherwise support. Q4 was decided as (a),
  so it is not taken.
- Considered and rejected:
  - Rejecting reserved identifiers inside `define` would require a non-public path from
    `zeroj-circuit-lib` and `zeroj-bls12381` into `zeroj-api`.
  - Dropping duplicate rejection would allow two descriptors with one identifier, which the
    registry spec forbids.

### D9 — On-chain library and validators (R2)

- **A published JuLC library** `PedersenG1Lib` in `zeroj-onchain-julc` (Q5), with:
  - `decodeCommitment`, with this split of responsibility:
    - The library checks length 48 before `uncompress` is called.
    - Curve and subgroup validity are delegated to the builtin's normative contract. CIP-0381
      says a `bls12_381_G1_element` "can only be generated with byte arrays that represent a
      point which is part of the prime order subgroup". The library does not re-implement curve
      arithmetic.
    - After `uncompress` and before the point is used, the library checks
      `compress(point) == bytes`. That rejects every non-canonical encoding `uncompress` might
      accept, which CIP-0381 does not specify, as `Groth16BLS12381Lib` does. The round trip is a
      canonicality check, not a subgroup check.
  - `verifyScalarOpening(C, m, r)`: check 1 on `m` and `r` before any builtin sees them, then
    `[m]·G + [r]·H == C` with the pinned bases.
  - `verifyBytesOpening(C, B, r)`: recompute `s` with the D4 mapping on-chain, check 1 on `r`, then
    the same equation.
  - `applyPublicDelta(C, δ, k_δ)`: the signed-delta rule.
  - Fixed-coefficient sums.
- **Builtins.** The library uses two `scalarMul` and one `add`.
  - M4 measures the alternative of one two-term `bls12_381_G1_multiScalarMul`. If it is cheaper,
    the library adopts it, always with two equal-length non-empty lists. The documented
    disagreement over empty and unequal lists then cannot matter.
  - The bases are pinned compressed constants, decompressed in the script. `hashToGroup` is used
    only in the tests that reproduce them.
- **Guards, not builtins.** Every scalar the library passes to a builtin has passed check 1 or the
  delta rule. M4 adds evidence vectors recording what the JuLC VM and the DevKit node do with
  negative and `≥ q` scalars, non-canonical and non-subgroup encodings, infinity, and empty or
  unequal MSM lists. These record behaviour; the library does not rely on them.
- **Example validators** in `zeroj-integration-tests`, not published:
  - a scalar opening;
  - a running total updated by public deltas held in a datum;
  - a bytes opening.

  Each documents what the library does not provide: authorization, replay protection, UTxO and
  context binding, non-negative balances, and the fact that every opened value is public forever.
- **Payload limit.** M4 measures and documents the largest payload a bytes opening can carry,
  bounded by the execution budget and by the 16,384-octet transaction that carries the redeemer,
  datum or reference-input datum. No figure is claimed before it is measured.
- **Proofs stay out.** V4 (proofs about committed values) stays blocked on ADR-0051 D7. This ADR
  takes the "G1 bases" part out of ADR-0051 M5 (Q6). M5 keeps the sigma proofs and their D7 gate,
  which this ADR neither decides nor weakens.

## Alternatives considered

| Alternative | Why not |
|---|---|
| `G` = the standard generator `g₁` (Q2 option b) | Binding is unchanged, but it reuses a base other protocols use and breaks the symmetric, reproducible derivation. Kept as an option for the maintainer. |
| Bases from a ZeroJ-specific try-and-increment or a SHA-256 seed | Not reproducible by `bls12_381_G1_hashToGroup`, and not a published procedure (registry spec §3). |
| Separate tags per base | Allowed by RFC 9380, but one tag with distinct messages is the BBS precedent and is simpler to reproduce on-chain. |
| A G1 byte mapping without the length suffix, or `BbsHashToScalar` on the bare payload | Would differ from `pedersen-jubjub-bytes-v1` for no gain. The suffix makes streaming of unknown-length input one-pass. |
| SHA-512 or Blake2b for the byte mapping | `sha2_256` and `expand_message_xmd` already exist on-chain and are reviewed (`BbsHashToScalar`). The Jubjub profile chose SHA-256 for the same reason. |
| Reject the identity point | Makes sums and `m = r = 0` unrepresentable, and differs from every Jubjub profile. Rejection remains available as application policy. |
| Reduce scalars instead of rejecting them | Creates aliases (`m` and `m + q` both open), which the registry spec forbids. |
| G1 types in `zeroj-circuit-lib` or a new module | They contain no circuit code, and a new module runs against ADR-0044. ADR-0059 already placed the contracts in `zeroj-api` so that `zeroj-bls12381` could implement them. |
| An example validator only, no library | Every application would re-derive the guards, which are exactly the security-relevant part. |
| Decide ADR-0051 D7 here to admit V4 | Out of scope. D7 is an escalated conflict between the pinned references and the platform. |

## Exact invariants

- **I1 — Bases.** `G` and `H` equal the D2 hash-to-curve outputs, are in the subgroup, are not the
  identity and satisfy `G ≠ ±H`. The pinned constants are reproduced by Java, by an independent
  Python implementation and by on-chain `hashToGroup`. (D2)
- **I2 — Strict decoding.** Every 48-octet input decodes to the point it encodes, or fails at the
  first D3 step with that step's class. Exactly `0xC0 ‖ 0^47` decodes to the identity, without
  coordinate recovery; every other encoding with the infinity flag is rejected. The cofactor is
  never cleared, and on-chain `compress(uncompress(b)) == b` holds for every accepted `b`.
  (D3, D9)
- **I3 — Canonical scalars.** No strict path, off-chain or on-chain, reduces or accepts `m` or `r`
  outside `[0, q)`. Check 2 accepts only `k ∈ [1, 254]`. No negative or out-of-range integer
  reaches a scalar multiplication. (D5, D9)
- **I4 — Byte mapping.** `s` equals the D4 value for every source, payload length and split of a
  stream.
  - An array longer than `MAX_PAYLOAD_BYTES`, or a declared length or maximum outside
    `[0, MAX_PAYLOAD_BYTES]`, is rejected before any read or digest work.
  - Stream content is bounded by counting: at most `length + 1` or `maxBytes + 1` octets are
    read, and an excess octet is never hashed.
  - No result or curve work happens before the source has been consumed successfully.
  - The on-chain mapping agrees with Java on every vector.

  (D4)
- **I5 — No cross-profile or cross-curve use.** Decoders and keys accept only the expected
  profile. Bytes commitments have no arithmetic, and Jubjub and G1 types cannot be combined.
  (D1, D5, D7)
- **I6 — Secret handling.** Generation uses only provider secret-scalar methods and runs
  offline/isolated. Opening holders satisfy the ADR-0059 I8 closure. No secret appears in a
  message, log or exception. No constant-time claim is made. (D6)
- **I7 — Provider parity.** Pure Java and blst give identical encodings and verdicts on every
  vector. (D6)
- **I8 — Built-in descriptors.** Every built-in descriptor exists, and is registered, before any
  external `define` can run. A `define` of a built-in identifier is rejected, and each built-in
  profile has exactly one descriptor per `zeroj-api` class loader. No ZeroJ profile module calls
  `define`. Mixing a pre-M1 profile module with a post-M1 `zeroj-api` is unsupported and fails
  closed at class initialisation. (D8)
- **I9 — Jubjub unchanged.** No Jubjub constant, base, encoding, circuit, key or vector changes,
  and every existing test and vector passes. The only Jubjub change is that `PROFILE` fields refer
  to the `zeroj-api` constants. (D8)
- **I10 — On-chain trust boundary.** The library's verdict on every applicable vector equals the
  off-chain verdict, including every malformed, non-canonical and non-subgroup encoding. It
  enforces:
  - the 48-octet length before `uncompress`;
  - curve and subgroup validity through the pinned CIP-0381 element contract, not through its
    own arithmetic;
  - canonical encoding by `compress(uncompress(b)) == b`, after `uncompress` and before the point
    is used;
  - check 1 and the delta rule before any `scalarMul` or MSM;
  - the byte mapping recomputed from the payload.

  (D9)
- **I11 — Measurements are records.** No benchmark changes a check, and no figure is claimed
  without the measurement in the registry spec's §15 form. (D9)

## Compatibility

- **Additive.**
  - The two G1 profiles, a basis set, a package in `zeroj-bls12381` and a library in
    `zeroj-onchain-julc` are new.
  - `zeroj-bls12381` gains a dependency on the dependency-free `zeroj-api`.
  - `zeroj-api` gains `CommitmentProfiles`.
- **Jubjub.** No Jubjub behaviour or encoding changes. The Jubjub `PROFILE` fields keep their
  names and types, and now refer to descriptors created in `zeroj-api`. That is source- and
  API-compatible.
- **Binaries: coordinated upgrade required.** A pre-M1 profile-module binary does not work with a
  post-M1 `zeroj-api`: its `PROFILE` initialiser calls `define` for a built-in identifier and
  fails closed with `ExceptionInInitializerError` (D8). `zeroj-api`, `zeroj-circuit-lib` and
  `zeroj-bls12381` must be upgraded together, through the BOM or one pinned version, with
  transitive resolution checked. Mixed versions are unsupported, and the M1 release notes say so.
- **`define`.** Code that called `define` with a built-in identifier, which previously disabled a
  ZeroJ profile, now gets `INVALID_CONFIGURATION` at that call.
- **Existing vectors and tests.** The existing Jubjub vector files stay valid. The reserved-profile
  envelope negatives in those files still expect `PROFILE_MISMATCH`, since a Jubjub codec rejects
  a G1 identifier whether or not that identifier is reserved.
- **Registry spec.** It moves to r6 at M0. That revision adds the parameters and the basis set,
  revises §12.1 for D8, and changes the §1 notation, §8.4, §9, §12, §13 and §14 sections. The
  entries stay `reserved` in r6. They become `active` only in r7, at M5, after every admission
  prerequisite has been checked (D1 lifecycle).
- **Shipped behaviour.** No existing validator, script hash or key changes.

## Implementation milestones (after acceptance)

| Milestone | Entry gate | Deliverable and exit criteria |
|---|---|---|
| M0 — spec | ADR accepted by a named maintainer | <ul><li>`docs/specs/pedersen-bls12-381-g1-v1.md`: basis set, both profiles, D3 decoder with its explicit identity branch, D4 mapping and stream rules, D5 encodings, vectors in the D2/D4 test sections.</li><li>`commitment-profiles-v1` r6: parameters, with the two profiles and the new basis set all `reserved` and pending admission under this ADR; §1, §8.4, §9, §12.1 per D8, §12.3 G1 rows, §13 G1 point fields (`xHex`/`yHex`, 48 octets) and G1 minimum sets, §14 cells still `planned`.</li><li>Java and independent Python reproductions of `G`, `H` and the D4 mapping. The Python is written without reading Java and passes all five RFC 9380 J.9.1 vectors.</li><li>Claude and Codex SPEC READY, then maintainer sign-off.</li></ul> |
| M1 — descriptors (#99) | ADR accepted and the §12.1 text agreed; it does not depend on the rest of M0, so #99 can ship first | <ul><li>`CommitmentProfiles` in `zeroj-api`, registering all five built-in descriptors (the G1 ones reserved, not admitted); Jubjub `PROFILE` fields as aliases.</li><li>A regression in which `define(pedersen-jubjub-v1, …)` runs before any profile class loads and the profiles stay usable.</li><li>A check that no profile module calls `define`; release notes stating the coordinated-upgrade requirement (D8).</li><li>Surface tests updated; full `zeroj-api` and `zeroj-circuit-lib` suites green.</li></ul> |
| M2 — Java G1 profiles | M0 signed off, M1 | <ul><li>D3 strict decoder with tests for steps 2–7, an identity positive and the infinity negatives; D5–D7 types and entry point.</li><li>Stream tests: an invalid limit before any read, excess content via the probe, an early end.</li><li>Pure-Java and blst parity tests.</li><li>The missing RFC 9380 J.9.1 and K.1 known-answer tests for the existing `hashToG1` and `expandMessageXmdSha256`.</li><li>Negative and closure tests mirroring ADR-0059 M1.</li><li>Seeded-fault check of the new guards.</li></ul> |
| M3 — vectors | M2 | <ul><li>`pedersen-bls12-381-g1-v1.json` and `-bytes-v1.json` in the registry spec §13 format, from a generator written from the spec only.</li><li>Java loader over both providers.</li><li>Independent recomputation of every case by a reviewer.</li></ul> |
| M4 — on-chain | M3 | <ul><li>`PedersenG1Lib`, example validators, and JuLC VM tests over every applicable vector.</li><li>Builtin evidence vectors (D9) and the on-chain `hashToGroup` reproduction of the bases.</li><li>DevKit E2E: opening, delta update, bytes opening, each with tampered negatives.</li><li>Registry spec §15 Cardano measurements, the documented payload limit, and MSM versus two `scalarMul`.</li></ul> |
| M5 — docs and admission | M4 | <ul><li>An admission check against every prerequisite of the D1 lifecycle, recorded in this ADR.</li><li>Registry spec r7: the basis set and both profiles `active`, and §14 cells implemented (experimental). If any prerequisite is missing, the entries stay `reserved` and the gap is recorded.</li><li>Docsite and module READMEs, the support matrix, and the registry spec §15 Java benchmarks.</li><li>An ADR-0051 status note recording the M5 split.</li><li>Implementation evidence in this ADR.</li></ul> |

Each milestone is reviewed by a Claude reviewer and Codex until no P0–P2 finding remains, then
committed and pushed. M1 can ship on its own if the maintainer wants #99 closed before the G1
work.

## Verification and test strategy

- **Known-answer tests:**
  - RFC 9380 J.9.1, all five vectors, for `hash_to_curve`, and K.1 for `expand_message_xmd`
    (SHA-256).
  - The Zcash generator encoding.
  - Pinned `G` and `H`.
  - D4 mapping values for the empty payload, a pattern payload and a payload longer than one
    SHA-256 block.
- **Independent implementations:**
  - The Python reproduction (M0) and the vector generator (M3), both written without reading Java.
  - On-chain `hashToGroup` and the on-chain mapping.
  - The blst provider for arithmetic.
  - The WASM provider as an assurance oracle where available.
- **Negative tests:**
  - Every D3 step:
    - infinity with the sort flag set, and infinity with a nonzero coordinate bit;
    - `0x80 ‖ 0^47`, which decodes to `(0, 2)` and is rejected with `NOT_IN_SUBGROUP`;
    - the identity `0xC0 ‖ 0^47`, as a positive.
  - Streams: a declared length or maximum of −1 and of `MAX_PAYLOAD_BYTES + 1`, rejected before
    any read; one excess octet, rejected via the probe and not hashed; an early end.
  - Check 1 at `q − 1`, `q`, `q + 1` and `−1` for `m` and `r`.
  - Check 2 at `2^k − 1` and `2^k`, and `k` at 0 and 255.
  - Deltas at `±(2^{k_δ} − 1)` and `±2^{k_δ}`.
  - Opening lengths 63, 65, 31 and 33.
  - Envelope negatives as in the registry spec §13.4.
  - Cross-profile and cross-curve substitution: a G1 bytes envelope with the G1 scalar codec, and
    a Jubjub envelope with a G1 codec.
  - Payload lengths −1 and `MAX_PAYLOAD_BYTES + 1`.
  - A `BigInteger` subclass that lies about its range.
  - Built-in-descriptor pre-emption (D8).
- **Differential:**
  - Pure Java against blst on every vector.
  - Java against the JuLC VM against DevKit on every validator-relevant vector.
  - On-chain `hashToGroup` against the pinned bases.
- **Seeded faults:** reduce instead of reject, skip the subgroup step, swap `G` and `H`, drop the
  length suffix, use `l` instead of `q`, and pass a negative delta to `scalarMul`. Each must be
  caught by a test.
- **Regression:** full `zeroj-api`, `zeroj-bls12381`, `zeroj-blst`, `zeroj-circuit-lib` and
  `zeroj-onchain-julc` suites, the existing Jubjub vectors byte for byte, and
  `verifyDefaultModuleSurface`.

## Consequences

- Cardano validators can open G1 commitments and update committed totals by public deltas
  natively, without a SNARK. Every opened value is public forever, and the residues are mod `q`,
  not balances.
- G1 commitments cannot be used inside the existing Jubjub circuits, and no bridge between the
  curves exists (ADR-0051 D8).
- Generation stays offline/isolated. A deployment that needs online G1 generation needs a provider
  with an audited side-channel contract, and its own review.
- The registry becomes tamper-proof for built-in identifiers (#99), at the cost of `zeroj-api`
  naming the built-in profiles of other modules.

## Risks and production/audit gates

- **Side channels in generation.** Neither provider has a side-channel contract. This is the main
  production gate, together with external review of the basis derivation and the byte mapping.
- **Builtin behaviour.**
  - The library relies on one normative builtin guarantee: CIP-0381's subgroup-only G1
    elements, which make `uncompress` the curve and subgroup check.
  - What CIP-0381 leaves unspecified is recorded, not relied on: `uncompress` canonicity,
    `scalarMul` on out-of-range integers, and MSM list rules. The library's own length,
    round-trip, scalar and delta guards cover them.
  - Accept/fail parity on malformed and non-subgroup encodings is tested in M4, so a node that
    broke the subgroup contract would be detected when those vectors are re-run, and reported.
- **JuLC VM versus node.** Costs and behaviour are measured in the JuLC VM and confirmed on
  DevKit, but DevKit's `/evaluate` cannot initialise blst on aarch64 (ADR-0056). No CI job runs
  the E2E tests, so they are run and recorded manually.
- **Payload limit.** On-chain byte openings are small: a few kilobytes at most, to be measured.
  Larger documents are off-chain only.
- **D7 remains blocked**, so no proof about a hidden G1 value is offered. Range claims need #96.
- **Maturity.** Everything is experimental until external review. Passing tests, AI reviews and
  successful DevKit runs are not evidence of cryptographic security.

## Related findings (out of scope)

- `BbsProofVerify` passes redeemer scalars to `scalarMul` without a range check. That is the BBS
  library's own design and is not changed here; it deserves its own review issue.
- `ScriptBudgetEstimator` uses pre-PV11 cost constants.
- The repository's docs disagree on the `ConfidentialNoteValidator` cost (3.66e9 against 3.85e9
  steps) and on the transaction memory limit (14M against 16.5M).
- `Bls12381Hash.expandMessageXmdSha256` does not reject an empty DST, although RFC 9380 §3.1
  says "Tags MUST have nonzero length"; that policy question belongs to the general API.
  Separately, its reduction of a DST longer than 255 octets to `SHA-256("H2C-OVERSIZE-DST-" ‖ DST)`
  is the behaviour RFC 9380 §5.3.3 specifies, and is correct. CIP-0381's 255-octet limit is a
  different boundary: the builtin's argument. D2 and D4 use fixed tags under 255 octets, so
  neither point affects them.
- #100, #101 and #102 (vector integer format, sealing, `INVALID_CONFIGURATION` asymmetry) stay
  separate.

## Implementation evidence (M2–M5)

Everything below is evidence, not a security claim (AGENTS.md). Measurements are in
[`docs/benchmarks/pedersen-g1-2026-10-22.md`](../benchmarks/pedersen-g1-2026-10-22.md).

### Deliverables

| Milestone | Deliverables |
|---|---|
| M2 | `org.zeroj.bls12381.pedersen` in `zeroj-bls12381`: `G1Pedersen`, `G1PedersenCommitment`, `G1PedersenBytesCommitment`, `G1PedersenOpening`, `G1PedersenBlinding` (public), `G1PedersenStrict`, `G1PedersenBases`, `G1PedersenBytesHash` (package-private); `Bls12381Codecs.scalarFromBigEndian32`/`scalarToBigEndian32`; native-image entries for the three non-secret public types. Tests: decoder (every D3 step, an independent affine reference, 1,147-case differential by a reviewer), checks and their order, deltas, openings, envelopes and cross-profile/cross-curve substitution, streams and cleanup, hostile `BigInteger` subclasses, exact API surface, provider capability and schedule (counting stub providers), RFC 9380 J.9.1 (`P`, `u`), K.1 and K.2 known answers, pure-Java/blst parity. |
| M3 | Independent generator `pedersen-g1-reference/emit_g1_commitment_vectors_v1.py` (written from the specs, never from Java; `--check`, `--self-test` with 30 generator mutants); `pedersen-bls12-381-g1-v1.json` and `-bytes-v1.json` in `zeroj-test-vectors`; the shared runner (`zeroj-bls12381` test fixtures, excluded from publication) run over both providers with identical outcomes; a reviewer's independent recomputation of every case with py_ecc found no mismatch. |
| M4 | `PedersenG1Lib` in `zeroj-onchain-julc`; Julc VM tests over every on-chain-applicable vector case with exact builtin counts (a marked PV11 cost model, ADR-0056) proving that guards precede `scalarMul` and `uncompress`; builtin evidence for `uncompress`, `scalarMul` and MSM in the VM and on Yaci DevKit; `hashToGroup` reproduction of the bases in the VM and on DevKit; three example validators (opening, running total, byte opening) with tampered negatives in the VM and on DevKit; node/VM parity of strict decoding; the payload limit; MSM against two `scalarMul`. |
| M5 | Registry r7 (admission); spec r2; the measurements document; module READMEs; the support matrix; the docsite Pedersen guide and API cheat sheet; the §15 Java harness (`./gradlew :zeroj-bls12381:g1PedersenBenchmark`); the ADR-0051 status note. |

### Admission check (D1 lifecycle, M5)

| Prerequisite | Evidence |
|---|---|
| Accepted ADR | Accepted (design) 2026-10-22 by maintainer Satya. The r5 amendment (delta width ≤ 253) was made under the maintainer's standing instruction of 2026-10-22 to finish every milestone without waiting for approval; it tightens a check and awaits the maintainer's explicit acceptance on PR #103 |
| Normative spec | `pedersen-bls12-381-g1-v1` r1 signed off at M0; r2 (delta width) records the one amendment |
| Three reproductions of `G` and `H` (D2) | Java `PedersenG1ReproductionTest`; the independent Python reference; on-chain `bls12_381_G1_hashToGroup` in the Julc VM (`PedersenG1LibVmTest`) and on Yaci DevKit (`G1PedersenNodeEvidenceE2ETest`) |
| §13 vectors and their independent recomputation | 260 + 182 cases from the spec-only generator; recomputed with py_ecc by an independent reviewer and by a second reviewer's own code: no mismatch |
| Descriptors | `CommitmentProfiles.PEDERSEN_BLS12_381_G1_V1`/`_BYTES_V1` (M1); `G1PedersenCommitment.PROFILE == CommitmentProfiles…` tested |
| M4 on-chain parity | Every on-chain-applicable vector case gives the off-chain verdict in the Julc VM; strict decoding, `scalarMul` and MSM evidence agree between the VM and the DevKit node on every case; DevKit E2E of the three example flows with tampered negatives |

Every prerequisite has its evidence, so registry r7 records the three entries `active`. Because the
r5 amendment is not yet explicitly accepted by a named maintainer, r7 takes effect only when PR #103
is merged; merging records that acceptance. Until then the registry on `main` keeps the two
profiles `reserved` and does not yet list the basis set.

### Invariants

- **I1:** three reproductions, above.
- **I2:** every D3 step and its class tested, including both infinity negatives and the order-3,
  `x = 4` and mixed-order points; round trip on every accepted input; node and VM agree.
- **I3:** check 1 at `q − 1`, `q`, `q + 1`, `−1`; check 2 for `k ∈ {1, 64, 252, 253, 254}` and
  invalid widths; on-chain, exact builtin counts show no `scalarMul` on any refused scalar, width or
  delta; off-chain, every provider call goes through a canonical-scalar guard
  (`requireMultipliable`), so a negative or out-of-range value is a bug that throws, never a
  multiplication.
- **I4:** the §10.2 values, three sources agreeing for every length and chunking, stream bounds
  before any read or digest, the probe octet never hashed; the on-chain map agrees on every vector
  payload a transaction can carry.
- **I5:** typed API, `PROFILE_MISMATCH` for every cross-profile and Jubjub envelope; on-chain the
  validator's configuration fixes the profile (documented in `PedersenG1Lib`).
- **I6:** generation calls only `g1SecretScalarMul` (counting stub providers); no secret in any
  message; redacted holders; wiped buffers; no constant-time claim.
- **I7:** pure Java and blst give identical commitments and verdicts on every vector and on
  parity sweeps. Decoding, envelopes, sums and deltas are shared pure-Java code, so parity there is
  by construction; the providers differ only in the multiplications.
- **I8, I9:** M1, unchanged; `git diff 2b7e9c5 -- zeroj-circuit-lib` is empty and no Jubjub
  vector file changed.
- **I10:** above (M4 parity).
- **I11:** every figure is a record; no check was removed or weakened for speed.

### Seeded faults

Each fault was applied to the source alone, the affected suites run, and the source restored.
Off-chain (the `org.zeroj.bls12381.pedersen` tests, 125 at the time), all killed:

| Fault | Tests failing |
|---|---:|
| Reduce instead of reject (check 1) | 18 |
| Skip the subgroup step | 11 |
| Swap `G` and `H` | 97 |
| Drop the length suffix of the byte map | 9 |
| Use the Jubjub order `l` for `q` | 26 |
| Signed delta passed to the multiplication | 7 |
| Delta width 254 accepted | 3 |
| Generation without the result checks | 1 |
| Generation through the public multiplication | 5 |
| Check 2 off by one | 9 |
| Accept any infinity encoding | 9 |
| No scalar snapshot | 3 |

On-chain (the `zeroj-onchain-julc` Pedersen VM tests, 17): no check 1 (4), no length check before
`uncompress` (1, through the exact `uncompress` count), delta width 254 accepted (2), signed delta
passed to `scalarMul` (1, through the argument of the traced multiplication), no delta bound (2),
length suffix dropped (4), `G` and `H` swapped (7): all killed.

Two faults are equivalent and survive by construction:
- **No canonical round trip on-chain.** The VM's and the node's `uncompress` already reject every
  non-canonical encoding (builtin evidence), so removing `compress(point) == bytes` changes no
  verdict. The check stays as defence in depth, because CIP-0381 does not specify which encodings
  `uncompress` accepts.
- **A negative delta multiplied directly off-chain.** `G1Point.scalarMul` negates internally, so
  `[δ]·G` and `−[|δ|]·G` are the same point. The library routes the multiplication through
  `requireMultipliable`, which throws on a negative value (the "signed delta" fault above); a
  direct call bypassing it would not be observable, so that part of I3 rests on code structure.

A second reviewer ran an independent mutation round in a separate copy of the repository, with
the same outcome.

### Changes made during implementation

- **Delta width 253 (design amendment, r5).** A reviewer showed that at `k_δ = 254` both `δ` and
  `δ − q` satisfy `|δ| < 2^254` and move a commitment to the same point, so a redeemer's delta was
  not unique, contrary to this ADR's threat model. The signed range `(−2^k, 2^k)` holds at most `q`
  integers exactly when `k ≤ 253`. D5, spec §6.4 and §8 (r2), registry §7 and §13.4 (r7), Java,
  `PedersenG1Lib`, the generator and the vectors now use `1 ≤ k_δ ≤ 253`; check 2 keeps 254. The
  maintainer had authorized completing all milestones without waiting for approval; this
  amendment is listed for the maintainer's review on the PR.
- **Generation checks on provider results.** Each provider result must be on the curve, and the
  public sum must be a valid subgroup point, so two invalid results cannot cancel into a
  commitment; verification trusts the provider's public multiplication (spec §8 r2).
- **Lazy bases on-chain.** Julc evaluates zero-argument library methods once at script start; the
  bases are decompressed only inside the operations that use them, saving about 106M steps for
  decoding, sums and deltas.
- **Exact builtin counts.** The Julc VM's builtin trace keeps only the last 20 builtins, so the
  "no `scalarMul` before the guard" checks use a marked PV11 cost model instead.

### Follow-ups (not in this ADR)

- **Shared-primitive performance.** `PureJavaBls12381Provider` and the blst provider re-validate
  their input points with an affine `[q]P` (about 4.3 ms) on every call; a Jacobian or
  endomorphism subgroup check (about 0.6 ms for the Jacobian form) and a pre-validated-base path
  for public verification would roughly halve verification time. Both are shared R3 primitives and
  need their own design.
- **Julc annotation processor.** After an edit to an `@OnchainLibrary`, a warm Gradle daemon can
  fail `:zeroj-integration-tests:compileTestJava` with "Undefined variable"; `--stop` or a forked
  compiler avoids it.
- **`YaciHelper.findAllUtxos`** reads only the first page of 100 UTxOs.
- **Vector format:** the order "value before blinding" and "`m` before `r`" cannot be pinned by
  file cases (both give the same class), and length bounds on `verifyBytes*` have no file
  operation; Java tests cover them.

## Design questions for the maintainer

All six were decided by maintainer Satya on 2026-10-22, each as leaned (option (a)). The other
options are kept for the record.

- **Q1 — Placement. Decided: (a).** (a) `org.zeroj.bls12381.pedersen` in `zeroj-bls12381`, which
  adds a `zeroj-api` dependency; (b) a new module; (c) `zeroj-circuit-lib`.
- **Q2 — Value base. Decided: (a).** (a) `G` and `H` both hashed; (b) `G = g₁`, `H` hashed.
- **Q3 — Scalar-only bytes mode. Decided: (a).** (a) None. A supplied-scalar check is a
  scalar-profile opening, documented as authenticating only `s`. (b) An explicit scalar-only
  verification mode on the bytes type.
- **Q4 — #99. Decided: (a).** (a) Built-in descriptors owned by `zeroj-api` (D8); (b) reserved
  identifiers rejected in `define`; (c) drop duplicate rejection. The D8 alternative of a `define`
  that returns the built-in instance is not taken: mixed versions stay unsupported.
- **Q5 — On-chain deliverable. Decided: (a).** (a) A published library plus test-source example
  validators; (b) examples only.
- **Q6 — ADR-0051 M5. Decided: (a).** (a) This ADR takes the G1 bases out of ADR-0051 M5, and the
  sigma proofs stay gated on D7; (b) leave M5 intact and block this ADR on D7.

## Revision history

- **r1 (2026-10-21):** Initial proposal for #95, folding in #99.
- **r2 (2026-10-21; responds to review of `937087c5ec4a8a62e5a8651f0f4012bfaf0978fb`):**
  - F1 → admission is separated from spec approval, descriptor reservation and implementation
    (D1 lifecycle). Registry r6 keeps the entries `reserved`; r7 admits them at M5 after every
    prerequisite, including the M4 on-chain base reproduction (D1, D2, Compatibility, M0, M1,
    M5). M1 no longer depends on the rest of M0.
  - F2 → D3 step 4 is an explicit identity branch that returns and stops. Steps 5–7 apply only
    to finite encodings, and `0x80 ‖ 0^47` is a step-7 negative (D3, I2, M2, tests).
  - F3 → the coordinated upgrade is recorded: mixed pre-/post-M1 binaries fail closed and are
    unsupported (BOM or one pinned version, release notes, M1 check). The alternative of a
    `define` that returns the built-in instance is recorded (D8, I8, Compatibility, M1).
  - F4 → the on-chain trust boundary is stated as a split: length before `uncompress`, subgroup
    via the CIP-0381 element contract, canonicality by round trip before use, and scalar and
    delta guards before multiplication (D9, I10, Risks).
  - F5 → the guarantee of rejection before any read is limited to arrays and declared
    lengths/maxima; stream content is bounded by counting and the probe (D4, I4, tests).
  - F6 → long-DST reduction is described as RFC 9380 §5.3.3 behaviour, separate from the
    empty-tag question (Related findings).

  No base, tag, mapping, encoding or other cryptographic choice changed.
- **r3 (2026-10-22; after Codex approval of `d1c31ca8ba338f8e96c0769dbd600e4c22a1cde6`):** maintainer
  Satya accepted the design and decided Q1–Q6 as leaned (a). Status, Date and the questions section
  record it. No decision, invariant, milestone or cryptographic choice changed.
- **r4 (2026-10-22; M0/M1 review round 1, three Claude reviewers and Codex on `f600d7c`):** wording
  only. D3 and the test list say `0x80 ‖ 0^47` decodes to `(0, 2)` (the sort flag picks the smaller
  root), not `(0, ±2)`; D8 records that the `define`-returns-the-built-in alternative is not taken
  (Q4 decided). The spec-level fixes from the same round are in `pedersen-bls12-381-g1-v1` r1 and
  `commitment-profiles-v1` r6. No decision, invariant or milestone changed.
- **r5 (2026-10-23; implementation of M2–M5, three Claude reviewers and Codex on the uncommitted
  M2–M4 work):** Status and the "Implementation evidence" section record the implementation, the
  admission check and the evidence. **Design amendment:** the public-delta width is `1 ≤ k_δ ≤ 253`
  (D5, spec r2, registry r7), so that a bounded delta is unique mod `q`. No other decision,
  invariant, base, tag, mapping or encoding changed.
