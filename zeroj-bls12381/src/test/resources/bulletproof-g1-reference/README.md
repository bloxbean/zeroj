# Second implementation: `bulletproof-range-bls12-381-g1-v1` (ADR-0061 M0)

`bulletproof_range_reference.py` is a stand-alone Python implementation of the Bulletproof range
proof `bulletproof-range-bls12-381-g1-v1`, its generator set `bulletproof-bls12-381-g1-gens-v1`,
its SHAKE128 duplex-sponge transcript and its codecs. It was written **only from the
specifications** so that the vectors it produces can be checked against the Java implementation
independently. It is ZeroJ's own second implementation; it is **not** an official, standard or
third-party reference, and agreement with it is not a security claim.

It is a **public test reference**. Nothing in it is constant-time; it uses Python integers and
variable-time arithmetic throughout. It must never handle real secrets.

## Spec revision implemented

`docs/specs/bulletproof-range-bls12-381-g1-v1.md`, **draft r1 (2026-10-24) as amended** with the
M0 second-implementation findings (spec §14). The file read had SHA-256
`12eb1b923926acd8889694284c22912793adb8aea04cfa904cf10f9738326943`. The amendments that changed
this script:

- `ctx` must be 1 to 1,024 octets. An empty `ctx` is `INVALID_CONFIGURATION` in both the prover
  and the verifier (§5.1, §7.1, §8.1, §9).
- §8.1 order: configuration, then `V`'s decoder, then the proof length, then the proof's fields
  **in proof order** (`A, S, T₁, T₂` points; `t̂, τ_x, μ` scalars; `L_1, R_1 … L_k, R_k` points;
  `a, b` scalars), with the first failure reported. `V = O → false` now comes **after** the format
  checks.
- §8.3: check 1 is evaluated before check 2, and both are always evaluated. The `layer` is the
  first failing check.
- §5.3: `a` and `b` are not absorbed. The `.A64` in the tag only describes the trailing octets.
  This script already behaved this way.
- §10: the sigma harness is test-only. The ten extra A.3.1 vectors are reported but not gated.

The first version of this script implemented the unamended r1. Its findings are kept below as a
record, each marked with how the amendment resolved it.

## Running

Python 3.13, standard library only (`hashlib`, `json`, `argparse`, `secrets`, `os`, `sys`,
`importlib`). Run in isolated mode from any directory:

```bash
python3 -I -B bulletproof_range_reference.py --self-test         # exit 0 only if every gated check passes (about 4 minutes)
python3 -I -B bulletproof_range_reference.py --print-generators  # JSON: DST, 129 encodings in order, D_gens
python3 -I -B bulletproof_range_reference.py --print-trace       # JSON: the fixed n = 16 example
```

`generators-v1.json` next to the script is the saved output of `--print-generators`. It is the
input for spec Appendix A.

The CFRG vectors are read from the repository's unchanged copies at
`../../../../../zeroj-test-vectors/src/main/resources/test-vectors/cfrg-drafts-03/`, resolved
relative to the script (spec §10). `--vectors-dir DIR` overrides that path. The self-test checks
each file's SHA-256 against the spec §10 pins. This directory holds no copies of its own.

The curve layer is imported by path from the sibling directory
`../pedersen-g1-reference/bls12_381_g1_reference.py`. That is ZeroJ's earlier independent
BLS12-381 G1 reference (field, RFC 9380 `hash_to_curve`, Zcash `compress`, the profile's strict
decoder `strict_decode`, `derive_basis`). It is used unmodified as a library and is not copied.
On top of it this script adds its own Jacobian arithmetic for speed. The self-test cross-checks
that arithmetic against the module's affine arithmetic.

## Independence: what was read

Read:

- `bulletproof-range-bls12-381-g1-v1.md`, in full, twice: draft r1 as first issued, then the
  amended r1 in `docs/specs/`. The amended copy was re-read in full, with attention to §5.1, §5.3,
  §7.1, §7.5, §8.1, §8.3, §8.4, §9 and §10.
- `pedersen-bls12-381-g1-v1.md` (r2): §1 notation, §2 (basis derivation, pinned `G` and `H`,
  rules), §3 profiles, §4 point encoding and strict decoder. The pinned `G`/`H` hex was
  transcribed by hand from §2.2.
- Bünz et al., *Bulletproofs* (ePrint 2017/1066), from the bundled text extraction: §3 (the
  overview, Protocol 1, Protocol 2, §3.1), §4.1 lines (36)–(68), §4.2, §6.2 lines (95)–(105). The
  PDF was not opened. Its math glyphs are garbled in the extraction but readable.
- `draft-irtf-cfrg-fiat-shamir-03`: table of contents, §2 (2.1–2.4), §3 (3.1, 3.2.1–3.2.3),
  §4 (4.1, 4.2.1–4.2.3), §5 (5.1, 5.2), §6 (6.1.1–6.1.5, 6.2.1–6.2.5), §7, §8.1 (first lines),
  §9 (9.1, 9.2). Appendix B was used only through the JSON files.
- `draft-irtf-cfrg-sigma-protocols-03`: table of contents, §2 (2.1–2.3.2), §3 (3.1–3.6),
  §4 (4.1–4.4), §5 (5.1–5.6), §7.3, §8 (8.1, 8.2), and Appendix A's introduction and A.1. A.3 was
  used only through the JSON files.
- The four CFRG JSON vector files. The first run used a bundle copy, and this one uses the
  repository copies (same SHA-256). Also the `README.md` in
  `zeroj-test-vectors/.../cfrg-drafts-03/`, which gives their provenance.
- `bls12_381_g1_reference.py` (to learn its API: constants, `strict_decode`, `compress`,
  `hash_to_curve`, `derive_basis`, `scalar_mul`, `point_add`) and its README.
- RFC 9380 and FIPS 202 were not read directly. They enter only through the curve module and
  CPython's `hashlib.shake_128`.

Not read: any `.java` file, any other repository file, the ZeroJ ADRs (including ADR-0061), the
web, and the CFRG drafts' proof-of-concept Python code. No third-party package was used, and git
was not run.

**Incident, recorded for transparency.** After the first version and its self-test were finished,
a `find` over the working tree (run to check for stray `.pyc` files) printed the names of other
repository files, including Java test class names. None of them was opened. The second
implementation's code had been written before that listing and was not changed in response to
it.

## What it implements

- **fiat-shamir-03.** The SHAKE128 duplex sponge (§3.2, R = 168). `hashlib.shake_128.digest(n)`
  does not stream, so the reader is emulated: the first squeeze after an absorb freezes the
  absorbed bytes (the `Copy().Finalize()`), and each later squeeze returns the next slice of
  `SHAKE128(frozen)`. Also `DeriveSessionID`, `LE`, `LE2IP`, `SerializeVarLenString` and its
  deserializer, `SerializeUint`/`DeserializeUint`, `DecodeUint`/`DecodeField` (m = 1), and the
  big-endian `SerializeField` of B.1.6.
- **sigma-03 §8.2 codecs.** A group element is 48 octets, read by the profile's strict decoder,
  and the identity is then rejected. A scalar is 32 octets big-endian, and anything `≥ q` is
  rejected.
- **A test-only sigma-03 harness** (spec §10): a generic verifier for sparse linear relations. It
  has a parser for the §3.6 encoding, the §3.5 instance validation (checks 1–10), map/image
  evaluation, and `VerifyBatchable` and `VerifyCompact`. It does not prove. sigma-03 defines no
  `LinearRelation` deserializer, so the parser is our own inverse of §3.6: the element count is
  taken from the bytes left after the equations, in 48-octet chunks.
- **The Bulletproof protocol.**
  - Generators and their checks (§2.2): the 131 points, none `O`, no two equal or negatives of
    each other, all in G1.
  - `D_gens`.
  - The tag (§5.1, with a non-empty `ctx`), the instance (§5.2) and the rounds (§5.3).
  - The proof encoding (§6).
  - The prover: the §7.1 refusals in order, CSPRNG nonces and restarts (§7.3), and the §7.5
    test-nonce seam `_prove_with_test_nonces`, which fails where §7.3 would restart.
  - The verifier: the amended §8.1 order, challenge recomputation with zero rejection, `δ`, `s_i`
    by the MSB-first rule, and check 1 then check 2. Both checks are always evaluated, naively
    term by term, and the layer is the first failing check.
  - The §9 error classes, as exception classes that carry their class name in `error_class`.
- **An independent check-2 cross-check.** `_verify_ipa_recursive` runs Protocol 1 and Protocol 2
  literally: it folds the generators and `P` round by round (paper (29)–(31)) and makes the final
  check (16). It does not use the `s_i` bit rule.

## Self-test coverage

`--self-test` prints one PASS/FAIL line per gated check, INFO lines for the reported-only group,
and a per-group summary. It exits non-zero on any gated failure.

- **CFRG vectors.**
  - Vector-file SHA-256 pins.
  - fiat-shamir-03 B.1.1, B.1.2, B.1.4–B.1.8, B.1.10, B.1.11 and B.2.1–B.2.11, each reported by
    `Id`.
  - The emulated reader compared with a one-shot `SHAKE128(session_id ‖ zeros(136) ‖ inputs)`.
  - sigma-03 A.3.1 for the four gated vectors. Each check reproduces `SessionId` from `Tag`,
    recomputes the challenge (for compact proofs, equal to the NARG challenge), verifies the proof,
    and confirms that the published witness satisfies the instance.
  - The other ten A.3.1 vectors in `sigma-valid-extra`, **reported, not gated**.
  - All 32 A.3.2 vectors, each with its accept/reject outcome, the layer where it was rejected and
    the number of challenges derived. A1, A3–A6, B1 and B2 must be rejected at deserialization
    with 0 challenges derived. They are also run directly against the §3 decoders.
- **Generators.**
  - `DST_BP` is 70 octets.
  - Derivation and the §2.2 checks: a fast x-coordinate check, and a brute-force check over all
    8,515 pairs.
  - Every point is in G1.
  - Every encoding round-trips through the strict decoder.
  - The pinned profile bases `G` and `H` equal their RFC 9380 recomputation.
  - The message for `G_5` is `47 00 00 00 05`.
  - The Jacobian arithmetic agrees with the module's affine arithmetic.
- **Transcript.** The spec §5.1 example tag is reproduced byte for byte, the 1-octet-`ctx` tag
  ends `/CTX0001:00`, the instance is 244 octets long, and the proof lengths are 736/832/928 for
  n = 16/32/64.
- **Round trips** for each n in {16, 32, 64}:
  - `v = 0` (with nonzero blinding), `1`, `2^n − 1` and a random value, all with test nonces.
    Each case has its own seed. Proving twice with the same seed gives the same proof, and the
    verifier reproduces the session id and every challenge.
  - A CSPRNG proof.
  - `V` passed as an already-decoded commitment.
  - The recursive IPA verifier.
  - Also: `ctx` of exactly 1 and exactly 1,024 octets, and different seeds giving different
    proofs. No case uses an empty `ctx`.
- **Prover refusals.**
  - `v = 2^n` and `v = q − 1` (`OUT_OF_RANGE`).
  - `v` or `γ` equal to `q` or `−1`, or a `bool` (`NON_CANONICAL_SCALAR`).
  - `(0, 0)` (`INVALID_STATEMENT`).
  - `n ∈ {0, 8, 17, 128, −16, 63, "16"}`, a 1,025-octet `ctx`, an **empty `ctx`** (both provers)
    and a non-bytes `ctx` (`INVALID_CONFIGURATION`).
  - Refusal-order cases, including empty `ctx` with `v = q`, where configuration comes first.
- **Verifier negatives** (n = 16):
  - Substituting each of the 12 points with another valid point, and each of the 5 scalars with
    `+1`.
  - Bit flips at each position class of every field: compression, infinity and sort flags, the
    x-coordinate LSB and a middle bit, and the scalar top bit and LSB.
  - A proof truncated by one octet, extended by one octet, or empty, and an n = 32 length.
  - The identity as a proof point, an order-3 point, and `x = P_381`.
  - Each scalar re-encoded as `s + q`.
  - Verification under a different n, a different `ctx`, a 1-octet prefix of `ctx`, an **empty
    `ctx` (`INVALID_CONFIGURATION`, also with an identity `V`)**, a different `V`, `−V`, `V = O`
    (both as octets and decoded), a non-subgroup `V`, a short `V`, a bad n, or an oversized `ctx`.
  - `L_1` and `R_1` swapped.
  - Each of `y, z, x, x_u, x_1 … x_4` forced to zero through the `_CHALLENGE_HOOK` seam. The
    verifier must return false at the challenge layer, and the test-nonce prover must fail. The
    CSPRNG prover must restart once.
  - Cheating provers that isolate the checks:
    - `v = 2^n`: check 1 fails, check 2 holds.
    - A non-bit `a_L` entry: check 1 fails.
    - `a + 1`: check 2 fails, check 1 holds.
  - A mutant verifier using an LSB-first `s_i` rule rejects the honest proof at check 2.
- **Decoding order** (amended §8.1):
  - Configuration comes before `V`.
  - A bad `V` with a bad length gives `V`'s class.
  - `V = O` with a bad length gives `MALFORMED_ENCODING` at the length layer.
  - `V = O` with an identity `A` gives `MALFORMED_ENCODING` at the point layer.
  - `V = O` with a non-canonical `b` gives `NON_CANONICAL_SCALAR`.
  - `V = O` with a well-formed proof gives `false` at the statement layer.
  - In proof order, the earlier defect is the one reported:

    | Earlier field | Later field | Reported |
    |---|---|---|
    | bad `t̂` | identity `R_4` | `NON_CANONICAL_SCALAR` |
    | identity `S` | bad `μ` | `MALFORMED_ENCODING` |
    | non-subgroup `R_4` | bad `a` | `NOT_IN_SUBGROUP` |
    | non-subgroup `S` | identity `T₂` | `NOT_IN_SUBGROUP` |
- **Transcript-omission mutants** (`_TRANSCRIPT_MUTATION` seam). Four mutants: drop `V` from the
  instance, drop `ctx` from the tag, drop `D_gens`, or swap `G` and `H`. Each must change every
  challenge. The mutated verifier must reject the original proof, and the real verifier must
  reject the mutated prover's proof.

## `--print-trace` fixed example

`n = 16`, `v = 12345`, blinding
`γ = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`, `ctx = "hello"`
(non-empty), nonce seed `00 01 … 1f`. The output has the tag, the session id, the commitment, the
instance hex, every challenge in decimal and the proof hex. It is deterministic, and is unchanged
by the amendment.

## Spec findings and their status

The spec's algebra was compared line by line with the paper. Checked: (44) and (47) for `A` and
`S`; `l(X)` and `r(X)`; (53) for `T_i`; (58)–(62); (64) for `h'`; Protocol 2 (21)–(24) for
`c_L`, `c_R`, `L`, `R` and (29)–(34) for the folding; Protocol 1 (8) for `P·u^{x·c}`; and §6.2
(97), (98), (101), (102) and (105). **No disagreement in the algebra was found.** Honest proofs
verify, and the literal recursive verifier agrees with the unrolled check 2.

The findings against the unamended r1, and how the amended r1 resolves each:

1. **§8.1 decoding order: points then scalars, against byte order.** *Resolved:* proof order, first
   failure reported. Implemented and pinned by the order cases above.
2. **§11 `layer` when both checks fail.** *Resolved* (§8.3): the first failing check in the order
   check 1, check 2, with both always evaluated. In a direct check, both checks failed in every
   case tried: substituting `A`, `S`, `T₁` or `T₂`, adding 1 to `t̂` or `τ_x`, and changing `ctx`.
   So the rule matters for vectors.
3. **§10 A.3.2 scope ("all discrete_logarithm") was inaccurate.** F2/F2b are `dleq`
   (two equations), E1–E3 are synthetic instances, and E1–E4 need §3.5. *Resolved:* §10 now
   describes this and the test-only harness. The ten extra A.3.1 vectors are reported, not gated.
4. **§8.3 check 2 departs from paper (105) on purpose** (independent `U` instead of `g`).
   *Resolved:* now stated in §8.3.
5. **The §8.3 MSB-first `s_i` rule** matches Protocol 2's folding. No change was needed. It is
   confirmed by the recursive verifier and by the LSB-first mutant.
6. **`.A64` against "a, b not absorbed".** *Resolved* (§5.3): they are not absorbed, and `.A64`
   only describes the octets.
7. **Identity `V` used to return `false` before the length check.** *Resolved:* `V = O → false`
   is now step 5, after the format checks. Implemented.
8. **§8.4 "fixed function of n".** *Resolved:* the work is bounded by n and may stop early.
9. **An empty `ctx` defeated fiat-shamir-03 §5.1 requirement 3.** *Resolved:* `ctx` must be 1 to
   1,024 octets. Implemented in the prover and the verifier, with negatives.
10. **§7.5 nonces depend only on the seed.** *Resolved* (§7.5): one seed per positive vector. The
    self-test uses a distinct seed per positive case.
11. **§2.2 subgroup check of the generators.** *Resolved:* membership is now stated. It was
    already checked here.
12. **No rule for a `V` passed as a decoded commitment.** *Resolved* (§8.1 step 2): it is valid by
    construction. This script only asserts that the point is on the curve.

**Still open in the amended text (minor; no implementation effect here):**

- **Classifying `V`-decoder failures.** §9 assigns `V`'s decoder failures to the classes
  `MALFORMED_ENCODING` and `NOT_IN_SUBGROUP`. §11's `layer` list has `statement`, but the spec
  does not say whether a `V` decoding failure is recorded as `statement` or as `point`. This
  script records it as `statement`.
- **Error class for a non-bytes `ctx`.** §7.1 and §8.1 do not say what class a `ctx` of the wrong
  type gets. This script raises `INVALID_CONFIGURATION`; Java's type system may make the case
  moot.

## Not implemented

All spec requirements are implemented. Not attempted:

- the extension-field, sumcheck and TurboSHAKE128 vectors (out of scope in §10);
- a sigma prover;
- reproducing the A.3.1 NARG strings from the A.1 seeded PRNG. A.1 does not pin how the PRNG
  output becomes scalars, and verification does not need it.

## Limits

Passing this self-test shows that this code agrees with the CFRG vectors and that its prover and
verifier are consistent with each other. It is not evidence of soundness or zero-knowledge, and
it is not a production-safety claim. An error shared by the spec text and this implementation
(for example, in a part of the transcript design that both follow) would not be caught here.
Cross-checking against the Java implementation, and review, remain necessary.
