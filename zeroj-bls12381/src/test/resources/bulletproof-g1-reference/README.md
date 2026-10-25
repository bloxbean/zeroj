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

`docs/specs/bulletproof-range-bls12-381-g1-v1.md`, draft r1 (2026-10-24) as revised after M0
review round 1. The exact file implemented has SHA-256:

```
a0a5c8447e48997a36723f9158c5597776a62e098cde4ff2cf11de69d6a3fd06
```

Afterwards, the integrating author made a wording-only edit to the §8.1 explanation of the
non-subgroup `V` example, stating the mod-3 condition on the integer representative of `−z²`. It
changes no normative rule, byte or check. The spec committed with this script then has SHA-256
`b3cf6982fc8a1bc57418809f92cda060b7267069934388bcb8c0c721a27664f7`.

**Current reviewed spec.** M0 review rounds 2 and 3 (commits `1d48bd2` and `a42a669`) amended the
spec again. The file reviewed and approved at `d906c57` has SHA-256:

```
5cf961d579948c6cf1a1b8c3f0fa13176b7ba070d55448c10152d0002da555f1
```

None of those amendments changes a byte this script computes or checks:
- §1.1: wording of the derived-commitment remark (`(v₁ − v₂) mod q ∈ [0, 2^n)`).
- §7.3: the Java prover's entropy trust assumption and its `SecureRandom` algorithm allowlist.
  These are Java API rules, outside this script.
- §7.5: the scope of the no-nonce-API rule, the `org.zeroj.bls12381.bulletproofs` package.
- §11: the vector file lists the generator encodings (`generators-v1.json`).

The only script change in those rounds pins the expected decoder class of each A.3.2 invalid
encoding (see the integration notes below).

Earlier states of r1 that this script also implemented, for the record:
- `12eb1b92…6943`: ctx made non-empty, and the first proof-order decoding.
- An unhashed first issue: the original draft.

## Changes for review round 1

Spec-driven:

1. **Tag (§5.1).** The round string no longer ends with `.A64`. This changes the session id and
   every challenge. `--print-trace` was regenerated and the new record is pinned.
2. **§8.1 order.**
   1. Configuration (n, and `ctx` of 1 to 1,024 octets).
   2. The proof **length**, before anything is decoded, `V` included.
   3. The proof fields in proof order, with the first failure reported.
   4. `V`: given as octets, it goes through the profile's strict decoder. **Given already decoded,
      it is not trusted**: an affine tuple must pass the full on-curve check (else
      `MALFORMED_ENCODING`) and the prime-order subgroup check (else `NOT_IN_SUBGROUP`).
   5. `V = O → false`.

   There is a regression test for `V' = [7]·G + [11]·H + (0, 2)`, where `(0, 2)` has order 3.
   Passed decoded, or as octets, `V'` gives `NOT_IN_SUBGROUP` at the `statement` layer. That
   includes an honest proof for `[7]·G + [11]·H` offered against `V'`. The previous version
   trusted a decoded tuple, so check 1 could pass or fail depending on `z`. The order tests were
   updated: "bad `V` + bad length" is now the length class, and a bad `V` with a bad proof field
   is the field's class.
3. **§7.1 and §7.3.** The refusal order is configuration, check 1, then `v ≥ 2^n`. A test counts
   that these refusals make no scalar multiplication. Then `V` is computed and an identity `V` is
   refused.
   - Restarts are bounded at **8 attempts**, then `ProverRestartsExhausted` (the analogue of Java's
     `IllegalStateException`) is raised and no proof is emitted. A test forces every `x` to 0 and
     counts exactly 8 attempts.
   - The test-nonce prover fails closed on any restart.
   - Wrong argument types (`bool`/`str` for `v` or `n`, `str` for `ctx`) raise `TypeError`. They
     are API-binding errors, not vector cases (§11).

Evidence quality:

4. **Known-answer pins, as fixed literals in the script.**
   - `DST_BP` hex.
   - `D_gens = 69abb9e7…ef19`.
   - `G_0`, `H_63` and `U`.
   - All 129 encodings, compared against `generators-v1.json`. Its order, names, `DSTHex`,
     `D_gens`, and the SHA-256 recomputed from its encodings are all checked.
   - The complete `--print-trace` record: tag, `sessionIdHex`, `commitmentHex`, `instanceHex`,
     every challenge, and `proofHex`. The pinned proof must also verify against the pinned
     commitment.

   Each of four mutations was applied to a scratch copy, and the full self-test then fails:

   | Mutation | Failing checks |
   |---|---|
   | `DST_BP` changed by one character (`ZeroJ` → `ZeroK`) | 15 |
   | Challenges decoded big-endian | 10 |
   | `G`/`H` order swapped in the instance | 11 |
   | Test-nonce order changed (`τ₁`, `τ₂` before `s_L`) | 9 |
5. **sigma-03 A.3.2: every class asserts its expected outcome and rejection layer.**

   | Class | Expected outcome |
   |---|---|
   | A | point deserialization, with 0 challenges derived |
   | B | scalar deserialization, with 0 challenges derived |
   | C | length |
   | D1 | simulated commitment is `O` |
   | E | instance validation |
   | F and H, except the controls | verification, with 1 challenge derived |
   | F1, F2 controls | accept |
6. **Unexpected exceptions are FAIL lines.** Checks run through `_Results.guard`, so an
   unexpected exception becomes a counted FAIL line. Each section is also wrapped, so an
   exception outside a guarded check is a counted FAIL and the next section still runs.
7. **Tautological checks replaced.**
   - For A.3.1, the old "challenge recomputed" checks are gone. In their place, a test-only seam
     adds 1 to the derived challenge, and the proof must then fail at verification. The proof must
     also fail with `response[0] + 1`.
   - The generator digest is compared with the pinned literal, not with a SHA-256 the script
     computed itself.
8. **New transcript mutants.**
   - Dropping `n` from the instance changes every challenge, and the proofs fail both ways.
   - Changing one prover message changes every **later** challenge and **no earlier** one. The
     messages tested are `A`, `T₁`, `t̂`, `L_2` and `R_4`.
   - Changing `a` or `b` changes no challenge, because they are not absorbed (§5.3).

## Running

Python 3.13, standard library only (`hashlib`, `json`, `argparse`, `secrets`, `os`, `sys`,
`importlib`). Run in isolated mode from any directory:

```bash
python3 -I -B bulletproof_range_reference.py --self-test         # exit 0 only if every gated check passes (about 4 minutes)
python3 -I -B bulletproof_range_reference.py --print-generators  # JSON: DST, 129 encodings in order, D_gens
python3 -I -B bulletproof_range_reference.py --print-trace       # JSON: the fixed n = 16 example
```

`generators-v1.json` next to the script is the saved output of `--print-generators`. It is the
source of spec Appendix A, which py_ecc and the Java implementation reproduce independently.

The CFRG vectors are read from the repository's unchanged copies at
`../../../../../zeroj-test-vectors/src/main/resources/test-vectors/cfrg-drafts-03/`, resolved
relative to the script (spec §10). `--vectors-dir DIR` overrides that path. Each file's SHA-256 is
checked against the spec §10 pins.

The curve layer is imported by path from
`../pedersen-g1-reference/bls12_381_g1_reference.py`. That is ZeroJ's earlier independent
BLS12-381 G1 reference (field, RFC 9380 `hash_to_curve`, Zcash `compress`, the profile's strict
decoder, `derive_basis`, `in_subgroup`). It is used unmodified as a library. On top of it this
script adds its own Jacobian arithmetic. The self-test cross-checks that arithmetic against the
module's affine arithmetic.

## Independence: what was read

Read:

- `bulletproof-range-bls12-381-g1-v1.md`, in full, three times: the draft r1 as first issued; the
  first amended r1; and the round-1 revision (hash above), including the new §1.1 and Appendix A.
- `pedersen-bls12-381-g1-v1.md` (r2): §1 notation, §2 (basis derivation, pinned `G` and `H`,
  rules), §3 profiles, §4 point encoding and strict decoder.
- Bünz et al., *Bulletproofs* (ePrint 2017/1066), from the bundled text extraction: §3 (the
  overview, Protocol 1, Protocol 2, §3.1), §4.1 lines (36)–(68), §4.2, §6.2 lines (95)–(105). The
  PDF was not opened.
- `draft-irtf-cfrg-fiat-shamir-03`: §2–§6 and §9, plus §7 and the start of §8. Appendix B was
  used only through the JSON files.
- `draft-irtf-cfrg-sigma-protocols-03`: §2–§5, §7.3, §8, and Appendix A's introduction and A.1.
  A.3 was used only through the JSON files.
- The four CFRG JSON vector files: a bundle copy first, then the repository copies, with the same
  SHA-256. Also the `README.md` in `zeroj-test-vectors/.../cfrg-drafts-03/`.
- `bls12_381_g1_reference.py` (for its API) and its README.
- RFC 9380 and FIPS 202 were not read directly. They enter only through the curve module and
  CPython's `hashlib.shake_128`.

Not read: any `.java` file, any other repository file, the ZeroJ ADRs (including ADR-0061), review
reports, the web, and the CFRG drafts' proof-of-concept Python code. No third-party package was
used, and git was not run. The review findings reached this work only as the coordinator's
instructions and the revised spec text.

**Incident, recorded for transparency.** After the first version and its self-test were finished,
a `find` over the working tree (run to check for stray `.pyc` files) printed the names of other
repository files, including Java test class names. None of them was opened. The code had been
written before that listing.

The known-answer trace pinned here is this script's own output. Its independent confirmation, by
external code, is done outside this directory by the coordinator. `D_gens` and the 129 encodings
are confirmed by py_ecc and Java (spec Appendix A).

## What it implements

- **fiat-shamir-03.** The SHAKE128 duplex sponge (§3.2, R = 168), with an emulated streaming
  reader over `hashlib.shake_128`. Also `DeriveSessionID`, `LE`, `LE2IP`,
  `SerializeVarLenString` and its deserializer, `SerializeUint`/`DeserializeUint`,
  `DecodeUint`/`DecodeField` (m = 1), and the big-endian `SerializeField` of B.1.6.
- **sigma-03 §8.2 codecs.** A group element is 48 octets, read by the strict decoder, and the
  identity is then rejected. A scalar is 32 octets big-endian, and anything `≥ q` is rejected.
- **A test-only sigma-03 harness** (spec §10): a generic sparse-linear-relation verifier. It has
  our own inverse of the §3.6 encoding (sigma-03 defines no deserializer), the §3.5 validation,
  map/image evaluation, and `VerifyBatchable` and `VerifyCompact`. It does not prove.
- **The Bulletproof protocol.**
  - Generators: the §2.2 checks, plus subgroup membership.
  - `D_gens`.
  - The tag (§5.1), the instance (§5.2) and the rounds (§5.3); `a` and `b` are not absorbed.
  - The proof encoding (§6).
  - The prover: the §7.1 refusals, CSPRNG nonces, the 8-attempt restart bound (§7.3), and the
    §7.5 test-nonce seam `_prove_with_test_nonces`, which fails closed.
  - The verifier: the §8.1 order, zero-challenge rejection, `δ`, MSB-first `s_i`, and check 1 then
    check 2. Both checks are always evaluated, naively term by term, and the layer is the first
    failing check.
  - The §9 error classes.
- **An independent check-2 cross-check.** `_verify_ipa_recursive` runs Protocol 1 and Protocol 2
  literally, folding round by round, without using the `s_i` bit rule.

Test-only seams, all module-level and none of them public API:
- `_TRANSCRIPT_MUTATION`: instance and tag omission mutants.
- `_CHALLENGE_HOOK`: forces a zero challenge.
- `_S_BIT_ORDER`: the LSB-first mutant.
- `_SIGMA_CHALLENGE_OFFSET`: the challenge-binding check for the sigma harness.
- `_prove_core(..., a_l_override)`: cheating provers.

## Self-test coverage

- **CFRG vectors.**
  - SHA-256 pins.
  - fiat-shamir-03 B.1.1, B.1.2, B.1.4–B.1.8, B.1.10, B.1.11 and B.2.1–B.2.11, each by `Id`.
  - The streaming emulation compared with a one-shot SHAKE128.
  - sigma-03 A.3.1, the four gated vectors. Each check reproduces `SessionId`, verifies the proof
    (the challenge is re-derived from tag, instance and commitment), fails with challenge + 1,
    fails with `response[0] + 1`, and confirms the published witness satisfies the instance.
  - The ten other A.3.1 vectors: reported, not gated.
  - All 32 A.3.2 vectors, with outcome and layer per class (above), plus direct decoder runs for
    A and B.
- **Generators.**
  - Pinned `DST_BP`, `D_gens`, `G_0`, `H_63` and `U`.
  - All 129 encodings against `generators-v1.json`.
  - The §2.2 checks, with a brute-force check over 8,515 pairs.
  - Subgroup membership and strict-decode round trips.
  - The profile bases `G` and `H` against RFC 9380.
  - The message for `G_5`.
  - Jacobian against affine arithmetic.
- **Known answer.** The full trace record pinned field by field.
- **Transcript shapes.**
  - The §5.1 example tag (no `.A64`).
  - The 1-octet-`ctx` tag.
  - The instance length, 244 octets.
  - The proof lengths 736, 832 and 928.
- **Round trips**, for n = 16, 32 and 64:
  - `v = 0`, `1`, `2^n − 1` and a random value with test nonces, each with its own seed;
  - determinism;
  - the recursive IPA verifier;
  - the CSPRNG prover with `V` as octets and as a validated decoded point;
  - `ctx` of 1 and of 1,024 octets;
  - different seeds giving different proofs.
- **Prover refusals.**
  - `OUT_OF_RANGE`, `NON_CANONICAL_SCALAR`, `INVALID_STATEMENT` and `INVALID_CONFIGURATION` cases,
    including an empty `ctx`.
  - `TypeError` for the API-binding cases.
  - The refusal order.
  - No curve work before the refusals.
- **Verifier negatives** (n = 16):
  - Each field substituted, and bit flips per position class.
  - Wrong lengths.
  - Identity, order-3 and `x = P_381` points.
  - Each scalar re-encoded as `s + q`.
  - Wrong n, `ctx` or `V`, and an empty `ctx`.
  - The `V'` regression, plus a decoded order-3 point and a decoded off-curve point.
  - `L_1` and `R_1` swapped.
  - Each zero challenge.
  - A single restart, and the 8-attempt bound.
  - The cheating provers that isolate check 1 and check 2.
  - Both checks evaluated even when check 1 fails.
  - The recursive verifier.
  - The LSB-first mutant.
- **Verifier order.** Fifteen §8.1 order cases.
- **Transcript mutants.**
  - Five omission or reordering mutants: drop `V`, drop `ctx`, drop `D_gens`, drop `n`, swap
    `G`/`H`.
  - The "later challenges only" checks for `A`, `T₁`, `t̂`, `L_2` and `R_4`.
  - `a` and `b` not absorbed.

## `--print-trace` fixed example

`n = 16`, `v = 12345`, blinding
`γ = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`, `ctx = "hello"`, nonce
seed `00 01 … 1f`. The record is pinned in `PIN_TRACE`. Its session id is
`aefa01ae578defec57e942213978543a2e26bdf81ae69ac9e95dd3bda9ec7556`.

## Findings history

The first round's twelve findings (proof-order decoding, the `layer` rule, the A.3.2 scope, the
`U` deviation from paper (105), the MSB-first rule, `.A64`, the identity-`V` order, bounded work,
non-empty `ctx`, the seed-only nonce stream, the subgroup check of the generators, and decoded
`V`) are all resolved in the spec now implemented. The review also found that a decoded `V` was
trusted without a subgroup check (Codex M0 F1, spec §8.1 step 4). That was a real soundness gap in
this script's previous version, and it is fixed here with a regression test.

The spec's algebra was compared line by line with the paper (see the first-round record: (44),
(47), (53), (58)–(62), (64), Protocols 1 and 2, and §6.2 (97)–(105)). No disagreement was found.

**Open (minor; no effect here).**
- The new §7.3/§7.5 requirements on `SecureRandom` ownership and test-seam fencing are Java
  API-surface rules. This script uses `secrets.token_bytes` for production nonces, and keeps the
  seed expansion in an underscore-named function that is not public API.
- The `V'` example in spec §8.1 says check 1 passes "when `−z² ≡ 0 (mod 3)`". A residue mod `q`
  has no mod-3 class as such. The intended reading is that the order-3 component of `[−z²]·V'`
  vanishes when `z² ≡ 0 (mod 3)` as an integer representative. That is about one challenge in
  three, as the spec says. Only the explanation is affected; the required behaviour
  (`NOT_IN_SUBGROUP`) is unambiguous.

## Not implemented

All spec requirements are implemented. Not attempted:
- the extension-field, sumcheck and TurboSHAKE128 vectors (out of scope in §10);
- a sigma prover;
- reproducing the A.3.1 NARG strings from the A.1 PRNG.

## Limits

Passing this self-test shows that this code agrees with the CFRG vectors and the pinned constants,
and that its prover and verifier are consistent with each other. It is not evidence of soundness
or zero-knowledge, and it is not a production-safety claim. An error shared by the spec text and
this implementation would not be caught here. Cross-checking against the Java implementation and
external code, and review, remain necessary.

## Integration notes (not by the second implementer)

- **External confirmation of the trace pin** (M0 review round 2, at `dd73317`). `PIN_TRACE` is
  the script's own output. It was recomputed with code that is not this script: the CFRG drafts'
  PoC `poc/fiat_shamir.py` (commit `91cc933`), py_ecc 8.0.0, and two reviewers' independent
  verifiers and provers. The tag, session id, instance, all eight challenges and `V` matched. Both
  checks held, and the independent provers reproduced `proofHex` byte for byte. `D_gens` and the
  129 encodings are also reproduced by py_ecc and by Java `Bls12381Hash.hashToG1`.
- **One test assertion tightened by the integrator** (reviewer (c) round-2 F10). The direct
  decoder check on sigma-03 A.3.2 now requires the exact class for each vector: `A5` gives
  `NOT_IN_SUBGROUP`; `A1`, `A3`, `A4` and `A6` give `MALFORMED_ENCODING`; `B1` and `B2` give
  `NON_CANONICAL_SCALAR`. Before, it accepted any rejection. No protocol code changed.

## M2: vector emitter (`emit_bulletproof_vectors_v1.py`)

`emit_bulletproof_vectors_v1.py` writes the protocol's vector file,
`zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/bulletproof-range-bls12-381-g1-v1.json`,
in the spec §11 format (`zeroj-proof-vectors-v1`) under the `commitment-profiles-v1` §13.2 value
conventions. Like the script above, this is **ZeroJ's own second implementation, not an official
or third-party reference**. Agreement between it and the Java implementation shows that two
implementations read the spec the same way. It does not show that the spec is right.

It imports `bulletproof_range_reference.py` from this directory by path and does not modify it.
Every proof, challenge and expected outcome in the file comes from that script:
- positive proofs from the §7.5 test-nonce prover;
- expected classes and layers from its verifier;
- prover refusals from its §7.1 preamble.

The emitter adds its own code only for checking:
- a separate transcript (sponge, tag, instance, challenges) that re-derives `sessionIdHex` and
  every challenge from the proof octets;
- check 1 in the curve module's affine arithmetic;
- a structural "intent" check of each negative case (below).

Check 2 of each positive and check-layer case is re-run with the script's literal Protocol 1/2
folding verifier.

### Running

Python 3.13, standard library only. Run in isolated mode:

```bash
python3 -I -B emit_bulletproof_vectors_v1.py                # the JSON on stdout
python3 -I -B emit_bulletproof_vectors_v1.py --out PATH     # the JSON to PATH
python3 -I -B emit_bulletproof_vectors_v1.py --check        # regenerate and compare byte for byte (about 2.5 minutes)
python3 -I -B emit_bulletproof_vectors_v1.py --self-test    # re-verify and run the mutations (about 13 minutes)
```

- `--check` compares with the committed file. Its path is resolved from the repository root, five
  directories above the script. `--repo-root DIR` overrides the root.
- The `spec` provenance records the SHA-256 and date of three specs, read from the repository
  root at generation time:
  - `bulletproof-range-bls12-381-g1-v1.md`, r2;
  - `pedersen-bls12-381-g1-v1.md`, r2;
  - `commitment-profiles-v1.md`, r8.
- `generator` records the script's SHA-256 and the Python version.
- Editing any of those specs, or this script, changes the output. Regenerate with `--out`.
  `--check` marks such differences `[provenance field]`.

### Contents

| Section | Cases | Coverage |
|---|---:|---|
| `generators` | 129 | `G_0 … G_63`, `H_0 … H_63`, `U`, as in Appendix A |
| `positive` | 14 | 4 at `n = 16`, 5 at 32, 5 at 64 |
| `negative` | 114 | 9 configuration, 17 statement, 10 length, 35 point, 22 scalar, 13 check1, 8 check2 |
| `proverNegative` | 25 | 9 `INVALID_CONFIGURATION`, 6 `NON_CANONICAL_SCALAR`, 7 `OUT_OF_RANGE`, 3 `INVALID_STATEMENT` |

**Positive cases.**
- At each width: the values `0`, `1`, `2^n − 1` and a fixed mid value; `0` always has a non-zero
  blinding.
- At each width: contexts of 1 octet (`00`), `"hello"`, `"https://example.com/payroll/v1"`, and
  1,024 octets. The 1,024-octet context follows the §13.2 pattern `131i+17`.
- Extras: `2^63` with blinding `q − 1`, and `0` with blinding `1`.
- Every case has its own 32-octet nonce seed (§7.5). The seed is SHA-256 of a label and the case
  id, except `n16-vmid-hello-trace`.
- `n16-vmid-hello-trace` is the `--print-trace` example (seed `00 … 1f`). It is pinned against the
  externally confirmed `PIN_TRACE`.

**Negative cases** cover each layer the verifier can reach from octets:
- configuration: bits 0, 8, 24 and 128; an empty `ctx`; a 1,025-octet `ctx`;
- statement:
  - malformed `V` encodings;
  - `(0, 2)`, a commitment plus `(0, 2)`, `[7]·G + [11]·H + (0, 2)`, and another non-subgroup
    point, all `NOT_IN_SUBGROUP`;
  - the identity, which gives `false`;
- length: short, long, empty, and a valid proof of another width;
- point: identity, non-subgroup and malformed encodings at `A`, at a middle `L_j` and at the last
  `R_k`, at `n` = 16, 32 and 64;
- scalar: each of `t̂`, `τ_x`, `μ`, `a` and `b` at exactly `q`, at `2^256 − 1`, and at `s + q`;
- check1 and check2:
  - scalars tampered and re-encoded canonically;
  - substituted, negated and swapped points;
  - a wrong `ctx`; another commitment;
  - two cheating-prover proofs (`v = 2^16`, and a non-bit `a_L`), which fail check 1 only;
- order: two field defects, where the earlier field wins; a bad `V` together with a bad proof
  field, which gives the field's class; a bad or identity `V` with a well-formed but tampered
  proof, which gives the statement outcome.

The `challenge` layer is not reachable from octets (a zero challenge has negligible probability),
so it has no case.

**Prover refusals.** The order is §7.1. The Java opening type rejects a non-canonical value or
blinding when it is constructed, before the prover's configuration check. So every
`NON_CANONICAL_SCALAR` case has a valid configuration (bits 16 or 64, `ctx` `"hello"`), and
every `INVALID_CONFIGURATION` case has a canonical opening. Configuration combined with an
out-of-range value or an identity opening is included.

### `--self-test`

It exits 0 only if every check passes.

1. **Pins.**
   - `D_gens`, `G_0`, and all 129 encodings against `generators-v1.json`.
   - `G` and `H`.
   - The §5.1 example tag, from both the emitter and the script.
   - The 244-octet instance and the proof lengths.
   - The decoder class of each crafted encoding.
   - The trace case against `PIN_TRACE`, including the emitter's own transcript.
2. **Determinism.** A second build, with every cached reference result discarded, must be
   byte-identical.
3. **Re-verification**, of the generated document and of the file on disk.
   - Positive cases:
     - the prover reproduces `proofHex` and `commitmentHex` from `value`, `blinding`, `bits`,
       `ctxHex` and `nonceSeedHex`;
     - the script and the emitter's own transcript both reproduce `sessionIdHex` and the
       challenges;
     - the verifier, affine check 1 and the folding verifier all accept;
     - the commitment matches an affine `[v]·G + [γ]·H`.
   - Negative cases (the intent check):
     - the defects present in the octets are computed by the §8.1 steps: configuration; length;
       each field in proof order; `V`; then the checks, by affine check 1 and the folding
       verifier;
     - they must equal the defects the case declares;
     - `expected` and `layer` must be those of the first declared defect, and must match the
       script's verifier;
     - tags tie a case to its base positive case: "the base proof with `a + 1`", "the same proof
       under another `ctx`", "`V` minus `(0, 2)` is a subgroup point".
   - Prover refusals are re-run through the script's §7.1 preamble and through the emitter's own
     §7.1 order, and the Java-binding constraint above is checked.
   - Coverage is computed from the octets.
4. **Document mutations.** 27 alterations of the emitted document must each be detected, for
   example:
   - a wrong class; a wrong layer; check 1 recorded as check 2;
   - a valid proof in a negative case; a defect moved to another field;
   - a flipped proof bit; `a + 1` in a positive case; a dropped `x_j`; `y + 1`;
   - a reused seed; swapped generators;
   - a JSON number; uppercase hex.
5. **Emitter mutations.** 12 mutations must each make strict generation refuse, or produce output
   that fails re-verification. They include:
   - a reused seed; `q − 1` in place of `q`;
   - a point defect shifted by one field; identity replaced by order 3;
   - a dropped challenge; swapped `y` and `z`;
   - the both-checks layer recorded as check 2;
   - an over-long positive `ctx`; `2^n` as a positive value;
   - a wrong refusal order;
   - two seams of the script: `V` dropped from the instance, and the LSB-first `s_i` rule.
6. **The `--check` comparator.** It must flag tampered copies.

One finding from the first run: the emitter had declared that the non-bit cheating proof fails
both checks. The intent check showed that check 2 holds, because the inner-product argument is
honest for the `l` and `r` that prover built. The declaration was corrected. The emitted file was
unchanged, because its `layer` already came from the verifier.

### Output

| `generator.python` | Output SHA-256 |
|---|---|
| CPython 3.13.5 | `870f01abf6813a62038b78b625e0776b3494ef6a116a33245b6a3ec8908de479` |

This is the committed file, regenerated at integration after the spec's r2 text changed
(`21e3404d…78a0`). Only the `spec` provenance field differs from the author's first output
(`353e8f8d…e37c`); every case is identical.

### Independence (M2)

The M2 author read:
- the spec (r2, SHA-256 `fdae01a9…9d41`), in full;
- `commitment-profiles-v1.md` §2.4, §11 and §13;
- ADR-0061: D4, D5, the invariants, the milestones and the verification strategy;
- this script, its README, the curve module's API, the Pedersen G1 emitter (for style), and the
  JSON vector files.

No `.java` file was opened. One directory listing of the shared staging area showed the name of
a Java file belonging to another work item. It was not opened.

The Java-binding constraint on prover refusals came from the integrator's instructions.

## M2: Java → Python (`verify_java_proofs.py`)

`java-proofs-v1.json` holds 12 proofs made by the **Java** prover with the §7.5 test nonces
(`n` = 16, 32, 64; values 0, 1, a mid value and `2^n − 1`; ASCII, binary and 1,024-octet contexts).
`JavaProofsFileTest` keeps it equal to what the Java code produces. `verify_java_proofs.py` checks
it with this directory's reference implementation only: the commitment is recomputed, each proof
verifies, re-proving with the same seed gives the identical octets, and one-octet tampers in every
field are rejected.

```
python3 -I -B verify_java_proofs.py      # 12 cases, 228 tampers, 0 failing (2026-10-25, CPython 3.13.5)
```

The script is glue written by the Java author; every check it makes calls
`bulletproof_range_reference.py`, which was written without reading Java.

## M2: external algebra check against dalek (`dalek-check/`)

See `dalek-check/README.md`: a group-generic Python core checked against dalek `bulletproofs`
5.0.0 in both directions, and the same core reproducing this protocol's known-answer proof.
