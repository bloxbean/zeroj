# ADR-0047: snarkjs-compatible JSON export and continuous bidirectional proof-verification CI

## Status
Proposed — implemented on branch `feat/31-snarkjs-bidirectional-ci` (issue
[#31](https://github.com/bloxbean/zeroj/issues/31), Phase 1 of umbrella #54), awaiting maintainer
review. The ADR and the implementation were produced together and have not been independently
reviewed. This ADR adds an egress serialization boundary and an assurance job; it does not change
any prover, verifier, transcript or maturity claim.

## Date
2026-09-06

## Risk classification
**R2** for the exporter (`zeroj-crypto` package `crypto.snarkjs`): encoding is a security boundary
(AGENTS.md "Canonical serialization"), and an exporter that silently reduced, rewrote or
substituted a value would let a ZeroJ proof or key be checked against a *different* statement than
the one ZeroJ proved. **R1** for the CI job, the test-vector sharing and the documentation. No
secret is handled: the exporter sees only proofs, verification keys and public inputs. No proof is
produced by this ADR's code (see invariant V8).

## Context

ZeroJ already consumed snarkjs artifacts (`SnarkjsJsonCodec`, `SnarkjsPlonkCodec`,
`ZkeyImporterBLS381`, `PlonKZkeyImporterBLS381`, `R1csExporter`) and its verifiers were checked
against snarkjs-generated vectors in the default build. The other direction did not exist: nothing
in the repository could write a ZeroJ Groth16 or PlonK proof or verification key in the format
`snarkjs groth16 verify` / `snarkjs plonk verify` reads, so the claim "ZeroJ proofs are
snarkjs-compatible" rested on ZeroJ verifying its own proofs with a snarkjs-derived verification
equation — the code under test supplying its own oracle. The live snarkjs→ZeroJ checks that did
exist were `@Tag("e2e")` tests in `zeroj-integration-tests`, excluded from the default `test` task
and run by no workflow, so a regression in either direction would not have been caught by CI.

Issue #31 asks for (1) proof JSON export utilities conforming to the snarkjs format for Groth16 and
PlonK, (2) a GitHub Actions job that installs snarkjs and verifies ZeroJ-generated proofs, and
(3) negative tests ensuring snarkjs rejects tampered ZeroJ proofs.

## Threat model and trust assumptions

- **Untrusted at this boundary: nothing on ingress.** The exporter's inputs are values ZeroJ
  itself produced (`Groth16ProofBLS381`, `Groth16Keys` / `Groth16SetupBLS381.SetupResult`,
  `PlonKProofBLS381`, `PlonKProvingKeyBLS381`, witness-derived public inputs). The threat is an
  *exporter* defect: a wrong key order, a reduced or wrapped scalar, a point rewritten (e.g.
  infinity encoded as a finite point or vice versa), or a wrong curve/protocol string, any of
  which would make the emitted artifact describe a different relation, key or statement than the
  one ZeroJ proved, while still parsing on the snarkjs side.
- **Oracle.** snarkjs v0.7.6 (with ffjavascript 0.3.1 and wasmcurves 0.2.2 as its npm
  dependencies) is treated as the reference implementation of the format and of the verification
  behaviour: what it writes is the format, and whether it accepts or rejects is the verdict. It is
  independent of ZeroJ's curve arithmetic (WASM builds of zkcrypto-derived code).
- **Not covered.** The npm install in CI is version-pinned but not hash-pinned; a compromised
  snarkjs release would compromise the oracle, not ZeroJ's shipped code. Test SRS/ceremonies are
  insecure by construction (`zeroj.allowInsecureTrustedSetup=true` under Gradle test tasks;
  `snarkjs powersoftau` with a fixed contribution). The assurance job proves interoperability, not
  soundness, zero-knowledge, or production readiness of either implementation.

## Pinned normative references

| Reference | Pinned to | Used for |
|---|---|---|
| snarkjs | v0.7.6 (`npm install -g snarkjs@0.7.6`) | JSON formats, CLI verdicts |
| `snarkjs/src/groth16_verify.js`, `plonk_verify.js` | v0.7.6 | which fields the verifier reads; `isValid` point checks; public inputs / evaluations must be `< r`; the PlonK verifier derives the domain generator itself (`Fr.w[vk.power]`) and never reads `vk.w`; verdict strings `OK!` / `Invalid proof` / `Invalid Proof` / `Proof commitments are not valid.` / `Proof evaluations are not valid` / `Public inputs are not valid.` / `Invalid number of public inputs` / `Number of public signals does not match with vk`; `cli.js` exits 0 on `OK!` and 1 both for a rejection and for an internal error |
| `snarkjs/src/zkey_export_verificationkey.js`, `groth16_prove.js`, `plonk_prove.js`, `cli.js` (lines 517, 535–536, 556: `bfj.write(file, stringifyBigInts(obj), {space: 1})`) | v0.7.6, bfj 7.1.0 | key insertion order; `vk_alphabeta_12 = curve.Gt.toObject(pairing(alpha, beta))`; the writer: one-space indent, no trailing newline, and — unlike `JSON.stringify(obj, null, 1)` — an empty container spread over two lines (`"[\n]"`), verified against the bundled bfj |
| ffjavascript `src/wasm_curve.js` (`G1/G2.toObject`, `fromObject`), `src/curves.js` | 0.3.1 | affine encoding `[x, y, "1"]` / `[[x0,x1],[y0,y1],["1","0"]]`; identity encoded `["0","1","0"]`; curve name `"bls12381"` written, `"bls12-381"` also accepted on read |
| wasmcurves `src/bls12381/build_bls12381.js`, `_finalExponentiation` (≈ lines 1185–1290; `finalExpZ = 15132376222941642752`, `finalExpIsNegative = true`, cyclotomic exponentiations + Frobenius maps) | 0.2.2 | the hard-part addition chain that yields `f^{3·(p^4−p^2+1)/r}`; the empirical relation below was established against ffjavascript's `curve.pairing` output directly, not derived from this code |
| Daiki Hayashida, Kenichiro Hayasaka, Tadanori Teruya, *Efficient Final Exponentiation via Cyclotomic Structure for Pairings over Families of Elliptic Curves*, IACR ePrint 2020/875 (title/authors verified 2026-09-06) | — | the family of hard-part algorithms whose BLS12 instance raises to a multiple `3·d(x)` of the exact exponent; cited for the origin of the factor 3, not as the source of the exporter's behaviour |
| ADR-0045 | this repo | Groth16 infinity rules: no proof/VK point, including every `IC[i]`, may be infinity |
| ADR-0046 | this repo | proof-producer allowlist; this package produces no proofs |
| ADR-0044 | this repo | module surface: no new runtime edges, no test-fixture edges |

## The `vk_alphabeta_12` convention (finding)

`snarkjs zkey export verificationkey` writes `vk_alphabeta_12 = e(alpha, beta)` and `snarkjs
groth16 verify` never reads it, but ZeroJ's `SnarkjsJsonCodec.parseVerificationKey` requires the
field, so the exporter has to emit it. Computing `e(alpha, beta)` with ZeroJ's
`BLS12381Pairing` and flattening the tower in declaration order did **not** reproduce snarkjs'
values: none of the twelve coefficients matched for any of the four snarkjs BLS12-381 verification
keys in the repository. Cross-checking `e(G1, G2)` against ffjavascript directly showed the
ffjavascript value equals **the cube** of ZeroJ's (`e_ff == e_ZeroJ^3` on the generators, and then on
all four snarkjs VKs and on the live VK exported in the interop suite): wasmcurves'
`_finalExponentiation` implements the cyclotomic hard-part chain (Hayashida–Hayasaka–Teruya
family) that raises to `3·(p^4−p^2+1)/r`, while ZeroJ's `finalExponentiation` raises to the exact
`(p^12−1)/r` by `BigInteger` exponentiation. Both are non-degenerate bilinear pairings
(`gcd(3, r) = 1`) and both verifiers are unaffected (a product-of-pairings check is invariant under a
fixed exponent), but the GT *elements* differ. The exporter therefore emits `e_ZeroJ(alpha,
beta)^3`, laid out `[[c0.c0, c0.c1, c0.c2], [c1.c0, c1.c1, c1.c2]]` with each `Fp2` as `[c0, c1]`.
The relation is pinned by a known-answer test on three snarkjs keys (byte-identical re-export)
that also asserts the *uncubed* value does not match, so a future "simplification" that drops the
cube fails visibly.

## Security invariants

- **V1 — byte-identical re-export.** (The vector files are pinned to LF line endings in
  `.gitattributes` so an `autocrlf=true` checkout cannot fail this invariant spuriously.) For every snarkjs-written BLS12-381 artifact in the
  repository (three Groth16 VKs, one Groth16 proof + public, one PlonK VK + proof + public) and for
  fresh `snarkjs ... prove` / `zkey export verificationkey` output produced in the interop suites,
  parse → export must reproduce the original bytes exactly: key order, decimal strings,
  projective markers, one-space indentation, no trailing newline.
- **V2 — no silent rewriting.** The exporter never reduces a scalar modulo `r`, never normalises
  a point, and never substitutes a default. A scalar outside `[0, r)`, a `null`, an off-curve or
  off-subgroup point, or a point at infinity throws `IllegalArgumentException`. The one deliberate
  exception is V3.
- **V3 — infinity policy mirrors the ingress verifiers.** Groth16: no exportable position may be
  infinity (ADR-0045 V1/V2, including every `IC[i]`). PlonK: only the five selector commitments
  `Qm/Ql/Qr/Qo/Qc` may be the identity — a selector polynomial that is identically zero commits to
  it, snarkjs writes it as `["0","1","0"]`, and `PlonkBLS12381Verifier` accepts infinity in exactly
  those five positions; proof commitments, `S1/S2/S3` and `X_2` stay strict.
- **V4 — protocol and curve strings.** `"groth16"` / `"plonk"` and `"bls12381"` exactly as snarkjs
  v0.7.6 writes them.
- **V5 — `vk_alphabeta_12`** is `e_ZeroJ(alpha, beta)^3` in the layout above (finding section).
- **V6 — public-input order** is wire order `1..nPublic`: `public.json[i]` is wire `i+1`, which is
  the order `R1csExporter` declares to snarkjs (`nPubOut = 0, nPubIn = numPublic`) and the order
  `IC[i+1]` binds. `nPublic` in an exported Groth16 VK is `IC.length − 1`; in a PlonK VK it is the
  key's `nPublic`, and `power = log2(domainSize)` with `domainSize` required to be a power of two.
- **V6a — canonical PlonK domain generator.** The exported `w` must equal
  `FieldFFTBLS381.rootOfUnity(power)`. snarkjs' verifier ignores `vk.w` and derives `Fr.w[power]`,
  while `PlonkBLS12381Verifier` reads `w` from the file and accepts any primitive `2^power`-th
  root; a non-canonical `w` would therefore be a key snarkjs accepts and ZeroJ rejects. The KAT
  pins that the `w` snarkjs itself wrote equals ZeroJ's root (the two implementations agree on the
  generator) and that another primitive root is refused at egress.
- **V7 — the oracle cannot silently vanish, drift, hang, or be mistaken for a verdict.** Locally
  the interop suites skip when snarkjs is not found (discovered via `SNARKJS_BIN`, common npm
  locations, then `PATH`; never a developer absolute path) or when its `--version` first line is not
  exactly `snarkjs@0.7.6`; under `-PrequireSnarkjs` (the assurance workflow) both are test
  failures, and the test task is never `UP-TO-DATE`/`FROM-CACHE` (the binary is outside Gradle's
  inputs). Every snarkjs invocation is bounded (`--version` 10 s, `verify` 300 s, killed on
  expiry; JUnit 20 min per test; job 45 min). The shared setup/prove runner redirects output
  to a temporary file before its timed wait, so reading a pipe to EOF cannot bypass that timeout;
  offline process regressions cover a hung child and output larger than a pipe buffer.
  A verdict is tri-state: exit 0 with `OK!` is
  VALID, exit 1 with one of the pinned rejection strings is INVALID, and anything else (a thrown
  JavaScript error also exits 1) is an error that fails the test — a negative test can only pass
  on a genuine rejection.
- **V8 — no proof production.** `crypto.snarkjs` contains no method returning a proof and calls no
  prover; it is outside the ADR-0046 proof-producer allowlist by package and by construction
  (`Groth16ProverApiSurfaceTest` scans `crypto.groth16` / `crypto.plonk`; the new package is a
  consumer of those types only).
- **V9 — no new runtime edges.** `zeroj-crypto` gains no dependency (the writer is ~150 lines of
  hand-written JSON, no Jackson); the only new edge is `zeroj-crypto` **test** → `zeroj-test-vectors`,
  which `verifyDefaultModuleSurface` permits (not a test-fixtures edge, not an assurance project).

## Decision

1. **Exporters live in `zeroj-crypto`, package `com.bloxbean.cardano.zeroj.crypto.snarkjs`:**
   `SnarkjsGroth16Json` (`proofJson`, `verificationKeyJson` from `Groth16Keys`, from
   `SetupResult`, or from the five components, `publicJson`) and `SnarkjsPlonkJson` (`proofJson`,
   `verificationKeyJson` from `PlonKProvingKeyBLS381` or from components, `publicJson`), sharing a
   package-private `SnarkjsJsonWriter` that emulates snarkjs' `bfj.write(..., {space: 1})` and
   holds the egress checks (V2/V3/V6a; subgroup membership via the same Montgomery Jacobian
   `[r]P == O` predicate `SetupCacheIO.validateG1/G2` use). Output is a `String`; callers write files.
2. **Known-answer tests in `zeroj-crypto`** (`crypto.snarkjs.SnarkjsGroth16JsonKatTest`,
   `SnarkjsPlonkJsonKatTest`) pin V1–V6 without snarkjs installed, in the default build. The
   snarkjs PlonK vector (`snarkjs 0.7.6 + circom 2.2.3`) moves byte-for-byte from
   `zeroj-verifier-plonk`'s test resources to `zeroj-test-vectors` under
   `test-vectors/snarkjs-plonk-bls12381/` (the verifier test already had that module on its test
   classpath and now reads the single shared copy; two copies at one classpath path would shadow
   each other silently).
3. **Live interop suites in `zeroj-integration-tests`, package `it.snarkjs`, not `e2e`-tagged**,
   driven by the existing `SnarkjsProver` helper:
   - Groth16: ZeroJ proof under a snarkjs zkey → `snarkjs groth16 verify` (with wrong public,
     swapped `pi_a/pi_c`, off-curve `pi_a` rejected); ZeroJ-native setup → exported VK + proof →
     snarkjs (wrong public, other-witness proof, wrong key rejected); live `snarkjs groth16 prove`
     → pure-Java **and** blst verifiers (wrong public rejected), plus byte-identical re-export of the
     fresh output.
   - PlonK: ZeroJ-native `PlonKSetupBLS381` + `PlonKProverBLS381.prove` → exported VK + proof →
     `snarkjs plonk verify` (wrong public, swapped `A/B`, tampered `eval_a`, other-witness proof
     rejected); live `snarkjs plonk setup` + `plonk prove` over a ZeroJ R1CS → `PlonkBLS12381Verifier`
     (wrong public rejected), plus byte-identical re-export; an offline ZeroJ → codec →
     ZeroJ-verifier round trip that runs without snarkjs; and an offline differential test
     (`SnarkjsPlonkInfinityPolicyTest`) asserting, per G1 key position, that the exporter accepts
     the identity point iff `PlonkBLS12381Verifier` accepts `["0","1","0"]` there — the V3 policy
     is written in two modules and this is what stops them drifting.
4. **CI:** a `snarkjs-interop` job in `.github/workflows/assurance.yml` (push, PR, nightly,
   dispatch) installs Node 22 and `snarkjs@0.7.6`, then runs the `it.snarkjs.*` suites with
   `-PrequireSnarkjs`. `ci.yml` stays pure Java.

### Alternatives considered

- **Put the exporter in `zeroj-codec` next to the parsers.** Rejected: it would need
  `zeroj-crypto`'s proof/key types, i.e. a `zeroj-codec → zeroj-crypto` edge in the wrong
  direction (the verifiers depend on codec, and `zeroj-verifier-plonk` already depends on crypto).
- **Give `zeroj-crypto` a `zeroj-codec` (Jackson/CBOR) dependency and reuse the record types.**
  Rejected: pulls Jackson and CBOR into the prover module for a formatting task, and Jackson's
  default serialisation would not reproduce snarkjs' bytes anyway (`serializeProofToBytes` in the
  codec writes record field names, not snarkjs names).
- **Reuse the `@Tag("e2e")` suites and just run `e2eTest` in CI.** Rejected: those suites also need
  Yaci DevKit and are application examples; the interop property should run whenever snarkjs is
  present and fail, not skip, in its dedicated job.
- **Emit `vk_alphabeta_12` as ZeroJ's own pairing value** (it is unused by snarkjs). Rejected: it
  would break V1 (parse → export would not round-trip snarkjs' own keys) and would put two
  different "e(alpha, beta)" conventions in circulation under the same field name.
- **Encode infinity as `["0","1","0"]` everywhere and let the verifiers decide.** Rejected for
  Groth16 (ADR-0045 forbids it and the exporter should not be able to emit a key the ZeroJ verifier
  rejects); adopted only for the PlonK selector positions where both verifiers accept it.

## Consequences

- ZeroJ proofs and ZeroJ-native verification keys can be handed to snarkjs (and to any
  snarkjs-format consumer) with one call, and CI proves it continuously in both directions.
- The exporter is a second, independent statement of the snarkjs format next to the parsers; a
  drift in either is caught by the byte-identical KATs.
- The `vk_alphabeta_12` cube relation is now documented and pinned; anyone changing
  `BLS12381Pairing.finalExponentiation` (e.g. to the cyclotomic algorithm) will see the KAT flip and
  must update the exporter and this ADR together.
- The assurance workflow gains a Node/npm step; the default build does not.

## Compatibility

Additive. No existing public signature changes. `zeroj-crypto` gains one public package (two public
final classes with static methods). `zeroj-test-vectors` gains one resource directory.
`zeroj-integration-tests`' default `test` task now also runs the `it.snarkjs.*` suites, which
skip in ~1 s when snarkjs is absent. GraalVM: no reflection, no resources, nothing to register.

## Implementation milestones

| Milestone | Scope | Status |
|---|---|---|
| M1 | `SnarkjsJsonWriter`, `SnarkjsGroth16Json`, Groth16 KATs (byte-identical re-export of 3 VKs + proof + public; cube relation; JVM round trips via native setup and via snarkjs zkey; egress rejections) | done |
| M2 | `it.snarkjs.SnarkjsGroth16InteropTest` (both directions + negatives), `-PrequireSnarkjs` plumbing, `snarkjs-interop` assurance job | done |
| M3 | `SnarkjsPlonkJson`, PlonK KATs, `SnarkjsPlonkInteropTest`, `SnarkjsPlonkExportRoundTripTest`, shared PlonK vector | done |
| M4 | this ADR, README assurance/ADR rows, module docs, #54 bookkeeping | done (bookkeeping on merge) |

## Verification and test-vector strategy

Independent evidence, per AGENTS.md "Testing":

- **Known-answer (format):** byte-identical re-export of every snarkjs-written BLS12-381 artifact
  in the repository (`zeroj-crypto/src/test/resources/test-circuits/{multiplier,cubic}-bls381`,
  `zeroj-test-vectors` `groth16-bls12381` and `snarkjs-plonk-bls12381`). The fourth snarkjs Groth16
  VK in the repository (`zeroj-onchain-julc` test resources) was checked ad hoc during the
  investigation and matches; it is not on the crypto test classpath.
- **Known-answer (pairing convention):** `vk_alphabeta_12 == e_ZeroJ^3` and `!= e_ZeroJ` on three
  keys, computed with `BLS12381Pairing` in the test, not with the exporter.
- **Differential (live oracle):** snarkjs v0.7.6 accepts ZeroJ Groth16 and PlonK proofs and keys
  and rejects ten distinct tamperings (the PlonK other-witness case proves under the *same* key, so
  the rejection is about the statement, not a key mismatch); ZeroJ's pure-Java and blst Groth16
  verifiers and the PlonK verifier accept live snarkjs proofs and reject tampered public inputs.
  The oracle's verdict is tri-state (V7): `OK!`+exit 0, a pinned rejection string+exit 1, or an
  error that fails the test; both verdict branches are exercised.
- **Negative (egress):** infinity in every Groth16 position (proof A/B/C, alpha, gamma, `IC[i]`,
  empty `IC`); PlonK identity in every G1 key position (accepted only for `Qm/Ql/Qr/Qo/Qc`, via the
  differential policy test) and in proof `A`, `Wxiw` and `X_2`; off-curve G1/G2;
  on-curve-but-off-subgroup G1 (the order-3 point `(0, 2)`); scalars `r`, `r+1`, `−1`, `null`;
  non-canonical PlonK `w`; non-power-of-two PlonK domain; negative `nPublic`.
- **Cross-provider:** pure Java and blst Groth16 verifiers on the same live snarkjs proof.
- **Local run:** `./gradlew :zeroj-crypto:test --tests 'com.bloxbean.cardano.zeroj.crypto.snarkjs.*'`
  (no snarkjs needed) and `./gradlew :zeroj-integration-tests:test --tests 'com.bloxbean.cardano.zeroj.it.snarkjs.*'`
  (skips without snarkjs; add `-PrequireSnarkjs` to make absence fail).

## Known gaps

- **ZeroJ proof under a snarkjs PlonK zkey is not covered.** `PlonKZkeyImporterBLS381` reads the
  header, selectors, sigmas and SRS but not the A/B/C wire-map sections, so ZeroJ cannot assign
  wires for a snarkjs-arithmetised circuit. Closing this needs an importer extension (its own
  R2 change), tracked separately.
- The live suites use one small circuit (`c = a·b`, `nPublic = 1`); the checked-in vectors add
  `nPublic = 2` (Groth16) and identity selector commitments (PlonK). Larger circuits and
  `nPublic = 0` are not exercised live.
- `vk_alphabeta_12` cannot be validated by snarkjs itself (its verifier ignores the field); the
  KAT is the only pin.
- The PlonK prover's b10/b11 blinding gap (issue #30) is unchanged: the exporter serialises what
  `PlonKProverBLS381.prove` produces today and adds nothing to its zero-knowledge claim.
- npm supply chain: `snarkjs@0.7.6` is version-pinned, not integrity-pinned.
- Point-validity checks (null / infinity / on-curve / subgroup) are now stated in five places
  (`Bls12381Codecs.requireValid`, `SetupCacheIO.validateG1/G2`, `PlonKSetupBLS381.requireValidSrsG1/G2`,
  the verifiers, `SnarkjsJsonWriter`), and the PlonK "which selectors may be the identity" table in
  four (verifier, `PlonkSetupCache`, on-chain `PlonkBLS12381Lib`, exporter). The differential
  policy test pins exporter↔verifier agreement; consolidating the helpers into one owner is a
  separate, cross-module refactor and is not attempted here.

## Production / audit gates (unchanged by this ADR)

Interoperability with snarkjs is evidence of format and verification-equation agreement, not of
soundness or zero-knowledge. The Groth16 and PlonK paths keep their existing maturity status and
the ADR-0025/ADR-0026 audit gates; nothing here upgrades a claim.
