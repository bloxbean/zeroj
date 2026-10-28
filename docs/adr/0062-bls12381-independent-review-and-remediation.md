# ADR-0062: BLS12-381 independent review (2026-10-28) and remediation plan

## Status
**Accepted (design), 2026-10-28, by maintainer Satya.** Q1, Q3 and Q4 are decided (see "Open
questions"); Q2 stays open. The maintainer chose the full D3 migration, so the D3 interim steps are
superseded. **Implementation in progress** on branch `fix/adr-0062-bls-remediation`, one commit
per milestone. Acceptance is not a maturity or security claim (AGENTS.md).

The ADR records the findings of an independent correctness/security review of the BLS12-381
stack and decides what to fix, in which order, and with which evidence.

It supplements, and does not supersede, [ADR-0018](0018-shared-bls12381-primitives-and-wasm-provider.md)
(shared primitives and WASM provider) and [ADR-0021](0021-bls12381-review-and-hardening.md)
(first review and hardening posture). Where this ADR revises an ADR-0021 decision it says so
explicitly (D1).

## Date
2026-10-28 (r1); 2026-10-28 (r2: accepted, Q1/Q3/Q4 decided, D1 construction fixed)

## Revision history
- **r1 (2026-10-28):** first version, written from the review described in §Evidence.
- **r2 (2026-10-28, maintainer decisions):** accepted as design. Q1 decided: fixed-length
  recoding **with** blinding, using the m-range construction now in D1 (the r1 candidates are
  replaced; a reduce-mod-r variant was rejected because the reduction cancels the blinding). Q3
  decided: moot, because D5 now applies `z = 1` to verification keys too and no fixture has
  `z ≠ 1`. Q4 decided: document only. D3: full migration chosen; the interim steps are superseded.
  No invariant changed.

## Risk classification
- **R3:** D1 (secret-scalar ladder schedule). It changes how a secret-dependent primitive
  executes. It must not change any output.
- **R2:**
  - D2 (secret-path documentation and provider contract);
  - D3 (provenance of the native binary on the pairing/verifier path);
  - D4 (FFM MSM scalar and point boundary);
  - D5 (Groth16 snarkjs point encoding: canonical `z = 1`);
  - D6 (release pipeline fail-closed for native artifacts);
  - D7 (raw pairing APIs and empty pairing products).
- **R1:** D8 (`pow` with negative exponents), D9 (test and differential gates).
- **R0:** D10 (dead constants, comments, documentation, GraalVM metadata verification).

## Context

### Scope of the review
Modules and files reviewed in full:
- `zeroj-bls12381`: `field/*`, `ec/*`, `pairing/BLS12381Pairing`, `Bls12381Codecs`,
  `Bls12381Generators`, `Bls12381Hash`, `Bls12381HashToCurve`, `spi/*`, native-image resources.
- `zeroj-blst`: `BlstBls12381Provider`, `BlstPairing`, `ffm/BlstFfm`, `ffm/BlstG1Msm`,
  `ffm/BlstG2Msm`, native-image resources, `scripts/build-blst.sh`.
- `zeroj-crypto-blst` (skimmed, for how the MSM entry points are reached).
- `assurance/zeroj-bls12381-wasm` (skimmed, as the differential oracle).
- Call sites in `zeroj-verifier-groth16`, `zeroj-verifier-plonk`, `zeroj-bbs` and
  `G1Pedersen*`, for how untrusted bytes reach the primitives.

Out of scope: the circuit DSL, the provers' own logic, the on-chain Julc verifiers, and the
`zeroj-crypto` zkey/ptau importers beyond spot checks.

### Evidence
All expected values below were produced **outside** the code under test.

| Area | Independent evidence | Result |
|---|---|---|
| Constants | `p`, `r` re-derived from `x = −0xd201000000010000`; Montgomery `INV`, `R`, `R²` (Fp and Fr), generators, `b = 4`, `b' = 4(1+u)`, RFC 9380 `Z`, `A'`, `B'`, `h_eff`, all 66 isogeny coefficients (machine-extracted from the RFC 9380 text, Appendix E.2/E.3) | All exact |
| Field tower | ~1,500 differential vectors against a Python big-integer reference that models `Fp12` as `Fp2[w]/(w⁶ − ξ)` with schoolbook multiplication (no formula shared with the Java code); edge values `0, 1, m−1, ⌊m/2⌋, 2⁶⁴±1` | 0 mismatches |
| Curve and codecs | 980 checks against an independent Python EC implementation; byte-exact round-trips in all four ZCash formats; malformed-input rejection corpus | 0 failures |
| Pairing | Final exponent shown to equal exactly `(p¹² − 1)/r`; `e(G1,G2)`, `e([a]G1,[b]G2)`, and a hash-derived pair compared coefficient-by-coefficient with **py_ecc 8.0.0** after basis mapping (ZeroJ = py_ecc⁻¹, because py_ecc omits the negative-`x` conjugation; ZeroJ is the standard orientation) | Match |
| Hash-to-curve | 130 checks: RFC 9380 J.9.1, J.9.2, J.10.1, J.10.2 (including `Q0`/`Q1` and `u`), K.1, K.2, K.6; `map_to_curve` differential against py_ecc (30 G1 inputs including the exceptional cases, 22 G2 inputs); Keccak/SHAKE-256 against `hashlib.shake_256` on 99 length combinations | All pass |
| Module tests | Java 25.0.2-graal, macOS aarch64: `:zeroj-bls12381:test` 1981 passed; `:zeroj-blst:test` 26 passed (native library loaded, nothing skipped); `:zeroj-crypto-blst:test` 10 run, 3 opt-in benchmarks skipped | Green |
| WASM oracle | `:zeroj-bls12381-wasm:test` **not run** (offline dependency cache missing chicory 1.7.5) | Not evidenced |

The review harnesses (Python references, Java differential drivers, timing probes) are
candidates for promotion into the repository under M7.

### Correctness assessment for library use

This section answers a specific question: **is the pure-Java `zeroj-bls12381` implementation
correct when another project uses it as a library?**

**Yes, for its checked API surface.** The review found no correctness bug in:
- field arithmetic (both the `BigInteger` tower and the Montgomery `Fp`/`Fr` layer);
- the G1/G2 group law, including all special cases (`P + P`, `P + (−P)`, identity on either side);
- scalar multiplication (zero, negative, `≥ r`, `≥ 2²⁵⁶`);
- the subgroup check (`[r]P = O`, no endomorphism shortcut, so none of the known wrong-variant bugs);
- the ZCash/CIP-0381 point and scalar codecs (canonical, strict flags, `< p`, on-curve, subgroup);
- the optimal ate pairing and final exponentiation;
- RFC 9380 hash-to-curve for G1/G2, RO and NU, XMD and XOF.

"Checked API surface" means the inputs arrive through `Bls12381Codecs.g{1,2}From{Compressed,Uncompressed}`,
`requireValid`/`isValid`, or a `Bls12381Provider`. A library consumer needs to know about
these correctness caveats:

1. **Raw types do not validate.** The `G1Point`/`G2Point` record constructors, `fromProjective`,
   `Jacobian*.fromAffine`, the `*Unchecked` decoders, and `BLS12381Pairing.pairingCheck`/`millerLoop`
   accept any coordinates. The group-law formulas never use `b`, so an off-curve point silently
   computes on a different curve. The caller must validate, or use the provider. (D7)
2. **`BLS12381Pairing.pairingCheck([], [])` returns `true`**, and so does
   `Bls12381Provider.pairingProductIsIdentity` for empty arrays or all-identity pairs. This is
   mathematically right for an empty product but dangerous in a verifier that builds its arrays
   dynamically. (D7)
3. **`MontFp381.pow` / `MontFr381.pow` with a negative exponent return a wrong value** (for
   example `pow(−1) = 1`). No production caller passes a negative exponent. (D8)
4. **`Fp.of`, `MontFp381.fromBigInteger` and `MontFr381.fromBigInteger` reduce silently.** That
   is correct modular arithmetic, but they are not canonical decoders. Any new byte decoder
   must range-check first, as `Bls12381Codecs.readFp` and `scalarFromBigEndian32` do.
5. **Performance, not correctness:** subgroup checks cost about 4.5 ms (G1) and 10 ms (G2) per
   checked decode, and a pairing about 100 ms. Untrusted input in bulk is a DoS consideration.

**Maturity label: no change.** The README and the component status already describe this module
as **Beta — verification-grade**. This review supports that label for correctness. It does not
justify `Stable`/production, for three reasons:
- AGENTS.md forbids raising maturity on test counts or an AI review;
- there is no external audit;
- the secret-scalar path has an open R3 finding (D1).

The version is `0.1.0-pre13`, so the API is not semver-stable either: D7 and D8 propose
small, fail-closed behaviour changes.

### Findings

Severity is the reviewer's estimate for ZeroJ as currently used. "Verified" means reproduced
with code or measurement during the review.

| # | Severity | Finding | Location | Verified |
|---|---|---|---|---|
| F1 | Medium (R3) | Pure-Java secret-scalar ladder leaks the scalar's bit length | `JacobianG1BLS381.java:172-197`, `JacobianG2BLS381.java:134-157` | Timing measured |
| F2 | Medium | blst provider's "secret" path is its public path; docs present it as the side-channel-safe choice | `BlstBls12381Provider.java:120-128`; `README.md:47`; `PureJavaBls12381Provider.java:17-18`; `zeroj-bbs/README.md:146-148`; `docs/component-status-2026-07-03.md:35` | Code read |
| F3 | Medium | Pairing, provider and blst Groth16 verifier run a third-party prebuilt JNI `libblst` (`foundation.icon:blst-java:0.3.2`), contrary to "built from source, no third-party binary" | `zeroj-blst/build.gradle:10`; `zeroj-blst/README.md:11-20`; `README.md:49,65,262` | Jar inspected |
| F4 | Medium (low in-repo exposure) | Public FFM MSM entry points silently compute wrong results for scalars outside `[0, 2²⁵⁵)`, ignore extra scalars, and accept non-subgroup bases | `ffm/BlstG1Msm.java:27,93-96,175-187`; `ffm/BlstG2Msm.java` (same shape) | Reproduced |
| F5 | Low | Both Groth16 BLS12-381 verifiers accept rescaled projective encodings (`z ≠ 1`): proof-byte malleability | `Groth16BLS12381PureJavaVerifier.java` (`toG1`/`toG2`); `Groth16BLS12381Verifier.java` (`decodeG1Bytes`/`decodeG2Bytes`) | Reproduced on a real proof |
| F6 | Low | Release silently ships committed dev native binaries if a source-built artifact is missing; blst source pinned by tag only | `.github/workflows/release.yml:218` (`cp … \|\| true`); `zeroj-blst/scripts/build-blst.sh:17,37` | Code read |
| F7 | Low | Raw pairing/blst helper APIs do not validate inputs; empty pairing product is `true`; undocumented | `BLS12381Pairing.java:51-64`; `BlstPairing.java:26,61,70,79`; `Bls12381Provider.java:70` | Reproduced |
| F8 | Low | `MontFp381.pow` / `MontFr381.pow` return wrong results for negative exponents; Javadoc claims a "fixed bit-length loop" | `MontFp381.java:190-199`; `MontFr381.java:153-163` | Reproduced |
| F9 | Test gap | Partial RFC 9380 vector coverage; positive-only pairing-check tests; thin WASM differential; no negative blst-provider tests | see D9 | Counted |
| F10 | Info | Dead and mis-commented `FROBENIUS_COEFF_X/Y`; empty DST accepted; XOF oversize-DST fixed at `k = 128`; unreachable incorrect vertical-line branch; GraalVM FFM metadata unverified; docs path errors | see D10 | Code read / computed |

#### F1 — Secret-scalar ladder leaks bit length (R3)
`ctScalarMul` initialises `r0 = INFINITY`, `r1 = P` and runs 256 MSB-first iterations. While
the leading bits are zero, `r0` stays at the identity. Then `r0.add(r1)` and `r0.doublePoint()`
take the early-return branches (`JacobianG1BLS381.java:64,84`), so each leading zero bit costs
one doubling instead of two doublings plus an addition.

Measured on G1 with a warmed JIT: 0.22 ms at 1 bit, 0.39 ms at 65 bits, 0.58 ms at 129 bits,
0.93 ms at 255 bits. That is linear, about 2.8 µs per bit. A second, independent harness
reproduced the slope. The Javadoc ("Always performs both a doubling and an addition per bit…
uniform operation schedule", `JacobianG1BLS381.java:162`, `JacobianG2BLS381.java:128-130`,
`G1Point.java:88-90`, `G2Point.java:91-93`) is false as a description of the work done.

Exposure. This is the default `g1SecretScalarMul`/`g2SecretScalarMul` of the pure-Java provider. It is used for:
- BBS key generation (`CfrgBbsCore.java:69`);
- signing (`:349`, `(SK + e)⁻¹`);
- proof generation (`:410-420`: `r1`, `r2`, `ẽ`, `r̃1`, `r̃3`, `m̃`);
- G1 Pedersen generation (`G1Pedersen.java:347-348`).

Bit-length leakage of nonces is the standard input to hidden-number-problem attacks (Minerva,
TPM-Fail), because BBS responses have the form `ê = ẽ + e·c`. **No key- or message-recovery
attack was built.** Exploitability under JVM noise is unquantified.

ADR-0021 identified this leak ("leaks MSB position") but decided only to correct the
documentation. ADR-0038 later removed the same class of leak for Jubjub (fixed-width ladder
P4, then scalar blinding P7.2). BLS12-381 was never brought to the same level.

#### F2 — blst "secret" path equals its public path
`BlstBls12381Provider.g1SecretScalarMul` returns `g1ScalarMul(point, scalar)`. That path does
`BigInteger.mod`, returns early on a zero scalar, converts with `toByteArray`, and goes
through SWIG `P1.mult(BigInteger)`. Nothing is zeroized.

Some docs say neither provider is constant-time (`zeroj-bls12381/README.md:44-50,75`;
ADR-0060). Others point secret workloads at blst as if it carried "an audited side-channel
contract". Today **no ZeroJ provider has an evidenced secret-scalar contract**.

#### F3 — Third-party prebuilt JNI binary
`zeroj-blst` depends on `foundation.icon:blst-java:0.3.2` (Sep 2023). That jar bundles its own
`libblst` for macOS x86_64/aarch64 and Linux amd64/aarch64; the upstream blst version is
unknown. It backs `BlstBls12381Provider`, `BlstPairing`, `Groth16BLS12381Verifier`, and BBS
when blst is selected.

The docs' "built from source, pinned v0.3.15, no third-party wrapper/binary" is true only for
the FFM MSM library, and `release.yml` rebuilds only that one. One process therefore loads two
blst builds of different versions.

The JNI loader (`blstJNI.<clinit>`, disassembled) can be redirected with the system property
`supranational.blst.jniResource`. If the resource is missing it falls back to
`System.loadLibrary("blst")`, which picks up whatever `libblst` is on `java.library.path`.

#### F4 — FFM MSM boundary
`BlstG1Msm` and `BlstG2Msm` pass `NBITS = 255` to Pippenger and `blst_p*_mult`, and
`leBytes32`/`leBytes32Into` keep the low 32 bytes of `toByteArray()`. Reproduced:
- scalar `2²⁵⁵ + 1` yields `G`;
- scalar `−1` yields an unrelated point;
- scalar `2²⁵⁶ + 1` yields `G`;
- `msm(byte[][], BigInteger[])` ignores surplus scalars;
- `blst_p1_deserialize` accepts non-subgroup bases;
- a 96-byte buffer with the compressed flag set is accepted and its trailing 48 bytes are ignored.

The in-repo prover is safe because it reaches these methods through `FlatScalars` (which
reduces mod `r`) with encoder-built canonical points. The methods are public, though, and
their semantics differ from the SPI's.

#### F5 — Groth16 projective encoding malleability
`G1Point.fromProjective` / `G2Point.fromProjective` divide by `z`. The pure-Java Groth16
verifier range-checks `z` but does not require `z = 1`, and the blst verifier's
`decodeG1Bytes`/`decodeG2Bytes` likewise divides by any non-zero `z`.

Replacing `pi_a` in `sealed-bid-bls12381/proof.json` with `(7x, 7y, 7)` still verifies. This
does not affect soundness, since Groth16 proofs are re-randomisable anyway. It does matter to
any application that keys replay protection or nullifiers on proof bytes or proof hashes.
`PlonkBLS12381Verifier.validateG1Encoding`/`validateG2Encoding` already require `z = 1` or
the canonical identity. snarkjs emits `"1"` / `["1","0"]` (see `SnarkjsGroth16Json.java:39`).
*Unverified:* whether ffjavascript reads `[x, y, z]` as Jacobian (`x/z², y/z³`); if it does,
ZeroJ and snarkjs decode the same `z ≠ 1` encoding to different points.

#### F6 — Release pipeline
`release.yml:218` copies each source-built `libblst` with `cp … || true`. A missing artifact
leaves the committed development binaries in the released jar, contradicting the documented
"never ships dev binaries". `build-blst.sh` clones `--depth 1 -b v0.3.15`, so it pins a tag but
not a commit hash, and checks no signature.

#### F7 — Raw APIs and empty products
- `BLS12381Pairing.pairingCheck` and `millerLoop` are public and do not validate. An off-curve
  `(1, 1)` is evaluated.
- The vertical-line branch of `lineFuncAdd` (`:137-140`) does not handle `T = Q`. It is
  unreachable for prime-order `Q`.
- `BlstPairing.millerLoop/g1Add/g1Neg/g1ScalarMul` do not check the subgroup, and
  `g1ScalarMul` does not reduce.
- Every in-repo caller validates first. BBS passes fixed two-element arrays and rejects
  identity components at decode. The verifiers do not use the SPI pairing.

The hazard is for future and external callers.

#### F8 — Negative exponents in Montgomery `pow`
For a negative `BigInteger`, `exp.bitLength()` describes the two's-complement form, so
`pow(−1)` returns `ONE` and `pow(−3)` returns `this`. `Fp`, `Fp2`, `Fp12` and
`MontFr381.pow(long)` are correct or reject.

#### F9 — Test gaps
- RFC 9380: J.9.2 G1 NU has 1 of 5 messages; J.10.1 G2 RO has 2 of 5 and no `u` values;
  J.10.2 G2 NU has 1 of 5; there is no `Q0`/`Q1`; K.6 SHAKE-256 has 1 of 10; there is no
  vector for the XOF hash-to-curve functions inside this module (BBS fixtures cover them
  indirectly); there are no length-bound negative tests. The oversize-DST test at
  `Bls12381HashToCurveTest.java:61-71` is self-referential (K.2 covers that path properly).
- Pairing: every `pairingCheck`/`pairingProductIsIdentity` test is a positive case, so an
  always-`true` implementation would pass. There are no infinity-input or length-mismatch
  tests in this module. Bilinearity uses one scalar pair. The GT KAT is self-pinned (the
  external ffjavascript KAT lives in `zeroj-crypto`).
- Field: no independent `Fp6`/`Fp12` vectors; `Fp2Test` covers only `sqrt(−1)`; no random
  sqrt / non-residue / `sgn0` property tests.
- WASM oracle (`Bls12381WasmClientTest`): it compares only the generators, scalar 42, three
  edge scalars and two pairing cases. It has no randomised corpus and no malformed-encoding
  comparison.
- blst: there are no off-curve, non-subgroup, null or empty-pairing tests for
  `BlstBls12381Provider`, and the FFM MSM tests are random happy paths only.

#### F10 — Informational
- `BLS12381Pairing.FROBENIUS_COEFF_X/Y` (`:36-46`) are unused. `Y` is the conjugate of
  `ξ^((p−1)/2)`, not `ξ^((p−1)/2)` as commented.
- An empty DST is accepted by `expandMessage*` and `hashTo*`. RFC 9380 §3.1 says tags MUST be
  non-empty.
- `expandMessageXofShake256` always reduces an oversize DST to 32 octets (`k = 128`). That is
  right for the BLS12-381 suites and BBS-SHAKE, but the method name is generic.
- `zeroj-blst/.../native-image.properties` assumes FFM downcalls need no registration. This
  is unverified, since no native-image build was run.
- `zeroj-blst/BUILDING.md` names a stale config path (`com.bloxbean.cardano/zeroj-blst`) and
  the wrong module for the FFM tests.
- The `zeroj-bls12381` `reflect-config.json` is broader than needed (ADR-0021 D5 already
  accepted this).

## Threat model and trust assumptions
- **Untrusted:** every byte string and every JSON coordinate that reaches a decoder or
  verifier; every point a library consumer passes to a public API; scalars passed to public
  MSM entry points.
- **Secret:** BBS signing keys, `e`, proof randomness, hidden-message scalars; Pedersen
  values and blindings at generation; any scalar routed through `g{1,2}SecretScalarMul`.
- **Attacker capabilities considered:**
  - submits malformed or malicious encodings;
  - submits re-encoded valid proofs;
  - measures wall-clock timing of many secret-scalar operations by the same key/credential;
  - controls JVM system properties or `java.library.path` (in F3, as a local or
    misconfigured-deployment adversary);
  - influences release-pipeline artifact availability (F6).
- **Not considered:** micro-architectural (cache, power, EM) attacks. The pure-Java path makes
  no claim against them and this ADR does not add one.
- **Trusted:** the JDK's `BigInteger`, `SecureRandom` and SHA-256; the pinned blst source;
  the build host.

## Normative references (pinned)
- Sakemi et al., *Pairing-Friendly Curves*, `draft-irtf-cfrg-pairing-friendly-curves-11`, §4.2.1 (BLS12-381 parameters).
- RFC 9380, *Hashing to Elliptic Curves* (Aug 2023): §3.1, §4.1, §5.3, §6.6.2, §8.8.1, §8.8.2, Appendices E, F.2, J.9, J.10, K.1, K.2, K.6.
- ZCash BLS12-381 serialization (`zkcrypto/bls12_381` 0.8.0 `notes/serialization.rs`) as adopted by CIP-0381 and the Plutus V3 builtins.
- `supranational/blst` v0.3.15 (`bindings/blst.h`, `src/e1.c`, `src/e2.c`, `src/pairing.c`). Pin to the commit hash under D6.
- E. Brier, M. Joye, *Weierstraß Elliptic Curves and Side-Channel Attacks*, PKC 2002 (fixed-length scalar recoding by adding the group order).
- J.-S. Coron, *Resistance against Differential Power Analysis for Elliptic Curve Cryptosystems*, CHES 1999 (scalar blinding `k + m·r`).
- J. Jančár et al., *Minerva: The curse of ECDSA nonces*, TCHES 2020/4 (bit-length leakage → HNP).
- ZeroJ precedent: [ADR-0038](0038-jubjub-dsl-remediation-plan.md) Decision 4 (P4 fixed width, P7.2 blinded fixed schedule, operation-count gate).

## Security invariants
After this ADR is implemented:

- **I1 (output identity).** D1 changes no output. For every valid point `P` and every scalar
  `k`, `g{1,2}SecretScalarMul(P, k) = [k mod r]P`, bit-identical to `g{1,2}ScalarMul`.
- **I2 (fixed operation schedule).** For every `k ∈ [0, r)` and every prime-order `P ≠ O`,
  the secret ladder performs the same number of field-level point additions and doublings. No
  identity early-return is taken at any iteration except where §D1 lists it explicitly
  (scalars that occur with negligible probability for uniform secrets). A deterministic
  operation-count test enforces this.
- **I3 (honest contract).** No ZeroJ document or Javadoc claims a constant-time or
  side-channel contract for a provider without cited evidence. Secret-bearing generation stays
  **offline/isolated only** for both providers.
- **I4 (single native source).** Every native BLS12-381 code path in a released artifact comes
  from the same pinned, source-built `libblst`. Loading is not redirectable by system
  properties or library-path search.
- **I5 (no silent scalar or point corruption).** Every public entry point that takes a
  `BigInteger` scalar either reduces it mod `r` or rejects it. None truncates. Point inputs to
  public native entry points are subgroup-checked or explicitly documented as caller-validated,
  with a validating overload available.
- **I6 (canonical proof encoding).** Groth16 BLS12-381 verifiers accept exactly one encoding
  per proof point: affine with `z = 1`. Identity is rejected for proof points, as today.
- **I7 (fail-closed pairing products).** Provider-level `pairingProductIsIdentity` rejects
  empty input. Raw `BLS12381Pairing` documents that it validates nothing.
- **I8 (provider equivalence).** Pure-Java, blst and WASM providers return equal results, or
  all reject, on a shared randomised and malformed corpus.

## Decision

### D1 — Remove the bit-length channel from the pure-Java secret ladder (R3; revises ADR-0021 D1)
ADR-0021 D1 kept the variable-length behaviour and corrected only the Javadoc. This ADR
requires the schedule itself to be fixed, at the level ADR-0038 reached for Jubjub. The
offline/isolated classification **does not change**: this removes an algorithmic channel. It
does not make the JVM path constant-time.

Requirements: I1, I2, plus:
- the ladder never starts from the identity. Its first state is `(P, 2P)` for a scalar whose
  top bit is fixed;
- there is no zero-scalar early return on the secret path. `k = 0` runs the full schedule and
  produces `O` at the end;
- the iteration count is a constant independent of `k`.

Construction (decided r2, Q1):
- Draw a fresh blinding factor `m` uniformly from `[M_MIN, M_MAX] = [⌈2³¹⁹/r⌉, ⌊(2³²⁰ − r)/r⌋]`
  using `SecureRandom`, and set `k̂ = k + m·r` **without reducing**. For `0 ≤ k < r` this gives
  `k̂ ∈ [2³¹⁹, 2³²⁰)`: the top bit is fixed at bit 319, with no branch on `k`. Both ends of the
  range were checked numerically for `k ∈ {0, r−1}`, and values just outside the range fail for
  some `k`.
- The range holds about 2^64.1 values, so each call takes about 64 bits of fresh entropy. `m` is
  drawn by rejection sampling of 65-bit values, which branches on public randomness only.
- `[k̂]P = [k]P` holds only for `P` in the prime-order subgroup. The secret path must
  subgroup-check its base and reject anything else.
- The ladder starts at `(P, 2P)` and runs 319 fixed iterations of one addition and one doubling.
- RNG failure fails closed: there is no fallback to an unblinded ladder.
- Tests inject a seeded blinding source through a package-private seam, never a public one.

Rejected variant: `k̂ = 2^(W−1) + ((k + m·r − 2^(W−1)) mod r)`. The reduction cancels `m·r`, so the
"blinding" would have no effect. The unblinded deterministic recoding `k̂ = 2²⁵⁵ + ((k − 2²⁵⁵) mod r)`
is correct and branch-free, but leaves the per-bit Java branch replaying a fixed pattern on every
use of the same key; blinding changes that pattern on every call, which defeats averaging across
repeated signatures (the residual ADR-0038 later blinded for Jubjub).

Identity can still appear inside the ladder only when a ladder prefix is `≡ 0`, `−1` or `−1/2`
(mod `r`). With random `m` this has negligible probability, except at the final iteration for
`k ≡ 0` and `k ≡ −1 (mod r)`, where the result (or its successor) is the identity by definition.
Those cases are correct, because `add` handles `H = 0`, and the operation-count test lists them as
documented exceptions.

The per-bit selection between already-computed points stays a Java branch, and `BigInteger`,
field reductions, JIT and GC stay variable-time. The Javadoc must say exactly that.

Evidence required: the operation-count gate (I2); a timing benchmark recorded the way
ADR-0038 P7.4 recorded it (median, exact 95% CI, bit-length and Hamming-weight sweeps; a
record, not a CI assertion); bit-identical BBS and G1 Pedersen golden vectors (I1).

### D2 — Make the secret-path documentation and provider contract honest (R2)
- Correct `README.md:47`, `PureJavaBls12381Provider.java:17-18`, `zeroj-bbs/README.md:146-148`
  and `docs/component-status-2026-07-03.md:35`. Neither provider currently has an evidenced
  side-channel contract, blst's secret methods delegate to its public path, and secret-bearing
  generation is offline/isolated only.
- `BlstBls12381Provider.g{1,2}SecretScalarMul` should get a dedicated implementation:
  - convert the scalar to fixed-width 32-octet little-endian bytes without `toByteArray`
    sign/length variance;
  - always call blst with `nbits = 255`;
  - drop the zero early return;
  - zero the temporary arrays.

  Its Javadoc states that blst's internal scalar multiplication is what provides any
  side-channel property, and ZeroJ has not evaluated it.
- No document upgrades blst to "side-channel safe" until there is a cited upstream
  constant-time statement for the exact functions and version used, plus a ZeroJ review of the
  binding (Q2).

### D3 — One pinned, source-built `libblst` for all native paths (R2)
Preferred: migrate `BlstBls12381Provider`, `BlstPairing` and `Groth16BLS12381Verifier` from
`foundation.icon:blst-java` to the existing FFM binding over the source-built `libblst`.
- Functions: `blst_p1_deserialize`/`blst_p2_deserialize`, `blst_p1_affine_in_g1`/`blst_p2_affine_in_g2`,
  `blst_p1_affine_is_inf`, `blst_p1_mult`/`blst_p2_mult`, `blst_p1_add_or_double`,
  `blst_miller_loop`, `blst_fp12_mul`, `blst_final_exp`/`blst_fp12_finalverify`, `blst_fp12_is_one`.
- Check every `BLST_ERROR`.
- Remove the JNI dependency.

This also satisfies I4 and aligns with [ADR-0057](0057-webassembly-and-native-library-bindings.md)
D4 (blst isolation in images; on its design branch).

Interim, until migration lands (**superseded r2**: the maintainer chose the full migration in
one release, so these steps are not implemented):
- add Gradle dependency verification (a SHA-256 for `blst-java-0.3.2.jar`);
- document the JNI binary and its unknown blst version in `zeroj-blst/README.md` and the root
  README;
- make `BlstBls12381Provider.createDefault()` refuse to start if
  `supranational.blst.jniResource` is set (fail closed, with an explicit message).

### D4 — Fail-closed FFM MSM boundary (R2)
- Public `BlstG1Msm.msm*` / `BlstG2Msm.msm*` overloads that take `BigInteger` scalars reduce
  each scalar mod `r` before encoding. This matches `Bls12381Provider.g1ScalarMul`, and the
  prover already does it in `FlatScalars`. The flat/encoder internal paths keep their
  documented precondition (`[0, r)`, canonical LE).
- Throw `IllegalArgumentException` if `points.length != scalars.length`.
- Reject any 96/192-octet base whose first octet has the compression (`0x80`) or sort (`0x20`)
  flag set, before calling `blst_p*_deserialize`.
- Document that bases are not subgroup-checked on the hot path, and add a validating overload
  (`msmValidated`) that runs `blst_p*_affine_in_g*` on each base.

Alternative considered: rejecting out-of-range scalars. Rejected because it would make the
MSM's semantics differ from the SPI's.

### D5 — Canonical `z = 1` for Groth16 BLS12-381 proof points (R2)
`Groth16BLS12381PureJavaVerifier` and `Groth16BLS12381Verifier` require `z = 1` (G1) and
`z = (1, 0)` (G2) for `pi_a`, `pi_b`, `pi_c`, and reject everything else with the existing
malformed-input reason code, exactly as `PlonkBLS12381Verifier.validateG*Encoding` does.

Verification-key ingestion follows the same rule (r2: no fixture needs otherwise; see Q3).

Compatibility: snarkjs always emits `z = 1`, so honest proofs are unaffected. Any
non-canonical encoding that verifies today will be rejected. Record that in the changelog as
an intentional tightening.

### D6 — Release and build pipeline fail closed (R2)
- Replace `cp … || true` in `release.yml` with a check that fails the release if any expected
  `blst-native-<os>-<arch>` artifact is missing or empty. Record the SHA-256 of every bundled
  native library in the release notes.
- Pin `build-blst.sh` to the v0.3.15 commit hash and verify it after cloning
  (`git rev-parse HEAD`). Keep the tag only as a label.

### D7 — Raw pairing APIs and empty products (R2)
- `Bls12381Provider.pairingProductIsIdentity` (pure-Java, blst and WASM providers) rejects
  `length == 0` with `IllegalArgumentException`. Document the existing behaviour on
  mismatched lengths and identity pairs (skipped, contributing 1). BBS is unaffected because
  it always passes two pairs.
- `BLS12381Pairing.pairingCheck`/`millerLoop` Javadoc states that the class validates nothing
  and callers must use `Bls12381Codecs.requireValid` or a provider. Same for the
  `BlstPairing` helpers. `BlstPairing.g1ScalarMul` reduces mod `r`.
- Remove or fix the unreachable vertical-line branch in `lineFuncAdd`, so that a future
  unvalidated caller cannot get a wrong line silently. Preferred: throw on `T.x == Q.x`,
  which is impossible for validated inputs.

### D8 — `pow` with negative exponents (R1)
`MontFp381.pow(BigInteger)` and `MontFr381.pow(BigInteger)` throw `IllegalArgumentException`
on `exp.signum() < 0`. Correct the "fixed bit-length loop" Javadoc
(`MontFr381.java:153`). Document the canonical-limb precondition of `FpArith381`/`FrArith381`
on the class.

### D9 — Test, vector and differential gates (R1; release gates for this module)
- **RFC 9380:** add every J.9.1, J.9.2, J.10.1 and J.10.2 vector (all 5 messages, including
  `u[0]`, `u[1]`, `Q0`, `Q1`); every K.1, K.2 and K.6 vector; negative tests for `len_in_bytes`
  bounds (XMD 8161, XOF 65536). Load them from a machine-extracted resource file rather than
  hand-typed literals. Replace the self-referential oversize-DST test.
- **Pairing:** negative pairing-product tests (`e(G1,G2)`, `e(aG1,bG2)·e(−G1,(ab+1)G2)`);
  identity inputs; length mismatch; empty (after D7); bilinearity over at least 8 random
  scalar pairs. Add an **external GT KAT** from py_ecc 8.0.0, with the documented basis
  mapping and inversion, corroborating the self-pinned vector. Check (as ADR-0021 asked) that
  the tests fail against a constant-1 pairing and against `e⁻¹`.
- **Field:** random `Fp`/`Fp2` sqrt of squares and rejection of non-squares (Euler criterion
  as oracle); `sgn0` and `lexicographicallyLargest` vectors; independent `Fp6`/`Fp12` vectors
  from the review's Python reference; negative-exponent rejection (D8); non-canonical
  `fromMontLimbs` rejection (exists).
- **Secret ladder (D1):** the operation-count gate across `0, 1, 2, r−2, r−1`, low and high
  Hamming weight, and every bit length 1…255; bit-identity with `scalarMul`.
- **Cross-provider (I8):** one shared corpus, run against pure-Java, blst and WASM:
  - ≥ 256 random scalar multiplications per group;
  - 64 random multi-pairings;
  - the complete malformed-encoding corpus (lengths, flags, `x ≥ p`, off-curve, non-subgroup
    on both `y` signs, G2 halves swapped, infinity-with-bits);
  - scalars `{−1, 0, r−1, r, r+1, 2²⁵⁵+1, 2²⁵⁶+1, −2³⁰⁰}`.

  Every provider must give equal results or reject. The WASM leg runs in `assurance.yml`.
- **blst-specific:** negative `BlstBls12381Provider` tests (off-curve, non-subgroup, null,
  empty pairing); MSM tests for identity bases, zero scalars, out-of-range scalars, length
  mismatch, and flagged bases (D4).
- **Groth16 (D5):** a rescaled-`z` proof is rejected by both verifiers, and the original is
  accepted.

### D10 — Clean-ups (R0)
- Remove `FROBENIUS_COEFF_X/Y` from `BLS12381Pairing`. If a later optimisation needs them, it
  must reintroduce them with computed-in-test values.
- Reject an empty DST in `Bls12381Hash.expandMessage*` and in the provider `hashTo*`/`encodeTo*`
  methods (RFC 9380 §3.1 "MUST"). First confirm by grep that no caller passes an empty DST.
- Document the `k = 128` oversize-DST reduction on `expandMessageXofShake256`, or rename it to
  express the parameter.
- Run a real native-image build of a consumer of `zeroj-blst` FFM. Either add the
  foreign-downcall metadata GraalVM needs, or record that none is needed, with the build log.
  Coordinate with ADR-0057 D4.
- Fix the `zeroj-blst/BUILDING.md` path and module references.

### Not decided here (deferred)
- A genuinely constant-time pure-Java BLS12-381 path (fixed-limb, branchless select and
  reduction). This remains a future ADR, as ADR-0021 D1 said.
- Performance: endomorphism-based subgroup checks (Bowe/Scott), cyclotomic final
  exponentiation, single field stack. These remain ADR-0021 D4 items. They are R3 and need
  their own design, with the D9 gates in place first.

## Alternatives considered
- **D1: documentation only (ADR-0021 D1 status quo).** Rejected. The leak is algorithmic,
  large (about 4× from 1 to 255 bits) and cheap to remove. ZeroJ already set the precedent for
  Jubjub.
- **D1: route all secret operations to blst and drop the pure-Java secret path.** Rejected
  for now. The blst path has no evidenced contract either (F2), and the pure-Java default must
  keep working without native code (ADR-0044).
- **D3: keep `blst-java` and only document it.** Accepted only as the interim step. As a final
  state it leaves two blst versions in one process and a redirectable loader.
- **D4: reject out-of-range MSM scalars.** Rejected in favour of reducing mod `r`, to match SPI
  semantics (I8).
- **D7: keep `true` for empty products.** Rejected at the provider level (fail closed). Kept on
  the raw class, because there it is mathematically correct and documented.

## Compatibility
- D1: no output change (I1). Secret-path latency rises for short scalars; that rise is the fix
  working.
- D4, D7, D8, D10 (empty DST): behaviour changes only for inputs that are wrong today (silent
  truncation, empty product, negative exponent, empty tag). These are breaking for misuse
  only. Changelog entries are required.
- D5: rejects non-canonical Groth16 encodings that currently verify. snarkjs output is
  unaffected.
- D3: removes a transitive dependency (`foundation.icon:blst-java`) from `zeroj-blst`. Any
  downstream code that used its classes directly must migrate.

## Implementation milestones
Each milestone is a separate, reviewed PR with positive and negative tests.

| M | Scope | Decisions | Risk |
|---|---|---|---|
| M0 | Documentation corrections; interim JNI checksum and property guard | D2 (docs), D3 (interim) | R2 |
| M1 | Test gates that need no behaviour change: RFC 9380 full vectors, negative pairing tests, external GT KAT, field property tests | D9 (part) | R1 |
| M2 | Fail-closed small changes: `pow` negative, empty pairing product, raw-API Javadoc, `lineFuncAdd` guard, empty DST | D7, D8, D10 (part) | R1/R2 |
| M3 | Groth16 canonical `z = 1` in both verifiers, plus tests | D5 | R2 |
| M4 | FFM MSM boundary, plus tests; release `|| true` removal; blst commit-hash pin | D4, D6 | R2 |
| M5 | Secret ladder fixed schedule (pure Java), operation-count gate, timing record, golden-vector identity | D1 | R3 |
| M6 | blst dedicated secret methods; migrate JNI paths to FFM; drop `blst-java` | D2 (code), D3 | R2 |
| M7 | Shared cross-provider corpus (pure-Java / blst / WASM) in CI and `assurance.yml`; promote review harnesses | D9 (rest), I8 | R1 |
| M8 | GraalVM native-image verification for `zeroj-blst` FFM | D10 (part) | R0/R1 |

M1 lands before M2–M6, so every behaviour change is made against stronger gates.

## Verification and test-vector strategy
- Expected values come from outside the code under test: RFC 9380 text (machine-extracted),
  py_ecc 8.0.0, Python big-integer references, `hashlib`, the zkcrypto `bls12_381` 0.8.0 WASM
  oracle, and blst.
- Every behaviour change ships with a negative test that fails before the change.
- Every R2/R3 milestone re-runs `:zeroj-bls12381:test`, `:zeroj-blst:test`,
  `:zeroj-crypto-blst:test`, `:zeroj-verifier-groth16:test`, `:zeroj-verifier-plonk:test`,
  `:zeroj-bbs:test`, and `-PincludeAssurance :zeroj-bls12381-wasm:test :zeroj-bbs-wasm:test :zeroj-bbs:test`.
- M5 also requires bit-identical BBS (CFRG fixtures) and G1 Pedersen profile vectors, plus the
  ADR-0038-style timing record.

## Production and audit gates
None of the following is changed by this ADR:
- `zeroj-bls12381` stays **Beta — verification-grade**;
- secret-bearing BBS and Pedersen generation stays **offline/isolated only** on every provider;
- nothing is approved for value-bearing or mainnet use.

Before a maturity upgrade:
1. M1–M7 complete, with the evidence above recorded.
2. An external cryptographic review of `zeroj-bls12381` (field, codecs, pairing,
   hash-to-curve) and of the native binding.
3. For any secret-scalar claim: a side-channel evaluation of the exact provider, version and
   platform, by a reviewer outside the implementation team.
4. For D3: the source-built `libblst` checksums published per release.

## Open questions (require maintainer / external decision)
- **Q1 (D1) — decided r2:** fixed-length recoding with blinding, using the m-range construction
  in D1 (width 320, 319 fixed iterations).
- **Q2 (D2):** which upstream statement, if any, documents blst's constant-time properties for
  `blst_p1_mult`/`blst_p2_mult` at v0.3.15, and does the FFM binding preserve them?
- **Q3 (D5) — decided r2 (moot):** D5 requires `z = 1` for verification keys as well as proofs.
  A scan of every Groth16 BLS12-381 fixture (40 VK and 9 proof points) found no `z ≠ 1`, so
  ffjavascript's interpretation of non-unit `z` no longer matters to ZeroJ.
- **Q4 (D7) — decided r2:** document only. `BLS12381Pairing` is used directly by production
  code in `zeroj-crypto`, both verifiers and the benchmarks, so it stays public and its Javadoc
  states that it validates nothing.

## Consequences
### Easier
- Library consumers get a precise statement of what the pure-Java module guarantees
  (§Correctness assessment) and fail-closed behaviour at the edges that are misused today.
- One native blst build removes version skew and a redirectable loader.
- Future performance work (ADR-0021 D4) gets full RFC vectors, negative pairing tests and a
  three-provider differential to land against.

### Harder
- The secret ladder gets slower for short scalars; that is the fix working.
- There is more CI surface: a shared corpus across three providers, and a release that fails
  when native artifacts are missing.
- D3 is a non-trivial binding migration.

## Risks
- **D1 regressions:** a recoding error breaks BBS and Pedersen outright. That is mitigated by
  I1 (bit-identical golden vectors) and the operation-count gate. A recoding error that is
  *output-correct* but still leaky would be caught only by the timing record, which is
  evidence, not proof.
- **Over-reading this ADR:** passing these gates does not make any Java path constant-time,
  and does not make any component production-ready. AGENTS.md's maturity rules still apply.
- **D3 migration:** the FFM pairing path must produce exactly the accept/reject behaviour of
  the JNI path it replaces. This is covered by the M7 corpus and the Groth16 real-proof
  vectors.
- **D5 compatibility:** an integration that currently emits non-canonical `z` would break.
  This is mitigated by the changelog and the snarkjs default.
