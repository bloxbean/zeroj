# ADR-0066: BLS12-381 PlonK `.ptau` Streaming Import, `n + 6` SRS Sizing, and `.zkey` Importer Withdrawal

## Status

Proposed (2026-11-21)

## Risk classification

- **R2:** Untrusted `.ptau` SRS codec/import boundary (`PtauImporterBLS381`), PlonK quotient-split
  and SRS sizing (`PlonKProverBLS381`, `PlonKSetupBLS381`, `PlonkSetupCache`), and explicit
  withdrawal of the broken `PlonKZkeyImporterBLS381` entry point.

## Context

Three coupled defects broke BLS12-381 PlonK ceremony-SRS interoperability against `snarkjs@0.7.6`:

1. **`PtauImporterBLS381` rejected every valid BLS12-381 `.ptau` file and could not stream large
   ceremony files.** Header prime parsing called `readFieldLE(..., FP, ...)` which rejected any
   value `>= FP`, unconditionally rejecting `prime == FP`. It also ignored `ceremonyPower`, mapped
   infinity sentinels `(0, 0)` / `(0, 0, 0, 0)` in `readG1Mont`/`readG2Mont` (which `toG1`/`toG2`
   then converted into off-curve non-infinity `(0, 0)` points), and buffered the entire `.ptau`
   stream in memory under a 64 MiB cap (too small for real BLS12-381 `.ptau` files above power ~15).
2. **`PlonKProverBLS381`, `PlonKSetupBLS381`, and `PlonkSetupCache` required `2n` SRS G1 powers
   instead of `n + 6`.** Because `t3` was allocated to `tCoeffs.length - 2n = 2n` (with `n - 6`
   trailing zero coefficients), a same-power `snarkjs` `.ptau` — which contains `2n - 1` G1 powers
   — was rejected even though `deg(t) <= 3n + 5` and `t3` only ever has `n + 6` coefficients.
3. **`PlonKZkeyImporterBLS381` was fundamentally incompatible with `snarkjs@0.7.6` PlonK `.zkey`
   files.** Beyond the same prime-parsing bug, it read sections 7–11 in the wrong order
   (`Ql, Qr, Qm, Qo, Qc` vs `snarkjs` `Qm, Ql, Qr, Qo, Qc`, each stored as `n` coefficients + `4n`
   extended evaluations), misparsed section 13 (`Fr` Lagrange polynomials) as 96-byte G1 points,
   required `2n` points in section 14 (snarkjs writes `n + 6`), and skipped sections 3–6 (additions
   and A/B/C wire maps). Several documentation pages still advertised `.zkey` import as working.

## Threat model & trust assumptions

- **Untrusted `.ptau` stream:** Callers may import `.ptau` files downloaded from public or untrusted
  mirrors. Malicious inputs may contain wrong curve primes, non-canonical coordinates (`>= p`),
  identity points, off-curve or small-subgroup points, inconsistent powers of `tau`, malformed or
  duplicate sections, trailing bytes, or multi-GB payloads designed to trigger OOM.
- **Content pinning:** When `expectedSha256` is supplied, the importer hashes the entire byte stream
  (including skipped sections) and verifies exact SHA-256 equality before returning an `SRS` or
  running pairing consistency checks.
- **Ceremony trust:** SRS soundness still depends on at least one honest phase-1 ceremony
  participant; `PtauImporterBLS381` verifies algebraic structure and optional SHA-256 pinning, not
  ceremony provenance.

## Pinned normative references

- `snarkjs@0.7.6`:
  - `src/powersoftau_utils.js` (`writePTauHeader`, `readPTauHeader`: 60-byte Section 1 = `n8`,
    raw unsigned LE `q`, `power`, `ceremonyPower`)
  - `src/powersoftau_new.js` (Section 2 = `(2^(power+1) - 1) * 96` B, Section 3 = `2^power * 192` B)
  - `src/plonk_setup.js` (Sections 7–11 selector layout, Section 13 Lagrange Fr, Section 14 `n + 6` G1)
  - `src/plonk_prove.js` (lines 649–684: `deg(T) < 3n + 6` degree assertion and `T3` length `n + 6`)
- `ffjavascript@0.3.1`: `src/wasm_curve.js` (LEM affine zero encoding `0^96` / `0^192`).
- [ADR-0047](0047-snarkjs-bidirectional-interop-export-and-ci.md) (pinned `snarkjs@0.7.6` CI oracle
  and `-PrequireSnarkjs`).

## Decision & exact security invariants

### I1 — Streaming `.ptau` parser with exact `snarkjs@0.7.6` framing

`PtauImporterBLS381.importPtau(InputStream, int maxPoints, byte[] expectedSha256)` streams the input
sequentially without buffering the entire file:

- Validates global header (`"ptau"`, `version == 1`, `1 <= numSections <= 64`) and rejects duplicate
  section IDs, negative sizes, premature EOF, and trailing bytes after the final section.
- Section 1 (must precede Sections 2 and 3): exact size `60` bytes; `n8 == 48`; raw unsigned LE
  `prime == MontFp381.modulus()`; `1 <= power <= 32`; `power <= ceremonyPower <= 32`.
- Section 2 (`tauG1`): exact size `((1L << (power + 1)) - 1) * 96`; loads `min(availableG1, maxPoints)`
  points (bounded by `MAX_IMPORT_POINTS = 2^24` to prevent OOM on unbounded calls) and streams past
  remaining bytes.
- Section 3 (`tauG2`): exact size `(1L << power) * 192`; loads the first 2 G2 points (`G2`,
  `tau·G2`) and streams past remaining bytes.
- Remaining sections (4–7, 12–15, etc.) are streamed past while still feeding `SHA-256` when
  `expectedSha256 != null`. Full-stream SHA-256 equality is verified before pairing consistency
  checks and before returning `SRS`.

### I2 — Strict SRS point validation & infinity rejection

- Every loaded coordinate is decoded via `MontFp381.fromMontLimbs(...)` (canonical `< p`, no silent
  modular reduction).
- Infinity (`(0, 0)` in G1, `(0, 0, 0, 0)` in G2) is explicitly rejected for all loaded SRS points.
  Defensively, `toG1`/`toG2` also map `isInfinity()` to `G1Point.INFINITY`/`G2Point.INFINITY` rather
  than constructing off-curve `(0, 0)`.
- Every loaded point is checked for curve membership (`isOnCurve()`) and prime-order subgroup
  membership (`isValid()`).
- Anchors `tauG1[0] == G1`, `tauG2[0] == G2`, and pairing progression
  `e(tauG1[i], G2) == e(tauG1[i-1], tauG2[1])` are verified for every loaded G1 power.

### I3 — Exact `t3 = n + 6` quotient-split & SRS sizing

- With 11 blinding scalars (`deg(aBlind), deg(bBlind), deg(cBlind) <= n + 1`, `deg(zBlind) <= n + 2`),
  the quotient polynomial `t(X)` has degree `<= 3n + 5` (`3n + 6` coefficients).
- `PlonKProverBLS381` sizes `t3` to exact length `n + 6` (indices `2n .. 3n + 5`) and throws
  `IllegalStateException` if any coefficient at index `>= 3n + 6` is non-zero (matching
  `snarkjs@0.7.6` `plonk_prove.js:649-651`).
- `PlonKSetupBLS381.validateSrs`, `PlonKProverBLS381.validateProverInputs`, and
  `PlonkSetupCache` require `srsG1.length >= domainSize + 6` (minimum `domainSize = 8`, where
  same-power `.ptau` provides `2n - 1 = 15 >= 14 = n + 6` powers).

### I4 — Explicit withdrawal of `PlonKZkeyImporterBLS381`

- Both `PlonKZkeyImporterBLS381.importZkey(InputStream)` and `importZkey(InputStream, byte[])`
  fail explicitly with `UnsupportedOperationException` citing this ADR and directing callers to
  `PtauImporterBLS381` + `PlonKSetupBLS381`. Full snarkjs PlonK `.zkey` import requires a separate
  format/wire-map rework.

### I5 — Documentation accuracy

- Align `README.md`, `www/src/content/docs/guides/proving/plonk.md`,
  [ADR-0047](0047-snarkjs-bidirectional-interop-export-and-ci.md), and `zeroj-crypto/README.md`
  to remove false `.zkey` import claims, document `PtauImporterBLS381` + `PlonKSetupBLS381`, and
  reconcile PlonK's status as Experimental (with 11 blinding scalars already implemented).

## Alternatives considered

1. **Full snarkjs PlonK `.zkey` rework now:** Requires implementing snarkjs addition gates, wire-map
   deserialization (sections 3–6), `writeP4` selector/sigma layout (sections 7–12), and Fr Lagrange
   loading (section 13). Deferred because PlonK remains Experimental and universal `.ptau` import +
   `PlonKSetupBLS381` already unlocks public-ceremony BLS12-381 PlonK proving.
2. **Keep `2n` SRS requirement and require a `.ptau` one power larger:** Rejected because `t3` has
   exact degree `<= n + 5` (`n + 6` coefficients); lowering to `n + 6` eliminates wasted MSM work
   on `n - 6` trailing zeros and makes same-power `.ptau` files work natively.

## Compatibility & breaking notes

- `PlonKZkeyImporterBLS381.importZkey(...)` now throws `UnsupportedOperationException` instead of
  failing with a misleading `IOException` ("prime is not canonical"). No in-repo production code
  called it.
- `PtauImporterBLS381` now requires exact `snarkjs@0.7.6` Section 1 length (60 bytes including
  `ceremonyPower`) and exact Section 2/3 sizes matching `power`; synthetic test fixtures must
  conform to the `snarkjs` layout.
- `PlonKSetupBLS381`, `PlonKProverBLS381`, and `PlonkSetupCache` now accept SRS lengths in
  `[domainSize + 6, 2 * domainSize)` that were previously rejected.

## Milestones

| Milestone | Scope | Status |
|---|---|---|
| M1 | Streaming `PtauImporterBLS381` + infinity/canonical/subgroup/SHA-256 enforcement | Implemented |
| M2 | `t3 = n + 6` sizing & degree check across `PlonKProverBLS381`, `PlonKSetupBLS381`, `PlonkSetupCache` | Implemented |
| M3 | Explicit `UnsupportedOperationException` withdrawal of `PlonKZkeyImporterBLS381` | Implemented |
| M4 | Offline positive/negative/70 MiB streaming tests + live same-power `snarkjs@0.7.6` `.ptau -> setup -> prove -> snarkjs plonk verify` CI test | Implemented |
| M5 | Documentation alignment across `README.md`, `plonk.md`, ADR-0047, and `zeroj-crypto/README.md` | Implemented |
| M6 | External cryptographic review before any promotion of PlonK out of Experimental | Open (mandatory gate) |

## Verification & test-vector strategy

- Offline positive tests: synthetic BLS12-381 `.ptau` full + bounded `maxPoints` import, SHA-256
  pin pass/mismatch, and a 70 MiB virtual streaming test exceeding the former 64 MiB cap.
- Offline negative tests: null/truncated/wrong-hash/duplicate-section/wrong-prime/trailing-bytes,
  infinity in G1/G2, off-curve, small-subgroup `(0, 2)`, non-canonical `>= p`, pairing-inconsistent
  SRS power, and `domainSize + 5` short SRS rejection alongside `domainSize + 6` acceptance.
- Live differential CI test (`PtauImporterBLS381Test` in `.github/workflows/assurance.yml` under
  `-PrequireSnarkjs`): generates a live same-power `snarkjs@0.7.6` `power=3` BLS12-381 `.ptau`,
  imports exact `14` (`8 + 6`) points with SHA-256 pinning, runs `PlonKSetupBLS381` +
  `PlonKProverBLS381`, exports snarkjs JSON, and verifies with live `snarkjs plonk verify`.

## Revision history

- **2026-11-21:** Initial `Proposed` ADR for PR-4 (`PtauImporterBLS381` streaming fix, `t3 = n + 6`
  SRS sizing, `PlonKZkeyImporterBLS381` withdrawal, and doc alignment).
