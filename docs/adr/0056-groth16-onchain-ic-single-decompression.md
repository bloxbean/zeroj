# ADR-0056: On-chain Groth16 verifier decompresses each IC point once

## Status
Proposed — 2026-10-10. Tracked as #84. Builds on PR #85, which decompresses the proof and key
points once and was approved at `8ccee4d`. This ADR covers the IC points, which PR #85 left
unchanged pending a reviewed decision.

**Risk class: R2.** This changes the on-chain verifier implementation (`Groth16BLS12381Lib`), not
the verification relation, encodings, transcript, setup or providers.

## Date
2026-10-10

## Context
`Groth16BLS12381Lib.verify` computes `vk_x = IC[0] + Σ input_i · IC[i+1]` and then checks the
pairing. Until PR #85 every point was decompressed twice:
- once by the canonical round-trip check `compress(uncompress(b)) == b`;
- once to be used.

PR #85 removed the duplicate for the 7 proof and key points, saving 457.4e6 steps. The `n + 1` IC
entries are still decompressed twice, at 52.9e6 steps each under the Plutus V3 PV11 cost model:
- 9 public inputs: 0.53e9 steps (5.3% of `maxTxExSteps`);
- 24 public inputs: 1.32e9 steps (13.2%).

**ADR-0045 V1 (affirmed, unchanged).** Every `IC[i]` that is infinity, off-curve, off-subgroup or
non-canonical is rejected **before any scalar multiplication or pairing**.

**Measured alternatives** (Julc pre18 VM; steps saved per verification compared with PR #85, and
the effect on V1 and on outcomes):

| Option | Mechanism | V1 as written | Outcomes compared with `458bfb1` | 2 inputs | 9 inputs | 24 inputs |
|---|---|---|---|---|---|---|
| A | Fused walk: validate `IC[i]`, then multiply, one entry at a time | **No.** Earlier validated entries are multiplied before later entries are validated | Identical | +162e6 | +540e6 | +1.32e9 |
| B | Separate validation pass, then `g1PointsFromCompressed` and `bls12_381_G1_multiScalarMul` | Yes | Identical | −219e6 | +144e6 | +924e6 |
| C | Drop the canonical round-trip and rely on `uncompress` | — | — | — | — | — |
| **D″** | Byte checks, then a recursive walk that validates every entry once **on the way down** and multiplies **on the way back up**; counts compared afterwards | **Yes** | Identical except one listed malformed-key ordering case | +156e6 | +520e6 | about +1.30e9 |

Notes on the table:
- **B's numbers include** the second decompression that `g1PointsFromCompressed` performs, and
  the builtin's fixed cost of about 0.42e9 steps.
- **C is not normatively established.** CIP-0381 (pinned at `86b89208`) specifies the ZCash
  encoding but does not state that `uncompress` rejects every non-canonical encoding. C would
  change the validation argument and is not pursued.
- **D″'s figures** are the measured savings on top of PR #85, from the differential test.

## Decision
**D1. Adopt D″ for `verify`.**
1. `validScalars(inputs)`, unchanged.
2. **IC byte checks** over the whole list. Every entry is 48 bytes and not the compressed point at
   infinity. Otherwise `false`, without decompressing anything.
3. **`icSum`.** A recursive walk decompresses each entry once and checks its canonical encoding:
   `compress(point) == bytes` and not infinity. It recurses before multiplying, so **every entry
   is validated before the first `scalarMul`**. Each `input_i · IC[i+1]` is added on the way back
   up, only over the common prefix of inputs and entries. An entry that fails here fails the
   script with a builtin error. In practice this is an undecodable or off-subgroup encoding: those
   already failed in the old code, because `uncompress` fails.
4. `matchingLengths(inputs, IC[1..])`, unchanged and still before any pairing. Otherwise `false`.
5. The proof and key checks and the pairing are those of PR #85, unchanged.

**D2. `verifyFour`.** Its five IC entries are each validated in order (length, decompression,
canonical non-infinity), exactly as the old `validIcPoints` did, and decompressed once. Only
then is `vk_x` computed from the same points. The outcomes are identical to `458bfb1`.

**D3. Multi-scalar multiplication is deferred.** It needs an incremental native point list, so
that the already validated points can be passed to `bls12_381_G1_multiScalarMul` without a second
decompression. That is Julc issue bloxbean/julc#240. With it, the estimated extra saving is about
+0.14e9 steps at 9 inputs and about +0.92e9 at 24 inputs, used only from about 8 inputs. It is
negative below that. It will be a separate revision once Julc provides the API.

## Invariants
- **I1 (ADR-0045 V1).** No scalar multiplication or pairing happens before every IC entry has
  been checked for length, decompressed (curve and subgroup) and checked canonical and not infinity.
- **I2 (ADR-0045 V2, ADR-0025).** The proof and key points keep their checks, in their order,
  unchanged from PR #85.
- **I3 (accept set).** The library accepts exactly the inputs that `458bfb1` accepts.
- **I4 (rejection form).** `false` and a builtin failure may swap only on malformed key data:
  - **Listed case** (the test's `DIVERGENCES`): an undecodable IC entry followed by a wrong-length
    or infinity entry now returns `false`, where the old code failed at the undecodable entry.
  - **Theoretical case:** an IC encoding that `uncompress` accepts but that is not canonical would
    now fail instead of returning `false`. None is known; none appears among the vectors.

  Both forms reject the transaction.
- **I5 (cost).** An accepted verification saves exactly `(n + 4)` G1 and 4 G2 decompressions
  compared with `458bfb1`, within half a G1 decompression. `verifyFour` saves 8 G1 + 4 G2.

## Consequences
- **Savings per verification** compared with `main`: 0.61e9 steps at 2 inputs, 0.98e9 at 9, and
  about 1.76e9 at 24.
  - For zeroj-usecases (mainnet prices, 0.0000721 lovelace per step) this means about 0.071 ADA
    per auction bid (9 inputs) and about 0.127 ADA per confidential-note transfer (24 inputs).
  - It also frees 6–18% of the step budget for larger circuits.
- **Script hashes** of every validator using the library change. The script size grows by 127
  bytes compared with `458bfb1`: `Groth16BLS12381Verifier` goes from 1,059 to 1,186 bytes.
- **Callers that combine `verify` with a fallback** (`verify(...) || other`) observe I4's
  `false`/failure swap only for malformed keys. Keys are deployment parameters or hash-pinned.

## Verification
`Groth16SingleDecompressionDifferentialTest` runs the library and a test-only copy of `458bfb1`
through outcome probes (accept / `false` / builtin failure) and checks:
- **Proofs:** honest proofs for 2 (snarkjs), 3, 4 and 9 public inputs, plus zero-input proofs.
- **Mutations:** over 40 per proof: infinity, length, flags, negation, off-curve, scalar range,
  counts, check order across points, and zero-input IC infinity.
- **Pairing-preserving infinity vectors** (review F1 on PR #85): inputs are 0 and every IC entry is
  `G`, with exponents such that the pairing holds. They isolate each of the 7 proof and key
  infinity checks, with explicit expected `FALSE`, plus an accepted baseline. This covers both
  `verify` and `verifyFour`.
- **Equality:** outcomes are equal except the I4 listed case, and the I5 saving is asserted
  exactly.
- **Suites:** the `:zeroj-onchain-julc` and `:zeroj-integration-tests` suites, and zeroj-usecases
  (VM and Yaci DevKit) against a local publish.

## Risks
- **Recursion depth:** one Julc call per IC entry. The previous code was also recursive, so the
  depth is no worse.
- **I4's form change** is visible only to composite validators on malformed keys.
- **Not an audit:** this ADR is not an audit of the verifier. ADR-0039's assurance classes apply
  unchanged.

## Revision history
- **r1** (2026-10-10): initial proposal. It records the measured alternatives A, B, C and D″,
  chooses D″, and defers multi-scalar multiplication to bloxbean/julc#240.
