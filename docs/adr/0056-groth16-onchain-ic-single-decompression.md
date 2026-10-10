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
the effect on V1 and on outcomes). A and B were measured with a scratch harness that is not part
of this ADR's PR; D″ is measured by the PR's own tests.

| Option | Mechanism | V1 as written | Outcomes compared with `458bfb1` | 2 inputs | 9 inputs | 24 inputs |
|---|---|---|---|---|---|---|
| A | Fused walk: validate `IC[i]`, then multiply, one entry at a time | **No.** Earlier validated entries are multiplied before later entries are validated | Identical | +162e6 | +540e6 | +1.32e9 |
| B | Separate validation pass, then `g1PointsFromCompressed` and `bls12_381_G1_multiScalarMul` | Yes | Identical | −219e6 | +144e6 | +924e6 |
| C | Drop the canonical round-trip and rely on `uncompress` | — | — | — | — | — |
| **D″** | Byte checks, then a recursive walk that validates every entry once **on the way down** and multiplies **on the way back up**, only when the counts agree | **Yes** | Identical except one malformed-key class (I4) | +156e6 | +518e6 | +1.29e9 |

Notes on the table:
- **B's numbers include** the second decompression that `g1PointsFromCompressed` performs, and
  the builtin's fixed cost of about 0.42e9 steps.
- **C is not normatively established.** CIP-0381 (pinned at `86b89208`) specifies the ZCash
  encoding but does not state that `uncompress` rejects every non-canonical encoding. C would
  change the validation argument and is not pursued.
- **D″'s figures** are the measured savings on top of PR #85, from the differential test.

## Threat model and trust assumptions
- **Untrusted:** the proof (A, B, C) and the public inputs, which come from the redeemer or datum.
  The verification key (alpha, beta, gamma, delta, IC) is a deployment parameter, or is
  hash-pinned by the calling validator.
- **Assets:** the soundness of the verifier, i.e. which (proof, inputs, key) triples are
  accepted. No secret is handled on-chain.
- **What this change may not do:** change the accept set; let any IC point reach a scalar
  multiplication or the pairing before it has been fully validated (ADR-0045 V1); weaken any
  proof or key check (V2).
- **Trusted:** the ledger's BLS12-381 builtins. They are evaluated in the node by cardano-base's
  blst bindings, and in tests by the Julc VM (`foundation.icon:blst-java:0.3.2`).

## Pinned references
- ADR-0045 (V1, V2) and ADR-0025 (the non-infinity rule), as on `main` at `458bfb1`.
- CIP-0381 at `86b89208`: the ZCash compressed encoding and the BLS builtins. It does not define
  which encodings `uncompress` must reject.
- The Plutus V3 cost model at protocol version 11, as in Julc pre18 (`DefaultCostModel`, and
  `plutus-v3-pv11-costs-v1.params`) and on Yaci DevKit: G1 uncompress 52,948,122 steps, G2
  uncompress 74,698,472, G1 scalarMul intercept 76,433,006, G1 multiScalarMul intercept
  321,837,444 and slope 25,087,669 per element, millerLoop 254,006,273, finalVerify 333,849,714.
- JuLC `v0.1.0-pre18` (`a29e6c71`) for M1, for the lowering of strict lets, lazy `?:` and
  `Builtins.error()`. M2 is built and measured with JuLC #241 at `4cc63c24` (local snapshot
  `0.1.0-pre19-4cc63c24-SNAPSHOT`); its native list cons is strict and evaluates the element
  first (ADR-047 Amendment 1 in JuLC). The merge gate (M2) re-pins the released version.
- **Multi-scalar multiplication semantics (M2).** The normative text and the ledger's
  implementation disagree on degenerate lists:
  - CIP-0133 at `86b89208`, §Specification: "The arrays of scalars and group elements must be
    non-empty and of equal size. If the input arrays are empty or not equal, the functions must
    fail."
  - Plutus at `da9949a6` (`plutus-core/plutus-core/src/PlutusCore/Crypto/BLS12_381/G1.hs`,
    `multiScalarMul`): fails only on a scalar over 512 bytes, then computes
    `blsMSM (zip ss points)`, so it truncates to the shorter list. The Julc VM
    (`BlsOperations.g1MultiScalarMul`) also truncates and returns the identity on empty lists.

  The library depends on neither behaviour. It calls the builtin only when the input and IC
  counts agree and there are at least 7 inputs, so both lists are non-empty and of equal length,
  and every scalar is in `[0, r)` (`validScalars`), far below the 512-byte bound and unchanged by
  any reduction mod r. Every reading of the builtin therefore returns `Σ s_i·P_i` here.

## Decision
**D1. Adopt D″ for `verify`.**
1. `validScalars(inputs)`, unchanged.
2. **IC byte checks** over the whole list. Every entry is 48 bytes and not the compressed point at
   infinity. Otherwise `false`, without decompressing anything.
3. **Count agreement.** `matchingLengths(inputs, IC[1..])` is a pure list walk that cannot fail.
   It is evaluated here only so that the walk can skip every multiplication when the counts
   disagree.
4. **`icSum`.** A recursive walk decompresses each entry once and checks its canonical encoding:
   `compress(point) == bytes` and not infinity. It recurses before multiplying, so **every entry
   is validated before the first `scalarMul`**. When the counts agree, each `input_i · IC[i+1]`
   is added on the way back up. When they disagree, nothing is multiplied: every entry is still
   validated, and then `false` is returned, as before. An entry that fails here fails the script
   with a builtin error. In practice this is an undecodable or off-subgroup encoding: those
   already failed in the old code, because `uncompress` fails.
5. The proof and key checks and the pairing are those of PR #85, unchanged.

**D2. `verifyFour`.** Its five IC entries are each validated in order (length, decompression,
canonical non-infinity), exactly as the old `validIcPoints` did, and decompressed once. Only
then is `vk_x` computed from the same points. The outcomes are identical to `458bfb1`.

**D3. Multi-scalar multiplication (milestone M2).** Passing the already validated points to
`bls12_381_G1_multiScalarMul` without a second decompression needs an incremental native point
list, which JuLC lacked (bloxbean/julc#240); r1 therefore deferred it. Since r4 it uses JuLC's
incremental native lists (bloxbean/julc#241: `g1PointsEmpty`, `g1PointsCons`, `scalarsEmpty`, `scalarsCons`). From 7 public inputs, `verify` takes `icSumMsm` when the counts agree:
1. The same walk validates every IC entry once on the way down: decompression, then canonical encoding and not infinity (`validatedIcPoint`).
2. On the way back up it conses each validated point onto a native `JulcG1Points` list.
3. Only after the walk has returned, so after every entry is validated (I1), it computes
   `vk_x = IC[0] + bls12_381_G1_multiScalarMul(scalars, points)`, where `scalars` is the native list
   of the public inputs.
4. Below 7 inputs, or when the counts disagree, D″'s path is unchanged.

The two paths validate identically, so I1–I4 hold for both. The threshold was measured on the
same proofs, as steps saved compared with `458bfb1`:

| Inputs | D″ (per-input `scalarMul`) | Multi-scalar | Difference |
|---|---|---|---|
| 2 | 0.611e9 | 0.393e9 | −0.218e9 |
| 3 | 0.662e9 | 0.497e9 | −0.165e9 |
| 4 | 0.712e9 | 0.601e9 | −0.111e9 |
| 9 | 0.976e9 | **1.116e9** | +0.140e9 |
| 24 | 1.752e9 | **2.676e9** | +0.924e9 |

The multi-scalar path gains about 53e6 steps per input over the per-input path, and the two cross
between 6 and 7 inputs. With the threshold in place (r5, measured with JuLC `4cc63c24`), the
saving is 0.814e9 steps at 6 inputs (per-input path) and 0.908e9 at 7 (multi-scalar path).
Fable's review of `5ffa908` forced each path at 5–10 and 24 inputs: the per-input path would save
0.865e9 at 7, and the multi-scalar path about 5–10e6 less than the per-input path at 6, so 7 is
the first size where it pays. The multi-scalar savings at 7, 9 and 24 inputs are pinned in the test to
within 1e7 steps, and the threshold itself is pinned by counting the operations each accepted
proof runs (I6). It needs the JuLC release that contains #241; until then M2 builds only against
a local JuLC snapshot of #241.

## Invariants
- **I1 (ADR-0045 V1).** No scalar multiplication or pairing happens before every IC entry has
  been checked for length, decompressed (curve and subgroup) and checked canonical and not infinity.
  On the multi-scalar path this validation is the only guard against an infinity IC entry: the
  node's `blsMSM` (cardano-base at `d9217fb7`,
  `cardano-crypto-class/src/Cardano/Crypto/EllipticCurve/BLS12_381/Internal.hs`) silently drops
  pairs whose point is infinity or whose scalar is 0, and returns the identity for an empty list,
  rather than failing.
- **I2 (ADR-0045 V2, ADR-0025).** The proof and key points keep their checks, in their order,
  unchanged from PR #85.
- **I3 (accept set).** The library accepts exactly the inputs that `458bfb1` accepts.
- **I4 (rejection form).** `false` and a builtin failure may swap only on malformed key data:
  - **The class.** An IC entry that `uncompress` rejects, at any position, followed by a
    wrong-length or infinity entry now returns `false`. The old code failed at the undecodable
    entry. The test's `DIVERGENCES` pins three instances: the undecodable entry first and at a
    later position, followed by a wrong-length entry and by an infinity entry.
  - **An IC encoding that `uncompress` accepts but that is not canonical** would fail instead of
    returning `false`. With blst this cannot happen: blst rejects a cleared compression bit,
    `x ≥ p`, and an infinity flag with a non-zero body or a sort bit. And because the G1 and G2
    cofactors are odd, no point has `y = −y`, so the sort bit always round-trips. The review
    vectors (`x ≥ p`, `0xE0‖0`, infinity with a non-zero body) fail in `uncompress` in both
    libraries. CIP-0381 does not make these rejections normative, so the canonical re-compression
    stays, as defense in depth; through `verify` its failure branch is not reachable.

  Both forms reject the transaction.
- **I5 (cost).** Below 7 inputs, an accepted verification saves `(n + 4)` G1 and 4 G2
  decompressions compared with `458bfb1`, less the byte checks and the path choice:
  - The overhead is about 2e6 steps per IC entry (byte checks, count walk and threshold walk).
    The test window is `[expected − 2.4e6·(n + 1) − 4e6, expected + 5e6]`. It is applied only up
    to 7 IC entries (below the threshold, and `verifyFour`), where it is far narrower than one G1
    decompression, so one decompression more or fewer fails; the test asserts the width.
  - From 7 inputs (M2) the saving also includes the replaced scalar multiplications, so it is
    pinned per size instead: 0.908e9 steps at 7 inputs, 1.116e9 at 9 and 2.676e9 at 24, to
    within 1e7 (less than a fifth of one decompression).
  - Measured with M2 (JuLC `4cc63c24`): 0.611e9 steps at 2 inputs, 0.662e9 at 3, 0.712e9 at 4,
    0.814e9 at 6. M1 alone (r2, JuLC pre18) measured 0.614e9 at 2, 0.976e9 at 9 and 1.752e9 at
    24; the difference at 2 inputs is M2's threshold check.
  - `verifyFour` saves 8 G1 + 4 G2: 0.726e9 steps, slightly above the formula, because it also
    drops the old validation recursion.
- **I6 (rejection cost).** A rejection costs at most the reference's cost plus 3e6 steps per IC
  entry (the byte checks and the count walk). No scalar multiplication runs when the counts
  disagree, or before an IC entry that fails. This is checked in two ways:
  - **Cost:** asserted on every rejected vector.
  - **Whole-evaluation operation counts (r3, review F11; r5 for the multi-scalar path).** Each
    vector of the library under test is also evaluated under the PV11 cost model with the CPU
    intercepts of G1 `scalarMul`, G1 `multiScalarMul`, `millerLoop` and `finalVerify` set to
    10^11, 10^13, 10^15 and 10^17, so the consumed CPU spells out how many of each ran. The test
    checks the original values at those parameter indices before marking them. Every vector
    refused by its IC entries, its input count or an input out of range, whether by `false` or by
    a builtin failure, runs none of the four. Every accepted proof runs 4 Miller loops and one
    final verification, plus `n` scalar multiplications below 7 inputs (and in `verifyFour`) or
    exactly one multi-scalar multiplication from 7. A self-test ties the counts to the real
    `DefaultFun` values in an honest run's trace, and requires the guard to fail on each
    forbidden operation, with a passing control. (r2 matched builtin names in the last 20 trace
    entries with the wrong case, so that check could never fail.)

  Mutation checks: multiplying when the counts disagree, and multiplying before the recursion,
  are each caught by the operation counts alone with the cost check disabled (r3); the cost
  check also catches both. Moving the threshold from 7 to 8 fails the operation counts at 7
  inputs (r5).

## Consequences
- **Savings per verification** compared with `main`, measured: 0.61e9 steps at 2 inputs; with
  M2, 1.12e9 at 9 and 2.68e9 at 24 (M1 alone: 0.98e9 and 1.75e9).
  - For zeroj-usecases (mainnet prices, 0.0000721 lovelace per step) this means about 0.080 ADA
    per auction bid (9 inputs) and about 0.193 ADA per confidential-note transfer (24 inputs);
    with M1 alone, 0.071 and 0.126 ADA.
  - It also frees 6–27% of the step budget for larger circuits.
- **Script hashes** of every validator using the library change. Measured as the blueprint's
  `compiledCode` bytes, `Groth16BLS12381Verifier` goes from 1,059 (`458bfb1`) to 1,203 with M1
  at `1525e97` (Julc testkit's `scriptSizeBytes()`: 1,053 to 1,197; r1's 1,186 predates the
  count check) and to 1,401 with M2 (JuLC `4cc63c24`):
  +342 bytes in all.
- **Memory units rise.** The pending recursion levels, the byte checks and (M2) the native lists
  add CEK steps and live values.
  - M1, measured on zeroj-usecases transactions against PR #85: auction bid +2.1%, settlement of
    3 bids +3.9%, registry rotation (two 7-input proofs) +6.2%.
  - With M2, per verification against `458bfb1` (r5 test output): 187,318 against 160,395 units
    at 2 inputs, 407,620 against 322,228 at 9 and 839,275 against 669,013 at 24, about +26%. The
    multi-scalar path uses less memory than the per-input path would (Fable: 414,454 at 9,
    901,174 at 24).
  - In fee terms the step saving dominates: at 24 inputs about 0.193 ADA saved on steps against
    about 0.010 ADA added on memory (170,262 units at 0.0577 lovelace), so about 0.183 ADA net;
    at 9 inputs about 0.080 against 0.005.
- **Callers that combine `verify` with a fallback** (`verify(...) || other`) observe I4's
  `false`/failure swap only for malformed keys. Keys are deployment parameters or hash-pinned.

## Verification
`Groth16SingleDecompressionDifferentialTest` runs the library and a test-only copy of `458bfb1`
through outcome probes (accept / `false` / builtin failure) and checks:
- **Proofs:** honest proofs for 2 (snarkjs), 3, 4, 6, 7, 9 and 24 public inputs, so both sides
  of the multi-scalar threshold, and proofs with one public input equal to 0 at 3 and 9 inputs.
  Zero public inputs (`IC = [G]`) are covered by the pairing-preserving vectors.
- **Degenerate scalars around the threshold (r5)** at 6, 7 and 9 inputs, on a key whose IC
  entries are all `G`: every scalar 0, `r − 1` so that `vk_x` is infinity, two terms that cancel,
  every scalar `r − 1`, each accepted with a matching proof, and `r − 1` against a proof for a
  different `vk_x`, refused. With zero coefficients, an infinity IC entry still returns `false`
  and an undecodable one still fails. Both libraries give the stated outcome.
- **Operation counts (I6, r3; r5 for the multi-scalar path)** for every vector of the library
  under test, and a self-test of that guard.
- **Paths:** the 7-, 9- and 24-input proofs (honest and all their mutations) and the degenerate
  vectors at 7 and 9 take the multi-scalar path; the others take the per-input path.
  `verifyFour` is unchanged by M2.
- **Mutations:** over 40 per proof: infinity, length, flags, negation, off-curve, scalar range,
  counts, check order across points, and zero-input IC infinity.
- **Pairing-preserving infinity vectors** (review F1 on PR #85): inputs are 0 and every IC entry is
  `G`, with exponents such that the pairing holds. They isolate each of the 7 proof and key
  infinity checks, with explicit expected `FALSE`, plus an accepted baseline. This covers both
  `verify` and `verifyFour`.
- **Equality:** outcomes are equal except the pinned I4 instances, and the I5 saving is asserted
  exactly (r5: 537 `verify` vectors, 56 `verifyFour`, 27 degenerate).
- **Suites:** the `:zeroj-onchain-julc` and `:zeroj-integration-tests` suites, and zeroj-usecases
  (VM and Yaci DevKit) against a local publish.

## Implementation milestones
- **M1 (this PR, stacked on #85).**
  - **Entry gate:** #85 approved.
  - **Exit:** I1–I6 asserted by `Groth16SingleDecompressionDifferentialTest`; the module and
    integration suites green; zeroj-usecases green against a local publish; an independent review
    with no open P0–P2.
- **M2 (r4; implemented against a local JuLC with #241).** Collect the validated points into a
  native list and use `bls12_381_G1_multiScalarMul` from 7 inputs.
  - **Entry gate:** JuLC #241 reviewed (Codex and Fable reviews done; JuLC review round r2 in
    progress).
  - **Exit:**
    - the same differential suite passes, with identical outcomes and every V1 check;
    - the multi-scalar savings are pinned;
    - zeroj-usecases is green against local ZeroJ and JuLC builds.
  - **Merge gate:**
    - a JuLC release containing #241, `julcVersion` bumped to it, and the pinned savings, windows
      and script size re-measured;
    - node evidence for the multi-scalar path: a Yaci DevKit run of validators with at least 7
      inputs (zeroj-usecases' registry possession proofs at 7, note transfers at 24), with their
      DevKit budgets recorded, and JuLC's PV11 node gate for the cons-built point lists.

## Production and audit gates
- **Maintainer acceptance** of this ADR, including I4. It is Proposed until then, and it should be
  accepted before the PR merges.
- **External review** of the verifier library remains a production gate, as before (ADR-0039).
- **The node's blst version** (cardano-base) has not been checked against the Julc VM's
  `blst-java 0.3.2` for I4's no-non-canonical-decoding argument. If that argument ever matters
  for a production claim, it needs that check.

## Risks
- **Recursion and memory.** The walk keeps one pending level per IC entry: the point and the pending
  addition stay alive until the levels below return. The old code's validation and accumulation
  walks recursed in tail position. The extra machine state is accounted in the execution budget.
  A 24-input verification is measured in the tests and fits.
- **I4's form change** is visible only to composite validators on malformed keys.
- **Not an audit:** this ADR is not an audit of the verifier. ADR-0039's assurance classes apply
  unchanged.

## Revision history
- **r1** (2026-10-10): initial proposal. It records the measured alternatives A, B, C and D″,
  chooses D″, and defers multi-scalar multiplication to bloxbean/julc#240.
- **r2** (2026-10-10; Codex review of `c1d8f5d`, no V1 violation or accept-set difference found):
  - **P2:** count mismatches multiplied before returning `false`. The counts are now evaluated
    first, and nothing is multiplied when they disagree; every entry is still validated. Adds I6,
    with its cost and structural tests.
  - **P2:** tests did not enforce V1's order. Adds I6's checks and two mutation probes. Also adds
    raw boundary vectors (a non-bytes IC entry, a non-integer input), zero inputs (`IC = [G]`), and
    the second listed divergence (an undecodable entry, then an infinity entry).
  - **P3:** the recursion note is corrected (pending levels, not tail recursion), and a 24-input
    proof is measured. I5 now states the per-entry overhead.
- **r2** (also responds to Fable's review of `c1d8f5d`, which found no V1 violation or
  accept-set difference):
  - **F1 (P1):** I5's window is now `[expected − 1.3e6·(n + 1) − 3e6, expected + 5e6]`. It is
    narrower than one decompression up to 33 inputs, and the test asserts the width. A 24-input
    proof is in the suite.
  - **F2:** I4 is described as a class, and three instances are pinned.
  - **F3:** adds the threat model, pinned references, milestones and gates.
  - **F4:** the blst argument closes I4's theoretical case; the branch stays as defense in depth.
  - **F5, F6:** as in the Codex items above.
  - **F7:** the A/B harness is noted, and the verification wording is fixed.
  - **F8:** the measurement method for script size is stated.
  - **F9:** memory is reported.
  - **F10:** acceptance before merge is listed as a gate.
- **r3** (2026-10-11; responds to the review of `1525e97`, which found no accept-set difference
  beyond the documented rejection forms and no V1 violation in the implementation):
  - **F11 (P2):** the structural I6 check matched `ScalarMul`, `MillerLoop` and `FinalVerify`
    against names such as `Bls12_381_G1_scalarMul`, so it could never fail. It is replaced by
    whole-evaluation operation counts from a marked cost model, plus a self-test that the guard
    sees the real `DefaultFun` values and fails on each forbidden operation. Both V1 mutations
    are caught with the cost check disabled.
  - **F12 (P3):** the script sizes are those of `1525e97`: 1,203 bytes (blueprint), 1,197
    (testkit), +144.
- **r4** (2026-10-11; numbered r3 before PR #86's review round r3): D3 implemented as milestone
  M2, using bloxbean/julc#241. A multi-scalar path is used from 7 public inputs, with measured
  savings of 1.116e9 steps at 9 inputs and 2.676e9 at 24. It merges only after a JuLC release.
- **r5** (2026-10-11; numbered r4 before PR #86's r3; Codex review of `5ffa908`, no V1 violation
  or accept-set/`vk_x` difference found):
  - **F1 (P2):** the threshold and degenerate scalars were untested. Adds 6- and 7-input proofs,
    a 9-input proof with a zero input, the degenerate-scalar vectors, and the operation counts
    that pin the threshold; moving it to 8 now fails.
  - **F2 (P2):** pins the compiler used for M2 and the multi-scalar semantics: CIP-0133's
    "non-empty and equal" against Plutus' and Julc's truncating `zip`, and why neither is
    reachable here.
  - **F3 (P3):** the V1 order check was a 20-builtin suffix. I6 now counts operations over the
    whole evaluation (the same guard as r3, extended to the multi-scalar path).
  - **F4 (P3):** I5 states the current window and separates M1 and M2 measurements; the pins are
    recentred on the measured values (they were 5.2e6 high).
- **r5** (also responds to Fable's review of `5ffa908`, which found no V1 violation and, over the
  whole suite forced onto the multi-scalar path and a Scalus cross-run, no accept-set or `vk_x`
  difference):
  - **F1 (P2):** as Codex F4 above; the 7-input pin is added.
  - **F2 (P2):** node evidence for the multi-scalar path is now part of M2's merge gate.
  - **F3 (P2):** as Codex F1 and F3 above.
  - **F4 (P3):** D3 is rewritten without the struck-through deferral; I5, I6 and Consequences
    give M2 numbers; script size (1,401 bytes) and memory are reported for M2; the per-input gain
    is about 53e6; the revision history is in order; Verification says which proofs take the
    multi-scalar path.
  - **F5 (P3):** the `msmMinInputs()` Javadoc uses the ADR's basis.
  - **F6 (P3):** I1 records that the node's `blsMSM` drops infinity points and zero scalars
    instead of failing, so validation is the only guard on this path.
  - **F7 (P3):** I5's window allows 2.4e6 per IC entry and is applied only up to 7 entries (the
    6-input proof had 1.1e6 of margin).
  - **F8 (P3):** the PR text gives fees on steps and net of memory.
