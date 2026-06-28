# Review: ADR-0022 & ADR-0023 — PlonK Hardening

## Status
Review feedback — for incorporation into ADR-0022 and ADR-0023 before either is moved from `Proposed` to `Accepted`.

## Date
2026-06-28

## Scope and method

This document reviews the two PlonK hardening ADRs against the **current implementation**, with the explicit goal of finding gaps in the ADRs themselves — places where the proposed decisions are incomplete, inaccurate, infeasible, or where they understate/overstate a risk. Because these are core cryptographic paths, the review was performed from four independent roles, each reading the ADRs and the source:

- **Cryptographer** — soundness of the transcript, point/subgroup validation, the KZG/pairing acceptance equation, scalar canonicalization.
- **Application-security engineer** — untrusted-input handling, trust boundaries, resource exhaustion / DoS, error hygiene.
- **Implementation-fidelity reviewer** — verify every concrete factual claim in both ADRs against `file:line`.
- **Cardano on-chain / Plutus V3 specialist** — feasibility of ADR-0023 under Plutus V3 budget, builtin, and script-size limits.

### Headline verdict

| ADR | Are the stated findings accurate? | Are the decisions sufficient to call the path "hardened"? |
|---|---|---|
| **0022** (off-chain pure-Java) | **Yes — all 8 findings confirmed at `file:line`.** The off-chain verification *equation* is also independently confirmed sound (matches snarkjs). | **No — necessary but not sufficient.** Misses an entire threat class (resource-exhaustion/DoS), one real soundness gap (VK domain-scalar validation), and three correctness fixes (prime-as-modulus, error classification, BN254 has no validation API at all). |
| **0023** (on-chain Julc/Plutus) | **Yes — all 6 findings confirmed.** Finding 6 is accurate but the cited disclaimer is itself wrong (see C-3). | **No — necessary but not sufficient, and two decisions are not realistic as written.** §3's "derive uncompressed bytes on-chain" has no Plutus builtin; the "use the off-chain verifier as the reference" instruction conflates two different transcripts; there is no budget/size go-no-go gate; "fail closed" is aspirational and currently fail-*open*. |

Both ADRs point in the right direction and correctly identify the most severe issues (off-chain: missing point/subgroup validation + non-injective transcript; on-chain: arbitrary-proof acceptance + transcript-binding). The additions below are what is required before either path can claim soundness.

---

## Part A — ADR-0022 (Pure Java PlonK)

### A.1 Claim verification

All eight numbered findings were verified accurate against current source. Highest-signal confirmations:

| Finding | Verdict | Evidence |
|---|---|---|
| 1 — point validation missing; BLS `isValid()` exists but unused; BN254 has none | Confirmed | `bls12381/ec/G1Point.java:27-38` & `G2Point.java:23-34` define `isOnCurve/isInSubgroup/isValid`, never called from `PlonkBLS12381Verifier`. `bn254/G1Point.java` exposes only `isInfinity()` — **no** validation method exists to call. `Fp` constructors silently `value.mod(p)` (`bn254/Fp.java:19-22`, `bls12381/field/Fp.java:22`), so `p+5` is accepted as `5`. |
| 2 — `writeBigEndian` trims over-width instead of rejecting | Confirmed | `FiatShamirTranscript.java:142-150` copies the low `size` bytes; negative `BigInteger` two's-complement bytes flow through unmodified. |
| 3 — material not bound to envelope; verifiers don't enforce protocol/curve | Confirmed | `VerifierOrchestrator.java:52-62` routes purely on `envelope.proofSystem()/curve()` and never reads `material.proofSystemId()/curveId()/circuitId()/vkHash()`. `PlonkBLS12381Verifier.java:63-71` stores `sv.protocol()/curve()` but only checks `nPublic`. |
| 4 — `.ptau`/`.zkey` importers permissive; primes skipped/trusted | Confirmed | `PtauImporter.java:72` reads then `// prime (skip)`; `PlonKZkeyImporter.java:80-83` reads `q`,`r` with no comparison. |
| 5 — provers accept wires longer than domain | Confirmed | `PlonKProver.java:72-77` guards only the *lower* bound; `padTo` (`:481-487`) returns oversized arrays into `FieldFFT.ifft`. |
| 6 — sigma decode falls back to column A | Confirmed | `PlonKSetup.java:147` `default -> omegaRow`; no length/range validation of `sigmaA/B/C`. |
| 7 — variable-time prover | Confirmed | `G1Point.scalarMul:73-85` branches on `s.testBit(0)`. A `ctScalarMul` exists but the prover does not use it. |
| 8 — tests are happy-path | Confirmed | Repo-wide grep for subgroup/off-curve/non-canonical/over-width/metadata-mismatch negative tests returns zero matches. |

**The off-chain equation is sound.** The cryptographer independently re-derived the BLS12-381 and BN254 linearization (`d1..d4`, `D=d1+d2-d3-d4`, `F`, `E`, `A1`, `B1`, `r0`, pairing `e(B1,G2)·e(-A1,X2)=1`) against the snarkjs convention and found it correct (`PlonkBLS12381Verifier.java:153,171-214`). This validates ADR-0022's framing that the off-chain gaps are **input-validation**, not equation errors.

### A.2 Gaps the ADR misses (must be added)

| # | Gap | Severity | Why it matters | Evidence / recommended ADR change |
|---|---|---:|---|---|
| **R1** | **Resource-exhaustion / DoS is not in the threat model at all.** ADR-0022 frames every issue as soundness/injectivity and never names availability. | **High** | A single request can hang a thread for minutes–hours. `power` comes straight from VK JSON and drives an unbounded squaring loop. | `PlonkBN254Verifier.java:114` loops `for(i=0;i<power;i++)`; `power` from `SnarkjsPlonkCodec.java:104` is never bounded. `nPublic` similarly amplifies allocations + `modInverse` (`:118-128`). **Add a decision:** bound `power`/`domainSize`/`nPublic` to the supported range at the verifier boundary *before* any loop/allocation, return `MALFORMED_ENVELOPE`. |
| **R2** | **`.ptau`/`.zkey` importers: unbounded allocation, integer truncation, NPE on missing section.** Decision 3 says "plausible sizes / within file" but only as soundness, with no overflow/limit/typed-failure specifics. | **High** | Hostile setup file → OOM, `NegativeArraySizeException`, or NPE. `input.readAllBytes()` has no size cap; `domainSize`/SRS counts/section sizes are attacker ints driving `new[]`; section walk casts `long ssize` to `int` (truncation lets sections escape the file); missing required section → `sections.get(1)` NPE. | `PtauImporter.java:50-92`, `PlonKZkeyImporter.java:66-143` (+BLS variants). **Add:** max-file-size, 64-bit overflow-safe `offset+size ≤ fileLength` and required-section/uniqueness checks, `domainSize`/SRS upper bounds, and wrap importer failures in a typed exception. |
| **R3** | **Declared prime `q`/`r` is *used as the reduction modulus*, not merely "uncompared."** Decision 3's "compare declared primes" wording understates this. | **High** | An attacker-chosen `q` in a `.zkey` reduces every imported point coordinate mod the attacker's modulus, then those points become a "trusted" proving key. | `PlonKZkeyImporter.java:80` reads `q`; `:177-178` `readG1Mont(...).mod(q)`. **Change Decision 3:** assert `q == curve.basePrime` and `r == curve.scalarPrime` *immediately after reading, before use as a modulus* — not just "compare." |
| **R4** | **VK domain-scalar validation is missing.** Decision 1 validates VK *points* but never the VK *scalars* `ω`, `k1`, `k2`, `domainSize`. | **High** | If the VK is untrusted (the stated posture), a VK with `k1=k2`, `k1∈⟨ω⟩`, non-primitive `ω`, or non-power-of-two `domainSize` collapses the permutation-argument coset partition and **breaks copy-constraint soundness — independent of any point check.** | Verifier consumes `vk.omega()/k1/k2` directly (`PlonkBLS12381Verifier.java:78,169`); setup hardcodes `k1=2,k2=3` (`PlonKSetup.java:54-55`) but the verifier does not require it. **Add to Decision 1:** validate `ω^n=1 ∧ ω^{n/2}≠1`, `{1,k1,k2}` distinct cosets, `domainSize=2^k` — **or** declare the VK trusted-by-pinned-hash and drop VK point validation too (pick one trust model, don't half-validate). |
| **R5** | **JSON parser hardening absent.** Decision 1 asks for "expected arity / no extra elements" only as a soundness rule. | **Medium-High** | `parseG1/parseG2` iterate *all* array elements before any arity check (10⁷-element arrays allocate first); snarkjs scalars are JSON *strings*, so a 20 MB decimal string hits `new BigInteger` at O(n²) under Jackson's default string limit; duplicate keys silently last-wins. | `SnarkjsPlonkCodec.java:28,156-190`. **Add:** enforce exact arity *before* materializing elements; set `StreamReadConstraints` (doc/array/number-string caps); enable strict duplicate-key detection. |
| **R6** | **Error classification: a blanket `catch(Exception) → INTERNAL_ERROR` defeats Decision 1's promised typed codes.** | **Medium** | Decision 1 promises `MALFORMED_ENVELOPE/INVALID_PROOF/INVALID_PUBLIC_INPUTS`; current code returns `INTERNAL_ERROR` with the raw parser message appended for *every* malformed input — wrong class for alerting, and leaks internal detail. | `PlonkBN254Verifier.java:200-203`, `PlonkBLS12381Verifier.java:219-223`; `CodecException` is a `RuntimeException`. **Add:** classify malformed-input exceptions to the typed codes and never echo raw exception text. |
| **R7** | **BN254 point types have no validation API — Decision 1 is not implementable for BN254 without new methods.** | **Medium (prerequisite)** | The ADR says "BN254 verifier point types do not expose point validation" as a *finding* but the decision then requires on-curve/subgroup checks "where required." For BN254 the methods literally do not exist yet. | `bn254/G1Point.java` / `G2Point.java`. **Add an implementation note:** Decision 1 for BN254 requires first adding `isOnCurve`/subgroup methods to the BN254 point types. |
| **R8** | **`Z_H(ζ)=0` / `ζ∈domain` returns `INTERNAL_ERROR`, not a deterministic reject.** | **Low-Medium** | `modInverse` on `ζ-1` / `ζ-ω^i` throws `ArithmeticException` → `INTERNAL_ERROR`. Negligible under honest Fiat-Shamir (not a forgery vector), but the decisions don't require a clean reason code. | `PlonkBLS12381Verifier.java:144,152`. **Add:** explicit `Z_H(ζ)≠0 ∧ ζ∉{ω^i}` check returning `INVALID_PROOF`. |
| **R9** | **Pairing silently skips infinity operands, so the verifier must enforce non-infinity itself.** | **Low** | `pairingCheck` drops any `isInfinity()` operand, so a proof/VK point supplied as infinity is accepted and silently removed from the equation. | `BLS12381Pairing.java:57`, `BN254Pairing.java:59`. **Note in Decision 1:** the pairing will not catch infinity; the verifier must reject it (scoped per O-1 below). |

### A.3 Over-statements / inaccuracies to correct in ADR-0022

- **O-1 — "Reject unexpected infinity in selector commitments" is too broad.** A selector polynomial that is identically zero (e.g. `Q_M` for a circuit with no multiplication gates) has a KZG commitment **equal to the point at infinity — a legitimate VK value.** Blanket-rejecting infinity selector commitments would reject valid VKs. **Scope the non-infinity requirement to SRS powers and `X_2` only** (permutation commitments `S1/S2/S3` are non-zero by construction; selector commitments may be infinity).
- **O-2 — The "High" malleability claim applies to the *scalar* path, not point coordinates.** Point coordinates are reduced mod `p` by `Fp` and the transcript binds the *reduced* value, so non-canonical coordinates are transcript-consistent (encoding-malleable but result-consistent). The genuinely non-injective binding is the **scalar** path (`writeBigEndian` truncation/negatives vs `.mod(r)` in equations). Keep "High" for the scalar case; do not assert it for point coordinates.
- **O-3 — Finding 5 (oversized wires) is a trusted-input API-contract gap, not an untrusted-input soundness attack.** The prover consumes locally-built witnesses, not attacker JSON. Real and worth fixing, but it should be ranked below the untrusted-input findings (1–4), not alongside them.

### A.4 Required additions before "hardened" (ADR-0022)

1. **A DoS/availability threat class** (R1, R2, R5) — currently absent; this is the single biggest omission because the most *exploitable* issues in the code today are resource-exhaustion, not forgery.
2. **`q`/`r` asserted == curve constants before use as a modulus** (R3) — stronger than "compare."
3. **VK domain-scalar validation** (R4) — the one missing *soundness* item.
4. **Implement** Decision 2 (material↔envelope binding) and extend it to backend *routing-by-curve*; add typed error classification (R6); add the BN254 validation-method prerequisite (R7).
5. **Scope** the non-infinity rule (O-1) and **split** the malleability claim (O-2).

---

## Part B — ADR-0023 (On-Chain PlonK)

### B.1 Claim verification

All six findings confirmed:

| Finding | Verdict | Evidence |
|---|---|---|
| 1 — acceptance is not a proof check; `validate` returns only `inv1Ok && inv2Ok` | Confirmed | `PlonkBLS12381FullVerifier.java:206`. `r0`, `[D]`, witnesses, pairing all excluded. |
| 2 — transcript bytes not bound to curve-op points; Javadoc claims a comparison the code omits | Confirmed | FS hashes raw uncompressed `cmARaw…` (`:102-103,113,120-121`); BLS ops uncompress compressed `cmA…` (`:156-164`); no cross-check. Javadoc `:22-25` claims it compares. |
| 3 — most proof data dead for soundness | Confirmed | `r0:146`, `dPt:192`, `wXi/wXiw:163-164`, `x2u:155`, `g1/g2:165-166` unused by `:206`. |
| 4 — datum/scalar boundaries too permissive; one-PI / domain-size-4 specialization | Confirmed | `:86-87` reads only `headList`; `:132` hardcodes `xi^4`. |
| 5 — PI sign differs (on-chain adds, off-chain subtracts) | Confirmed | On-chain `:137` `pi = pub0.multiply(l1)`; off-chain `PlonkBLS12381Verifier.java:153` `pi.subtract(...)`. |
| 6 — `sha2_256` vs disclaimer | Confirmed (with C-3 caveat) | `:104,108,112,117`. |

### B.2 Gaps the ADR misses (must be added)

| # | Gap | Severity | Why it matters on Plutus | Evidence / recommended ADR change |
|---|---|---:|---|---|
| **S1** | **§3's preferred "derive the transcript bytes from the decompressed point on-chain" has no Plutus builtin and is a Julc-emulation trap.** | **Critical** | gnark's transcript hashes the **96-byte uncompressed** G1 serialization. Plutus V3 offers only `bls12_381_G1_compress` (→48 bytes) and `uncompress` (→opaque element). There is **no builtin that emits uncompressed bytes**; reproducing them on-chain needs manual Fp coordinate recovery (modular sqrt over the 381-bit field). In Julc's JVM model `uncompress()` returns a hashable `byte[]`, so §3 *appears* to compile and pass tests while having no on-chain meaning. | `Builtins`: `compress`/`uncompress` only. **Change §3:** drop "derive uncompressed bytes on-chain." Decide between (a) **re-prove with a compressed-point (48-byte) transcript** the script can reproduce via `compress(uncompress(x))==x`, or (b) explicitly budget on-chain coordinate recovery. Flag the Julc `byte[]` abstraction as non-faithful for uncompressed serialization. |
| **S2** | **Transcript-authority conflation: the off-chain "executable reference" uses a *different* transcript than the on-chain prototype, and Decision 2's challenge list is snarkjs-shaped.** | **High** | Off-chain `PlonkBLS12381Verifier` = **Keccak-256, snarkjs order (β→γ→α→ζ→v→u), `u` folded into `[D]`**; on-chain prototype = **SHA-256, gnark order (γ→β→α→ζ), no v/u**. A proof verifiable off-chain will not verify on-chain. Decision 2 lists snarkjs `v` (KZG fold) and `u` (aggregation) challenges, which are **not** how gnark batches openings. | `FiatShamirTranscript.java:9,20,111` vs `PlonkBLS12381FullVerifier.java:89-122`. **Add a prerequisite decision:** pin *one* target proving system + transcript (hash, serialization, challenge order, domain separation) with cross-implementation vectors, *before* implementing Decision 2. If gnark-on-chain stays, the reference must be a gnark verifier/vectors — not the snarkjs off-chain verifier. |
| **S3** | **No budget go/no-go gate; the in-repo estimator undercounts and is never cited.** | **High** | The ADR's risk row says "measure after correctness" but states no ceiling. The in-repo `ScriptBudgetEstimator` counts only `8+nPublic≈9` scalar muls, but a full verify does ~**18** (9 for `[D]`, 5 for `[F]`, 1 for `[E]`, ~3 for `A1/B1`). Re-estimated ≈ **2.9e9 CPU (~29% of the 10e9 limit)** — plausibly feasible, but the model understates PlonK CPU ~2× and uses `blake2b` costs while the code uses `sha2_256`. | `ScriptBudgetEstimator.java:69-76` (self-described as unvalidated). **Add a decision:** an explicit go/no-go gate citing **CPU 10e9 / mem 14e6 / size 16,384 B**, and require the estimator be corrected to ~18 scalar muls and reconciled with measured Julc-VM numbers before any status change. |
| **S4** | **Script size / CIP-33 reference scripts treated as a "Medium maybe" but are effectively mandatory.** | **High** | The `@Param` block bakes ~1.4 KB of VK/generator data into the applied script, on top of full-PlonK UPLC, and the redeemer carries duplicate encodings (~1.1 KB). The 16,384 B inline limit is almost certainly exceeded → CIP-33 reference scripts (with Conway tiered ref-script fees) become required. | `PlonkBLS12381FullVerifier.java:36-63` (`@Param` VK), `:68-81` (duplicate redeemer encodings — §3 dedup saves ~672 B). **Promote** reference-script deployment from a Medium mitigation to a decision, with a script-size gate against 16,384 B and a note on ref-script fee tiers. |
| **S5** | **"Fail closed" is aspirational, and the code is currently fail-*open*.** | **Medium-High** | No production build profile, feature flag, or fail-closed path exists. Worse, `OnChainFeasibility.isFeasible(PLONK, BLS12_381)` returns **true** because `EXPERIMENTAL` is treated as feasible — a programmatic fail-open signal for a validator that checks no proof. Class is still named `FullVerifier`. | `OnChainFeasibility.java:73-76`. **Add:** exclude `EXPERIMENTAL` from `isFeasible` (or gate behind explicit opt-in), and make the rename/feature-flag a concrete deliverable, not a "should." |
| **S6** | **ex-mem ceiling and identity/zero-point handling unaddressed.** | **Medium** | Mem (`14e6`) is the proportionally tighter limit; the multi-KB `appendByteString` transcript concatenations are memory-sensitive and unvalidated. On-chain has no infinity handling for commitments/witnesses; `uncompress` of the canonical infinity encoding and identity behavior of `scalarMul`/`add` must be defined. | **Add:** a separate mem gate, and a requirement to reject infinity for all proof commitments and opening witnesses on-chain (ADR-0022 §1 covers this off-chain but ADR-0023 §4 does not for on-chain). |
| **S7** | **MSM builtin / CIP-0133 baseline and gamma-hash domain separation unstated.** | **Low** | Julc exposes `bls12_381_G1_multiScalarMul`, yet the budget model assembles MSM from per-element scalar muls; if an MSM builtin is available on the target protocol version, budget and script shape improve materially. The gamma preimage concatenates VK block + public input + A/B/C under one tag with no inter-segment separator (low risk because fields are fixed-width, but §6 "domain separation" should name it). | **Add:** state the assumed protocol/builtin baseline (is MSM in scope?), and name the gamma concatenation explicitly under the domain-separation decision; note replay-across-scripts is mitigated by VK ∈ script hash. |

### B.3 Inaccuracy to correct in ADR-0023

- **C-3 — Finding 6 is accurate, but the disclaimer it relies on is wrong.** The fixture/disclaimer (and `docs/plonk-support.md:114`) state "**Plutus V3 lacks SHA-256**" — directly contradicted by the prototype, which calls `Builtins.sha2_256` and passes. `sha2_256` **is** an available Plutus V3 builtin. The ADR's real point (prototype hash ≠ documented production direction ≠ off-chain Keccak transcript) holds, but **fix the false "Plutus lacks SHA-256" claim** in `docs/plonk-support.md:114` and the fixture disclaimer as part of this work, so the transcript decision rests on correct facts.

### B.4 Required additions before status change (ADR-0023)

1. **Pin the target proving system + transcript** (S2) — this is load-bearing; without it, implementing Decision 2 yields a verifier that gates on a pairing but interoperates with neither prover.
2. **Replace §3's infeasible binding** with a compressed-point (48-byte) transcript re-proof decision (S1), and flag the Julc `byte[]` emulation as non-faithful.
3. **An explicit budget + size go/no-go gate** (S3, S4) citing CPU 10e9 / mem 14e6 / size 16,384 B, with the in-repo estimator corrected (~18 scalar muls) and reference-script deployment promoted to a decision.
4. **Make "fail closed" real** (S5): exclude `EXPERIMENTAL` from `isFeasible`, rename `FullVerifier`, add a feature flag.
5. **Reject infinity on-chain** and add a mem gate (S6); fix the `plonk-support.md` SHA-256 claim (C-3).

---

## Part C — Cross-cutting notes

- **Trust-model coherence (applies to both ADRs).** Several decisions only make sense once the VK trust model is fixed. If the VK is *untrusted* (the off-chain posture), it needs both point validation **and** domain-scalar validation (R4). If it is *trusted-by-pinned-hash* (the on-chain `@Param` posture, S-row), point/scalar validation of the VK is redundant. The ADRs should state the VK trust model explicitly per path and validate accordingly — not partially.
- **The off-chain equation is the asset; protect it.** ADR-0022's correctness is real and verified. The risk is entirely at the boundary (inputs, setup material, envelope binding, availability). Frame ADR-0022 as "the math is right; harden the boundary, including availability," and the priority order falls out naturally.
- **On-chain is earlier-stage than the ADR's tone implies.** Today the on-chain validator gates on two field inversions and is not a proof check at all. ADR-0023's decisions are correct, but the path from here is gated on a design choice (which transcript / which point encoding) that must be made *before* coding the pairing predicate, not after.

## References

- ADR-0022: Pure Java PlonK Backend Review Outcomes and Hardening Posture
- ADR-0023: On-Chain PlonK Verifier Hardening Posture
- `zeroj-verifier-plonk/src/main/java/com/bloxbean/cardano/zeroj/verifier/plonk/PlonkBLS12381Verifier.java`
- `zeroj-crypto/src/main/java/com/bloxbean/cardano/zeroj/crypto/transcript/FiatShamirTranscript.java`
- `zeroj-codec/src/main/java/com/bloxbean/cardano/zeroj/codec/SnarkjsPlonkCodec.java`
- `zeroj-verifier-core/src/main/java/com/bloxbean/cardano/zeroj/verifier/core/VerifierOrchestrator.java`
- `zeroj-crypto/src/main/java/com/bloxbean/cardano/zeroj/crypto/plonk/{PtauImporter,PlonKZkeyImporter,PlonKSetup,PlonKProver}.java`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/plonk/validator/PlonkBLS12381FullVerifier.java`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/analysis/{OnChainFeasibility,ScriptBudgetEstimator}.java`
- `docs/plonk-support.md`
