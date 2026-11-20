# ADR-0068: Circuit DSL Soundness, PlonK Scaling, Poseidon MPF Canonicality, and Gadget Hardening

- **Status:** Proposed
- **Date:** 2026-11-21
- **Risk Classification:** R2 (security-sensitive circuit soundness, witness validation, SRS verification, and state-tree conformance)
- **Related ADRs:** ADR-0022 (PlonK BLS12-381), ADR-0025 (Legacy BN254 opt-in gating), ADR-0037 / ADR-0038 (DSL range & ownership soundness), ADR-0063 (Direct Boolean lowering), ADR-0065 (`arrayAccess` bounds), ADR-0066 (BLS12-381 PlonK `.ptau` & `t3 = n + 6` SRS sizing)

---

## Context

Seven related correctness, soundness, and scaling defects span the circuit DSL, symbolic annotation layer, BLS12-381 PlonK setup/prover, Poseidon MPF circuits, and standard-library gadgets:

1. **`ZkUInt.sub` 253-bit underflow wrap-around on BN254.** `ZkUInt.MAX_BITS` is `253`, and `ZkUInt.sub` constrains `a - b` to `max(a.bits, b.bits)` bits without capping at `252`. On BN254 (`r ≈ 2^253.57`), `2^254 > r`, so `0 - (2^253 - 1) ≡ r - (2^253 - 1) < 2^253` satisfies the 253-bit range check and wraps around silently. The comment on `CircuitAPIImpl.MAX_SAFE_BITS` also conflates decomposition uniqueness (`2^bits < p`, 253 bits on BN254) with difference-underflow safety (`2^(bits+1) <= p`, 252 bits on BN254).
2. **PlonK BLS12-381 $O(n^2)$ loops and duplicated $O(n)$ SRS pairings.** `PlonKProverBLS381.cosetEval` calls linear `powFr(shift, i)` inside an $O(n)$ loop and computes `zeta^n` in $O(n)$ multiplications; `PlonKSetupBLS381` calls linear `evalOmegaPow` inside its domain loop and `decodeSigmaTarget`; both `PtauImporterBLS381` and `PlonKSetupBLS381` independently execute `count - 1` sequential two-pairing checks (`O(n)` pairings performed twice across import + setup).
3. **Raw `CircuitAPI.{xor,and,or,not,fromBinary}` booleanity and width guards.** Raw `xor`, `and`, `or`, and `not` rely on a Javadoc precondition that operands are `{0, 1}` without enforcing `assertBoolean`, while `fromBinary` has no upper bit-width guard against field wrap-around. Naively enforcing `assertBoolean` without tracking derived-boolean wires would inflate circuits that chain boolean expressions.
4. **Witness input validation gaps and BN254-hardcoded `Groth16Prover.validateWitness`.** `WitnessCalculator` silently reduces out-of-range and negative inputs modulo `p`, ignores unknown input keys, and ignores extra entries in input value lists. `ZkInputMap` and generated `Inputs` setters accept negative or out-of-type values. There is no curve-generic public `verifyWitness` helper in `zeroj-circuit-dsl`, while the public `Groth16Prover.validateWitness` hard-codes `MontFr254.modulus()`, lacks `LegacyCurvePolicy` gating, and skips wire-0 / bounds / canonical checks.
5. **Poseidon MPF `< Fr` key-path canonicality and `Step.fork` nibble validation.** `docs/merkle/poseidon-authenticated-state-v1.md` requires every 32-byte decoded key to be canonical (`< Fr`) rather than reduced, and host `PoseidonMpfHash.digestToNibbles` rejects `>= Fr`, but `ZkMpf.requireKeyPath` only checks that each of the 64 nibbles is 4-bit (`0..15`), allowing non-canonical `>= Fr` nibble paths (such as `64 × 0xF`) in-circuit. `PoseidonMpfCodec.Step.fork` checks `prefix.length <= 64` but does not validate that each prefix byte is a nibble in `[0, 15]`.
6. **Standard-library gadget defects and foreign `ZkBool` ownership.**
   - `Binary.rotateLeft` and `SignalBinary.rotateLeft` rotate LSB-first bit arrays in the right-shift direction (`(i + n) % len`) and throw `ArrayIndexOutOfBoundsException` for negative `n`; `Binary.shiftRight` accepts negative `n` and can overflow `i + n`.
   - `AliasCheck` claims circomlib `< p` canonicality enforcement, but delegates to `toBinary(value, nBits)`, which throws at 254/255 bits and checks `< 2^nBits` (rejecting ~72.4% of valid BLS12-381 scalars at `nBits = 253`).
   - `PoseidonN` left-folds 2-input Poseidon without domain/arity separation (`PoseidonN(x) == Poseidon(x, 0) == PoseidonN(x, 0)`, `PoseidonN(a, b, c) == Poseidon(Poseidon(a, b), c)`) while claiming circomlib `Poseidon(nInputs)` equivalence.
   - `CircuitAnnotationProcessor` invokes `.assertTrue()` on a `@Prove` method's returned `ZkBool` without checking that the returned signal belongs to the circuit's own `ZkContext`.

---

## Threat Model & Trust Assumptions

- **Malicious prover:** Controls all private witness values and can bypass `WitnessCalculator` to feed arbitrary field elements directly to a prover, attempting to satisfy under-constrained arithmetic (`ZkUInt.sub` underflow, unvalidated raw boolean ops, non-canonical MPF key paths, or circuits whose `@Prove` assertion was silently emitted into a foreign builder).
- **Untrusted SRS / `.ptau` / MPF wire proof inputs:** A corrupted SRS with valid individual subgroup points can still violate `tauG1[i] == tau * tauG1[i-1]` unless consistency is verified. Untrusted MPF CBOR proofs can carry non-nibble fork prefix bytes.
- **Misconfigured caller:** A caller passing negative/out-of-range inputs, unknown keys, or a BLS12-381 witness to BN254-hardcoded `Groth16Prover.validateWitness` must receive an explicit failure rather than silent modular wrap-around or false validation.
- **Trust assumptions:** `SecureRandom` supplies unbiased field challenges for batched SRS consistency checks. Circuit-level key regeneration is required for any deployed MPF circuit because enforcing `< Fr` changes the R1CS constraint set and canonical digest.

---

## Normative References

- **BN254 scalar field order:** `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617` (`2^253 < r < 2^254`).
- **BLS12-381 scalar field order:** `r = 52435875175126190479447740508185965837690552500527637822603658699938581184513` (`2^254 < r < 2^255`).
- **Batched pairing RLC (Schwartz-Zippel over `F_r`):**
  - Primary references: Bellare, Garay & Rabin, *"Fast Batch Verification for Modular Exponentiation and Digital Signatures"* (EUROCRYPT 1998, LNCS 1403); Bowe, Gabizon & Miers, *"Scalable Multi-party Computation for zk-SNARK Parameters in the Random Beacon Model"* (IACR ePrint 2017/1050, §2.2 Powers of Tau ratio check).
  - **Fixed-input-before-challenge assumption:** All G1/G2 SRS points are copied into a private caller-isolated snapshot (`PlonKSetupBLS381` / `PtauImporterBLS381`) *before* subgroup checks or drawing the `SecureRandom` challenge `r in F_r \ {0}`, and that same private snapshot is used for every KZG commitment and stored in the returned `PlonKProvingKeyBLS381`.
  - For fixed validated prime-order subgroup points `P_0..P_{m}` in `G1` and `G2, tau*G2` in `G2`, checking `e(sum_{j=0}^{m-1} r^j P_{j+1}, G2) == e(sum_{j=0}^{m-1} r^j P_j, tau*G2)` fails to detect an inconsistent SRS with probability at most `(m - 1) / (r - 1) < 2^{-230}` for `m <= 2^24 + 6`.
- **ZeroJ Poseidon Authenticated State v1 specification:** `docs/merkle/poseidon-authenticated-state-v1.md` (Proof normalization invariant #8: every field decoded from 32 bytes is canonical rather than reduced).
- **ADR-0025 / ADR-0037 / ADR-0038 / ADR-0063 / ADR-0066.**

---

## Security Invariants

1. **I1 (Subtraction non-underflow):** `ZkUInt.sub(other)` rejects `max(bits, other.bits) >= MAX_BITS` (`>= 253`), ensuring `2^(width + 1) <= p` on every supported curve (BN254, BLS12-381, Pallas).
2. **I2 (SRS consistency soundness & caller-isolated snapshot):** `PlonKSetupBLS381.setup` copies the required `domainSize + 6` G1 prefix and 2 G2 anchors into private arrays at entry before validation, uses those same private arrays for every KZG commitment and inside the returned `PlonKProvingKeyBLS381`, and never re-reads caller-visible arrays. Every SRS accepted by `PtauImporterBLS381` or `PlonKSetupBLS381` has validated generator anchors, validated non-infinity prime-order subgroup points, and passes the `SecureRandom`-challenged batched pairing check on its pinned snapshot. Reusing a `PtauImporterBLS381`-verified `SRS` in `PlonKSetupBLS381` skips redundant subgroup/pairing work **only** when element-by-element equality of the pinned snapshot against the recorded import snapshot confirms zero post-import mutation.
3. **I3 (Booleanity enforcement without bloat):** `CircuitAPIImpl` records provably-boolean wires (`oneWire`, exact constants `0` and `1`, `isZero` / `isEqual`, `lessThan`, `decompose` bits, and outputs of `xor`/`and`/`or`/`not`) in `booleanWires`, enforces `assertBoolean` on operands of `xor`, `and`, `or`, and `not`, and bounds `fromBinary` to `1 <= bits.length <= MAX_SAFE_BITS`. Non-boolean constants (`2`, `p - 1`, etc.) remain excluded from `booleanWires` so explicit `assertBoolean(constant(2))` still fails.
4. **I4 (Canonical witness & input validation with secret redaction):**
   - `WitnessCalculator` rejects null maps, unknown input keys, null values, multi-value lists (`size != 1`), and non-canonical values (`< 0` or `>= p`) rather than silently reducing modulo `p`.
   - `ZkInputMap` and generated `Inputs` setters enforce non-negative / declared type ranges (`BOOL`/`BITS`: `{0, 1}`, `BYTES`: `[0, 255]`, `UINT(bits)`: `[0, 2^bits)`, `FIELD`: `[0, p)` at curve-bound validation).
   - `R1CSConstraintSystem.verifyWitness` provides curve-generic R1CS witness verification checking wire-0 `== 1`, canonical `[0, prime)`, bounds, and every constraint `(A·w)(B·w) ≡ C·w (mod prime)`.
   - `Groth16Prover.validateWitness` is `@Deprecated(forRemoval = true)`, gated behind `LegacyCurvePolicy.requireLegacyBn254Enabled()`, and enforces bounds, wire-0 `== 1`, and canonical BN254 scalars.
   - All validation exceptions report only the signal name, wire index, constraint index, and failed rule — never witness values or witness-derived linear-combination evaluations.
5. **I5 (MPF canonical `< Fr` key paths & nibble-checked forks):** `ZkMpf.requireKeyPath` (and `ZkMpfProof` leaf key paths) constrain the 64-nibble big-endian key path to be strictly less than `FieldConfig.BLS12_381.prime()`. `PoseidonMpfCodec.Step.fork` rejects `prefix.length > 64`, negative `skip`, `neighborNibble` outside `[0, 15]`, or any prefix byte outside `[0, 15]`.
6. **I6 (Correct bit rotation, honest range/hash semantics, and `@Prove` ownership):**
   - `Binary.rotateLeft` and `SignalBinary.rotateLeft` rotate LSB-first bit vectors left (`result[i] = bits[(i - floorMod(n, len) + len) % len]`), rejecting null/empty arrays; `Binary.shiftRight` rejects `n < 0` and avoids integer overflow.
   - `RangeCheck` replaces `AliasCheck` (`@Deprecated(forRemoval = true)`) with accurate `< 2^nBits` semantics.
   - `PoseidonN` null-checks inputs and documents fixed-arity-only non-circomlib semantics and collision caveats.
   - `CircuitAnnotationProcessor` checks `Objects.requireNonNull` and `__zeroj.requireSignal(__zerojResult.signal())` before calling `.assertTrue()` on a `@Prove` return value.

---

## Decision & Alternatives Considered

- **Batched SRS pairing vs. per-index pairing:** Per-index pairing is $O(n)$ pairings (seconds to minutes at medium powers). A single `SecureRandom` RLC reduces pairing cost to $O(1)$ (2 Miller loops + 1 final exponentiation) with `< 2^{-230}` soundness error, while a snapshot-verified `WeakHashMap` avoids duplicating work when `PlonKSetupBLS381.setup` consumes an unmodified `PtauImporterBLS381.SRS`.
  - *Alternative rejected:* Trusting a mutable boolean flag on `SRS` without snapshot comparison — rejected because `SRS.tauG1()` is a mutable array that callers could tamper with after import.
- **Caching derived booleans in `CircuitAPIImpl` vs. forcing `assertBoolean` inside `fromBinary`:** SHA-256 and SHA-512 gadgets construct `ch`/`maj` using direct arithmetic (`mul`/`add`/`sub`) and pass those wires to `fromBinary`. Calling `assertBoolean` inside `fromBinary` would add ~4,096 redundant constraints per SHA block. Instead, enforcing `assertBoolean` on `xor`/`and`/`or`/`not` (backed by `booleanWires` propagation) protects raw boolean callers with zero bloat on proven booleans, while `fromBinary` enforces the `1..MAX_SAFE_BITS` width guard.
- **Strict canonical `WitnessCalculator` by default vs. opt-in overload:** Silent `.mod(p)` hides prover-vs-verifier public-input mismatches because BLS12-381 verifiers fail closed on `>= r`. Making canonical `[0, p)` enforcement the default closes the mismatch class completely.
- **Deprecating `AliasCheck` and `Groth16Prover.validateWitness` vs. immediate deletion:** Keeping source-compatible deprecated facades with clear replacements (`RangeCheck` and `R1CSConstraintSystem.verifyWitness`) preserves existing API surface contracts (including `Groth16ProverApiSurfaceTest`) while blocking unsafe use (`LegacyCurvePolicy` gate on `validateWitness`).

---

## Compatibility & Migration Notes

- **Poseidon MPF circuit keys (breaking R1CS change):** Enforcing `< Fr` on `keyPath` (and `leafKeyPath`) adds constraints and changes the canonical R1CS SHA-256 digests for all MPF templates (`inclusion`, `non-inclusion-*`, `value-update`, `insert-*`, `full-semantics-*`). Existing deployments must recompile MPF circuits and regenerate proving/verifying keys.
- **Derived-boolean deduplication (breaking R1CS change for affected circuits):** Recording provably-boolean outputs (`oneWire`, exact `0`/`1` constants, `isZero`/`isEqual`, `xor`/`and`/`or`/`not`) in `CircuitAPIImpl.booleanWires` eliminates redundant `AssertBoolean` rows in circuits that later select on or re-assert those wires (for example, `-1` row on `ZkJubjubPoint.assertInPrimeOrderSubgroup` and `-160` rows on `zeroj-jmt-v1-insert-different-leaf-s8-p2`). Recompile and regenerate keys for affected circuits.
- **Poseidon MPF terminal-fork exclusion limitation:** In `ZkMpf`, full-semantics non-inclusion fails closed on terminal-fork steps (`valid && forkKind && lastValid`) because CCL's terminal-fork wire proof omits an authenticated commitment for the skipped branch. For a fixed absent key on an unchanged trie, the proof path is deterministic, so that absent key cannot be proven non-included under the current MPF full-semantics or branch-only templates (branch-only templates cover only branch-only empty-child and different-leaf shapes). Callers requiring total non-inclusion over arbitrary authenticated trie states should use the `zeroj-jmt-poseidon` templates (which have no compressed fork steps) or wait for a future MPF witness format that authenticates terminal-fork commitments.
- **`Binary.rotateLeft` / `SignalBinary.rotateLeft`:** Previously rotated in the opposite (right) direction; callers expecting LSB-first circular left rotation now get the mathematically correct result.
- **`WitnessCalculator` / `ZkInputMap`:** Negative inputs, values `>= p`, unknown keys, and multi-element input lists now throw `IllegalArgumentException` instead of being silently reduced or ignored.
- **`Groth16Prover.validateWitness`:** Now requires legacy BN254 opt-in (`LegacyCurvePolicy`) and is scheduled for removal; migrate to `R1CSConstraintSystem.verifyWitness`.

---

## Implementation Milestones

1. **M1:** Cap `ZkUInt.sub` at `<= 252` bits, clarify `CircuitAPIImpl.MAX_SAFE_BITS` Javadoc, add BN254 & BLS12-381 regression tests.
2. **M2:** Eliminate PlonK $O(n^2)$ exponent loops (`cosetEval`, `powFr`, `zetaN`, `PlonKSetupBLS381` precomputed `omegaPows`) and introduce `SrsConsistencyBLS381` batched RLC pairing check with snapshot-checked reuse across `PtauImporterBLS381` and `PlonKSetupBLS381`.
3. **M3:** Propagate derived-boolean tracking in `CircuitAPIImpl`, enforce operand booleanity in `xor`/`and`/`or`/`not`, and add `1..MAX_SAFE_BITS` width guard on `fromBinary`.
4. **M4:** Enforce canonical input validation in `WitnessCalculator`, `ZkInputMap`, and generated `Inputs`; add curve-generic `R1CSConstraintSystem.verifyWitness`; deprecate, gate, and harden `Groth16Prover.validateWitness`.
5. **M5:** Enforce `< Fr` key-path canonicality in `ZkMpf`, validate nibble range in `PoseidonMpfCodec.Step.fork`, update pinned MPF R1CS profiles, and document the unsupported MPF terminal-fork exclusion case accurately.
6. **M6:** Fix `Binary`/`SignalBinary.rotateLeft` and `Binary.shiftRight`, add `RangeCheck` & deprecate `AliasCheck`, harden/document `PoseidonN`, and check returned `ZkBool` ownership in `CircuitAnnotationProcessor`.

---

## Verification & Test-Vector Strategy

- **Negative soundness tests:** BN254 253-bit `ZkUInt.sub` rejection + 252-bit underflow rejection on BN254 & BLS12-381; raw non-boolean witness injection into `xor`/`and`/`or`/`not` rejected by R1CS; `fromBinary` empty and `> 253` width rejection; non-canonical MPF `64 × 0xF` and `Fr` key paths rejected by R1CS; non-nibble fork prefix bytes rejected by `Step.fork` & CBOR decode; foreign-builder and null `@Prove` `ZkBool` return rejection.
- **PlonK scaling & interop:** Synthetic corrupted SRS (single tampered G1 power, swapped G1 power, wrong generator anchor, mutated post-import `SRS`) rejected by batched RLC check; live `snarkjs@0.7.6` `.ptau -> setup -> prove -> verify` interop remains green.
- **Witness & gadget correctness:** Unknown keys, multi-value lists, negative and `>= p` inputs rejected by `WitnessCalculator` and `ZkInputMap`/`Inputs`; `R1CSConstraintSystem.verifyWitness` verified on both BLS12-381 and BN254 with tampered wire-0, out-of-range scalar, wrong length, and broken constraint; integer-value tests for `Binary.rotateLeft`, `SignalBinary.rotateLeft`, `Binary.shiftRight`, `RangeCheck`, `PoseidonN`.

---

## Production & Audit Gates

- This ADR does **not** promote any module to production-safe status. External cryptographic review of the DSL constraint lowering, PlonK prover/setup, and Poseidon MPF circuits remains mandatory before value-bearing or mainnet deployment.
