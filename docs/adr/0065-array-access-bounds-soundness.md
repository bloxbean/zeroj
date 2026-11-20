# ADR-0065: Bounds-Constrained `CircuitAPI.arrayAccess` and Explicit Total Lookup (`arrayAccessOrZero`)

## Status
Proposed — 2026-11-20 (pending review sign-off). Hardens `CircuitAPI.arrayAccess` (and its delegates `SignalBuilder.arrayAccess` and `Mux.arrayAccess`) to enforce `0 <= index < arr.length` in-circuit, and introduces an explicitly named total-function variant `arrayAccessOrZero` for callers with independently constrained indices and masked padding rows. Amends [ADR-0010](0010-java-circuit-dsl.md).

**Risk class: R2.** Changes circuit soundness semantics and emitted R1CS/PlonK constraints for every caller of `CircuitAPI.arrayAccess` / `SignalBuilder.arrayAccess` / `Mux.arrayAccess`.

## Date
2026-11-20

## Context
`CircuitAPIImpl.arrayAccess(Variable[] arr, Variable index)` implements dynamic indexing over a fixed-length circuit array by computing:

$$\text{result} = \sum_{i=0}^{n-1} \text{arr}[i] \cdot \text{isEqual}(\text{index}, i)$$

Previously, the method neither rejected empty arrays nor constrained `index` to lie in `[0, n - 1]`. Consequently, whenever a prover supplied any out-of-bounds field element (`index = n`, `index = p - 1`, etc.), every selector `isEqual(index, i)` evaluated to `0`, the sum silently produced `0`, and the constraint system remained satisfied.

In an application circuit that assumes `arr[index]` reads a real entry of `arr` (for example, looking up an allowlisted value, permission flag, fee tier, or commitment at a secret index, or asserting `arr[index] == 0`), a malicious prover could supply an out-of-bounds index (such as `arr.length` or `p - 1`) to fabricate a `0` lookup result without possessing a valid array entry.

A full in-repository caller census showed only three production call paths:
1. `SignalBuilder.arrayAccess(Signal[], Signal)` (`zeroj-circuit-dsl`) — delegates to `CircuitAPI.arrayAccess`.
2. `Mux.arrayAccess(CircuitAPI, Variable[], Variable)` (`zeroj-circuit-lib`) — delegates to `CircuitAPI.arrayAccess`.
3. `ZkMpf.PathSignals.at(ZkContext, Signal)` (`zeroj-mpf-poseidon/.../circuit/ZkMpf.java:829`) — looks up a nibble in a 64-element key path. Every active lookup in `ZkMpf` already carries an explicit `lteConst` bounds constraint (`<= 63`), whereas inactive padding rows (`valid == 0`) intentionally evaluate `queryIndex = 64` and discard the lookup via `valid.select(...)`.

## Threat Model and Trust Assumptions
- **Untrusted:** Any prover-controlled witness wire passed as `index` or as an element of `arr` (including `index = arr.length`, `index = p - 1`, or arbitrary field elements in `F_p`).
- **Trusted:** Circuit-construction-time array length `arr.length` (`1 <= arr.length <= Integer.MAX_VALUE < p` for all supported curves: BLS12-381 `Fr`, BN254 `Fr`, Pallas `Fp`).
- **Constraint-system assumption:** `isEqual(index, constant(i))` is sound (returns `1` iff `index == i (mod p)` and `0` otherwise, enforced via `isZero`).

## Pinned Normative References
- [ADR-0010](0010-java-circuit-dsl.md) — Java Circuit DSL (`CircuitAPI.arrayAccess`).
- [ADR-0037](0037-jubjub-soundness-and-hardening.md) — Circuit-DSL soundness precedent (explicit in-circuit bounds on `lessThan` rather than undocumented caller preconditions).
- [ADR-0042](0042-operation-specific-poseidon-mpf-and-jmt-circuits.md) — Operation-specific Poseidon MPF circuits and their pinned canonical R1CS SHA-256 digests (`ZkMpfOperationCircuitTest`, `ZkMpfTransitionCircuitTest`).

## Decision
1. **D1 (Strict bounds-constrained `arrayAccess`):**
   - `CircuitAPIImpl.arrayAccess(Variable[] arr, Variable index)` validates `requireNotFrozen()`, rejects `null` arguments (array, elements, or `index`) atomically before emitting any gate, and rejects `arr.length == 0` with `IllegalArgumentException`.
   - For `arr.length >= 1`, `arrayAccess` computes `selector_i = isEqual(index, constant(i))`, accumulates `result = sum(arr[i] * selector_i)`, forms the single linear combination `selectorSum = sum(selector_i)` via `Gate.LinComb`, and emits **`assertEqual(selectorSum, oneWire)`**.
   - **Soundness proof:** Because `1 <= n <= Integer.MAX_VALUE < p`, the constants `0, 1, ..., n - 1` are pairwise distinct modulo `p`. For any field element `index ∈ F_p`, at most one `selector_i` equals `1` (the rest are `0`). Hence `sum_{i=0}^{n-1} selector_i == 1` holds **if and only if** `index ∈ {0, 1, ..., n - 1}`, in which case `result == arr[index]`. Any out-of-bounds `index` yields `selectorSum == 0 != 1`, making the constraint system unsatisfiable.
   - **Cost:** Adding `Gate.LinComb` + `AssertEq` costs **1 R1CS constraint and 1 wire** regardless of `arr.length` (no extra multiplications or bit decompositions).
   - `SignalBuilder.arrayAccess` and `Mux.arrayAccess` delegate directly to `CircuitAPI.arrayAccess` and inherit this invariant automatically.
2. **D2 (Explicit total-function lookup `arrayAccessOrZero`):**
   - Add `default Variable arrayAccessOrZero(Variable[] arr, Variable index)` to `CircuitAPI` (overridden in `CircuitAPIImpl` with lifecycle/null validation) and `SignalBuilder.arrayAccessOrZero(Signal[] arr, Signal index)` with explicit Javadoc warning that out-of-bounds indices silently return `0` without constraining `index`.
   - `arrayAccessOrZero` is strictly opt-in for circuits that independently constrain `index` on active rows and mask inactive padding rows.
3. **D3 (`ZkMpf` padding-row preservation):**
   - Update `ZkMpf.PathSignals.at` (`ZkMpf.java:829`) to call `zk.builder().arrayAccessOrZero(signals, index)` with an inline citation to `ZkMpf`'s existing explicit bounds constraints (`prepareBranchProof:249`, `computeRoot:321`, `nonInclusionDifferentLeaf:131`, `verifyDifferentLeafInsertion:168`) and padding-row masking (`valid.select`).
   - This preserves all existing pinned `ZkMpf` R1CS constraint counts and canonical SHA-256 digests unchanged while making the opt-in total-lookup semantics explicit in source.

## Alternatives Considered
- **Clamp `queryIndex` on padding rows in `ZkMpf` and keep only strict `arrayAccess`:** Rejected for this PR because clamping adds `select` + `arrayAccess` constraints on every `ZkMpf` branch step and breaks every pinned R1CS SHA-256 digest and proving key across `zeroj-mpf-poseidon` even though `ZkMpf` already constrains active bounds independently. Providing `arrayAccessOrZero` keeps the general `arrayAccess` API sound by default with zero key churn on `ZkMpf`.
- **Add a `lessThan(index, n)` bit-decomposition check instead of `sum(selector_i) == 1`:** Rejected — `arrayAccess` already computes all `n` equality selectors `isEqual(index, i)`, so constraining `sum(selector_i) == 1` costs 1 linear constraint instead of `ceil(log2(n)) + 2` range-check constraints and requires no bit-width parameter.
- **Document OOB → 0 as a precondition on `arrayAccess`:** Rejected — matches the unsafe pattern ADR-0037 retired for `lessThan`; dynamic array indexing must fail closed by default.

## Security Invariants
- **I1 (In-bounds enforcement):** For any non-empty array `arr` of length `n >= 1`, `arrayAccess(arr, index)` is satisfiable iff `index ∈ {0, 1, ..., n - 1}` (as a field element in `F_p`), and its output wire equals `arr[index]`.
- **I2 (OOB rejection):** Any witness with `index = n`, `index = n + 1`, or `index = p - 1` fails R1CS and PlonK constraint satisfaction on both BLS12-381 and BN254, even when `arr` contains `0` entries.
- **I3 (Empty-array & null rejection):** `arrayAccess` throws `IllegalArgumentException` on `arr.length == 0` and `NullPointerException` on null `arr`, null elements, or null `index`, atomically before emitting any gate.
- **I4 (Explicit total opt-in):** Out-of-bounds → `0` semantics are reachable only through the explicitly named `arrayAccessOrZero` method.
- **I5 (MPF template stability):** All pinned `ZkMpf` R1CS constraint counts and canonical SHA-256 digests in `zeroj-mpf-poseidon` remain identical.

## Consequences
- **Positive:** Eliminates a silent under-constrained OOB→0 forgery class across `CircuitAPI.arrayAccess`, `SignalBuilder.arrayAccess`, and `Mux.arrayAccess` at a cost of 1 R1CS constraint per lookup.
- **Trade-offs:**
  - Circuits calling `arrayAccess` outside `ZkMpf` gain 1 R1CS constraint and 1 wire per `arrayAccess` call and therefore produce new R1CS digests / proving & verification keys.
  - Custom `CircuitAPI` implementations remain source-compatible because `arrayAccessOrZero` has a `default` implementation on `CircuitAPI`.

## Risks
- **Misuse of `arrayAccessOrZero`:** A caller choosing `arrayAccessOrZero` without independently constraining active indices reintroduces OOB→0 behavior. Mitigated by naming (`OrZero`), explicit Javadoc warning, and keeping `Mux.arrayAccess` / `SignalBuilder.arrayAccess` / `CircuitAPI.arrayAccess` strictly constrained.
- **Downstream key migration:** External circuits (e.g., in downstream applications using `Mux.arrayAccess` or `SignalBuilder.arrayAccess`) must regenerate proving/verifying keys after upgrading.

## Compatibility
- **Breaking R1CS / key change for `arrayAccess` callers:** Every circuit calling `CircuitAPI.arrayAccess`, `SignalBuilder.arrayAccess`, or `Mux.arrayAccess` gains 1 R1CS constraint and 1 wire per call and requires fresh circuit-specific keys. Release notes must record this explicitly.
- **Non-breaking for `zeroj-mpf-poseidon`:** `ZkMpf` switches to `arrayAccessOrZero` (matching its independently constrained active indices and masked padding rows), so all pinned MPF R1CS digests and keys remain unchanged.
- **Source/binary API compatibility:** `CircuitAPI.arrayAccessOrZero` is added as a `default` method so existing `CircuitAPI` implementations compile unchanged.

## Implementation Milestones
- **M1 — DSL & MPF implementation (Complete):** Enforce `sum(selector_i) == 1` and reject empty arrays in `CircuitAPIImpl.arrayAccess`, add `arrayAccessOrZero` to `CircuitAPI`/`CircuitAPIImpl`/`SignalBuilder`, update `Mux.arrayAccess` Javadoc, and switch `ZkMpf.PathSignals.at` to `arrayAccessOrZero`.
- **M2 — Adversarial & cross-backend verification (Complete):** Add `ArrayAccessSoundnessTest` in `zeroj-circuit-dsl` covering in-bounds reads, OOB rejections (`arr.length`, `arr.length + 1`, `p - 1`, `arr.length == 1`, zero-valued entries), empty/null/frozen rejections, `SignalBuilder` and `Mux` delegation, both BLS12-381 and BN254, and both R1CS and PlonK constraint checks; verify `zeroj-mpf-poseidon` pinned R1CS digests remain unchanged.
- **M3 — Documentation & review (In progress):** `ADR-0010` back-reference and user guides (`docs/circuit-dsl-user-guide.md`, `www/src/content/docs/guides/circuits/circuit-dsl.md`) updated; awaiting external review sign-off before marking ADR-0065 `Accepted`.

## Verification Strategy
1. **Unit & adversarial soundness (`zeroj-circuit-dsl` — `ArrayAccessSoundnessTest`):**
   - Positive tests: every valid index `0 .. n - 1` (for `n = 1` and `n = 4`) returns exact `arr[index]` and satisfies R1CS and PlonK on both BLS12-381 and BN254.
   - Negative OOB tests (all must fail witness / constraint verification): `index = n`, `index = n + 1`, `index = p - 1`, including when `arr` contains `0` and when the caller asserts `result == 0` (reproducing the pre-fix forgery).
   - Guard tests: empty `arr` throws `IllegalArgumentException`, null `arr` / null element / null `index` throws `NullPointerException` atomically before emitting gates, and post-freeze invocation throws `IllegalStateException`.
   - `arrayAccessOrZero` tests: returns `arr[i]` for `0 <= i < n` and `0` for `index = n` / `index = p - 1` / empty `arr`.
2. **Stdlib & MPF regression (`zeroj-circuit-lib`, `zeroj-mpf-poseidon`, `zeroj-integration-tests`):**
   - Verify `Mux.arrayAccess` rejects OOB indices.
   - Verify all pinned `ZkMpfOperationCircuitTest` and `ZkMpfTransitionCircuitTest` R1CS SHA-256 digests and padding-row tests pass unchanged.

## Remaining Production / Audit Gates
- External cryptographic/circuit audit remains required before mainnet or value-bearing deployment of circuits built with `zeroj-circuit-dsl`.

## Revision History
| Date | Status | Summary |
|---|---|---|
| 2026-11-20 | Proposed (rev 1) | Initial ADR and implementation for bounds-constrained `arrayAccess` and opt-in `arrayAccessOrZero`. |
