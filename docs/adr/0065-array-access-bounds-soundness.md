# ADR-0065: Bounds-Constrained `CircuitAPI.arrayAccess` and Explicit Total Lookup (`arrayAccessOrZero`)

## Status
Proposed — 2026-11-20 (pending review sign-off). Hardens `CircuitAPI.arrayAccess` (and its delegates `SignalBuilder.arrayAccess` and `Mux.arrayAccess`) to enforce `0 <= index < arr.length` in-circuit, and introduces an explicitly named total-function variant `arrayAccessOrZero` for callers with independently constrained indices and masked padding rows. Amends [ADR-0010](0010-java-circuit-dsl.md).

**Risk class: R2.** Changes circuit soundness semantics and emitted R1CS/PlonK/Halo2 constraints for every caller of `CircuitAPI.arrayAccess` / `SignalBuilder.arrayAccess` / `Mux.arrayAccess`.

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
3. `ZkMpf.PathSignals.at(ZkContext, Signal)` (`zeroj-mpf-poseidon/.../circuit/ZkMpf.java:829`) — looks up a nibble in a 64-element key path. Every active lookup in `ZkMpf` already carries an explicit `lteConst` bounds constraint (`<= 63`), whereas inactive padding rows (`valid == 0`) evaluate the final cursor (`cursor + 0 + 1 - 1`), which can be `64` when the full 64-nibble key path has been consumed, and discard the lookup via `valid.select(...)`.

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
   - For `arr.length >= 1`, `arrayAccess` computes `selector_i = isEqual(index, constant(i))`, accumulates `result = sum(arr[i] * selector_i)`, forms the single linear combination `selectorSum = sum(selector_i)` via `Gate.LinComb` (whose compact constructor defends `terms` with `List.copyOf` so published graphs are immutable), and emits **`assertEqual(selectorSum, oneWire)`**.
   - **Soundness proof:** Because `1 <= n <= Integer.MAX_VALUE < p`, the constants `0, 1, ..., n - 1` are pairwise distinct modulo `p`. For any field element `index ∈ F_p`, at most one `selector_i` equals `1` (the rest are `0`). Hence `sum_{i=0}^{n-1} selector_i == 1` holds **if and only if** `index ∈ {0, 1, ..., n - 1}`, in which case `result == arr[index]`. Any out-of-bounds `index` yields `selectorSum == 0 != 1`, making the constraint system unsatisfiable across R1CS, PlonK, and Halo2.
   - **Per-backend cost (vs `arrayAccessOrZero` for an `n`-element array):**
     - **DSL graph:** `+1` intermediate wire (`selectorSum`), `+1` `Gate.LinComb`, `+1` `Gate.AssertEq`.
     - **R1CS (`R1CSCompiler`):** `+1` constraint row when `selectorSum` is inlined; `+2` constraint rows under compiler pressure mode (when the compiler materializes `selectorSum` in its own row before the equality row).
     - **PlonK (`PlonKCompiler`) and Halo2 (`Halo2Compiler`):** `+n` rows/gates (`n - 1` binary addition gates for the `n`-term `LinComb` chain plus `1` equality gate; e.g., `50 -> 54` at `n = 4`, `185 -> 201` at `n = 16`, `713 -> 777` at `n = 64`).
   - `SignalBuilder.arrayAccess` and `Mux.arrayAccess` delegate directly to `CircuitAPI.arrayAccess` and inherit this invariant automatically.
2. **D2 (Explicit total-function lookup `arrayAccessOrZero`):**
   - Add `default Variable arrayAccessOrZero(Variable[] arr, Variable index)` to `CircuitAPI` (overridden in `CircuitAPIImpl` with lifecycle/null validation) and `SignalBuilder.arrayAccessOrZero(Signal[] arr, Signal index)` with explicit Javadoc warning that out-of-bounds indices silently return `0` without constraining `index`.
   - `arrayAccessOrZero` is strictly opt-in for circuits that independently constrain `index` on active rows and mask inactive padding rows.
3. **D3 (`ZkMpf` padding-row preservation):**
   - Update `ZkMpf.PathSignals.at` (`ZkMpf.java:829`) to call `zk.builder().arrayAccessOrZero(signals, index)` with an inline citation to `ZkMpf`'s existing explicit bounds constraints (`prepareBranchProof:249`, `computeRoot:323`, `differentLeafRoot:131`, `verifyDifferentLeafInsertion:168`) and padding-row masking (`valid.select`, where padding rows evaluate the final cursor, which can be `64`).
   - This preserves all existing pinned `ZkMpf` R1CS constraint counts and canonical SHA-256 digests unchanged while making the opt-in total-lookup semantics explicit in source.

## Alternatives Considered
- **Clamp `queryIndex` on padding rows in `ZkMpf` and keep only strict `arrayAccess`:** Rejected for this PR because clamping adds `select` + `arrayAccess` constraints on every `ZkMpf` branch step and breaks every pinned R1CS SHA-256 digest and proving key across `zeroj-mpf-poseidon` even though `ZkMpf` already constrains active bounds independently. Providing `arrayAccessOrZero` keeps the general `arrayAccess` API sound by default with zero key churn on `ZkMpf`.
- **Add a `lessThan(index, n)` bit-decomposition check instead of `sum(selector_i) == 1`:** Rejected — `arrayAccess` already computes all `n` equality selectors `isEqual(index, i)`, so constraining `sum(selector_i) == 1` reuses existing selectors, costs 1–2 rows on R1CS (and `n` linear/eq rows on PlonK/Halo2), and requires no bit-width parameter.
- **Document OOB → 0 as a precondition on `arrayAccess`:** Rejected — matches the unsafe pattern ADR-0037 retired for `lessThan`; dynamic array indexing must fail closed by default.

## Security Invariants
- **I1 (In-bounds enforcement):** For any non-empty array `arr` of length `n >= 1`, `arrayAccess(arr, index)` is satisfiable iff `index ∈ {0, 1, ..., n - 1}` (as a field element in `F_p`), and its output wire equals `arr[index]`.
- **I2 (OOB rejection across all backends):** Any witness with `index ∈ {n, n + 1, p - 1}` fails R1CS, PlonK, and Halo2 constraint satisfaction on both BLS12-381 and BN254, even when `arr` contains `0` entries, while the identical witness satisfies the `arrayAccessOrZero` control circuit on all three backends.
- **I3 (Empty-array, null, frozen, and immutability guards):** `arrayAccess` throws `IllegalArgumentException` on `arr.length == 0`, `NullPointerException` on null `arr`/elements/`index` atomically before emitting any gate, and `IllegalStateException` after graph freeze; published `Gate.LinComb.terms()` lists are immutable (`List.copyOf`).
- **I4 (Explicit total opt-in):** Out-of-bounds → `0` semantics are reachable only through the explicitly named `arrayAccessOrZero` method.
- **I5 (MPF template stability):** All pinned `ZkMpf` R1CS constraint counts and canonical SHA-256 digests in `zeroj-mpf-poseidon` remain identical.

## Consequences
- **Positive:** Eliminates a silent under-constrained OOB→0 forgery class across `CircuitAPI.arrayAccess`, `SignalBuilder.arrayAccess`, and `Mux.arrayAccess` on R1CS, PlonK, and Halo2, and makes `Gate.LinComb.terms()` immutable for all callers (including `fromBinary`).
- **Trade-offs:**
  - Circuits calling `arrayAccess` outside `ZkMpf` pay `+1` R1CS row when inlined (`+2` under pressure mode) or `+n` PlonK/Halo2 rows per `arrayAccess` call and produce new proving/verifying keys across every backend.
  - Empty-array `arrayAccess` calls now fail fast at circuit definition time instead of silently returning `constant(0)`.

## Risks
- **Misuse of `arrayAccessOrZero`:** A caller choosing `arrayAccessOrZero` without independently constraining active indices reintroduces OOB→0 behavior. Mitigated by naming (`OrZero`), explicit Javadoc warning, and keeping `Mux.arrayAccess` / `SignalBuilder.arrayAccess` / `CircuitAPI.arrayAccess` strictly constrained.
- **Custom `CircuitAPI` implementations:** Downstream code supplying its own `CircuitAPI` implementation to `Mux` or other `zeroj-circuit-lib` gadgets compiles without error against the unchanged `arrayAccess` signature and would silently retain old zero-on-miss behavior if not updated. Mitigated by the explicit provider migration note in Compatibility below (`CircuitBuilder` always instantiates `CircuitAPIImpl`).
- **Downstream key migration:** External circuits using `Mux.arrayAccess`, `SignalBuilder.arrayAccess`, or `CircuitAPI.arrayAccess` must regenerate proving/verifying keys across R1CS, PlonK, and Halo2 after upgrading.

## Compatibility
- **Breaking constraint & key change across all backends (R1CS, PlonK, Halo2):** Every circuit calling `CircuitAPI.arrayAccess`, `SignalBuilder.arrayAccess`, or `Mux.arrayAccess` (outside `ZkMpf`) changes its compiled constraint system (`+1` R1CS row when inlined, `+2` under pressure mode; `+n` PlonK/Halo2 rows; `+1` DSL wire) and requires fresh circuit-specific proving/verifying keys. Release notes must record this explicitly.
- **Breaking build-time behavior for empty arrays:** Previously `arrayAccess(new Variable[0], index)` compiled and returned `constant(0)`. It now throws `IllegalArgumentException` at circuit definition time; callers genuinely requiring a total empty-array lookup must opt into `arrayAccessOrZero`.
- **Migration note for custom `CircuitAPI` implementations:** `CircuitBuilder` always constructs `CircuitAPIImpl`, so standard DSL circuits inherit the fix automatically. However, because `CircuitAPI.arrayAccess` retains its method signature, any downstream custom `CircuitAPI` implementation passed directly into `Mux.arrayAccess` or other `zeroj-circuit-lib` gadgets will still compile and load. Custom `CircuitAPI` authors **must** update their `arrayAccess` implementation to reject empty arrays and constrain `sum_i isEqual(index, i) == 1` (and confirm compiled constraints reject out-of-range indices) before regenerating keys.
- **Non-breaking for `zeroj-mpf-poseidon`:** `ZkMpf` switches to `arrayAccessOrZero` (matching its independently constrained active indices and masked padding rows), so all pinned MPF R1CS digests and keys remain unchanged.
- **Source/binary API compatibility:** `CircuitAPI.arrayAccessOrZero` is added as a `default` method so existing `CircuitAPI` implementations compile unchanged.

## Implementation Milestones
- **M1 — DSL & MPF implementation (Complete):** Enforce `sum(selector_i) == 1` and reject empty arrays in `CircuitAPIImpl.arrayAccess`, defend `Gate.LinComb.terms()` with `List.copyOf`, add `arrayAccessOrZero` to `CircuitAPI`/`CircuitAPIImpl`/`SignalBuilder`, update `Mux.arrayAccess` Javadoc, and switch `ZkMpf.PathSignals.at` to `arrayAccessOrZero`.
- **M2 — Adversarial & cross-backend verification (Complete):** Add `ArrayAccessSoundnessTest` in `zeroj-circuit-dsl` covering in-bounds reads, OOB rejections (`{n, n + 1, p - 1}` directly against R1CS, PlonK, and Halo2 constraint matrices with `arrayAccessOrZero` positive control, plus `WitnessCalculator` checks with zero-valued entries), per-backend row deltas, empty/null/frozen/immutability guards, and `Mux.arrayAccess` delegation on both BLS12-381 and BN254; verify `zeroj-mpf-poseidon` pinned R1CS digests remain unchanged.
- **M3 — Documentation & review (In progress):** `ADR-0010` back-reference and user guides (`docs/circuit-dsl-user-guide.md`, `www/src/content/docs/guides/circuits/circuit-dsl.md`, `www/src/content/docs/guides/circuits/gadgets.md`, `zeroj-circuit-lib/README.md`) updated; awaiting external review sign-off before marking ADR-0065 `Accepted`.

## Verification Strategy
1. **Unit & adversarial soundness (`zeroj-circuit-dsl` — `ArrayAccessSoundnessTest`):**
   - Positive tests: every valid index `0 .. n - 1` (for `n = 1` and `n = 4`) returns exact `arr[index]` and satisfies R1CS, PlonK, and Halo2 on both BLS12-381 and BN254.
   - Direct constraint-matrix OOB tests with control: forged OOB witnesses for `index ∈ {n, n + 1, p - 1}` fail R1CS, PlonK, and Halo2 on both BLS12-381 and BN254 for strict `arrayAccess`, while the identical forged witnesses satisfy the `arrayAccessOrZero` control circuit on all three backends.
   - `WitnessCalculator` OOB tests: `index ∈ {n, n + 1, 64, p - 1, p - 12345}` rejected even when `arr` contains `0` entries and the caller asserts `result == 0`.
   - Guard & immutability tests: empty `arr` throws `IllegalArgumentException`, null `arr` / null element / null `index` throws `NullPointerException` atomically before emitting gates, post-freeze invocation throws `IllegalStateException`, and published `Gate.LinComb.terms()` lists throw `UnsupportedOperationException` on mutation.
   - Cost & `arrayAccessOrZero` tests: verifies `+1` R1CS (inlined), `+n` PlonK, and `+n` Halo2 row deltas, plus total-function behavior for `0 <= i < n`, `index = n`, `index = p - 1`, and empty `arr`.
2. **Stdlib & MPF regression (`zeroj-circuit-lib`, `zeroj-mpf-poseidon`):**
   - Verify `Mux.arrayAccess` accepts in-bounds reads and rejects OOB indices and empty arrays.
   - Verify all pinned `ZkMpfOperationCircuitTest` and `ZkMpfTransitionCircuitTest` R1CS SHA-256 digests and padding-row tests pass unchanged.

## Remaining Production / Audit Gates
- External cryptographic/circuit audit remains required before mainnet or value-bearing deployment of circuits built with `zeroj-circuit-dsl`.

## Revision History
| Date | Status | Summary |
|---|---|---|
| 2026-11-20 | Proposed (rev 1) | Initial ADR and implementation for bounds-constrained `arrayAccess` and opt-in `arrayAccessOrZero`. |
| 2026-11-20 | Proposed (rev 2) | Addressed PR #119 review findings: made `Gate.LinComb.terms()` immutable via `List.copyOf` + test; documented exact per-backend costs (R1CS inlined `+1` / pressure `+2`, PlonK/Halo2 `+n`); extended constraint-matrix forged-witness tests to `{n, n + 1, p - 1}` across R1CS, PlonK, and Halo2 with `arrayAccessOrZero` positive control; added custom `CircuitAPI` migration note and empty-array Compatibility bullet; fixed `ZkMpf` citations (`differentLeafRoot:131`, `computeRoot:323`, final-cursor padding wording) and updated `gadgets.md` + `zeroj-circuit-lib/README.md`. |
