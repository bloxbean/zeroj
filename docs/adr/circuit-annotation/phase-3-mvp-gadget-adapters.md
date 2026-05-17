# Phase 3: MVP Gadget Adapters

## Status

Approved.

## Goal

Add the first symbolic adapters for existing `zeroj-circuit-lib` gadgets so
annotation-authored circuits can use realistic hash and Merkle workflows
without extracting raw `Signal` values and wrapping results manually.

## Implemented Changes

- Added `zeroj-circuit-lib` dependency on `zeroj-circuit-annotation-api`.
- Added `com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMiMC`.
- Added `com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidon`.
- Added `com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle`.
- Added `ZkMerkle.HashType` with `MIMC` and `POSEIDON` choices.
- Added `ZkMerkle.HashFn` for custom symbolic two-to-one hash functions.
- Added BN254 field guards to existing MiMC gadgets.
- Added differential tests against `SignalMiMC`, `SignalPoseidon`, and
  `SignalMerkle`.
- Updated `zeroj-circuit-lib` README with the symbolic adapter surface.

## Public API Changes

- `ZkMiMC.hash(zk, left, right)` returns `ZkField`.
- `ZkPoseidon.hash(zk, left, right)` returns `ZkField` using the existing
  default Poseidon parameters.
- `ZkPoseidon.hash(zk, params, left, right)` supports explicit
  `PoseidonParams`.
- `ZkMerkle.computeRoot(...)` returns the computed symbolic root.
- `ZkMerkle.verify(...)` asserts the computed root equals the supplied root.
- `ZkMerkle.verifyProof(...)` aliases `verify(...)` for parity with
  `SignalMerkle.verifyProof(...)`.
- `ZkMerkle.isMember(...)` returns a `ZkBool` membership predicate.
- All adapters validate that input signals belong to the supplied `ZkContext`.
- `ZkMiMC` is guarded as BN254-only, matching the existing MiMC constants.

## Exit Criteria Mapping

| ADR exit criterion | Phase 3 result |
|--------------------|----------------|
| Hash commitment can be written without `.signal()` / `wrap(...)` boilerplate | Covered by `ZkMiMC.hash(...)` and `ZkPoseidon.hash(...)`. |
| Merkle membership can be written with `ZkArray` | Covered by `ZkMerkle.computeRoot(...)`, `verify(...)`, and `isMember(...)`. |
| Adapters reuse existing `Signal` or `Variable` gadgets | `ZkMiMC` delegates to `SignalMiMC`; `ZkPoseidon` delegates to `SignalPoseidon`; `ZkMerkle` delegates to `SignalMerkle`. |
| Differential tests against existing gadgets | Covered by `ZkGadgetAdaptersTest`. |

## Verification

- `./gradlew :zeroj-circuit-lib:test --tests com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkGadgetAdaptersTest` passed after blocker fixes.
- `./gradlew :zeroj-circuit-lib:test` passed.
- `./gradlew :zeroj-circuit-annotation-api:test :zeroj-circuit-annotation-processor:test` passed.
- `rg -n "[[:blank:]]$" docs/adr/circuit-annotation zeroj-circuit-lib/src/main/java/com/bloxbean/cardano/zeroj/circuit/lib/zk zeroj-circuit-lib/src/test/java/com/bloxbean/cardano/zeroj/circuit/lib/zk zeroj-circuit-lib/build.gradle zeroj-circuit-lib/README.md zeroj-circuit-lib/src/main/java/com/bloxbean/cardano/zeroj/circuit/lib/MiMC.java zeroj-circuit-lib/src/main/java/com/bloxbean/cardano/zeroj/circuit/lib/SignalMiMC.java` passed.
- `git diff --cached --check` passed.

## Review Results

Three-agent review approved Phase 3 after blocker fixes:

- API/design review initially blocked on `ZkMerkle` duplicating
  `SignalMerkle`, missing root ownership validation, and weak Merkle
  differential behavior. The final review approved the delegation,
  `verifyProof(...)` alias, root validation, and strengthened tests.
- ZK-safety review initially blocked on MiMC missing a field guard. The final
  review approved the BN254 guard in `MiMC` and `SignalMiMC`, plus ownership
  validation for custom Merkle hash results.
- Tests/docs review initially blocked on the Merkle reuse/differential gap. The
  final review approved the stronger Merkle behavior tests, Poseidon hash-type
  coverage, explicit BLS12-381 Poseidon-params test, MiMC field-guard test, and
  cross-builder guard tests.

## Commit

Pending.
