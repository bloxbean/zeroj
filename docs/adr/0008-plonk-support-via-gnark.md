# ADR-0008: PlonK Support via gnark

## Status
Accepted

## Date
2026-03-27

## Context

ZeroJ currently supports Groth16 verification on BN254 (pure Java) and BLS12-381 (via blst). Groth16 requires a per-circuit trusted setup — every new circuit needs a new ceremony, which creates friction for developers. PlonK uses a universal Structured Reference String (SRS) that works for any circuit up to a size threshold, and the SRS is updatable (anyone can strengthen it).

gnark (Go, Consensys) already supports PlonK on BLS12-381 and BN254 with the same circuit definition language used for Groth16. ZeroJ already has a `zeroj-prover-gnark` module with FFM bindings to gnark for Groth16. Extending to PlonK is a natural next step.

Cardano Plutus V3 provides BLS12-381 builtins (CIP-0381) sufficient for PlonK verification on-chain. The existing `zeroj-examples` project has demonstrated Groth16 BLS12-381 verification on Cardano preprod. PlonK BLS12-381 verification uses the same builtins (G1 add, scalarMul, millerLoop, finalVerify) with a different verification algorithm.

## Decision

### 1. Add PlonK as a first-class proof system in ZeroJ

- Add `ProofSystemId.PLONK` (already defined in the enum)
- Implement `PlonKVerifier` in `zeroj-verifier-groth16` module (or a new `zeroj-verifier-plonk` module)
- Reuse the existing `ZkVerifier` SPI — no API changes needed
- PlonK proofs flow through the same `ZkProofEnvelope`, `VerifierOrchestrator`, and pattern libraries

### 2. Extend gnark FFM integration for PlonK

The existing `zeroj-prover-gnark` Go wrapper exposes Groth16 setup/prove/verify. Extend it with:

```
zeroj_plonk_setup(r1csPath, srsPath, srsLagrangePath, pkPath, vkPath) → error
zeroj_plonk_prove(pkPath, r1csPath, witnessJson) → proofJson
zeroj_plonk_verify(vkPath, proofJson, publicInputsJson) → bool
zeroj_plonk_generate_srs(size, outputPath) → error  // for testing/dev
```

The SRS is a shared artifact — generated once, used for all circuits up to the SRS size.

### 3. Support both BN254 and BLS12-381 curves

gnark supports PlonK on both curves. For Cardano on-chain verification, BLS12-381 is required (Plutus V3 builtins). For off-chain/Yaci verification, either curve works.

### 4. PlonK proof codec

PlonK proofs have a different structure than Groth16:
- **Groth16**: 2 G1 + 1 G2 elements (~192 bytes compressed)
- **PlonK**: ~9 G1 elements + ~7 field elements (~656 bytes compressed)

The `zeroj-codec` module needs a PlonK-aware parser alongside the existing Groth16 snarkjs parser. gnark outputs proofs in its own JSON/binary format (not snarkjs format).

### 5. On-chain PlonK verification (Cardano)

PlonK verification on Plutus V3 requires:
- ~18 G1 scalar multiplications and additions (computing linearized commitment)
- 6 Fiat-Shamir challenge hash computations
- 2 Miller loops + 1 finalVerify (pairing check)
- Scalar field inversions

**Budget analysis** (with current Plutus V3 primitives):
- Pairing: ~1.19B CPU units (2 millerLoops + finalVerify)
- Scalar multiplications: dominant cost, depends on implementation
- **Feasible but tight** with current primitives
- **CIP-0133 (Multi-Scalar Multiplication)** would make it comfortable (~7-37x speedup)

The `zeroj-examples` on-chain verifier would need a new `PlonKBLS12381Verifier.java` Julc validator implementing the PlonK verification algorithm.

## Implementation Plan

### Phase 1: gnark Go wrapper extension
1. Add `zeroj_plonk_setup`, `zeroj_plonk_prove`, `zeroj_plonk_verify` to the Go wrapper
2. Add SRS generation helper for testing (`test/unsafekzg` package)
3. Build shared library for macOS-arm64 (dev), Linux-x86_64 (CI)
4. Fix the existing Go runtime crash (exit code 134) if possible

### Phase 2: Java FFM bindings
1. Add PlonK methods to `GnarkLibrary.java` (FFM downcall handles)
2. Add `GnarkPlonKProver` implementing the prover interface
3. Add PlonK proof/VK parsing to `zeroj-codec`

### Phase 3: Verifier backend
1. Implement `PlonKBLS12381Verifier` (off-chain, via blst)
2. Register via ServiceLoader as `ZkVerifier` implementation
3. PlonK proofs route through existing `VerifierOrchestrator`

### Phase 4: On-chain verifier (zeroj-examples)
1. Implement `PlonKBLS12381OnChainVerifier.java` as a Julc spending validator
2. UPLC unit tests with real gnark-generated PlonK proofs
3. E2E test on Cardano preprod

### Phase 5: Integration
1. Update patterns (StateTransition, NullifierClaim, Membership) — no changes needed, they're proof-system-agnostic
2. Update Yaci pipeline — no changes needed, it uses `VerifierOrchestrator`
3. Add PlonK examples to `zeroj-examples`

## Consequences

### Positive
- Developers can change circuits without running new trusted setup ceremonies
- Same gnark Go library, same FFM integration, same Java API
- Universal SRS is updatable — stronger security model than per-circuit Groth16 setup
- BLS12-381 PlonK proofs are verifiable on Cardano using existing Plutus V3 builtins
- Proof-system-agnostic architecture means patterns, pipeline, and anchoring work unchanged

### Negative
- PlonK proofs are ~3.5x larger than Groth16 (656 vs 192 bytes)
- PlonK verification is more expensive on-chain (more scalar multiplications)
- SRS must be distributed (shared artifact, ~MB-GB depending on max circuit size)
- gnark Go wrapper increases in complexity (more exported functions)

### Risks
- gnark Go runtime crash (exit code 134) in current FFM integration — may affect PlonK too
- CIP-0133 (MSM builtins) not yet enacted — on-chain PlonK verification may exceed budget without it
- gnark PlonK proof format differs from snarkjs PlonK — codec needs to handle both

## References

- [gnark PlonK documentation](https://docs.gnark.consensys.io/Concepts/schemes_curves)
- [CIP-0381: BLS12-381 Plutus builtins](https://cips.cardano.org/cip/CIP-0381)
- [CIP-0133: Multi-Scalar Multiplication](https://cips.cardano.org/cip/CIP-0133)
- [PlonK paper (Gabizon, Williamson, Ciobotaru 2019)](https://eprint.iacr.org/2019/953)
- [plutus-plonk-example (Cardano)](https://github.com/perturbing/plutus-plonk-example)
