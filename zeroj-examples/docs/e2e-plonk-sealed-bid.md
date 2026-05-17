# E2E: Sealed-Bid Auction (Java DSL → PlonK → Cardano)

## Overview

Same circuit as the [Groth16 guide](e2e-groth16-sealed-bid.md), but using **PlonK** instead of Groth16.

### Groth16 vs PlonK

| | Groth16 | PlonK |
|---|---|---|
| **Setup** | Phase 1 (universal) + Phase 2 (circuit-specific) | Phase 1 only (truly universal) |
| **Proof size** | 3 group elements (~192 bytes for BLS12-381) | Larger (~580 bytes for BLS12-381) |
| **Verification** | Fastest (4 pairings) | Slower (2 pairings + more scalar muls) |
| **Trust** | Circuit-specific ceremony needed | Universal ceremony — one for all circuits |
| **gnark support** | `GnarkProver.groth16FullProve()` | `GnarkProver.plonkFullProve()` |

**PlonK advantage:** No circuit-specific Phase 2 ceremony. If you change your circuit, you don't need a new trusted setup — just re-run with the same universal SRS.

## Step-by-Step

### 1-3. Same as Groth16

Circuit definition, R1CS compilation, and witness calculation are identical. The circuit DSL is proof-system-agnostic.

### 4. Setup + Prove (gnark FFM — in-process)

```java
try (var prover = new GnarkProver()) {
    // Single call: universal setup + prove (no Phase 2 ceremony!)
    var result = prover.plonkFullProve(r1cs, witness, CurveId.BLS12_381);
    // result.proveResponse() → proof + public signals
    // result.vkJson() → verification key
}
```

Or use the helper:
```java
try (var prover = new GnarkProver()) {
    var result = GnarkProverHelper.plonkProve(
            SealedBidCircuit.build(), inputs, CurveId.BLS12_381, prover);
}
```

### 5. Verify off-chain

```java
// gnark binary PlonK proof JSON should be verified with gnark today.
boolean ok = prover.plonkVerify("bls12381", vkPath, proofBase64, publicWitnessPath);
assert ok;
```

The pure Java `PlonkBLS12381Verifier` consumes structured snarkjs/ZeroJ PlonK
proof JSON. A dedicated adapter is still needed before gnark's opaque binary
PlonK JSON can be routed through that verifier.

### 6. On-chain verification

The `PlonkBLS12381FullVerifier` in `zeroj-onchain-julc` is currently an experimental on-chain prototype. It validates the Fiat-Shamir transcript and inverse checks, but the KZG batch opening pairing check is still deferred, so it is not yet a full trustless on-chain PlonK verifier.

## Running the Tests

```bash
# PlonK E2E test (gnark FFM — no snarkjs needed)
./gradlew :zeroj-examples:test --tests "*SealedBidGnarkE2ETest.plonk*"
```
