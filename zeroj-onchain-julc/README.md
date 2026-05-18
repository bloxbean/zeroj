# zeroj-onchain-julc

Reusable Julc validators and on-chain helpers for Cardano Plutus V3 proof
verification.

This module is the Cardano on-chain verification layer for ZeroJ. It contains
Julc-compiled spending validators, proof/VK conversion helpers, and feasibility
tools for estimating whether a proof system and curve are practical on Plutus
V3.

## Current Status

| Validator / Helper | Status | Notes |
|--------------------|--------|-------|
| `Groth16BLS12381GenericVerifier` | Working | Default BLS12-381 Groth16 verifier using Plutus V3 BLS builtins; supports arbitrary public-input counts |
| `Groth16BLS12381Verifier` | Deprecated compatibility | Fixed two-public-input verifier retained for older callers |
| `PlonkBLS12381FullVerifier` | Experimental prototype | Re-derives transcript and checks inverse constraints; KZG batch opening pairing check is deferred |
| `SnarkjsToCardano` | Working helper | Converts snarkjs Groth16 JSON points to Cardano-compatible compressed bytes |
| `ProverToCardano` | Working helper | Converts ZeroJ prover artifacts to on-chain data shapes |
| `ScriptBudgetEstimator` | Planning helper | Estimates Plutus CPU/memory budgets for supported combinations |
| `OnChainFeasibility` | Planning helper | Matrix for proof system / curve support on Cardano |
| `ReferenceScriptDeployer` | Config helper | Describes CIP-0033 reference-script deployment patterns; does not submit transactions |

## Why It Is Useful

- Bridges ZeroJ off-chain proof generation with Cardano on-chain verification.
- Keeps Groth16 BLS12-381 as the reliable Plutus V3 path.
- Makes PlonK status explicit and measurable without overstating production
  readiness.
- Provides budget and deployment metadata for applications using CCL or other
  Cardano transaction builders.

## Testing

```bash
./gradlew :zeroj-onchain-julc:test
```

The tests run validators in the Julc VM and include Groth16 positive/negative
checks, pure Java Groth16 prover to on-chain verification, budget estimation, and
the PlonK prototype transcript/inverse-check path.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-onchain-julc'
}
```
