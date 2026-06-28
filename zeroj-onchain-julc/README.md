# zeroj-onchain-julc

Reusable Julc validators and on-chain helpers for Cardano Plutus V3 proof
verification.

This module is the Cardano on-chain verification layer for ZeroJ. It contains
Julc-compiled spending validators, proof/VK conversion helpers, and feasibility
tools for estimating whether a proof system and curve are practical on Plutus
V3.

## Current Status

| Package | Contents | Status | Notes |
|---------|----------|--------|-------|
| `com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator` | `Groth16BLS12381Verifier` | Working validator | Default BLS12-381 Groth16 spending validator using Plutus V3 BLS builtins; supports arbitrary public-input counts |
| `com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib` | `Groth16BLS12381Lib` | Working on-chain library | Reusable `@OnchainLibrary` proof verification helper for custom validators |
| `com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec` | `SnarkjsToCardano`, `ProverToCardano` | Working off-chain helpers | Convert snarkjs and ZeroJ Groth16 artifacts to Cardano-compatible compressed bytes and Plutus data shapes |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator` | `PlonkBLS12381Verifier` | Experimental opt-in validator | Cardano-profile compressed-transcript verifier with full KZG batch-opening pairing check for the current one-public-input shape; third-party audit still pending |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator` | `PlonkBLS12381MultiInputVerifier` | Experimental opt-in validator | Bounded MPI Cardano profile verifier for `1..8` datum-supplied public inputs with profile/count transcript binding and verified inverse witnesses; third-party audit still pending |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator` | `PlonkBLS12381MultiInputParamVerifier` | Experimental opt-in validator | Bounded MPI Cardano profile verifier for `1..8` script-parameter public inputs; use when statement values should be pinned by the script hash |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator` | `PlonkBLS12381TranscriptPrototype` | Prototype only | gnark transcript/inverse regression fixture; must not secure value |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec` | `PlonKProverToCardano` | Working off-chain helper | Converts ZeroJ BLS12-381 PlonK proofs/VKs to compressed Cardano redeemer/parameter bytes |
| `com.bloxbean.cardano.zeroj.onchain.julc.analysis` | `ScriptBudgetEstimator`, `OnChainFeasibility` | Planning helpers | Estimate Plutus CPU/memory budgets and report proof system / curve feasibility |
| `com.bloxbean.cardano.zeroj.onchain.julc.deployment` | `ReferenceScriptDeployer` | Config helper | Describes CIP-0033 reference-script deployment patterns; does not submit transactions |

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
checks, pure Java Groth16 prover to on-chain verification, budget estimation, the
PlonK prototype transcript/inverse-check path, and the full Cardano-profile
PlonK verifier positive/negative/budget gates, including the bounded MPI profile
for 1, 2, 4, and 8 public inputs and the script-parameter MPI variant.

## Imports

Use package names by role:

```java
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator.Groth16BLS12381Verifier;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
```

Custom validators should define their own local redeemer record and compose the
shared library:

```java
@SpendingValidator
public class MyVerifier {
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        return Groth16BLS12381Lib.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }
}
```

The proof record is kept validator-local because Julc record decoding is
validator-local today. Sharing `Groth16BLS12381Lib` still avoids duplicating the
pairing and public-input folding logic.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-onchain-julc'
}
```
