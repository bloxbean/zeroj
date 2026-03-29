# zeroj-onchain-experimental

Java-side helpers for on-chain ZK proof verification on Cardano.

This module provides utilities for preparing proofs and verification keys for submission to Plutus scripts, estimating script execution budgets, and evaluating feasibility of different proof system / curve combinations on-chain.

> **Note:** Reusable Plutus V3 on-chain verifiers (Groth16 + PlonK) live in [`zeroj-onchain-julc`](../../zeroj-onchain-julc/). This module provides the Java-side data preparation and budget estimation only.

## Key Classes

| Class | Purpose |
|-------|---------|
| `OnChainProofPreparer` | Converts `ZkProofEnvelope` → Plutus redeemer format (G1/G2 point byte arrays) |
| `OnChainVkPreparer` | Compresses VK for on-chain use, computes VK hash for commitment patterns |
| `ScriptBudgetEstimator` | Estimates CPU/memory costs based on Plutus V3 BLS12-381 builtin costs (CIP-0381) |
| `OnChainFeasibility` | Structured feasibility matrix — which systems work on-chain and at what cost |
| `ReferenceScriptDeployer` | CIP-0033 reference script deployment patterns and configuration |

## Feasibility Matrix

| System | Curve | Status | Est. CPU Budget |
|--------|-------|--------|-----------------|
| Groth16 | BLS12-381 | **Working** | ~2.0B (1 public input) |
| PlonK | BLS12-381 | Experimental | ~2.0B+ (with MSM) |
| Halo2 KZG | BLS12-381 | Assessment only | Very high |
| Groth16/PlonK | BN254 | Not feasible | No BN254 builtins |

```java
// Check feasibility
boolean feasible = OnChainFeasibility.isFeasible(ProofSystemId.GROTH16, CurveId.BLS12_381);

// Estimate budget
long cpu = ScriptBudgetEstimator.estimateCpu(ProofSystemId.GROTH16, CurveId.BLS12_381, 1);

// Prepare proof for on-chain submission
List<byte[]> redeemerElements = OnChainProofPreparer.prepareGroth16BLS12381Redeemer(envelope);
List<BigInteger> publicInputs = OnChainProofPreparer.preparePublicInputs(envelope);
```

## Reference Script Patterns

| Pattern | Description | Trade-off |
|---------|-------------|-----------|
| VK-in-script | VK baked into script at deploy | Simple, larger script |
| Reference script + datum VK | Logic as CIP-0033, VK in datum | Small script, VK rotatable |
| VK hash commitment | Script has hash, full VK in redeemer | Smallest script, VK in redeemer |

```java
// Configure deployment
var config = ReferenceScriptDeployer.DeploymentConfig.referenceWithDatumVk(scriptBytes, vkBytes);
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-onchain-experimental'
}
```
