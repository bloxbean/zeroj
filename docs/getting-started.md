# Getting Started -- Java DSL to On-Chain Verification

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Define the Circuit (Java DSL)](#step-1-define-the-circuit-java-dsl)
- [Step 2: Compile and Calculate Witness (Pure Java)](#step-2-compile-and-calculate-witness-pure-java)
- [Step 3: Generate Proof (Pure Java)](#step-3-generate-proof-pure-java)
- [Step 4: Verify Off-Chain (Pure Java)](#step-4-verify-off-chain-pure-java)
- [Step 5: Deploy On-Chain Verifier (Julc / Plutus V3)](#step-5-deploy-on-chain-verifier-julc--plutus-v3)
- [Step 6: Lock Funds with Public Inputs as Datum](#step-6-lock-funds-with-public-inputs-as-datum)
- [Step 7: Unlock with ZK Proof as Redeemer](#step-7-unlock-with-zk-proof-as-redeemer)
- [What Happens On-Chain](#what-happens-on-chain)
- [End-to-End Flow Summary](#end-to-end-flow-summary)
- [Running the Examples](#running-the-examples)
- [Prover Options](#prover-options)
- [Curves and On-Chain Feasibility](#curves-and-on-chain-feasibility)

---

This guide walks through the complete ZeroJ flow: define a ZK circuit in Java, generate a proof, verify it off-chain, and execute on-chain verification on Cardano via Yaci DevKit.

We'll build a **private multiplier** circuit where the prover shows they know a secret factor `b` such that `a * b = c`, while `a` and `c` remain public. This small circuit matches the reusable Groth16 on-chain verifier, which currently accepts two public inputs.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Java | 25+ (GraalVM) | `sdk use java 25.0.2-graal` |
| Yaci DevKit | latest | Local Cardano devnet (only for on-chain steps) |

### Building the gnark native prover (optional)

The gnark native library is only needed if you want to generate proofs using the optional in-process gnark FFM prover. The main flow in this guide uses the pure Java prover.

If you want to use the gnark prover, you need **Go 1.21+** to build the native library once:

```bash
cd zeroj-prover-gnark/gnark-wrapper && make build
```

Start Yaci DevKit (only for on-chain Steps 5-7):
```bash
yaci-cli:default> create-node -o --start
```

## Step 1: Define the Circuit (Java DSL)

The circuit proves: "I know a secret `b` such that `a * b == c`."

```java
// PrivateMultiplierCircuit.java
public class PrivateMultiplierCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal a = c.publicInput("a");
        Signal b = c.privateInput("b");
        Signal cOut = c.publicOutput("c");
        c.assertEqual(a.mul(b), cOut);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("private-multiplier")
                .publicVar("a")
                .publicVar("c")
                .secretVar("b")
                .defineSignals(new PrivateMultiplierCircuit());
    }
}
```

Key points:
- `secretVar` -- only the prover knows this value (`b`)
- `publicVar` -- visible to the verifier (`a` and `c`)
- `CircuitSpec` keeps the circuit reusable and testable

## Step 2: Compile and Calculate Witness (Pure Java)

```java
var circuit = PrivateMultiplierCircuit.build();

// Compile circuit to R1CS (Groth16 constraint system)
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
// Calculate witness with concrete inputs
BigInteger a = BigInteger.valueOf(3);
BigInteger b = BigInteger.valueOf(11);
BigInteger c = BigInteger.valueOf(33);

var witness = circuit.calculateWitness(Map.of(
    "a", List.of(a),
    "b", List.of(b),
    "c", List.of(c)
), CurveId.BLS12_381);
```

This is all pure Java -- no external tools needed.

## Step 3: Generate Proof (Pure Java)

```java
var constraints = r1cs.constraints();

// Local test setup only: toxic waste is known.
var srs = PowersOfTauBLS381.generate(4);
var setupResult = Groth16SetupBLS381.setup(
        constraints, r1cs.numWires(), r1cs.numPublicInputs(), srs.tauScalar());

var proof = Groth16ProverBLS381.prove(
        setupResult.provingKey(), witness, constraints, r1cs.numWires());
```

For setup beyond local tests, import MPC-generated `.zkey` artifacts instead of using `PowersOfTauBLS381.generate(...)`.

## Step 4: Verify Off-Chain (Pure Java)

```java
BigInteger[] publicInputs = new BigInteger[r1cs.numPublicInputs()];
for (int i = 0; i < publicInputs.length; i++) {
    publicInputs[i] = witness[i + 1];
}

boolean ok = verifyGroth16Pairing(proof, setupResult, publicInputs);
assert ok;
```

The complete helper is shown in `PureJavaProverYaciE2ETest`; it computes the Groth16 `vk_x` linear combination and runs the BLS12-381 pairing equation.

## Step 5: Deploy On-Chain Verifier (Julc / Plutus V3)

ZeroJ includes reusable Plutus V3 validators compiled from Java via Julc. The VK is baked into the script at deploy time:

```java
// Compress proof + VK for on-chain BLS format
var compressedVk = ProverToCardano.compressVk(setupResult);
var compressedProof = ProverToCardano.compressProof(proof);

// Compile Julc validator with VK parameters
var script = JulcScriptLoader.load(Groth16BLS12381Verifier.class,
    new BytesPlutusData(compressedVk.alpha()),
    new BytesPlutusData(compressedVk.beta()),
    new BytesPlutusData(compressedVk.gamma()),
    new BytesPlutusData(compressedVk.delta()),
    new BytesPlutusData(compressedVk.ic().get(0)),
    new BytesPlutusData(compressedVk.ic().get(1)),
    new BytesPlutusData(compressedVk.ic().get(2))
);

var scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
```

## Step 6: Lock Funds with Public Inputs as Datum

```java
// Datum = public inputs that the on-chain verifier checks: [a, c]
var datum = ListPlutusData.of(
    BigIntPlutusData.of(a),
    BigIntPlutusData.of(c)
);

// Lock 5 ADA at the script address
var lockTx = new Tx()
    .payToContract(scriptAddr, Amount.ada(5), datum)
    .from(sender.baseAddress());

var lockResult = new QuickTxBuilder(backend)
    .compose(lockTx)
    .withSigner(SignerProviders.signerFrom(sender))
    .complete();
```

## Step 7: Unlock with ZK Proof as Redeemer

```java
// Redeemer = the Groth16 proof (piA, piB, piC compressed BLS points)
var redeemer = ConstrPlutusData.builder()
    .alternative(0)
    .data(ListPlutusData.of(
        new BytesPlutusData(compressedProof.piA()),
        new BytesPlutusData(compressedProof.piB()),
        new BytesPlutusData(compressedProof.piC())
    ))
    .build();

// Spend the script UTXO -- triggers on-chain ZK verification
var unlockTx = new ScriptTx()
    .collectFrom(scriptUtxo, redeemer)
    .payToAddress(sender.baseAddress(), Amount.ada(4.5))
    .attachSpendingValidator(script);

var unlockResult = new QuickTxBuilder(backend)
    .compose(unlockTx)
    .withSigner(SignerProviders.signerFrom(sender))
    .feePayer(sender.baseAddress())
    .collateralPayer(sender.baseAddress())
    .complete();

// Transaction succeeds = proof verified on-chain by Plutus V3!
```

## What Happens On-Chain

The `Groth16BLS12381Verifier` Plutus V3 script executes:

1. **Extract** public inputs from datum: `[a, c]`
2. **Decompress** proof points (piA, piB, piC) from BLS12-381 compressed bytes
3. **Compute** `vk_x = ic[0] + pub[0] * ic[1] + pub[1] * ic[2]` (linear combination)
4. **Verify** pairing equation: `e(piA, piB) == e(alpha, beta) * e(vk_x, gamma) * e(piC, delta)`
5. Return `True` if pairing check passes -- UTXO unlocked

## End-to-End Flow Summary

```
PrivateMultiplierCircuit.java (define in Java DSL)
        |
   compileR1CS()          (pure Java → R1CS binary)
        |
   calculateWitness()     (pure Java → BigInteger[])
        |
   pure Java prove        (Groth16ProverBLS381)
        |
   Java verify            (pure Java pairing check)
        |
   Julc compile           (VK baked → Plutus V3 script)
        |
   Lock ADA at script     (datum = public inputs)
        |
   Unlock with proof      (redeemer = piA, piB, piC)
        |
   Plutus V3 executes     (BLS12-381 pairing check)
        |
   Transaction succeeds   (proof verified on Cardano!)
```

## Running the Examples

The `zeroj-examples` module contains complete working examples:

```bash
# Off-chain: DSL circuit → prove → Java verify
./gradlew :zeroj-examples:test

# On-chain: full flow on Yaci DevKit (requires running Yaci)
./gradlew :zeroj-examples:e2eTest
```

### Available Examples

**Pure Java prover (zero external tools):**

| Example | Circuit | Prove | Verify | On-Chain |
|---------|---------|-------|--------|----------|
| `SealedBidPureJavaE2ETest` | Sealed bid (497 constraints) | Pure Java | Pairing | No |
| `AnonymousVotingPureJavaE2ETest` | Anonymous voting (367 constraints) | Pure Java | Pairing | No |
| `BalanceThresholdPureJavaE2ETest` | Balance threshold (132 constraints) | Pure Java | Pairing | No |
| `PureJavaProverYaciE2ETest` | Multiplier | Pure Java | **Yaci DevKit** | **Yes** |
| `CircomToOnChainE2ETest` | Circom multiplier | Pure Java | **Julc VM** | Yes |
| `ParameterizedCircuitE2ETest` | Hash chain, Merkle, multi-commit | Pure Java | Pairing | No |

**FFM/CLI provers (native dependencies):**

| Example | Circuit | Prove | Verify | On-Chain |
|---------|---------|-------|--------|----------|
| `SealedBidE2ETest` | Sealed bid auction | snarkjs | Pure Java | No |
| `SealedBidGnarkE2ETest` | Sealed bid auction | gnark FFM | Pure Java | No |
| `SealedBidOnChainE2ETest` | Sealed bid auction | Pre-generated | Julc/Plutus V3 | Yes (Yaci) |
| `AnonymousVotingE2ETest` | Anonymous voting | snarkjs | Pure Java | No |
| `BalanceThresholdE2ETest` | Balance threshold | snarkjs | Pure Java | No |

### Example Circuits

- **Sealed Bid Auction** -- prove bid >= reserve without revealing bid amount
- **Anonymous Voting** -- prove vote is 0/1 with a MiMC commitment in the
  BN254/off-chain reference flow. For Cardano/BLS12-381 circuits, use Poseidon
  with explicit BLS12-381 parameters.
- **Balance Threshold** -- prove balance >= threshold without revealing exact balance

See the [examples README](../zeroj-examples/README.md) for detailed descriptions of each flow.

## Prover Options

| Prover | Proof System | Curve | External Deps | Notes |
|--------|-------------|-------|---------------|-------|
| **Pure Java** | Groth16 + PlonK | BLS12-381, BN254 | **None** | Recommended default path |
| **gnark FFM** | Groth16 + PlonK | BLS12-381, BN254 | Go native lib | Optional native backend |
| **snarkjs CLI** | Groth16 + PlonK | BLS12-381, BN254 | Node.js + snarkjs | External CLI workflow |

**Pure Java** is the recommended prover for the core Cardano path -- zero native dependencies and covered by end-to-end on-chain tests. See the [Pure Java Prover Guide](pure-java-prover-guide.md) for the complete pipeline.

For native or CLI alternatives, see [Alternate Prover Backends](alternate-prover-backends.md).

## Curves and On-Chain Feasibility

| Curve | Off-Chain | On-Chain (Plutus V3) | Notes |
|-------|-----------|---------------------|-------|
| BLS12-381 | Groth16 + PlonK | Groth16 supported; PlonK prototype | Plutus V3 has native BLS builtins |
| BN254 | Groth16 + PlonK | Not feasible | No Plutus BN254 builtins |

For on-chain verification, always use **BLS12-381**.
