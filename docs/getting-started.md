# Getting Started -- Java DSL to On-Chain Verification

This guide walks through the complete ZeroJ flow: define a ZK circuit in Java, generate a proof, verify it off-chain, and execute on-chain verification on Cardano via Yaci DevKit.

We'll build a **sealed-bid auction** where a bidder proves their bid exceeds a reserve price without revealing the actual bid amount.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Java | 25+ (GraalVM) | `sdk use java 25.0.2-graal` |
| Yaci DevKit | latest | Local Cardano devnet (only for on-chain steps) |

### Building the gnark native prover (optional)

The gnark native library is only needed if you want to generate proofs using the in-process gnark FFM prover (Steps 3+). Circuit definition, R1CS compilation, witness calculation, and off-chain verification are all **pure Java** with no native dependencies.

If you want to use the gnark prover, you need **Go 1.21+** to build the native library once:

```bash
cd zeroj-prover-gnark/gnark-wrapper && make build
```

Start Yaci DevKit (only for on-chain Steps 5-7):
```bash
yaci-cli:default> create-node -o --start
```

## Step 1: Define the Circuit (Java DSL)

The circuit proves: "I know a bid amount and salt such that `MiMC(bidAmount, salt) == commitment` and `bidAmount >= reservePrice`."

```java
// SealedBidCircuit.java
public class SealedBidCircuit implements CircuitSpec {

    public static CircuitBuilder build() {
        return CircuitBuilder.create("sealed-bid", new SealedBidCircuit());
    }

    @Override
    public void define(CircuitBuilder builder) {
        builder
            .secretVar("bidAmount")
            .secretVar("salt")
            .publicVar("reservePrice")
            .publicVar("bidCommitment")    // output
            .publicVar("isAboveReserve")   // output
            .define(api -> {
                // 1. Prove knowledge of commitment
                var hash = MiMC.hash(api, api.var("bidAmount"), api.var("salt"));
                api.assertEqual(hash, api.var("bidCommitment"));

                // 2. Prove bid >= reserve
                var result = Comparators.greaterOrEqual(
                    api, api.var("bidAmount"), api.var("reservePrice"), 64);
                api.assertEqual(result, api.var("isAboveReserve"));
            });
    }
}
```

Key points:
- `secretVar` -- only the prover knows these (bid amount, salt)
- `publicVar` -- visible to the verifier (reserve price, commitment, result)
- `MiMC.hash` and `Comparators.greaterOrEqual` are from `zeroj-circuit-lib`

## Step 2: Compile and Calculate Witness (Pure Java)

```java
var circuit = SealedBidCircuit.build();

// Compile circuit to R1CS (Groth16 constraint system)
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
byte[] r1csBytes = R1CSSerializer.serialize(r1cs);

// Calculate witness with concrete inputs
BigInteger bidAmount = BigInteger.valueOf(1000);
BigInteger salt = BigInteger.valueOf(42);
BigInteger reservePrice = BigInteger.valueOf(500);
BigInteger commitment = MiMCHash.hash(bidAmount, salt, BLS12_381_PRIME);

var witness = circuit.calculateWitness(Map.of(
    "bidAmount",       List.of(bidAmount),
    "salt",            List.of(salt),
    "reservePrice",    List.of(reservePrice),
    "bidCommitment",   List.of(commitment),
    "isAboveReserve",  List.of(BigInteger.ONE)  // bid 1000 >= reserve 500
), CurveId.BLS12_381);

byte[] wtnsBytes = WitnessExporter.toWtns(witness, r1cs.prime(), r1cs.fieldConfig().n32());
```

This is all pure Java -- no external tools needed.

## Step 3: Generate Proof (gnark FFM)

```java
try (var prover = new GnarkProver()) {
    var result = prover.groth16FullProve(r1csBytes, wtnsBytes, "bls12381");

    String proofJson  = result.proveResponse().proofJson();
    String vkJson     = result.vkJson();
    String publicJson = result.proveResponse().publicInputsJson();
}
```

This runs gnark **inside the JVM** via Foreign Function & Memory API -- no external CLI, no Node.js.

## Step 4: Verify Off-Chain (Pure Java)

```java
// Parse proof artifacts
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
    proofJson, vkJson, publicJson, new CircuitId("sealed-bid"));

// Verify -- pure Java, zero native dependencies
var verifier = new Groth16BLS12381PureJavaVerifier();
var material = VerificationMaterial.of(vkBytes,
    ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("sealed-bid"));
var result = verifier.verify(envelope, material);

assert result.proofValid();  // cryptographic proof is valid
```

## Step 5: Deploy On-Chain Verifier (Julc / Plutus V3)

ZeroJ includes reusable Plutus V3 validators compiled from Java via Julc. The VK is baked into the script at deploy time:

```java
// Parse VK for on-chain parameters
var vkCompressed = SnarkjsToCardano.parseVk(vkJson);

// Compile Julc validator with VK parameters
var script = JulcScriptLoader.load(Groth16BLS12381Verifier.class,
    new BytesPlutusData(reservePriceBytes),
    new BytesPlutusData(vkCompressed.alpha()),   // VK alpha (G1, 48 bytes)
    new BytesPlutusData(vkCompressed.beta()),    // VK beta  (G2, 96 bytes)
    new BytesPlutusData(vkCompressed.gamma()),   // VK gamma (G2, 96 bytes)
    new BytesPlutusData(vkCompressed.delta()),   // VK delta (G2, 96 bytes)
    new BytesPlutusData(vkCompressed.ic(0)),     // IC[0] (G1, 48 bytes)
    new BytesPlutusData(vkCompressed.ic(1)),     // IC[1] (G1, 48 bytes)
    new BytesPlutusData(vkCompressed.ic(2))      // IC[2] (G1, 48 bytes)
);

var scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet());
```

## Step 6: Lock Funds with Public Inputs as Datum

```java
// Datum = public inputs that the on-chain verifier checks
var datum = ListPlutusData.of(
    BigIntPlutusData.of(bidCommitment),
    BigIntPlutusData.of(reservePrice)
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
        new BytesPlutusData(proof.piA()),   // G1 compressed (48 bytes)
        new BytesPlutusData(proof.piB()),   // G2 compressed (96 bytes)
        new BytesPlutusData(proof.piC())    // G1 compressed (48 bytes)
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

1. **Extract** public inputs from datum: `[bidCommitment, reservePrice]`
2. **Check** reserve price matches the parameter baked at deploy
3. **Decompress** proof points (piA, piB, piC) from BLS12-381 compressed bytes
4. **Compute** `vk_x = ic[0] + pub[0] * ic[1] + pub[1] * ic[2]` (linear combination)
5. **Verify** pairing equation: `e(piA, piB) == e(alpha, beta) * e(vk_x, gamma) * e(piC, delta)`
6. Return `True` if pairing check passes -- UTXO unlocked

## End-to-End Flow Summary

```
SealedBidCircuit.java     (define in Java DSL)
        |
   compileR1CS()          (pure Java → R1CS binary)
        |
   calculateWitness()     (pure Java → BigInteger[])
        |
   gnark FFM prove        (in-process → proofJson, vkJson)
        |
   Java verify            (pure Java → VerificationResult)
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
# Off-chain: DSL circuit → snarkjs/gnark prove → Java verify
./gradlew :zeroj-examples:test

# On-chain: full flow on Yaci DevKit (requires running Yaci)
./gradlew :zeroj-examples:e2eTest
```

### Available Examples

| Example | Circuit | Prove | Verify | On-Chain |
|---------|---------|-------|--------|----------|
| `SealedBidE2ETest` | Sealed bid auction | snarkjs | Pure Java | No |
| `SealedBidGnarkE2ETest` | Sealed bid auction | gnark FFM | Pure Java | No |
| `SealedBidOnChainE2ETest` | Sealed bid auction | Pre-generated | Julc/Plutus V3 | Yes (Yaci) |
| `AnonymousVotingE2ETest` | Anonymous voting | snarkjs | Pure Java | No |
| `BalanceThresholdE2ETest` | Balance threshold | snarkjs | Pure Java | No |

### Example Circuits

- **Sealed Bid Auction** -- prove bid >= reserve without revealing bid amount
- **Anonymous Voting** -- prove vote is 0/1 with MiMC commitment (double-vote prevention via nullifier)
- **Balance Threshold** -- prove balance >= threshold without revealing exact balance

See the [examples README](../zeroj-examples/README.md) for detailed descriptions of each flow.

## Prover Options

| Prover | Proof System | Curve | External Deps | Speed |
|--------|-------------|-------|---------------|-------|
| **gnark FFM** | Groth16 + PlonK | BLS12-381, BN254 | gnark native lib | ~50-300ms |
| **snarkjs CLI** | Groth16 + PlonK | BLS12-381, BN254 | Node.js + snarkjs | Minutes |
| **rapidsnark** | Groth16 | BN254 only | rapidsnark native lib | ~10-50ms |

gnark FFM is the recommended prover for production use -- everything runs in-process.

## Curves and On-Chain Feasibility

| Curve | Off-Chain | On-Chain (Plutus V3) | Notes |
|-------|-----------|---------------------|-------|
| BLS12-381 | Full support | Full support | Plutus V3 has native BLS builtins |
| BN254 | Full support | Not feasible | No Plutus BN254 builtins |
| Pallas | Halo2 only (incubator) | Not feasible | No Plutus Pallas builtins |

For on-chain verification, always use **BLS12-381**.
