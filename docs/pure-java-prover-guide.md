# Pure Java Prover — Circuit to On-Chain Verification

Zero external tools. 100% Java 25. Prove ZK circuits and verify on Cardano.

## Table of Contents

- [Overview](#overview)
- [Quick Start — 5 Minutes to Your First Proof](#quick-start--5-minutes-to-your-first-proof)
- [Complete End-to-End: Circuit → Prove → On-Chain Verify](#complete-end-to-end-circuit--prove--on-chain-verify)
- [PlonK Prover (Pure Java)](#plonk-prover-pure-java)
- [Circom Compatibility](#circom-compatibility)
- [Production vs Development Setup](#production-vs-development-setup)
- [End-to-End Flow Diagram](#end-to-end-flow-diagram)
- [Module Dependencies](#module-dependencies)
- [Running the Examples](#running-the-examples)

---

## Overview

The zeroj pure Java prover generates Groth16 and PlonK proofs for BLS12-381 without any native dependencies — no gnark, no snarkjs, no circom, no Go, no Node.js, no Rust.

```
Java Circuit → compileR1CS(BLS12_381) → Groth16ProverBLS381.prove() → on-chain verify ✓
```

| Proof System | Curve | Module | Status |
|-------------|-------|--------|--------|
| Groth16 | BLS12-381 | `zeroj-crypto` | Production-ready |
| PlonK | BLS12-381 | `zeroj-crypto` | Production-ready |
| Groth16 | BN254 | `zeroj-crypto` | Production-ready (off-chain only) |
| PlonK | BN254 | `zeroj-crypto` | Production-ready (off-chain only) |

For on-chain Cardano verification, use **BLS12-381** (Plutus V3 has native BLS builtins).

## Quick Start — 5 Minutes to Your First Proof

### 1. Add Dependencies

```gradle
implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'
implementation 'com.bloxbean.cardano:zeroj-circuit-lib'
implementation 'com.bloxbean.cardano:zeroj-crypto'
```

### 2. Define a Circuit

```java
import com.bloxbean.cardano.zeroj.circuit.*;
import com.bloxbean.cardano.zeroj.circuit.lib.*;

public class SecretMultiplierCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal a = c.publicInput("a");      // public: known factor
        Signal b = c.privateInput("b");     // secret: hidden factor
        Signal product = c.publicOutput("product"); // public: result

        c.assertEqual(a.mul(b), product);   // a * b == product
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("secret-multiplier")
                .publicVar("a")
                .publicVar("product")
                .secretVar("b")
                .defineSignals(new SecretMultiplierCircuit());
    }
}
```

### 3. Prove and Verify (Pure Java)

```java
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.crypto.groth16.*;
import com.bloxbean.cardano.zeroj.crypto.setup.*;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field.*;

// Compile circuit
var circuit = SecretMultiplierCircuit.build();
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
var constraints = r1cs.constraints().stream()
    .map(c -> new Groth16Prover.R1CSConstraint(c.a(), c.b(), c.c()))
    .toArray(Groth16Prover.R1CSConstraint[]::new);

// Compute witness: a=3, b=11 (secret), product=33
BigInteger[] witness = circuit.calculateWitness(Map.of(
    "a", List.of(BigInteger.valueOf(3)),
    "b", List.of(BigInteger.valueOf(11)),
    "product", List.of(BigInteger.valueOf(33))
), CurveId.BLS12_381);

// Trusted setup (DEVELOPMENT ONLY — see "Production Setup" below)
var srs = PowersOfTauBLS381.generate(4);
var setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
    r1cs.numPublicInputs(), srs.tauScalar());

// PROVE — pure Java, zero native dependencies
var proof = Groth16ProverBLS381.prove(setup.provingKey(), witness,
    constraints, r1cs.numWires());

// proof.a() ∈ G1, proof.b() ∈ G2, proof.c() ∈ G1
System.out.println("Proof generated! A on curve: " + proof.a().isOnCurve());
```

That's it. No external tools installed, no build steps, no CLI.

## Complete End-to-End: Circuit → Prove → On-Chain Verify

### Step 1: Define the Circuit (CircuitSpec)

See the [Circuit DSL Guide](circuit-dsl-user-guide.md) for the full API. The recommended pattern is a class implementing `CircuitSpec`:

```java
public class BalanceProofCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal balance   = c.privateInput("balance");
        Signal threshold = c.publicInput("threshold");
        Signal isAbove   = c.publicOutput("isAbove");

        c.assertEqual(
            SignalComparators.greaterOrEqual(c, balance, threshold, 64),
            isAbove);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("balance-proof")
                .publicVar("threshold")
                .publicVar("isAbove")
                .secretVar("balance")
                .defineSignals(new BalanceProofCircuit());
    }
}
```

### Step 2: Compile and Generate Witness

```java
var circuit = BalanceProofCircuit.build();
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

System.out.println("Constraints: " + r1cs.numConstraints());
System.out.println("Public inputs: " + r1cs.numPublicInputs());

// Witness: balance=1000 (secret), threshold=500 (public), isAbove=1 (public)
BigInteger[] witness = circuit.calculateWitness(Map.of(
    "balance", List.of(BigInteger.valueOf(1000)),
    "threshold", List.of(BigInteger.valueOf(500)),
    "isAbove", List.of(BigInteger.ONE)
), CurveId.BLS12_381);
```

### Step 3: Trusted Setup

**For development/testing — single-party setup (pure Java):**

```java
// WARNING: Single-party setup. Toxic waste is known. DO NOT use for production.
var srs = PowersOfTauBLS381.generate(8);  // 2^8 = 256 constraints max
var setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
    r1cs.numPublicInputs(), srs.tauScalar());
var pk = setup.provingKey();
```

**For production — import snarkjs .zkey from MPC ceremony:**

```java
// Import .zkey generated by snarkjs multi-party ceremony
var zkeyData = ZkeyImporterBLS381.importZkeyFull(
    Files.readAllBytes(Path.of("circuit.zkey")));
var pk = zkeyData.provingKey();
var constraints = zkeyData.constraints();
```

How to generate the .zkey:
```bash
# 1. Export R1CS from Java DSL (or use circom)
# 2. Use a well-known Powers of Tau (e.g., Hermez, PPOT)
snarkjs groth16 setup circuit.r1cs hermez_pot20.ptau circuit.zkey
# 3. Contribute to Phase 2 ceremony
snarkjs zkey contribute circuit.zkey circuit_final.zkey --name="contributor"
```

### Step 4: Prove (Pure Java)

```java
var proof = Groth16ProverBLS381.prove(pk, witness, constraints, r1cs.numWires());

assert proof.a().isOnCurve();  // Proof A ∈ BLS12-381 G1
assert proof.b().isOnCurve();  // Proof B ∈ BLS12-381 G2
assert proof.c().isOnCurve();  // Proof C ∈ BLS12-381 G1
```

### Step 5: Verify Off-Chain (Pure Java)

```java
// Build VK accumulator: vk_x = IC[0] + pub[0]*IC[1] + pub[1]*IC[2]
var ic = setup.ic();
var pubInputs = new BigInteger[]{witness[1], witness[2]};  // public inputs

G1Point vkX = toG1(ic[0]);
for (int i = 0; i < pubInputs.length; i++) {
    vkX = vkX.add(toG1(ic[i + 1]).scalarMul(pubInputs[i]));
}

// Groth16 pairing check: e(A,B) * e(-α,β) * e(-vk_x,γ) * e(-C,δ) == 1
boolean valid = BLS12381Pairing.pairingCheck(
    new G1Point[]{toG1(proof.a()), toG1(pk.alphaG1()).negate(),
                  vkX.negate(), toG1(proof.c()).negate()},
    new G2Point[]{toG2(proof.b()), toG2(pk.betaG2()),
                  toG2(setup.gammaG2()), toG2(pk.deltaG2())});

assert valid;  // Cryptographic verification passed!
```

### Step 6: Verify On-Chain (Cardano Plutus V3)

```java
// Compress proof + VK for on-chain BLS format
var compressedVk = ProverToCardano.compressVk(setup);
var compressedProof = ProverToCardano.compressProof(proof);

// Load the generic Groth16 BLS12-381 verifier with VK baked in
var script = JulcScriptLoader.load(Groth16BLS12381Verifier.class,
    new BytesPlutusData(compressedVk.alpha()),
    new BytesPlutusData(compressedVk.beta()),
    new BytesPlutusData(compressedVk.gamma()),
    new BytesPlutusData(compressedVk.delta()),
    new BytesPlutusData(compressedVk.ic().get(0)),
    new BytesPlutusData(compressedVk.ic().get(1)),
    new BytesPlutusData(compressedVk.ic().get(2)));

var scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet());

// Lock ADA with public inputs as datum
var datum = ListPlutusData.of(
    BigIntPlutusData.of(pubInputs[0]),    // threshold
    BigIntPlutusData.of(pubInputs[1]));   // isAbove

var lockTx = new Tx()
    .payToContract(scriptAddr, Amount.ada(5), datum)
    .from(sender.baseAddress());

// Unlock with ZK proof as redeemer
var redeemer = ConstrPlutusData.builder()
    .alternative(0)
    .data(ListPlutusData.of(
        new BytesPlutusData(compressedProof.piA()),
        new BytesPlutusData(compressedProof.piB()),
        new BytesPlutusData(compressedProof.piC())))
    .build();

var unlockTx = new ScriptTx()
    .collectFrom(scriptUtxo, redeemer)
    .payToAddress(sender.baseAddress(), Amount.ada(4.5))
    .attachSpendingValidator(script);

// Transaction succeeds = proof verified on Cardano!
```

## PlonK Prover (Pure Java)

The PlonK prover follows the same pattern but uses `PlonKProverBLS381`:

```java
// Compile to PlonK
var plonk = circuit.compilePlonK(CurveId.BLS12_381);

// Setup (development)
var srs = PowersOfTauBLS381.generate(8);
var pk = PlonKSetupBLS381.setup(numGates, numPublic, gateSelectors,
    sigmaA, sigmaB, sigmaC, numWires, srs);

// Prove
var proof = PlonKProverBLS381.prove(pk, wireA, wireB, wireC, pubInputs);
// proof has 9 commitments + 6 evaluations (snarkjs-compatible format)
```

See `PlonKBLS381EndToEndTest.java` for a complete working example.

## Circom Compatibility

Circuits written in **circom** work with the pure Java prover. The flow:

```bash
# 1. Compile circom circuit
circom circuit.circom --r1cs --wasm --sym -p bls12381

# 2. Generate .zkey via snarkjs
snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit.zkey

# 3. Generate witness
node circuit_js/generate_witness.js circuit.wasm input.json witness.wtns
```

```java
// 4. Import .zkey and .wtns into Java
var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(Path.of("circuit.zkey")));
var witness = ZkeyImporterBLS381.importWtns(new FileInputStream("witness.wtns"));

// 5. Prove with pure Java prover
var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness,
    zkeyData.constraints(), zkeyData.numWires());

// 6. Verify on-chain (same as above)
```

## Production vs Development Setup

| | Development | Production |
|---|---|---|
| **Powers of Tau** | `PowersOfTauBLS381.generate(n)` | Import .ptau from MPC ceremony (Hermez, PPOT) |
| **Phase 2 Setup** | `Groth16SetupBLS381.setup(...)` | `snarkjs groth16 setup` with multi-party ceremony |
| **Importing** | Use `srs.tauScalar()` directly | Use `ZkeyImporterBLS381.importZkeyFull(...)` |
| **Trust** | Single party (toxic waste known) | Multi-party (trust distributed) |
| **Use for** | Testing, development, CI | Mainnet deployment |

**Never deploy single-party setup to production.** The generator knows the toxic waste and could forge proofs.

## End-to-End Flow Diagram

```
                        CIRCUIT DEFINITION
                               │
        ┌──────────────────────┤
        │                      │
  Java CircuitSpec        circom (.circom)
        │                      │
  compileR1CS(BLS12_381)   circom compiler
        │                      │
        │               snarkjs setup
        │                      │
        ▼                      ▼
   R1CS constraints      .zkey binary
        │                      │
        │            ZkeyImporterBLS381
        │                      │
        └──────────┬───────────┘
                   │
                   ▼
         ┌─────────────────┐
         │ Groth16Prover   │  ◄── witness (BigInteger[])
         │   BLS381        │
         └────────┬────────┘
                  │
                  ▼
         Groth16ProofBLS381
          (A ∈ G1, B ∈ G2, C ∈ G1)
                  │
        ┌─────────┴─────────┐
        │                   │
   Off-chain verify    On-chain verify
   (BLS12381Pairing)   (Plutus V3 script)
        │                   │
        ▼                   ▼
     boolean            Transaction
     (valid?)           (succeeds = verified!)
```

## Module Dependencies

```gradle
// Circuit definition + standard library
implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'
implementation 'com.bloxbean.cardano:zeroj-circuit-lib'

// Pure Java prover (BN254 + BLS12-381, Groth16 + PlonK)
implementation 'com.bloxbean.cardano:zeroj-crypto'

// Off-chain verification (pure Java)
implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
implementation 'com.bloxbean.cardano:zeroj-verifier-plonk'

// On-chain verification (Cardano Plutus V3)
implementation 'com.bloxbean.cardano:zeroj-onchain-julc'

// Transaction building (for on-chain submission)
testImplementation 'com.bloxbean.cardano:cardano-client-lib'
```

## Running the Examples

```bash
# Unit tests (off-chain: circuit → prove → pairing verify)
./gradlew :zeroj-examples:test

# On-chain tests (requires Yaci DevKit running)
./gradlew :zeroj-examples:e2eTest

# Full crypto test suite (2680+ tests)
./gradlew :zeroj-crypto:test
```

### Pure Java Prover Examples

| Test | Circuit | What It Proves |
|------|---------|---------------|
| `SealedBidPureJavaE2ETest` | Sealed bid auction (497 constraints) | MiMC hash + range comparison |
| `AnonymousVotingPureJavaE2ETest` | Anonymous voting (367 constraints) | MiMC commitment + boolean |
| `BalanceThresholdPureJavaE2ETest` | Balance threshold (132 constraints) | Range comparison |
| `PureJavaProverYaciE2ETest` | Multiplier | **Full stack: prove → Yaci DevKit on-chain** |
| `Groth16BLS381ZkeyEndToEndTest` | Multiplier + Cubic | snarkjs .zkey import → Java prove → pairing verify |
| `CircomToOnChainE2ETest` | Circom multiplier | circom .zkey → Java prove → **on-chain Julc VM** |
| `ParameterizedCircuitE2ETest` | Hash chain, Merkle, multi-commit | Parameterized circuits (depth, arity, hash) |
