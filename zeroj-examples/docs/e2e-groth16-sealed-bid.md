# E2E: Sealed-Bid Auction (Java DSL → Groth16 → Cardano)

## Overview

This guide walks through the complete flow of proving a sealed bid is valid using zero-knowledge proofs, from circuit definition in Java to on-chain verification on Cardano.

**What is proved:** A bidder knows `bidAmount` and `salt` such that:
1. `MiMC(bidAmount, salt) == bidCommitment` (the bidder committed to this bid)
2. `bidAmount >= reservePrice` (the bid meets the minimum)

**What is NOT revealed:** The actual `bidAmount` and `salt` remain private.

## Prerequisites

- **Java 25** (GraalVM): `sdk use java 25.0.2-graal`
- **gnark native library**: bundled with `zeroj-prover-gnark` (no external tools needed)
- **Yaci DevKit**: for on-chain E2E tests (optional — tests skip gracefully without it)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Pure Java (no native deps)               │
│                                                                 │
│  SealedBidCircuit ──→ R1CSSerializer ──→ R1CS (in memory)      │
│  (CircuitSpec)         (iden3 format)                           │
│                                                                 │
│  WitnessCalculator ──→ witness array (BigInteger[])            │
│  (field arithmetic)                                             │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     gnark FFM (in-process via JVM FFI)          │
│                                                                 │
│  GnarkProver.groth16FullProve(r1cs, witness, curve)            │
│  → Trusted setup + Prove in a single call                      │
│  → Returns: proof, public signals, verification key             │
│  (No Node.js, no CLI, no temp files)                           │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Pure Java Verification                       │
│                                                                 │
│  Groth16BLS12381PureJavaVerifier.verify(envelope, material)    │
│  → BLS12-381 pairing check: e(A,B) · e(-α,β) · e(-vk_x,γ)    │
│    · e(-C,δ) == 1                                              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Cardano On-Chain (Yaci DevKit)                │
│                                                                 │
│  ZkAuctionVerifier (Julc Plutus V3 script)                     │
│  → VK points baked as @Param at deploy time                    │
│  → Lock tADA at script address with public inputs as datum     │
│  → Unlock with ZK proof as redeemer (BLS12-381 pairing check)  │
└─────────────────────────────────────────────────────────────────┘
```

## Step-by-Step

### 1. Define the circuit in Java

```java
public class SealedBidCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal bidAmount = c.privateInput("bidAmount");
        Signal salt = c.privateInput("salt");
        Signal reservePrice = c.publicInput("reservePrice");
        Signal bidCommitment = c.publicOutput("bidCommitment");
        Signal isAboveReserve = c.publicOutput("isAboveReserve");

        c.assertEqual(SignalMiMC.hash(c, bidAmount, salt), bidCommitment);
        c.assertEqual(SignalComparators.greaterOrEqual(c, bidAmount, reservePrice, 64),
                      isAboveReserve);
    }
}
```

### 2. Compile to R1CS (pure Java)

```java
var circuit = SealedBidCircuit.build();
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
```

### 3. Calculate witness (pure Java)

```java
BigInteger commitment = MiMCHash.hash(bidAmount, salt, FieldConfig.BLS12_381.prime());
BigInteger isAbove = bidAmount.compareTo(reservePrice) >= 0 ? ONE : ZERO;

BigInteger[] witness = circuit.calculateWitness(Map.of(
    "bidAmount",       List.of(bidAmount),
    "salt",            List.of(salt),
    "bidCommitment",   List.of(commitment),
    "reservePrice",    List.of(reservePrice),
    "isAboveReserve",  List.of(isAbove)
), CurveId.BLS12_381);
```

### 4. Generate proof (gnark FFM — in-process, no external tools)

```java
try (var prover = new GnarkProver()) {
    // Single call: trusted setup + prove
    var result = prover.groth16FullProve(r1cs, witness, CurveId.BLS12_381);
    // result.proveResponse() → proof JSON + public signals
    // result.vkJson() → verification key
}
```

Or use the helper for even simpler usage:
```java
try (var prover = new GnarkProver()) {
    var result = GnarkProverHelper.groth16Prove(
            SealedBidCircuit.build(), inputs, CurveId.BLS12_381, prover);
}
```

### 5. Verify off-chain (pure Java)

```java
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
    proof.proofJson(), proof.vkJson(), proof.publicJson(),
    new CircuitId("sealed-bid"));

var material = VerificationMaterial.of(
    proof.vkJson().getBytes(UTF_8),
    ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("sealed-bid"));

var verifier = new Groth16BLS12381PureJavaVerifier();
var result = verifier.verify(envelope, material);
assert result.proofValid();
```

### 6. On-chain verification (Julc + Yaci DevKit)

The on-chain verification uses a Julc-compiled Plutus V3 script (`ZkAuctionVerifier`) that performs the BLS12-381 pairing check natively on Cardano.

```java
// 1. Compress VK points for on-chain use
var vk = SnarkjsToCardano.parseVk(vkJson);

// 2. Load verifier script with VK + reserve price params
var script = JulcScriptLoader.load(ZkAuctionVerifier.class,
        new BytesPlutusData(reservePriceBytes),
        new BytesPlutusData(vk.alpha()),
        new BytesPlutusData(vk.beta()),
        /* ... remaining VK params ... */);

// 3. Lock ADA at script address with public inputs as datum
var lockTx = new Tx()
        .payToContract(scriptAddr, Amount.ada(5), datum)
        .from(sender.baseAddress());

// 4. Unlock with ZK proof as redeemer
var unlockTx = new ScriptTx()
        .collectFrom(scriptUtxo, redeemer)
        .attachSpendingValidator(script);
```

## Powers of Tau (.ptau) — What You Need to Know

### What it is
The Powers of Tau ceremony is a multi-party computation that generates the "toxic waste" parameters for the proving system. It's the foundation of trust in Groth16.

### Key facts
- **One .ptau works for ALL circuits** on the same curve (curve-wide, not circuit-specific)
- It only depends on: (1) the elliptic curve and (2) the maximum circuit size
- **Phase 1** (Powers of Tau) is universal — run once per curve
- **Phase 2** (Groth16 setup) is circuit-specific — run once per circuit
- As long as ONE participant in the ceremony is honest, the setup is secure

### gnark handles setup internally
When using `GnarkProver.groth16FullProve()`, gnark performs the trusted setup internally. For production deployments, you should use community ceremony files (e.g., Filecoin Powers of Tau for BLS12-381) and separate the setup from proving.

### PlonK advantage
PlonK only needs Phase 1 — no circuit-specific Phase 2 ceremony. This makes it a "universal" setup: one ceremony works for any circuit (up to the size limit).

## Running the Tests

```bash
# Unit tests (pure Java, no external tools needed)
./gradlew :zeroj-examples:test --tests "*SealedBidCircuitTest*"

# E2E tests with gnark FFM prover (no snarkjs needed)
./gradlew :zeroj-examples:test --tests "*SealedBidGnarkE2ETest*"

# On-chain E2E (requires Yaci DevKit running)
./gradlew :zeroj-examples:e2eTest --tests "*SealedBidOnChainE2ETest*"

# All DSL E2E tests
./gradlew :zeroj-examples:test --tests "*dsl*"
```
