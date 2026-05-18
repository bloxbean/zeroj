# zeroj-examples

End-to-end demonstrations of ZeroJ capabilities -- from Java DSL circuit definition through proof generation to on-chain verification on Cardano.

## Quick Start

```bash
# Off-chain tests (unit): DSL → prove → verify
./gradlew :zeroj-examples:test

# On-chain E2E tests (requires Yaci DevKit running)
./gradlew :zeroj-examples:e2eTest
```

## Example Circuits

### Cardano Defaults

For new examples intended to be verified on Cardano, prefer:

```text
Java DSL or @ZKCircuit
  -> CurveId.BLS12_381
  -> Groth16
  -> Julc / Plutus V3 BLS12-381 verifier
```

Use Poseidon with explicit BLS12-381 parameters for hashes. MiMC-based Java DSL
and annotation examples are BN254/off-chain references unless they are migrated
to a separate BLS12-381 hash. The no-params Poseidon path is also BN254-oriented
for backward compatibility.

See the circuit annotation support matrix:
[`docs/adr/circuit-annotation/cardano-gadget-support-matrix.md`](../docs/adr/circuit-annotation/cardano-gadget-support-matrix.md).

### 0. Annotation-Based Circuits
Write circuits as annotated Java classes and use generated companions for
`build(...)`, `schema(...)`, and witness input builders.
- **Examples**: range proof, age verification, private transfer, MiMC
  commitment, sealed-bid auction, anonymous voting, parameterized Merkle
  membership, Pedersen commitment, proof-flow helper
- **Source**: [`examples/annotation`](src/main/java/com/bloxbean/cardano/zeroj/examples/annotation)
- **Tests**: [`AnnotatedCircuitExamplesTest.java`](src/test/java/com/bloxbean/cardano/zeroj/examples/annotation/AnnotatedCircuitExamplesTest.java)
- **Guide**: [`docs/circuit-annotation-user-guide.md`](../docs/circuit-annotation-user-guide.md)
- **Note**: MiMC-based annotation examples target BN254/off-chain. For
  Cardano/BLS12-381 circuits, use Poseidon with explicit BLS12-381 parameters.

### 1. Sealed-Bid Auction
Prove your bid exceeds a reserve price without revealing the bid amount.
- **Private**: bidAmount, salt
- **Public**: reservePrice, bidCommitment (MiMC hash), isAboveReserve (0/1)
- **Cardano note**: the Java DSL MiMC version is a BN254/off-chain reference.
  Use a BLS12-381 Poseidon commitment for new Cardano-ready sealed-bid circuits.
- **Source**: [`SealedBidCircuit.java`](src/main/java/com/bloxbean/cardano/zeroj/examples/dsl/auction/SealedBidCircuit.java)

### 2. Anonymous Voting
Prove a vote is valid (0 or 1) with a hash commitment for double-vote prevention.
- **Private**: vote, nullifier
- **Public**: commitment (MiMC hash)
- **Cardano note**: the MiMC commitment version is BN254/off-chain. Use
  BLS12-381 Poseidon for Cardano-ready voting circuits.
- **Source**: [`AnonymousVotingCircuit.java`](src/main/java/com/bloxbean/cardano/zeroj/examples/dsl/voting/AnonymousVotingCircuit.java)

### 3. Balance Threshold
Prove a balance exceeds a threshold without revealing the exact balance.
- **Private**: balance
- **Public**: threshold, isAboveThreshold (0/1)
- **Source**: [`BalanceThresholdCircuit.java`](src/main/java/com/bloxbean/cardano/zeroj/examples/dsl/balance/BalanceThresholdCircuit.java)

## Test Matrix

| Test | Circuit | Prover | Verifier | On-Chain |
|------|---------|--------|----------|----------|
| `SealedBidE2ETest` | Sealed bid, MiMC reference | snarkjs CLI | Pure Java | No |
| `SealedBidGnarkE2ETest` | Sealed bid, MiMC reference | gnark FFM | Pure Java | No |
| `SealedBidOnChainE2ETest` | Sealed bid | Pre-generated | Julc/Plutus V3 | Yes (Yaci DevKit) |
| `AnonymousVotingE2ETest` | Voting, MiMC reference | snarkjs CLI | Pure Java | No |
| `BalanceThresholdE2ETest` | Balance | snarkjs CLI | Pure Java (BLS12-381) | No |

## Three Proving Paths

### Path 1: snarkjs CLI (external tools)
```
Java DSL → R1CS (pure Java) → snarkjs CLI (Node.js) → Java verify (pure Java)
```
Used in: `SealedBidE2ETest`, `AnonymousVotingE2ETest`, `BalanceThresholdE2ETest`

### Path 2: gnark FFM (in-process, no external tools)
```
Java DSL → R1CS (pure Java) → gnark FFM (in-JVM) → verify
```
Used in: `SealedBidGnarkE2ETest`. Groth16 artifacts use the pure Java verifier;
gnark binary PlonK artifacts use gnark native verification until a structured
proof adapter is added.

### Path 3: On-chain (Julc / Plutus V3)
```
Java DSL → R1CS → gnark/snarkjs prove → Julc Plutus V3 verify (Yaci DevKit)
```
Used in: `SealedBidOnChainE2ETest`. The on-chain path uses BLS12-381 proof
artifacts and should not be confused with the BN254/off-chain MiMC Java DSL
reference circuit.

## On-Chain Flow (SealedBidOnChainE2ETest)

This is the full end-to-end flow from circuit to on-chain execution:

1. **Load** pre-generated BLS12-381 proof artifacts
2. **Compile** `Groth16BLS12381Verifier` Julc script with VK parameters baked in
3. **Lock** ADA at script address with public inputs (commitment, reservePrice) as datum
4. **Unlock** with ZK proof (piA, piB, piC) as redeemer
5. **Plutus V3 executes** BLS12-381 pairing verification on-chain
6. **Transaction succeeds** = proof verified on Cardano

See the [Getting Started Guide](../docs/getting-started.md) for a detailed walkthrough.

## On-Chain Verifiers

The on-chain Plutus V3 validators live in [`zeroj-onchain-julc`](../zeroj-onchain-julc/):

| Validator | Proof System | Source |
|-----------|-------------|--------|
| `Groth16BLS12381Verifier` | Groth16 BLS12-381 | `zeroj-onchain-julc` |
| `PlonkBLS12381FullVerifier` | PlonK BLS12-381 prototype | `zeroj-onchain-julc` |

The example-specific `ZkAuctionVerifier` in this module extends the pattern with auction-specific logic (reserve price check).

## Prover Toolchains

| Toolchain | Circuit Language | Prove | Verify | External Deps |
|-----------|-----------------|-------|--------|---------------|
| **gnark FFM** | Java DSL | In-process FFM | Groth16: pure Java; PlonK binary: gnark native | gnark native lib |
| **snarkjs** | Java DSL / circom | Node.js CLI | Pure Java | circom + Node.js |

## Verification Options (all pure Java, zero native deps)

| Proof System | Curve | Verifier Class |
|-------------|-------|----------------|
| Groth16 | BN254 | `Groth16BN254Verifier` |
| Groth16 | BLS12-381 | `Groth16BLS12381PureJavaVerifier` |
| Groth16 | BLS12-381 | `Groth16BLS12381Verifier` (blst, faster) |
| PlonK | BN254 | `PlonkBN254Verifier` |
| PlonK | BLS12-381 | `PlonkBLS12381Verifier` |

## Legacy Demos

### EndToEndDemo (snarkjs Groth16/BN254)
Pre-generated snarkjs proof flow: load -> verify -> anchor.

```bash
./gradlew :zeroj-examples:run
```

### GnarkPlonkEndToEndDemo (gnark PlonK/BLS12-381)
In-process gnark proving and native verification + Cardano anchor metadata.

```bash
cd zeroj-prover-gnark/gnark-wrapper && make build  # one-time
./gradlew :zeroj-examples:run -PmainClass=com.bloxbean.cardano.zeroj.examples.GnarkPlonkEndToEndDemo
```
