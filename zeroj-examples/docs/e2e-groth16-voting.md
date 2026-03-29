# E2E: Anonymous Voting (Java DSL → Groth16 → Cardano)

## Overview

A voter proves their vote is valid (0 or 1) without revealing the choice. The commitment `MiMC(vote, nullifier)` is published on-chain. The nullifier prevents double-voting while keeping the vote private.

**What is proved:**
1. `vote ∈ {0, 1}` (boolean constraint)
2. `commitment == MiMC(vote, nullifier)`

**What is NOT revealed:** The actual `vote` value and the `nullifier`.

## Circuit

```java
public class AnonymousVotingCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal vote = c.privateInput("vote");
        Signal nullifier = c.privateInput("nullifier");
        Signal commitment = c.publicOutput("commitment");

        vote.assertBoolean();  // vote must be 0 or 1
        c.assertEqual(SignalMiMC.hash(c, vote, nullifier), commitment);
    }
}
```

## Flow

### 1. Voter computes commitment off-chain

```java
var helper = new AnonymousVotingProofHelper(CurveId.BLS12_381);
BigInteger commitment = helper.computeCommitment(vote, nullifier);
```

### 2. Generate proof (gnark FFM — in-process)

```java
try (var prover = new GnarkProver()) {
    var result = helper.generateGroth16ProofNative(vote, nullifier, prover);
    // result contains proof, public signals, and verification key
}
```

Or with snarkjs CLI (if preferred):
```java
Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);
var proof = helper.generateGroth16Proof(vote, nullifier, ptau, workDir, snarkjs);
```

### 3. Submit on-chain

The commitment is published as a public output in the proof. On-chain:
- The **commitment** identifies the voter (linked to a registration Merkle tree)
- The **nullifier** is derived from the voter's secret and the election ID
- The same nullifier can't be used twice (double-vote prevention)

### 4. Tally

Anyone can verify all proofs and count votes without knowing individual choices.

## Extending: Merkle-based voter registration

For a production voting system, add a Merkle membership proof:

```java
public class FullVotingCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal vote = c.privateInput("vote");
        Signal nullifier = c.privateInput("nullifier");
        Signal voterSecret = c.privateInput("voterSecret");
        Signal[] siblings = ...;  // Merkle path
        Signal[] pathBits = ...;  // Merkle path direction

        Signal commitment = c.publicOutput("commitment");
        Signal merkleRoot = c.publicInput("merkleRoot");
        Signal nullifierHash = c.publicOutput("nullifierHash");

        vote.assertBoolean();
        c.assertEqual(SignalMiMC.hash(c, vote, nullifier), commitment);

        // Prove voter is in the registration tree
        Signal leaf = SignalMiMC.hash(c, voterSecret, c.constant(0));
        Signal computedRoot = SignalMerkle.computeRoot(c, leaf, siblings, pathBits, SignalMiMC::hash);
        c.assertEqual(computedRoot, merkleRoot);

        // Nullifier hash (published on-chain for double-vote detection)
        c.assertEqual(SignalMiMC.hash(c, nullifier, voterSecret), nullifierHash);
    }
}
```

## Running the Tests

```bash
# E2E test (gnark FFM prover — no snarkjs needed)
./gradlew :zeroj-examples:test --tests "*AnonymousVotingE2ETest*"
```
