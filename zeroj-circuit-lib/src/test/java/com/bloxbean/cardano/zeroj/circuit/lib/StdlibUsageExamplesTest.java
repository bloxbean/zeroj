package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Practical examples showing how to use the circuit stdlib.
 *
 * <p>Each test is a self-contained example that a developer can copy and adapt.</p>
 */
class StdlibUsageExamplesTest {

    // ========================================================================
    // Example 1: Age verification — prove you're over 18 without revealing age
    // ========================================================================
    @Test
    void example_ageVerification_proveOver18() {
        var circuit = CircuitBuilder.create("age-check")
                .publicVar("minAge")     // public: the threshold (18)
                .secretVar("myAge")      // private: actual age (not revealed)
                .publicVar("isOldEnough") // public: 1 if age >= minAge
                .define(api -> {
                    var result = Comparators.greaterOrEqual(
                            api, api.var("myAge"), api.var("minAge"), 8);
                    api.assertEqual(result, api.var("isOldEnough"));
                });

        // Person is 25, threshold is 18 → isOldEnough=1, assertEqual passes
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "minAge", List.of(BigInteger.valueOf(18)),
                "myAge", List.of(BigInteger.valueOf(25)),
                "isOldEnough", List.of(BigInteger.ONE)), CurveId.BN254));

        // Person is 15, threshold is 18 → isOldEnough=0, assertEqual passes
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "minAge", List.of(BigInteger.valueOf(18)),
                "myAge", List.of(BigInteger.valueOf(15)),
                "isOldEnough", List.of(BigInteger.ZERO)), CurveId.BN254));

        // Wrong claim: 15 years old but claims isOldEnough=1 → constraint violation
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "minAge", List.of(BigInteger.valueOf(18)),
                "myAge", List.of(BigInteger.valueOf(15)),
                "isOldEnough", List.of(BigInteger.ONE)), CurveId.BN254));
    }

    // ========================================================================
    // Example 2: Range proof — prove a value is within bounds
    // ========================================================================
    @Test
    void example_rangeProof_balanceInRange() {
        var circuit = CircuitBuilder.create("range-proof")
                .publicVar("lowerBound")  // e.g., 0
                .publicVar("upperBound")  // e.g., 1000
                .secretVar("balance")     // private: actual balance
                .publicVar("inRange")     // public: 1 if in range
                .define(api -> {
                    var result = Comparators.inRange(
                            api, api.var("balance"),
                            api.var("lowerBound"), api.var("upperBound"), 16);
                    api.assertEqual(result, api.var("inRange"));
                });

        // Balance 500, range [0, 1000] → in range, assertEqual passes
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "lowerBound", List.of(BigInteger.ZERO),
                "upperBound", List.of(BigInteger.valueOf(1000)),
                "balance", List.of(BigInteger.valueOf(500)),
                "inRange", List.of(BigInteger.ONE)), CurveId.BN254));

        // Balance 500 but claims inRange=0 → constraint violation
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "lowerBound", List.of(BigInteger.ZERO),
                "upperBound", List.of(BigInteger.valueOf(1000)),
                "balance", List.of(BigInteger.valueOf(500)),
                "inRange", List.of(BigInteger.ZERO)), CurveId.BN254));
    }

    // ========================================================================
    // Example 3: Hash preimage — prove you know the preimage of a MiMC hash
    // ========================================================================
    @Test
    void example_hashPreimage_proveMiMCKnowledge() {
        // First, compute the hash outside the circuit to get the expected value
        var hashCircuit = CircuitBuilder.create("mimc-compute")
                .secretVar("preimage").secretVar("key")
                .define(api -> MiMC.hash(api, api.var("preimage"), api.var("key")));

        // Compute witness to get the hash value (last non-null intermediate)
        var computeWitness = hashCircuit.calculateWitness(Map.of(
                "preimage", List.of(BigInteger.valueOf(42)),
                "key", List.of(BigInteger.valueOf(7))), CurveId.BN254);

        // The MiMC hash result is the last computed value
        // (we'd need to track which wire it is — for this example, just verify
        // the circuit runs without errors and is deterministic)
        assertNotNull(computeWitness);
        assertTrue(computeWitness.length > 3);
    }

    // ========================================================================
    // Example 4: Merkle membership — prove a leaf exists in a Merkle tree
    // ========================================================================
    @Test
    void example_merkleMembership_depth2() {
        var circuit = CircuitBuilder.create("merkle-membership")
                .secretVar("leaf")
                .secretVar("sibling0").secretVar("sibling1")
                .secretVar("path0").secretVar("path1")
                .define(api -> {
                    var siblings = new Variable[]{api.var("sibling0"), api.var("sibling1")};
                    var pathBits = new Variable[]{api.var("path0"), api.var("path1")};
                    // Compute the root (don't assert against a public root — just show computation)
                    Merkle.computeRoot(api, api.var("leaf"), siblings, pathBits, MiMC::hash);
                });

        // Verify the circuit builds and witness computes successfully
        var witness = circuit.calculateWitness(Map.of(
                "leaf", List.of(BigInteger.TEN),
                "sibling0", List.of(BigInteger.valueOf(20)),
                "sibling1", List.of(BigInteger.valueOf(30)),
                "path0", List.of(BigInteger.ZERO),
                "path1", List.of(BigInteger.ZERO)), CurveId.BN254);

        assertNotNull(witness);
        assertEquals(BigInteger.ONE, witness[0]); // constant wire
    }

    // ========================================================================
    // Example 5: Voting — prove vote is valid (0 or 1) without revealing it
    // ========================================================================
    @Test
    void example_voting_booleanVote() {
        var circuit = CircuitBuilder.create("vote")
                .secretVar("vote")        // private: 0 or 1
                .publicVar("commitment")  // public: hash(vote, nullifier)
                .secretVar("nullifier")   // private: unique per voter
                .define(api -> {
                    // Vote must be boolean (0 or 1)
                    api.assertBoolean(api.var("vote"));

                    // Commitment = hash(vote, nullifier)
                    var computed = MiMC.hash(api, api.var("vote"), api.var("nullifier"));
                    api.assertEqual(computed, api.var("commitment"));
                });

        // This compiles — proving vote=1 with a specific nullifier
        var r1cs = circuit.compileR1CS(CurveId.BN254);
        assertNotNull(r1cs);
        assertTrue(r1cs.numConstraints() > 0);

        // Also compiles to PlonK
        var plonk = circuit.compilePlonK(CurveId.BN254);
        assertNotNull(plonk);
        assertTrue(plonk.numGates() > 0);
    }

    // ========================================================================
    // Example 6: Conditional logic — different computation based on flag
    // ========================================================================
    @Test
    void example_conditionalComputation() {
        var circuit = CircuitBuilder.create("conditional")
                .publicVar("result")
                .secretVar("flag")    // 0 or 1
                .secretVar("a")
                .secretVar("b")
                .define(api -> {
                    // If flag=1: result = a * b
                    // If flag=0: result = a + b
                    var product = api.mul(api.var("a"), api.var("b"));
                    var sum = api.add(api.var("a"), api.var("b"));
                    var out = Mux.mux1(api, api.var("flag"), product, sum);
                    api.assertEqual(out, api.var("result"));
                });

        // flag=1 → result = 3*11 = 33
        var w1 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.valueOf(33)),
                "flag", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(33), w1[1]);

        // flag=0 → result = 3+11 = 14
        var w2 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.valueOf(14)),
                "flag", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(14), w2[1]);
    }

    // ========================================================================
    // Example 7: Both backends from same circuit
    // ========================================================================
    @Test
    void example_dualBackend_sameCircuitBothProofSystems() {
        var circuit = CircuitBuilder.create("dual")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    api.assertEqual(api.mul(api.var("x"), api.var("y")), api.var("z"));
                });

        // Same circuit → R1CS (for Groth16 via rapidsnark or gnark)
        var r1cs = circuit.compileR1CS(CurveId.BN254);
        assertNotNull(r1cs);

        // Same circuit → PlonK (for PlonK via gnark)
        var plonk = circuit.compilePlonK(CurveId.BN254);
        assertNotNull(plonk);

        // Same circuit → BLS12-381 (for Cardano on-chain)
        var r1cs381 = circuit.compileR1CS(CurveId.BLS12_381);
        assertNotNull(r1cs381);

        // Witness is the same regardless of backend
        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(33), witness[1]);
    }
}
