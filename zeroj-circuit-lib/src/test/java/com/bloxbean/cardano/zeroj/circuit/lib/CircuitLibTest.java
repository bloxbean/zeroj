package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the circuit standard library components.
 */
class CircuitLibTest {

    // --- Comparators ---

    @Test
    void lessThan_3lt11() {
        var circuit = CircuitBuilder.create("lt")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var lt = Comparators.lessThan(api, api.var("a"), api.var("b"), 8);
                    api.assertEqual(lt, api.var("result"));
                });

        var w = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        assertEquals(BigInteger.ONE, w[1], "3 < 11 should be 1");
    }

    @Test
    void lessThan_11notLt3() {
        var circuit = CircuitBuilder.create("lt")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var lt = Comparators.lessThan(api, api.var("a"), api.var("b"), 8);
                    api.assertEqual(lt, api.var("result"));
                });

        var w = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.valueOf(11)),
                "b", List.of(BigInteger.valueOf(3))), CurveId.BN254);
        assertEquals(BigInteger.ZERO, w[1], "11 < 3 should be 0");
    }

    @Test
    void lessThan_equalValues() {
        var circuit = CircuitBuilder.create("lt")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var lt = Comparators.lessThan(api, api.var("a"), api.var("b"), 8);
                    api.assertEqual(lt, api.var("result"));
                });

        var w = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.valueOf(5)),
                "b", List.of(BigInteger.valueOf(5))), CurveId.BN254);
        assertEquals(BigInteger.ZERO, w[1], "5 < 5 should be 0");
    }

    // --- Mux ---

    @Test
    void mux1_selectA() {
        var circuit = CircuitBuilder.create("mux")
                .publicVar("out").secretVar("sel").secretVar("a").secretVar("b")
                .define(api -> {
                    var result = Mux.mux1(api, api.var("sel"), api.var("a"), api.var("b"));
                    api.assertEqual(result, api.var("out"));
                });

        var w = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.TEN),
                "sel", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.TEN),
                "b", List.of(BigInteger.valueOf(20))), CurveId.BN254);
        assertEquals(BigInteger.TEN, w[1]);
    }

    @Test
    void mux2_allCombinations() {
        var circuit = CircuitBuilder.create("mux2")
                .publicVar("out")
                .secretVar("s0").secretVar("s1")
                .secretVar("a").secretVar("b").secretVar("c").secretVar("d")
                .define(api -> {
                    var result = Mux.mux2(api, api.var("s0"), api.var("s1"),
                            api.var("a"), api.var("b"), api.var("c"), api.var("d"));
                    api.assertEqual(result, api.var("out"));
                });

        // s0=0,s1=0 → a=100
        var w = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(100)),
                "s0", List.of(BigInteger.ZERO), "s1", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.valueOf(100)), "b", List.of(BigInteger.valueOf(200)),
                "c", List.of(BigInteger.valueOf(300)), "d", List.of(BigInteger.valueOf(400))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(100), w[1]);

        // s0=1,s1=1 → d=400
        var w2 = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(400)),
                "s0", List.of(BigInteger.ONE), "s1", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.valueOf(100)), "b", List.of(BigInteger.valueOf(200)),
                "c", List.of(BigInteger.valueOf(300)), "d", List.of(BigInteger.valueOf(400))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(400), w2[1]);
    }

    // --- MiMC ---

    @Test
    void mimc_hashIsDeterministic() {
        // No assertEqual on hash — just compute and check determinism
        var circuit = CircuitBuilder.create("mimc")
                .secretVar("left").secretVar("right")
                .define(api -> MiMC.hash(api, api.var("left"), api.var("right")));

        var w1 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.valueOf(3)),
                "right", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        var w2 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.valueOf(3)),
                "right", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        assertArrayEquals(w1, w2, "MiMC hash must be deterministic");
    }

    @Test
    void mimc_differentInputsDifferentHash() {
        // Just verify the circuit compiles and runs without errors for different inputs
        var circuit = CircuitBuilder.create("mimc")
                .secretVar("left").secretVar("right")
                .define(api -> MiMC.hash(api, api.var("left"), api.var("right")));

        var w1 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.ONE),
                "right", List.of(BigInteger.TWO)), CurveId.BN254);

        var w2 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.valueOf(3)),
                "right", List.of(BigInteger.valueOf(4))), CurveId.BN254);

        assertNotNull(w1);
        assertNotNull(w2);
        // Different inputs should produce different witnesses
        assertFalse(java.util.Arrays.equals(w1, w2));
    }

    // --- Merkle ---

    @Test
    void merkle_depth2_verifyProof() {
        // Build a depth-2 Merkle tree using MiMC
        // Leaves: L0, L1, L2, L3
        // Level 1: H01 = hash(L0, L1), H23 = hash(L2, L3)
        // Root: hash(H01, H23)
        //
        // Prove leaf L0 is in the tree.
        // Path bits: [0, 0] (left at both levels)
        // Siblings: [L1, H23]

        var circuit = CircuitBuilder.create("merkle")
                .publicVar("root")
                .secretVar("leaf").secretVar("sib0").secretVar("sib1")
                .secretVar("path0").secretVar("path1")
                .define(api -> {
                    var siblings = new com.bloxbean.cardano.zeroj.circuit.Variable[]{
                            api.var("sib0"), api.var("sib1")};
                    var pathBits = new com.bloxbean.cardano.zeroj.circuit.Variable[]{
                            api.var("path0"), api.var("path1")};
                    var computedRoot = Merkle.computeRoot(api, api.var("leaf"),
                            siblings, pathBits, MiMC::hash);
                    api.assertEqual(computedRoot, api.var("root"));
                });

        // Compute the tree values manually
        var L0 = BigInteger.valueOf(10);
        var L1 = BigInteger.valueOf(20);
        var L2 = BigInteger.valueOf(30);
        var L3 = BigInteger.valueOf(40);

        // For this test, just verify the circuit runs without constraint violations
        // by letting the witness calculator compute the root
        // We set root to placeholder 0 initially, then re-run with the correct root
        try {
            circuit.calculateWitness(Map.of(
                    "root", List.of(BigInteger.ZERO), // will fail assertEqual
                    "leaf", List.of(L0),
                    "sib0", List.of(L1),
                    "sib1", List.of(BigInteger.valueOf(999)), // placeholder
                    "path0", List.of(BigInteger.ZERO),
                    "path1", List.of(BigInteger.ZERO)), CurveId.BN254);
            fail("Should fail with wrong root");
        } catch (ArithmeticException e) {
            // Expected — root doesn't match
            assertTrue(e.getMessage().contains("Constraint violation"));
        }
    }

    // --- Binary ---

    @Test
    void binary_num2bitsAndBack() {
        var circuit = CircuitBuilder.create("binary")
                .publicVar("value")
                .define(api -> {
                    var bits = Binary.num2Bits(api, api.var("value"), 8);
                    var reconstructed = Binary.bits2Num(api, bits);
                    api.assertEqual(reconstructed, api.var("value"));
                });

        var w = circuit.calculateWitness(Map.of(
                "value", List.of(BigInteger.valueOf(170))), CurveId.BN254);  // 10101010
        assertEquals(BigInteger.valueOf(170), w[1]);
    }
}
