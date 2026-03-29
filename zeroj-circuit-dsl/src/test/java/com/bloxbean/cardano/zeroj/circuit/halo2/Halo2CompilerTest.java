package com.bloxbean.cardano.zeroj.circuit.halo2;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Halo2 PLONKish backend compiler.
 */
class Halo2CompilerTest {

    private static final BigInteger BN254_PRIME = FieldConfig.BN254.prime();

    // --- Structure tests ---

    @Test
    void multiplier_compilesSuccessfully() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);

        assertNotNull(halo2);
        assertTrue(halo2.numRows() > 0);
        assertEquals(3, halo2.adviceColumns().size(), "should have 3 advice columns (a, b, c)");
        assertEquals(5, halo2.selectorColumns().size(), "should have 5 selector columns");
        assertEquals(1, halo2.numPublicInputs());
        assertTrue(halo2.k() >= 1, "k must be at least 1");
    }

    @Test
    void multiplier_hasPermutationCycles() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        assertTrue(halo2.permutation().size() > 0,
                "Should have permutation cycles for shared wires");
    }

    @Test
    void pallas_compiles() {
        var circuit = CircuitBuilder.create("test")
                .publicVar("x").secretVar("y")
                .define(api -> api.assertEqual(api.var("x"), api.var("y")));

        var halo2 = circuit.compileHalo2(CurveId.PALLAS);
        assertNotNull(halo2);
        assertEquals("Pallas", halo2.fieldConfig().name());
    }

    @Test
    void jsonSerialization() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(api.mul(api.var("x"), api.var("y")), api.var("z")));

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        String json = halo2.toJson(witness);
        assertNotNull(json);
        assertTrue(json.contains("\"version\": \"1.0\""));
        assertTrue(json.contains("\"k\":"));
        assertTrue(json.contains("\"adviceColumns\""));
        assertTrue(json.contains("\"fixedColumns\""));
    }

    @Test
    void allThreeBackends_sameCircuit() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(api.mul(api.var("x"), api.var("y")), api.var("z")));

        var r1cs = circuit.compileR1CS(CurveId.BN254);
        var plonk = circuit.compilePlonK(CurveId.BN254);
        var halo2 = circuit.compileHalo2(CurveId.BN254);

        assertNotNull(r1cs);
        assertNotNull(plonk);
        assertNotNull(halo2);

        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(33), witness[1]);
    }

    // --- Gate satisfaction tests ---

    @Test
    void multiplier_gatesSatisfied() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void extendWitness_noVirtualWires_returnsOriginal() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(api.mul(api.var("x"), api.var("y")), api.var("z")));

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        assertSame(witness, halo2.extendWitness(witness),
                "When no virtual wires exist, extendWitness should return the original array");
    }

    @Test
    void complexCircuit_selectAndArithmetic_gatesSatisfied() {
        var circuit = CircuitBuilder.create("complex")
                .publicVar("result").secretVar("a").secretVar("b").secretVar("flag")
                .define(api -> {
                    var sum = api.add(api.var("a"), api.var("b"));
                    var product = api.mul(api.var("a"), api.var("b"));
                    var selected = api.select(api.var("flag"), product, sum);
                    api.assertEqual(selected, api.var("result"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);

        // flag=1 �� product=33
        var w1 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11)),
                "flag", List.of(BigInteger.ONE)), CurveId.BN254);
        verifyHalo2GateSatisfaction(halo2, w1);

        // flag=0 → sum=14
        var w2 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.valueOf(14)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11)),
                "flag", List.of(BigInteger.ZERO)), CurveId.BN254);
        verifyHalo2GateSatisfaction(halo2, w2);
    }

    @Test
    void toBinary_roundTrip_gatesSatisfied() {
        var circuit = CircuitBuilder.create("binary")
                .publicVar("value").secretVar("input")
                .define(api -> {
                    var bits = api.toBinary(api.var("input"), 8);
                    var reconstructed = api.fromBinary(bits);
                    api.assertEqual(reconstructed, api.var("value"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "value", List.of(BigInteger.valueOf(170)),
                "input", List.of(BigInteger.valueOf(170))), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void toBinary_3bits_boundaryCase_gatesSatisfied() {
        // 3-bit decomposition = 3-term LinComb = minimum multi-term chaining case
        var circuit = CircuitBuilder.create("binary3")
                .publicVar("value").secretVar("input")
                .define(api -> {
                    var bits = api.toBinary(api.var("input"), 3);
                    var reconstructed = api.fromBinary(bits);
                    api.assertEqual(reconstructed, api.var("value"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "value", List.of(BigInteger.valueOf(5)),
                "input", List.of(BigInteger.valueOf(5))), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void toBinary_64bits_stressTest_gatesSatisfied() {
        // 64-term LinComb — stress test for virtual wire chaining
        var circuit = CircuitBuilder.create("binary64")
                .publicVar("value").secretVar("input")
                .define(api -> {
                    var bits = api.toBinary(api.var("input"), 64);
                    var reconstructed = api.fromBinary(bits);
                    api.assertEqual(reconstructed, api.var("value"));
                });

        BigInteger val = new BigInteger("DEADBEEFCAFEBABE", 16);
        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "value", List.of(val),
                "input", List.of(val)), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void lessThan_true_gatesSatisfied() {
        var circuit = CircuitBuilder.create("comparator")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var lt = api.lessThan(api.var("a"), api.var("b"), 8);
                    api.assertEqual(lt, api.var("result"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.valueOf(5)),
                "b", List.of(BigInteger.valueOf(10))), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void lessThan_false_gatesSatisfied() {
        var circuit = CircuitBuilder.create("comparator")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var lt = api.lessThan(api.var("a"), api.var("b"), 8);
                    api.assertEqual(lt, api.var("result"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.valueOf(10)),
                "b", List.of(BigInteger.valueOf(5))), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void lessThan_equal_gatesSatisfied() {
        var circuit = CircuitBuilder.create("comparator")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var lt = api.lessThan(api.var("a"), api.var("b"), 8);
                    api.assertEqual(lt, api.var("result"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.TEN),
                "b", List.of(BigInteger.TEN)), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void assertInRange_gatesSatisfied() {
        var circuit = CircuitBuilder.create("range")
                .secretVar("x")
                .define(api -> api.assertInRange(api.var("x"), 16));

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "x", List.of(BigInteger.valueOf(65535))), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void isZero_gatesSatisfied() {
        var circuit = CircuitBuilder.create("iszero")
                .publicVar("result").secretVar("x")
                .define(api -> {
                    var iz = api.isZero(api.var("x"));
                    api.assertEqual(iz, api.var("result"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);

        // x=0 → result=1
        var w1 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ONE),
                "x", List.of(BigInteger.ZERO)), CurveId.BN254);
        verifyHalo2GateSatisfaction(halo2, w1);

        // x=42 → result=0
        var w2 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "x", List.of(BigInteger.valueOf(42))), CurveId.BN254);
        verifyHalo2GateSatisfaction(halo2, w2);
    }

    @Test
    void neg_gatesSatisfied() {
        var circuit = CircuitBuilder.create("negate")
                .publicVar("out").secretVar("x")
                .define(api -> {
                    var neg = api.neg(api.var("x"));
                    api.assertEqual(neg, api.var("out"));
                });

        BigInteger x = BigInteger.valueOf(42);
        BigInteger negX = BN254_PRIME.subtract(x);

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "out", List.of(negX),
                "x", List.of(x)), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void div_gatesSatisfied() {
        var circuit = CircuitBuilder.create("division")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var q = api.div(api.var("a"), api.var("b"));
                    api.assertEqual(q, api.var("result"));
                });

        // 33 / 3 = 11
        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.valueOf(11)),
                "a", List.of(BigInteger.valueOf(33)),
                "b", List.of(BigInteger.valueOf(3))), CurveId.BN254);

        verifyHalo2GateSatisfaction(halo2, witness);
    }

    @Test
    void wrongWitness_gateNotSatisfied() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(api.mul(api.var("x"), api.var("y")), api.var("z")));

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        // Corrupt witness
        BigInteger[] corrupted = witness.clone();
        corrupted[1] = BigInteger.valueOf(99);

        assertThrows(AssertionError.class, () ->
                verifyHalo2GateSatisfaction(halo2, corrupted));
    }

    @Test
    void crossBackend_lessThan_allThreeBackendsSatisfied() {
        var circuit = CircuitBuilder.create("comparator")
                .publicVar("result").secretVar("a").secretVar("b")
                .define(api -> {
                    var lt = api.lessThan(api.var("a"), api.var("b"), 8);
                    api.assertEqual(lt, api.var("result"));
                });

        var inputs = Map.of(
                "result", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.valueOf(42)),
                "b", List.of(BigInteger.valueOf(100)));

        var witness = circuit.calculateWitness(inputs, CurveId.BN254);

        // All three backends should be satisfied by the same witness
        var halo2 = circuit.compileHalo2(CurveId.BN254);
        verifyHalo2GateSatisfaction(halo2, witness);

        var plonk = circuit.compilePlonK(CurveId.BN254);
        // PlonK also satisfied (cross-check) — skip public input rows (first nPub)
        var extendedPlonk = plonk.extendWitness(witness);
        var plonkRows = plonk.gateRows();
        for (int i = plonk.numPublicInputs(); i < plonkRows.size(); i++) {
            var row = plonkRows.get(i);
            BigInteger a = extendedPlonk[row.wireA()];
            BigInteger b = extendedPlonk[row.wireB()];
            BigInteger c = extendedPlonk[row.wireC()];
            BigInteger result = row.qL().multiply(a)
                    .add(row.qR().multiply(b))
                    .add(row.qO().multiply(c))
                    .add(row.qM().multiply(a).multiply(b))
                    .add(row.qC())
                    .mod(BN254_PRIME);
            assertEquals(BigInteger.ZERO, result, "PlonK gate " + i + " not satisfied");
        }
    }

    // --- Helpers ---

    private static void verifyHalo2GateSatisfaction(Halo2CircuitSystem halo2, BigInteger[] baseWitness) {
        BigInteger[] witness = halo2.extendWitness(baseWitness);

        var colA = halo2.adviceColumns().get(0).wireIndices();
        var colB = halo2.adviceColumns().get(1).wireIndices();
        var colC = halo2.adviceColumns().get(2).wireIndices();
        var qL = halo2.selectorColumns().get(0).values();
        var qR = halo2.selectorColumns().get(1).values();
        var qO = halo2.selectorColumns().get(2).values();
        var qM = halo2.selectorColumns().get(3).values();
        var qC = halo2.selectorColumns().get(4).values();

        for (int i = 0; i < halo2.numRows(); i++) {
            assertTrue(colA[i] < witness.length,
                    "wireA index " + colA[i] + " out of bounds (row " + i + ")");
            assertTrue(colB[i] < witness.length,
                    "wireB index " + colB[i] + " out of bounds (row " + i + ")");
            assertTrue(colC[i] < witness.length,
                    "wireC index " + colC[i] + " out of bounds (row " + i + ")");

            BigInteger a = witness[colA[i]];
            BigInteger b = witness[colB[i]];
            BigInteger c = witness[colC[i]];

            assertNotNull(a, "witness[wireA=" + colA[i] + "] is null at row " + i);
            assertNotNull(b, "witness[wireB=" + colB[i] + "] is null at row " + i);
            assertNotNull(c, "witness[wireC=" + colC[i] + "] is null at row " + i);

            BigInteger result = qL[i].multiply(a)
                    .add(qR[i].multiply(b))
                    .add(qO[i].multiply(c))
                    .add(qM[i].multiply(a).multiply(b))
                    .add(qC[i])
                    .mod(BN254_PRIME);

            assertEquals(BigInteger.ZERO, result, "Halo2 gate row " + i + " not satisfied: "
                    + "qL=" + qL[i] + " qR=" + qR[i] + " qO=" + qO[i]
                    + " qM=" + qM[i] + " qC=" + qC[i]
                    + " a=" + a + " b=" + b + " c=" + c
                    + " wireA=" + colA[i] + " wireB=" + colB[i] + " wireC=" + colC[i]);
        }
    }
}
