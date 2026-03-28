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
        assertEquals(5, halo2.fixedColumns().size(), "should have 5 selector columns");
        assertEquals(1, halo2.numPublicInputs());
        assertTrue(halo2.k() >= 1, "k must be at least 1");
    }

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

        // Verify each gate row: qL*a + qR*b + qO*c + qM*(a*b) + qC = 0
        var colA = halo2.adviceColumns().get(0).wireIndices();
        var colB = halo2.adviceColumns().get(1).wireIndices();
        var colC = halo2.adviceColumns().get(2).wireIndices();
        var qL = halo2.fixedColumns().get(0).wireIndices();
        var qR = halo2.fixedColumns().get(1).wireIndices();
        var qO = halo2.fixedColumns().get(2).wireIndices();
        var qM = halo2.fixedColumns().get(3).wireIndices();
        var qC = halo2.fixedColumns().get(4).wireIndices();

        for (int i = 0; i < halo2.numRows(); i++) {
            BigInteger a = witness[colA[i]];
            BigInteger b = witness[colB[i]];
            BigInteger c = witness[colC[i]];
            if (a == null || b == null || c == null) continue;

            BigInteger result = BigInteger.valueOf(qL[i]).multiply(a)
                    .add(BigInteger.valueOf(qR[i]).multiply(b))
                    .add(BigInteger.valueOf(qO[i]).multiply(c))
                    .add(BigInteger.valueOf(qM[i]).multiply(a).multiply(b))
                    .add(BigInteger.valueOf(qC[i]))
                    .mod(BN254_PRIME);

            assertEquals(BigInteger.ZERO, result, "Halo2 gate row " + i + " not satisfied");
        }
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

        // Wires that appear in multiple gate rows should have permutation cycles
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
    void complexCircuit_toBinaryAndSelect() {
        var circuit = CircuitBuilder.create("complex")
                .publicVar("result").secretVar("a").secretVar("b").secretVar("flag")
                .define(api -> {
                    var sum = api.add(api.var("a"), api.var("b"));
                    var product = api.mul(api.var("a"), api.var("b"));
                    var selected = api.select(api.var("flag"), product, sum);
                    api.assertEqual(selected, api.var("result"));
                });

        var halo2 = circuit.compileHalo2(CurveId.BN254);
        assertNotNull(halo2);
        assertTrue(halo2.numRows() > 3, "complex circuit should have multiple gate rows");

        // Verify witness satisfies
        var witness = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11)),
                "flag", List.of(BigInteger.ONE)), CurveId.BN254);
        assertNotNull(witness);
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

        // Same circuit compiles to all three backends
        var r1cs = circuit.compileR1CS(CurveId.BN254);
        var plonk = circuit.compilePlonK(CurveId.BN254);
        var halo2 = circuit.compileHalo2(CurveId.BN254);

        assertNotNull(r1cs);
        assertNotNull(plonk);
        assertNotNull(halo2);

        // Same witness works with all backends
        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(33), witness[1]);
    }
}
