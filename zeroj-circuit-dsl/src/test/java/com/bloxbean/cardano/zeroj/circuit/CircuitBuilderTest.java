package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CircuitBuilderTest {

    @Test
    void multiplier_witnessCalculation() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });

        var witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        assertEquals(BigInteger.ONE, witness[0], "wire 0 must be 1");
        assertEquals(BigInteger.valueOf(33), witness[1], "z=33");
        assertEquals(BigInteger.valueOf(3), witness[2], "x=3");
        assertEquals(BigInteger.valueOf(11), witness[3], "y=11");
    }

    @Test
    void multiplier_constraintViolation_throws() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(99)),  // wrong! 3*11 != 99
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254));
    }

    @Test
    void adder_witnessCalculation() {
        var circuit = CircuitBuilder.create("adder")
                .publicVar("sum").secretVar("a").secretVar("b")
                .define(api -> {
                    var s = api.add(api.var("a"), api.var("b"));
                    api.assertEqual(s, api.var("sum"));
                });

        var witness = circuit.calculateWitness(Map.of(
                "sum", List.of(BigInteger.valueOf(15)),
                "a", List.of(BigInteger.valueOf(7)),
                "b", List.of(BigInteger.valueOf(8))), CurveId.BN254);

        assertEquals(BigInteger.valueOf(15), witness[1]);
    }

    @Test
    void chainedOps_witnessCalculation() {
        // d = a*b + c
        var circuit = CircuitBuilder.create("chain")
                .publicVar("d").secretVar("a").secretVar("b").secretVar("c")
                .define(api -> {
                    var ab = api.mul(api.var("a"), api.var("b"));
                    var result = api.add(ab, api.var("c"));
                    api.assertEqual(result, api.var("d"));
                });

        var witness = circuit.calculateWitness(Map.of(
                "d", List.of(BigInteger.valueOf(38)),  // 3*11 + 5 = 38
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11)),
                "c", List.of(BigInteger.valueOf(5))), CurveId.BN254);

        assertEquals(BigInteger.valueOf(38), witness[1]);
    }

    @Test
    void select_witnessCalculation() {
        var circuit = CircuitBuilder.create("conditional")
                .publicVar("out").secretVar("cond").secretVar("a").secretVar("b")
                .define(api -> {
                    var result = api.select(api.var("cond"), api.var("a"), api.var("b"));
                    api.assertEqual(result, api.var("out"));
                });

        // cond=1 → select a=10
        var w1 = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.TEN),
                "cond", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.TEN),
                "b", List.of(BigInteger.valueOf(20))), CurveId.BN254);
        assertEquals(BigInteger.TEN, w1[1]);

        // cond=0 → select b=20
        var w2 = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(20)),
                "cond", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.TEN),
                "b", List.of(BigInteger.valueOf(20))), CurveId.BN254);
        assertEquals(BigInteger.valueOf(20), w2[1]);
    }

    @Test
    void r1cs_multiplier_constraintCount() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });

        var r1cs = circuit.compileR1CS(CurveId.BN254);

        // Multiplier: 1 mul constraint + 1 assertEqual constraint
        // The assertEqual compiles to (diff) * 1 = 0
        assertTrue(r1cs.numConstraints() <= 2,
                "multiplier should have at most 2 R1CS constraints, got " + r1cs.numConstraints());
    }

    @Test
    void plonk_multiplier_compilesSuccessfully() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });

        var plonk = circuit.compilePlonK(CurveId.BN254);
        assertTrue(plonk.numGates() > 0, "PlonK should have at least one gate");
        assertEquals(1, plonk.numPublicInputs());
    }

    @Test
    void isZero_witnessCalculation() {
        var circuit = CircuitBuilder.create("iszero")
                .publicVar("result").secretVar("x")
                .define(api -> {
                    var iz = api.isZero(api.var("x"));
                    api.assertEqual(iz, api.var("result"));
                });

        // x=0 → result=1
        var w1 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ONE),
                "x", List.of(BigInteger.ZERO)), CurveId.BN254);
        assertEquals(BigInteger.ONE, w1[1]);

        // x=42 → result=0
        var w2 = circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "x", List.of(BigInteger.valueOf(42))), CurveId.BN254);
        assertEquals(BigInteger.ZERO, w2[1]);
    }

    @Test
    void toBinary_roundTrip() {
        var circuit = CircuitBuilder.create("binary")
                .publicVar("value").secretVar("input")
                .define(api -> {
                    var bits = api.toBinary(api.var("input"), 8);
                    var reconstructed = api.fromBinary(bits);
                    api.assertEqual(reconstructed, api.var("value"));
                });

        var witness = circuit.calculateWitness(Map.of(
                "value", List.of(BigInteger.valueOf(170)),  // 10101010 in binary
                "input", List.of(BigInteger.valueOf(170))), CurveId.BN254);

        assertEquals(BigInteger.valueOf(170), witness[1]);
    }

    @Test
    void bls12381_fieldPrime() {
        var circuit = CircuitBuilder.create("test")
                .publicVar("x")
                .define(api -> {});

        var witness = circuit.calculateWitness(Map.of(
                "x", List.of(BigInteger.ONE)), CurveId.BLS12_381);
        assertEquals(BigInteger.ONE, witness[1]);
    }
}
