package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0034 M7: {@link WitnessCalculator#calculateFlat} shares the boxed path's evaluation code —
 * only the storage differs — so the two must produce value-identical witnesses, including through
 * hints, bit decomposition, selects, and modular arithmetic edge values.
 */
class FlatWitnessDifferentialTest {

    private static CircuitBuilder mixedGadgetCircuit() {
        return CircuitBuilder.create("mixed")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var x = api.var("x");
                    var y = api.var("y");
                    var product = api.mul(x, y);                 // Mul
                    var sum = api.add(product, api.constant(BigInteger.valueOf(41))); // Add + Const
                    var bits = api.toBinary(sum, 16);            // BitDecompose + binding
                    var back = api.fromBinary(bits);             // LinComb
                    var isZero = api.isZero(api.sub(back, api.var("z"))); // Hint(s) + Mul/AssertEq
                    api.assertEqual(isZero, api.constant(BigInteger.ONE));
                });
    }

    @Test
    void flatWitness_equalsBoxedWitness() {
        var circuit = mixedGadgetCircuit();
        Map<String, List<BigInteger>> in = Map.of(
                "x", List.of(BigInteger.valueOf(7)),
                "y", List.of(BigInteger.valueOf(11)),
                "z", List.of(BigInteger.valueOf(7 * 11 + 41)));

        BigInteger[] boxed = circuit.calculateWitness(in, CurveId.BLS12_381);
        long[] flat = circuit.calculateWitnessFlat(in, CurveId.BLS12_381);

        assertEquals(boxed.length * 4, flat.length, "flat holds 4 limbs per wire");
        for (int i = 0; i < boxed.length; i++) {
            BigInteger flatVal = limbsToBigInteger(flat, i);
            assertEquals(boxed[i], flatVal, "wire " + i);
        }
    }

    @Test
    void flatWitness_constraintViolation_throwsSameAsBoxed() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> {
                    var product = api.mul(api.var("x"), api.var("y"));
                    api.assertEqual(product, api.var("z"));
                });
        Map<String, List<BigInteger>> bad = Map.of(
                "z", List.of(BigInteger.valueOf(76)), // wrong: 7*11 = 77
                "x", List.of(BigInteger.valueOf(7)),
                "y", List.of(BigInteger.valueOf(11)));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(bad, CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitnessFlat(bad, CurveId.BLS12_381));
    }

    private static BigInteger limbsToBigInteger(long[] limbs, int wire) {
        byte[] be = new byte[32];
        int base = wire * 4;
        for (int j = 0; j < 4; j++) {
            long l = limbs[base + j];
            int o = 24 - j * 8;
            for (int k = 0; k < 8; k++) be[o + 7 - k] = (byte) (l >>> (8 * k));
        }
        return new BigInteger(1, be);
    }
}
