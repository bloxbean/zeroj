package com.bloxbean.cardano.zeroj.bls12381.ec;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class JacobianG2BLS381Test {

    static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test
    void generator_isOnCurve() {
        var aff = JacobianG2BLS381.GENERATOR.toAffine();
        assertTrue(aff.isOnCurve(), "G2 generator must be on twist curve y^2 = x^3 + 4(1+u)");
    }

    @Test
    void infinity_isIdentity() {
        var g = JacobianG2BLS381.GENERATOR;
        var sum = JacobianG2BLS381.INFINITY.add(g);
        assertEquals(g.toAffine(), sum.toAffine());
    }

    @Test
    void doublePoint_isOnCurve() {
        var dbl = JacobianG2BLS381.GENERATOR.doublePoint();
        assertTrue(dbl.toAffine().isOnCurve());
    }

    @Test
    void add_generatorToItself_equalsDouble() {
        var g = JacobianG2BLS381.GENERATOR;
        var sum = g.add(g);
        var dbl = g.doublePoint();
        assertEquals(dbl.toAffine(), sum.toAffine());
    }

    @Test
    void scalarMul_byOrder_returnsInfinity() {
        var result = JacobianG2BLS381.GENERATOR.scalarMul(R);
        assertTrue(result.isInfinity(), "r * G2 must be infinity");
    }

    @Test
    void negate_addOriginal_isInfinity() {
        var g = JacobianG2BLS381.GENERATOR;
        var sum = g.add(g.negate());
        assertTrue(sum.isInfinity(), "P + (-P) must be infinity");
    }

    @Test
    void scalarMul_small_isOnCurve() {
        for (int k = 2; k <= 5; k++) {
            var p = JacobianG2BLS381.GENERATOR.scalarMul(BigInteger.valueOf(k));
            assertTrue(p.toAffine().isOnCurve(), k + " * G2 must be on twist curve");
        }
    }
}
