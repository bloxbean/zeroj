package com.bloxbean.cardano.zeroj.bls12381.ec;

import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class JacobianG1BLS381Test {

    static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test
    void generator_isOnCurve() {
        var aff = JacobianG1BLS381.GENERATOR.toAffine();
        assertTrue(aff.isOnCurve(), "Generator must be on curve y^2 = x^3 + 4");
    }

    @Test
    void infinity_isIdentity() {
        var g = JacobianG1BLS381.GENERATOR;
        var sum = JacobianG1BLS381.INFINITY.add(g);
        assertEquals(g.toAffine(), sum.toAffine());
    }

    @Test
    void doublePoint_isOnCurve() {
        var dbl = JacobianG1BLS381.GENERATOR.doublePoint();
        assertTrue(dbl.toAffine().isOnCurve());
    }

    @Test
    void add_generatorToItself_equalsDouble() {
        var g = JacobianG1BLS381.GENERATOR;
        var sum = g.add(g);
        var dbl = g.doublePoint();
        assertEquals(dbl.toAffine(), sum.toAffine());
    }

    @Test
    void scalarMul_byOrder_returnsInfinity() {
        var result = JacobianG1BLS381.GENERATOR.scalarMul(R);
        assertTrue(result.isInfinity(), "r * G must be infinity");
    }

    @Test
    void negate_addOriginal_isInfinity() {
        var g = JacobianG1BLS381.GENERATOR;
        var sum = g.add(g.negate());
        assertTrue(sum.isInfinity(), "P + (-P) must be infinity");
    }

    @Test
    void scalarMul_small_isOnCurve() {
        for (int k = 2; k <= 10; k++) {
            var p = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(k));
            assertTrue(p.toAffine().isOnCurve(), k + " * G must be on curve");
        }
    }

    @Test
    void ctScalarMul_matchesScalarMul() {
        for (int k = 1; k <= 20; k++) {
            var expected = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(k)).toAffine();
            var actual = JacobianG1BLS381.GENERATOR.ctScalarMul(BigInteger.valueOf(k)).toAffine();
            assertEquals(expected.xBigInt(), actual.xBigInt(), "ctScalarMul(" + k + ") x mismatch");
            assertEquals(expected.yBigInt(), actual.yBigInt(), "ctScalarMul(" + k + ") y mismatch");
        }
    }

    @Test
    void ctScalarMul_largeScalar_matchesRegular() {
        var scalar = new BigInteger("123456789012345678901234567890123456789012345678901234567890");
        var expected = JacobianG1BLS381.GENERATOR.scalarMul(scalar).toAffine();
        var actual = JacobianG1BLS381.GENERATOR.ctScalarMul(scalar).toAffine();
        assertEquals(expected.xBigInt(), actual.xBigInt());
        assertEquals(expected.yBigInt(), actual.yBigInt());
    }

    @Test
    void ctScalarMul_byOrder_returnsInfinity() {
        assertTrue(JacobianG1BLS381.GENERATOR.ctScalarMul(R).isInfinity());
    }

    @Test
    void ctScalarMul_rejectsScalarsAbove256Bits() {
        BigInteger scalar = BigInteger.ONE.shiftLeft(256).add(BigInteger.ONE);

        assertThrows(IllegalArgumentException.class,
                () -> JacobianG1BLS381.GENERATOR.ctScalarMul(scalar));
    }

    @Test
    void crossValidate_withVerifierG1Point() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var verG1 = new com.bloxbean.cardano.zeroj.bls12381.ec.G1Point(
                com.bloxbean.cardano.zeroj.bls12381.field.Fp.of(g.xBigInt()),
                com.bloxbean.cardano.zeroj.bls12381.field.Fp.of(g.yBigInt()));

        // Double using verifier
        var verDbl = verG1.doublePoint();
        // Double using prover
        var montDbl = JacobianG1BLS381.GENERATOR.doublePoint().toAffine();

        assertEquals(verDbl.x().value(), montDbl.xBigInt(), "2G.x must match");
        assertEquals(verDbl.y().value(), montDbl.yBigInt(), "2G.y must match");
    }
}
