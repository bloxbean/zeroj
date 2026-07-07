package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M2a: fixed-base {@link FixedBaseG1BLS381#mul} must equal the object double-and-add
 * {@code GENERATOR.scalarMul} over random + edge scalars.
 */
class FixedBaseG1BLS381Test {

    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Random RND = new Random(0xF1BA5E01L);

    private static void assertEqualPoint(BigInteger k) {
        JacobianG1BLS381 expected = JacobianG1BLS381.GENERATOR.scalarMul(k.mod(R));
        JacobianG1BLS381 actual = FixedBaseG1BLS381.mul(k);
        if (expected.isInfinity()) { assertTrue(actual.isInfinity(), "expected infinity for k=" + k); return; }
        var e = expected.toAffine();
        var a = actual.toAffine();
        assertEquals(e.x().toBigInteger(), a.x().toBigInteger(), "x mismatch k=" + k);
        assertEquals(e.y().toBigInteger(), a.y().toBigInteger(), "y mismatch k=" + k);
    }

    @Test
    void matchesDoubleAndAdd() {
        for (BigInteger k : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(15),
                BigInteger.valueOf(16), BigInteger.valueOf(255), R.subtract(BigInteger.ONE)})
            assertEqualPoint(k);
        for (int t = 0; t < 200; t++) assertEqualPoint(new BigInteger(255, RND).mod(R));
    }

    @Test
    void scalarsAtOrAboveOrder_reduced() {
        assertEqualPoint(R);                       // ≡ 0
        assertEqualPoint(R.add(BigInteger.valueOf(7)));
    }
}
