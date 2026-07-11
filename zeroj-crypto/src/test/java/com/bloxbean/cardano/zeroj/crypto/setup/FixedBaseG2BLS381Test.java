package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0035 M4: the G2 comb table + batched normalization must equal the generic
 * {@code scalarMul().toAffine()} exactly — including zero, one, r−1, and random scalars.
 */
class FixedBaseG2BLS381Test {

    private static final BigInteger FR = MontFr381.modulus();

    @Test
    void combMulEqualsScalarMul() {
        var rnd = new Random(42);
        BigInteger[] scalars = new BigInteger[64];
        scalars[0] = BigInteger.ZERO;
        scalars[1] = BigInteger.ONE;
        scalars[2] = BigInteger.TWO;
        scalars[3] = FR.subtract(BigInteger.ONE);
        scalars[4] = FR.subtract(BigInteger.TWO);
        scalars[5] = BigInteger.ONE.shiftLeft(254).mod(FR);
        for (int i = 6; i < scalars.length; i++) scalars[i] = new BigInteger(255, rnd).mod(FR);

        // comb (Jacobian) + batch normalization vs generic scalarMul + individual toAffine
        JacobianG2BLS381[] comb = new JacobianG2BLS381[scalars.length];
        for (int i = 0; i < scalars.length; i++) comb[i] = FixedBaseG2BLS381.mulJacobian(scalars[i]);
        var batch = JacobianG2BLS381.batchToAffine(comb, scalars.length);

        for (int i = 0; i < scalars.length; i++) {
            var expected = JacobianG2BLS381.GENERATOR.scalarMul(scalars[i]).toAffine();
            assertEquals(expected.x().reBigInt(), batch[i].x().reBigInt(), "x.re scalar " + i);
            assertEquals(expected.x().imBigInt(), batch[i].x().imBigInt(), "x.im scalar " + i);
            assertEquals(expected.y().reBigInt(), batch[i].y().reBigInt(), "y.re scalar " + i);
            assertEquals(expected.y().imBigInt(), batch[i].y().imBigInt(), "y.im scalar " + i);
        }
    }
}
