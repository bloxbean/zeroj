package com.bloxbean.cardano.zeroj.crypto.kzg;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class KZGCommitmentTest {

    @Test
    void commit_constantPolynomial() {
        // f(X) = 5, SRS = {G, tau*G, ...}
        // [f(tau)]_1 = 5*G
        var g = JacobianG1BN254.GENERATOR.toAffine();
        var tauG = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(7)).toAffine(); // tau=7

        var result = KZGCommitment.commit(
                new AffineG1[]{g, tauG},
                new BigInteger[]{BigInteger.valueOf(5), BigInteger.ZERO});

        var expected = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(5));
        var rAff = result.toAffine();
        var eAff = expected.toAffine();
        assertEquals(eAff.xBigInt(), rAff.xBigInt());
        assertEquals(eAff.yBigInt(), rAff.yBigInt());
    }

    @Test
    void commit_linearPolynomial() {
        // f(X) = 3 + 2X, SRS with tau=7: [f(7)]_1 = [3 + 14]_1 = [17]_1 = 17*G
        var g = JacobianG1BN254.GENERATOR.toAffine();
        var tauG = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(7)).toAffine();

        var result = KZGCommitment.commit(
                new AffineG1[]{g, tauG},
                new BigInteger[]{BigInteger.valueOf(3), BigInteger.TWO});

        var expected = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(17));
        var rAff = result.toAffine();
        assertEquals(expected.toAffine().xBigInt(), rAff.xBigInt());
    }

    @Test
    void syntheticDivision_simple() {
        // f(X) = X^2 - 1, z=1, f(z)=0
        // (X^2 - 1) / (X - 1) = X + 1
        var coeffs = new MontFr254[]{
                MontFr254.fromLong(-1).add(MontFr254.fromBigInteger(MontFr254.modulus())),  // actually mod r, so -1 = r-1
                MontFr254.ZERO,
                MontFr254.ONE};
        // Manually: f(X) = -1 + 0*X + 1*X^2
        // f(1) = -1 + 0 + 1 = 0
        var z = MontFr254.ONE;
        var fz = MontFr254.ZERO;

        var q = KZGCommitment.syntheticDivision(coeffs, z, fz);

        // Expected: q(X) = 1 + X (coefficients [1, 1])
        assertEquals(2, q.length);
        assertEquals(BigInteger.ONE, q[0].toBigInteger());
        assertEquals(BigInteger.ONE, q[1].toBigInteger());
    }

    @Test
    void syntheticDivision_verifyEvaluation() {
        // f(X) = 5 + 3X + 7X^2, z=2, f(2) = 5 + 6 + 28 = 39
        var coeffs = new MontFr254[]{
                MontFr254.fromLong(5), MontFr254.fromLong(3), MontFr254.fromLong(7)};
        var z = MontFr254.fromLong(2);
        var fz = MontFr254.fromLong(39);

        var q = KZGCommitment.syntheticDivision(coeffs, z, fz);

        // Verify: q(X) * (X - 2) + 39 = f(X)
        // q should have degree 1: q(X) = a + bX
        assertEquals(2, q.length);

        // Check: q(z) * (z - z) + fz = fz (trivial at evaluation point)
        // Better: check q(3) * (3 - 2) + 39 = f(3) = 5 + 9 + 63 = 77
        var q_at_3 = q[0].add(q[1].mul(MontFr254.fromLong(3)));
        var reconstructed = q_at_3.mul(MontFr254.fromLong(1)).add(MontFr254.fromLong(39)); // q(3)*(3-2)+39
        assertEquals(BigInteger.valueOf(77), reconstructed.toBigInteger());
    }
}
