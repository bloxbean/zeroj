package com.bloxbean.cardano.zeroj.crypto.kzg;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class KZGCommitmentBLS381Test {

    static final BigInteger FR = MontFr381.modulus();
    static AffineG1[] srs;

    @BeforeAll
    static void setupSRS() {
        // Build a small SRS: tau^i * G for i=0..15 using a known tau
        BigInteger tau = BigInteger.valueOf(12345678);
        int n = 16;
        srs = new AffineG1[n];
        var g = JacobianG1BLS381.GENERATOR;
        BigInteger tauPow = BigInteger.ONE;
        for (int i = 0; i < n; i++) {
            srs[i] = g.scalarMul(tauPow).toAffine();
            tauPow = tauPow.multiply(tau).mod(FR);
        }
    }

    @Test
    void commit_zeroPolynomial_isInfinity() {
        var result = KZGCommitmentBLS381.commit(srs, new BigInteger[]{BigInteger.ZERO});
        assertTrue(result.isInfinity(), "Commitment to zero polynomial should be infinity");
    }

    @Test
    void commit_constantPolynomial_matchesScalarMul() {
        BigInteger c = BigInteger.valueOf(42);
        var result = KZGCommitmentBLS381.commit(srs, new BigInteger[]{c}).toAffine();
        var expected = JacobianG1BLS381.GENERATOR.scalarMul(c).toAffine();
        assertEquals(expected.xBigInt(), result.xBigInt());
        assertEquals(expected.yBigInt(), result.yBigInt());
    }

    @Test
    void commit_linearPolynomial_isOnCurve() {
        // f(x) = 3 + 7x
        var result = KZGCommitmentBLS381.commit(srs,
                new BigInteger[]{BigInteger.valueOf(3), BigInteger.valueOf(7)});
        assertFalse(result.isInfinity());
        assertTrue(result.toAffine().isOnCurve(), "Commitment must be on BLS12-381 G1 curve");
    }

    @Test
    void commit_fromMontFr_matchesBigInteger() {
        MontFr381[] coeffs = {MontFr381.fromLong(5), MontFr381.fromLong(11)};
        BigInteger[] biCoeffs = {BigInteger.valueOf(5), BigInteger.valueOf(11)};

        var r1 = KZGCommitmentBLS381.commit(srs, coeffs).toAffine();
        var r2 = KZGCommitmentBLS381.commit(srs, biCoeffs).toAffine();

        assertEquals(r1.xBigInt(), r2.xBigInt());
        assertEquals(r1.yBigInt(), r2.yBigInt());
    }

    @Test
    void syntheticDivision_linear() {
        // f(x) = 3 + 5x, z=2, v=f(2)=13
        // q(x) = (f(x) - 13) / (x - 2) = (3 + 5x - 13) / (x - 2) = (-10 + 5x) / (x - 2) = 5
        MontFr381[] coeffs = {MontFr381.fromLong(3), MontFr381.fromLong(5)};
        MontFr381 z = MontFr381.fromLong(2);
        MontFr381 v = MontFr381.fromLong(13);

        var q = KZGCommitmentBLS381.syntheticDivision(coeffs, z, v);

        assertEquals(1, q.length);
        assertEquals(BigInteger.valueOf(5), q[0].toBigInteger());
    }

    @Test
    void syntheticDivision_quadratic() {
        // f(x) = 1 + 2x + 3x^2, z=1, f(1) = 6
        // (f(x) - 6) / (x - 1) = (-5 + 2x + 3x^2) / (x - 1) = 5 + 3x  [synthetic division]
        // Check: (5 + 3x)(x - 1) = 5x - 5 + 3x^2 - 3x = -5 + 2x + 3x^2 ✓
        MontFr381[] coeffs = {MontFr381.fromLong(1), MontFr381.fromLong(2), MontFr381.fromLong(3)};
        MontFr381 z = MontFr381.fromLong(1);
        MontFr381 v = MontFr381.fromLong(6);

        var q = KZGCommitmentBLS381.syntheticDivision(coeffs, z, v);

        assertEquals(2, q.length);
        assertEquals(BigInteger.valueOf(5), q[0].toBigInteger());
        assertEquals(BigInteger.valueOf(3), q[1].toBigInteger());
    }

    @Test
    void openingProof_isOnCurve() {
        MontFr381[] coeffs = {MontFr381.fromLong(1), MontFr381.fromLong(2), MontFr381.fromLong(3)};
        MontFr381 z = MontFr381.fromLong(5);
        MontFr381 fz = FieldFFTBLS381.polyEval(coeffs, z);

        var proof = KZGCommitmentBLS381.openingProof(srs, coeffs, z, fz);
        assertFalse(proof.isInfinity());
        assertTrue(proof.toAffine().isOnCurve(), "Opening proof must be on curve");
    }

    @Test
    void commit_exceedsSRS_throws() {
        BigInteger[] tooLarge = new BigInteger[srs.length + 1];
        for (int i = 0; i < tooLarge.length; i++) tooLarge[i] = BigInteger.ONE;
        assertThrows(IllegalArgumentException.class, () ->
                KZGCommitmentBLS381.commit(srs, tooLarge));
    }
}
