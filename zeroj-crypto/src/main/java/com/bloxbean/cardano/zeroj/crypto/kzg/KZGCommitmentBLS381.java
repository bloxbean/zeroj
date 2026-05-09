package com.bloxbean.cardano.zeroj.crypto.kzg;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.msm.PippengerBLS381;

import java.math.BigInteger;

/**
 * KZG polynomial commitment scheme over BLS12-381 G1.
 *
 * @see KZGCommitment
 */
public final class KZGCommitmentBLS381 {

    private KZGCommitmentBLS381() {}

    public static JacobianG1BLS381 commit(AffineG1[] srsG1, BigInteger[] coeffs) {
        if (coeffs.length > srsG1.length)
            throw new IllegalArgumentException(
                    "Polynomial degree (" + coeffs.length + ") exceeds SRS size (" + srsG1.length + ")");
        int n = Math.min(srsG1.length, coeffs.length);
        if (n == 0) return JacobianG1BLS381.INFINITY;

        AffineG1[] points = new AffineG1[n];
        BigInteger[] scalars = new BigInteger[n];
        System.arraycopy(srsG1, 0, points, 0, n);
        System.arraycopy(coeffs, 0, scalars, 0, n);
        return PippengerBLS381.msm(points, scalars);
    }

    public static JacobianG1BLS381 commit(AffineG1[] srsG1, MontFr381[] coeffs) {
        if (coeffs.length > srsG1.length)
            throw new IllegalArgumentException(
                    "Polynomial degree (" + coeffs.length + ") exceeds SRS size (" + srsG1.length + ")");
        BigInteger[] scalars = new BigInteger[coeffs.length];
        for (int i = 0; i < coeffs.length; i++) {
            scalars[i] = coeffs[i].toBigInteger();
        }
        return commit(srsG1, scalars);
    }

    public static JacobianG1BLS381 openingProof(AffineG1[] srsG1, MontFr381[] coeffs,
                                                  MontFr381 z, MontFr381 fz) {
        MontFr381[] quotient = syntheticDivision(coeffs, z, fz);
        return commit(srsG1, quotient);
    }

    public static MontFr381[] syntheticDivision(MontFr381[] coeffs, MontFr381 z, MontFr381 v) {
        int n = coeffs.length;
        if (n <= 1) return new MontFr381[]{MontFr381.ZERO};

        MontFr381[] f = new MontFr381[n];
        System.arraycopy(coeffs, 0, f, 0, n);
        f[0] = f[0].sub(v);

        MontFr381[] q = new MontFr381[n - 1];
        q[n - 2] = f[n - 1];
        for (int i = n - 3; i >= 0; i--) {
            q[i] = f[i + 1].add(z.mul(q[i + 1]));
        }
        return q;
    }
}
