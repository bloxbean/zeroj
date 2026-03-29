package com.bloxbean.cardano.zeroj.crypto.kzg;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.msm.Pippenger;

import java.math.BigInteger;

/**
 * KZG (Kate-Zaverucha-Goldberg) polynomial commitment scheme over BN254 G1.
 *
 * <p>Given a polynomial f(X) = sum(c_i * X^i) and an SRS = {[tau^i]_1 for i=0..d},
 * the commitment is [f(tau)]_1 = sum(c_i * [tau^i]_1) — a single G1 MSM.</p>
 *
 * <p>Opening proof for evaluation f(z) = y:
 * Compute quotient q(X) = (f(X) - y) / (X - z), then commitment [q(tau)]_1.</p>
 */
public final class KZGCommitment {

    private KZGCommitment() {}

    /**
     * Commit to a polynomial using KZG: [f(tau)]_1 = MSM(SRS, coefficients).
     *
     * @param srsG1  SRS points [tau^0]_1, [tau^1]_1, ..., [tau^d]_1
     * @param coeffs polynomial coefficients [c_0, c_1, ..., c_d]
     * @return commitment as a G1 point
     */
    public static JacobianG1BN254 commit(AffineG1[] srsG1, BigInteger[] coeffs) {
        int n = Math.min(srsG1.length, coeffs.length);
        if (n == 0) return JacobianG1BN254.INFINITY;

        AffineG1[] points = new AffineG1[n];
        BigInteger[] scalars = new BigInteger[n];
        System.arraycopy(srsG1, 0, points, 0, n);
        System.arraycopy(coeffs, 0, scalars, 0, n);
        return Pippenger.msm(points, scalars);
    }

    /**
     * Commit to a polynomial given as MontFr254 values.
     */
    public static JacobianG1BN254 commit(AffineG1[] srsG1, MontFr254[] coeffs) {
        BigInteger[] scalars = new BigInteger[coeffs.length];
        for (int i = 0; i < coeffs.length; i++) {
            scalars[i] = coeffs[i].toBigInteger();
        }
        return commit(srsG1, scalars);
    }

    /**
     * Compute KZG opening proof: q(X) = (f(X) - f(z)) / (X - z).
     *
     * @param srsG1  SRS points
     * @param coeffs polynomial coefficients of f(X)
     * @param z      evaluation point
     * @param fz     f(z) — the claimed evaluation value
     * @return [q(tau)]_1 — the opening proof commitment
     */
    public static JacobianG1BN254 openingProof(AffineG1[] srsG1, MontFr254[] coeffs,
                                                 MontFr254 z, MontFr254 fz) {
        // q(X) = (f(X) - fz) / (X - z) via synthetic division
        MontFr254[] quotient = syntheticDivision(coeffs, z, fz);
        return commit(srsG1, quotient);
    }

    /**
     * Synthetic division: compute (f(X) - v) / (X - z) where v = f(z).
     *
     * <p>Process from highest degree down: q[i-1] = f[i] + z * q[i]</p>
     *
     * @param coeffs polynomial coefficients [c_0, c_1, ..., c_d]
     * @param z      divisor root (divide by X - z)
     * @param v      value to subtract (f(z))
     * @return quotient coefficients (degree = deg(f) - 1)
     */
    public static MontFr254[] syntheticDivision(MontFr254[] coeffs, MontFr254 z, MontFr254 v) {
        int n = coeffs.length;
        if (n <= 1) return new MontFr254[]{MontFr254.ZERO};

        // f(X) - v: subtract v from constant term
        MontFr254[] f = new MontFr254[n];
        System.arraycopy(coeffs, 0, f, 0, n);
        f[0] = f[0].sub(v);

        // Synthetic division by (X - z): process from top
        MontFr254[] q = new MontFr254[n - 1];
        q[n - 2] = f[n - 1];
        for (int i = n - 3; i >= 0; i--) {
            q[i] = f[i + 1].add(z.mul(q[i + 1]));
        }
        return q;
    }
}
