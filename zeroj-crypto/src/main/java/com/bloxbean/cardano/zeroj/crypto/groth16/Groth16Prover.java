package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.msm.Pippenger;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFT;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

/**
 * Pure Java Groth16 prover for BN254.
 *
 * <p>Given an R1CS constraint system, a proving key (from trusted setup), and a
 * witness, produces a Groth16 proof (A ∈ G1, B ∈ G2, C ∈ G1).</p>
 *
 * <h3>Algorithm</h3>
 * <ol>
 *   <li>Compute h(x) = (A(x)*B(x) - C(x)) / Z_H(x) via FFT</li>
 *   <li>Sample random blinding factors r, s</li>
 *   <li>Compute proof elements:
 *     <ul>
 *       <li>π_A = α + Σ(w_i * A_i) + r*δ (G1 MSM)</li>
 *       <li>π_B = β + Σ(w_i * B_i) + s*δ (G2 scalar muls + adds)</li>
 *       <li>π_C = Σ(h_i * H_i) + Σ(w_j * L_j) + s*π_A + r*π_B1 - r*s*δ (G1 MSM)</li>
 *     </ul>
 *   </li>
 * </ol>
 */
public final class Groth16Prover {

    private Groth16Prover() {}

    /**
     * Generate a Groth16 proof.
     *
     * @param pk          proving key from trusted setup
     * @param witness     full witness vector [1, public..., private..., intermediates...]
     * @param constraints R1CS constraints as (A, B, C) maps: wireIndex → coefficient
     * @param numWires    total number of wires
     * @return Groth16 proof (A, B, C)
     */
    public static Groth16Proof prove(
            Groth16ProvingKey pk,
            BigInteger[] witness,
            R1CSConstraint[] constraints,
            int numWires) {

        int numConstraints = constraints.length;

        // Step 1: Compute h(x) polynomial
        BigInteger[] hCoeffs = computeH(constraints, witness, numConstraints);

        // Step 2: Random blinding factors
        var rng = new SecureRandom();
        BigInteger r = randomScalar(rng);
        BigInteger s = randomScalar(rng);

        // Step 3a: π_A = α + Σ(w_i * pk.A_i) + r * δ  (in G1)
        var piA = computePiA(pk, witness, r);

        // Step 3b: π_B in G2 = β + Σ(w_i * pk.B2_i) + s * δ  (in G2)
        var piB = computePiB_G2(pk, witness, s);

        // Step 3c: π_B in G1 (needed for C computation)
        var piB1 = computePiB_G1(pk, witness, s);

        // Step 3d: π_C = Σ(h_i * H_i) + Σ(w_j * L_j) + s*A + r*B1 - r*s*δ  (in G1)
        var piC = computePiC(pk, hCoeffs, witness, r, s, piA, piB1);

        return new Groth16Proof(piA.toAffine(), piB.toAffine(), piC.toAffine());
    }

    /**
     * Compute h(x) = (A(x)*B(x) - C(x)) / Z_H(x) via FFT.
     *
     * <p>A(x) = Σ w_i * a_i(x), B(x) = Σ w_i * b_i(x), C(x) = Σ w_i * c_i(x)
     * where a_i, b_i, c_i are the Lagrange basis representations of the R1CS matrices.</p>
     */
    static BigInteger[] computeH(R1CSConstraint[] constraints, BigInteger[] witness, int numConstraints) {
        BigInteger r = MontFr254.modulus();

        // Domain size = next power of 2 >= numConstraints
        int domainSize = Integer.highestOneBit(numConstraints);
        if (domainSize < numConstraints) domainSize <<= 1;
        if (domainSize < 2) domainSize = 2;

        // Evaluate A(x), B(x), C(x) at the witness: these are the constraint evaluations
        // For each constraint i: a_eval[i] = Σ_j a_ij * w_j, etc.
        MontFr254[] aEval = new MontFr254[domainSize];
        MontFr254[] bEval = new MontFr254[domainSize];
        MontFr254[] cEval = new MontFr254[domainSize];

        for (int i = 0; i < domainSize; i++) {
            if (i < numConstraints) {
                aEval[i] = evalLinComb(constraints[i].a(), witness, r);
                bEval[i] = evalLinComb(constraints[i].b(), witness, r);
                cEval[i] = evalLinComb(constraints[i].c(), witness, r);
            } else {
                aEval[i] = MontFr254.ZERO;
                bEval[i] = MontFr254.ZERO;
                cEval[i] = MontFr254.ZERO;
            }
        }

        // These are evaluations at the roots of unity omega^0, ..., omega^{n-1}.
        // We have: A(omega^i) * B(omega^i) - C(omega^i) = 0 for valid witnesses.
        // h(x) = (A(x)*B(x) - C(x)) / Z_H(x) where Z_H(x) = x^n - 1.

        // To compute h: evaluate A*B-C on a *coset* (shift by a generator),
        // divide by Z_H on the coset, then IFFT back to coefficients.
        // For simplicity, use the direct approach:
        // 1. IFFT to get coefficient form of A, B, C
        // 2. Multiply A*B in coefficient form (via FFT at 2n points)
        // 3. Subtract C
        // 4. Divide by Z_H(x) = x^n - 1

        // Step 1: Get coefficients via IFFT
        var aCoeffs = FieldFFT.ifft(aEval);
        var bCoeffs = FieldFFT.ifft(bEval);
        var cCoeffs = FieldFFT.ifft(cEval);

        // Step 2: A*B via FFT polynomial multiplication
        var abCoeffs = FieldFFT.polyMul(aCoeffs, bCoeffs);

        // Step 3: A*B - C (pad C to match length)
        int abLen = abCoeffs.length;
        MontFr254[] abMinusC = new MontFr254[abLen];
        for (int i = 0; i < abLen; i++) {
            MontFr254 ci = (i < cCoeffs.length) ? cCoeffs[i] : MontFr254.ZERO;
            abMinusC[i] = abCoeffs[i].sub(ci);
        }

        // Step 4: Divide by Z_H(x) = x^n - 1
        // Z_H has coefficients: [-1, 0, ..., 0, 1] (degree n)
        // Polynomial long division: quotient has degree (2n-2) - n = n-2
        BigInteger[] hResult = polyDivByVanishing(abMinusC, domainSize);

        return hResult;
    }

    /**
     * Polynomial division by Z_H(x) = x^n - 1.
     * Given f(x) of degree 2n-2, compute q(x) = f(x) / (x^n - 1).
     * Returns coefficients as BigInteger (for MSM scalars).
     */
    private static BigInteger[] polyDivByVanishing(MontFr254[] f, int n) {
        // f(x) / (x^n - 1): process from highest degree down
        // For degree d coefficient: q[d-n] += f[d], then f[d-n] += f[d] (since x^n = 1 in the quotient)
        int fLen = f.length;
        MontFr254[] q = new MontFr254[fLen]; // quotient (oversized, will trim)
        MontFr254[] rem = new MontFr254[fLen];
        for (int i = 0; i < fLen; i++) rem[i] = f[i];

        for (int i = fLen - 1; i >= n; i--) {
            // Leading coefficient of remainder at position i
            // Divide by x^n: subtract rem[i] * (x^n - 1) * x^{i-n}
            // This sets q[i-n] = rem[i] and rem[i-n] += rem[i]
            MontFr254 coeff = rem[i];
            if (!coeff.isZero()) {
                q[i - n] = coeff;
                rem[i] = MontFr254.ZERO;
                rem[i - n] = rem[i - n].add(coeff); // since we're dividing by (x^n - 1)
            } else {
                q[i - n] = MontFr254.ZERO;
            }
        }

        // Trim quotient and convert to BigInteger
        int qDeg = fLen - n; // max quotient degree + 1
        BigInteger[] result = new BigInteger[qDeg];
        for (int i = 0; i < qDeg; i++) {
            result[i] = (q[i] != null) ? q[i].toBigInteger() : BigInteger.ZERO;
        }
        return result;
    }

    // --- Proof element computation ---

    private static JacobianG1BN254 computePiA(Groth16ProvingKey pk, BigInteger[] witness, BigInteger r) {
        // π_A = α + Σ(w_i * A_i) + r * δ
        var result = JacobianG1BN254.fromAffine(pk.alphaG1().x(), pk.alphaG1().y());

        // MSM: Σ(w_i * A_i)
        int n = Math.min(witness.length, pk.pointsA().length);
        if (n > 0) {
            AffineG1[] points = new AffineG1[n];
            BigInteger[] scalars = new BigInteger[n];
            System.arraycopy(pk.pointsA(), 0, points, 0, n);
            System.arraycopy(witness, 0, scalars, 0, n);
            result = result.add(Pippenger.msm(points, scalars));
        }

        // + r * δ
        result = result.add(JacobianG1BN254.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(r));

        return result;
    }

    private static JacobianG2BN254 computePiB_G2(Groth16ProvingKey pk, BigInteger[] witness, BigInteger s) {
        // π_B = β + Σ(w_i * B2_i) + s * δ  (in G2)
        var result = JacobianG2BN254.fromAffine(pk.betaG2().x(), pk.betaG2().y());

        // Naive sum (no Pippenger for G2 yet — G2 MSM is less critical)
        int n = Math.min(witness.length, pk.pointsB2().length);
        for (int i = 0; i < n; i++) {
            if (witness[i].signum() != 0 && !pk.pointsB2()[i].isInfinity()) {
                result = result.add(
                        JacobianG2BN254.fromAffine(pk.pointsB2()[i].x(), pk.pointsB2()[i].y())
                                .scalarMul(witness[i]));
            }
        }

        // + s * δ
        result = result.add(JacobianG2BN254.fromAffine(pk.deltaG2().x(), pk.deltaG2().y()).scalarMul(s));

        return result;
    }

    private static JacobianG1BN254 computePiB_G1(Groth16ProvingKey pk, BigInteger[] witness, BigInteger s) {
        // π_B1 = β + Σ(w_i * B1_i) + s * δ  (in G1, for C computation)
        var result = JacobianG1BN254.fromAffine(pk.betaG1().x(), pk.betaG1().y());

        int n = Math.min(witness.length, pk.pointsB1().length);
        if (n > 0) {
            AffineG1[] points = new AffineG1[n];
            BigInteger[] scalars = new BigInteger[n];
            System.arraycopy(pk.pointsB1(), 0, points, 0, n);
            System.arraycopy(witness, 0, scalars, 0, n);
            result = result.add(Pippenger.msm(points, scalars));
        }

        result = result.add(JacobianG1BN254.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(s));

        return result;
    }

    private static JacobianG1BN254 computePiC(
            Groth16ProvingKey pk, BigInteger[] hCoeffs, BigInteger[] witness,
            BigInteger r, BigInteger s,
            JacobianG1BN254 piA, JacobianG1BN254 piB1) {

        JacobianG1BN254 result = JacobianG1BN254.INFINITY;

        // Σ(h_i * H_i) — h polynomial MSM
        int hLen = Math.min(hCoeffs.length, pk.pointsH().length);
        if (hLen > 0) {
            AffineG1[] hPoints = new AffineG1[hLen];
            BigInteger[] hScalars = new BigInteger[hLen];
            System.arraycopy(pk.pointsH(), 0, hPoints, 0, hLen);
            System.arraycopy(hCoeffs, 0, hScalars, 0, hLen);
            result = result.add(Pippenger.msm(hPoints, hScalars));
        }

        // Σ(w_j * L_j) — private witness wires MSM
        int numPrivate = witness.length - pk.numPublic() - 1; // exclude wire 0 and public
        if (numPrivate > 0 && pk.pointsL().length > 0) {
            int lLen = Math.min(numPrivate, pk.pointsL().length);
            AffineG1[] lPoints = new AffineG1[lLen];
            BigInteger[] lScalars = new BigInteger[lLen];
            System.arraycopy(pk.pointsL(), 0, lPoints, 0, lLen);
            // Private wires start at index numPublic + 1
            System.arraycopy(witness, pk.numPublic() + 1, lScalars, 0, lLen);
            result = result.add(Pippenger.msm(lPoints, lScalars));
        }

        // + s * π_A
        result = result.add(piA.scalarMul(s));

        // + r * π_B1
        result = result.add(piB1.scalarMul(r));

        // - r * s * δ
        BigInteger rs = r.multiply(s).mod(MontFr254.modulus());
        result = result.add(
                JacobianG1BN254.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(rs).negate());

        return result;
    }

    // --- Helpers ---

    private static MontFr254 evalLinComb(Map<Integer, BigInteger> lc, BigInteger[] witness, BigInteger mod) {
        MontFr254 sum = MontFr254.ZERO;
        for (var entry : lc.entrySet()) {
            int wire = entry.getKey();
            BigInteger coeff = entry.getValue();
            if (wire < witness.length && coeff.signum() != 0) {
                sum = sum.add(MontFr254.fromBigInteger(coeff).mul(MontFr254.fromBigInteger(witness[wire])));
            }
        }
        return sum;
    }

    private static BigInteger randomScalar(SecureRandom rng) {
        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(MontFr254.modulus());
    }

    /** R1CS constraint: A · w × B · w = C · w */
    public record R1CSConstraint(
            Map<Integer, BigInteger> a,
            Map<Integer, BigInteger> b,
            Map<Integer, BigInteger> c
    ) {}
}
