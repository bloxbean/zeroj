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
        // Domain size = length of H points array in proving key
        int domainSize = pk.pointsH().length;
        return prove(pk, witness, constraints, numWires, domainSize);
    }

    public static Groth16Proof prove(
            Groth16ProvingKey pk,
            BigInteger[] witness,
            R1CSConstraint[] constraints,
            int numWires,
            int domainSize) {

        int numConstraints = constraints.length;

        // Step 1: Compute h(x) polynomial
        BigInteger[] hCoeffs = computeH(constraints, witness, numConstraints, domainSize);

        // Step 2: Random blinding factors (set to 0 for debugging with proveUnblinded)
        var rng = new SecureRandom();
        BigInteger r = randomScalar(rng);
        BigInteger s = randomScalar(rng);

        return proveInternal(pk, witness, hCoeffs, r, s);
    }

    /** Prove without blinding (r=0, s=0) — for debugging only. */
    static Groth16Proof proveUnblinded(
            Groth16ProvingKey pk, BigInteger[] witness,
            R1CSConstraint[] constraints, int numWires, int domainSize) {
        BigInteger[] hCoeffs = computeH(constraints, witness, constraints.length, domainSize);
        BigInteger r = BigInteger.ZERO;
        BigInteger s = BigInteger.ZERO;
        return proveInternal(pk, witness, hCoeffs, r, s);
    }

    private static Groth16Proof proveInternal(
            Groth16ProvingKey pk, BigInteger[] witness, BigInteger[] hCoeffs,
            BigInteger r, BigInteger s) {

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
     * Compute h(x) scalars for the H-point MSM, using snarkjs's coset evaluation approach.
     *
     * <p>The .zkey's H points (Section 9) are odd-indexed Lagrange basis elements,
     * so the MSM scalars must be coset evaluations of (A*B - C), NOT monomial coefficients.</p>
     *
     * <p>Algorithm (matching snarkjs groth16_prove.js):
     * <ol>
     *   <li>Build A, B evaluations on the standard domain from constraints + witness</li>
     *   <li>Compute C = A * B pointwise (on the standard domain)</li>
     *   <li>For each of A, B, C: IFFT → shift by coset generator → FFT (coset evaluation)</li>
     *   <li>Compute (A_coset * B_coset - C_coset) pointwise</li>
     *   <li>Return these coset evaluations as the MSM scalars (no final IFFT)</li>
     * </ol>
     *
     * <p>The coset generator is omega_{2n} = the primitive (2*domainSize)-th root of unity,
     * which equals the square root of the domain's omega_n.</p>
     */
    static BigInteger[] computeH(R1CSConstraint[] constraints, BigInteger[] witness,
                                  int numConstraints, int domainSize) {
        BigInteger mod = MontFr254.modulus();
        if (domainSize < 2) domainSize = 2;
        int logN = Integer.numberOfTrailingZeros(domainSize);

        // Step 1: Build A, B evaluations on the standard domain from R1CS constraints
        MontFr254[] aEval = new MontFr254[domainSize];
        MontFr254[] bEval = new MontFr254[domainSize];

        for (int i = 0; i < domainSize; i++) {
            if (i < numConstraints && i < constraints.length) {
                aEval[i] = evalLinComb(constraints[i].a(), witness, mod);
                bEval[i] = evalLinComb(constraints[i].b(), witness, mod);
            } else {
                aEval[i] = MontFr254.ZERO;
                bEval[i] = MontFr254.ZERO;
            }
        }

        // C = A * B pointwise on the standard domain
        // This is what snarkjs does: C is NOT from the R1CS C matrix.
        // The R1CS constraint A*B = C means that on the standard domain,
        // the product equals the C evaluation. The difference A*B - C = 0
        // on the standard domain (for valid witness), but NOT on a coset.
        MontFr254[] cEval = new MontFr254[domainSize];
        for (int i = 0; i < domainSize; i++) {
            cEval[i] = aEval[i].mul(bEval[i]);
        }

        // Step 2: Coset shift — IFFT, multiply by inc^i, FFT
        // inc = omega_{2n} (primitive 2*domainSize-th root of unity)
        MontFr254 inc = FieldFFT.rootOfUnity(logN + 1);

        var aCoset = cosetFFT(aEval, inc);
        var bCoset = cosetFFT(bEval, inc);
        var cCoset = cosetFFT(cEval, inc);

        // Step 3: Pointwise (A*B - C) on the coset
        // A_coset[i] * B_coset[i] is the "true" product at coset point i
        // C_coset[i] is the coset evaluation of the degree-(n-1) product polynomial
        // The difference captures the high-degree terms — exactly h(x) * Z_H(x) on the coset
        // Combined with the Lagrange-basis H points, this gives the correct h contribution
        BigInteger[] result = new BigInteger[domainSize];
        for (int i = 0; i < domainSize; i++) {
            var val = aCoset[i].mul(bCoset[i]).sub(cCoset[i]);
            result[i] = val.toBigInteger();
        }
        return result;
    }

    /**
     * Coset FFT: evaluate polynomial on the coset {inc * omega^i}.
     * Computed as: IFFT → multiply coeff[i] by inc^i → FFT.
     */
    private static MontFr254[] cosetFFT(MontFr254[] evals, MontFr254 inc) {
        // IFFT: evaluations → coefficients
        var coeffs = FieldFFT.ifft(evals);

        // Shift: coeff[i] *= inc^i
        MontFr254 power = MontFr254.ONE;
        for (int i = 0; i < coeffs.length; i++) {
            coeffs[i] = coeffs[i].mul(power);
            power = power.mul(inc);
        }

        // FFT: coefficients → evaluations on coset
        return FieldFFT.fft(coeffs);
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
