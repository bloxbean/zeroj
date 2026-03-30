package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Prover.R1CSConstraint;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;

/**
 * Groth16 Phase 2 setup for BLS12-381 — generates a proving key from R1CS constraints + Powers of Tau SRS.
 *
 * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b> This is a single-party setup — the toxic
 * waste (alpha, beta, gamma, delta, tau) is known to one party. For production, use
 * snarkjs multi-party ceremony: {@code snarkjs groth16 setup circuit.r1cs pot.ptau circuit.zkey}.</p>
 *
 * <p>Algorithm (from Groth16 paper, Section 3.2):</p>
 * <ol>
 *   <li>Sample random alpha, beta, gamma, delta</li>
 *   <li>Compute Lagrange basis evaluations L_i(tau) for each constraint row</li>
 *   <li>For each wire s, compute QAP polynomials u_s(tau), v_s(tau), w_s(tau)</li>
 *   <li>Compute proving key points via scalar multiplication on G1/G2 generators</li>
 *   <li>Compute H points as odd-indexed Lagrange basis on double-sized domain / delta</li>
 * </ol>
 */
public final class Groth16SetupBLS381 {

    private Groth16SetupBLS381() {}

    private static final BigInteger FR = MontFr381.modulus();

    /**
     * Generate a Groth16 proving key from R1CS constraints and known tau.
     *
     * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b></p>
     *
     * @param constraints R1CS constraints (A*w x B*w = C*w)
     * @param numWires    total wire count
     * @param numPublic   number of public inputs (wires 1..numPublic)
     * @param tau         the toxic waste from PowersOfTauBLS381 (KNOWN — dev/test only)
     * @return Groth16 proving key ready for Groth16ProverBLS381.prove()
     */
    public static SetupResult setup(R1CSConstraint[] constraints, int numWires,
                                     int numPublic, BigInteger tau) {
        System.err.println("WARNING: Single-party Groth16 Phase 2 setup (BLS12-381) — "
                + "for DEVELOPMENT and TESTING only. "
                + "Use snarkjs multi-party ceremony for production.");

        var rng = new SecureRandom();
        int nConstraints = constraints.length;

        // Domain size: next power of 2 >= nConstraints
        int domainSize = Integer.highestOneBit(nConstraints);
        if (domainSize < nConstraints) domainSize <<= 1;
        if (domainSize < 4) domainSize = 4;
        int logN = Integer.numberOfTrailingZeros(domainSize);

        // Sample random toxic waste for Phase 2
        BigInteger alpha = randomScalar(rng);
        BigInteger beta = randomScalar(rng);
        BigInteger gamma = randomScalar(rng);
        BigInteger delta = randomScalar(rng);

        BigInteger gammaInv = gamma.modInverse(FR);
        BigInteger deltaInv = delta.modInverse(FR);

        // Compute omega (primitive domainSize-th root of unity)
        MontFr381 omega = FieldFFTBLS381.rootOfUnity(logN);

        // Compute Lagrange basis evaluations at tau: L_i(tau) = (tau^N - 1) / (N * (tau - omega^i))
        BigInteger tauN = tau.modPow(BigInteger.valueOf(domainSize), FR);
        BigInteger zh = tauN.subtract(BigInteger.ONE).mod(FR); // tau^N - 1
        BigInteger nInv = BigInteger.valueOf(domainSize).modInverse(FR);

        BigInteger[] lagrange = new BigInteger[domainSize];
        BigInteger omegaI = BigInteger.ONE;
        BigInteger omegaBi = omega.toBigInteger();
        for (int i = 0; i < domainSize; i++) {
            // L_i(tau) = omega^i * (tau^N - 1) / (N * (tau - omega^i))
            BigInteger diff = tau.subtract(omegaI).mod(FR);
            if (diff.signum() == 0) {
                lagrange[i] = BigInteger.ONE;
            } else {
                lagrange[i] = omegaI.multiply(zh).mod(FR).multiply(nInv).mod(FR)
                        .multiply(diff.modInverse(FR)).mod(FR);
            }
            omegaI = omegaI.multiply(omegaBi).mod(FR);
        }

        // For each wire s, compute u_s(tau), v_s(tau), w_s(tau)
        // u_s = sum_c A_c[s] * L_c(tau), etc.
        BigInteger[] us = new BigInteger[numWires];
        BigInteger[] vs = new BigInteger[numWires];
        BigInteger[] ws = new BigInteger[numWires];
        Arrays.fill(us, BigInteger.ZERO);
        Arrays.fill(vs, BigInteger.ZERO);
        Arrays.fill(ws, BigInteger.ZERO);

        for (int c = 0; c < nConstraints && c < domainSize; c++) {
            var constraint = constraints[c];
            BigInteger lc = lagrange[c];
            accumulate(us, constraint.a(), lc);
            accumulate(vs, constraint.b(), lc);
            accumulate(ws, constraint.c(), lc);
        }

        // Compute group elements
        var g1 = JacobianG1BLS381.GENERATOR;
        var g2 = JacobianG2BLS381.GENERATOR;

        AffineG1 alphaG1 = g1.scalarMul(alpha).toAffine();
        AffineG1 betaG1 = g1.scalarMul(beta).toAffine();
        AffineG2 betaG2 = g2.scalarMul(beta).toAffine();
        AffineG1 deltaG1 = g1.scalarMul(delta).toAffine();
        AffineG2 deltaG2 = g2.scalarMul(delta).toAffine();

        // pointsA[s] = u_s(tau) * G1
        AffineG1[] pointsA = new AffineG1[numWires];
        for (int s = 0; s < numWires; s++) {
            pointsA[s] = us[s].signum() == 0 ? AffineG1.INFINITY : g1.scalarMul(us[s]).toAffine();
        }

        // pointsB1[s] = v_s(tau) * G1
        AffineG1[] pointsB1 = new AffineG1[numWires];
        for (int s = 0; s < numWires; s++) {
            pointsB1[s] = vs[s].signum() == 0 ? AffineG1.INFINITY : g1.scalarMul(vs[s]).toAffine();
        }

        // pointsB2[s] = v_s(tau) * G2
        AffineG2[] pointsB2 = new AffineG2[numWires];
        for (int s = 0; s < numWires; s++) {
            pointsB2[s] = vs[s].signum() == 0 ? AffineG2.INFINITY : g2.scalarMul(vs[s]).toAffine();
        }

        // pointsL[j] = (beta*u_s + alpha*v_s + w_s) / delta * G1  for private wire s = numPublic+1+j
        int numPrivate = numWires - numPublic - 1;
        AffineG1[] pointsL = new AffineG1[Math.max(0, numPrivate)];
        for (int j = 0; j < numPrivate; j++) {
            int s = numPublic + 1 + j;
            BigInteger lVal = beta.multiply(us[s]).add(alpha.multiply(vs[s])).add(ws[s])
                    .multiply(deltaInv).mod(FR);
            pointsL[j] = lVal.signum() == 0 ? AffineG1.INFINITY : g1.scalarMul(lVal).toAffine();
        }

        // H points: odd-indexed Lagrange basis on double-sized domain / delta
        // L_{2i+1}^{(2N)}(tau) / delta * G1
        int domainSize2 = 2 * domainSize;
        MontFr381 omega2 = FieldFFTBLS381.rootOfUnity(logN + 1); // primitive 2N-th root
        BigInteger omega2Bi = omega2.toBigInteger();
        BigInteger tauN2 = tau.modPow(BigInteger.valueOf(domainSize2), FR);
        BigInteger zh2 = tauN2.subtract(BigInteger.ONE).mod(FR);
        BigInteger nInv2 = BigInteger.valueOf(domainSize2).modInverse(FR);

        AffineG1[] pointsH = new AffineG1[domainSize];
        for (int i = 0; i < domainSize; i++) {
            int lagIdx = 2 * i + 1; // odd index
            // omega2^lagIdx
            BigInteger omegaPow = omega2Bi.modPow(BigInteger.valueOf(lagIdx), FR);
            BigInteger diff = tau.subtract(omegaPow).mod(FR);
            BigInteger hLagrange;
            if (diff.signum() == 0) {
                hLagrange = BigInteger.ONE;
            } else {
                // L_{lagIdx}^{(2N)}(tau) = omega2^{lagIdx} * (tau^{2N} - 1) / (2N * (tau - omega2^{lagIdx}))
                hLagrange = omegaPow.multiply(zh2).mod(FR).multiply(nInv2).mod(FR)
                        .multiply(diff.modInverse(FR)).mod(FR);
            }
            BigInteger hVal = hLagrange.multiply(deltaInv).mod(FR);
            pointsH[i] = hVal.signum() == 0 ? AffineG1.INFINITY : g1.scalarMul(hVal).toAffine();
        }

        // Verification key components: gamma_G2 and IC points
        AffineG2 gammaG2 = g2.scalarMul(gamma).toAffine();

        // IC[s] = (beta*u_s + alpha*v_s + w_s) / gamma * G1  for public wires s = 0..numPublic
        AffineG1[] ic = new AffineG1[numPublic + 1];
        for (int s = 0; s <= numPublic; s++) {
            BigInteger icVal = beta.multiply(us[s]).add(alpha.multiply(vs[s])).add(ws[s])
                    .multiply(gammaInv).mod(FR);
            ic[s] = icVal.signum() == 0 ? AffineG1.INFINITY : g1.scalarMul(icVal).toAffine();
        }

        // Securely discard toxic waste (best-effort — see PowersOfTauBLS381.java for caveats)
        alpha = beta = gamma = delta = BigInteger.ZERO;

        var pk = new Groth16ProvingKeyBLS381(
                alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                pointsA, pointsB1, pointsB2, pointsH, pointsL, numPublic);

        return new SetupResult(pk, gammaG2, ic);
    }

    /**
     * Setup result containing both proving key and verification key components.
     *
     * @param provingKey the Groth16 proving key
     * @param gammaG2    gamma in G2 (needed for verification equation)
     * @param ic         input commitment points: IC[0] + sum(pub_i * IC[i+1])
     */
    public record SetupResult(
            Groth16ProvingKeyBLS381 provingKey,
            AffineG2 gammaG2,
            AffineG1[] ic
    ) {}

    private static void accumulate(BigInteger[] target, Map<Integer, BigInteger> sparse, BigInteger lagrange) {
        for (var entry : sparse.entrySet()) {
            int wire = entry.getKey();
            if (wire < target.length) {
                target[wire] = target[wire].add(entry.getValue().multiply(lagrange)).mod(FR);
            }
        }
    }

    private static BigInteger randomScalar(SecureRandom rng) {
        byte[] bytes = new byte[64];
        rng.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(FR);
    }
}
