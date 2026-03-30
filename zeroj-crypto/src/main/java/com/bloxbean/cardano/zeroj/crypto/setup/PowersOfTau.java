package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporter;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Powers of Tau generator for BN254 — development and testing only.
 *
 * <p><b>WARNING: This is a single-party generator. The toxic waste (tau) is known
 * to a single party. DO NOT use this for production deployments.</b></p>
 *
 * <p>For production, use SRS from established multi-party computation (MPC) ceremonies:</p>
 * <ul>
 *   <li><a href="https://github.com/iden3/snarkjs#7-prepare-phase-2">Hermez Phase 1</a> (54 contributors, 2^28)</li>
 *   <li><a href="https://github.com/privacy-scaling-explorations/perpetualpowersoftau">Perpetual Powers of Tau</a> (70+ contributors)</li>
 *   <li><a href="https://github.com/ebfull/powersoftau">Zcash Powers of Tau</a> (87 contributors)</li>
 * </ul>
 *
 * <p>These can be imported with {@link PtauImporter#importPtau(java.io.InputStream)}.</p>
 */
public final class PowersOfTau {

    private PowersOfTau() {}

    private static final BigInteger FR = MontFr254.modulus();

    /**
     * Generate a Powers of Tau SRS for BN254.
     *
     * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b> A single-party SRS provides no
     * trust guarantee — the generator knows tau and could forge proofs.
     * Use {@link PtauImporter} with MPC ceremony outputs for production.</p>
     *
     * @param power log2 of the maximum circuit size (e.g., 12 for up to 4096 constraints)
     * @return SRS containing tau^i * G1 and tau^i * G2 points
     */
    public static PtauImporter.SRS generate(int power) {
        if (power < 4 || power > 28)
            throw new IllegalArgumentException("Power must be in [4, 28], got " + power
                    + " (minimum 4 required for PlonK domain size >= 8)");

        System.err.println("WARNING: Single-party Powers of Tau generation — "
                + "for DEVELOPMENT and TESTING only. "
                + "Use MPC ceremony outputs (Hermez, Zcash PoT) for production.");

        var rng = new SecureRandom();
        int n = 1 << power;

        // Sample toxic waste tau from 512-bit random (negligible bias)
        byte[] tauBytes = new byte[64];
        rng.nextBytes(tauBytes);
        BigInteger tau = new BigInteger(1, tauBytes).mod(FR);

        // Compute tau^i * G1 for i = 0..2n
        // Need 2n+1 points: PlonK quotient T3 may have up to n+3 coefficients with blinding,
        // and the KZG commit requires srs.length >= coeffs.length
        int numG1 = 2 * n + 1;
        AffineG1[] tauG1 = new AffineG1[numG1];

        var g1 = JacobianG1BN254.GENERATOR;
        BigInteger tauPow = BigInteger.ONE;
        for (int i = 0; i < numG1; i++) {
            tauG1[i] = g1.scalarMul(tauPow).toAffine();
            tauPow = tauPow.multiply(tau).mod(FR);
        }

        // Compute tau^i * G2 for i = 0..1
        // Only two G2 points needed: G2 and tau*G2
        AffineG2[] tauG2 = new AffineG2[2];
        var g2 = JacobianG2BN254.GENERATOR;
        tauG2[0] = g2.toAffine();
        tauG2[1] = g2.scalarMul(tau).toAffine();

        // Discard toxic waste — best-effort in Java.
        // NOTE: BigInteger is immutable. Reassigning tau = ZERO does NOT overwrite the original
        // object's internal int[] in memory. The original tau value persists until GC collects it.
        // Intermediate tauPow values also litter the heap as unreachable BigInteger objects.
        // For a development-only tool this is acceptable. For production MPC ceremonies,
        // use native memory (MemorySegment) with explicit zeroing.
        Arrays.fill(tauBytes, (byte) 0);
        tau = BigInteger.ZERO;
        tauPow = BigInteger.ZERO;

        return new PtauImporter.SRS(tauG1, tauG2, power);
    }

    /**
     * Generate a small Powers of Tau SRS for quick testing.
     * Equivalent to {@code generate(8)} (supports circuits up to 256 constraints).
     *
     * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b> See {@link #generate(int)} for details.</p>
     */
    public static PtauImporter.SRS generateForTesting() {
        return generate(8);
    }
}
