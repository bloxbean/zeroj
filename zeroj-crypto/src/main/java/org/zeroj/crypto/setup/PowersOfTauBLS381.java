package org.zeroj.crypto.setup;

import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.api.TrustedSetupPolicy;
import org.zeroj.crypto.plonk.PtauImporterBLS381;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Powers of Tau generator for BLS12-381 — development and testing only.
 *
 * <p><b>WARNING: This is a single-party generator. The toxic waste (tau) is known
 * to a single party. DO NOT use this for production deployments.</b></p>
 *
 * <p>Any insecure-dev SRS file that persists tau contains toxic waste and outlives this
 * process. Delete it and any copies after testing; owner-only permissions and file deletion
 * do not guarantee erasure from storage, snapshots or backups.</p>
 *
 * <p>For production, use independently verified, hash-pinned BLS12-381 ceremony outputs.
 * ADR-0031 records the selected Filecoin source and still-open conversion/review gates.
 * BN254 Hermez/Perpetual Powers of Tau artifacts cannot be used on BLS12-381.</p>
 */
public final class PowersOfTauBLS381 {

    private PowersOfTauBLS381() {}

    private static final BigInteger FR = MontFr381.modulus();

    /**
     * Generate a Powers of Tau SRS for BLS12-381.
     *
     * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b> A single-party SRS provides no
     * trust guarantee — the generator knows tau and could forge proofs.
     * Use {@link PtauImporterBLS381} with MPC ceremony outputs for production.</p>
     *
     * @param power log2 of the maximum circuit size (e.g., 12 for up to 4096 constraints)
     * @return SRS containing tau^i * G1 and tau^i * G2 points
     */
    public static PtauImporterBLS381.SRS generate(int power) {
        TrustedSetupPolicy.requireInsecureTrustedSetupEnabled();
        if (power < 4 || power > 32)
            throw new IllegalArgumentException("Power must be in [4, 32], got " + power
                    + " (minimum 4 required for PlonK domain size >= 8)");

        System.err.println("WARNING: Single-party Powers of Tau generation (BLS12-381) — "
                + "for DEVELOPMENT and TESTING only. "
                + "Use independently verified, hash-pinned BLS12-381 MPC ceremony outputs for production.");

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

        // ADR-0029 M5a: precompute the scalar powers (sequential, cheap Fr mults), then compute each
        // tau^i * G in parallel via the fixed-base comb. The old loop did numG1 (=2n+1) full
        // single-threaded scalarMuls — the dominant cost of a large dev SRS. ~10x (parallel) × ~1.7x
        // (fixed-base). (Production uses an MPC .ptau via PtauImporterBLS381, not this path.)
        BigInteger[] tauPows = new BigInteger[numG1];
        tauPows[0] = BigInteger.ONE;
        for (int i = 1; i < numG1; i++) tauPows[i] = tauPows[i - 1].multiply(tau).mod(FR);
        java.util.stream.IntStream.range(0, numG1).parallel().forEach(i ->
                tauG1[i] = FixedBaseG1BLS381.mulAffine(tauPows[i]));

        // Compute tau^i * G2 for i = 0..1
        // Only two G2 points needed: G2 and tau*G2
        AffineG2[] tauG2 = new AffineG2[2];
        var g2 = JacobianG2BLS381.GENERATOR;
        tauG2[0] = g2.toAffine();
        tauG2[1] = g2.scalarMul(tau).toAffine();

        // Clear owned mutable buffers/references as lifetime hygiene only. BigInteger objects,
        // their derived values, JVM copies and the intentionally returned tau are not
        // erased. This dev-only API offers no reliable heap-zeroization or constant-time contract.
        // A future production secret-processing implementation requires a separate reviewed design;
        // moving one buffer off-heap alone would not establish that contract.
        Arrays.fill(tauBytes, (byte) 0);
        Arrays.fill(tauPows, BigInteger.ZERO);

        // Retain tau for Groth16SetupBLS381 (development-only — production .ptau files do not expose tau).
        return new PtauImporterBLS381.SRS(tauG1, tauG2, power, tau);
    }

    /**
     * Generate a small Powers of Tau SRS for quick testing.
     * Equivalent to {@code generate(8)} (supports circuits up to 256 constraints).
     *
     * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b> See {@link #generate(int)} for details.</p>
     */
    public static PtauImporterBLS381.SRS generateForTesting() {
        return generate(8);
    }
}
