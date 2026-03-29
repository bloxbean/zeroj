package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.kzg.KZGCommitment;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFT;

import java.math.BigInteger;

/**
 * PlonK trusted setup from a DSL-compiled PlonK constraint system + SRS.
 *
 * <p>Takes the output of {@code PlonKCompiler} (gate rows + sigma permutation)
 * and an SRS from a Powers of Tau ceremony, and produces a {@link PlonKProvingKey}
 * with committed selector/permutation polynomials.</p>
 *
 * <p>This replaces the snarkjs {@code plonk setup} command for DSL-defined circuits.</p>
 */
public final class PlonKSetup {

    private PlonKSetup() {}

    private static final BigInteger FR = MontFr254.modulus();

    /**
     * Perform PlonK setup: compile selector/permutation polynomials and commit via KZG.
     *
     * @param numGates    number of gate rows (from PlonKConstraintSystem)
     * @param numPublic   number of public inputs
     * @param gateRows    gate selector values per row: [qL, qR, qO, qM, qC]
     * @param sigmaA      sigma permutation for column A
     * @param sigmaB      sigma permutation for column B
     * @param sigmaC      sigma permutation for column C
     * @param numWires    total number of wires
     * @param srs         SRS from .ptau import
     * @return proving key with committed selectors and SRS
     */
    public static PlonKProvingKey setup(
            int numGates, int numPublic,
            BigInteger[][] gateSelectors, // [numGates][5] = [qL, qR, qO, qM, qC]
            int[] sigmaA, int[] sigmaB, int[] sigmaC,
            int numWires,
            PtauImporter.SRS srs) {

        // Domain size = next power of 2 >= numGates
        int domainSize = Integer.highestOneBit(numGates);
        if (domainSize < numGates) domainSize <<= 1;
        if (domainSize < 4) domainSize = 4; // minimum for FFT
        int logN = Integer.numberOfTrailingZeros(domainSize);

        MontFr254 omega = FieldFFT.rootOfUnity(logN);
        BigInteger k1 = BigInteger.TWO;
        BigInteger k2 = BigInteger.valueOf(3);

        // Build selector polynomial evaluations on the domain
        MontFr254[] ql = new MontFr254[domainSize];
        MontFr254[] qr = new MontFr254[domainSize];
        MontFr254[] qm = new MontFr254[domainSize];
        MontFr254[] qo = new MontFr254[domainSize];
        MontFr254[] qc = new MontFr254[domainSize];

        for (int i = 0; i < domainSize; i++) {
            if (i < numGates && gateSelectors[i] != null) {
                ql[i] = MontFr254.fromBigInteger(gateSelectors[i][0]);
                qr[i] = MontFr254.fromBigInteger(gateSelectors[i][1]);
                qo[i] = MontFr254.fromBigInteger(gateSelectors[i][2]);
                qm[i] = MontFr254.fromBigInteger(gateSelectors[i][3]);
                qc[i] = MontFr254.fromBigInteger(gateSelectors[i][4]);
            } else {
                ql[i] = qr[i] = qm[i] = qo[i] = qc[i] = MontFr254.ZERO;
            }
        }

        // Build sigma (permutation) polynomial evaluations
        // sigma maps position (col, row) → target position
        // The sigma polynomial encodes: sigma1(omega^i) = omega^{sigma_a[i]} * k_col
        // where k_col = 1 for col A, k1 for col B, k2 for col C
        MontFr254[] s1 = new MontFr254[domainSize];
        MontFr254[] s2 = new MontFr254[domainSize];
        MontFr254[] s3 = new MontFr254[domainSize];

        MontFr254 k1Fr = MontFr254.fromBigInteger(k1);
        MontFr254 k2Fr = MontFr254.fromBigInteger(k2);

        for (int i = 0; i < domainSize; i++) {
            // Default: identity permutation
            // Position i in col A → omega^i
            // Position i in col B → k1 * omega^i
            // Position i in col C → k2 * omega^i
            MontFr254 omegaI = evalOmegaPow(omega, i);

            if (i < numGates) {
                // sigma_a[i] gives the flattened target: target = row + col * numGates
                s1[i] = decodeSigmaTarget(sigmaA[i], numGates, omega, k1Fr, k2Fr);
                s2[i] = decodeSigmaTarget(sigmaB[i], numGates, omega, k1Fr, k2Fr);
                s3[i] = decodeSigmaTarget(sigmaC[i], numGates, omega, k1Fr, k2Fr);
            } else {
                // Padding rows: identity permutation
                s1[i] = omegaI;
                s2[i] = k1Fr.mul(omegaI);
                s3[i] = k2Fr.mul(omegaI);
            }
        }

        // Convert to coefficient form and commit via KZG
        var qlCoeffs = FieldFFT.ifft(ql);
        var qrCoeffs = FieldFFT.ifft(qr);
        var qmCoeffs = FieldFFT.ifft(qm);
        var qoCoeffs = FieldFFT.ifft(qo);
        var qcCoeffs = FieldFFT.ifft(qc);
        var s1Coeffs = FieldFFT.ifft(s1);
        var s2Coeffs = FieldFFT.ifft(s2);
        var s3Coeffs = FieldFFT.ifft(s3);

        AffineG1[] srsG1 = srs.tauG1();

        var qmCommit = KZGCommitment.commit(srsG1, qmCoeffs).toAffine();
        var qlCommit = KZGCommitment.commit(srsG1, qlCoeffs).toAffine();
        var qrCommit = KZGCommitment.commit(srsG1, qrCoeffs).toAffine();
        var qoCommit = KZGCommitment.commit(srsG1, qoCoeffs).toAffine();
        var qcCommit = KZGCommitment.commit(srsG1, qcCoeffs).toAffine();
        var s1Commit = KZGCommitment.commit(srsG1, s1Coeffs).toAffine();
        var s2Commit = KZGCommitment.commit(srsG1, s2Coeffs).toAffine();
        var s3Commit = KZGCommitment.commit(srsG1, s3Coeffs).toAffine();

        return new PlonKProvingKey(
                domainSize, numPublic, numGates, k1, k2, omega,
                ql, qr, qm, qo, qc, s1, s2, s3,
                srsG1, srsG1, // lagrange SRS = standard SRS for now
                srs.x2(),
                qmCommit, qlCommit, qrCommit, qoCommit, qcCommit,
                s1Commit, s2Commit, s3Commit);
    }

    /** Decode a sigma permutation target from flattened index. */
    private static MontFr254 decodeSigmaTarget(int flatIdx, int numGates,
                                                 MontFr254 omega, MontFr254 k1, MontFr254 k2) {
        int row = flatIdx % numGates;
        int col = flatIdx / numGates;
        MontFr254 omegaRow = evalOmegaPow(omega, row);
        return switch (col) {
            case 0 -> omegaRow;                 // column A: omega^row
            case 1 -> k1.mul(omegaRow);          // column B: k1 * omega^row
            case 2 -> k2.mul(omegaRow);          // column C: k2 * omega^row
            default -> omegaRow;
        };
    }

    private static MontFr254 evalOmegaPow(MontFr254 omega, int exp) {
        if (exp == 0) return MontFr254.ONE;
        MontFr254 result = omega;
        for (int i = 1; i < exp; i++) result = result.mul(omega);
        return result;
    }
}
