package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.kzg.KZGCommitmentBLS381;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;

import java.math.BigInteger;

/**
 * PlonK trusted setup for BLS12-381 from a DSL-compiled PlonK constraint system + SRS.
 *
 * <p>Takes the output of {@code PlonKCompiler} (gate rows + sigma permutation)
 * and an SRS from a Powers of Tau ceremony, and produces a {@link PlonKProvingKeyBLS381}
 * with committed selector/permutation polynomials.</p>
 *
 * <p>This replaces the snarkjs {@code plonk setup} command for DSL-defined circuits.</p>
 */
public final class PlonKSetupBLS381 {

    private PlonKSetupBLS381() {}

    private static final BigInteger FR = MontFr381.modulus();

    /**
     * Perform PlonK setup: compile selector/permutation polynomials and commit via KZG.
     *
     * @param numGates    number of gate rows (from PlonKConstraintSystem)
     * @param numPublic   number of public inputs
     * @param gateSelectors gate selector values per row: [qL, qR, qO, qM, qC]
     * @param sigmaA      sigma permutation for column A
     * @param sigmaB      sigma permutation for column B
     * @param sigmaC      sigma permutation for column C
     * @param numWires    total number of wires
     * @param srs         SRS from .ptau import
     * @return proving key with committed selectors and SRS
     */
    public static PlonKProvingKeyBLS381 setup(
            int numGates, int numPublic,
            BigInteger[][] gateSelectors, // [numGates][5] = [qL, qR, qO, qM, qC]
            int[] sigmaA, int[] sigmaB, int[] sigmaC,
            int numWires,
            PtauImporterBLS381.SRS srs) {

        // Domain size = next power of 2 >= numGates
        // Minimum 8: with blinding (degree n+2 wire/Z polynomials), the quotient
        // numerator has degree ~3n+6. The 4n coset needs 4n > 3n+6, i.e., n > 6.
        int domainSize = Integer.highestOneBit(numGates);
        if (domainSize < numGates) domainSize <<= 1;
        if (domainSize < 8) domainSize = 8; // minimum for blinding with 4n coset
        int logN = Integer.numberOfTrailingZeros(domainSize);

        MontFr381 omega = FieldFFTBLS381.rootOfUnity(logN);
        BigInteger k1 = BigInteger.TWO;
        BigInteger k2 = BigInteger.valueOf(3);

        // Build selector polynomial evaluations on the domain
        MontFr381[] ql = new MontFr381[domainSize];
        MontFr381[] qr = new MontFr381[domainSize];
        MontFr381[] qm = new MontFr381[domainSize];
        MontFr381[] qo = new MontFr381[domainSize];
        MontFr381[] qc = new MontFr381[domainSize];

        for (int i = 0; i < domainSize; i++) {
            if (i < numGates && gateSelectors[i] != null) {
                ql[i] = MontFr381.fromBigInteger(gateSelectors[i][0]);
                qr[i] = MontFr381.fromBigInteger(gateSelectors[i][1]);
                qo[i] = MontFr381.fromBigInteger(gateSelectors[i][2]);
                qm[i] = MontFr381.fromBigInteger(gateSelectors[i][3]);
                qc[i] = MontFr381.fromBigInteger(gateSelectors[i][4]);
            } else {
                ql[i] = qr[i] = qm[i] = qo[i] = qc[i] = MontFr381.ZERO;
            }
        }

        // Build sigma (permutation) polynomial evaluations
        // sigma maps position (col, row) -> target position
        // The sigma polynomial encodes: sigma1(omega^i) = omega^{sigma_a[i]} * k_col
        // where k_col = 1 for col A, k1 for col B, k2 for col C
        MontFr381[] s1 = new MontFr381[domainSize];
        MontFr381[] s2 = new MontFr381[domainSize];
        MontFr381[] s3 = new MontFr381[domainSize];

        MontFr381 k1Fr = MontFr381.fromBigInteger(k1);
        MontFr381 k2Fr = MontFr381.fromBigInteger(k2);

        for (int i = 0; i < domainSize; i++) {
            // Default: identity permutation
            // Position i in col A -> omega^i
            // Position i in col B -> k1 * omega^i
            // Position i in col C -> k2 * omega^i
            MontFr381 omegaI = evalOmegaPow(omega, i);

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
        var qlCoeffs = FieldFFTBLS381.ifft(ql);
        var qrCoeffs = FieldFFTBLS381.ifft(qr);
        var qmCoeffs = FieldFFTBLS381.ifft(qm);
        var qoCoeffs = FieldFFTBLS381.ifft(qo);
        var qcCoeffs = FieldFFTBLS381.ifft(qc);
        var s1Coeffs = FieldFFTBLS381.ifft(s1);
        var s2Coeffs = FieldFFTBLS381.ifft(s2);
        var s3Coeffs = FieldFFTBLS381.ifft(s3);

        AffineG1[] srsG1 = srs.tauG1();

        var qmCommit = KZGCommitmentBLS381.commit(srsG1, qmCoeffs).toAffine();
        var qlCommit = KZGCommitmentBLS381.commit(srsG1, qlCoeffs).toAffine();
        var qrCommit = KZGCommitmentBLS381.commit(srsG1, qrCoeffs).toAffine();
        var qoCommit = KZGCommitmentBLS381.commit(srsG1, qoCoeffs).toAffine();
        var qcCommit = KZGCommitmentBLS381.commit(srsG1, qcCoeffs).toAffine();
        var s1Commit = KZGCommitmentBLS381.commit(srsG1, s1Coeffs).toAffine();
        var s2Commit = KZGCommitmentBLS381.commit(srsG1, s2Coeffs).toAffine();
        var s3Commit = KZGCommitmentBLS381.commit(srsG1, s3Coeffs).toAffine();

        return new PlonKProvingKeyBLS381(
                domainSize, numPublic, numGates, k1, k2, omega,
                ql, qr, qm, qo, qc, s1, s2, s3,
                srsG1, srsG1, // lagrange SRS = standard SRS for now
                srs.x2(),
                qmCommit, qlCommit, qrCommit, qoCommit, qcCommit,
                s1Commit, s2Commit, s3Commit);
    }

    /** Decode a sigma permutation target from flattened index. */
    private static MontFr381 decodeSigmaTarget(int flatIdx, int numGates,
                                                 MontFr381 omega, MontFr381 k1, MontFr381 k2) {
        int row = flatIdx % numGates;
        int col = flatIdx / numGates;
        MontFr381 omegaRow = evalOmegaPow(omega, row);
        return switch (col) {
            case 0 -> omegaRow;                 // column A: omega^row
            case 1 -> k1.mul(omegaRow);          // column B: k1 * omega^row
            case 2 -> k2.mul(omegaRow);          // column C: k2 * omega^row
            default -> omegaRow;
        };
    }

    private static MontFr381 evalOmegaPow(MontFr381 omega, int exp) {
        if (exp == 0) return MontFr381.ONE;
        MontFr381 result = omega;
        for (int i = 1; i < exp; i++) result = result.mul(omega);
        return result;
    }
}
