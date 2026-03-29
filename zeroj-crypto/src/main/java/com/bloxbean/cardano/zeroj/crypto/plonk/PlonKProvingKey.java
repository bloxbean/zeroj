package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;

import java.math.BigInteger;

/**
 * PlonK proving key for BN254.
 *
 * <p>Contains the selector polynomial evaluations, permutation polynomial evaluations,
 * SRS points, and committed verification key points needed for the 5-round PlonK prover.</p>
 *
 * @param domainSize    FFT domain size (power of 2)
 * @param nPublic       number of public inputs
 * @param nConstraints  number of PlonK constraints (gate rows)
 * @param k1            coset shift factor k1 (for sigma permutation)
 * @param k2            coset shift factor k2
 * @param omega         primitive root of unity for the domain
 * @param ql            Ql selector polynomial evaluations on the domain
 * @param qr            Qr selector polynomial evaluations
 * @param qm            Qm selector polynomial evaluations
 * @param qo            Qo selector polynomial evaluations
 * @param qc            Qc selector polynomial evaluations
 * @param s1            sigma1 permutation polynomial evaluations
 * @param s2            sigma2 permutation polynomial evaluations
 * @param s3            sigma3 permutation polynomial evaluations
 * @param srsG1         SRS points in G1: [tau^0]_1, [tau^1]_1, ..., [tau^d]_1
 * @param srsG1Lagrange SRS points in Lagrange basis (for evaluation-form commitments)
 * @param x2            SRS second point in G2: [tau]_2
 * @param qmCommit      Qm commitment (from verification key)
 * @param qlCommit      Ql commitment
 * @param qrCommit      Qr commitment
 * @param qoCommit      Qo commitment
 * @param qcCommit      Qc commitment
 * @param s1Commit      S1 commitment
 * @param s2Commit      S2 commitment
 * @param s3Commit      S3 commitment
 */
public record PlonKProvingKey(
        int domainSize,
        int nPublic,
        int nConstraints,
        BigInteger k1,
        BigInteger k2,
        MontFr254 omega,
        MontFr254[] ql, MontFr254[] qr, MontFr254[] qm, MontFr254[] qo, MontFr254[] qc,
        MontFr254[] s1, MontFr254[] s2, MontFr254[] s3,
        AffineG1[] srsG1,
        AffineG1[] srsG1Lagrange,
        AffineG2 x2,
        AffineG1 qmCommit, AffineG1 qlCommit, AffineG1 qrCommit,
        AffineG1 qoCommit, AffineG1 qcCommit,
        AffineG1 s1Commit, AffineG1 s2Commit, AffineG1 s3Commit
) {}
