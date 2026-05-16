package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;

import java.math.BigInteger;

/**
 * PlonK proving key for BLS12-381.
 *
 * @see PlonKProvingKey
 */
public record PlonKProvingKeyBLS381(
        int domainSize,
        int nPublic,
        int nConstraints,
        BigInteger k1,
        BigInteger k2,
        MontFr381 omega,
        MontFr381[] ql, MontFr381[] qr, MontFr381[] qm, MontFr381[] qo, MontFr381[] qc,
        MontFr381[] s1, MontFr381[] s2, MontFr381[] s3,
        AffineG1[] srsG1,
        AffineG1[] srsG1Lagrange,
        AffineG2 x2,
        AffineG1 qmCommit, AffineG1 qlCommit, AffineG1 qrCommit,
        AffineG1 qoCommit, AffineG1 qcCommit,
        AffineG1 s1Commit, AffineG1 s2Commit, AffineG1 s3Commit
) {}
