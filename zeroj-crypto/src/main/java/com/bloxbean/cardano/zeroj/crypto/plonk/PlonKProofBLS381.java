package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;

import java.math.BigInteger;

/**
 * A PlonK proof for BLS12-381: 9 G1 point commitments + 6 scalar evaluations.
 */
public record PlonKProofBLS381(
        AffineG1 commitA, AffineG1 commitB, AffineG1 commitC,
        AffineG1 commitZ,
        AffineG1 commitT1, AffineG1 commitT2, AffineG1 commitT3,
        BigInteger evalA, BigInteger evalB, BigInteger evalC,
        BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
        AffineG1 commitWxi, AffineG1 commitWxiw
) {}
