package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;

import java.math.BigInteger;

/**
 * A PlonK proof: 9 G1 point commitments + 6 scalar evaluations.
 *
 * <p>Matches the snarkjs PlonK proof format.</p>
 */
public record PlonKProof(
        // Round 1: wire commitments
        AffineG1 commitA, AffineG1 commitB, AffineG1 commitC,
        // Round 2: permutation accumulator
        AffineG1 commitZ,
        // Round 3: quotient polynomial (split into 3 parts)
        AffineG1 commitT1, AffineG1 commitT2, AffineG1 commitT3,
        // Round 4: opening evaluations
        BigInteger evalA, BigInteger evalB, BigInteger evalC,
        BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
        // Round 5: opening proofs
        AffineG1 commitWxi, AffineG1 commitWxiw
) {}
