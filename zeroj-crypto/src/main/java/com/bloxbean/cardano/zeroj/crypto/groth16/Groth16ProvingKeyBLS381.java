package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;

/**
 * Groth16 proving key for BLS12-381.
 *
 * @see Groth16ProvingKey
 */
public record Groth16ProvingKeyBLS381(
        AffineG1 alphaG1,
        AffineG1 betaG1,
        AffineG2 betaG2,
        AffineG1 deltaG1,
        AffineG2 deltaG2,
        AffineG1[] pointsA,
        AffineG1[] pointsB1,
        AffineG2[] pointsB2,
        AffineG1[] pointsH,
        AffineG1[] pointsL,
        int numPublic
) {}
