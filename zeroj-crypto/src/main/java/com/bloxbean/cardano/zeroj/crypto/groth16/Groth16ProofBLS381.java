package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;

/**
 * A Groth16 proof for BLS12-381: three group elements (A in G1, B in G2, C in G1).
 */
public record Groth16ProofBLS381(AffineG1 a, AffineG2 b, AffineG1 c) {}
