package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254.AffineG2;

/**
 * A Groth16 proof: three group elements (A in G1, B in G2, C in G1).
 */
public record Groth16Proof(AffineG1 a, AffineG2 b, AffineG1 c) {}
