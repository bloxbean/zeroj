package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;

import java.math.BigInteger;

/**
 * Pluggable G2 multi-scalar-multiplication backend for the Groth16 prover (ADR-0029 M8).
 *
 * <p>The prover's single G2 MSM ({@code computePiB_G2}) is its dominant cost in pure Java, so routing
 * it through this seam lets the object-based {@code g2Msm} be swapped for the FFM blst
 * {@code blst_p2s_mult_pippenger} binding.</p>
 */
@FunctionalInterface
public interface G2MsmBackend {
    /** {@code Σ scalars[i] · points[i]} over the first {@code n} points. */
    JacobianG2BLS381 msm(AffineG2[] points, BigInteger[] scalars, int n);
}
