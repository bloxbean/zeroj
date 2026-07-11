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
 *
 * <p>Points come from a {@link G2AffineReader} (ADR-0033 M3) so the G2 proving key can stay
 * mmap'd/off-heap like the G1 arrays; {@link #msm(AffineG2[], BigInteger[], int)} adapts an
 * on-heap array for in-RAM PKs and tests.</p>
 */
@FunctionalInterface
public interface G2MsmBackend {

    /**
     * {@code Σ scalars[i] · point_i} over the first {@code n} points of {@code points}, scalars
     * from packed canonical limbs (ADR-0034 M3).
     */
    JacobianG2BLS381 msm(G2AffineReader points, FlatScalars scalars, int n);

    /** Boxed-scalar form: packs once (reducing out-of-range values), then runs the flat path. */
    default JacobianG2BLS381 msm(G2AffineReader points, BigInteger[] scalars, int n) {
        return msm(points, FlatScalars.pack(scalars, n), n);
    }

    /** {@code Σ scalars[i] · points[i]} over the first {@code n} points of an on-heap array. */
    default JacobianG2BLS381 msm(AffineG2[] points, BigInteger[] scalars, int n) {
        return msm(new G2AffineReader.HeapG2Reader(points), FlatScalars.pack(scalars, n), n);
    }
}
