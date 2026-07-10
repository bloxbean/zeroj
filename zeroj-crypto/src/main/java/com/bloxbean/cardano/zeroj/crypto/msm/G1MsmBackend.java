package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;

import java.math.BigInteger;

/**
 * Pluggable G1 multi-scalar-multiplication backend for the Groth16 prover (ADR-0029 M7).
 *
 * <p>The prover routes each G1 MSM through this seam so the pure-Java flat MSM
 * ({@link #PURE_JAVA}) can be swapped for a native one (e.g. the FFM blst
 * {@code blst_p1s_mult_pippenger} binding, ~2.5–3.8× on the MSM) without touching the prover logic.
 * The blst backend lives in an opt-in module so {@code zeroj-crypto} stays JNI/native-free by
 * default.</p>
 */
@FunctionalInterface
public interface G1MsmBackend {

    /**
     * {@code Σ scalars[i] · point_i}, reading points from {@code reader} (heap or mmap-backed)
     * and scalars from packed canonical limbs (ADR-0034 M3).
     */
    JacobianG1BLS381 msm(PippengerFlatBLS381.G1AffineReader reader, int n, FlatScalars scalars);

    /** Boxed-scalar form: packs once (reducing out-of-range values), then runs the flat path. */
    default JacobianG1BLS381 msm(PippengerFlatBLS381.G1AffineReader reader, int n, BigInteger[] scalars) {
        return msm(reader, n, FlatScalars.pack(scalars, n));
    }

    /** The default pure-Java, allocation-lean flat Pippenger (native-image-clean). */
    G1MsmBackend PURE_JAVA = PippengerFlatBLS381::msmReader;
}
