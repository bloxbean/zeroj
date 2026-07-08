package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.msm.G1MsmBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.G2MsmBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.ParallelMsm;

/**
 * The MSM backends the Groth16 prover uses (ADR-0029 M7/M8) — G1 and G2. {@link #PURE_JAVA} is the
 * native-image-clean default; an opt-in module can supply FFM-blst backends for both.
 */
public record ProverBackend(G1MsmBackend g1, G2MsmBackend g2) {

    /**
     * Pure-Java, native-image-clean (flat G1 Pippenger + object-based G2 MSM), multi-core: large
     * MSMs are chunked across cores via {@link ParallelMsm} (ADR-0029 M5b). Point addition is
     * associative, so the affine result — and therefore the proof — is identical to the serial
     * path. {@link #PURE_JAVA_SERIAL} keeps the single-threaded backends for differential testing
     * or core-constrained environments.
     */
    public static final ProverBackend PURE_JAVA = new ProverBackend(
            ParallelMsm.parallel(G1MsmBackend.PURE_JAVA),
            ParallelMsm.parallel(Groth16ProverBLS381::g2Msm));

    /** The single-threaded pure-Java backends (pre-M5b behavior). */
    public static final ProverBackend PURE_JAVA_SERIAL =
            new ProverBackend(G1MsmBackend.PURE_JAVA, Groth16ProverBLS381::g2Msm);
}
