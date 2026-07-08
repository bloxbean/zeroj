package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.msm.G1MsmBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.G2MsmBackend;

/**
 * The MSM backends the Groth16 prover uses (ADR-0029 M7/M8) — G1 and G2. {@link #PURE_JAVA} is the
 * native-image-clean default; an opt-in module can supply FFM-blst backends for both.
 */
public record ProverBackend(G1MsmBackend g1, G2MsmBackend g2) {

    /** Pure-Java, native-image-clean (flat G1 Pippenger + object-based G2 MSM). */
    public static final ProverBackend PURE_JAVA =
            new ProverBackend(G1MsmBackend.PURE_JAVA, Groth16ProverBLS381::g2Msm);
}
