package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.mpf.proof.ProofVerifier;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Reference verifier for Poseidon-rooted MPF proofs using CCL's public proof
 * verifier and the ZeroJ Poseidon adapters.
 */
public final class PoseidonMpfReference {
    private PoseidonMpfReference() {}

    public static boolean including(byte[] expectedRoot, byte[] key, byte[] value, byte[] proofCbor) {
        return verify(PoseidonParamsBLS12_381T3.INSTANCE, expectedRoot, key, value, true, proofCbor);
    }

    public static boolean excluding(byte[] expectedRoot, byte[] key, byte[] proofCbor) {
        return verify(PoseidonParamsBLS12_381T3.INSTANCE, expectedRoot, key, null, false, proofCbor);
    }

    public static boolean verify(
            PoseidonParams params,
            byte[] expectedRoot,
            byte[] key,
            byte[] value,
            boolean including,
            byte[] proofCbor) {
        return ProofVerifier.verify(
                expectedRoot,
                key,
                value,
                including,
                proofCbor,
                new PoseidonMpfHashFunction(params),
                new PoseidonMpfCommitmentScheme(params));
    }
}
