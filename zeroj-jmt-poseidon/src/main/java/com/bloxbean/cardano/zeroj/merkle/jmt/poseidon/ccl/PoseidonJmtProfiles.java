package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.jmt.JmtProfile;
import com.bloxbean.cardano.vds.jmt.proof.ClassicJmtProofCodec;
import com.bloxbean.cardano.vds.jmt.store.JmtFormatDescriptor;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

/** Stable CCL profile factory for Poseidon JMT v1. */
public final class PoseidonJmtProfiles {
    private static final JmtFormatDescriptor FORMAT = JmtFormatDescriptor.custom(
            PoseidonJmtProfile.PROFILE_ID,
            PoseidonJmtProfile.HASH_ALGORITHM_ID,
            PoseidonJmtProfile.DIGEST_BYTES);
    private static final ClassicJmtProofCodec PROOF_CODEC = new ClassicJmtProofCodec();

    private PoseidonJmtProfiles() {}

    public static JmtFormatDescriptor format() {
        return FORMAT;
    }

    public static JmtProfile v1() {
        return v1(new PoseidonJmtHashFunction(), new PoseidonJmtCommitmentScheme());
    }

    static JmtProfile v1(
            PoseidonJmtHashFunction hashFunction,
            PoseidonJmtCommitmentScheme commitmentScheme) {
        return JmtProfile.custom(
                FORMAT,
                hashFunction,
                commitmentScheme,
                PROOF_CODEC);
    }

    static ClassicJmtProofCodec proofCodec() {
        return PROOF_CODEC;
    }
}
