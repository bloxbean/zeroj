package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import org.junit.jupiter.api.Test;

import java.util.Set;

/** Optional Julc bridge for a manifest-bound MPF benchmark artifact bundle. */
class PoseidonMpfCardanoArtifactTest extends PoseidonCardanoArtifactTestSupport {
    @Test
    void realPoseidonMpfProofPassesJulcVmAndMutatedRootFails() throws Exception {
        verifyArtifact(
                "zeroj.poseidonMpf.cardanoArtifacts",
                "PoseidonMpfCardano",
                "zeroj-poseidon-mpf-v1",
                Set.of(
                        "zeroj-mpf-v1-inclusion-s8-p1",
                        "zeroj-mpf-v1-inclusion-s9-p1",
                        "zeroj-mpf-v1-inclusion-s12-p1"));
    }
}
