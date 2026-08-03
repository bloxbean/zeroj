package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import org.junit.jupiter.api.Test;

import java.util.Set;

/** Optional Julc bridge for a manifest-bound JMT benchmark artifact bundle. */
class PoseidonJmtCardanoArtifactTest extends PoseidonCardanoArtifactTestSupport {
    @Test
    void realPoseidonJmtProofPassesJulcVmAndMutatedRootFails() throws Exception {
        verifyArtifact(
                "zeroj.poseidonJmt.cardanoArtifacts",
                "PoseidonJmtCardano",
                "zeroj-poseidon-jmt-v1",
                Set.of(
                        "zeroj-jmt-v1-inclusion-s8-p1",
                        "zeroj-jmt-v1-inclusion-s10-p1",
                        "zeroj-jmt-v1-inclusion-s12-p1",
                        "zeroj-jmt-v1-inclusion-s64-p1"));
    }
}
