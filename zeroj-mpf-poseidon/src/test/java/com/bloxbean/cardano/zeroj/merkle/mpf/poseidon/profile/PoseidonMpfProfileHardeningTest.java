package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PoseidonMpfProfileHardeningTest {
    @Test
    void acceptsOnlyTheExactReviewedParameterBundle() {
        PoseidonParams params = PoseidonParamsBLS12_381T3.INSTANCE;
        org.junit.jupiter.api.Assertions.assertEquals(
                "4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2",
                PoseidonMpfProfile.PARAMETER_FINGERPRINT);
        assertDoesNotThrow(() -> PoseidonMpfProfile.requireSupported(params));

        var constants = params.c();
        constants[0] = constants[0].add(java.math.BigInteger.ONE).mod(params.field().prime());
        PoseidonParams changed = new PoseidonParams(
                params.field(), params.t(), params.alpha(), params.rf(), params.rp(), constants, params.m());
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfProfile.requireSupported(changed));
    }
}
