package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonParameterFingerprintTest {
    @Test
    void v1BindsFieldIdentityAndLegacyValueIsMigrationOnly() {
        PoseidonParams params = PoseidonParamsBLS12_381T3.INSTANCE;
        assertEquals("3920ef069c36d968b77c99cef6dbc7e6f20f957e373a28fc84d145ee0a0d824d",
                PoseidonParameterFingerprint.legacySha256(params));
        assertEquals("4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2",
                PoseidonParameterFingerprint.sha256(params));

        FieldConfig renamedField = new FieldConfig(
                CurveId.BN254, params.field().prime(), params.field().n32(), "not-bls12-381");
        PoseidonParams renamed = new PoseidonParams(
                renamedField, params.t(), params.alpha(), params.rf(), params.rp(), params.c(), params.m());
        assertNotEquals(PoseidonParameterFingerprint.sha256(params),
                PoseidonParameterFingerprint.sha256(renamed));
    }

    @Test
    void v1BindsRoundConstantsAndMdsMatrix() {
        PoseidonParams params = PoseidonParamsBLS12_381T3.INSTANCE;
        var constants = params.c();
        constants[0] = constants[0].add(java.math.BigInteger.ONE).mod(params.field().prime());
        PoseidonParams changedConstant = new PoseidonParams(
                params.field(), params.t(), params.alpha(), params.rf(), params.rp(), constants, params.m());
        assertNotEquals(PoseidonParameterFingerprint.sha256(params),
                PoseidonParameterFingerprint.sha256(changedConstant));

        var matrix = params.m();
        matrix[0] = matrix[0].add(java.math.BigInteger.ONE).mod(params.field().prime());
        PoseidonParams changedMatrix = new PoseidonParams(
                params.field(), params.t(), params.alpha(), params.rf(), params.rp(), params.c(), matrix);
        assertNotEquals(PoseidonParameterFingerprint.sha256(params),
                PoseidonParameterFingerprint.sha256(changedMatrix));
    }
}
