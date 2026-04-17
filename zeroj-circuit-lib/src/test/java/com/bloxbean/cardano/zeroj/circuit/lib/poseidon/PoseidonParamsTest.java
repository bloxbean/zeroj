package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonConstants;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the generated Poseidon parameter presets.
 *
 * <p>The BN254 preset is cross-checked against the existing
 * {@link PoseidonConstants} (which was itself produced by the hadeshash Sage
 * script via circomlibjs). This closes the loop: codegen output =
 * {@link PoseidonGrainLFSR} output = circomlibjs output.
 *
 * <p>The BLS12-381 preset is checked for structural validity and for byte-match
 * against the regression fixtures in {@link PoseidonGrainLFSRTest}.
 */
class PoseidonParamsTest {

    @Test
    @DisplayName("PoseidonParamsBN254T3.INSTANCE C matches committed circomlibjs reference")
    void bn254T3_roundConstants_matchCircomlibReference() {
        PoseidonParams p = PoseidonParamsBN254T3.INSTANCE;
        assertEquals(FieldConfig.BN254, p.field());
        assertEquals(3, p.t());
        assertEquals(5, p.alpha());
        assertEquals(8, p.rf());
        assertEquals(57, p.rp());
        assertEquals(195, p.c().length);
        assertArrayEquals(PoseidonConstants.C, p.c(),
                "BN254 C diverged from circomlibjs reference — codegen or LFSR is broken");
    }

    @Test
    @DisplayName("PoseidonParamsBN254T3.INSTANCE M matches committed circomlibjs reference")
    void bn254T3_mds_matchesCircomlibReference() {
        PoseidonParams p = PoseidonParamsBN254T3.INSTANCE;
        assertEquals(9, p.m().length);
        assertArrayEquals(PoseidonConstants.M, p.m(),
                "BN254 M diverged from circomlibjs reference — codegen or LFSR is broken");
    }

    @Test
    @DisplayName("PoseidonParamsBLS12_381T3.INSTANCE is well-formed")
    void bls12_381_t3_isWellFormed() {
        PoseidonParams p = PoseidonParamsBLS12_381T3.INSTANCE;
        assertEquals(FieldConfig.BLS12_381, p.field());
        assertEquals(3, p.t());
        assertEquals(5, p.alpha());
        assertEquals(8, p.rf());
        assertEquals(57, p.rp());
        assertEquals(195, p.c().length);
        assertEquals(9, p.m().length);

        BigInteger prime = FieldConfig.BLS12_381.prime();
        for (int i = 0; i < p.c().length; i++) {
            assertTrue(p.c()[i].signum() >= 0 && p.c()[i].compareTo(prime) < 0,
                    "C[" + i + "] out of range");
        }
        for (int i = 0; i < p.m().length; i++) {
            assertTrue(p.m()[i].signum() > 0 && p.m()[i].compareTo(prime) < 0,
                    "M[" + i + "] out of range");
        }
    }

    @Test
    @DisplayName("PoseidonParamsBLS12_381T3.INSTANCE matches fresh LFSR regeneration")
    void bls12_381_t3_codegenMatchesLfsrOutput() {
        PoseidonParams committed = PoseidonParamsBLS12_381T3.INSTANCE;

        PoseidonGrainLFSR gen = PoseidonGrainLFSR.forGFp(255, 3, 8, 57, FieldConfig.BLS12_381.prime());
        BigInteger[] freshC = gen.generateRoundConstants();
        BigInteger[][] freshMMatrix = gen.generateMdsMatrix();
        BigInteger[] freshM = new BigInteger[9];
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                freshM[i * 3 + j] = freshMMatrix[i][j];
            }
        }

        assertArrayEquals(freshC, committed.c(),
                "Committed BLS12-381 C diverged from fresh LFSR output — run :generatePoseidonParams");
        assertArrayEquals(freshM, committed.m(),
                "Committed BLS12-381 M diverged from fresh LFSR output — run :generatePoseidonParams");
    }

    @Test
    @DisplayName("PoseidonParams record defensively copies arrays")
    void record_isImmutable() {
        PoseidonParams p = PoseidonParamsBN254T3.INSTANCE;
        BigInteger[] c1 = p.c();
        BigInteger[] c2 = p.c();
        assertNotSame(c1, c2, "accessors must return defensive copies");
        c1[0] = BigInteger.ZERO;
        assertEquals(p.c()[0], c2[0], "mutating returned array must not affect record");
    }

    @Test
    @DisplayName("PoseidonParams constructor rejects mismatched array sizes")
    void constructor_rejectsInvalidSizes() {
        BigInteger[] wrongC = new BigInteger[10];
        BigInteger[] validM = new BigInteger[9];
        for (int i = 0; i < wrongC.length; i++) wrongC[i] = BigInteger.ZERO;
        for (int i = 0; i < validM.length; i++) validM[i] = BigInteger.ONE;
        assertThrows(IllegalArgumentException.class, () ->
                new PoseidonParams(FieldConfig.BN254, 3, 5, 8, 57, wrongC, validM));
    }

    @Test
    @DisplayName("totalRounds() returns rf + rp")
    void totalRounds_isSum() {
        assertEquals(65, PoseidonParamsBN254T3.INSTANCE.totalRounds());
        assertEquals(65, PoseidonParamsBLS12_381T3.INSTANCE.totalRounds());
    }

    @Test
    @DisplayName("cAt(r, i) and mAt(i, j) access row-major layout correctly")
    void rowMajorAccessors_work() {
        PoseidonParams p = PoseidonParamsBN254T3.INSTANCE;
        assertEquals(p.c()[0], p.cAt(0, 0));
        assertEquals(p.c()[1], p.cAt(0, 1));
        assertEquals(p.c()[3], p.cAt(1, 0));
        assertEquals(p.m()[0], p.mAt(0, 0));
        assertEquals(p.m()[4], p.mAt(1, 1));
        assertEquals(p.m()[8], p.mAt(2, 2));
    }
}
