package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PoseidonJmtProfileHardeningTest {
    @Test
    void acceptsOnlyTheExactReviewedFieldAndParameterBundle() {
        PoseidonParams params = PoseidonParamsBLS12_381T3.INSTANCE;
        assertEquals("4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2",
                PoseidonJmtProfile.PARAMETER_FINGERPRINT);
        assertDoesNotThrow(() -> PoseidonJmtProfile.requireSupported(params));

        FieldConfig renamedField = new FieldConfig(
                CurveId.BN254, params.field().prime(), params.field().n32(), "renamed");
        PoseidonParams wrongField = new PoseidonParams(
                renamedField, params.t(), params.alpha(), params.rf(), params.rp(), params.c(), params.m());
        assertThrows(IllegalArgumentException.class, () -> PoseidonJmtProfile.requireSupported(wrongField));

        var matrix = params.m();
        matrix[0] = matrix[0].add(java.math.BigInteger.ONE).mod(params.field().prime());
        PoseidonParams changed = new PoseidonParams(
                params.field(), params.t(), params.alpha(), params.rf(), params.rp(), params.c(), matrix);
        assertThrows(IllegalArgumentException.class, () -> PoseidonJmtProfile.requireSupported(changed));
    }

    @Test
    void branchPathRequiresCanonicalSiblingsAndEmptySubtreesMatchFullBranch() {
        byte[][] emptyChildren = new byte[PoseidonJmtProfile.RADIX][];
        byte[] emptyBranch = PoseidonJmtCommitments.branch(emptyChildren);
        for (int child = 0; child < PoseidonJmtProfile.RADIX; child++) {
            assertArrayEquals(emptyBranch, PoseidonJmtCommitments.branchPath(
                    child,
                    null,
                    java.util.List.of(
                            PoseidonJmtCommitments.emptySubtree(0),
                            PoseidonJmtCommitments.emptySubtree(1),
                            PoseidonJmtCommitments.emptySubtree(2),
                            PoseidonJmtCommitments.emptySubtree(3))));
        }
        assertThrows(NullPointerException.class, () -> PoseidonJmtCommitments.branchPath(
                0, null, java.util.Arrays.asList(
                        null,
                        PoseidonJmtCommitments.emptySubtree(1),
                        PoseidonJmtCommitments.emptySubtree(2),
                        PoseidonJmtCommitments.emptySubtree(3))));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonJmtCommitments.emptySubtree(-1));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonJmtCommitments.emptySubtree(4));
    }

    @Test
    void byteHashIsTotalAcrossFixedAndFallbackBoundaries() {
        for (int length : new int[]{0, 1, 31, 32, 33, 95, 96, 97, 4096}) {
            byte[] value = new byte[length];
            java.util.Arrays.fill(value, (byte) 0xff);
            byte[] first = PoseidonJmtHash.digest(value);
            assertArrayEquals(first, PoseidonJmtHash.digest(value));
            assertDoesNotThrow(() -> PoseidonJmtHash.decode(first));
        }
    }
}
