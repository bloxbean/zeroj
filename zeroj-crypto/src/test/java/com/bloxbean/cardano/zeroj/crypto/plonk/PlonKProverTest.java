package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyImporter;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the PlonK prover infrastructure.
 *
 * <p>The full 5-round PlonK prover requires wire map parsing from .zkey sections 4-6
 * to correctly map witness values to constraint rows. This is WIP — current tests
 * validate the proving key import, KZG commitment infrastructure, and proof structure.</p>
 */
class PlonKProverTest {

    private static final String ZKEY_PATH = "/test-circuits/plonk-multiplier/multiplier_plonk.zkey";
    private static final String WTNS_PATH = "/test-circuits/plonk-multiplier/witness.wtns";

    @Test
    void provingKeyImport_structureCorrect() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));

        assertEquals(8, pk.domainSize());
        assertEquals(2, pk.nPublic());
        assertEquals(3, pk.nConstraints());

        // SRS should have enough points for the domain
        assertTrue(pk.srsG1().length >= pk.domainSize(),
                "SRS should have at least domainSize points, got " + pk.srsG1().length);

        // Selector commitments should match VK (non-infinity for non-trivial circuits)
        assertFalse(pk.qlCommit().isInfinity(), "Ql commitment should not be infinity");
        assertFalse(pk.qmCommit().isInfinity(), "Qm commitment should not be infinity");
    }

    @Test
    void prover_producesStructurallyValidProof() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));
        var witness = ZkeyImporter.importWtns(getClass().getResourceAsStream(WTNS_PATH));

        // Generate proof (structural test — full correctness requires wire map parsing)
        var proof = PlonKProver.prove(pk, witness);

        assertNotNull(proof);

        // All 9 commitments should be valid G1 points
        assertTrue(proof.commitA().isOnCurve() || proof.commitA().isInfinity(), "A on curve");
        assertTrue(proof.commitB().isOnCurve() || proof.commitB().isInfinity(), "B on curve");
        assertTrue(proof.commitC().isOnCurve() || proof.commitC().isInfinity(), "C on curve");
        assertTrue(proof.commitZ().isOnCurve() || proof.commitZ().isInfinity(), "Z on curve");
        assertTrue(proof.commitT1().isOnCurve() || proof.commitT1().isInfinity(), "T1 on curve");
        assertTrue(proof.commitT2().isOnCurve() || proof.commitT2().isInfinity(), "T2 on curve");
        assertTrue(proof.commitT3().isOnCurve() || proof.commitT3().isInfinity(), "T3 on curve");
        assertTrue(proof.commitWxi().isOnCurve() || proof.commitWxi().isInfinity(), "Wxi on curve");
        assertTrue(proof.commitWxiw().isOnCurve() || proof.commitWxiw().isInfinity(), "Wxiw on curve");

        // 6 evaluations should be in the scalar field
        BigInteger r = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        assertTrue(proof.evalA().compareTo(r) < 0, "evalA in field");
        assertTrue(proof.evalB().compareTo(r) < 0, "evalB in field");
        assertTrue(proof.evalC().compareTo(r) < 0, "evalC in field");
        assertTrue(proof.evalS1().compareTo(r) < 0, "evalS1 in field");
        assertTrue(proof.evalS2().compareTo(r) < 0, "evalS2 in field");
        assertTrue(proof.evalZw().compareTo(r) < 0, "evalZw in field");

        System.out.println("PlonK proof generated (structural test):");
        System.out.println("  A.x = " + (proof.commitA().isInfinity() ? "inf" : proof.commitA().xBigInt()));
        System.out.println("  Z.x = " + (proof.commitZ().isInfinity() ? "inf" : proof.commitZ().xBigInt()));
        System.out.println("  evalA = " + proof.evalA());
        System.out.println("  evalZw = " + proof.evalZw());
    }
}
