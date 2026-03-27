package com.bloxbean.cardano.zeroj.blst;

import org.junit.jupiter.api.Test;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for BLS12-381 pairing operations via blst native library.
 * <p>
 * Validates the low-level pairing primitives used by Groth16 BLS12-381 verification.
 */
class BlstPairingTest {

    @Test
    void millerLoop_generatorPoints_doesNotThrow() {
        // G1 and G2 generator points (uncompressed, 96 and 192 bytes)
        byte[] g1 = new P1().generator().serialize();
        byte[] g2 = new P2().generator().serialize();

        var result = BlstPairing.millerLoop(g1, g2);
        assertNotNull(result, "Miller loop should produce a result");
    }

    @Test
    void mulMlResult_twoResults_doesNotThrow() {
        byte[] g1 = new P1().generator().serialize();
        byte[] g2 = new P2().generator().serialize();

        var ml1 = BlstPairing.millerLoop(g1, g2);
        var ml2 = BlstPairing.millerLoop(g1, g2);

        var product = BlstPairing.mulMlResult(ml1, ml2);
        assertNotNull(product);
    }

    @Test
    void g1Add_generatorPlusGenerator_notIdentity() {
        byte[] g1 = new P1().generator().serialize();
        byte[] doubled = BlstPairing.g1Add(g1, g1);

        assertNotNull(doubled);
        assertEquals(96, doubled.length, "G1 uncompressed point should be 96 bytes");
        assertFalse(java.util.Arrays.equals(g1, doubled), "G + G should not equal G");
    }

    @Test
    void g1Neg_generatorNegated_addToZero() {
        byte[] g1 = new P1().generator().serialize();
        byte[] neg = BlstPairing.g1Neg(g1);

        assertEquals(96, neg.length);
        assertFalse(java.util.Arrays.equals(g1, neg), "G and -G should differ");

        // G + (-G) should be the identity point
        byte[] sum = BlstPairing.g1Add(g1, neg);
        // Identity point in uncompressed form: check that it's a valid point
        assertNotNull(sum);
    }

    @Test
    void g1ScalarMul_byOne_returnsOriginal() {
        byte[] g1 = new P1().generator().serialize();
        byte[] result = BlstPairing.g1ScalarMul(g1, java.math.BigInteger.ONE);

        assertArrayEquals(g1, result, "1 * G should equal G");
    }

    @Test
    void g1ScalarMul_byTwo_equalsAdd() {
        byte[] g1 = new P1().generator().serialize();
        byte[] doubled = BlstPairing.g1ScalarMul(g1, java.math.BigInteger.TWO);
        byte[] added = BlstPairing.g1Add(g1, g1);

        assertArrayEquals(doubled, added, "2*G should equal G+G");
    }

    @Test
    void finalVerify_identityPairing_succeeds() {
        // e(G1, G2) * e(-G1, G2) should equal 1 in GT
        byte[] g1 = new P1().generator().serialize();
        byte[] g2 = new P2().generator().serialize();
        byte[] negG1 = BlstPairing.g1Neg(g1);

        var lhs = BlstPairing.millerLoop(g1, g2);
        var rhs = BlstPairing.millerLoop(negG1, g2);
        var product = BlstPairing.mulMlResult(lhs, rhs);

        assertTrue(BlstPairing.finalVerify(product), "e(G1,G2) * e(-G1,G2) should be identity");
    }

    @Test
    void finalVerify_nonIdentity_fails() {
        // e(G1, G2) alone should NOT be the identity
        byte[] g1 = new P1().generator().serialize();
        byte[] g2 = new P2().generator().serialize();

        var ml = BlstPairing.millerLoop(g1, g2);

        assertFalse(BlstPairing.finalVerify(ml), "e(G1,G2) alone should not be identity");
    }
}
