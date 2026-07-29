package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Off-circuit EdDSA-Jubjub correctness tests.
 */
class EdDSAJubjubTest {

    private static final BigInteger SK = new BigInteger(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16);
    private static final BigInteger MSG = new BigInteger(
            "0101010101010101010101010101010101010101010101010101010101010101", 16);

    /**
     * Literal interoperability/compatibility fixture. These values are intentionally not
     * recomputed from another helper in the test: coordinated drift in signing, point
     * arithmetic, and encoding must fail rather than self-confirm.
     */
    @Test
    @DisplayName("scheme signature and public-key golden vector is byte-for-byte pinned")
    void schemeGoldenVector_isPinned() {
        EdDSAJubjub.Keypair keypair =
                EdDSAJubjub.keypairFromSecret(SK.mod(JubjubCurve.SUBGROUP_ORDER));
        EdDSAJubjub.Signature signature = EdDSAJubjub.sign(keypair, MSG);

        assertEquals(new BigInteger(
                        "21f9c9921b63da042689e717546684173153230197232dbdf78a747d6da56c9e", 16),
                keypair.pk().affineU());
        assertEquals(new BigInteger(
                        "831b5dc03bf4efb60a61ae883daa50f3cbefb80e830fa491991d894eb094cc5", 16),
                keypair.pk().affineV());
        assertEquals(new BigInteger(
                        "54a32472642bd660ebe7a6c9739c7b7ba8268c962d9eae3c6bec308f2fe1cfd7", 16),
                signature.r().affineU());
        assertEquals(new BigInteger(
                        "373f62b874cb57f35a2e95b718b5776faab013ab41b35c0a2e0901b4de99f4a2", 16),
                signature.r().affineV());
        assertEquals("a2f499deb401092e0a5cb341ab13b0aa6f77b518b7952e5af357cb74b8623fb7",
                HexFormat.of().formatHex(signature.r().toBytes()));
        assertEquals(new BigInteger(
                        "8d60707517e507c5c6b9710a4980b36970b44ebf6557d93503fb09afa9f896f", 16),
                signature.s());
        assertTrue(EdDSAJubjub.verify(keypair.pk(), MSG, signature));
    }

    @Test
    @DisplayName("keypairFromSecret: pk = [sk]·G")
    void keypair_fromSecret() {
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(SK.mod(JubjubCurve.SUBGROUP_ORDER));
        JubjubPoint expectedPk = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(
                SK.mod(JubjubCurve.SUBGROUP_ORDER));
        assertTrue(kp.pk().projectiveEquals(expectedPk));
    }

    @Test
    @DisplayName("keypairFromSecret rejects sk == 0 and sk >= l")
    void keypair_rejectsOutOfRangeSk() {
        assertThrows(IllegalArgumentException.class, () ->
                EdDSAJubjub.keypairFromSecret(BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class, () ->
                EdDSAJubjub.keypairFromSecret(JubjubCurve.SUBGROUP_ORDER));
        assertThrows(IllegalArgumentException.class, () ->
                EdDSAJubjub.keypairFromSecret(JubjubCurve.SUBGROUP_ORDER.add(BigInteger.ONE)));
    }

    @Test
    @DisplayName("sign + verify round-trip: freshly-signed signature passes verify")
    void sign_verify_roundTrip() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(sk);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(sk, MSG);
        assertTrue(EdDSAJubjub.verify(kp.pk(), MSG, sig));
    }

    @Test
    @DisplayName("sign is deterministic: same (sk, msg) yields same signature")
    void sign_isDeterministic() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Signature a = EdDSAJubjub.sign(sk, MSG);
        EdDSAJubjub.Signature b = EdDSAJubjub.sign(sk, MSG);
        assertTrue(a.r().projectiveEquals(b.r()));
        assertEquals(a.s(), b.s());
    }

    @Test
    @DisplayName("verify rejects tampered message")
    void verify_rejectsTamperedMessage() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(sk);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(sk, MSG);
        BigInteger tamperedMsg = MSG.add(BigInteger.ONE);
        assertFalse(EdDSAJubjub.verify(kp.pk(), tamperedMsg, sig));
    }

    @Test
    @DisplayName("verify rejects signature under wrong public key")
    void verify_rejectsWrongPk() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(sk);
        EdDSAJubjub.Keypair other = EdDSAJubjub.keypairFromSecret(
                sk.add(BigInteger.ONE).mod(JubjubCurve.SUBGROUP_ORDER));
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(sk, MSG);
        assertFalse(EdDSAJubjub.verify(other.pk(), MSG, sig));
    }

    @Test
    @DisplayName("verify rejects malleated S = S + l (malleability defense)")
    void verify_rejectsMalleatedS() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(sk);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(sk, MSG);
        // S + l is a mathematically equivalent but non-canonical signature; reject.
        EdDSAJubjub.Signature malleated = new EdDSAJubjub.Signature(
                sig.r(), sig.s().add(JubjubCurve.SUBGROUP_ORDER));
        assertFalse(EdDSAJubjub.verify(kp.pk(), MSG, malleated));
    }

    @Test
    @DisplayName("verify rejects a signature with non-subgroup R (small-subgroup attack defense)")
    void verify_rejectsNonSubgroupR() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(sk);
        EdDSAJubjub.Signature original = EdDSAJubjub.sign(sk, MSG);
        // Replace R with FULL_GENERATOR (order 8l, not in subgroup).
        EdDSAJubjub.Signature bad = new EdDSAJubjub.Signature(
                JubjubPoint.FULL_GENERATOR, original.s());
        assertFalse(EdDSAJubjub.verify(kp.pk(), MSG, bad));
    }

    @Test
    @DisplayName("verify rejects a signature with S < 0")
    void verify_rejectsNegativeS() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(sk);
        EdDSAJubjub.Signature original = EdDSAJubjub.sign(sk, MSG);
        EdDSAJubjub.Signature bad = new EdDSAJubjub.Signature(
                original.r(), BigInteger.valueOf(-1));
        assertFalse(EdDSAJubjub.verify(kp.pk(), MSG, bad));
    }

    @Test
    @DisplayName("Multiple distinct messages signed with same key each verify independently")
    void verify_multipleMessages() {
        BigInteger sk = SK.mod(JubjubCurve.SUBGROUP_ORDER);
        EdDSAJubjub.Keypair kp = EdDSAJubjub.keypairFromSecret(sk);
        for (int i = 1; i <= 5; i++) {
            BigInteger msg = BigInteger.valueOf(i * 1000000L);
            EdDSAJubjub.Signature sig = EdDSAJubjub.sign(sk, msg);
            assertTrue(EdDSAJubjub.verify(kp.pk(), msg, sig),
                    "Iter " + i + " verify failed");
        }
    }
}
