package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

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
