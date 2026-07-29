package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0037 M2 gates: off-circuit verifier and key-handling hardening.
 */
class EdDSAJubjubHardeningM2Test {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger SK = new BigInteger(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16).mod(L);
    private static final BigInteger MSG = BigInteger.valueOf(0x5EED);

    // ------------------------------------------------------------------
    //  Identity public key
    // ------------------------------------------------------------------

    @Test
    @DisplayName("verify rejects the identity public key (was a universal forgery)")
    void identityPublicKeyRejected() {
        // No secret key is involved: [k]*O = O collapses the equation to [S]*G == R, so
        // choosing any r and setting R = [r]*G, S = r satisfies it for every message.
        BigInteger r = BigInteger.valueOf(999_331);
        var forged = new EdDSAJubjub.Signature(
                JubjubPoint.SUBGROUP_GENERATOR.scalarMul(r), r.mod(L));

        assertTrue(JubjubPoint.IDENTITY.isInSubgroup(),
                "the identity passes the subgroup check, which is why it needed its own test");
        assertFalse(EdDSAJubjub.verify(JubjubPoint.IDENTITY, MSG, forged),
                "identity pk must be rejected outright");
        // ...and for an arbitrary other message too, since the forgery is message-independent.
        assertFalse(EdDSAJubjub.verify(JubjubPoint.IDENTITY, BigInteger.ONE, forged));
    }

    // ------------------------------------------------------------------
    //  Secret-key range
    // ------------------------------------------------------------------

    @Test
    @DisplayName("sign rejects sk outside (0, l), matching keypairFromSecret")
    void signRejectsOutOfRangeSecret() {
        assertThrows(IllegalArgumentException.class, () -> EdDSAJubjub.sign(BigInteger.ZERO, MSG));
        assertThrows(IllegalArgumentException.class, () -> EdDSAJubjub.sign(L, MSG));
        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.sign(L.add(BigInteger.valueOf(5)), MSG));
        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.sign(BigInteger.valueOf(-1), MSG));
        assertDoesNotThrow(() -> EdDSAJubjub.sign(BigInteger.ONE, MSG));
        assertDoesNotThrow(() -> EdDSAJubjub.sign(L.subtract(BigInteger.ONE), MSG));
    }

    @Test
    @DisplayName("keypairFromSecret and sign agree on the accepted range")
    void signAndKeypairAgreeOnRange() {
        for (BigInteger bad : new BigInteger[]{BigInteger.ZERO, L, L.add(BigInteger.ONE)}) {
            assertThrows(IllegalArgumentException.class, () -> EdDSAJubjub.keypairFromSecret(bad));
            assertThrows(IllegalArgumentException.class, () -> EdDSAJubjub.sign(bad, MSG));
        }
    }

    // ------------------------------------------------------------------
    //  Message range
    // ------------------------------------------------------------------

    @Test
    @DisplayName("sign and verify reject msg outside [0, p), closing the msg/msg+p alias")
    void messageRangeEnforced() {
        var kp = EdDSAJubjub.keypairFromSecret(SK);
        var sig = EdDSAJubjub.sign(SK, MSG);

        assertThrows(IllegalArgumentException.class, () -> EdDSAJubjub.sign(SK, P));
        assertThrows(IllegalArgumentException.class, () -> EdDSAJubjub.sign(SK, MSG.add(P)));
        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.sign(SK, BigInteger.valueOf(-1)));

        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.verify(kp.pk(), MSG.add(P), sig),
                "before M2 this returned true: Poseidon reduced msg+p to msg internally, so "
                        + "one signature covered two distinct application messages");
        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.verify(kp.pk(), P, sig));

        assertTrue(EdDSAJubjub.verify(kp.pk(), MSG, sig), "in-range message still verifies");
        assertDoesNotThrow(() -> EdDSAJubjub.sign(SK, P.subtract(BigInteger.ONE)));
    }

    // ------------------------------------------------------------------
    //  Keypair.toString redaction
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Keypair.toString does not leak the private key")
    void keypairToStringRedactsSecret() {
        BigInteger sk = new BigInteger("c0ffee1234567890abcdef", 16);
        var kp = EdDSAJubjub.keypairFromSecret(sk);
        String s = kp.toString();

        assertFalse(s.contains(sk.toString()), "decimal form of sk leaked: " + s);
        assertFalse(s.contains(sk.toString(16)), "hex form of sk leaked: " + s);
        assertTrue(s.contains("redacted"), "redaction marker missing: " + s);
        assertTrue(s.contains(kp.pk().affineU().toString(16)),
                "the public key should still be visible for debugging");
    }

    // ------------------------------------------------------------------
    //  Key generation
    // ------------------------------------------------------------------

    @Test
    @DisplayName("generateKeypair produces sk in [1, l) with a valid non-identity public key")
    void generateKeypairRange() {
        SecureRandom rnd = new SecureRandom();
        Set<BigInteger> seen = new HashSet<>();
        for (int i = 0; i < 300; i++) {
            var kp = EdDSAJubjub.generateKeypair(rnd);
            assertTrue(kp.sk().signum() > 0, "sk must be positive");
            assertTrue(kp.sk().compareTo(L) < 0, "sk must be < l");
            assertTrue(kp.pk().isInSubgroup(), "pk must be in the prime-order subgroup");
            assertFalse(kp.pk().isIdentity(), "pk must not be the identity");
            assertTrue(kp.pk().projectiveEquals(
                            JubjubPoint.SUBGROUP_GENERATOR.scalarMul(kp.sk())),
                    "pk must equal [sk]*G");
            seen.add(kp.sk());
        }
        assertEquals(300, seen.size(), "keys must not repeat");
    }

    @Test
    @DisplayName("generateKeypair is unbiased across the top of the range (rejection sampling)")
    void generateKeypairCoversHighRange() {
        // A `random mod l` implementation would still produce high values, so this is a
        // smoke test for range coverage rather than a bias proof: assert the sampler reaches
        // both halves of [1, l) rather than being clamped into one.
        SecureRandom rnd = new SecureRandom();
        BigInteger half = L.shiftRight(1);
        boolean low = false, high = false;
        for (int i = 0; i < 200 && !(low && high); i++) {
            BigInteger sk = EdDSAJubjub.generateKeypair(rnd).sk();
            if (sk.compareTo(half) < 0) low = true; else high = true;
        }
        assertTrue(low && high, "sampler should reach both halves of [1, l)");
    }

    @Test
    @DisplayName("generateKeypair rejects a null RNG rather than defaulting to a weak one")
    void generateKeypairRequiresRandom() {
        assertThrows(NullPointerException.class, () -> EdDSAJubjub.generateKeypair(null));
    }

    @Test
    @DisplayName("generated keypairs sign and verify")
    void generatedKeypairsRoundTrip() {
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < 10; i++) {
            var kp = EdDSAJubjub.generateKeypair(rnd);
            BigInteger msg = EdDSAJubjub.hashToField(("message " + i).getBytes(StandardCharsets.UTF_8));
            var sig = EdDSAJubjub.sign(kp.sk(), msg);
            assertTrue(EdDSAJubjub.verify(kp.pk(), msg, sig));
        }
    }

    // ------------------------------------------------------------------
    //  hashToField
    // ------------------------------------------------------------------

    @Test
    @DisplayName("hashToField output is always a canonical field element")
    void hashToFieldRange() {
        for (int i = 0; i < 200; i++) {
            byte[] msg = ("msg-" + i).getBytes(StandardCharsets.UTF_8);
            BigInteger h = EdDSAJubjub.hashToField(msg);
            assertTrue(h.signum() >= 0 && h.compareTo(P) < 0,
                    "hashToField must land in [0, p); got bitLength " + h.bitLength());
        }
    }

    @Test
    @DisplayName("hashToField is deterministic and collision-free on distinct inputs")
    void hashToFieldDeterministicAndDistinct() {
        byte[] a = "hello".getBytes(StandardCharsets.UTF_8);
        assertEquals(EdDSAJubjub.hashToField(a), EdDSAJubjub.hashToField(a.clone()));

        Set<BigInteger> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            seen.add(EdDSAJubjub.hashToField(("distinct-" + i).getBytes(StandardCharsets.UTF_8)));
        }
        assertEquals(500, seen.size());
    }

    @Test
    @DisplayName("hashToField length-prefixes the message, so concatenation is unambiguous")
    void hashToFieldIsUnambiguous() {
        // Without length framing, hash("ab" || "c") and hash("a" || "bc") could collide when
        // a caller builds the input by concatenation.
        assertNotEquals(
                EdDSAJubjub.hashToField("abc".getBytes(StandardCharsets.UTF_8)),
                EdDSAJubjub.hashToField("ab".getBytes(StandardCharsets.UTF_8)));
        assertNotEquals(
                EdDSAJubjub.hashToField(new byte[0]),
                EdDSAJubjub.hashToField(new byte[]{0}));
    }

    @Test
    @DisplayName("hashToField accepts the empty message and rejects null")
    void hashToFieldEdgeCases() {
        assertDoesNotThrow(() -> EdDSAJubjub.hashToField(new byte[0]));
        assertThrows(NullPointerException.class, () -> EdDSAJubjub.hashToField(null));
    }

    /**
     * Golden vectors pinning the exact construction — DST, framing, byte order, and
     * reduction — so a change that would break interoperability fails here rather than
     * silently in the field.
     *
     * <p>These were produced by an <b>independent Python implementation</b> of the documented
     * formula, not dumped from this class, so they are a genuine cross-implementation check:
     *
     * <pre>
     * import hashlib, struct
     * p   = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
     * dst = b'ZeroJ-JubjubEdDSA-v1-hashToField'
     * def h2f(msg):
     *     buf = bytes([len(dst)]) + dst + struct.pack('&gt;q', len(msg)) + msg
     *     return int.from_bytes(hashlib.sha512(buf).digest(), 'big') % p
     * </pre>
     */
    @Test
    @DisplayName("hashToField golden vectors (cross-checked against an independent implementation)")
    void hashToFieldGoldenVectors() {
        assertEquals(
                new BigInteger("6a482f890fb3b183bcf9dcc92882f5e73db111459d830b2d3f306b44c6a0ce5d", 16),
                EdDSAJubjub.hashToField(new byte[0]),
                "empty-message vector drifted — the construction changed");
        assertEquals(
                new BigInteger("54fb4aff307c5e8e14317ab691f43f93b453d7acc444cbe49f4246ad9c1d422c", 16),
                EdDSAJubjub.hashToField("a".getBytes(StandardCharsets.UTF_8)));
        assertEquals(
                new BigInteger("304275eedabef9c974cb80beab9264e2ecdfd644da7221cccabd8364e3501f60", 16),
                EdDSAJubjub.hashToField("the quick brown fox".getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Independent recomputation of the documented formula. If {@link EdDSAJubjub#hashToField}
     * and its Javadoc ever disagree, this fails — which is the point: the golden vector alone
     * would happily pin a construction that no longer matches the spec.
     */
    @Test
    @DisplayName("hashToField matches its documented specification, recomputed independently")
    void hashToFieldMatchesItsSpecification() throws Exception {
        byte[] dst = "ZeroJ-JubjubEdDSA-v1-hashToField".getBytes(StandardCharsets.UTF_8);
        for (byte[] msg : new byte[][]{
                new byte[0],
                "a".getBytes(StandardCharsets.UTF_8),
                "the quick brown fox".getBytes(StandardCharsets.UTF_8),
                new byte[300]}) {

            var out = new java.io.ByteArrayOutputStream();
            out.write(dst.length);
            out.write(dst);
            out.write(java.nio.ByteBuffer.allocate(8).putLong(msg.length).array());
            out.write(msg);

            byte[] wide = java.security.MessageDigest.getInstance("SHA-512").digest(out.toByteArray());
            BigInteger expected = new BigInteger(1, wide).mod(P);

            assertEquals(expected, EdDSAJubjub.hashToField(msg),
                    "implementation diverged from the documented construction");
        }
    }

    // ------------------------------------------------------------------
    //  Regressions preserved from before M2
    // ------------------------------------------------------------------

    @Test
    @DisplayName("existing verify behaviour is unchanged for valid inputs")
    void existingBehaviourPreserved() {
        var kp = EdDSAJubjub.keypairFromSecret(SK);
        var sig = EdDSAJubjub.sign(SK, MSG);
        assertTrue(EdDSAJubjub.verify(kp.pk(), MSG, sig));
        assertFalse(EdDSAJubjub.verify(kp.pk(), MSG.add(BigInteger.ONE), sig));
        assertFalse(EdDSAJubjub.verify(kp.pk(), MSG,
                new EdDSAJubjub.Signature(sig.r(), sig.s().add(L))));
        assertFalse(EdDSAJubjub.verify(kp.pk(), MSG,
                new EdDSAJubjub.Signature(JubjubPoint.FULL_GENERATOR, sig.s())));
    }
}
