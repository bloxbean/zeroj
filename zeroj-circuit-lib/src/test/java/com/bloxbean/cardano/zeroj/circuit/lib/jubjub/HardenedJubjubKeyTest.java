package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HardenedJubjubKeyTest {

    @Test
    @DisplayName("canonical key import rejects every boundary and derives the legacy public key")
    void canonicalImport() {
        assertThrows(IllegalArgumentException.class,
                () -> HardenedJubjubKey.importCanonical(new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> HardenedJubjubKey.importCanonical(new byte[33]));
        assertThrows(IllegalArgumentException.class,
                () -> HardenedJubjubKey.importCanonical(fixed32(BigInteger.ZERO)));
        assertThrows(IllegalArgumentException.class,
                () -> HardenedJubjubKey.importCanonical(
                        fixed32(JubjubCurve.SUBGROUP_ORDER)));

        for (BigInteger secret : new BigInteger[]{
                BigInteger.ONE, BigInteger.TWO,
                JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE)}) {
            byte[] encoded = fixed32(secret);
            try (HardenedJubjubKey key = HardenedJubjubKey.importCanonical(encoded)) {
                assertTrue(key.publicKey().projectiveEquals(
                        JubjubPoint.SUBGROUP_GENERATOR.scalarMul(secret)));
                assertFalse(key.isClosed());
            }
        }
    }

    @Test
    @DisplayName("key import owns its input and redacts all object text")
    void importOwnershipAndRedaction() {
        byte[] secret = fixed32(new BigInteger(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                16));
        byte[] original = secret.clone();
        try (HardenedJubjubKey key = HardenedJubjubKey.importCanonical(secret)) {
            Arrays.fill(secret, (byte) 0);
            assertTrue(key.publicKey().projectiveEquals(
                    JubjubPoint.SUBGROUP_GENERATOR.scalarMul(
                            new BigInteger(1, original))));
            String text = key.toString();
            assertTrue(text.contains("<redacted>"));
            assertFalse(text.contains(new BigInteger(1, original).toString()));
            assertFalse(text.contains(toHex(original)));
        } finally {
            Arrays.fill(original, (byte) 0);
        }
    }

    @Test
    @DisplayName("key generation rejection-samples zero, l, and above-l without reduction")
    void rejectionSampling() {
        byte[] aboveL = fixed32(JubjubCurve.SUBGROUP_ORDER.add(BigInteger.ONE));
        ScriptedRandom random = new ScriptedRandom(
                fixed32(BigInteger.ZERO),
                fixed32(JubjubCurve.SUBGROUP_ORDER),
                aboveL,
                fixed32(BigInteger.ONE));
        try (HardenedJubjubKey key = HardenedJubjubKey.generate(random)) {
            assertEquals(4, random.draws);
            assertTrue(key.publicKey().projectiveEquals(
                    JubjubPoint.SUBGROUP_GENERATOR));
        }
    }

    @Test
    @DisplayName("provider failure returns no key and wipes owned candidate storage")
    void providerFailure() {
        AtomicReference<byte[]> ownedCandidate = new AtomicReference<>();
        SecureRandom failing = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                ownedCandidate.set(bytes);
                Arrays.fill(bytes, (byte) 0x5a);
                throw new IllegalStateException("provider failure");
            }
        };
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> HardenedJubjubKey.generate(failing));
        assertEquals("provider failure", failure.getMessage());
        assertArrayEquals(new byte[32], ownedCandidate.get());
    }

    @Test
    @DisplayName("close is idempotent, wipes persistent arrays, and rejects later admission")
    void closeWipes() throws Exception {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(77)));
        key.close();
        key.close();
        assertTrue(key.isClosed());
        assertThrows(IllegalStateException.class, key::admit);

        for (String fieldName : new String[]{"secretScalar", "nonceKey", "publicPoint"}) {
            Field field = HardenedJubjubKey.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            long[] value = (long[]) field.get(key);
            assertArrayEquals(new long[value.length], value, fieldName);
        }
    }

    @Test
    @DisplayName("key establishment rejects a zero derived nonce key")
    void zeroNonceKeyGuard() {
        long[] candidate = new long[CtJubjubFqOps.LIMBS];
        assertThrows(IllegalStateException.class,
                () -> HardenedJubjubKey.requireNonZeroNonceKey(candidate, 0));
        CtJubjubFqOps.one(candidate, 0);
        assertDoesNotThrow(
                () -> HardenedJubjubKey.requireNonZeroNonceKey(candidate, 0));
    }

    @Test
    @DisplayName("key has identity semantics and is not Java-serializable")
    void typeSurface() {
        assertFalse(java.io.Serializable.class.isAssignableFrom(HardenedJubjubKey.class));
        try (HardenedJubjubKey a =
                     HardenedJubjubKey.importCanonical(fixed32(BigInteger.ONE));
             HardenedJubjubKey b =
                     HardenedJubjubKey.importCanonical(fixed32(BigInteger.ONE))) {
            assertFalse(a.equals(b));
            assertFalse(a.hashCode() == b.hashCode() && a.equals(b));
        }
    }

    private static final class ScriptedRandom extends SecureRandom {
        private final Queue<byte[]> values = new ArrayDeque<>();
        private int draws;

        private ScriptedRandom(byte[]... values) {
            for (byte[] value : values) {
                this.values.add(value.clone());
            }
        }

        @Override
        public void nextBytes(byte[] bytes) {
            draws++;
            byte[] next = values.remove();
            System.arraycopy(next, 0, bytes, 0, bytes.length);
        }
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int source = raw.length == 33 && raw[0] == 0 ? 1 : 0;
        System.arraycopy(raw, source, out, out.length - (raw.length - source),
                raw.length - source);
        return out;
    }

    private static String toHex(byte[] value) {
        return java.util.HexFormat.of().formatHex(value);
    }
}
