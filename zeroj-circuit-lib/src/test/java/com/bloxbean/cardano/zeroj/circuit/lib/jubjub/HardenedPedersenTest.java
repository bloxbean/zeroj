package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.time.Duration;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HardenedPedersenTest {

    private static final Random RANDOM = new Random(0x39_504544L);

    @Test
    @DisplayName("hardened Pedersen matches legacy generation at boundaries and random inputs")
    void differential() {
        BigInteger[] boundaries = {
                BigInteger.ZERO,
                BigInteger.ONE,
                JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE),
                JubjubCurve.SUBGROUP_ORDER,
                JubjubCurve.SUBGROUP_ORDER.add(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)
        };
        for (BigInteger value : boundaries) {
            for (BigInteger blinding : boundaries) {
                assertCommitment(value, blinding);
            }
        }
        for (int i = 0; i < 100; i++) {
            assertCommitment(random256(), random256());
        }
    }

    @Test
    @DisplayName("small explicit widths preserve the existing golden commitment")
    void goldenVector() {
        try (HardenedPedersenOpening opening = HardenedPedersenOpening.fromUnsigned(
                unsigned(BigInteger.valueOf(42), 8), 8,
                unsigned(BigInteger.valueOf(12345), 16), 16)) {
            JubjubPoint commitment = HardenedPedersen.commit(opening);
            assertEquals(new BigInteger(
                            "478a0bd6a0eebdffc610618ad979b39d6237f240125534886d38720cbd76a025",
                            16),
                    commitment.affineU());
            assertEquals(new BigInteger(
                            "6387c33be7b7177b74ce909592456d7c81dab375a6ba3182eb7f5e2974e0d357",
                            16),
                    commitment.affineV());
        }
    }

    @Test
    @DisplayName("opening enforces exact lengths and unused high bits")
    void widthValidation() {
        assertThrows(IllegalArgumentException.class,
                () -> HardenedPedersenOpening.fromUnsigned(
                        new byte[1], 0, new byte[1], 1));
        assertThrows(IllegalArgumentException.class,
                () -> HardenedPedersenOpening.fromUnsigned(
                        new byte[1], 257, new byte[1], 1));
        assertThrows(IllegalArgumentException.class,
                () -> HardenedPedersenOpening.fromUnsigned(
                        new byte[2], 8, new byte[1], 1));
        assertThrows(IllegalArgumentException.class,
                () -> HardenedPedersenOpening.fromUnsigned(
                        new byte[]{(byte) 0x80}, 7, new byte[]{0}, 1));
        assertThrows(IllegalArgumentException.class,
                () -> HardenedPedersenOpening.fromUnsigned(
                        new byte[]{0}, 1, new byte[]{2}, 1));
    }

    @Test
    @DisplayName("opening owns inputs, redacts text, wipes on close, and rejects reuse")
    void lifecycle() throws Exception {
        byte[] value = {(byte) 42};
        byte[] blinding = {1, 2};
        HardenedPedersenOpening opening =
                HardenedPedersenOpening.fromUnsigned(value, 8, blinding, 16);
        Arrays.fill(value, (byte) 0);
        Arrays.fill(blinding, (byte) 0);
        assertTrue(opening.toString().contains("<redacted>"));
        assertTrue(PedersenCommitment.verify(
                HardenedPedersen.commit(opening),
                BigInteger.valueOf(42), BigInteger.valueOf(258)));
        opening.close();
        opening.close();
        assertTrue(opening.isClosed());
        assertThrows(IllegalStateException.class,
                () -> HardenedPedersen.commit(opening));

        for (String fieldName : new String[]{"value", "blinding"}) {
            Field field = HardenedPedersenOpening.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            long[] words = (long[]) field.get(opening);
            assertArrayEquals(new long[4], words);
        }
        assertFalse(java.io.Serializable.class.isAssignableFrom(
                HardenedPedersenOpening.class));
        assertFalse(Modifier.isPublic(HardenedPedersen.class.getModifiers()));
        assertFalse(Modifier.isPublic(HardenedPedersenOpening.class.getModifiers()));
    }

    @Test
    @DisplayName("close waits for an admitted commit, then rejects later commits")
    void concurrentCommitClose() {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            HardenedPedersenOpening opening =
                    HardenedPedersenOpening.fromUnsigned(
                            new byte[]{42}, 8, new byte[]{1, 2}, 16);
            CountDownLatch admitted = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<JubjubPoint> active = executor.submit(() ->
                        HardenedPedersen.commit(opening, () -> {
                            admitted.countDown();
                            await(release);
                        }));
                assertTrue(admitted.await(2, TimeUnit.SECONDS));
                Future<?> close = executor.submit(opening::close);
                Thread.sleep(25);
                assertFalse(close.isDone(),
                        "close must wait for the admitted commitment");
                release.countDown();
                assertTrue(PedersenCommitment.verify(
                        active.get(5, TimeUnit.SECONDS),
                        BigInteger.valueOf(42), BigInteger.valueOf(258)));
                close.get(5, TimeUnit.SECONDS);
                assertTrue(opening.isClosed());
                assertThrows(IllegalStateException.class,
                        () -> HardenedPedersen.commit(opening));
            } finally {
                release.countDown();
                opening.close();
                executor.shutdownNow();
            }
        });
    }

    private static void assertCommitment(BigInteger value, BigInteger blinding) {
        try (HardenedPedersenOpening opening = HardenedPedersenOpening.fromUnsigned(
                fixed32(value), 256, fixed32(blinding), 256)) {
            JubjubPoint actual = HardenedPedersen.commit(opening);
            JubjubPoint expected = PedersenCommitment.commit(value, blinding);
            assertTrue(actual.projectiveEquals(expected),
                    () -> "value=" + value.toString(16)
                            + ", blinding=" + blinding.toString(16));
            assertTrue(PedersenCommitment.verify(actual, value, blinding));
        }
    }

    private static BigInteger random256() {
        return new BigInteger(256, RANDOM);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("timed out waiting for test latch");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private static byte[] fixed32(BigInteger value) {
        return unsigned(value, 256);
    }

    private static byte[] unsigned(BigInteger value, int bits) {
        int length = (bits + 7) >>> 3;
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int source = raw.length == length + 1 && raw[0] == 0 ? 1 : 0;
        System.arraycopy(raw, source, out, out.length - (raw.length - source),
                raw.length - source);
        return out;
    }
}
