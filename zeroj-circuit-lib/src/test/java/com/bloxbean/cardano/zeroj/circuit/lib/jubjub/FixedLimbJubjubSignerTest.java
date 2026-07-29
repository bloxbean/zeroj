package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FixedLimbJubjubSignerTest {

    private static final Random RANDOM = new Random(0x39_5349474eL);

    @Test
    @DisplayName("fixed-limb deterministic signer preserves legacy public keys and signatures")
    void deterministicCompatibility() {
        List<BigInteger> secrets = new ArrayList<>(List.of(
                BigInteger.ONE,
                BigInteger.TWO,
                JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE)));
        for (int i = 0; i < 20; i++) {
            secrets.add(randomNonZeroBelow(JubjubCurve.SUBGROUP_ORDER));
        }
        for (BigInteger secret : secrets) {
            for (BigInteger field : new BigInteger[]{
                    BigInteger.ZERO, BigInteger.ONE,
                    JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE),
                    randomBelow(JubjubCurve.BASE_FIELD_PRIME)}) {
                JubjubMessage message =
                        JubjubMessage.fromCanonicalFieldBytes(fixed32(field));
                EdDSAJubjub.Keypair legacyKey =
                        EdDSAJubjub.keypairFromSecret(secret);
                EdDSAJubjub.Signature expected =
                        EdDSAJubjub.sign(legacyKey, field);
                try (HardenedJubjubKey key =
                             HardenedJubjubKey.importCanonical(fixed32(secret));
                     JubjubSigner signer =
                             JubjubSigners.fixedLimbDeterministicV1Compatibility(key)) {
                    assertEquals(
                            JubjubSigningProfile.FIXED_LIMB_DETERMINISTIC_V1_COMPATIBILITY,
                            signer.profile());
                    assertTrue(signer.publicKey().projectiveEquals(legacyKey.pk()));
                    EdDSAJubjub.Signature actual = signer.sign(message);
                    assertTrue(actual.r().projectiveEquals(expected.r()));
                    assertEquals(expected.s(), actual.s());
                    assertTrue(EdDSAJubjub.verify(signer.publicKey(), message, actual));
                }
            }
        }
    }

    @Test
    @DisplayName("forced deterministic zero nonce fails before point multiplication")
    void deterministicZeroNonceFailsClosed() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(7)));
        AtomicInteger pointMultiplications = new AtomicInteger();
        FixedLimbJubjubSigner signer = new FixedLimbJubjubSigner(
                key,
                FixedLimbJubjubSigner.Mode.DETERMINISTIC_V1,
                null,
                (words, offset) -> CtJubjubFrOps.zero(words, offset),
                candidate -> candidate,
                pointMultiplications::incrementAndGet);
        try (signer) {
            IllegalStateException failure = assertThrows(
                    IllegalStateException.class,
                    () -> signer.sign(message(11)));
            assertTrue(failure.getMessage().contains("zero"));
            assertEquals(0, pointMultiplications.get());
        }
    }

    @Test
    @DisplayName("hedged candidate binds auxiliary randomness and always verifies")
    void hedgedCandidate() {
        byte[] auxiliaryA = new byte[32];
        byte[] auxiliaryB = new byte[32];
        Arrays.fill(auxiliaryA, (byte) 0x11);
        Arrays.fill(auxiliaryB, (byte) 0x22);
        BigInteger secret = BigInteger.valueOf(123456789);
        JubjubMessage message = message(55);

        EdDSAJubjub.Signature first = hedged(secret, message, auxiliaryA);
        EdDSAJubjub.Signature repeated = hedged(secret, message, auxiliaryA);
        EdDSAJubjub.Signature changed = hedged(secret, message, auxiliaryB);
        assertTrue(first.r().projectiveEquals(repeated.r()));
        assertEquals(first.s(), repeated.s());
        assertFalse(first.r().projectiveEquals(changed.r())
                && first.s().equals(changed.s()));
    }

    @Test
    @DisplayName("release check rejects public candidate corruption")
    void releaseCheckRejectsFault() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(17)));
        FixedLimbJubjubSigner signer = new FixedLimbJubjubSigner(
                key,
                FixedLimbJubjubSigner.Mode.HEDGED_CANDIDATE,
                fixedAuxiliary((byte) 1),
                (words, offset) -> { },
                candidate -> new EdDSAJubjub.Signature(
                        candidate.r(),
                        candidate.s().add(BigInteger.ONE)
                                .mod(JubjubCurve.SUBGROUP_ORDER)),
                () -> { });
        try (signer) {
            assertThrows(IllegalStateException.class,
                    () -> signer.sign(message(19)));
        }
    }

    @Test
    @DisplayName("nonce re-derivation rejects zero and attacker-known nonce faults")
    void nonceRederivationRejectsFaults() {
        List<FixedLimbJubjubSigner.NonceTestHook> faults = List.of(
                (words, offset) -> CtJubjubFrOps.zero(words, offset),
                (words, offset) -> CtJubjubFrOps.one(words, offset)
        );
        for (var fault : faults) {
            HardenedJubjubKey key = HardenedJubjubKey.importCanonical(
                    fixed32(BigInteger.valueOf(1234567)));
            FixedLimbJubjubSigner signer = new FixedLimbJubjubSigner(
                    key,
                    FixedLimbJubjubSigner.Mode.HEDGED_CANDIDATE,
                    fixedAuxiliary((byte) 9),
                    fault,
                    candidate -> candidate,
                    () -> { });
            try (signer) {
                IllegalStateException failure = assertThrows(
                        IllegalStateException.class,
                        () -> signer.sign(message(23)));
                assertTrue(failure.getMessage().contains("nonce invariant"),
                        failure::getMessage);
            }
        }
    }

    @Test
    @DisplayName("independent release check rejects a corrupted secret-key scratch")
    void releaseCheckRejectsKeyStateFault() {
        HardenedJubjubKey key = HardenedJubjubKey.importCanonical(
                fixed32(BigInteger.valueOf(1234567)));
        FixedLimbJubjubSigner signer = new FixedLimbJubjubSigner(
                key,
                FixedLimbJubjubSigner.Mode.HEDGED_CANDIDATE,
                fixedAuxiliary((byte) 9),
                (words, offset) -> CtJubjubFrOps.one(words, SigningScratch.SK),
                candidate -> candidate,
                () -> { });
        try (signer) {
            IllegalStateException failure = assertThrows(
                    IllegalStateException.class,
                    () -> signer.sign(message(23)));
            assertTrue(failure.getMessage().contains("failed verification"));
        }
    }

    @Test
    @DisplayName("release check rejects nonce-point conversion corruption")
    void releaseCheckRejectsPointFault() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(31)));
        FixedLimbJubjubSigner signer = new FixedLimbJubjubSigner(
                key,
                FixedLimbJubjubSigner.Mode.HEDGED_CANDIDATE,
                fixedAuxiliary((byte) 4),
                (words, offset) -> { },
                candidate -> new EdDSAJubjub.Signature(
                        candidate.r().add(JubjubPoint.SUBGROUP_GENERATOR),
                        candidate.s()),
                () -> { });
        try (signer) {
            assertThrows(IllegalStateException.class,
                    () -> signer.sign(message(29)));
        }
    }

    @Test
    @DisplayName("auxiliary source failure occurs before key copy and leaves key usable")
    void randomFailureBeforeKeyAccess() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(23)));
        JubjubAuxiliaryRandomSource failing = output -> {
            throw new IllegalStateException("draw failed");
        };
        JubjubSigner failed =
                JubjubSigners.hedgedCandidateForTesting(key, failing);
        assertThrows(IllegalStateException.class, () -> failed.sign(message(1)));

        // A failed draw released its admission lease without closing or corrupting the key.
        JubjubSigner retry = JubjubSigners.hedgedCandidateForTesting(
                key, fixedAuxiliary((byte) 3));
        assertDoesNotThrow(() -> retry.sign(message(1)));
        retry.close();
    }

    @Test
    @DisplayName("close rejects new calls and lets an already-admitted operation finish")
    void closeRaceContract() {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            HardenedJubjubKey key =
                    HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(29)));
            CountDownLatch enteredRandom = new CountDownLatch(1);
            CountDownLatch releaseRandom = new CountDownLatch(1);
            JubjubAuxiliaryRandomSource blocking = output -> {
                enteredRandom.countDown();
                await(releaseRandom);
                Arrays.fill(output, (byte) 5);
            };
            JubjubSigner signer =
                    JubjubSigners.hedgedCandidateForTesting(key, blocking);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<EdDSAJubjub.Signature> active =
                        executor.submit(() -> signer.sign(message(31)));
                assertTrue(enteredRandom.await(2, TimeUnit.SECONDS));
                Future<?> close = executor.submit(signer::close);
                Thread.sleep(25);
                assertFalse(close.isDone(), "close must wait for the admitted operation");
                releaseRandom.countDown();
                assertTrue(EdDSAJubjub.verify(
                        signer.publicKey(), message(31), active.get(5, TimeUnit.SECONDS)));
                close.get(5, TimeUnit.SECONDS);
                assertTrue(key.isClosed());
                assertThrows(IllegalStateException.class,
                        () -> signer.sign(message(31)));
            } finally {
                releaseRandom.countDown();
                executor.shutdownNow();
            }
        });
    }

    @Test
    @DisplayName("every concurrent close waits for admitted work and source destruction")
    void concurrentCloseIsSynchronouslyIdempotent() {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            HardenedJubjubKey key =
                    HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(30)));
            CountDownLatch enteredRandom = new CountDownLatch(1);
            CountDownLatch releaseRandom = new CountDownLatch(1);
            AtomicInteger sourceCloseCount = new AtomicInteger();
            JubjubAuxiliaryRandomSource blocking = new JubjubAuxiliaryRandomSource() {
                @Override
                public void fill(byte[] output) {
                    enteredRandom.countDown();
                    await(releaseRandom);
                    Arrays.fill(output, (byte) 6);
                }

                @Override
                public void close() {
                    sourceCloseCount.incrementAndGet();
                }
            };
            JubjubSigner signer =
                    JubjubSigners.hedgedCandidateForTesting(key, blocking);
            ExecutorService executor = Executors.newFixedThreadPool(3);
            try {
                Future<EdDSAJubjub.Signature> active =
                        executor.submit(() -> signer.sign(message(32)));
                assertTrue(enteredRandom.await(2, TimeUnit.SECONDS));

                CountDownLatch closeCallsEntered = new CountDownLatch(2);
                Future<?> firstClose = executor.submit(() -> {
                    closeCallsEntered.countDown();
                    signer.close();
                });
                Future<?> secondClose = executor.submit(() -> {
                    closeCallsEntered.countDown();
                    signer.close();
                });
                assertTrue(closeCallsEntered.await(2, TimeUnit.SECONDS));
                Thread.sleep(25);
                assertFalse(firstClose.isDone(),
                        "the first close must wait for the admitted operation");
                assertFalse(secondClose.isDone(),
                        "every concurrent close must wait for destruction completion");
                assertFalse(key.isClosed());
                assertEquals(0, sourceCloseCount.get());

                releaseRandom.countDown();
                assertTrue(EdDSAJubjub.verify(
                        signer.publicKey(), message(32), active.get(5, TimeUnit.SECONDS)));
                firstClose.get(5, TimeUnit.SECONDS);
                secondClose.get(5, TimeUnit.SECONDS);
                assertTrue(key.isClosed());
                assertEquals(1, sourceCloseCount.get());
            } finally {
                releaseRandom.countDown();
                executor.shutdownNow();
            }
        });
    }

    @Test
    @DisplayName("every close caller observes one recorded source-close failure")
    void concurrentCloseFailureIsRecordedAndRethrown() {
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            HardenedJubjubKey key =
                    HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(33)));
            AtomicInteger sourceCloseCount = new AtomicInteger();
            IllegalStateException expected =
                    new IllegalStateException("source close failed");
            JubjubAuxiliaryRandomSource source = new JubjubAuxiliaryRandomSource() {
                @Override
                public void fill(byte[] output) {
                    Arrays.fill(output, (byte) 7);
                }

                @Override
                public void close() {
                    sourceCloseCount.incrementAndGet();
                    throw expected;
                }
            };
            JubjubSigner signer =
                    JubjubSigners.hedgedCandidateForTesting(key, source);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch start = new CountDownLatch(1);
            try {
                Future<Throwable> firstClose = executor.submit(() -> {
                    ready.countDown();
                    await(start);
                    return captureCloseFailure(signer);
                });
                Future<Throwable> secondClose = executor.submit(() -> {
                    ready.countDown();
                    await(start);
                    return captureCloseFailure(signer);
                });
                assertTrue(ready.await(2, TimeUnit.SECONDS));
                start.countDown();

                assertSame(expected, firstClose.get(5, TimeUnit.SECONDS));
                assertSame(expected, secondClose.get(5, TimeUnit.SECONDS));
                assertTrue(key.isClosed());
                assertEquals(1, sourceCloseCount.get());
                assertThrows(IllegalStateException.class,
                        () -> signer.sign(message(33)));
                assertSame(expected,
                        assertThrows(IllegalStateException.class, signer::close));
                assertEquals(1, sourceCloseCount.get());
            } finally {
                start.countDown();
                executor.shutdownNow();
            }
        });
    }

    @Test
    @DisplayName("profile and public key remain available after signer close")
    void publicMetadataRemainsAvailableAfterClose() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(34)));
        JubjubSigner signer =
                JubjubSigners.fixedLimbDeterministicV1Compatibility(key);
        JubjubPoint publicKey = signer.publicKey();
        JubjubSigningProfile profile = signer.profile();

        signer.close();

        assertEquals(publicKey, signer.publicKey());
        assertEquals(profile, signer.profile());
        assertThrows(IllegalStateException.class,
                () -> signer.sign(message(34)));
    }

    @Test
    @DisplayName("one signer supports concurrent operations with isolated scratch")
    void concurrentSigning() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(37)));
        AtomicInteger counter = new AtomicInteger();
        JubjubAuxiliaryRandomSource source = output -> {
            int value = counter.getAndIncrement();
            Arrays.fill(output, (byte) value);
        };
        JubjubSigner signer = JubjubSigners.hedgedCandidateForTesting(key, source);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<EdDSAJubjub.Signature>> futures = new ArrayList<>();
            for (int i = 0; i < 32; i++) {
                int message = i;
                futures.add(executor.submit(() -> signer.sign(message(message))));
            }
            for (int i = 0; i < futures.size(); i++) {
                EdDSAJubjub.Signature signature =
                        futures.get(i).get(10, TimeUnit.SECONDS);
                assertTrue(EdDSAJubjub.verify(
                        signer.publicKey(), message(i), signature));
            }
        } catch (Exception e) {
            throw new AssertionError(e);
        } finally {
            signer.close();
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("fixed-limb wrappers share the key destruction domain explicitly")
    void sharedKeyDestructionDomain() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(39)));
        JubjubSigner first =
                JubjubSigners.fixedLimbDeterministicV1Compatibility(key);
        JubjubSigner second =
                JubjubSigners.fixedLimbDeterministicV1Compatibility(key);
        assertDoesNotThrow(() -> second.sign(message(1)));
        first.close();
        assertTrue(key.isClosed());
        assertThrows(IllegalStateException.class,
                () -> second.sign(message(1)));
        second.close();
    }

    @Test
    @DisplayName("closing a hedged signer closes its owned randomness source")
    void auxiliarySourceLifecycle() {
        HardenedJubjubKey key =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(40)));
        AtomicBoolean sourceClosed = new AtomicBoolean();
        JubjubAuxiliaryRandomSource source = new JubjubAuxiliaryRandomSource() {
            @Override
            public void fill(byte[] output) {
                Arrays.fill(output, (byte) 9);
            }

            @Override
            public void close() {
                sourceClosed.set(true);
            }
        };
        JubjubSigner signer =
                JubjubSigners.hedgedCandidateForTesting(key, source);
        assertDoesNotThrow(() -> signer.sign(message(1)));
        signer.close();
        assertTrue(sourceClosed.get());
        assertTrue(key.isClosed());
    }

    @Test
    @DisplayName("validated factory fails closed and never falls back")
    void validatedFactoryIsGated() {
        UnsupportedOperationException failure =
                assertThrows(UnsupportedOperationException.class,
                        JubjubSigners::validatedDedicatedHostJavaRequired);
        assertTrue(failure.getMessage().contains("M4-M8"));
        assertTrue(Arrays.stream(JubjubSigners.class.getDeclaredMethods())
                .filter(method -> method.getName()
                        .equals("validatedDedicatedHostJavaRequired"))
                .allMatch(method -> method.getParameterCount() == 0),
                "fail-closed placeholder must not accept an untagged key or RNG");
    }

    @Test
    @DisplayName("operation scratch and auxiliary storage are wiped after success and failure")
    void operationScratchIsWiped() {
        AtomicReference<long[]> successWords = new AtomicReference<>();
        AtomicReference<byte[]> successAux = new AtomicReference<>();
        HardenedJubjubKey successKey =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(41)));
        FixedLimbJubjubSigner successSigner = new FixedLimbJubjubSigner(
                successKey,
                FixedLimbJubjubSigner.Mode.HEDGED_CANDIDATE,
                output -> {
                    successAux.set(output);
                    Arrays.fill(output, (byte) 0x5a);
                },
                (words, offset) -> successWords.set(words),
                candidate -> candidate,
                () -> { });
        try (successSigner) {
            successSigner.sign(message(7));
        }
        assertAllZero(successWords.get());
        assertAllZero(successAux.get());

        AtomicReference<byte[]> failureAux = new AtomicReference<>();
        HardenedJubjubKey failureKey =
                HardenedJubjubKey.importCanonical(fixed32(BigInteger.valueOf(43)));
        JubjubSigner failureSigner = JubjubSigners.hedgedCandidateForTesting(
                failureKey, output -> {
                    failureAux.set(output);
                    Arrays.fill(output, (byte) 0x6b);
                    throw new IllegalStateException("injected provider failure");
                });
        assertThrows(IllegalStateException.class,
                () -> failureSigner.sign(message(7)));
        assertAllZero(failureAux.get());
        failureSigner.close();
    }

    @Test
    @DisplayName("hedged-v1 candidate signature vector is pinned")
    void hedgedCandidateSignatureVector() {
        EdDSAJubjub.Signature signature =
                hedged(BigInteger.ONE, message(0), new byte[32]);
        String vector = "r.u=" + signature.r().affineU().toString(16)
                + ";r.v=" + signature.r().affineV().toString(16)
                + ";s=" + signature.s().toString(16);
        assertEquals(
                "r.u=3d88964c92cd3be8cc36c0c816109969026c063aaf38783413d2eddfdede4703"
                        + ";r.v=b972b74f628eddc4b677f51357356bc374e087d90b6f39ad2df5c0758fa3205"
                        + ";s=79c82bc79d94d80361209007bb81f2e8bf13f747360d8d08aa0966c444c18c1",
                vector);
    }

    private static EdDSAJubjub.Signature hedged(
            BigInteger secret, JubjubMessage message, byte[] auxiliary) {
        try (HardenedJubjubKey key =
                     HardenedJubjubKey.importCanonical(fixed32(secret));
             JubjubSigner signer =
                     JubjubSigners.hedgedCandidateForTesting(
                             key, output ->
                                     System.arraycopy(auxiliary, 0, output, 0, output.length))) {
            EdDSAJubjub.Signature signature = signer.sign(message);
            assertTrue(EdDSAJubjub.verify(signer.publicKey(), message, signature));
            return signature;
        }
    }

    private static JubjubAuxiliaryRandomSource fixedAuxiliary(byte value) {
        return output -> Arrays.fill(output, value);
    }

    private static Throwable captureCloseFailure(JubjubSigner signer) {
        try {
            signer.close();
            return null;
        } catch (RuntimeException | Error failure) {
            return failure;
        }
    }

    private static JubjubMessage message(long value) {
        return JubjubMessage.fromCanonicalFieldBytes(
                fixed32(BigInteger.valueOf(value)));
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

    private static BigInteger randomBelow(BigInteger modulus) {
        BigInteger value;
        do {
            value = new BigInteger(modulus.bitLength(), RANDOM);
        } while (value.compareTo(modulus) >= 0);
        return value;
    }

    private static BigInteger randomNonZeroBelow(BigInteger modulus) {
        BigInteger value;
        do {
            value = randomBelow(modulus);
        } while (value.signum() == 0);
        return value;
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int source = raw.length == 33 && raw[0] == 0 ? 1 : 0;
        System.arraycopy(raw, source, out, out.length - (raw.length - source),
                raw.length - source);
        return out;
    }

    private static void assertAllZero(long[] values) {
        assertTrue(values != null);
        for (long value : values) {
            assertEquals(0L, value);
        }
    }

    private static void assertAllZero(byte[] values) {
        assertTrue(values != null);
        for (byte value : values) {
            assertEquals((byte) 0, value);
        }
    }
}
