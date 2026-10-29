package org.zeroj.bls12381.pedersen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M2 and {@code pedersen-bls12-381-g1-v1} §5.1, §7, §8: cleanup and failure propagation on
 * every exit of {@link G1PedersenBytesHash}, and validation before any digest is obtained.
 *
 * <p>A port of the Jubjub {@code PedersenBytesCleanupTest}. A tracking digest delegates to the real
 * SHA-256 and keeps a reference to every array the mapper hands it or receives from it. Failures are
 * injected at every update, at every digest output and at the reset, for both the array and the
 * stream paths. After each run: the original exception propagated (a reset failure is only attached
 * as suppressed), the digest was reset, every owned temporary (digest outputs, the length suffix,
 * the XOR chain value, the read buffer) is all zero, and the caller's payload is unchanged.
 */
class G1PedersenBytesCleanupTest {

    private static final byte[] PAYLOAD = G1PedersenBytesStreamTest.pattern(10_000);
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();
    private static final BigInteger Q = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    /** {@code DST_S ‖ 0x34}: 52 + 1 octets. */
    private static final int DST_PRIME_BYTES = 53;

    @Test
    @DisplayName("Array path: every injected update/digest failure propagates unchanged and leaves no secret temporaries")
    void arrayPathFaultInjection() throws Exception {
        TrackingDigest dry = new TrackingDigest(0, 0, false);
        G1PedersenBytesHash.hashToScalar(PAYLOAD.clone(), dry);
        assertTrue(dry.updates > 5 && dry.digests == 3, "dry run: " + dry.updates + " updates, " + dry.digests + " digests");
        assertClean(dry, PAYLOAD);

        for (int k = 1; k <= dry.updates; k++) {
            TrackingDigest d = new TrackingDigest(k, 0, false);
            byte[] payload = PAYLOAD.clone();
            RuntimeException e = assertThrows(RuntimeException.class, () -> G1PedersenBytesHash.hashToScalar(payload, d));
            assertSame(d.marker, e, "update failure " + k + " must propagate unchanged");
            assertArrayEquals(PAYLOAD, payload, "caller payload untouched");
            assertClean(d, PAYLOAD);
        }
        for (int k = 1; k <= 3; k++) {
            TrackingDigest d = new TrackingDigest(0, k, false);
            assertSame(d.marker, assertThrows(RuntimeException.class, () -> G1PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d)));
            assertClean(d, PAYLOAD);
        }
    }

    @Test
    @DisplayName("Stream path: injected update/digest/I/O failures propagate unchanged; buffer and temporaries wiped")
    void streamPathFaultInjection() throws Exception {
        TrackingDigest dry = new TrackingDigest(0, 0, false);
        G1PedersenBytesStreamTest.CapturingStream dryIn =
                new G1PedersenBytesStreamTest.CapturingStream(new ByteArrayInputStream(PAYLOAD));
        stream(dryIn, dry);
        assertClean(dry, PAYLOAD);
        assertTrue(allZero(dryIn.buffer));

        for (int k = 1; k <= dry.updates; k++) {
            TrackingDigest d = new TrackingDigest(k, 0, false);
            G1PedersenBytesStreamTest.CapturingStream in =
                    new G1PedersenBytesStreamTest.CapturingStream(new ByteArrayInputStream(PAYLOAD));
            assertSame(d.marker, assertThrows(RuntimeException.class, () -> stream(in, d)), "update failure " + k);
            assertClean(d, PAYLOAD);
            assertTrue(in.buffer == null || allZero(in.buffer), "read buffer wiped, update failure " + k);
        }
        for (int k = 1; k <= 3; k++) {
            TrackingDigest d = new TrackingDigest(0, k, false);
            G1PedersenBytesStreamTest.CapturingStream in =
                    new G1PedersenBytesStreamTest.CapturingStream(new ByteArrayInputStream(PAYLOAD));
            assertSame(d.marker, assertThrows(RuntimeException.class, () -> stream(in, d)));
            assertClean(d, PAYLOAD);
            assertTrue(allZero(in.buffer));
        }
        // I/O failure after most of the payload has been hashed.
        TrackingDigest d = new TrackingDigest(0, 0, false);
        G1PedersenBytesStreamTest.CapturingStream in = new G1PedersenBytesStreamTest.CapturingStream(
                new G1PedersenBytesStreamTest.FaultingStream(PAYLOAD, 9_000));
        IOException io = assertThrows(IOException.class, () -> stream(in, d));
        assertEquals("injected fault", io.getMessage());
        assertClean(d, PAYLOAD);
        assertTrue(allZero(in.buffer));
        assertEquals(0, d.digests, "no digest output after a read failure");
    }

    @Test
    @DisplayName("A reset failure is suppressed under the original failure, and blocks an otherwise successful result")
    void resetFailureNeverHidesOrBecomesSuccess() throws Exception {
        // Original I/O failure + reset failure: the IOException wins, the reset failure is suppressed.
        TrackingDigest d1 = new TrackingDigest(0, 0, true);
        IOException io = assertThrows(IOException.class, () -> stream(
                new G1PedersenBytesStreamTest.FaultingStream(PAYLOAD, 5_000), d1));
        assertEquals(1, io.getSuppressed().length);
        assertSame(d1.resetFailure, io.getSuppressed()[0]);

        // Original provider failure + reset failure, array path.
        TrackingDigest d2 = new TrackingDigest(3, 0, true);
        RuntimeException e = assertThrows(RuntimeException.class, () -> G1PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d2));
        assertSame(d2.marker, e);
        assertSame(d2.resetFailure, e.getSuppressed()[0]);

        // Original provider failure + reset failure, stream path.
        TrackingDigest d2s = new TrackingDigest(3, 0, true);
        RuntimeException es = assertThrows(RuntimeException.class, () -> stream(new ByteArrayInputStream(PAYLOAD), d2s));
        assertSame(d2s.marker, es);
        assertSame(d2s.resetFailure, es.getSuppressed()[0]);

        // No other failure: the reset failure itself propagates, so no scalar is returned.
        TrackingDigest d3 = new TrackingDigest(0, 0, true);
        assertSame(d3.resetFailure,
                assertThrows(RuntimeException.class, () -> G1PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d3)));
        TrackingDigest d4 = new TrackingDigest(0, 0, true);
        assertSame(d4.resetFailure,
                assertThrows(RuntimeException.class, () -> stream(new ByteArrayInputStream(PAYLOAD), d4)));
    }

    @Test
    @DisplayName("A provider that throws the same instance from update and reset still fails with that instance")
    void selfSuppressionIsAvoided() throws Exception {
        TrackingDigest d = new TrackingDigest(3, 0, false) {
            @Override
            protected void engineReset() {
                throw marker;
            }
        };
        assertSame(d.marker, assertThrows(RuntimeException.class, () -> G1PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d)));
        TrackingDigest ds = new TrackingDigest(3, 0, false) {
            @Override
            protected void engineReset() {
                throw marker;
            }
        };
        assertSame(ds.marker, assertThrows(RuntimeException.class, () -> stream(new ByteArrayInputStream(PAYLOAD), ds)));
    }

    @Test
    @DisplayName("Every entry point rejects invalid arguments before obtaining a digest or reading; precedence null → r → bound")
    void validationBeforeDigest() throws IOException {
        BigInteger ok = BigInteger.ONE;
        BigInteger bad = Q;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(PAYLOAD, ok);
        byte[] p = PAYLOAD;
        long n = PAYLOAD.length;

        List<Executable> badBlinding = List.of(
                () -> PEDERSEN.commitBytes(p, bad),
                () -> PEDERSEN.commitBytes(in(), n, bad),
                () -> PEDERSEN.commitBytesToEnd(in(), n, bad),
                () -> PEDERSEN.verifyBytes(c, p, bad),
                () -> PEDERSEN.verifyBytes(c, in(), n, bad),
                () -> PEDERSEN.verifyBytesToEnd(c, in(), n, bad));
        for (Executable op : badBlinding) {
            assertNoDigest(op, CommitmentError.NON_CANONICAL_SCALAR, "blinding");
        }
        // Blinding and bound both invalid: the blinding is reported.
        List<Executable> both = List.of(
                () -> PEDERSEN.commitBytes(in(), -1, bad),
                () -> PEDERSEN.commitBytesToEnd(in(), -1, bad),
                () -> PEDERSEN.verifyBytes(c, in(), -1, bad),
                () -> PEDERSEN.verifyBytesToEnd(c, in(), -1, bad));
        for (Executable op : both) {
            assertNoDigest(op, CommitmentError.NON_CANONICAL_SCALAR, "blinding");
        }
        // Valid blinding, invalid bound.
        long over = G1PedersenBytesHash.MAX_PAYLOAD_BYTES + 1;
        assertNoDigest(() -> PEDERSEN.commitBytes(in(), over, ok), CommitmentError.LENGTH_OUT_OF_RANGE, "length");
        assertNoDigest(() -> PEDERSEN.commitBytesToEnd(in(), over, ok), CommitmentError.LENGTH_OUT_OF_RANGE, "maxBytes");
        assertNoDigest(() -> PEDERSEN.verifyBytes(c, in(), over, ok), CommitmentError.LENGTH_OUT_OF_RANGE, "length");
        assertNoDigest(() -> PEDERSEN.verifyBytesToEnd(c, in(), over, ok), CommitmentError.LENGTH_OUT_OF_RANGE, "maxBytes");
        assertNoDigest(() -> PEDERSEN.commitBytes(in(), -1, ok), CommitmentError.LENGTH_OUT_OF_RANGE, "length");
        assertNoDigest(() -> PEDERSEN.verifyBytesToEnd(c, in(), -1, ok), CommitmentError.LENGTH_OUT_OF_RANGE, "maxBytes");
        // Null and invalid blinding together: the null is reported.
        assertNoDigest(() -> PEDERSEN.commitBytes((byte[]) null, bad), NullPointerException.class, "payload");
        assertNoDigest(() -> PEDERSEN.commitBytes((InputStream) null, -1, bad), NullPointerException.class, "payload");
        assertNoDigest(() -> PEDERSEN.commitBytes(p, null), NullPointerException.class, "blinding");
        assertNoDigest(() -> PEDERSEN.verifyBytes(null, p, bad), NullPointerException.class, "commitment");
        assertNoDigest(() -> PEDERSEN.verifyBytesToEnd(c, null, -1, bad), NullPointerException.class, "payload");

        // Control: a valid call obtains exactly one digest.
        AtomicInteger acquired = new AtomicInteger();
        G1PedersenBytesHash.installDigestObserverForTesting(acquired::incrementAndGet);
        try {
            PEDERSEN.commitBytesToEnd(new ByteArrayInputStream(PAYLOAD), n, ok);
        } finally {
            G1PedersenBytesHash.clearDigestObserverForTesting();
        }
        assertEquals(1, acquired.get());
    }

    @Test
    @DisplayName("Without generation support, commitBytes* fails right after the null checks: no digest, no read, no blinding check")
    void unsupportedGenerationBeforeEverything() {
        G1Pedersen verifyOnly = G1Pedersen.withProvider(new PublicOnlyProvider());
        assertFalse(verifyOnly.supportsGeneration());
        BigInteger bad = Q;
        assertNoDigest(() -> verifyOnly.commitBytes(PAYLOAD, bad), UnsupportedOperationException.class, "");
        assertNoDigest(() -> verifyOnly.commitBytes(in(), -1, bad), UnsupportedOperationException.class, "");
        assertNoDigest(() -> verifyOnly.commitBytesToEnd(in(), -1, bad), UnsupportedOperationException.class, "");
        // Nulls still come first.
        assertNoDigest(() -> verifyOnly.commitBytes((byte[]) null, bad), NullPointerException.class, "payload");

        // Verification works with public operations only and gives the same verdicts.
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(PAYLOAD, BigInteger.TEN);
        assertTrue(verifyOnly.verifyBytes(c, PAYLOAD, BigInteger.TEN));
        assertFalse(verifyOnly.verifyBytes(c, PAYLOAD, BigInteger.ONE));
    }

    @Test
    @DisplayName("No mutable static state: the mapper holds only constants and the empty test hook")
    void noRetainedState() throws Exception {
        for (Field f : G1PedersenBytesHash.class.getDeclaredFields()) {
            if (f.isSynthetic()) {
                continue; // coverage instrumentation
            }
            assertTrue(Modifier.isStatic(f.getModifiers()) && Modifier.isFinal(f.getModifiers()),
                    "field " + f.getName() + " must be static final");
        }
        // The pinned constants are not altered by use, even through a digest that scribbles on inputs.
        MessageDigest scribbler = new MessageDigest("scribbler") {
            private final MessageDigest delegate = MessageDigest.getInstance("SHA-256");
            @Override protected void engineUpdate(byte input) { delegate.update(input); }
            @Override protected void engineUpdate(byte[] input, int offset, int len) {
                delegate.update(input, offset, len);
                Arrays.fill(input, offset, offset + len, (byte) 0x5a);
            }
            @Override protected byte[] engineDigest() { return delegate.digest(); }
            @Override protected void engineReset() { delegate.reset(); }
        };
        BigInteger before = G1PedersenBytesHash.hashToScalar(new byte[]{1, 2, 3});
        G1PedersenBytesHash.hashToScalar(new byte[]{1, 2, 3}, scribbler);
        assertEquals(before, G1PedersenBytesHash.hashToScalar(new byte[]{1, 2, 3}),
                "a misbehaving digest cannot alter DST_prime or the trailer for later operations");
        // Results do not depend on earlier operations or threads.
        BigInteger[] other = new BigInteger[1];
        Thread t = new Thread(() -> other[0] = G1PedersenBytesHash.hashToScalar(new byte[]{1, 2, 3}));
        t.start();
        t.join();
        assertEquals(before, other[0]);
    }

    // ---- helpers ----

    private static InputStream in() {
        return new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("read before validation");
            }

            @Override
            public int read(byte[] b, int off, int len) {
                throw new AssertionError("read before validation");
            }
        };
    }

    private static void assertNoDigest(Executable op, CommitmentError reason, String messagePart) {
        AtomicInteger acquired = new AtomicInteger();
        G1PedersenBytesHash.installDigestObserverForTesting(acquired::incrementAndGet);
        try {
            CommitmentFormatException e = assertThrows(CommitmentFormatException.class, op);
            assertEquals(reason, e.reason());
            assertTrue(String.valueOf(e.getMessage()).contains(messagePart),
                    "expected the " + messagePart + " failure first, got: " + e.getMessage());
        } finally {
            G1PedersenBytesHash.clearDigestObserverForTesting();
        }
        assertEquals(0, acquired.get(), "a digest was obtained before validation");
    }

    private static void assertNoDigest(Executable op, Class<? extends RuntimeException> type, String messagePart) {
        AtomicInteger acquired = new AtomicInteger();
        G1PedersenBytesHash.installDigestObserverForTesting(acquired::incrementAndGet);
        try {
            RuntimeException e = assertThrows(type, op);
            assertTrue(String.valueOf(e.getMessage()).contains(messagePart),
                    "expected the " + messagePart + " failure first, got: " + e.getMessage());
        } finally {
            G1PedersenBytesHash.clearDigestObserverForTesting();
        }
        assertEquals(0, acquired.get(), "a digest was obtained before validation");
    }

    private static BigInteger stream(InputStream in, MessageDigest d) throws IOException {
        return G1PedersenBytesHash.hashToScalar(in, PAYLOAD.length, true, G1PedersenBytesHash.MAX_PAYLOAD_BYTES, d);
    }

    /** Every owned temporary the mapper exchanged with the digest is zero; the digest was reset. */
    private static void assertClean(TrackingDigest d, byte[] payload) {
        assertTrue(d.resets >= 1, "digest reset on exit");
        for (byte[] out : d.outputs) {
            assertTrue(allZero(out), "digest output not wiped");
        }
        for (byte[] in : d.inputs.keySet()) {
            int len = in.length;
            // Public trailer I2OSP(48, 2) ‖ 0x00, DST_prime, zero pad.
            boolean constantCopy = len == 3 || len == DST_PRIME_BYTES || len == 64;
            boolean callerPayload = Arrays.equals(in, payload) && len == payload.length;
            if (!constantCopy && !callerPayload && len <= 32) {
                assertTrue(allZero(in), "owned temporary of length " + len + " not wiped");
            }
            if (len == G1PedersenBytesHash.BUFFER_BYTES && !callerPayload) {
                assertTrue(allZero(in), "read buffer not wiped");
            }
        }
    }

    private static boolean allZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    /** The pure-Java provider without its secret-scalar method: verification only. */
    static final class PublicOnlyProvider implements Bls12381Provider {
        private final Bls12381Provider delegate = PureJavaBls12381Provider.INSTANCE;

        @Override public String id() { return "public-only-test"; }
        @Override public G1Point g1Generator() { return delegate.g1Generator(); }
        @Override public G2Point g2Generator() { return delegate.g2Generator(); }
        @Override public G1Point g1ScalarMul(G1Point point, BigInteger scalar) { return delegate.g1ScalarMul(point, scalar); }
        @Override public G2Point g2ScalarMul(G2Point point, BigInteger scalar) { return delegate.g2ScalarMul(point, scalar); }
        @Override public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
            return delegate.pairingProductIsIdentity(g1Points, g2Points);
        }
    }

    /** Delegates to SHA-256, records arrays, and can fail on the k-th update, the k-th digest, or reset. */
    static class TrackingDigest extends MessageDigest {
        final RuntimeException marker = new IllegalStateException("injected provider failure");
        final RuntimeException resetFailure = new IllegalStateException("injected reset failure");
        private final MessageDigest delegate;
        private final int failUpdate;
        private final int failDigest;
        private final boolean failReset;
        final Map<byte[], Boolean> inputs = new IdentityHashMap<>();
        final List<byte[]> outputs = new ArrayList<>();
        int updates;
        int digests;
        int resets;

        TrackingDigest(int failUpdate, int failDigest, boolean failReset) throws NoSuchAlgorithmException {
            super("tracking-sha256");
            this.delegate = MessageDigest.getInstance("SHA-256");
            this.failUpdate = failUpdate;
            this.failDigest = failDigest;
            this.failReset = failReset;
        }

        @Override
        protected void engineUpdate(byte input) {
            if (++updates == failUpdate) throw marker;
            delegate.update(input);
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            if (++updates == failUpdate) throw marker;
            inputs.put(input, Boolean.TRUE);
            delegate.update(input, offset, len);
        }

        @Override
        protected byte[] engineDigest() {
            if (++digests == failDigest) throw marker;
            byte[] out = delegate.digest();
            outputs.add(out);
            return out;
        }

        @Override
        protected void engineReset() {
            resets++;
            delegate.reset();
            if (failReset) throw resetFailure;
        }
    }
}
