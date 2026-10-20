package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 D5/I8 and spec §6/§7: cleanup and failure propagation on every exit, and validation
 * before any digest is obtained.
 *
 * <p>A tracking digest delegates to the real SHA-256 and keeps a reference to every array the
 * mapper hands it or receives from it. Failures are injected at every update, at every digest
 * output and at the reset, for both the array and the stream paths. After each run: the original
 * exception propagated (a reset failure is only attached as suppressed), the digest was reset,
 * every owned temporary (digest outputs, the length suffix, the XOR chain value, the read buffer)
 * is all zero, and the caller's payload is unchanged.
 */
class PedersenBytesCleanupTest {

    private static final byte[] PAYLOAD = PedersenBytesStreamTest.pattern(10_000);

    @Test
    @DisplayName("Array path: every injected update/digest failure propagates unchanged and leaves no secret temporaries")
    void arrayPathFaultInjection() throws Exception {
        TrackingDigest dry = new TrackingDigest(0, 0, false);
        PedersenBytesHash.hashToScalar(PAYLOAD.clone(), dry);
        assertTrue(dry.updates > 5 && dry.digests == 3, "dry run: " + dry.updates + " updates, " + dry.digests + " digests");
        assertClean(dry, PAYLOAD);

        for (int k = 1; k <= dry.updates; k++) {
            TrackingDigest d = new TrackingDigest(k, 0, false);
            byte[] payload = PAYLOAD.clone();
            RuntimeException e = assertThrows(RuntimeException.class, () -> PedersenBytesHash.hashToScalar(payload, d));
            assertSame(d.marker, e, "update failure " + k + " must propagate unchanged");
            assertArrayEquals(PAYLOAD, payload, "caller payload untouched");
            assertClean(d, PAYLOAD);
        }
        for (int k = 1; k <= 3; k++) {
            TrackingDigest d = new TrackingDigest(0, k, false);
            assertSame(d.marker, assertThrows(RuntimeException.class, () -> PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d)));
            assertClean(d, PAYLOAD);
        }
    }

    @Test
    @DisplayName("Stream path: injected update/digest/I/O failures propagate unchanged; buffer and temporaries wiped")
    void streamPathFaultInjection() throws Exception {
        TrackingDigest dry = new TrackingDigest(0, 0, false);
        PedersenBytesStreamTest.CapturingStream dryIn = new PedersenBytesStreamTest.CapturingStream(new ByteArrayInputStream(PAYLOAD));
        stream(dryIn, dry);
        assertClean(dry, PAYLOAD);
        assertTrue(allZero(dryIn.buffer));

        for (int k = 1; k <= dry.updates; k++) {
            TrackingDigest d = new TrackingDigest(k, 0, false);
            PedersenBytesStreamTest.CapturingStream in = new PedersenBytesStreamTest.CapturingStream(new ByteArrayInputStream(PAYLOAD));
            assertSame(d.marker, assertThrows(RuntimeException.class, () -> stream(in, d)), "update failure " + k);
            assertClean(d, PAYLOAD);
            assertTrue(in.buffer == null || allZero(in.buffer), "read buffer wiped, update failure " + k);
        }
        for (int k = 1; k <= 3; k++) {
            TrackingDigest d = new TrackingDigest(0, k, false);
            PedersenBytesStreamTest.CapturingStream in = new PedersenBytesStreamTest.CapturingStream(new ByteArrayInputStream(PAYLOAD));
            assertSame(d.marker, assertThrows(RuntimeException.class, () -> stream(in, d)));
            assertClean(d, PAYLOAD);
            assertTrue(allZero(in.buffer));
        }
        // I/O failure after most of the payload has been hashed.
        TrackingDigest d = new TrackingDigest(0, 0, false);
        PedersenBytesStreamTest.CapturingStream in = new PedersenBytesStreamTest.CapturingStream(
                new PedersenBytesStreamTest.FaultingStream(PAYLOAD, 9_000));
        IOException io = assertThrows(IOException.class, () -> stream(in, d));
        assertEquals("injected fault", io.getMessage());
        assertClean(d, PAYLOAD);
        assertTrue(allZero(in.buffer));
    }

    @Test
    @DisplayName("A reset failure is suppressed under the original failure, and blocks an otherwise successful result")
    void resetFailureNeverHidesOrBecomesSuccess() throws Exception {
        // Original I/O failure + reset failure: the IOException wins, the reset failure is suppressed.
        TrackingDigest d1 = new TrackingDigest(0, 0, true);
        IOException io = assertThrows(IOException.class, () -> stream(
                new PedersenBytesStreamTest.FaultingStream(PAYLOAD, 5_000), d1));
        assertEquals(1, io.getSuppressed().length);
        assertSame(d1.resetFailure, io.getSuppressed()[0]);

        // Original provider failure + reset failure, array path.
        TrackingDigest d2 = new TrackingDigest(3, 0, true);
        RuntimeException e = assertThrows(RuntimeException.class, () -> PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d2));
        assertSame(d2.marker, e);
        assertSame(d2.resetFailure, e.getSuppressed()[0]);

        // No other failure: the reset failure itself propagates, so no scalar is returned.
        TrackingDigest d3 = new TrackingDigest(0, 0, true);
        assertSame(d3.resetFailure,
                assertThrows(RuntimeException.class, () -> PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d3)));
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
        assertSame(d.marker, assertThrows(RuntimeException.class, () -> PedersenBytesHash.hashToScalar(PAYLOAD.clone(), d)));
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
        BigInteger bad = JubjubCurve.SUBGROUP_ORDER;
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(PAYLOAD, ok);
        byte[] p = PAYLOAD;
        long n = PAYLOAD.length;

        List<Executable> badBlinding = List.of(
                () -> PedersenCommitment.commitBytes(p, bad),
                () -> PedersenCommitment.commitBytes(in(), n, bad),
                () -> PedersenCommitment.commitBytesToEnd(in(), n, bad),
                () -> PedersenCommitment.verifyBytes(c, p, bad),
                () -> PedersenCommitment.verifyBytes(c, in(), n, bad),
                () -> PedersenCommitment.verifyBytesToEnd(c, in(), n, bad));
        for (Executable op : badBlinding) {
            assertNoDigest(op, IllegalArgumentException.class, "blinding");
        }
        // Blinding and bound both invalid: the blinding is reported.
        List<Executable> both = List.of(
                () -> PedersenCommitment.commitBytes(in(), -1, bad),
                () -> PedersenCommitment.commitBytesToEnd(in(), -1, bad),
                () -> PedersenCommitment.verifyBytes(c, in(), -1, bad),
                () -> PedersenCommitment.verifyBytesToEnd(c, in(), -1, bad));
        for (Executable op : both) {
            assertNoDigest(op, IllegalArgumentException.class, "blinding");
        }
        // Valid blinding, invalid bound.
        long over = PedersenBytesHash.MAX_PAYLOAD_BYTES + 1;
        assertNoDigest(() -> PedersenCommitment.commitBytes(in(), over, ok), IllegalArgumentException.class, "length");
        assertNoDigest(() -> PedersenCommitment.commitBytesToEnd(in(), over, ok), IllegalArgumentException.class, "maxBytes");
        assertNoDigest(() -> PedersenCommitment.verifyBytes(c, in(), over, ok), IllegalArgumentException.class, "length");
        assertNoDigest(() -> PedersenCommitment.verifyBytesToEnd(c, in(), over, ok), IllegalArgumentException.class, "maxBytes");
        // Null and invalid blinding together: the null is reported.
        assertNoDigest(() -> PedersenCommitment.commitBytes((byte[]) null, bad), NullPointerException.class, "payload");
        assertNoDigest(() -> PedersenCommitment.commitBytes((InputStream) null, -1, bad), NullPointerException.class, "payload");
        assertNoDigest(() -> PedersenCommitment.verifyBytes(null, p, bad), NullPointerException.class, "commitment");

        // Control: a valid call obtains exactly one digest.
        AtomicInteger acquired = new AtomicInteger();
        PedersenBytesHash.installDigestObserverForTesting(acquired::incrementAndGet);
        try {
            PedersenCommitment.commitBytesToEnd(new ByteArrayInputStream(PAYLOAD), n, ok);
        } finally {
            PedersenBytesHash.clearDigestObserverForTesting();
        }
        assertEquals(1, acquired.get());
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

    private static void assertNoDigest(Executable op, Class<? extends RuntimeException> type, String messagePart) {
        AtomicInteger acquired = new AtomicInteger();
        PedersenBytesHash.installDigestObserverForTesting(acquired::incrementAndGet);
        try {
            RuntimeException e = assertThrows(type, op);
            assertTrue(String.valueOf(e.getMessage()).contains(messagePart),
                    "expected the " + messagePart + " failure first, got: " + e.getMessage());
        } finally {
            PedersenBytesHash.clearDigestObserverForTesting();
        }
        assertEquals(0, acquired.get(), "a digest was obtained before validation");
    }

    private static BigInteger stream(InputStream in, MessageDigest d) throws IOException {
        return PedersenBytesHash.hashToScalar(in, PAYLOAD.length, true, PedersenBytesHash.MAX_PAYLOAD_BYTES, d);
    }

    /** Every owned temporary the mapper exchanged with the digest is zero; the digest was reset. */
    private static void assertClean(TrackingDigest d, byte[] payload) {
        assertTrue(d.resets >= 1, "digest reset on exit");
        for (byte[] out : d.outputs) {
            assertTrue(allZero(out), "digest output not wiped");
        }
        for (byte[] in : d.inputs.keySet()) {
            int len = in.length;
            boolean constantCopy = len == 3 || len == 47 || len == 64; // public trailer, DST_prime, zero pad
            boolean callerPayload = Arrays.equals(in, payload) && len == payload.length;
            if (!constantCopy && !callerPayload && len <= 32) {
                assertTrue(allZero(in), "owned temporary of length " + len + " not wiped");
            }
        }
    }

    private static boolean allZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
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
