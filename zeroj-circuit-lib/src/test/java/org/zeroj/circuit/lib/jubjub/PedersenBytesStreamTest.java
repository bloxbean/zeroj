package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 D6 / spec §6.1: arrays, declared-length streams and bounded read-to-end streams map
 * the same octets to the same scalar under every chunking; truncation, excess input, read faults
 * and invalid bounds never succeed; the stream is never closed; and invalid arguments are
 * rejected before the first read.
 */
class PedersenBytesStreamTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int[] LENGTHS = {0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128,
            PedersenBytesHash.BUFFER_BYTES - 1, PedersenBytesHash.BUFFER_BYTES, PedersenBytesHash.BUFFER_BYTES + 1,
            3 * PedersenBytesHash.BUFFER_BYTES + 17, 100_000};
    private static final int[] CHUNKS = {1, 3, 7, 64, 4095, PedersenBytesHash.BUFFER_BYTES, Integer.MAX_VALUE};

    static byte[] pattern(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (131 * i + 17);
        }
        return b;
    }

    @Test
    @DisplayName("Array, declared-length and to-end streams agree for every length and chunking")
    void allSourcesAgree() throws IOException {
        for (int n : LENGTHS) {
            byte[] payload = pattern(n);
            BigInteger expected = PedersenBytesHash.hashToScalar(payload);
            for (int chunk : CHUNKS) {
                assertEquals(expected, PedersenBytesHash.hashToScalar(new ChunkedStream(payload, chunk), n, true),
                        "declared n=" + n + " chunk=" + chunk);
                assertEquals(expected, PedersenBytesHash.hashToScalar(new ChunkedStream(payload, chunk), n, false),
                        "to-end at the limit n=" + n + " chunk=" + chunk);
                assertEquals(expected, PedersenBytesHash.hashToScalar(new ChunkedStream(payload, chunk), n + 5L, false),
                        "to-end below the limit n=" + n + " chunk=" + chunk);
            }
            // Irregular reads: a different chunk size on every call, including zero-progress reads.
            assertEquals(expected, PedersenBytesHash.hashToScalar(new IrregularStream(payload), n, true), "irregular n=" + n);
            assertEquals(expected, PedersenBytesHash.hashToScalar(new IrregularStream(payload), Long.MAX_VALUE >>> 3, false),
                    "irregular to-end n=" + n);
        }
    }

    @Test
    @DisplayName("Generated input of unknown length is hashed in one pass to the same scalar")
    void unknownLengthGenerator() throws IOException {
        int n = 1 << 20;
        BigInteger expected = PedersenBytesHash.hashToScalar(pattern(n));
        assertEquals(expected, PedersenBytesHash.hashToScalar(new GeneratedStream(n), PedersenBytesHash.MAX_PAYLOAD_BYTES, false));
    }

    @Test
    @DisplayName("Public commit and verify agree across all three sources")
    void publicApiAgrees() throws IOException {
        byte[] payload = pattern(20_000);
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(payload, r);
        assertEquals(c, PedersenCommitment.commitBytes(new ChunkedStream(payload, 333), payload.length, r));
        assertEquals(c, PedersenCommitment.commitBytesToEnd(new ChunkedStream(payload, 333), 1 << 20, r));
        assertTrue(PedersenCommitment.verifyBytes(c, new ChunkedStream(payload, 1), payload.length, r));
        assertTrue(PedersenCommitment.verifyBytesToEnd(c, new ChunkedStream(payload, 8192), payload.length, r));
        byte[] shorter = java.util.Arrays.copyOf(payload, payload.length - 1);
        assertFalse(PedersenCommitment.verifyBytesToEnd(c, new ByteArrayInputStream(shorter), payload.length, r));
    }

    @Test
    @DisplayName("Declared length: early end of stream fails, for every length and chunking")
    void declaredTruncationFails() {
        for (int n : new int[]{1, 64, 8193}) {
            byte[] payload = pattern(n - 1);
            for (int chunk : new int[]{1, 4096}) {
                RecordingStream s = new RecordingStream(new ChunkedStream(payload, chunk));
                assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(s, n, true));
                assertFalse(s.closed, "never closed");
            }
        }
        BigInteger r = BigInteger.ONE;
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(pattern(10), r);
        assertThrows(IOException.class, () -> PedersenCommitment.commitBytes(new ByteArrayInputStream(pattern(9)), 10, r));
        assertThrows(IOException.class, () -> PedersenCommitment.verifyBytes(c, new ByteArrayInputStream(pattern(9)), 10, r));
    }

    @Test
    @DisplayName("Excess input fails in both modes; at most bound + 1 octets are read")
    void excessFails() {
        for (int n : new int[]{0, 1, 64, 8192}) {
            byte[] longer = pattern(n + 3);
            for (boolean exact : new boolean[]{true, false}) {
                RecordingStream s = new RecordingStream(new ByteArrayInputStream(longer));
                assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(s, n, exact));
                assertEquals(n + 1L, s.delivered, "reads exactly bound + 1 octets, n=" + n + " exact=" + exact);
                assertFalse(s.closed);
            }
        }
        BigInteger r = BigInteger.ONE;
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(pattern(10), r);
        assertThrows(IOException.class, () -> PedersenCommitment.commitBytesToEnd(new ByteArrayInputStream(pattern(11)), 10, r));
        assertThrows(IOException.class, () -> PedersenCommitment.verifyBytes(c, new ByteArrayInputStream(pattern(11)), 10, r));
        assertThrows(IOException.class, () -> PedersenCommitment.verifyBytesToEnd(c, new ByteArrayInputStream(pattern(11)), 10, r));
    }

    @Test
    @DisplayName("Success reads exactly the payload plus one end-of-stream probe at the bound, and never closes")
    void successConsumption() throws IOException {
        byte[] payload = pattern(5000);
        RecordingStream declared = new RecordingStream(new ByteArrayInputStream(payload));
        PedersenBytesHash.hashToScalar(declared, payload.length, true);
        assertEquals(payload.length, declared.delivered);
        assertTrue(declared.sawEof, "probed for end of stream");
        assertFalse(declared.closed);

        RecordingStream below = new RecordingStream(new ByteArrayInputStream(payload));
        PedersenBytesHash.hashToScalar(below, payload.length + 100L, false);
        assertEquals(payload.length, below.delivered);
        assertFalse(below.closed);
    }

    @Test
    @DisplayName("Zero bounds: an empty stream maps like the empty array; one octet is excess")
    void zeroBounds() throws IOException {
        BigInteger empty = PedersenBytesHash.hashToScalar(new byte[0]);
        assertEquals(empty, PedersenBytesHash.hashToScalar(InputStream.nullInputStream(), 0, true));
        assertEquals(empty, PedersenBytesHash.hashToScalar(InputStream.nullInputStream(), 0, false));
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(new ByteArrayInputStream(new byte[1]), 0, true));
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(new ByteArrayInputStream(new byte[1]), 0, false));
    }

    @Test
    @DisplayName("Read faults propagate at every stage, including the end-of-stream probe")
    void faultsPropagate() {
        byte[] payload = pattern(20_000);
        for (long failAt : new long[]{0, 1, 8191, 8192, 19_999, 20_000}) {
            for (boolean exact : new boolean[]{true, false}) {
                RecordingStream s = new RecordingStream(new FaultingStream(payload, failAt));
                assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(s, payload.length, exact),
                        "failAt=" + failAt + " exact=" + exact);
                assertFalse(s.closed);
            }
        }
    }

    @Test
    @DisplayName("Read results outside [−1, requested] are failures, never success or stale bytes")
    void invalidReadCounts() {
        InputStream overReports = new InputStream() {
            @Override public int read() { return 1; }
            @Override public int read(byte[] b, int off, int len) { return len + 1; }
        };
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(overReports, 100, false));
        InputStream negative = new InputStream() {
            @Override public int read() { return -1; }
            @Override public int read(byte[] b, int off, int len) { return -2; }
        };
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(negative, 100, false));
        InputStream badSingle = new InputStream() {
            @Override public int read() { return 256; }
            @Override public int read(byte[] b, int off, int len) { return 0; }
        };
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(badSingle, 100, false));
    }

    @Test
    @DisplayName("A zero-octet bulk read is not end of stream; it falls back to a single-octet read")
    void zeroProgressIsNotEof() throws IOException {
        byte[] payload = pattern(300);
        assertEquals(PedersenBytesHash.hashToScalar(payload),
                PedersenBytesHash.hashToScalar(new ZeroProgressStream(payload), 10_000, false),
                "a to-end stream that returns 0 must not be committed as a truncated prefix");
        assertEquals(PedersenBytesHash.hashToScalar(payload),
                PedersenBytesHash.hashToScalar(new ZeroProgressStream(payload), payload.length, true));
    }

    @Test
    @DisplayName("Invalid bounds are rejected before any read")
    void boundsCheckedFirst() {
        BigInteger r = BigInteger.ONE;
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(new byte[0], r);
        long max = PedersenBytesHash.MAX_PAYLOAD_BYTES;
        for (long bad : new long[]{-1, Long.MIN_VALUE, max + 1, Long.MAX_VALUE}) {
            RecordingStream s = new RecordingStream(new ByteArrayInputStream(pattern(10)));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.commitBytes(s, bad, r));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.commitBytesToEnd(s, bad, r));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.verifyBytes(c, s, bad, r));
            assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.verifyBytesToEnd(c, s, bad, r));
            assertEquals(0, s.calls, "no read before validation, bound=" + bad);
        }
        RecordingStream s = new RecordingStream(new ByteArrayInputStream(pattern(10)));
        assertThrows(IllegalArgumentException.class,
                () -> PedersenCommitment.commitBytes(s, 10, JubjubCurve.SUBGROUP_ORDER));
        assertThrows(IllegalArgumentException.class,
                () -> PedersenCommitment.verifyBytesToEnd(c, s, 10, BigInteger.ONE.negate()));
        assertEquals(0, s.calls, "no read before blinding validation");
    }

    @Test
    @DisplayName("The normative maximum is accepted as a bound; cap and cap + 1 behave at the injected seam")
    void capBoundary() throws Exception {
        // The real cap cannot be reached with I/O; the seam takes a small cap and the same code path.
        long cap = 1000;
        byte[] atCap = pattern((int) cap);
        assertEquals(PedersenBytesHash.hashToScalar(atCap),
                PedersenBytesHash.hashToScalar(new ByteArrayInputStream(atCap), cap, true, cap, sha256()));
        assertEquals(PedersenBytesHash.hashToScalar(atCap),
                PedersenBytesHash.hashToScalar(new ByteArrayInputStream(atCap), cap, false, cap, sha256()));
        assertThrows(IllegalArgumentException.class,
                () -> PedersenBytesHash.hashToScalar(new ByteArrayInputStream(atCap), cap + 1, false, cap, sha256()));
        RecordingStream over = new RecordingStream(new ByteArrayInputStream(pattern((int) cap + 1)));
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(over, cap, false, cap, sha256()));
        assertEquals(cap + 1, over.delivered);

        // The real maximum is a valid declared bound: an empty to-end stream under it succeeds.
        assertEquals(PedersenBytesHash.hashToScalar(new byte[0]),
                PedersenBytesHash.hashToScalar(InputStream.nullInputStream(), PedersenBytesHash.MAX_PAYLOAD_BYTES, false));
        assertEquals((1L << 61) - 256, PedersenBytesHash.MAX_PAYLOAD_BYTES);
        assertTrue(PedersenBytesHash.MAX_PAYLOAD_BYTES + 122 < (1L << 61));
    }

    @Test
    @DisplayName("A bound past int range sizes the buffer correctly and is not truncated (the 2^31 crossing itself is in the opt-in resource test)")
    void boundPastIntRange() throws IOException {
        // A cheap structural check of the counter: the declared bound exceeds int range and an
        // early end of stream must be reported as truncation, not as success or overflow.
        long bound = (1L << 31) + 5;
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(new GeneratedStream(1 << 16), bound, true));
        assertEquals(PedersenBytesHash.hashToScalar(pattern(1 << 16)),
                PedersenBytesHash.hashToScalar(new GeneratedStream(1 << 16), bound, false));
    }

    @Test
    @DisplayName("A digest provider failure propagates and never yields a scalar")
    void providerFailurePropagates() {
        MessageDigest broken = new MessageDigest("broken") {
            @Override protected void engineUpdate(byte input) { throw new IllegalStateException("provider failure"); }
            @Override protected void engineUpdate(byte[] input, int offset, int len) { throw new IllegalStateException("provider failure"); }
            @Override protected byte[] engineDigest() { throw new IllegalStateException("provider failure"); }
            @Override protected void engineReset() { }
        };
        assertThrows(IllegalStateException.class, () -> PedersenBytesHash.hashToScalar(new byte[3], broken));
        assertThrows(IllegalStateException.class, () -> PedersenBytesHash.hashToScalar(
                new ByteArrayInputStream(new byte[3]), 3, true, PedersenBytesHash.MAX_PAYLOAD_BYTES, broken));
    }

    @Test
    @DisplayName("A single-octet read returning −2 after a zero-progress read fails; it is not end of stream")
    void singleReadNegativeTwoFails() {
        InputStream s = new ScriptedStream(pattern(5), new int[]{0}, -2);
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(s, 100, false));
    }

    @Test
    @DisplayName("A single-octet read returning 256 fails rather than hashing a phantom octet")
    void singleRead256Fails() {
        InputStream s = new ScriptedStream(pattern(5), new int[]{0}, 256);
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(s, 100, false));
    }

    @Test
    @DisplayName("The end-of-stream probe treats −2 and 256 as failures in both modes")
    void probeOutOfRangeFails() {
        for (int bad : new int[]{-2, 256, Integer.MIN_VALUE}) {
            for (boolean exact : new boolean[]{true, false}) {
                InputStream s = new ProbeStream(pattern(10), bad);
                assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(s, 10, exact),
                        "probe value " + bad + " exact=" + exact);
            }
        }
    }

    @Test
    @DisplayName("An over-reported count is a failure even when it still fits the buffer (no stale octets)")
    void overReportWithinBufferFails() {
        int n = 2 * PedersenBytesHash.BUFFER_BYTES + 3616;
        byte[] payload = pattern(n);
        InputStream overReportsShortReads = new ChunkedStream(payload, Integer.MAX_VALUE) {
            @Override
            public int read(byte[] b, int off, int len) {
                int got = super.read(b, off, len);
                return got > 0 && len < b.length ? got + 1 : got;
            }
        };
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(overReportsShortReads, n, true));
    }

    @Test
    @DisplayName("The owned read buffer is wiped after success and after failure")
    void bufferWipedOnEveryExit() throws IOException {
        CapturingStream ok = new CapturingStream(new ByteArrayInputStream(pattern(20_000)));
        PedersenBytesHash.hashToScalar(ok, 20_000, true);
        assertTrue(ok.buffer != null && allZero(ok.buffer), "buffer wiped after success");

        CapturingStream failing = new CapturingStream(new FaultingStream(pattern(20_000), 9_000));
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(failing, 20_000, true));
        assertTrue(failing.buffer != null && allZero(failing.buffer), "buffer wiped after an I/O failure");

        CapturingStream excess = new CapturingStream(new ByteArrayInputStream(pattern(101)));
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(excess, 100, false));
        assertTrue(excess.buffer != null && allZero(excess.buffer), "buffer wiped after excess input");
    }

    @Test
    @DisplayName("The operation-owned digest is reset on stream and array failures (no partial payload state)")
    void digestResetOnFailure() throws Exception {
        byte[] emptyDigest = MessageDigest.getInstance("SHA-256").digest();

        MessageDigest streamDigest = sha256();
        assertThrows(IOException.class, () -> PedersenBytesHash.hashToScalar(
                new FaultingStream(pattern(20_000), 12_345), 20_000, true, PedersenBytesHash.MAX_PAYLOAD_BYTES, streamDigest));
        assertArrayEquals(emptyDigest, streamDigest.digest(), "stream path reset after failure");

        FailingAfterDigest arrayDigest = new FailingAfterDigest(sha256(), 2);
        assertThrows(IllegalStateException.class, () -> PedersenBytesHash.hashToScalar(pattern(5000), arrayDigest));
        assertArrayEquals(emptyDigest, arrayDigest.delegate.digest(), "array path reset after failure");

        MessageDigest okDigest = sha256();
        PedersenBytesHash.hashToScalar(pattern(5000), okDigest);
        assertArrayEquals(emptyDigest, okDigest.digest(), "reset after success too");
    }

    private static MessageDigest sha256() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256");
    }

    // ---- test streams ----

    private static boolean allZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    /** Bulk reads follow {@code bulk} (0 = zero progress) then deliver data; the next single read returns {@code single}. */
    static final class ScriptedStream extends InputStream {
        private final byte[] data;
        private final int[] bulk;
        private final int single;
        private int pos;
        private int call;
        private boolean singleUsed;

        ScriptedStream(byte[] data, int[] bulk, int single) {
            this.data = data;
            this.bulk = bulk;
            this.single = single;
        }

        @Override
        public int read() {
            if (!singleUsed) {
                singleUsed = true;
                return single;
            }
            return -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (call < bulk.length) {
                call++;
                if (bulk[call - 1] == 0) return 0;
            }
            if (pos >= data.length) return 0; // force the single-octet fallback
            int n = Math.min(len, data.length - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    /** Delivers {@code data} through bulk reads; the single-octet probe returns {@code probe}. */
    static final class ProbeStream extends InputStream {
        private final byte[] data;
        private final int probe;
        private int pos;

        ProbeStream(byte[] data, int probe) {
            this.data = data;
            this.probe = probe;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & 0xff : probe;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (pos >= data.length) return -1;
            int n = Math.min(len, data.length - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    /** Keeps a reference to the caller's read buffer so a test can inspect it afterwards. */
    static final class CapturingStream extends InputStream {
        private final InputStream in;
        byte[] buffer;

        CapturingStream(InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            return in.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            buffer = b;
            return in.read(b, off, len);
        }
    }

    /** Delegates to a real digest and throws on the {@code failOn}-th update call. */
    static final class FailingAfterDigest extends MessageDigest {
        final MessageDigest delegate;
        private final int failOn;
        private int updates;

        FailingAfterDigest(MessageDigest delegate, int failOn) {
            super("failing-after");
            this.delegate = delegate;
            this.failOn = failOn;
        }

        private void tick() {
            if (++updates == failOn) throw new IllegalStateException("provider failure");
        }

        @Override protected void engineUpdate(byte input) { tick(); delegate.update(input); }
        @Override protected void engineUpdate(byte[] input, int offset, int len) { tick(); delegate.update(input, offset, len); }
        @Override protected byte[] engineDigest() { return delegate.digest(); }
        @Override protected void engineReset() { delegate.reset(); }
    }

    /** Returns at most {@code chunk} octets per bulk read. */
    static class ChunkedStream extends InputStream {
        private final byte[] data;
        private final int chunk;
        private int pos;

        ChunkedStream(byte[] data, int chunk) {
            this.data = data;
            this.chunk = chunk;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & 0xff : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (pos >= data.length) return -1;
            int n = Math.min(Math.min(len, chunk), data.length - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    /** Chunk sizes cycle through 1, 0, 7, 2, 300, 0, 5000 — zero means a zero-progress read. */
    static final class IrregularStream extends InputStream {
        private static final int[] SIZES = {1, 0, 7, 2, 300, 0, 5000};
        private final byte[] data;
        private int pos;
        private int call;

        IrregularStream(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & 0xff : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (pos >= data.length) return -1;
            int n = Math.min(Math.min(len, SIZES[call++ % SIZES.length]), data.length - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    /** Every bulk read returns 0; only single-octet reads make progress. */
    static final class ZeroProgressStream extends InputStream {
        private final byte[] data;
        private int pos;

        ZeroProgressStream(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & 0xff : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            return pos < data.length ? 0 : -1;
        }
    }

    /** Generates {@link #pattern} octets on the fly without materialising them. */
    static final class GeneratedStream extends InputStream {
        private final long length;
        private long pos;

        GeneratedStream(long length) {
            this.length = length;
        }

        @Override
        public int read() {
            return pos < length ? (int) ((131 * pos++ + 17) & 0xff) : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (pos >= length) return -1;
            int n = (int) Math.min(len, length - pos);
            for (int i = 0; i < n; i++) {
                b[off + i] = (byte) (131 * (pos + i) + 17);
            }
            pos += n;
            return n;
        }
    }

    /** Throws once {@code failAt} octets have been delivered (including the end-of-stream probe). */
    static final class FaultingStream extends InputStream {
        private final byte[] data;
        private final long failAt;
        private int pos;

        FaultingStream(byte[] data, long failAt) {
            this.data = data;
            this.failAt = failAt;
        }

        @Override
        public int read() throws IOException {
            if (pos >= failAt) throw new IOException("injected fault");
            return pos < data.length ? data[pos++] & 0xff : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (pos >= failAt) throw new IOException("injected fault");
            if (pos >= data.length) return -1;
            int n = (int) Math.min(Math.min(len, data.length - pos), failAt - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    /** Records delivered octets, calls, end-of-stream and any close/reset/skip/available use. */
    static final class RecordingStream extends InputStream {
        private final InputStream in;
        long delivered;
        int calls;
        boolean sawEof;
        boolean closed;

        RecordingStream(InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            calls++;
            int v = in.read();
            if (v < 0) sawEof = true; else delivered++;
            return v;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            calls++;
            int n = in.read(b, off, len);
            if (n < 0) sawEof = true; else delivered += n;
            return n;
        }

        @Override
        public void close() {
            closed = true;
        }

        @Override
        public synchronized void reset() {
            throw new AssertionError("reset must not be called");
        }

        @Override
        public long skip(long n) {
            throw new AssertionError("skip must not be called");
        }

        @Override
        public int available() {
            throw new AssertionError("available must not be called");
        }
    }
}
