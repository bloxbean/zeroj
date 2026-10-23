package org.zeroj.bls12381.pedersen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M2 / {@code pedersen-bls12-381-g1-v1} §5.1, §5.2 and §8, importing
 * {@code pedersen-jubjub-bytes-v1} §6.1: arrays, declared-length streams and bounded read-to-end
 * streams map the same octets to the same scalar under every chunking; truncation, excess input,
 * read faults and invalid bounds never succeed; the stream is never closed, reset, marked, skipped
 * or asked for {@code available()}; and invalid arguments are rejected, in the order of §8, before
 * the first read and before any digest is obtained.
 *
 * <p>A port of the Jubjub {@code PedersenBytesStreamTest} to {@link G1PedersenBytesHash} and
 * {@link G1Pedersen}: tag {@code DST_S}, modulus {@code q}, {@code b0} input {@code n + 128}.
 */
class G1PedersenBytesStreamTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();
    private static final BigInteger Q = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final int[] LENGTHS = {0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128,
            G1PedersenBytesHash.BUFFER_BYTES - 1, G1PedersenBytesHash.BUFFER_BYTES, G1PedersenBytesHash.BUFFER_BYTES + 1,
            3 * G1PedersenBytesHash.BUFFER_BYTES + 17, 100_000};
    private static final int[] CHUNKS = {1, 3, 7, 64, 4095, G1PedersenBytesHash.BUFFER_BYTES, Integer.MAX_VALUE};

    /** Octet {@code i} is {@code (131·i + 17) mod 256} ({@code commitment-profiles-v1} §13.2). */
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
            BigInteger expected = G1PedersenBytesHash.hashToScalar(payload);
            for (int chunk : CHUNKS) {
                assertEquals(expected, G1PedersenBytesHash.hashToScalar(new ChunkedStream(payload, chunk), n, true),
                        "declared n=" + n + " chunk=" + chunk);
                assertEquals(expected, G1PedersenBytesHash.hashToScalar(new ChunkedStream(payload, chunk), n, false),
                        "to-end at the limit n=" + n + " chunk=" + chunk);
                assertEquals(expected, G1PedersenBytesHash.hashToScalar(new ChunkedStream(payload, chunk), n + 5L, false),
                        "to-end below the limit n=" + n + " chunk=" + chunk);
            }
            // Irregular reads: a different chunk size on every call, including zero-progress reads.
            assertEquals(expected, G1PedersenBytesHash.hashToScalar(new IrregularStream(payload), n, true), "irregular n=" + n);
            assertEquals(expected, G1PedersenBytesHash.hashToScalar(new IrregularStream(payload), Long.MAX_VALUE >>> 3, false),
                    "irregular to-end n=" + n);
        }
    }

    @Test
    @DisplayName("Generated input of unknown length is hashed in one pass to the same scalar")
    void unknownLengthGenerator() throws IOException {
        int n = 1 << 20;
        BigInteger expected = G1PedersenBytesHash.hashToScalar(pattern(n));
        assertEquals(expected,
                G1PedersenBytesHash.hashToScalar(new GeneratedStream(n), G1PedersenBytesHash.MAX_PAYLOAD_BYTES, false));
    }

    @Test
    @DisplayName("Public commit and verify agree across all three sources")
    void publicApiAgrees() throws IOException {
        byte[] payload = pattern(20_000);
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, r);
        assertEquals(c, PEDERSEN.commitBytes(new ChunkedStream(payload, 333), payload.length, r));
        assertEquals(c, PEDERSEN.commitBytesToEnd(new ChunkedStream(payload, 333), 1 << 20, r));
        assertEquals(c, PEDERSEN.commitBytesToEnd(new IrregularStream(payload), payload.length, r));
        assertTrue(PEDERSEN.verifyBytes(c, payload, r));
        assertTrue(PEDERSEN.verifyBytes(c, new ChunkedStream(payload, 1), payload.length, r));
        assertTrue(PEDERSEN.verifyBytesToEnd(c, new ChunkedStream(payload, 8192), payload.length, r));
        assertTrue(PEDERSEN.verifyBytesToEnd(c, new ZeroProgressStream(payload), payload.length + 1L, r));
        byte[] shorter = Arrays.copyOf(payload, payload.length - 1);
        assertFalse(PEDERSEN.verifyBytesToEnd(c, new ByteArrayInputStream(shorter), payload.length, r));
    }

    @Test
    @DisplayName("Declared length: early end of stream fails, for every length and chunking, and nothing is finished")
    void declaredTruncationFails() throws Exception {
        for (int n : new int[]{1, 64, 8193}) {
            byte[] payload = pattern(n - 1);
            for (int chunk : new int[]{1, 4096}) {
                RecordingStream s = new RecordingStream(new ChunkedStream(payload, chunk));
                CountingDigest d = new CountingDigest();
                assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(
                        s, n, true, G1PedersenBytesHash.MAX_PAYLOAD_BYTES, d));
                assertFalse(s.closed, "never closed");
                // Zero pad plus the n − 1 octets read; no length suffix, no b0 and no b1, b2.
                assertEquals(64L + n - 1, d.octets, "nothing after the payload is hashed, n=" + n);
                assertEquals(0, d.digests, "no digest output before the checks pass");
            }
        }
        BigInteger r = BigInteger.ONE;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(pattern(10), r);
        assertThrows(IOException.class, () -> PEDERSEN.commitBytes(new ByteArrayInputStream(pattern(9)), 10, r));
        assertThrows(IOException.class, () -> PEDERSEN.verifyBytes(c, new ByteArrayInputStream(pattern(9)), 10, r));
    }

    @Test
    @DisplayName("Excess input fails in both modes; exactly bound + 1 octets are read and the excess octet is never hashed")
    void excessFails() throws Exception {
        for (int n : new int[]{0, 1, 64, 8192}) {
            byte[] longer = pattern(n + 3);
            for (boolean exact : new boolean[]{true, false}) {
                RecordingStream s = new RecordingStream(new ByteArrayInputStream(longer));
                CountingDigest d = new CountingDigest();
                assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(
                        s, n, exact, G1PedersenBytesHash.MAX_PAYLOAD_BYTES, d));
                assertEquals(n + 1L, s.delivered, "reads exactly bound + 1 octets, n=" + n + " exact=" + exact);
                assertEquals(64L + n, d.octets, "the probe octet is never hashed, n=" + n + " exact=" + exact);
                assertEquals(0, d.digests, "no length suffix and no output after excess input");
                assertFalse(s.closed);
            }
        }
        BigInteger r = BigInteger.ONE;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(pattern(10), r);
        assertThrows(IOException.class, () -> PEDERSEN.commitBytes(new ByteArrayInputStream(pattern(11)), 10, r));
        assertThrows(IOException.class, () -> PEDERSEN.commitBytesToEnd(new ByteArrayInputStream(pattern(11)), 10, r));
        assertThrows(IOException.class, () -> PEDERSEN.verifyBytes(c, new ByteArrayInputStream(pattern(11)), 10, r));
        assertThrows(IOException.class, () -> PEDERSEN.verifyBytesToEnd(c, new ByteArrayInputStream(pattern(11)), 10, r));
    }

    @Test
    @DisplayName("Success reads exactly the payload plus one end-of-stream probe at the bound, and never closes")
    void successConsumption() throws Exception {
        byte[] payload = pattern(5000);
        RecordingStream declared = new RecordingStream(new ByteArrayInputStream(payload));
        CountingDigest d = new CountingDigest();
        G1PedersenBytesHash.hashToScalar(declared, payload.length, true, G1PedersenBytesHash.MAX_PAYLOAD_BYTES, d);
        assertEquals(payload.length, declared.delivered);
        assertTrue(declared.sawEof, "probed for end of stream");
        assertFalse(declared.closed);
        // b0's input is n + 128 octets: 64 zero pad, n payload, 8 length, 3 trailer, 53 DST_prime.
        assertEquals(payload.length + 128L, d.octetsBeforeFirstDigest, "b0 input is n + 128 octets");
        assertEquals(3, d.digests, "b0, b1, b2");

        RecordingStream below = new RecordingStream(new ByteArrayInputStream(payload));
        G1PedersenBytesHash.hashToScalar(below, payload.length + 100L, false);
        assertEquals(payload.length, below.delivered);
        assertTrue(below.sawEof);
        assertFalse(below.closed);
    }

    @Test
    @DisplayName("Zero bounds: an empty stream maps like the empty array; one octet is excess")
    void zeroBounds() throws IOException {
        BigInteger empty = G1PedersenBytesHash.hashToScalar(new byte[0]);
        assertEquals(empty, G1PedersenBytesHash.hashToScalar(InputStream.nullInputStream(), 0, true));
        assertEquals(empty, G1PedersenBytesHash.hashToScalar(InputStream.nullInputStream(), 0, false));
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(new ByteArrayInputStream(new byte[1]), 0, true));
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(new ByteArrayInputStream(new byte[1]), 0, false));

        BigInteger r = BigInteger.TWO;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(new byte[0], r);
        assertEquals(c, PEDERSEN.commitBytes(InputStream.nullInputStream(), 0, r));
        assertEquals(c, PEDERSEN.commitBytesToEnd(InputStream.nullInputStream(), 0, r));
        assertTrue(PEDERSEN.verifyBytes(c, InputStream.nullInputStream(), 0, r));
        assertTrue(PEDERSEN.verifyBytesToEnd(c, InputStream.nullInputStream(), 0, r));
    }

    @Test
    @DisplayName("Read faults propagate at every stage, including the end-of-stream probe")
    void faultsPropagate() {
        byte[] payload = pattern(20_000);
        for (long failAt : new long[]{0, 1, 8191, 8192, 19_999, 20_000}) {
            for (boolean exact : new boolean[]{true, false}) {
                RecordingStream s = new RecordingStream(new FaultingStream(payload, failAt));
                IOException e = assertThrows(IOException.class,
                        () -> G1PedersenBytesHash.hashToScalar(s, payload.length, exact),
                        "failAt=" + failAt + " exact=" + exact);
                assertEquals("injected fault", e.getMessage(), "the read failure itself propagates");
                assertFalse(s.closed);
            }
        }
        // Through the public API, at the probe (all octets read, the probe throws).
        BigInteger r = BigInteger.ONE;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, r);
        assertThrows(IOException.class, () -> PEDERSEN.commitBytes(new FaultingStream(payload, 20_000), 20_000, r));
        assertThrows(IOException.class, () -> PEDERSEN.commitBytesToEnd(new FaultingStream(payload, 20_000), 20_000, r));
        assertThrows(IOException.class, () -> PEDERSEN.verifyBytes(c, new FaultingStream(payload, 20_000), 20_000, r));
        assertThrows(IOException.class, () -> PEDERSEN.verifyBytesToEnd(c, new FaultingStream(payload, 20_000), 20_000, r));
    }

    @Test
    @DisplayName("Read results outside [−1, requested] are failures, never success or stale bytes")
    void invalidReadCounts() {
        InputStream overReports = new InputStream() {
            @Override public int read() { return 1; }
            @Override public int read(byte[] b, int off, int len) { return len + 1; }
        };
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(overReports, 100, false));
        InputStream negative = new InputStream() {
            @Override public int read() { return -1; }
            @Override public int read(byte[] b, int off, int len) { return -2; }
        };
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(negative, 100, false));
        InputStream minValue = new InputStream() {
            @Override public int read() { return -1; }
            @Override public int read(byte[] b, int off, int len) { return Integer.MIN_VALUE; }
        };
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(minValue, 100, true));
        InputStream badSingle = new InputStream() {
            @Override public int read() { return 256; }
            @Override public int read(byte[] b, int off, int len) { return 0; }
        };
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(badSingle, 100, false));
    }

    @Test
    @DisplayName("A zero-octet bulk read is not end of stream; it falls back to a single-octet read")
    void zeroProgressIsNotEof() throws IOException {
        byte[] payload = pattern(300);
        assertEquals(G1PedersenBytesHash.hashToScalar(payload),
                G1PedersenBytesHash.hashToScalar(new ZeroProgressStream(payload), 10_000, false),
                "a to-end stream that returns 0 must not be committed as a truncated prefix");
        assertEquals(G1PedersenBytesHash.hashToScalar(payload),
                G1PedersenBytesHash.hashToScalar(new ZeroProgressStream(payload), payload.length, true));
    }

    @Test
    @DisplayName("Bounds −1 and MAX_PAYLOAD_BYTES + 1 are LENGTH_OUT_OF_RANGE before any read and any digest")
    void boundsCheckedFirst() {
        BigInteger r = BigInteger.ONE;
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(new byte[0], r);
        long max = G1PedersenBytesHash.MAX_PAYLOAD_BYTES;
        for (long bad : new long[]{-1, Long.MIN_VALUE, max + 1, Long.MAX_VALUE}) {
            RecordingStream s = new RecordingStream(new ByteArrayInputStream(pattern(10)));
            assertRejectedBeforeDigest(() -> PEDERSEN.commitBytes(s, bad, r), CommitmentError.LENGTH_OUT_OF_RANGE, "length");
            assertRejectedBeforeDigest(() -> PEDERSEN.commitBytesToEnd(s, bad, r), CommitmentError.LENGTH_OUT_OF_RANGE, "maxBytes");
            assertRejectedBeforeDigest(() -> PEDERSEN.verifyBytes(c, s, bad, r), CommitmentError.LENGTH_OUT_OF_RANGE, "length");
            assertRejectedBeforeDigest(() -> PEDERSEN.verifyBytesToEnd(c, s, bad, r), CommitmentError.LENGTH_OUT_OF_RANGE, "maxBytes");
            assertEquals(0, s.calls, "no read before validation, bound=" + bad);
        }
        RecordingStream s = new RecordingStream(new ByteArrayInputStream(pattern(10)));
        assertRejectedBeforeDigest(() -> PEDERSEN.commitBytes(s, 10, Q), CommitmentError.NON_CANONICAL_SCALAR, "blinding");
        assertRejectedBeforeDigest(() -> PEDERSEN.verifyBytesToEnd(c, s, 10, BigInteger.ONE.negate()),
                CommitmentError.NON_CANONICAL_SCALAR, "blinding");
        assertEquals(0, s.calls, "no read before blinding validation");
    }

    @Test
    @DisplayName("Spec §8 check order: nulls, then blinding NON_CANONICAL_SCALAR, then LENGTH_OUT_OF_RANGE, all before any read")
    void checkOrder() {
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(new byte[0], BigInteger.ONE);
        long over = G1PedersenBytesHash.MAX_PAYLOAD_BYTES + 1;
        for (BigInteger badR : new BigInteger[]{BigInteger.ONE.negate(), Q, Q.add(BigInteger.ONE), BigInteger.TWO.pow(300)}) {
            for (long badBound : new long[]{-1, over}) {
                RecordingStream s = new RecordingStream(new ByteArrayInputStream(pattern(10)));
                // Both the blinding and the bound are invalid: the blinding is reported.
                assertRejectedBeforeDigest(() -> PEDERSEN.commitBytes(s, badBound, badR),
                        CommitmentError.NON_CANONICAL_SCALAR, "blinding");
                assertRejectedBeforeDigest(() -> PEDERSEN.commitBytesToEnd(s, badBound, badR),
                        CommitmentError.NON_CANONICAL_SCALAR, "blinding");
                assertRejectedBeforeDigest(() -> PEDERSEN.verifyBytes(c, s, badBound, badR),
                        CommitmentError.NON_CANONICAL_SCALAR, "blinding");
                assertRejectedBeforeDigest(() -> PEDERSEN.verifyBytesToEnd(c, s, badBound, badR),
                        CommitmentError.NON_CANONICAL_SCALAR, "blinding");
                assertEquals(0, s.calls, "no read before validation");
            }
        }
        // Nulls precede everything: a null stream with an invalid blinding and bound is a null failure.
        assertThrows(NullPointerException.class, () -> PEDERSEN.commitBytes((InputStream) null, -1, Q));
        assertThrows(NullPointerException.class, () -> PEDERSEN.commitBytesToEnd(null, -1, Q));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyBytes(null, new ByteArrayInputStream(new byte[0]), -1, Q));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyBytesToEnd(c, null, -1, Q));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyBytesToEnd(c, InputStream.nullInputStream(), -1, null));
    }

    @Test
    @DisplayName("The normative maximum is accepted as a bound; cap and cap + 1 behave at the injected seam")
    void capBoundary() throws Exception {
        // The real cap cannot be reached with I/O; the seam takes a small cap and the same code path.
        long cap = 1000;
        byte[] atCap = pattern((int) cap);
        assertEquals(G1PedersenBytesHash.hashToScalar(atCap),
                G1PedersenBytesHash.hashToScalar(new ByteArrayInputStream(atCap), cap, true, cap, sha256()));
        assertEquals(G1PedersenBytesHash.hashToScalar(atCap),
                G1PedersenBytesHash.hashToScalar(new ByteArrayInputStream(atCap), cap, false, cap, sha256()));
        RecordingStream untouched = new RecordingStream(new ByteArrayInputStream(atCap));
        assertThrows(IllegalArgumentException.class,
                () -> G1PedersenBytesHash.hashToScalar(untouched, cap + 1, false, cap, sha256()));
        assertThrows(IllegalArgumentException.class,
                () -> G1PedersenBytesHash.hashToScalar(untouched, -1, true, cap, sha256()));
        assertEquals(0, untouched.calls, "the seam rejects the bound before reading");
        RecordingStream over = new RecordingStream(new ByteArrayInputStream(pattern((int) cap + 1)));
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(over, cap, false, cap, sha256()));
        assertEquals(cap + 1, over.delivered);

        // The real maximum is a valid declared bound: an empty to-end stream under it succeeds.
        assertEquals(G1PedersenBytesHash.hashToScalar(new byte[0]),
                G1PedersenBytesHash.hashToScalar(InputStream.nullInputStream(), G1PedersenBytesHash.MAX_PAYLOAD_BYTES, false));
        BigInteger r = BigInteger.ONE;
        G1PedersenBytesCommitment empty = PEDERSEN.commitBytes(new byte[0], r);
        assertEquals(empty, PEDERSEN.commitBytesToEnd(InputStream.nullInputStream(), G1PedersenBytesHash.MAX_PAYLOAD_BYTES, r));
        assertTrue(PEDERSEN.verifyBytesToEnd(empty, InputStream.nullInputStream(), G1PedersenBytesHash.MAX_PAYLOAD_BYTES, r));
        // A declared length at the maximum is accepted as an argument; the empty stream is then truncation.
        assertThrows(IOException.class,
                () -> PEDERSEN.commitBytes(InputStream.nullInputStream(), G1PedersenBytesHash.MAX_PAYLOAD_BYTES, r));

        assertEquals((1L << 61) - 256, G1PedersenBytesHash.MAX_PAYLOAD_BYTES);
        assertEquals(2305843009213693696L, G1PedersenBytesHash.MAX_PAYLOAD_BYTES);
        // b0's input is n + 128 octets (spec §5); at the maximum it stays below 2^61 octets.
        assertTrue(G1PedersenBytesHash.MAX_PAYLOAD_BYTES + 128 < (1L << 61));
    }

    @Test
    @DisplayName("A bound past int range sizes the buffer correctly and is not truncated")
    void boundPastIntRange() throws IOException {
        // A cheap structural check of the counter: the declared bound exceeds int range and an
        // early end of stream must be reported as truncation, not as success or overflow.
        long bound = (1L << 31) + 5;
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(new GeneratedStream(1 << 16), bound, true));
        assertEquals(G1PedersenBytesHash.hashToScalar(pattern(1 << 16)),
                G1PedersenBytesHash.hashToScalar(new GeneratedStream(1 << 16), bound, false));
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
        assertThrows(IllegalStateException.class, () -> G1PedersenBytesHash.hashToScalar(new byte[3], broken));
        assertThrows(IllegalStateException.class, () -> G1PedersenBytesHash.hashToScalar(
                new ByteArrayInputStream(new byte[3]), 3, true, G1PedersenBytesHash.MAX_PAYLOAD_BYTES, broken));
    }

    @Test
    @DisplayName("A single-octet read returning −2 after a zero-progress read fails; it is not end of stream")
    void singleReadNegativeTwoFails() {
        InputStream s = new ScriptedStream(pattern(5), new int[]{0}, -2);
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(s, 100, false));
    }

    @Test
    @DisplayName("A single-octet read returning 256 fails rather than hashing a phantom octet")
    void singleRead256Fails() {
        InputStream s = new ScriptedStream(pattern(5), new int[]{0}, 256);
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(s, 100, false));
    }

    @Test
    @DisplayName("The end-of-stream probe treats −2, 256 and extreme values as failures in both modes")
    void probeOutOfRangeFails() {
        for (int bad : new int[]{-2, 256, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
            for (boolean exact : new boolean[]{true, false}) {
                InputStream s = new ProbeStream(pattern(10), bad);
                assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(s, 10, exact),
                        "probe value " + bad + " exact=" + exact);
            }
        }
    }

    @Test
    @DisplayName("An over-reported count is a failure even when it still fits the buffer (no stale octets)")
    void overReportWithinBufferFails() {
        int n = 2 * G1PedersenBytesHash.BUFFER_BYTES + 3616;
        byte[] payload = pattern(n);
        InputStream overReportsShortReads = new ChunkedStream(payload, Integer.MAX_VALUE) {
            @Override
            public int read(byte[] b, int off, int len) {
                int got = super.read(b, off, len);
                return got > 0 && len < b.length ? got + 1 : got;
            }
        };
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(overReportsShortReads, n, true));
    }

    @Test
    @DisplayName("Bulk reads never ask for more than the remaining budget, nor for zero octets")
    void readsWithinBudget() throws IOException {
        for (int n : new int[]{1, 100, G1PedersenBytesHash.BUFFER_BYTES + 1, 20_000}) {
            BudgetStream s = new BudgetStream(pattern(n));
            G1PedersenBytesHash.hashToScalar(s, n, true);
            assertTrue(s.maxRequested <= n, "never more than the bound");
            assertTrue(s.maxRequested <= G1PedersenBytesHash.BUFFER_BYTES, "never more than the buffer");
            assertFalse(s.zeroRequested, "never a zero-length bulk read");
        }
    }

    @Test
    @DisplayName("The owned read buffer is wiped after success and after failure")
    void bufferWipedOnEveryExit() throws IOException {
        CapturingStream ok = new CapturingStream(new ByteArrayInputStream(pattern(20_000)));
        G1PedersenBytesHash.hashToScalar(ok, 20_000, true);
        assertTrue(ok.buffer != null && allZero(ok.buffer), "buffer wiped after success");

        CapturingStream failing = new CapturingStream(new FaultingStream(pattern(20_000), 9_000));
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(failing, 20_000, true));
        assertTrue(failing.buffer != null && allZero(failing.buffer), "buffer wiped after an I/O failure");

        CapturingStream excess = new CapturingStream(new ByteArrayInputStream(pattern(101)));
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(excess, 100, false));
        assertTrue(excess.buffer != null && allZero(excess.buffer), "buffer wiped after excess input");

        // The buffer is fixed: never sized by the payload.
        CapturingStream big = new CapturingStream(new GeneratedStream(100_000));
        G1PedersenBytesHash.hashToScalar(big, G1PedersenBytesHash.MAX_PAYLOAD_BYTES, false);
        assertEquals(G1PedersenBytesHash.BUFFER_BYTES, big.buffer.length);
    }

    @Test
    @DisplayName("The operation-owned digest is reset on stream and array failures (no partial payload state)")
    void digestResetOnFailure() throws Exception {
        byte[] emptyDigest = MessageDigest.getInstance("SHA-256").digest();

        MessageDigest streamDigest = sha256();
        assertThrows(IOException.class, () -> G1PedersenBytesHash.hashToScalar(
                new FaultingStream(pattern(20_000), 12_345), 20_000, true, G1PedersenBytesHash.MAX_PAYLOAD_BYTES, streamDigest));
        assertArrayEquals(emptyDigest, streamDigest.digest(), "stream path reset after failure");

        FailingAfterDigest arrayDigest = new FailingAfterDigest(sha256(), 2);
        assertThrows(IllegalStateException.class, () -> G1PedersenBytesHash.hashToScalar(pattern(5000), arrayDigest));
        assertArrayEquals(emptyDigest, arrayDigest.delegate.digest(), "array path reset after failure");

        MessageDigest okDigest = sha256();
        G1PedersenBytesHash.hashToScalar(pattern(5000), okDigest);
        assertArrayEquals(emptyDigest, okDigest.digest(), "reset after success too");
    }

    @Test
    @DisplayName("The stream is never closed, reset, marked, skipped or asked for available(), on success or failure")
    void neverTouchesStreamControl() throws IOException {
        BigInteger r = BigInteger.ONE;
        byte[] payload = pattern(9000);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, r);
        RecordingStream[] streams = {
                new RecordingStream(new ByteArrayInputStream(payload)),
                new RecordingStream(new ByteArrayInputStream(payload)),
                new RecordingStream(new ByteArrayInputStream(payload)),
                new RecordingStream(new ByteArrayInputStream(payload)),
                new RecordingStream(new ByteArrayInputStream(pattern(9001))),
                new RecordingStream(new ByteArrayInputStream(pattern(8999))),
                new RecordingStream(new FaultingStream(payload, 4000))};
        assertEquals(c, PEDERSEN.commitBytes(streams[0], payload.length, r));
        assertEquals(c, PEDERSEN.commitBytesToEnd(streams[1], payload.length, r));
        assertTrue(PEDERSEN.verifyBytes(c, streams[2], payload.length, r));
        assertTrue(PEDERSEN.verifyBytesToEnd(c, streams[3], payload.length + 10L, r));
        assertThrows(IOException.class, () -> PEDERSEN.commitBytes(streams[4], payload.length, r));
        assertThrows(IOException.class, () -> PEDERSEN.verifyBytes(c, streams[5], payload.length, r));
        assertThrows(IOException.class, () -> PEDERSEN.commitBytesToEnd(streams[6], payload.length, r));
        for (RecordingStream s : streams) {
            assertFalse(s.closed, "never closed");
            assertFalse(s.marked, "never marked");
            // reset, skip and available throw AssertionError, which would have surfaced above.
        }
    }

    // ---- helpers ----

    private static void assertRejectedBeforeDigest(Executable op, CommitmentError reason, String messagePart) {
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

    private static MessageDigest sha256() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256");
    }

    private static boolean allZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    // ---- test digests ----

    /** Delegates to SHA-256 and counts the octets and digest outputs it is given. */
    static final class CountingDigest extends MessageDigest {
        private final MessageDigest delegate;
        long octets;
        long octetsBeforeFirstDigest = -1;
        int digests;

        CountingDigest() throws NoSuchAlgorithmException {
            super("counting-sha256");
            this.delegate = MessageDigest.getInstance("SHA-256");
        }

        @Override protected void engineUpdate(byte input) { octets++; delegate.update(input); }
        @Override protected void engineUpdate(byte[] input, int offset, int len) { octets += len; delegate.update(input, offset, len); }

        @Override
        protected byte[] engineDigest() {
            if (digests++ == 0) {
                octetsBeforeFirstDigest = octets;
            }
            return delegate.digest();
        }

        @Override protected void engineReset() { delegate.reset(); }
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

    // ---- test streams ----

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

    /** Records the largest bulk request and whether a zero-length bulk read was issued. */
    static final class BudgetStream extends InputStream {
        private final byte[] data;
        private int pos;
        int maxRequested;
        boolean zeroRequested;

        BudgetStream(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & 0xff : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            maxRequested = Math.max(maxRequested, len);
            if (len == 0) zeroRequested = true;
            if (pos >= data.length) return -1;
            int n = Math.min(Math.min(len, 1000), data.length - pos);
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

    /** Records delivered octets, calls, end-of-stream and any close/mark use; reset/skip/available fail the test. */
    static final class RecordingStream extends InputStream {
        private final InputStream in;
        long delivered;
        int calls;
        boolean sawEof;
        boolean closed;
        boolean marked;

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
        public synchronized void mark(int readlimit) {
            marked = true;
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
        public void skipNBytes(long n) {
            throw new AssertionError("skipNBytes must not be called");
        }

        @Override
        public int available() {
            throw new AssertionError("available must not be called");
        }
    }
}
