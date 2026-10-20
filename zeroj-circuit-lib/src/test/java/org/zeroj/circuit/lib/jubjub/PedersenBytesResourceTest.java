package org.zeroj.circuit.lib.jubjub;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 M2 resource gates (opt-in; run with {@code ./gradlew :zeroj-circuit-lib:pedersenBytesResourceTest},
 * which uses a 64 MiB heap). These assert:
 *
 * <ul>
 *   <li>a generated 256 MiB payload commits in both stream modes under a 64 MiB heap, with no
 *       payload spool, and opens with the same payload;</li>
 *   <li>allocation inside the mapper does not grow with payload size (1 MiB vs 256 MiB);</li>
 *   <li>a payload longer than {@code 2^31} octets is counted and framed correctly.</li>
 * </ul>
 * Expected scalars come from an independent streaming expander over BouncyCastle's SHA-256, not
 * from the code under test.
 */
@EnabledIfSystemProperty(named = "zeroj.pedersenBytesResource", matches = "true")
class PedersenBytesResourceTest {

    private static final long MIB = 1L << 20;

    @Test
    @DisplayName("256 MiB generated stream commits and verifies in both modes under a 64 MiB heap")
    void largeStreamUnderSmallHeap() throws IOException {
        long n = 256 * MIB;
        long maxHeap = Runtime.getRuntime().maxMemory();
        System.out.printf("max heap: %.1f MiB%n", maxHeap / (double) MIB);
        assertTrue(maxHeap <= 80 * MIB, "this gate must run with a small heap; got " + maxHeap);

        BigInteger expected = independentScalar(n);
        BigInteger r = PedersenCommitment.randomBlinding(new java.security.SecureRandom());
        long t0 = System.nanoTime();
        PedersenBytesCommitment toEnd = PedersenCommitment.commitBytesToEnd(new PedersenBytesStreamTest.GeneratedStream(n), n, r);
        long t1 = System.nanoTime();
        PedersenBytesCommitment declared = PedersenCommitment.commitBytes(new PedersenBytesStreamTest.GeneratedStream(n), n, r);
        assertEquals(toEnd, declared);
        assertEquals(new PedersenBytesCommitment(PedersenCommitment.commit(expected, r)), toEnd);
        assertTrue(PedersenCommitment.verifyBytesToEnd(toEnd, new PedersenBytesStreamTest.GeneratedStream(n), n, r));
        System.out.printf("commitBytesToEnd 256 MiB: %.0f ms (%.0f MiB/s incl. generator)%n",
                (t1 - t0) / 1e6, 256 / ((t1 - t0) / 1e9));
    }

    @Test
    @DisplayName("Mapper allocation is flat in payload size (no per-chunk allocation)")
    void allocationIsFlat() throws IOException {
        com.sun.management.ThreadMXBean threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        // Without allocation accounting the bean returns -1 and every difference is 0, which would
        // pass vacuously. The gate is unmet unless the measurement is real.
        assertTrue(threads.isThreadAllocatedMemorySupported(), "thread allocation accounting is unsupported on this JVM");
        threads.setThreadAllocatedMemoryEnabled(true);
        assertTrue(threads.isThreadAllocatedMemoryEnabled(), "thread allocation accounting could not be enabled");
        long tid = Thread.currentThread().threadId();
        // Warm up so class loading and JIT allocation are not attributed to the measured runs.
        for (int i = 0; i < 3; i++) {
            PedersenBytesHash.hashToScalar(new PedersenBytesStreamTest.GeneratedStream(4 * MIB), 4 * MIB, false);
        }
        long[] sizes = {MIB, 16 * MIB, 256 * MIB};
        long[] allocated = new long[sizes.length];
        for (int i = 0; i < sizes.length; i++) {
            PedersenBytesStreamTest.GeneratedStream in = new PedersenBytesStreamTest.GeneratedStream(sizes[i]);
            long before = threads.getThreadAllocatedBytes(tid);
            PedersenBytesHash.hashToScalar(in, sizes[i], false);
            long after = threads.getThreadAllocatedBytes(tid);
            assertTrue(before >= 0 && after >= before, "invalid allocation samples " + before + ", " + after);
            allocated[i] = after - before;
            assertTrue(allocated[i] > 0, "the mapper allocates its buffer, so a zero sample means no measurement");
            System.out.printf("mapper allocation for %d MiB stream: %d bytes%n", sizes[i] / MIB, allocated[i]);
        }
        // A fixed 8 KiB buffer plus fixed-size digest and BigInteger work. Growth of even one small
        // object per 8 KiB chunk would add > 32 KiB at 256 MiB (32,768 chunks).
        assertTrue(allocated[0] < 64 * 1024, "1 MiB allocation " + allocated[0]);
        assertTrue(allocated[2] - allocated[0] < 32 * 1024,
                "allocation grows with payload size: " + allocated[0] + " -> " + allocated[2]);
    }

    @Test
    @DisplayName("A payload past 2^31 octets is counted with long arithmetic and framed correctly")
    void longCounterPast2to31() throws IOException {
        long n = (1L << 31) + 4099;
        BigInteger expected = independentScalar(n);
        assertEquals(expected, PedersenBytesHash.hashToScalar(new PedersenBytesStreamTest.GeneratedStream(n), n, true));
        assertEquals(expected, PedersenBytesHash.hashToScalar(new PedersenBytesStreamTest.GeneratedStream(n),
                PedersenBytesHash.MAX_PAYLOAD_BYTES, false));
    }

    /** RFC 9380 XMD/SHA-256 over the generated payload, streamed through BouncyCastle. */
    private static BigInteger independentScalar(long n) {
        byte[] dst = "ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-256".getBytes(StandardCharsets.US_ASCII);
        byte[] dstPrime = java.util.Arrays.copyOf(dst, dst.length + 1);
        dstPrime[dst.length] = (byte) dst.length;
        SHA256Digest d = new SHA256Digest();
        d.update(new byte[64], 0, 64);
        byte[] chunk = new byte[1 << 16];
        for (long pos = 0; pos < n; ) {
            int len = (int) Math.min(chunk.length, n - pos);
            for (int i = 0; i < len; i++) chunk[i] = (byte) (131 * (pos + i) + 17);
            d.update(chunk, 0, len);
            pos += len;
        }
        for (int i = 7; i >= 0; i--) d.update((byte) (n >>> (8 * i)));
        d.update(new byte[]{0x00, 0x30, 0x00}, 0, 3);
        d.update(dstPrime, 0, dstPrime.length);
        byte[] b0 = new byte[32];
        d.doFinal(b0, 0);
        d.update(b0, 0, 32);
        d.update((byte) 1);
        d.update(dstPrime, 0, dstPrime.length);
        byte[] b1 = new byte[32];
        d.doFinal(b1, 0);
        for (int i = 0; i < 32; i++) b0[i] ^= b1[i];
        d.update(b0, 0, 32);
        d.update((byte) 2);
        d.update(dstPrime, 0, dstPrime.length);
        byte[] b2 = new byte[32];
        d.doFinal(b2, 0);
        byte[] u = new byte[48];
        System.arraycopy(b1, 0, u, 0, 32);
        System.arraycopy(b2, 0, u, 32, 16);
        return new BigInteger(1, u).mod(JubjubCurve.SUBGROUP_ORDER);
    }
}
