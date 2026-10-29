package org.zeroj.circuit.lib.jubjub;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ADR-0058 cross-path evidence: the streaming expander agrees with two unrelated implementations
 * of RFC 9380 {@code expand_message_xmd}/SHA-256 over the same frame and DST.
 *
 * <ul>
 *   <li>{@link Bls12381Hash#expandMessageXmdSha256}: ZeroJ's existing BBS/BLS expander, which
 *       builds the whole frame in memory (so it is an oracle here, not a reusable mapper; D2).</li>
 *   <li>A from-scratch expander over BouncyCastle's {@code SHA256Digest}: a different SHA-256
 *       implementation from the JDK provider the library uses.</li>
 * </ul>
 * The final reduction modulo {@code l} is checked against the independent Python reference in
 * {@code PedersenBytesReferenceVectorsTest}; here it is only re-derived from the oracle's bytes.
 */
class PedersenBytesCrossCheckTest {

    private static final byte[] DST = PedersenBytesHash.DST.getBytes(StandardCharsets.US_ASCII);

    @Test
    @DisplayName("Uniform bytes match Bls12381Hash and a BouncyCastle expander; s = OS2IP(u) mod l")
    void expandersAgree() {
        for (int n : new int[]{0, 1, 2, 55, 56, 63, 64, 65, 127, 128, 129, 8191, 8192, 8193, 70_000}) {
            byte[] payload = PedersenBytesStreamTest.pattern(n);
            byte[] frame = frame(payload);
            byte[][] mine = PedersenBytesHash.intermediatesForTesting(payload);

            byte[] oracle = Bls12381Hash.expandMessageXmdSha256(frame, DST, 48);
            assertArrayEquals(oracle, mine[3], "Bls12381Hash uniform bytes, n=" + n);

            byte[][] bc = bouncyCastleExpand(frame);
            assertArrayEquals(bc[0], mine[0], "b0, n=" + n);
            assertArrayEquals(bc[1], mine[1], "b1, n=" + n);
            assertArrayEquals(bc[2], mine[2], "b2, n=" + n);
            assertArrayEquals(bc[3], mine[3], "uniform, n=" + n);

            assertEquals(new BigInteger(1, oracle).mod(JubjubCurve.SUBGROUP_ORDER), PedersenBytesHash.hashToScalar(payload));
        }
    }

    private static byte[] frame(byte[] payload) {
        byte[] out = Arrays.copyOf(payload, payload.length + 8);
        long n = payload.length;
        for (int i = 7; i >= 0; i--) {
            out[payload.length + i] = (byte) n;
            n >>>= 8;
        }
        return out;
    }

    /** RFC 9380 §5.3.1 for len_in_bytes = 48, written directly against BouncyCastle SHA-256. */
    private static byte[][] bouncyCastleExpand(byte[] msg) {
        byte[] dstPrime = Arrays.copyOf(DST, DST.length + 1);
        dstPrime[DST.length] = (byte) DST.length;
        byte[] b0 = sha(new byte[64], msg, new byte[]{0x00, 0x30}, new byte[]{0x00}, dstPrime);
        byte[] b1 = sha(b0, new byte[]{0x01}, dstPrime);
        byte[] x = new byte[32];
        for (int i = 0; i < 32; i++) x[i] = (byte) (b0[i] ^ b1[i]);
        byte[] b2 = sha(x, new byte[]{0x02}, dstPrime);
        byte[] u = new byte[48];
        System.arraycopy(b1, 0, u, 0, 32);
        System.arraycopy(b2, 0, u, 32, 16);
        return new byte[][]{b0, b1, b2, u};
    }

    private static byte[] sha(byte[]... parts) {
        SHA256Digest d = new SHA256Digest();
        for (byte[] p : parts) d.update(p, 0, p.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }
}
