package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The Tonelli–Shanks constants behind {@link JubjubPoint#fromBytes}, and decoding checked
 * against the Euler criterion on random inputs: every 32-byte string either decodes to a point
 * that re-encodes to exactly those bytes, or is rejected for a reason the criterion confirms.
 */
class JubjubDecodeSqrtTest {

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger HALF = P.subtract(BigInteger.ONE).shiftRight(1);

    @Test
    @DisplayName("The cached non-residue 5 is the smallest quadratic non-residue mod p")
    void nonResidue() {
        for (int n = 2; n < 5; n++) {
            assertEquals(BigInteger.ONE, BigInteger.valueOf(n).modPow(HALF, P), n + " is a residue");
        }
        assertEquals(P.subtract(BigInteger.ONE), JubjubPoint.TS_NON_RESIDUE.modPow(HALF, P));
    }

    @Test
    @DisplayName("Random encodings: canonical round trip, or a rejection the Euler criterion confirms")
    void randomEncodings() {
        Random rnd = new Random(59);
        int decoded = 0;
        for (int i = 0; i < 2_000; i++) {
            byte[] bytes = new byte[32];
            rnd.nextBytes(bytes);
            BigInteger v = littleEndian(bytes);
            try {
                JubjubPoint point = JubjubPoint.fromBytes(bytes);
                decoded++;
                assertArrayEquals(bytes, point.toBytes(), "decode then encode is the identity");
            } catch (IllegalArgumentException e) {
                if (v.compareTo(P) >= 0) continue;
                BigInteger vv = v.multiply(v).mod(P);
                BigInteger num = vv.subtract(BigInteger.ONE).mod(P);
                BigInteger den = JubjubCurve.D.multiply(vv).add(BigInteger.ONE).mod(P);
                BigInteger uu = num.multiply(den.modInverse(P)).mod(P);
                boolean nonSquare = uu.signum() != 0 && uu.modPow(HALF, P).equals(P.subtract(BigInteger.ONE));
                boolean zeroWithSign = uu.signum() == 0 && (bytes[31] & 0x80) != 0;
                if (!nonSquare && !zeroWithSign) {
                    fail("rejected a decodable encoding: " + Arrays.toString(bytes) + " — " + e.getMessage());
                }
            }
        }
        assertTrue(decoded > 400, "roughly half of the in-range strings decode: " + decoded);
    }

    private static BigInteger littleEndian(byte[] bytes) {
        byte[] be = new byte[33];
        for (int i = 0; i < 32; i++) be[32 - i] = bytes[i];
        be[1] &= 0x7F; // clear the sign bit (byte 31 of the little-endian input)
        return new BigInteger(be);
    }
}
