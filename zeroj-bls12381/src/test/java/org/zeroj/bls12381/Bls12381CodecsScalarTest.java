package org.zeroj.bls12381;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code pedersen-bls12-381-g1-v1} §8: {@link Bls12381Codecs#scalarFromBigEndian32} and
 * {@link Bls12381Codecs#scalarToBigEndian32}, the canonical 32-octet big-endian scalar codec. Wrong
 * length or a value outside {@code [0, q)} is an {@link IllegalArgumentException}; nothing is reduced.
 * Expected octets are built with {@link String#format} from the spec's definition of {@code I2OSP}.
 */
class Bls12381CodecsScalarTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger Q =
            new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final BigInteger Q_MINUS_1 = Q.subtract(BigInteger.ONE);
    private static final BigInteger TWO_256_MINUS_1 = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    @Test
    @DisplayName("Known answers and round trip, including 0, 1, values with leading zero octets, and q − 1")
    void knownAnswers() {
        List<BigInteger> values = new ArrayList<>(List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(0xff),
                BigInteger.valueOf(0x100), BigInteger.ONE.shiftLeft(64), BigInteger.ONE.shiftLeft(248).subtract(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(248), BigInteger.ONE.shiftLeft(254), Q_MINUS_1, Q.shiftRight(8)));
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 16; i++) {
            values.add(new BigInteger(255, random).mod(Q));
        }
        for (BigInteger v : values) {
            byte[] expected = HEX.parseHex(String.format("%064x", v));
            assertArrayEquals(expected, Bls12381Codecs.scalarToBigEndian32(v), v.toString(16));
            assertEquals(v, Bls12381Codecs.scalarFromBigEndian32(expected));
        }
        assertArrayEquals(new byte[32], Bls12381Codecs.scalarToBigEndian32(BigInteger.ZERO));
        byte[] one = new byte[32];
        one[31] = 1;
        assertArrayEquals(one, Bls12381Codecs.scalarToBigEndian32(BigInteger.ONE));
        assertEquals(HEX.formatHex(Q_MINUS_1.toByteArray()), HEX.formatHex(Bls12381Codecs.scalarToBigEndian32(Q_MINUS_1)));
        assertEquals(Q, Bls12381Generators.SCALAR_FIELD_ORDER);
    }

    @Test
    @DisplayName("Big-endian, not little-endian: the octet order differs from scalarToLittleEndian32")
    void endianness() {
        BigInteger v = new BigInteger("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 16);
        byte[] be = Bls12381Codecs.scalarToBigEndian32(v);
        assertEquals(1, be[0]);
        assertEquals(0x20, be[31]);
        byte[] le = Bls12381Codecs.scalarToLittleEndian32(v);
        for (int i = 0; i < 32; i++) {
            assertEquals(be[i], le[31 - i]);
        }
    }

    @Test
    @DisplayName("Decoding: lengths 0/31/33/64 and null are rejected; q, q + 1 and 2^256 − 1 are rejected, never reduced")
    void decodeRejects() {
        assertThrows(NullPointerException.class, () -> Bls12381Codecs.scalarFromBigEndian32(null));
        for (int length : new int[]{0, 31, 33, 64}) {
            assertThrows(IllegalArgumentException.class, () -> Bls12381Codecs.scalarFromBigEndian32(new byte[length]));
        }
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Codecs.scalarFromBigEndian32(Arrays.copyOf(HEX.parseHex(String.format("%064x", BigInteger.ONE)), 31)));
        for (BigInteger bad : List.of(Q, Q.add(BigInteger.ONE), Q.add(BigInteger.valueOf(123456789)), TWO_256_MINUS_1,
                BigInteger.ONE.shiftLeft(255))) {
            byte[] encoded = HEX.parseHex(String.format("%064x", bad));
            assertNoValueInMessage(bad, () -> Bls12381Codecs.scalarFromBigEndian32(encoded));
        }
    }

    @Test
    @DisplayName("Decoding reads its input without modifying or retaining it")
    void decodeDoesNotTouchInput() {
        byte[] encoded = HEX.parseHex(String.format("%064x", Q_MINUS_1));
        byte[] copy = encoded.clone();
        BigInteger v = Bls12381Codecs.scalarFromBigEndian32(encoded);
        assertArrayEquals(copy, encoded);
        encoded[31] ^= 1;
        assertEquals(Q_MINUS_1, v);
    }

    @Test
    @DisplayName("Encoding: null is NullPointerException; −1, −q, q, q + 1 and 2^256 − 1 are IllegalArgumentException")
    void encodeRejects() {
        assertThrows(NullPointerException.class, () -> Bls12381Codecs.scalarToBigEndian32(null));
        for (BigInteger bad : List.of(BigInteger.ONE.negate(), Q.negate(), Q_MINUS_1.negate(), Q, Q.add(BigInteger.ONE),
                Q.add(BigInteger.valueOf(123456789)), TWO_256_MINUS_1, BigInteger.ONE.shiftLeft(256))) {
            assertNoValueInMessage(bad, () -> Bls12381Codecs.scalarToBigEndian32(bad));
        }
    }

    @Test
    @DisplayName("Encoding a hostile BigInteger subclass checks and encodes one plain copy, and wipes the copy's octets")
    void subclassSnapshot() {
        // Lies about its range through every observer except toByteArray.
        Hostile liar = new Hostile(BigInteger.ONE, Q);
        assertTrue(liar.signum() > 0 && liar.compareTo(Q) < 0, "the fixture fools a naive check");
        assertThrows(IllegalArgumentException.class, () -> Bls12381Codecs.scalarToBigEndian32(liar));
        assertTrue(liar.handedOutWiped());
        assertThrows(IllegalArgumentException.class, () -> Bls12381Codecs.scalarToBigEndian32(new Hostile(BigInteger.ONE, BigInteger.ONE.negate())));

        // Canonical on the first read, non-canonical afterwards: encodes the first value, read once.
        BigInteger first = BigInteger.valueOf(0xabcdef);
        Hostile shifter = new Hostile(Q.add(BigInteger.TEN), first, Q.add(BigInteger.TEN));
        assertArrayEquals(HEX.parseHex(String.format("%064x", first)), Bls12381Codecs.scalarToBigEndian32(shifter));
        assertEquals(1, shifter.reads);
        assertTrue(shifter.handedOutWiped());

        // Non-canonical on the first read is rejected even if later reads are canonical.
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Codecs.scalarToBigEndian32(new Hostile(BigInteger.TEN, Q, BigInteger.TEN)));

        // A plain BigInteger is encoded as is.
        BigInteger plain = BigInteger.valueOf(42);
        assertSame(BigInteger.class, plain.getClass());
        assertEquals(plain, Bls12381Codecs.scalarFromBigEndian32(Bls12381Codecs.scalarToBigEndian32(plain)));
    }

    private static void assertNoValueInMessage(BigInteger value, Executable call) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, call, value.toString(16));
        String message = String.valueOf(e.getMessage());
        // Short values (such as −1) can occur in any text by accident; only long ones are meaningful.
        if (value.abs().bitLength() > 32) {
            assertFalse(message.contains(value.abs().toString()) || message.contains(value.abs().toString(16)), message);
        }
    }

    /**
     * {@code toByteArray} yields {@code values[0]} first and {@code values[1..]} afterwards; every other
     * observer reports {@code claimed}.
     */
    static final class Hostile extends BigInteger {
        private final BigInteger claimed;
        private final BigInteger[] values;
        private final List<byte[]> handedOut = new ArrayList<>();
        int reads;

        Hostile(BigInteger claimed, BigInteger... values) {
            super(values[0].toByteArray());
            this.claimed = claimed;
            this.values = values.clone();
        }

        @Override
        public byte[] toByteArray() {
            byte[] out = values[Math.min(reads, values.length - 1)].toByteArray();
            reads++;
            handedOut.add(out);
            return out;
        }

        boolean handedOutWiped() {
            if (handedOut.isEmpty()) return false;
            for (byte[] b : handedOut) {
                for (byte x : b) if (x != 0) return false;
            }
            return true;
        }

        @Override public int signum() { return claimed.signum(); }
        @Override public int compareTo(BigInteger other) { return claimed.compareTo(other); }
        @Override public int bitLength() { return claimed.bitLength(); }
        @Override public boolean testBit(int n) { return claimed.testBit(n); }
        @Override public BigInteger abs() { return claimed.abs(); }
        @Override public BigInteger mod(BigInteger m) { return claimed.mod(m); }
        @Override public BigInteger shiftRight(int n) { return claimed.shiftRight(n); }
        @Override public int intValue() { return claimed.intValue(); }
        @Override public long longValue() { return claimed.longValue(); }
        @Override public boolean equals(Object o) { return claimed.equals(o); }
        @Override public int hashCode() { return claimed.hashCode(); }
        @Override public String toString() { return claimed.toString(); }
    }
}
