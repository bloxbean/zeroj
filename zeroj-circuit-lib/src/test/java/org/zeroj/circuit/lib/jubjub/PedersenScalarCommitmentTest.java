package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.zeroj.circuit.lib.jubjub.CommitmentTestPoints.L;

/**
 * {@code commitment-profiles-v1} §7 (checks 1 and 2), §8.1, §8.2, §10 and §12.3 for the
 * {@code pedersen-jubjub-v1} strict paths, each paired with the unchanged legacy behaviour.
 */
class PedersenScalarCommitmentTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger[] NON_CANONICAL = {L, L.add(BigInteger.ONE), BigInteger.ONE.negate()};

    @Test
    @DisplayName("commitScalar equals legacy commit on canonical inputs, including 0 and l − 1, and verifies")
    void commitMatchesLegacy() {
        BigInteger lMinus1 = L.subtract(BigInteger.ONE);
        for (BigInteger[] mr : new BigInteger[][]{{BigInteger.ZERO, BigInteger.ZERO}, {lMinus1, lMinus1},
                {BigInteger.valueOf(42), PedersenCommitment.randomBlinding(RANDOM)}}) {
            PedersenScalarCommitment c = PedersenCommitment.commitScalar(mr[0], mr[1]);
            assertArrayEquals(PedersenCommitment.commit(mr[0], mr[1]).toBytes(), c.toPointBytes());
            assertTrue(PedersenCommitment.verifyScalar(c, mr[0], mr[1]));
            assertTrue(PedersenCommitment.verify(c.point(), mr[0], mr[1]));
        }
        assertArrayEquals(CommitmentTestPoints.IDENTITY,
                PedersenCommitment.commitScalar(BigInteger.ZERO, BigInteger.ZERO).toPointBytes());
    }

    @Test
    @DisplayName("Check 1: value or blinding at l, l + 1 or −1 is NON_CANONICAL_SCALAR; legacy still reduces")
    void canonicalResidue() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenScalarCommitment c = PedersenCommitment.commitScalar(BigInteger.ZERO, r);
        for (BigInteger bad : NON_CANONICAL) {
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.commitScalar(bad, r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.commitScalar(BigInteger.ONE, bad));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyScalar(c, bad, r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyScalar(c, BigInteger.ZERO, bad));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyScalar(c, bad, r, 64));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenScalarOpening.of(bad, r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenScalarOpening.of(BigInteger.ONE, bad));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenBlinding.encode(bad));
        }
        // Paired legacy behaviour (unchanged): value = l opens a commitment to 0.
        assertTrue(PedersenCommitment.verify(c.point(), L, r));
        assertArrayEquals(PedersenCommitment.commit(BigInteger.ZERO, r).toBytes(), PedersenCommitment.commit(L, r).toBytes());
    }

    @Test
    @DisplayName("A BigInteger subclass that lies about its range cannot pass check 1 with another value")
    void hostileSubclass() {
        BigInteger lying = new LyingBigInteger(L);
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.commitScalar(lying, BigInteger.ONE));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenScalarOpening.of(BigInteger.ONE, lying));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenBlinding.encode(lying));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.commitBytes(new byte[0], lying));
        PedersenScalarCommitment c = PedersenCommitment.commitScalar(BigInteger.ZERO, BigInteger.ONE);
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyScalar(c, lying, BigInteger.ONE, 8));
        // A well-behaved subclass is accepted and stored as a plain BigInteger.
        PedersenScalarOpening opening = PedersenScalarOpening.of(new LyingBigInteger(BigInteger.TEN), BigInteger.ONE);
        assertEquals(BigInteger.class, opening.value().getClass());
    }

    @Test
    @DisplayName("Copying a BigInteger subclass wipes its temporary octets, on success and on rejection")
    void subclassCopyIsWiped() {
        RecordingBigInteger r = new RecordingBigInteger(BigInteger.valueOf(7));
        PedersenCommitment.commitBytes(new byte[0], r);
        assertTrue(r.wiped(), "temporary left after success");
        RecordingBigInteger r2 = new RecordingBigInteger(BigInteger.valueOf(7));
        assertError(CommitmentError.LENGTH_OUT_OF_RANGE,
                () -> PedersenCommitment.commitBytes(new ByteArrayInputStream(new byte[0]), -1, r2));
        assertTrue(r2.wiped(), "temporary left after rejection");
        RecordingBigInteger m = new RecordingBigInteger(BigInteger.valueOf(9));
        PedersenScalarOpening.of(m, BigInteger.ONE);
        assertTrue(m.wiped());
    }

    /** A well-behaved subclass that records every array its toByteArray hands out. */
    static final class RecordingBigInteger extends BigInteger {
        private final List<byte[]> handedOut = new ArrayList<>();

        RecordingBigInteger(BigInteger value) {
            super(value.toByteArray());
        }

        @Override
        public byte[] toByteArray() {
            byte[] out = super.toByteArray();
            handedOut.add(out);
            return out;
        }

        boolean wiped() {
            if (handedOut.isEmpty()) return false;
            for (byte[] b : handedOut) {
                for (byte x : b) if (x != 0) return false;
            }
            return true;
        }
    }

    /**
     * Claims through signum and compareTo to be positive and below every bound. toByteArray (which
     * does not consult those methods) still yields the stored value, so the copy that the strict
     * paths check and use is that value.
     */
    static final class LyingBigInteger extends BigInteger {
        LyingBigInteger(BigInteger value) {
            super(value.toByteArray());
        }

        @Override
        public int signum() {
            return 1;
        }

        @Override
        public int compareTo(BigInteger other) {
            return -1;
        }
    }

    @Test
    @DisplayName("Messages of non-canonical rejections never contain the scalar")
    void noSecretInMessages() {
        BigInteger secret = L.add(BigInteger.valueOf(123456789));
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                () -> PedersenCommitment.commitScalar(secret, BigInteger.ONE));
        assertFalse(e.getMessage().contains(secret.toString()) || e.getMessage().contains(secret.toString(16)));
    }

    @Test
    @DisplayName("Check 2: 2^k − 1 passes and 2^k is OUT_OF_RANGE; k = 0 and 252 are INVALID_CONFIGURATION; k = 251 works")
    void amountBound() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        for (int k : new int[]{1, 8, 64, 251}) {
            BigInteger max = BigInteger.ONE.shiftLeft(k).subtract(BigInteger.ONE);
            assertTrue(PedersenCommitment.verifyScalar(PedersenCommitment.commitScalar(max, r), max, r, k));
            BigInteger over = BigInteger.ONE.shiftLeft(k);
            PedersenScalarCommitment c = PedersenCommitment.commitScalar(over, r);
            assertTrue(PedersenCommitment.verifyScalar(c, over, r), "a valid residue");
            assertError(CommitmentError.OUT_OF_RANGE, () -> PedersenCommitment.verifyScalar(c, over, r, k));
        }
        PedersenScalarCommitment c = PedersenCommitment.commitScalar(BigInteger.ONE, r);
        for (int k : new int[]{0, -1, 252, Integer.MAX_VALUE}) {
            assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenCommitment.verifyScalar(c, BigInteger.ONE, r, k));
        }
        assertFalse(PedersenCommitment.verifyScalar(c, BigInteger.TWO, r, 8), "in range, wrong value");
    }

    @Test
    @DisplayName("§12.3 order: amountBits before check 1, value before blinding, check 1 before check 2")
    void checkOrder() {
        PedersenScalarCommitment c = PedersenCommitment.commitScalar(BigInteger.ONE, BigInteger.ONE);
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PedersenCommitment.verifyScalar(c, L, L, 0));
        assertMessage("value", () -> PedersenCommitment.verifyScalar(c, L, L));
        assertMessage("value", () -> PedersenCommitment.commitScalar(L, L));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyScalar(c, BigInteger.ONE, L, 1)
        );
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyScalar(c, L, BigInteger.ONE, 8));
        // Check 2 comes after the blinding's check 1: an over-bound value with a bad blinding is
        // NON_CANONICAL_SCALAR, and with a good blinding OUT_OF_RANGE.
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyScalar(c, BigInteger.valueOf(256), L, 8));
        assertError(CommitmentError.OUT_OF_RANGE, () -> PedersenCommitment.verifyScalar(c, BigInteger.valueOf(256), BigInteger.ONE, 8));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.verifyScalar(c, null, BigInteger.ONE, 0));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.verifyScalar(null, BigInteger.ONE, BigInteger.ONE));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitScalar(null, BigInteger.ONE));
        assertThrows(NullPointerException.class, () -> PedersenCommitment.commitScalar(BigInteger.ONE, null));
    }

    @Test
    @DisplayName("§10 decoder: identity accepted; lengths, v ≥ p, off-curve and both sign aliases MALFORMED; torsion and mixed NOT_IN_SUBGROUP")
    void strictDecoder() {
        assertArrayEquals(CommitmentTestPoints.IDENTITY, PedersenScalarCommitment.decode(CommitmentTestPoints.IDENTITY).toPointBytes());
        for (byte[] malformed : new byte[][]{new byte[0], new byte[31], new byte[33], CommitmentTestPoints.V_NOT_BELOW_P,
                CommitmentTestPoints.OFF_CURVE, CommitmentTestPoints.ALIAS_IDENTITY, CommitmentTestPoints.ALIAS_ORDER_2}) {
            assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenScalarCommitment.decode(malformed));
            assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenScalarCommitment.CODEC.decodePoint(malformed));
            assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenCommitment.decode(malformed));
        }
        for (byte[] small : new byte[][]{CommitmentTestPoints.ORDER_2, CommitmentTestPoints.ORDER_4,
                CommitmentTestPoints.ORDER_8, CommitmentTestPoints.MIXED, JubjubPoint.FULL_GENERATOR.toBytes()}) {
            assertError(CommitmentError.NOT_IN_SUBGROUP, () -> PedersenScalarCommitment.decode(small));
            assertError(CommitmentError.NOT_IN_SUBGROUP, () -> PedersenCommitment.decode(small));
            assertError(CommitmentError.NOT_IN_SUBGROUP, () -> PedersenBytesCommitment.decode(small));
        }
        assertThrows(NullPointerException.class, () -> PedersenScalarCommitment.decode(null));
        assertThrows(NullPointerException.class, () -> PedersenScalarCommitment.CODEC.decodePoint(null));
        assertThrows(NullPointerException.class, () -> PedersenBytesCommitment.decode(null));
        // Legacy null handling (spec §12.3): a plain IllegalArgumentException, not the subclass.
        IllegalArgumentException legacy = assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.decode(null));
        assertFalse(legacy instanceof CommitmentFormatException);
    }

    @Test
    @DisplayName("The sign aliases of spec §10 are the identity and (0, −1) with the sign bit set")
    void signAliasesArePinned() {
        byte[] identityAlias = CommitmentTestPoints.IDENTITY.clone();
        identityAlias[31] |= (byte) 0x80;
        assertArrayEquals(identityAlias, CommitmentTestPoints.ALIAS_IDENTITY);
        byte[] order2Alias = CommitmentTestPoints.ORDER_2.clone();
        order2Alias[31] |= (byte) 0x80;
        assertArrayEquals(order2Alias, CommitmentTestPoints.ALIAS_ORDER_2);
        assertTrue(JubjubPoint.fromBytes(CommitmentTestPoints.ORDER_2).projectiveEquals(
                JubjubPoint.fromAffine(BigInteger.ZERO, CommitmentTestPoints.P.subtract(BigInteger.ONE))));
    }

    @Test
    @DisplayName("Typed arithmetic is residue arithmetic of both components")
    void arithmetic() {
        BigInteger a = BigInteger.valueOf(700), b = BigInteger.valueOf(1000);
        BigInteger r1 = PedersenCommitment.randomBlinding(RANDOM), r2 = PedersenCommitment.randomBlinding(RANDOM);
        PedersenScalarCommitment ca = PedersenCommitment.commitScalar(a, r1);
        PedersenScalarCommitment cb = PedersenCommitment.commitScalar(b, r2);
        assertTrue(PedersenCommitment.verifyScalar(ca.add(cb), a.add(b), r1.add(r2).mod(L)));
        PedersenScalarCommitment diff = ca.subtract(cb);
        assertTrue(PedersenCommitment.verifyScalar(diff, a.subtract(b).mod(L), r1.subtract(r2).mod(L)));
        assertTrue(PedersenCommitment.verifyScalar(ca.negate(), a.negate().mod(L), r1.negate().mod(L)));
        assertEquals(PedersenCommitment.commitScalar(BigInteger.ZERO, BigInteger.ZERO), ca.add(ca.negate()));
        assertThrows(NullPointerException.class, () -> ca.add(null));
        assertThrows(NullPointerException.class, () -> ca.subtract(null));
    }

    @Test
    @DisplayName("Value equality over the encoding; toString shows only profile and point")
    void equalityAndToString() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenScalarCommitment c = PedersenCommitment.commitScalar(BigInteger.valueOf(5), r);
        PedersenScalarCommitment decoded = PedersenScalarCommitment.decode(c.toPointBytes());
        assertEquals(c, decoded);
        assertEquals(c.hashCode(), decoded.hashCode());
        assertNotEquals(c, PedersenCommitment.commitScalar(BigInteger.valueOf(6), r));
        assertSame(PedersenScalarCommitment.PROFILE, c.profile());
        assertFalse(c.toString().contains(r.toString()) || c.toString().contains(r.toString(16)));
        assertTrue(c.toString().contains("pedersen-jubjub-v1"));
        byte[] copy = c.toPointBytes();
        copy[0] ^= 1;
        assertNotEquals(copy[0], c.toPointBytes()[0]);
    }

    @Test
    @DisplayName("§8.1 opening: 64 octets round trip; lengths 63 and 65 MALFORMED; m = l then r = l NON_CANONICAL; redacted")
    void scalarOpening() {
        BigInteger m = BigInteger.valueOf(31337), r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenScalarOpening opening = PedersenScalarOpening.of(m, r);
        byte[] encoded = opening.encode();
        assertEquals(64, encoded.length);
        assertEquals(m, new BigInteger(1, Arrays.copyOfRange(encoded, 0, 32)));
        assertEquals(r, new BigInteger(1, Arrays.copyOfRange(encoded, 32, 64)));
        PedersenScalarOpening back = PedersenScalarOpening.decode(encoded);
        assertEquals(m, back.value());
        assertEquals(r, back.blinding());
        PedersenScalarOpening max = PedersenScalarOpening.decode(PedersenScalarOpening.of(L.subtract(BigInteger.ONE),
                L.subtract(BigInteger.ONE)).encode());
        assertEquals(L.subtract(BigInteger.ONE), max.value());

        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenScalarOpening.decode(new byte[63]));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenScalarOpening.decode(new byte[65]));
        byte[] mAtL = concat(i2osp(L), i2osp(r));
        assertMessage("value", () -> PedersenScalarOpening.decode(concat(i2osp(L), i2osp(L))));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenScalarOpening.decode(mAtL));
        assertMessage("blinding", () -> PedersenScalarOpening.decode(concat(i2osp(m), i2osp(L.add(BigInteger.ONE)))));
        assertThrows(NullPointerException.class, () -> PedersenScalarOpening.decode(null));
        assertThrows(NullPointerException.class, () -> PedersenScalarOpening.of(null, r));

        assertEquals("PedersenScalarOpening[redacted]", opening.toString());
    }

    @Test
    @DisplayName("§8.2 blinding: 32 octets round trip; lengths 31 and 33 MALFORMED; r = l NON_CANONICAL")
    void blindingCodec() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        byte[] encoded = PedersenBlinding.encode(r);
        assertArrayEquals(i2osp(r), encoded);
        assertEquals(r, PedersenBlinding.decode(encoded));
        assertArrayEquals(new byte[32], PedersenBlinding.encode(BigInteger.ZERO));
        assertEquals(L.subtract(BigInteger.ONE), PedersenBlinding.decode(PedersenBlinding.encode(L.subtract(BigInteger.ONE))));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenBlinding.decode(new byte[31]));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> PedersenBlinding.decode(new byte[33]));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenBlinding.decode(i2osp(L)));
        byte[] allOnes = new byte[32];
        Arrays.fill(allOnes, (byte) 0xFF);
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenBlinding.decode(allOnes));
        assertThrows(NullPointerException.class, () -> PedersenBlinding.decode(null));
        assertThrows(NullPointerException.class, () -> PedersenBlinding.encode(null));
    }

    @Test
    @DisplayName("Bytes entry points report NON_CANONICAL_SCALAR before LENGTH_OUT_OF_RANGE")
    void bytesClasses() {
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.commitBytes(new byte[0], L));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.commitBytes(
                new ByteArrayInputStream(new byte[0]), -1, L));
        assertError(CommitmentError.LENGTH_OUT_OF_RANGE, () -> PedersenCommitment.commitBytes(
                new ByteArrayInputStream(new byte[0]), -1, BigInteger.ONE));
        assertError(CommitmentError.LENGTH_OUT_OF_RANGE, () -> PedersenCommitment.commitBytesToEnd(
                new ByteArrayInputStream(new byte[0]), PedersenBytesHash.MAX_PAYLOAD_BYTES + 1, BigInteger.ONE));
        PedersenBytesCommitment c = PedersenCommitment.commitBytes(new byte[0], BigInteger.ONE);
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PedersenCommitment.verifyBytes(c, new byte[0], BigInteger.ONE.negate()));
        assertError(CommitmentError.LENGTH_OUT_OF_RANGE, () -> PedersenCommitment.verifyBytes(c,
                new ByteArrayInputStream(new byte[0]), PedersenBytesHash.MAX_PAYLOAD_BYTES + 1, BigInteger.ONE));
        assertError(CommitmentError.LENGTH_OUT_OF_RANGE, () -> PedersenCommitment.verifyBytesToEnd(c,
                new ByteArrayInputStream(new byte[0]), -1, BigInteger.ONE));
    }

    static byte[] i2osp(BigInteger x) {
        byte[] out = new byte[32];
        byte[] raw = x.toByteArray();
        int skip = raw.length > 32 ? raw.length - 32 : 0;
        System.arraycopy(raw, skip, out, 32 - (raw.length - skip), raw.length - skip);
        return out;
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    static void assertError(CommitmentError expected, Executable op) {
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class, op);
        assertEquals(expected, e.reason(), e.getMessage());
    }

    private static void assertMessage(String part, Executable op) {
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class, op);
        assertEquals(CommitmentError.NON_CANONICAL_SCALAR, e.reason());
        assertTrue(e.getMessage().contains(part), "expected the " + part + " check first: " + e.getMessage());
    }
}
