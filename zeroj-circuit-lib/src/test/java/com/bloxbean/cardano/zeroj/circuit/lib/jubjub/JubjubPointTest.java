package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Correctness tests for {@link JubjubPoint}.
 *
 * <p>The most important tests here are the {@link #zkcrypto_serializationTestVectors}
 * assertions — 16 sequential multiples of the subgroup generator, each
 * encoded to 32 bytes, pulled verbatim from zkcrypto/jubjub's
 * {@code test_serialization_consistency} test. Passing these proves that:
 * <ul>
 *   <li>Our curve parameters (a, d, generator, cofactor) match zkcrypto.</li>
 *   <li>Our extended-coord add/double formulas agree with the spec.</li>
 *   <li>Our cofactor-clearing produces the same subgroup generator.</li>
 *   <li>Our compressed-point encoding matches Zcash/zkcrypto byte-for-byte.</li>
 * </ul>
 */
class JubjubPointTest {

    // ------------------------------------------------------------------
    //  zkcrypto/jubjub serialization test vectors (16 sequential multiples
    //  of the subgroup generator). Source: `test_serialization_consistency`
    //  in github.com/zkcrypto/jubjub at HEAD. Order of multiples:
    //    v[0] = [1]·SUBGROUP_GENERATOR
    //    v[1] = [2]·SUBGROUP_GENERATOR
    //    ...
    //    v[15] = [16]·SUBGROUP_GENERATOR
    // ------------------------------------------------------------------
    private static final int[][] ZKCRYPTO_VECTORS = {
            {203, 85, 12, 213, 56, 234, 12, 193, 19, 132, 128, 64, 142, 110, 170, 185, 179, 108, 97, 63, 13, 211, 247, 120, 79, 219, 110, 234, 131, 123, 19, 215},
            {113, 154, 240, 230, 224, 198, 208, 170, 104, 15, 59, 126, 151, 222, 233, 195, 203, 195, 167, 129, 89, 121, 240, 142, 51, 166, 64, 250, 184, 202, 154, 177},
            {197, 41, 93, 209, 203, 55, 164, 174, 88, 0, 90, 199, 1, 156, 149, 141, 240, 29, 14, 82, 86, 225, 126, 129, 186, 157, 148, 162, 219, 51, 156, 199},
            {182, 117, 250, 241, 81, 196, 199, 227, 151, 74, 243, 17, 221, 97, 200, 139, 192, 83, 231, 35, 214, 14, 95, 69, 130, 201, 4, 116, 177, 19, 179, 0},
            {118, 41, 29, 200, 60, 189, 119, 252, 78, 40, 230, 18, 208, 221, 38, 214, 176, 250, 4, 10, 77, 101, 26, 216, 193, 198, 226, 84, 25, 177, 230, 185},
            {226, 189, 227, 208, 112, 117, 136, 98, 72, 38, 211, 167, 254, 82, 174, 113, 112, 166, 138, 171, 166, 113, 52, 251, 129, 197, 138, 45, 195, 7, 61, 140},
            {38, 198, 156, 196, 146, 225, 55, 163, 138, 178, 157, 128, 115, 135, 204, 215, 0, 33, 171, 20, 60, 32, 142, 209, 33, 233, 125, 146, 207, 12, 16, 24},
            {17, 187, 231, 83, 165, 36, 232, 184, 140, 205, 195, 252, 166, 85, 59, 86, 3, 226, 211, 67, 179, 29, 238, 181, 102, 142, 58, 63, 57, 89, 174, 138},
            {210, 159, 80, 16, 181, 39, 221, 204, 224, 144, 145, 79, 54, 231, 8, 140, 142, 216, 93, 190, 183, 116, 174, 63, 33, 242, 177, 118, 148, 40, 241, 203},
            {0, 143, 107, 102, 149, 187, 27, 124, 18, 10, 98, 28, 113, 123, 121, 185, 29, 152, 14, 130, 149, 28, 87, 35, 135, 135, 153, 54, 112, 53, 54, 68},
            {178, 131, 85, 160, 214, 51, 208, 157, 196, 152, 247, 93, 202, 56, 81, 239, 155, 122, 59, 188, 237, 253, 11, 169, 208, 236, 12, 4, 163, 211, 88, 97},
            {246, 194, 231, 195, 159, 101, 180, 133, 80, 21, 185, 220, 195, 115, 144, 12, 90, 150, 44, 117, 8, 156, 168, 248, 206, 41, 60, 82, 67, 75, 57, 67},
            {212, 205, 171, 153, 113, 16, 194, 241, 224, 43, 177, 110, 190, 248, 22, 201, 208, 166, 2, 83, 134, 130, 85, 129, 166, 136, 185, 191, 163, 38, 54, 10},
            {8, 60, 190, 39, 153, 222, 119, 23, 142, 237, 12, 110, 146, 9, 19, 219, 143, 64, 161, 99, 199, 77, 39, 148, 70, 213, 246, 227, 150, 178, 237, 178},
            {11, 114, 217, 160, 101, 37, 100, 220, 56, 114, 42, 31, 138, 33, 84, 157, 214, 167, 73, 233, 115, 81, 124, 134, 15, 31, 181, 60, 184, 130, 175, 159},
            {141, 238, 235, 202, 241, 32, 210, 10, 127, 230, 54, 31, 146, 80, 247, 9, 107, 124, 0, 26, 203, 16, 237, 34, 214, 147, 133, 15, 29, 236, 37, 88},
    };

    @Test
    @DisplayName("zkcrypto/jubjub serialization test vectors: [i]·SUBGROUP_GENERATOR encodes byte-for-byte")
    void zkcrypto_serializationTestVectors() {
        JubjubPoint gen = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint p = gen;
        for (int i = 0; i < ZKCRYPTO_VECTORS.length; i++) {
            byte[] expected = toBytes(ZKCRYPTO_VECTORS[i]);
            byte[] actual = p.toBytes();
            assertArrayEquals(expected, actual,
                    "[" + (i + 1) + "]·SUBGROUP_GENERATOR encoding diverged from zkcrypto");
            // also round-trip
            JubjubPoint decoded = JubjubPoint.fromBytes(actual);
            assertTrue(decoded.projectiveEquals(p),
                    "fromBytes(toBytes(p)) != p at index " + i);
            p = p.add(gen);
        }
    }

    @Test
    @DisplayName("Identity is on the curve and acts as group identity")
    void identity_isGroupIdentity() {
        JubjubPoint id = JubjubPoint.IDENTITY;
        assertTrue(id.isIdentity());
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        assertTrue(g.add(id).projectiveEquals(g), "G + 0 = G");
        assertTrue(id.add(g).projectiveEquals(g), "0 + G = G");
    }

    @Test
    @DisplayName("Doubling agrees with self-addition")
    void doubling_matchesAddition() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        assertTrue(g.doubled().projectiveEquals(g.add(g)), "G.doubled() == G + G");
        JubjubPoint g2 = g.doubled();
        assertTrue(g2.doubled().projectiveEquals(g2.add(g2)), "(2G).doubled() == 2G + 2G");
    }

    @Test
    @DisplayName("[l]·G == 0 for subgroup generator (subgroup order is respected)")
    void subgroupOrder_respected() {
        assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(JubjubCurve.SUBGROUP_ORDER).isIdentity());
    }

    @Test
    @DisplayName("Subgroup generator passes isInSubgroup")
    void subgroupGenerator_isInSubgroup() {
        assertTrue(JubjubPoint.SUBGROUP_GENERATOR.isInSubgroup());
    }

    @Test
    @DisplayName("Full generator fails isInSubgroup (order 8l, not in prime-order subgroup)")
    void fullGenerator_notInSubgroup() {
        assertFalse(JubjubPoint.FULL_GENERATOR.isInSubgroup(),
                "FULL_GENERATOR has order 8l; [l]·FULL_GEN should be nonzero (a cofactor point)");
    }

    @Test
    @DisplayName("mulByCofactor of FULL_GENERATOR equals SUBGROUP_GENERATOR")
    void mulByCofactor_matchesSubgroupGenerator() {
        assertTrue(JubjubPoint.FULL_GENERATOR.mulByCofactor()
                .projectiveEquals(JubjubPoint.SUBGROUP_GENERATOR));
    }

    @Test
    @DisplayName("[2]·G via scalarMul equals G.doubled()")
    void scalarMul_consistency() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        assertTrue(g.scalarMul(BigInteger.TWO).projectiveEquals(g.doubled()));
        assertTrue(g.scalarMul(BigInteger.valueOf(3))
                .projectiveEquals(g.doubled().add(g)));
    }

    @Test
    @DisplayName("Negation: G + (-G) = 0")
    void negation_invertsPoint() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        assertTrue(g.add(g.negate()).isIdentity());
    }

    @Test
    @DisplayName("fromAffine rejects off-curve points")
    void fromAffine_rejectsOffCurve() {
        // (1, 0) is not on -u^2 + v^2 = 1 + d·u^2·v^2 (LHS = -1, RHS = 1)
        assertThrows(IllegalArgumentException.class,
                () -> JubjubPoint.fromAffine(BigInteger.ONE, BigInteger.ZERO));
    }

    @Test
    @DisplayName("fromBytes rejects encoding of a v-coordinate that is not on the curve")
    void fromBytes_rejectsOffCurve() {
        // Use v = 2, which is not a curve point — no u satisfies -u² + 4 = 1 + 4d·u².
        // Encoded: LE 32 bytes of 2, no sign bit set.
        byte[] bytes = new byte[32];
        bytes[0] = 2;
        assertThrows(IllegalArgumentException.class, () -> JubjubPoint.fromBytes(bytes));
    }

    @Test
    @DisplayName("fromBytes rejects v >= base_field_prime")
    void fromBytes_rejectsOutOfRangeV() {
        // v = p (the base field prime) is not a valid encoding (must be < p).
        // Encode LE bytes of base_field_prime with high bit cleared.
        byte[] bytes = new byte[32];
        BigInteger p = JubjubCurve.BASE_FIELD_PRIME;
        byte[] be = p.toByteArray();
        int start = (be.length > 1 && be[0] == 0) ? 1 : 0;
        int effLen = be.length - start;
        for (int i = 0; i < effLen; i++) {
            bytes[i] = be[be.length - 1 - i];
        }
        // Clear top bit so the encoding's sign bit = 0.
        bytes[31] &= 0x7F;
        assertThrows(IllegalArgumentException.class, () -> JubjubPoint.fromBytes(bytes));
    }

    @Test
    @DisplayName("Addition is commutative")
    void addition_isCommutative() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint p = g.scalarMul(BigInteger.valueOf(12345));
        JubjubPoint q = g.scalarMul(BigInteger.valueOf(67890));
        assertTrue(p.add(q).projectiveEquals(q.add(p)));
    }

    @Test
    @DisplayName("Addition is associative")
    void addition_isAssociative() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint p = g.scalarMul(BigInteger.valueOf(5));
        JubjubPoint q = g.scalarMul(BigInteger.valueOf(7));
        JubjubPoint r = g.scalarMul(BigInteger.valueOf(11));
        assertTrue(p.add(q).add(r).projectiveEquals(p.add(q.add(r))));
    }

    @Test
    @DisplayName("scalarMul respects modular reduction of scalar by l")
    void scalarMul_reducesByL() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        BigInteger k = BigInteger.valueOf(12345);
        assertTrue(g.scalarMul(k).projectiveEquals(g.scalarMul(k.add(JubjubCurve.SUBGROUP_ORDER))),
                "[k]·G == [k + l]·G");
    }

    @Test
    @DisplayName("SUBGROUP_ORDER matches zkcrypto/jubjub FR_MODULUS_BYTES")
    void subgroupOrder_matchesZkcrypto() {
        // LE bytes from zkcrypto/jubjub FR_MODULUS_BYTES, reversed to BE for BigInteger.
        int[] leBytes = {183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166,
                0, 59, 52, 1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14};
        byte[] be = new byte[leBytes.length + 1];
        be[0] = 0; // positive sign
        for (int i = 0; i < leBytes.length; i++) {
            be[be.length - 1 - i] = (byte) leBytes[i];
        }
        BigInteger expected = new BigInteger(be);
        assertEquals(expected, JubjubCurve.SUBGROUP_ORDER);
    }

    @Test
    @DisplayName("SUBGROUP_ORDER is 252 bits (consistent with cofactor-8 structure on BLS12-381)")
    void subgroupOrder_bitLength() {
        assertEquals(252, JubjubCurve.SUBGROUP_ORDER.bitLength());
    }

    @Test
    @DisplayName("scalarMul(0) returns identity")
    void scalarMul_zeroReturnsIdentity() {
        assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.ZERO).isIdentity());
    }

    @Test
    @DisplayName("scalarMul with negative k equals scalarMul(|k|).negate()")
    void scalarMul_negativeScalar() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        BigInteger k = BigInteger.valueOf(12345);
        assertTrue(g.scalarMul(k.negate()).projectiveEquals(g.scalarMul(k).negate()));
    }

    @Test
    @DisplayName("fromBytes(toBytes(IDENTITY)) round-trips to identity")
    void identity_roundTripsEncoding() {
        byte[] encoded = JubjubPoint.IDENTITY.toBytes();
        JubjubPoint decoded = JubjubPoint.fromBytes(encoded);
        assertTrue(decoded.isIdentity());
    }

    @Test
    @DisplayName("Sign-bit branch: encoding with odd u-coordinate decodes to odd-u point")
    void signBit_oddUBranch() {
        // Find a small-scalar multiple of G whose u-coordinate is odd, then
        // verify the encoding has the top bit set and round-trips correctly.
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint p = g;
        for (int k = 1; k <= 20; k++) {
            if (p.affineU().testBit(0)) {
                byte[] encoded = p.toBytes();
                assertTrue((encoded[31] & 0x80) != 0,
                        "[" + k + "]·G has odd u but encoding's top bit is cleared");
                JubjubPoint decoded = JubjubPoint.fromBytes(encoded);
                assertTrue(decoded.projectiveEquals(p));
                return;
            }
            p = p.add(g);
        }
        throw new AssertionError("No small multiple of G has odd u in first 20 scalars — unlikely; test needs rework");
    }

    @Test
    @DisplayName("equals: projectively-equal points compare equal with identical hashCode")
    void equals_hashCode_projectiveConsistency() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        // G vs G + IDENTITY — same affine point, potentially different extended coords.
        JubjubPoint gPlusIdentity = g.add(JubjubPoint.IDENTITY);
        assertEquals(g, gPlusIdentity);
        assertEquals(g.hashCode(), gPlusIdentity.hashCode());
    }

    @Test
    @DisplayName("fromBytes rejects non-canonical IDENTITY encoding (u=0 with sign bit set)")
    void fromBytes_rejectsNonCanonicalIdentity() {
        // IDENTITY = (0, 1). Canonical encoding: v=1 LE, sign bit=0. Non-canonical: sign bit=1.
        byte[] encoded = JubjubPoint.IDENTITY.toBytes();
        encoded[31] |= (byte) 0x80;  // set sign bit — non-canonical
        assertThrows(IllegalArgumentException.class, () -> JubjubPoint.fromBytes(encoded));
    }

    @Test
    @DisplayName("isInSubgroup: a crafted cofactor point (order 2) fails the check")
    void isInSubgroup_rejectsCofactorPoint() {
        // (0, -1) is on the Jubjub curve (0 + 1 = 1 + 0, satisfies -u^2 + v^2 = 1 + d·u^2·v^2 when u=0)
        // and has order 2. It's in the cofactor subgroup, not the prime-order subgroup.
        JubjubPoint cofactorPoint = JubjubPoint.fromAffine(
                BigInteger.ZERO, JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE));
        // Sanity: order 2
        assertTrue(cofactorPoint.doubled().isIdentity(), "(0, -1) should have order 2");
        // Subgroup check: [l] · (order-2 point). Since l is odd, [l]·P = P ≠ 0.
        assertFalse(cofactorPoint.isInSubgroup(),
                "(0, -1) has order 2, is a non-trivial cofactor point, must fail subgroup check");
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static byte[] toBytes(int[] ints) {
        byte[] out = new byte[ints.length];
        for (int i = 0; i < ints.length; i++) out[i] = (byte) ints[i];
        return out;
    }
}
