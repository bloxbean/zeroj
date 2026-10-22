package org.zeroj.bls12381.pedersen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.ec.G1Point;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The strict point decoder of {@code pedersen-bls12-381-g1-v1} §4 and every row of §10.4, for both
 * commitment types and both codecs. Expected verdicts come from the spec table or from {@link Ref},
 * an independent re-implementation of §4 in plain {@link BigInteger} affine arithmetic that never
 * calls {@link G1Point} or the codec.
 */
class G1PedersenDecoderTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** The four strict decoders under test; each returns the re-encoding of what it accepted. */
    private static final List<Function<byte[], byte[]>> DECODERS = List.of(
            b -> G1PedersenCommitment.decode(b).toPointBytes(),
            b -> G1PedersenCommitment.CODEC.decodePoint(b).toPointBytes(),
            b -> G1PedersenBytesCommitment.decode(b).toPointBytes(),
            b -> G1PedersenBytesCommitment.CODEC.decodePoint(b).toPointBytes());

    // ---- §10.4, row by row ----

    @Test
    @DisplayName("§10.4: c0‖0^47 is the identity and re-encodes to itself")
    void identity() {
        byte[] identity = identityBytes();
        assertEquals(Verdict.accepted(identity), Ref.decode(identity));
        assertAllDecoders(Verdict.accepted(identity), identity);
    }

    @Test
    @DisplayName("§10.4: e0‖0^47 (infinity with sort flag) is MALFORMED_ENCODING at step 4")
    void infinityWithSortFlag() {
        assertRow("e0" + "00".repeat(47), Verdict.error(CommitmentError.MALFORMED_ENCODING, 4));
    }

    @Test
    @DisplayName("§10.4: c0‖0^46‖01 (infinity with a coordinate bit) is MALFORMED_ENCODING at step 4")
    void infinityWithCoordinateBit() {
        assertRow("c0" + "00".repeat(46) + "01", Verdict.error(CommitmentError.MALFORMED_ENCODING, 4));
    }

    @Test
    @DisplayName("§10.4: 80‖0^47 (x = 0, the order-3 point (0, 2)) is NOT_IN_SUBGROUP at step 7")
    void xZero() {
        assertRow("80" + "00".repeat(47), Verdict.error(CommitmentError.NOT_IN_SUBGROUP, 7));
        Ref.Pt t = new Ref.Pt(BigInteger.ZERO, BigInteger.TWO);
        assertTrue(Ref.onCurve(t));
        assertNull(Ref.mul(t, BigInteger.valueOf(3)), "(0, 2) has order 3");
    }

    @Test
    @DisplayName("§10.4: compression flag clear is MALFORMED_ENCODING at step 3")
    void compressionFlagClear() {
        byte[] g = HEX.parseHex(G1PedersenBases.G_HEX);
        g[0] &= 0x7f;
        assertRow(HEX.formatHex(g), Verdict.error(CommitmentError.MALFORMED_ENCODING, 3));
        assertRow("00".repeat(48), Verdict.error(CommitmentError.MALFORMED_ENCODING, 3));
    }

    @Test
    @DisplayName("§10.4 step 2: lengths 0, 47, 49 and 96 (including uncompressed G and the identity) are MALFORMED_ENCODING")
    void lengths() {
        byte[] g = HEX.parseHex(G1PedersenBases.G_HEX);
        byte[] uncompressedG = HEX.parseHex(
                "00453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e"
                        + "0ab307006d17731edfeef508a959c6c43f6ad8f72d27af8aa0645356ffe864fd0ced6dfa806e5b2b63c8850f7cfb691c");
        byte[] uncompressedIdentity = new byte[96];
        uncompressedIdentity[0] = 0x40;
        List<byte[]> inputs = List.of(new byte[0], Arrays.copyOf(g, 47), Arrays.copyOf(g, 49),
                Arrays.copyOf(identityBytes(), 47), Arrays.copyOf(identityBytes(), 49),
                new byte[96], uncompressedG, uncompressedIdentity, Arrays.copyOf(g, 96));
        for (byte[] input : inputs) {
            assertEquals(Verdict.error(CommitmentError.MALFORMED_ENCODING, 2), Ref.decode(input));
            assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 2), input);
        }
    }

    @Test
    @DisplayName("§10.4 step 5: x = P_381, P_381 + 1 and 2^381 − 1 with the compression flag are MALFORMED_ENCODING")
    void xNotBelowP() {
        for (BigInteger x : List.of(Ref.P, Ref.P.add(BigInteger.ONE), BigInteger.ONE.shiftLeft(381).subtract(BigInteger.ONE))) {
            for (int flags : new int[]{0x80, 0xa0}) {
                byte[] input = withFlags(x, flags);
                assertEquals(Verdict.error(CommitmentError.MALFORMED_ENCODING, 5), Ref.decode(input), x.toString(16));
                assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 5), input);
            }
            // With the infinity flag the same bits stop at step 4; without compression at step 3.
            assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 4), withFlags(x, 0xc0));
            assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 3), withFlags(x, 0x00));
        }
        // P_381 − 1 is below the modulus, so it reaches steps 6/7; the reference decides which.
        byte[] pMinus1 = withFlags(Ref.P.subtract(BigInteger.ONE), 0x80);
        Verdict v = Ref.decode(pMinus1);
        assertTrue(v.step() >= 6, "x = P − 1 must pass step 5: " + v);
        assertAllDecoders(v, pMinus1);
    }

    @Test
    @DisplayName("§10.4: 80‖0^46‖01 (x = 1, x³ + 4 = 5 not a square) is MALFORMED_ENCODING at step 6")
    void xOne() {
        assertFalse(Ref.isSquare(BigInteger.valueOf(5)));
        assertRow("80" + "00".repeat(46) + "01", Verdict.error(CommitmentError.MALFORMED_ENCODING, 6));
        assertRow("a0" + "00".repeat(46) + "01", Verdict.error(CommitmentError.MALFORMED_ENCODING, 6));
    }

    @Test
    @DisplayName("§10.4: a0‖0^47 (x = 0 with sort flag, (0, P_381 − 2)) is NOT_IN_SUBGROUP at step 7")
    void xZeroSorted() {
        assertRow("a0" + "00".repeat(47), Verdict.error(CommitmentError.NOT_IN_SUBGROUP, 7));
        // (0, 2) is the lexicographically smaller root, so the sort flag selects P − 2.
        assertTrue(BigInteger.TWO.compareTo(Ref.HALF) <= 0);
        assertNull(Ref.mul(new Ref.Pt(BigInteger.ZERO, Ref.P.subtract(BigInteger.TWO)), BigInteger.valueOf(3)));
    }

    @Test
    @DisplayName("§10.4: 80‖0^46‖04 (x = 4, the smallest positive x on the curve) is NOT_IN_SUBGROUP at step 7")
    void xFour() {
        for (int x = 1; x <= 3; x++) {
            assertFalse(Ref.isSquare(Ref.rhs(BigInteger.valueOf(x))), "x = " + x + " is not on the curve");
        }
        assertTrue(Ref.isSquare(Ref.rhs(BigInteger.valueOf(4))));
        assertRow("80" + "00".repeat(46) + "04", Verdict.error(CommitmentError.NOT_IN_SUBGROUP, 7));
        assertRow("a0" + "00".repeat(46) + "04", Verdict.error(CommitmentError.NOT_IN_SUBGROUP, 7));
    }

    @Test
    @DisplayName("§10.4: G + (0, 2) is mixed order and NOT_IN_SUBGROUP; the decoder never cofactor-clears it")
    void mixedOrder() {
        String hex = "b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb93dc0230190c18ae135644c2d3df4";
        // The spec vector is reproduced independently from the pinned affine G and (0, 2).
        Ref.Pt mixed = Ref.add(Ref.G, new Ref.Pt(BigInteger.ZERO, BigInteger.TWO));
        assertEquals(hex, HEX.formatHex(Ref.compress(mixed)));
        assertFalse(Ref.inSubgroup(mixed));
        assertRow(hex, Verdict.error(CommitmentError.NOT_IN_SUBGROUP, 7));
        // [3]·P = [3]·G is in 𝔾₁; a cofactor-clearing decoder would return such a point instead of rejecting.
        byte[] cleared = Ref.compress(Ref.mul(mixed, BigInteger.valueOf(3)));
        assertArrayEquals(cleared, G1PedersenCommitment.decode(cleared).toPointBytes(), "[3]P is a valid subgroup point");
        assertNotRepairs(HEX.parseHex(hex));
        assertNotRepairs(HEX.parseHex("80" + "00".repeat(46) + "04"));
    }

    // ---- flags and steps ----

    @Test
    @DisplayName("Every top-3-bit flag combination on G's body and on the zero body has the spec §4 outcome")
    void allFlagCombinations() {
        byte[] gBody = HEX.parseHex(G1PedersenBases.G_HEX);
        gBody[0] &= 0x1f;
        byte[] gNeg = Ref.compress(Ref.neg(Ref.G));
        for (int flags = 0; flags < 8; flags++) {
            int top = flags << 5;
            byte[] onG = gBody.clone();
            onG[0] |= (byte) top;
            Verdict expected = switch (top) {
                case 0x00, 0x20, 0x40, 0x60 -> Verdict.error(CommitmentError.MALFORMED_ENCODING, 3);
                case 0x80 -> Verdict.accepted(HEX.parseHex(G1PedersenBases.G_HEX));
                case 0xa0 -> Verdict.accepted(gNeg);
                default -> Verdict.error(CommitmentError.MALFORMED_ENCODING, 4);
            };
            assertEquals(expected, Ref.decode(onG), "G body, flags " + Integer.toHexString(top));
            assertAllDecoders(expected, onG);

            byte[] zero = new byte[48];
            zero[0] = (byte) top;
            Verdict expectedZero = switch (top) {
                case 0x00, 0x20, 0x40, 0x60 -> Verdict.error(CommitmentError.MALFORMED_ENCODING, 3);
                case 0x80, 0xa0 -> Verdict.error(CommitmentError.NOT_IN_SUBGROUP, 7);
                case 0xc0 -> Verdict.accepted(identityBytes());
                default -> Verdict.error(CommitmentError.MALFORMED_ENCODING, 4);
            };
            assertEquals(expectedZero, Ref.decode(zero), "zero body, flags " + Integer.toHexString(top));
            assertAllDecoders(expectedZero, zero);
        }
    }

    @Test
    @DisplayName("Step order: a flag defect is MALFORMED_ENCODING even when the body is a small-order point")
    void stepOrderBeforeSubgroup() {
        // The body of (0, 2) or of x = 4 would be NOT_IN_SUBGROUP at step 7, but steps 3 and 4 come first.
        for (String body : List.of("00".repeat(47) + "00", "00".repeat(46) + "04")) {
            for (int flags : new int[]{0x00, 0x20, 0x40, 0x60}) {
                assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 3),
                        withFlags(new BigInteger(body, 16), flags));
            }
            assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 4),
                    withFlags(new BigInteger(body, 16), 0xe0));
        }
        assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 4), withFlags(BigInteger.valueOf(4), 0xc0));
        // The infinity flag on a subgroup point's x is step 4, never a finite decoding.
        byte[] h = HEX.parseHex(G1PedersenBases.H_HEX);
        h[0] |= 0x40;
        assertAllDecoders(Verdict.error(CommitmentError.MALFORMED_ENCODING, 4), h);
    }

    @Test
    @DisplayName("Random x values agree with the independent reference (steps 5, 6, 7), for both sort flags")
    void randomXAgreeWithReference() {
        Random random = new Random(0x0060_0002L);
        int[] seen = new int[8];
        for (int i = 0; i < 24; i++) {
            byte[] body = new byte[48];
            random.nextBytes(body);
            body[0] &= 0x1f;
            for (int flags : new int[]{0x80, 0xa0}) {
                byte[] input = body.clone();
                input[0] |= (byte) flags;
                Verdict expected = Ref.decode(input);
                seen[expected.step()]++;
                assertAllDecoders(expected, input);
            }
        }
        assertTrue(seen[5] > 0 && seen[6] > 0 && seen[7] > 0,
                "the sample must reach steps 5, 6 and 7: " + Arrays.toString(seen));
    }

    @Test
    @DisplayName("Canonical round trip: random subgroup points, their negations and sums re-encode to the exact input")
    void canonicalRoundTrip() {
        G1Pedersen pedersen = G1Pedersen.pureJava();
        List<byte[]> accepted = new ArrayList<>();
        accepted.add(identityBytes());
        accepted.add(HEX.parseHex(G1PedersenBases.G_HEX));
        accepted.add(HEX.parseHex(G1PedersenBases.H_HEX));
        G1PedersenCommitment previous = G1PedersenCommitment.decode(HEX.parseHex(G1PedersenBases.G_HEX));
        for (int i = 0; i < 6; i++) {
            G1PedersenCommitment c = pedersen.commitScalar(G1Pedersen.randomBlinding(RANDOM), G1Pedersen.randomBlinding(RANDOM));
            accepted.add(c.toPointBytes());
            accepted.add(c.negate().toPointBytes());
            accepted.add(c.add(previous).toPointBytes());
            previous = c;
        }
        for (byte[] b : accepted) {
            assertEquals(Verdict.accepted(b), Ref.decode(b), "reference must accept " + HEX.formatHex(b));
            assertAllDecoders(Verdict.accepted(b), b);
            if ((b[0] & 0x40) == 0) {
                // The sort flag selects −P, which is also in the subgroup and re-encodes to the flipped input.
                byte[] flipped = b.clone();
                flipped[0] ^= 0x20;
                assertEquals(Verdict.accepted(flipped), Ref.decode(flipped));
                assertAllDecoders(Verdict.accepted(flipped), flipped);
                assertEquals(G1PedersenCommitment.decode(b).negate(), G1PedersenCommitment.decode(flipped));
            }
        }
    }

    @Test
    @DisplayName("Step 1: a null input is a NullPointerException from every decoder")
    void nullInput() {
        assertThrows(NullPointerException.class, () -> G1PedersenCommitment.decode(null));
        assertThrows(NullPointerException.class, () -> G1PedersenCommitment.CODEC.decodePoint(null));
        assertThrows(NullPointerException.class, () -> G1PedersenBytesCommitment.decode(null));
        assertThrows(NullPointerException.class, () -> G1PedersenBytesCommitment.CODEC.decodePoint(null));
    }

    @Test
    @DisplayName("The decoder neither modifies nor retains its input, and toPointBytes returns a fresh copy")
    void inputNotRetained() {
        byte[] input = HEX.parseHex(G1PedersenBases.H_HEX);
        byte[] copy = input.clone();
        G1PedersenCommitment c = G1PedersenCommitment.decode(input);
        assertArrayEquals(copy, input);
        input[5] ^= 1;
        assertArrayEquals(copy, c.toPointBytes());
        byte[] out = c.toPointBytes();
        out[0] = 0;
        assertArrayEquals(copy, c.toPointBytes());
    }

    @Test
    @DisplayName("The reference constants are consistent: P ≡ 3 mod 4, q = G1Point.R, P + 1 − t = h·q, pinned G and H in 𝔾₁")
    void referenceConstants() {
        assertEquals(3, Ref.P.mod(BigInteger.valueOf(4)).intValue());
        assertEquals(Ref.Q, G1Point.R);
        BigInteger u = new BigInteger("-d201000000010000", 16);
        BigInteger trace = u.add(BigInteger.ONE);
        assertEquals(Ref.P.add(BigInteger.ONE).subtract(trace), Ref.H_COFACTOR.multiply(Ref.Q));
        assertTrue(Ref.Q.isProbablePrime(64) && Ref.P.isProbablePrime(64));
        for (Ref.Pt base : List.of(Ref.G, Ref.H)) {
            assertTrue(Ref.onCurve(base));
            assertTrue(Ref.inSubgroup(base));
        }
        assertEquals(G1PedersenBases.G_HEX, HEX.formatHex(Ref.compress(Ref.G)));
        assertEquals(G1PedersenBases.H_HEX, HEX.formatHex(Ref.compress(Ref.H)));
    }

    // ---- helpers ----

    private static void assertRow(String hex, Verdict expected) {
        byte[] input = HEX.parseHex(hex);
        assertEquals(expected, Ref.decode(input), "independent reference disagrees with spec §10.4 for " + hex);
        assertAllDecoders(expected, input);
    }

    /** Every decoder reaches the expected verdict, agrees with the others and leaves the input intact. */
    static void assertAllDecoders(Verdict expected, byte[] input) {
        for (Function<byte[], byte[]> decoder : DECODERS) {
            byte[] before = input.clone();
            if (expected.error() == null) {
                byte[] reencoded;
                try {
                    reencoded = decoder.apply(input);
                } catch (CommitmentFormatException e) {
                    fail("rejected " + HEX.formatHex(input) + " (" + e.reason() + "), expected acceptance");
                    return;
                }
                assertArrayEquals(expected.encoding(), reencoded, HEX.formatHex(input));
                assertArrayEquals(input, reencoded, "canonical: re-encoding equals the input");
            } else {
                assertError(expected.error(), () -> decoder.apply(input),
                        "step " + expected.step() + ", input " + HEX.formatHex(input));
            }
            assertArrayEquals(before, input, "decoder modified its input");
        }
    }

    /** A rejected non-subgroup curve point is not mapped to any point: no decoder returns. */
    private static void assertNotRepairs(byte[] input) {
        for (Function<byte[], byte[]> decoder : DECODERS) {
            assertError(CommitmentError.NOT_IN_SUBGROUP, () -> decoder.apply(input), HEX.formatHex(input));
        }
    }

    static CommitmentFormatException assertError(CommitmentError expected, Executable executable, String message) {
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class, executable, message);
        assertEquals(expected, e.reason(), message + ": " + e.getMessage());
        return e;
    }

    static byte[] identityBytes() {
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xc0;
        return identity;
    }

    private static byte[] withFlags(BigInteger x, int flags) {
        byte[] raw = x.toByteArray();
        byte[] out = new byte[48];
        int skip = raw.length > 48 ? raw.length - 48 : 0;
        System.arraycopy(raw, skip, out, 48 - (raw.length - skip), raw.length - skip);
        out[0] |= (byte) flags;
        return out;
    }

    /** An expected decoder outcome: the error class and spec §4 step, or the accepted re-encoding. */
    record Verdict(CommitmentError error, int step, byte[] encoding) {
        static Verdict accepted(byte[] encoding) {
            return new Verdict(null, encoding[0] == (byte) 0xc0 ? 4 : 7, encoding.clone());
        }

        static Verdict error(CommitmentError error, int step) {
            return new Verdict(error, step, null);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Verdict v && error == v.error && step == v.step && Arrays.equals(encoding, v.encoding);
        }

        @Override
        public int hashCode() {
            return 31 * step + Arrays.hashCode(encoding);
        }

        @Override
        public String toString() {
            return error == null ? "accepted " + HEX.formatHex(encoding) : error + " (step " + step + ")";
        }
    }

    /**
     * Independent reference for BLS12-381 G1 ({@code y² = x³ + 4} over {@code GF(P_381)}): constants
     * copied from spec §1/§2.2, affine arithmetic with {@link BigInteger#modInverse}, Euler's criterion,
     * the {@code P ≡ 3 (mod 4)} square root, and the §4 decoder. A {@code null} point is the identity.
     */
    static final class Ref {
        static final BigInteger P = new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
        static final BigInteger Q = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
        static final BigInteger H_COFACTOR = new BigInteger("396c8c005555e1568c00aaab0000aaab", 16);
        static final BigInteger HALF = P.subtract(BigInteger.ONE).shiftRight(1);
        static final Pt G = new Pt(
                new BigInteger("00453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e", 16),
                new BigInteger("0ab307006d17731edfeef508a959c6c43f6ad8f72d27af8aa0645356ffe864fd0ced6dfa806e5b2b63c8850f7cfb691c", 16));
        static final Pt H = new Pt(
                new BigInteger("12e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65", 16),
                new BigInteger("01e0f1bf4e0e4e344cb2779b2dc6adec8b0b07caf8a9812c3b6f4b056af2d0fda0e7b05ffb16008ca855ffe55686184e", 16));

        record Pt(BigInteger x, BigInteger y) {
        }

        private Ref() {
        }

        static BigInteger rhs(BigInteger x) {
            return x.pow(3).add(BigInteger.valueOf(4)).mod(P);
        }

        static boolean isSquare(BigInteger a) {
            BigInteger v = a.mod(P);
            return v.signum() == 0 || v.modPow(HALF, P).equals(BigInteger.ONE);
        }

        static BigInteger sqrt(BigInteger a) {
            BigInteger y = a.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
            if (!y.multiply(y).mod(P).equals(a.mod(P))) {
                throw new IllegalArgumentException("not a square");
            }
            return y;
        }

        static boolean onCurve(Pt p) {
            return p == null || p.y.multiply(p.y).mod(P).equals(rhs(p.x));
        }

        static Pt neg(Pt p) {
            return p == null ? null : new Pt(p.x, P.subtract(p.y).mod(P));
        }

        static Pt add(Pt a, Pt b) {
            if (a == null) return b;
            if (b == null) return a;
            if (a.x.equals(b.x)) {
                return a.y.add(b.y).mod(P).signum() == 0 ? null : dbl(a);
            }
            BigInteger l = b.y.subtract(a.y).multiply(b.x.subtract(a.x).modInverse(P)).mod(P);
            BigInteger x3 = l.multiply(l).subtract(a.x).subtract(b.x).mod(P);
            return new Pt(x3, l.multiply(a.x.subtract(x3)).subtract(a.y).mod(P));
        }

        static Pt dbl(Pt a) {
            if (a == null || a.y.signum() == 0) return null;
            BigInteger l = a.x.multiply(a.x).multiply(BigInteger.valueOf(3))
                    .multiply(a.y.shiftLeft(1).modInverse(P)).mod(P);
            BigInteger x3 = l.multiply(l).subtract(a.x.shiftLeft(1)).mod(P);
            return new Pt(x3, l.multiply(a.x.subtract(x3)).subtract(a.y).mod(P));
        }

        /** Left-to-right double-and-add for {@code k ≥ 0}. */
        static Pt mul(Pt p, BigInteger k) {
            Pt r = null;
            for (int i = k.bitLength() - 1; i >= 0; i--) {
                r = dbl(r);
                if (k.testBit(i)) r = add(r, p);
            }
            return r;
        }

        static boolean inSubgroup(Pt p) {
            return mul(p, Q) == null;
        }

        static byte[] compress(Pt p) {
            if (p == null) return identityBytes();
            byte[] out = withFlags(p.x, 0x80);
            if (p.y.compareTo(HALF) > 0) out[0] |= 0x20;
            return out;
        }

        /** Spec §4, steps 2–7, written from the table. */
        static Verdict decode(byte[] b) {
            if (b.length != 48) return Verdict.error(CommitmentError.MALFORMED_ENCODING, 2);
            int flags = b[0] & 0xe0;
            if ((flags & 0x80) == 0) return Verdict.error(CommitmentError.MALFORMED_ENCODING, 3);
            byte[] body = b.clone();
            body[0] &= 0x1f;
            BigInteger x = new BigInteger(1, body);
            if ((flags & 0x40) != 0) {
                return flags == 0xc0 && x.signum() == 0
                        ? Verdict.accepted(b) : Verdict.error(CommitmentError.MALFORMED_ENCODING, 4);
            }
            if (x.compareTo(P) >= 0) return Verdict.error(CommitmentError.MALFORMED_ENCODING, 5);
            BigInteger rhs = rhs(x);
            if (!isSquare(rhs)) return Verdict.error(CommitmentError.MALFORMED_ENCODING, 6);
            BigInteger y = sqrt(rhs);
            boolean sort = (flags & 0x20) != 0;
            if ((y.compareTo(HALF) > 0) != sort) y = P.subtract(y);
            Pt point = new Pt(x, y);
            if (!inSubgroup(point)) return Verdict.error(CommitmentError.NOT_IN_SUBGROUP, 7);
            return Verdict.accepted(compress(point));
        }
    }
}
