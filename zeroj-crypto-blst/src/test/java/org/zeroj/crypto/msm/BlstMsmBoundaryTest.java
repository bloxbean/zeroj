package org.zeroj.crypto.msm;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.blst.ffm.BlstG1Msm;
import org.zeroj.blst.ffm.BlstG2Msm;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 D4 / I5: the public FFM MSM entry points reduce every scalar mod r, never truncate,
 * reject length mismatches and flagged encodings, and offer a subgroup-validating overload. Expected
 * values come from the pure-Java group law ({@code [k mod r]P}), not from blst.
 */
class BlstMsmBoundaryTest {
    private static final BigInteger R = Bls12381Generators.SCALAR_FIELD_ORDER;
    private static final G1Point G1 = Bls12381Generators.G1;
    private static final G2Point G2 = Bls12381Generators.G2;
    private static final byte[] G1_ENC = Bls12381Codecs.g1ToUncompressed(G1);
    private static final byte[] G2_ENC = Bls12381Codecs.g2ToUncompressed(G2);

    /** Scalars the review reproduced as wrong: 2^255 + 1 used to give G, -1 an unrelated point. */
    private static final List<BigInteger> EDGE_SCALARS = List.of(
            BigInteger.valueOf(-1), BigInteger.ZERO, R.subtract(BigInteger.ONE), R, R.add(BigInteger.ONE),
            BigInteger.TWO.pow(255).add(BigInteger.ONE), BigInteger.TWO.pow(256).add(BigInteger.ONE),
            BigInteger.TWO.pow(300).negate());

    @Test
    void singleMulReducesEveryScalarModR() {
        for (BigInteger k : EDGE_SCALARS) {
            assertArrayEquals(g1(k), BlstG1Msm.singleMul(G1_ENC, k), "G1 k=" + k);
            assertArrayEquals(g2(k), BlstG2Msm.singleMul(G2_ENC, k), "G2 k=" + k);
        }
    }

    @Test
    void msmReducesEveryScalarModR() {
        BigInteger[] scalars = EDGE_SCALARS.toArray(BigInteger[]::new);
        byte[][] g1Points = new byte[scalars.length][];
        byte[][] g2Points = new byte[scalars.length][];
        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < scalars.length; i++) {
            // distinct bases [i+1]G, so the result is Σ k_i (i+1) · G
            g1Points[i] = Bls12381Codecs.g1ToUncompressed(G1.scalarMul(BigInteger.valueOf(i + 1L)));
            g2Points[i] = Bls12381Codecs.g2ToUncompressed(G2.scalarMul(BigInteger.valueOf(i + 1L)));
            sum = sum.add(scalars[i].mod(R).multiply(BigInteger.valueOf(i + 1L)));
        }
        assertArrayEquals(g1(sum), BlstG1Msm.msm(g1Points, scalars));
        assertArrayEquals(g2(sum), BlstG2Msm.msm(g2Points, scalars));
        assertArrayEquals(g1(sum), BlstG1Msm.msm(scalars.length,
                (i, dst) -> System.arraycopy(g1Points[i], 0, dst, 0, 96), scalars));
        assertArrayEquals(g2(sum), BlstG2Msm.msm(scalars.length,
                (i, dst) -> System.arraycopy(g2Points[i], 0, dst, 0, 192), scalars));
        assertArrayEquals(g1(sum), BlstG1Msm.msmValidated(g1Points, scalars));
        assertArrayEquals(g2(sum), BlstG2Msm.msmValidated(g2Points, scalars));
    }

    @Test
    void identityBasesAndZeroScalars() {
        byte[] g1Inf = Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY);
        byte[] g2Inf = Bls12381Codecs.g2ToUncompressed(G2Point.INFINITY);
        BigInteger[] s = {BigInteger.valueOf(5), BigInteger.valueOf(9)};
        assertArrayEquals(g1(BigInteger.valueOf(9)), BlstG1Msm.msm(new byte[][]{g1Inf, G1_ENC}, s));
        assertArrayEquals(g2(BigInteger.valueOf(9)), BlstG2Msm.msm(new byte[][]{g2Inf, G2_ENC}, s));
        BigInteger[] zeros = {BigInteger.ZERO, R};
        assertArrayEquals(g1Inf, BlstG1Msm.msm(new byte[][]{G1_ENC, G1_ENC}, zeros));
        assertArrayEquals(g2Inf, BlstG2Msm.msm(new byte[][]{G2_ENC, G2_ENC}, zeros));
    }

    /**
     * ADR-0062 F11: for fewer than 32 points blst 0.3.15 precomputes window tables that treat an
     * identity base as the affine point (0, 0, Z = 1), which corrupts the whole sum. Every size
     * from 2 to 40 with identity bases mixed in must equal the pure-Java sum.
     */
    @Test
    void identityBasesNeverCorruptTheSum() {
        Random rnd = new Random(0x0062_0011L);
        byte[] g1Inf = Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY);
        byte[] g2Inf = Bls12381Codecs.g2ToUncompressed(G2Point.INFINITY);
        for (int n = 1; n <= 40; n++) {
            for (int stride : new int[]{1, 2, 3}) {
                byte[][] p1 = new byte[n][];
                byte[][] p2 = new byte[n][];
                BigInteger[] sc = new BigInteger[n];
                BigInteger sum = BigInteger.ZERO;
                for (int i = 0; i < n; i++) {
                    sc[i] = new BigInteger(256, rnd);
                    if (i % stride == 0) {
                        p1[i] = g1Inf;
                        p2[i] = g2Inf;
                    } else {
                        BigInteger mul = BigInteger.valueOf(i + 1L);
                        p1[i] = Bls12381Codecs.g1ToUncompressed(G1.scalarMul(mul));
                        p2[i] = Bls12381Codecs.g2ToUncompressed(G2.scalarMul(mul));
                        sum = sum.add(sc[i].mod(R).multiply(mul));
                    }
                }
                assertArrayEquals(g1(sum), BlstG1Msm.msm(p1, sc), "G1 n=" + n + " stride=" + stride);
                if (n <= 34) {
                    assertArrayEquals(g2(sum), BlstG2Msm.msm(p2, sc), "G2 n=" + n + " stride=" + stride);
                }
            }
        }
    }

    @Test
    void identityFlagWithNonZeroCoordinatesIsRejected() {
        byte[] bad = Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY);
        bad[95] = 1;
        assertThrows(IllegalArgumentException.class,
                () -> BlstG1Msm.msm(new byte[][]{bad, G1_ENC}, new BigInteger[]{BigInteger.ONE, BigInteger.ONE}));
        byte[] bad2 = Bls12381Codecs.g2ToUncompressed(G2Point.INFINITY);
        bad2[191] = 1;
        assertThrows(IllegalArgumentException.class,
                () -> BlstG2Msm.msm(new byte[][]{bad2, G2_ENC}, new BigInteger[]{BigInteger.ONE, BigInteger.ONE}));
    }

    @Test
    void lengthMismatchIsRejected() {
        BigInteger[] three = {BigInteger.ONE, BigInteger.TWO, BigInteger.TEN};
        assertThrows(IllegalArgumentException.class, () -> BlstG1Msm.msm(new byte[][]{G1_ENC, G1_ENC}, three));
        assertThrows(IllegalArgumentException.class, () -> BlstG2Msm.msm(new byte[][]{G2_ENC, G2_ENC}, three));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG1Msm.msm(2, (i, dst) -> System.arraycopy(G1_ENC, 0, dst, 0, 96), three));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG2Msm.msm(2, (i, dst) -> System.arraycopy(G2_ENC, 0, dst, 0, 192), three));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG1Msm.msm(new byte[][]{Arrays.copyOf(G1_ENC, 95)}, new BigInteger[]{BigInteger.ONE}));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG1Msm.singleMul(Arrays.copyOf(G1_ENC, 144), BigInteger.ONE));
    }

    /** A compressed G1 encoding padded to 96 bytes used to be accepted with its tail ignored. */
    @Test
    void compressedOrSortFlaggedEncodingsAreRejected() {
        byte[] compressedPadded = Arrays.copyOf(Bls12381Codecs.g1ToCompressed(G1), 96);
        assertThrows(IllegalArgumentException.class, () -> BlstG1Msm.singleMul(compressedPadded, BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG1Msm.msm(new byte[][]{compressedPadded, G1_ENC}, new BigInteger[]{BigInteger.ONE, BigInteger.ONE}));
        byte[] sortFlagged = G1_ENC.clone();
        sortFlagged[0] |= 0x20;
        assertThrows(IllegalArgumentException.class, () -> BlstG1Msm.singleMul(sortFlagged, BigInteger.ONE));
        byte[] g2Compressed = Arrays.copyOf(Bls12381Codecs.g2ToCompressed(G2), 192);
        assertThrows(IllegalArgumentException.class, () -> BlstG2Msm.singleMul(g2Compressed, BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG2Msm.msm(new byte[][]{G2_ENC, g2Compressed}, new BigInteger[]{BigInteger.ONE, BigInteger.ONE}));
    }

    @Test
    void scalarEncoderPathRejectsNonCanonicalScalars() {
        byte[] rLe = le(R);
        byte[] maxLe = new byte[32];
        Arrays.fill(maxLe, (byte) 0xff);
        for (byte[] bad : List.of(rLe, maxLe)) {
            assertThrows(IllegalArgumentException.class, () -> BlstG1Msm.msm(2,
                    (i, dst) -> System.arraycopy(G1_ENC, 0, dst, 0, 96),
                    (i, dst) -> System.arraycopy(i == 1 ? bad : le(BigInteger.ONE), 0, dst, 0, 32)));
            assertThrows(IllegalArgumentException.class, () -> BlstG2Msm.msm(1,
                    (i, dst) -> System.arraycopy(G2_ENC, 0, dst, 0, 192),
                    (i, dst) -> System.arraycopy(bad, 0, dst, 0, 32)));
        }
        // r - 1 is the largest canonical scalar
        byte[] rMinusOne = le(R.subtract(BigInteger.ONE));
        assertArrayEquals(g1(R.subtract(BigInteger.ONE)), BlstG1Msm.msm(1,
                (i, dst) -> System.arraycopy(G1_ENC, 0, dst, 0, 96),
                (i, dst) -> System.arraycopy(rMinusOne, 0, dst, 0, 32)));
    }

    @Test
    void msmValidatedRejectsNonSubgroupBases() {
        byte[] g1Torsion = Bls12381Codecs.g1ToUncompressed(g1PointOutsideSubgroup());
        byte[] g2Torsion = Bls12381Codecs.g2ToUncompressed(g2PointOutsideSubgroup());
        BigInteger[] one = {BigInteger.ONE};
        BigInteger[] two = {BigInteger.ONE, BigInteger.ONE};
        // The hot path accepts them (documented: caller-validated) ...
        assertDoesNotThrow(() -> BlstG1Msm.msm(new byte[][]{g1Torsion}, one));
        assertDoesNotThrow(() -> BlstG2Msm.msm(new byte[][]{g2Torsion}, one));
        // ... the validating overload rejects them, for n = 1 and for the Pippenger path.
        assertThrows(IllegalArgumentException.class, () -> BlstG1Msm.msmValidated(new byte[][]{g1Torsion}, one));
        assertThrows(IllegalArgumentException.class, () -> BlstG2Msm.msmValidated(new byte[][]{g2Torsion}, one));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG1Msm.msmValidated(new byte[][]{G1_ENC, g1Torsion}, two));
        assertThrows(IllegalArgumentException.class,
                () -> BlstG2Msm.msmValidated(new byte[][]{G2_ENC, g2Torsion}, two));
    }

    // ---- helpers ----

    private static byte[] g1(BigInteger k) {
        return Bls12381Codecs.g1ToUncompressed(G1.scalarMul(k.mod(R)));
    }

    private static byte[] g2(BigInteger k) {
        return Bls12381Codecs.g2ToUncompressed(G2.scalarMul(k.mod(R)));
    }

    private static byte[] le(BigInteger v) {
        byte[] be = v.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < Math.min(be.length, 32); i++) out[i] = be[be.length - 1 - i];
        return out;
    }

    private static G1Point g1PointOutsideSubgroup() {
        for (int x = 1; ; x++) {
            Fp fx = Fp.of(x);
            var y = fx.square().mul(fx).add(Fp.of(4)).sqrt();
            if (y.isPresent()) {
                G1Point p = new G1Point(fx, y.get());
                if (p.isOnCurve() && !p.isInSubgroup()) return p;
            }
        }
    }

    private static G2Point g2PointOutsideSubgroup() {
        for (int x = 1; ; x++) {
            Fp2 fx = Fp2.of(Fp.of(x), Fp.ZERO);
            var y = fx.square().mul(fx).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt();
            if (y.isPresent()) {
                G2Point p = new G2Point(fx, y.get());
                if (p.isOnCurve() && !p.isInSubgroup()) return p;
            }
        }
    }
}
