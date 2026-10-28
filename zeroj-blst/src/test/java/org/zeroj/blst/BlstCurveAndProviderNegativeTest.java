package org.zeroj.blst;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.Bls12381Providers;
import org.zeroj.blst.ffm.BlstCurve;
import org.zeroj.blst.ffm.BlstCurve.PointStatus;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 D3 / D9 (blst): the FFM binding and the provider built on it reject every malformed,
 * off-curve or non-subgroup input, the secret path equals the public path, and no JNI blst class is
 * on the runtime class path (I4).
 */
class BlstCurveAndProviderNegativeTest {
    private static final Bls12381Provider BLST = BlstBls12381Provider.createDefault();
    private static final Bls12381Provider PURE = Bls12381Providers.pureJava();
    private static final BigInteger R = Bls12381Generators.SCALAR_FIELD_ORDER;
    private static final G1Point G1 = Bls12381Generators.G1;
    private static final G2Point G2 = Bls12381Generators.G2;

    @Test
    void noJniBlstClassIsOnTheClassPath() {
        assertThrows(ClassNotFoundException.class, () -> Class.forName("supranational.blst.P1"));
        assertThrows(ClassNotFoundException.class, () -> Class.forName("supranational.blst.blstJNI"));
    }

    @Test
    void pointStatusClassifiesEveryEncoding() {
        byte[] g1 = Bls12381Codecs.g1ToUncompressed(G1);
        byte[] g2 = Bls12381Codecs.g2ToUncompressed(G2);
        assertEquals(PointStatus.VALID, BlstCurve.g1Status(g1));
        assertEquals(PointStatus.VALID, BlstCurve.g2Status(g2));
        assertEquals(PointStatus.IDENTITY, BlstCurve.g1Status(Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY)));
        assertEquals(PointStatus.IDENTITY, BlstCurve.g2Status(Bls12381Codecs.g2ToUncompressed(G2Point.INFINITY)));

        assertEquals(PointStatus.NOT_IN_SUBGROUP, BlstCurve.g1Status(Bls12381Codecs.g1ToUncompressed(g1Torsion())));
        assertEquals(PointStatus.NOT_IN_SUBGROUP, BlstCurve.g2Status(Bls12381Codecs.g2ToUncompressed(g2Torsion())));
        assertEquals(PointStatus.NOT_ON_CURVE, BlstCurve.g1Status(Bls12381Codecs.g1ToUncompressed(new G1Point(Fp.ONE, Fp.ONE))));

        byte[] zeros = new byte[96];
        assertEquals(PointStatus.NOT_ON_CURVE, BlstCurve.g1Status(zeros), "all-zero without the identity flag is (0, 0), off the curve");
        byte[] infWithBits = Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY);
        infWithBits[95] = 1;
        assertEquals(PointStatus.BAD_ENCODING, BlstCurve.g1Status(infWithBits));
        byte[] compressed = Arrays.copyOf(Bls12381Codecs.g1ToCompressed(G1), 96);
        assertEquals(PointStatus.BAD_ENCODING, BlstCurve.g1Status(compressed));
        byte[] sorted = g1.clone();
        sorted[0] |= 0x20;
        assertEquals(PointStatus.BAD_ENCODING, BlstCurve.g1Status(sorted));
        assertEquals(PointStatus.BAD_ENCODING, BlstCurve.g1Status(Arrays.copyOf(g1, 95)));
        assertEquals(PointStatus.BAD_ENCODING, BlstCurve.g1Status(null));
        byte[] xTooBig = g1.clone();
        byte[] p = Fp.P.toByteArray();
        System.arraycopy(p, p.length - 48, xTooBig, 0, 48); // x = p
        assertEquals(PointStatus.BAD_ENCODING, BlstCurve.g1Status(xTooBig));
    }

    @Test
    void arithmeticRejectsInvalidInputs() {
        byte[] bad = Bls12381Codecs.g1ToUncompressed(g1Torsion());
        byte[] g1 = Bls12381Codecs.g1ToUncompressed(G1);
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.g1Add(g1, bad));
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.g1Negate(bad));
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.g1Mul(bad, BigInteger.TWO));
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.g1MulSecret(bad, BigInteger.TWO));
        byte[] badG2 = Bls12381Codecs.g2ToUncompressed(g2Torsion());
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.g2Mul(badG2, BigInteger.TWO));
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.pairingProductIsOne(
                new byte[][]{g1}, new byte[][]{badG2}));
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.pairingProductIsOne(new byte[0][], new byte[0][]));
        assertThrows(IllegalArgumentException.class, () -> BlstCurve.pairingProductIsOne(
                new byte[][]{g1}, new byte[0][]));
        assertThrows(NullPointerException.class, () -> BlstCurve.g1Mul(g1, null));
    }

    @Test
    void providerRejectsOffCurveNonSubgroupNullAndEmpty() {
        G1Point offCurve = new G1Point(Fp.ONE, Fp.ONE);
        G1Point torsion = g1Torsion();
        G2Point torsion2 = g2Torsion();
        for (G1Point bad : List.of(offCurve, torsion)) {
            assertThrows(IllegalArgumentException.class, () -> BLST.g1Add(G1, bad));
            assertThrows(IllegalArgumentException.class, () -> BLST.g1Negate(bad));
            assertThrows(IllegalArgumentException.class, () -> BLST.g1ScalarMul(bad, BigInteger.TWO));
            assertThrows(IllegalArgumentException.class, () -> BLST.g1SecretScalarMul(bad, BigInteger.TWO));
            assertThrows(IllegalArgumentException.class,
                    () -> BLST.pairingProductIsIdentity(new G1Point[]{bad}, new G2Point[]{G2}));
        }
        assertThrows(IllegalArgumentException.class, () -> BLST.g2ScalarMul(torsion2, BigInteger.TWO));
        assertThrows(IllegalArgumentException.class, () -> BLST.g2SecretScalarMul(torsion2, BigInteger.TWO));
        assertThrows(IllegalArgumentException.class,
                () -> BLST.pairingProductIsIdentity(new G1Point[]{G1}, new G2Point[]{torsion2}));
        assertThrows(RuntimeException.class, () -> BLST.g1ScalarMul(null, BigInteger.ONE));
        assertThrows(NullPointerException.class, () -> BLST.g1ScalarMul(G1, null));
        assertThrows(NullPointerException.class, () -> BLST.g1SecretScalarMul(G1, null));
        assertThrows(IllegalArgumentException.class,
                () -> BLST.pairingProductIsIdentity(new G1Point[0], new G2Point[0]));
    }

    @Test
    void secretPathEqualsPublicPathAndPureJava() {
        Random random = new Random(0x0062_0006L);
        List<BigInteger> scalars = List.of(BigInteger.ZERO, BigInteger.ONE, R.subtract(BigInteger.ONE), R,
                R.add(BigInteger.ONE), BigInteger.valueOf(-1), BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE),
                new BigInteger(256, random), new BigInteger(256, random));
        for (BigInteger k : scalars) {
            G1Point expected1 = G1.scalarMul(k.mod(R));
            G2Point expected2 = G2.scalarMul(k.mod(R));
            assertEquals(expected1, BLST.g1SecretScalarMul(G1, k), "g1 secret k=" + k);
            assertEquals(expected1, BLST.g1ScalarMul(G1, k), "g1 public k=" + k);
            assertEquals(expected1, PURE.g1SecretScalarMul(G1, k), "pure g1 secret k=" + k);
            assertEquals(expected2, BLST.g2SecretScalarMul(G2, k), "g2 secret k=" + k);
            assertEquals(expected2, BLST.g2ScalarMul(G2, k), "g2 public k=" + k);
        }
    }

    @Test
    void identityPairsContributeOneAndDoNotMaskOthers() {
        assertTrue(BLST.pairingProductIsIdentity(new G1Point[]{G1Point.INFINITY}, new G2Point[]{G2}));
        assertFalse(BLST.pairingProductIsIdentity(new G1Point[]{G1Point.INFINITY, G1}, new G2Point[]{G2, G2}));
        assertTrue(BLST.pairingProductIsIdentity(new G1Point[]{G1, G1.negate(), G1}, new G2Point[]{G2, G2, G2Point.INFINITY}));
    }

    private static G1Point g1Torsion() {
        for (int x = 1; ; x++) {
            Fp fx = Fp.of(x);
            var y = fx.square().mul(fx).add(Fp.of(4)).sqrt();
            if (y.isPresent() && !new G1Point(fx, y.get()).isInSubgroup()) return new G1Point(fx, y.get());
        }
    }

    private static G2Point g2Torsion() {
        for (int x = 1; ; x++) {
            Fp2 fx = Fp2.of(Fp.of(x), Fp.ZERO);
            var y = fx.square().mul(fx).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt();
            if (y.isPresent() && !new G2Point(fx, y.get()).isInSubgroup()) return new G2Point(fx, y.get());
        }
    }
}
