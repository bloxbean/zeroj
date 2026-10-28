package org.zeroj.blst;

import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.blst.ffm.BlstCurve;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BLS12-381 provider backed by the source-built {@code libblst}, through the FFM binding
 * {@link BlstCurve} (ADR-0062 D3). It shares one pinned native library with the FFM MSM.
 *
 * <p>Inputs are validated with the pure-Java {@link Bls12381Codecs#requireValid} and results are
 * decoded with the checked decoders, so this provider accepts and rejects exactly what the
 * pure-Java provider does (ADR-0062 I8); {@link BlstCurve} validates every encoding again
 * natively.</p>
 *
 * <p><b>Side channels.</b> The secret-scalar methods use a dedicated path (fixed-width scalar,
 * {@code nbits = 255}, no zero-scalar early return, zeroed temporaries), but any side-channel
 * property comes from blst's internal scalar multiplication, which ZeroJ has not evaluated
 * (ADR-0062 D2, Q2). Secret-bearing generation is offline/isolated only on this provider too.</p>
 */
public final class BlstBls12381Provider implements Bls12381Provider {
    private static final BlstBls12381Provider INSTANCE = new BlstBls12381Provider();

    private BlstBls12381Provider() {}

    public static BlstBls12381Provider createDefault() {
        return INSTANCE;
    }

    @Override
    public String id() {
        return "zeroj-bls12381-blst";
    }

    @Override
    public G1Point g1Generator() {
        return decodeG1(BlstCurve.g1Generator());
    }

    @Override
    public G2Point g2Generator() {
        return decodeG2(BlstCurve.g2Generator());
    }

    @Override
    public G1Point g1Add(G1Point left, G1Point right) {
        left = Bls12381Codecs.requireValid(left);
        right = Bls12381Codecs.requireValid(right);
        if (left.isInfinity()) {
            return right;
        }
        if (right.isInfinity()) {
            return left;
        }
        return decodeG1(BlstCurve.g1Add(encodeG1(left), encodeG1(right)));
    }

    @Override
    public G2Point g2Add(G2Point left, G2Point right) {
        left = Bls12381Codecs.requireValid(left);
        right = Bls12381Codecs.requireValid(right);
        if (left.isInfinity()) {
            return right;
        }
        if (right.isInfinity()) {
            return left;
        }
        return decodeG2(BlstCurve.g2Add(encodeG2(left), encodeG2(right)));
    }

    @Override
    public G1Point g1Negate(G1Point point) {
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return point;
        }
        return decodeG1(BlstCurve.g1Negate(encodeG1(point)));
    }

    @Override
    public G2Point g2Negate(G2Point point) {
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return point;
        }
        return decodeG2(BlstCurve.g2Negate(encodeG2(point)));
    }

    @Override
    public G1Point g1ScalarMul(G1Point point, BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return G1Point.INFINITY;
        }
        return decodeG1(BlstCurve.g1Mul(encodeG1(point), scalar));
    }

    @Override
    public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return G2Point.INFINITY;
        }
        return decodeG2(BlstCurve.g2Mul(encodeG2(point), scalar));
    }

    /** Dedicated secret path; see the class Javadoc for what it does and does not claim. */
    @Override
    public G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return G1Point.INFINITY; // the base is public
        }
        return decodeG1(BlstCurve.g1MulSecret(encodeG1(point), scalar));
    }

    /** Dedicated secret path; see the class Javadoc for what it does and does not claim. */
    @Override
    public G2Point g2SecretScalarMul(G2Point point, BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return G2Point.INFINITY; // the base is public
        }
        return decodeG2(BlstCurve.g2MulSecret(encodeG2(point), scalar));
    }

    @Override
    public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
        Bls12381Provider.requirePairingProductInput(g1Points, g2Points);
        byte[][] g1 = new byte[g1Points.length][];
        byte[][] g2 = new byte[g2Points.length][];
        for (int i = 0; i < g1Points.length; i++) {
            g1[i] = encodeG1(Bls12381Codecs.requireValid(g1Points[i]));
            g2[i] = encodeG2(Bls12381Codecs.requireValid(g2Points[i]));
        }
        return BlstCurve.pairingProductIsOne(g1, g2);
    }

    private static byte[] encodeG1(G1Point point) {
        return Bls12381Codecs.g1ToUncompressed(point);
    }

    private static byte[] encodeG2(G2Point point) {
        return Bls12381Codecs.g2ToUncompressed(point);
    }

    private static G1Point decodeG1(byte[] bytes) {
        return Bls12381Codecs.g1FromUncompressed(bytes);
    }

    private static G2Point decodeG2(byte[] bytes) {
        return Bls12381Codecs.g2FromUncompressed(bytes);
    }
}
