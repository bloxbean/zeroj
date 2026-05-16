package com.bloxbean.cardano.zeroj.blst;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;
import supranational.blst.PT;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BLS12-381 provider backed by the blst native library.
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
        return decodeG1(P1.generator().serialize());
    }

    @Override
    public G2Point g2Generator() {
        return decodeG2(P2.generator().serialize());
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
        P1 result = new P1(encodeG1(left));
        result.add(new P1_Affine(encodeG1(right)));
        return decodeG1(result.serialize());
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
        P2 result = new P2(encodeG2(left));
        result.add(new P2_Affine(encodeG2(right)));
        return decodeG2(result.serialize());
    }

    @Override
    public G1Point g1Negate(G1Point point) {
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return point;
        }
        P1 result = new P1(encodeG1(point));
        result.neg();
        return decodeG1(result.serialize());
    }

    @Override
    public G2Point g2Negate(G2Point point) {
        point = Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            return point;
        }
        P2 result = new P2(encodeG2(point));
        result.neg();
        return decodeG2(result.serialize());
    }

    @Override
    public G1Point g1ScalarMul(G1Point point, BigInteger scalar) {
        point = Bls12381Codecs.requireValid(point);
        BigInteger reduced = reduceScalar(scalar);
        if (point.isInfinity() || reduced.signum() == 0) {
            return G1Point.INFINITY;
        }
        P1 result = new P1(encodeG1(point));
        result.mult(reduced);
        return decodeG1(result.serialize());
    }

    @Override
    public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
        point = Bls12381Codecs.requireValid(point);
        BigInteger reduced = reduceScalar(scalar);
        if (point.isInfinity() || reduced.signum() == 0) {
            return G2Point.INFINITY;
        }
        P2 result = new P2(encodeG2(point));
        result.mult(reduced);
        return decodeG2(result.serialize());
    }

    @Override
    public G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
        return g1ScalarMul(point, scalar);
    }

    @Override
    public G2Point g2SecretScalarMul(G2Point point, BigInteger scalar) {
        return g2ScalarMul(point, scalar);
    }

    @Override
    public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
        Objects.requireNonNull(g1Points, "g1Points required");
        Objects.requireNonNull(g2Points, "g2Points required");
        if (g1Points.length != g2Points.length) {
            throw new IllegalArgumentException("Pairing point arrays must have the same length");
        }

        PT accumulated = null;
        for (int i = 0; i < g1Points.length; i++) {
            G1Point g1 = Bls12381Codecs.requireValid(g1Points[i]);
            G2Point g2 = Bls12381Codecs.requireValid(g2Points[i]);
            if (g1.isInfinity() || g2.isInfinity()) {
                continue;
            }
            PT term = new PT(new P1_Affine(encodeG1(g1)), new P2_Affine(encodeG2(g2)));
            accumulated = accumulated == null ? term : BlstPairing.mulMlResult(accumulated, term);
        }
        return accumulated == null || BlstPairing.finalVerify(accumulated);
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

    private static BigInteger reduceScalar(BigInteger scalar) {
        return Objects.requireNonNull(scalar, "scalar required")
                .mod(Bls12381Generators.SCALAR_FIELD_ORDER);
    }
}
