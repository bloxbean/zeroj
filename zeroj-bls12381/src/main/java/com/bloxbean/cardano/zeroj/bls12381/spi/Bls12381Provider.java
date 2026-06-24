package com.bloxbean.cardano.zeroj.bls12381.spi;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Hash;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Provider boundary for BLS12-381 primitive implementations.
 *
 * <p>Scalar multiplication methods reduce the scalar modulo the BLS12-381
 * scalar-field order. They are for public scalars. Protocol code that multiplies
 * by secret scalars must use the secret-scalar methods and select a provider with
 * a side-channel contract appropriate for the deployment.</p>
 */
public interface Bls12381Provider {
    String id();

    G1Point g1Generator();

    G2Point g2Generator();

    default G1Point g1Identity() {
        return G1Point.INFINITY;
    }

    default G2Point g2Identity() {
        return G2Point.INFINITY;
    }

    default G1Point g1Add(G1Point left, G1Point right) {
        return Bls12381Codecs.requireValid(left).add(Bls12381Codecs.requireValid(right));
    }

    default G2Point g2Add(G2Point left, G2Point right) {
        return Bls12381Codecs.requireValid(left).add(Bls12381Codecs.requireValid(right));
    }

    default G1Point g1Negate(G1Point point) {
        return Bls12381Codecs.requireValid(point).negate();
    }

    default G2Point g2Negate(G2Point point) {
        return Bls12381Codecs.requireValid(point).negate();
    }

    G1Point g1ScalarMul(G1Point point, BigInteger scalar);

    G2Point g2ScalarMul(G2Point point, BigInteger scalar);

    /**
     * Multiply a G1 point by a secret scalar using this provider's secret-scalar path.
     * Consult the provider documentation for its side-channel guarantees.
     */
    default G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
        throw new UnsupportedOperationException(id() + " does not declare a secret-scalar G1 multiplication contract");
    }

    /**
     * Multiply a G2 point by a secret scalar using this provider's secret-scalar path.
     * Consult the provider documentation for its side-channel guarantees.
     */
    default G2Point g2SecretScalarMul(G2Point point, BigInteger scalar) {
        throw new UnsupportedOperationException(id() + " does not declare a secret-scalar G2 multiplication contract");
    }

    boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points);

    default boolean g1IsValid(G1Point point) {
        return point != null && point.isValid();
    }

    default boolean g2IsValid(G2Point point) {
        return point != null && point.isValid();
    }

    default byte[] g1ToCompressed(G1Point point) {
        return Bls12381Codecs.g1ToCompressed(Bls12381Codecs.requireValid(point));
    }

    default G1Point g1FromCompressed(byte[] bytes) {
        return Bls12381Codecs.g1FromCompressed(bytes);
    }

    default byte[] g1ToUncompressed(G1Point point) {
        return Bls12381Codecs.g1ToUncompressed(Bls12381Codecs.requireValid(point));
    }

    default G1Point g1FromUncompressed(byte[] bytes) {
        return Bls12381Codecs.g1FromUncompressed(bytes);
    }

    default byte[] g2ToCompressed(G2Point point) {
        return Bls12381Codecs.g2ToCompressed(Bls12381Codecs.requireValid(point));
    }

    default G2Point g2FromCompressed(byte[] bytes) {
        return Bls12381Codecs.g2FromCompressed(bytes);
    }

    default byte[] g2ToUncompressed(G2Point point) {
        return Bls12381Codecs.g2ToUncompressed(Bls12381Codecs.requireValid(point));
    }

    default G2Point g2FromUncompressed(byte[] bytes) {
        return Bls12381Codecs.g2FromUncompressed(bytes);
    }

    default BigInteger hashToScalar(byte[] message, byte[] dst) {
        Objects.requireNonNull(message, "message required");
        Objects.requireNonNull(dst, "dst required");
        return Bls12381Hash.hashToScalar(message, dst);
    }

    default BigInteger hashToScalarXofShake256(byte[] message, byte[] dst) {
        Objects.requireNonNull(message, "message required");
        Objects.requireNonNull(dst, "dst required");
        return Bls12381Hash.hashToScalarXofShake256(message, dst);
    }

    default G1Point g1HashToCurve(byte[] message, byte[] dst) {
        return Bls12381Hash.hashToG1(message, dst);
    }

    default G1Point g1EncodeToCurve(byte[] message, byte[] dst) {
        return Bls12381Hash.encodeToG1(message, dst);
    }

    default G1Point g1HashToCurveXofShake256(byte[] message, byte[] dst) {
        return Bls12381Hash.hashToG1XofShake256(message, dst);
    }

    default G1Point g1EncodeToCurveXofShake256(byte[] message, byte[] dst) {
        return Bls12381Hash.encodeToG1XofShake256(message, dst);
    }

    default G2Point g2HashToCurve(byte[] message, byte[] dst) {
        return Bls12381Hash.hashToG2(message, dst);
    }

    default G2Point g2EncodeToCurve(byte[] message, byte[] dst) {
        return Bls12381Hash.encodeToG2(message, dst);
    }

    default G2Point g2HashToCurveXofShake256(byte[] message, byte[] dst) {
        return Bls12381Hash.hashToG2XofShake256(message, dst);
    }

    default G2Point g2EncodeToCurveXofShake256(byte[] message, byte[] dst) {
        return Bls12381Hash.encodeToG2XofShake256(message, dst);
    }

    default G1Point g1ScalarMulGenerator(BigInteger scalar) {
        return g1ScalarMul(g1Generator(), scalar);
    }

    default G2Point g2ScalarMulGenerator(BigInteger scalar) {
        return g2ScalarMul(g2Generator(), scalar);
    }

    default G1Point g1SecretScalarMulGenerator(BigInteger scalar) {
        return g1SecretScalarMul(g1Generator(), scalar);
    }

    default G2Point g2SecretScalarMulGenerator(BigInteger scalar) {
        return g2SecretScalarMul(g2Generator(), scalar);
    }
}
