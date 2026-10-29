package org.zeroj.bls12381.spi;

import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Hash;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;

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

    /**
     * Whether {@code ∏ e(g1Points[i], g2Points[i])} is the identity of GT.
     *
     * <p>Every provider implements the same contract (ADR-0062 D7, I7, I8):</p>
     * <ul>
     *   <li>null arrays, arrays of different length, and <b>empty arrays</b> are rejected with an
     *       exception; an empty product is not accepted as a successful check, so a verifier that
     *       builds its arrays dynamically fails closed;</li>
     *   <li>every point is validated (on curve, in the prime-order subgroup) and an invalid point
     *       is rejected with an exception;</li>
     *   <li>a pair with an identity component contributes 1, so an all-identity input returns
     *       {@code true}. Callers that must not accept identity inputs check for them first.</li>
     * </ul>
     *
     * <p>{@link #requirePairingProductInput} performs the array checks for implementations.</p>
     */
    boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points);

    /**
     * Array checks shared by every {@link #pairingProductIsIdentity} implementation: non-null, equal
     * length, and non-empty (ADR-0062 D7). Point validation stays with the implementation.
     *
     * @throws NullPointerException if either array is null
     * @throws IllegalArgumentException if the lengths differ or the input is empty
     */
    static void requirePairingProductInput(G1Point[] g1Points, G2Point[] g2Points) {
        Objects.requireNonNull(g1Points, "g1Points required");
        Objects.requireNonNull(g2Points, "g2Points required");
        if (g1Points.length != g2Points.length) {
            throw new IllegalArgumentException("Pairing point arrays must have the same length");
        }
        if (g1Points.length == 0) {
            throw new IllegalArgumentException("Pairing product input must not be empty");
        }
    }

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
