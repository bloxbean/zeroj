package com.bloxbean.cardano.zeroj.bls12381.spi;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Default provider backed by ZeroJ's pure Java BLS12-381 implementation.
 */
public final class PureJavaBls12381Provider implements Bls12381Provider {
    public static final PureJavaBls12381Provider INSTANCE = new PureJavaBls12381Provider();

    private PureJavaBls12381Provider() {}

    @Override
    public String id() {
        return "zeroj-bls12381-pure-java";
    }

    @Override
    public G1Point g1Generator() {
        return Bls12381Generators.G1;
    }

    @Override
    public G2Point g2Generator() {
        return Bls12381Generators.G2;
    }

    @Override
    public G1Point g1ScalarMul(G1Point point, BigInteger scalar) {
        return Bls12381Codecs.requireValid(point)
                .scalarMul(reduceScalar(scalar));
    }

    @Override
    public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
        return Bls12381Codecs.requireValid(point)
                .scalarMul(reduceScalar(scalar));
    }

    @Override
    public G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
        return Bls12381Codecs.requireValid(point)
                .ctScalarMul(reduceScalar(scalar));
    }

    @Override
    public G2Point g2SecretScalarMul(G2Point point, BigInteger scalar) {
        return Bls12381Codecs.requireValid(point)
                .ctScalarMul(reduceScalar(scalar));
    }

    @Override
    public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
        Objects.requireNonNull(g1Points, "g1Points required");
        Objects.requireNonNull(g2Points, "g2Points required");
        for (G1Point point : g1Points) {
            Bls12381Codecs.requireValid(point);
        }
        for (G2Point point : g2Points) {
            Bls12381Codecs.requireValid(point);
        }
        return BLS12381Pairing.pairingCheck(g1Points, g2Points);
    }

    private static BigInteger reduceScalar(BigInteger scalar) {
        return Objects.requireNonNull(scalar, "scalar required")
                .mod(Bls12381Generators.SCALAR_FIELD_ORDER);
    }
}
