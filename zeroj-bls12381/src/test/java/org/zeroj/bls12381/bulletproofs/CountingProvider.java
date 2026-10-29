package org.zeroj.bls12381.bulletproofs;

import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * A test provider over the pure-Java one that records every G1 multiplication: which entry point,
 * and the base. Scalars are recorded only as a class (zero, one, minus one, other) so that the
 * schedule test can compare call sequences without depending on their values.
 */
final class CountingProvider implements Bls12381Provider {

    enum Kind { PUBLIC, SECRET }

    record Call(Kind kind, G1Point base, String scalarClass) {
    }

    private final Bls12381Provider delegate = PureJavaBls12381Provider.INSTANCE;
    final List<Call> calls = new ArrayList<>();

    @Override
    public String id() {
        return "zeroj-test-counting";
    }

    @Override
    public G1Point g1Generator() {
        return delegate.g1Generator();
    }

    @Override
    public G2Point g2Generator() {
        return delegate.g2Generator();
    }

    @Override
    public G1Point g1ScalarMul(G1Point point, BigInteger scalar) {
        calls.add(new Call(Kind.PUBLIC, point, classify(scalar)));
        return delegate.g1ScalarMul(point, scalar);
    }

    @Override
    public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
        return delegate.g2ScalarMul(point, scalar);
    }

    @Override
    public G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
        calls.add(new Call(Kind.SECRET, point, classify(scalar)));
        return delegate.g1SecretScalarMul(point, scalar);
    }

    @Override
    public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
        return delegate.pairingProductIsIdentity(g1Points, g2Points);
    }

    long count(Kind kind) {
        return calls.stream().filter(c -> c.kind() == kind).count();
    }

    private static String classify(BigInteger scalar) {
        if (scalar.signum() == 0) return "0";
        if (scalar.equals(BigInteger.ONE)) return "1";
        if (scalar.equals(PointCodec.Q.subtract(BigInteger.ONE))) return "-1";
        return "x";
    }
}
