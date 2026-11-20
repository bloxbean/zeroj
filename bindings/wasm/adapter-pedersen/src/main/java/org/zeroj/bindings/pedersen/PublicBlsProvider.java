package org.zeroj.bindings.pedersen;

import java.math.BigInteger;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

/** Public operations only: G1Pedersen capability probing must not draw entropy for verification. */
final class PublicBlsProvider implements Bls12381Provider {
    private static final Bls12381Provider JAVA = PureJavaBls12381Provider.INSTANCE;
    public String id() { return "zeroj-bindings-public-java"; }
    public G1Point g1Generator() { return JAVA.g1Generator(); }
    public G2Point g2Generator() { return JAVA.g2Generator(); }
    public G1Point g1ScalarMul(G1Point p, BigInteger s) { return JAVA.g1ScalarMul(p,s); }
    public G2Point g2ScalarMul(G2Point p, BigInteger s) { return JAVA.g2ScalarMul(p,s); }
    public boolean pairingProductIsIdentity(G1Point[] a,G2Point[] b) { return JAVA.pairingProductIsIdentity(a,b); }
}
