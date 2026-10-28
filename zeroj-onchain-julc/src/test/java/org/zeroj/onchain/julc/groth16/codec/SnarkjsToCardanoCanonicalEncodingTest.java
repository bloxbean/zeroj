package org.zeroj.onchain.julc.groth16.codec;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** ADR-0062 D5: the snarkjs-to-Cardano codec accepts only affine (z = 1) points, like the verifiers. */
class SnarkjsToCardanoCanonicalEncodingTest {
    private static final BigInteger G1X = Bls12381Generators.G1.x().value();
    private static final BigInteger G1Y = Bls12381Generators.G1.y().value();

    @Test
    void g1CanonicalEncodingCompresses() {
        assertArrayEquals(Bls12381Codecs.g1ToCompressed(Bls12381Generators.G1),
                SnarkjsToCardano.g1Compress(List.of(G1X, G1Y, BigInteger.ONE)));
    }

    @Test
    void g1RescaledEncodingIsRejected() {
        BigInteger lambda = BigInteger.valueOf(7);
        var rescaled = List.of(G1X.multiply(lambda).mod(Fp.P), G1Y.multiply(lambda).mod(Fp.P), lambda);
        assertThrows(IllegalArgumentException.class, () -> SnarkjsToCardano.g1Compress(rescaled));
    }

    @Test
    void g2RescaledEncodingIsRejected() {
        var g2 = Bls12381Generators.G2;
        var x = List.of(g2.x().c0().value(), g2.x().c1().value());
        var y = List.of(g2.y().c0().value(), g2.y().c1().value());
        assertArrayEquals(Bls12381Codecs.g2ToCompressed(g2),
                SnarkjsToCardano.g2Compress(List.of(x, y, List.of(BigInteger.ONE, BigInteger.ZERO))));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsToCardano.g2Compress(
                List.of(x, y, List.of(BigInteger.TWO, BigInteger.ZERO))));
    }

    /** ADR-0062 M6 review: only the canonical identity encoding is accepted for z = 0. */
    @Test
    void onlyTheCanonicalIdentityIsAccepted() {
        assertArrayEquals(Bls12381Codecs.g1ToCompressed(G1Point.INFINITY),
                SnarkjsToCardano.g1Compress(List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO)));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsToCardano.g1Compress(List.of(G1X, G1Y, BigInteger.ZERO)));
        var zero = List.of(BigInteger.ZERO, BigInteger.ZERO);
        var one = List.of(BigInteger.ONE, BigInteger.ZERO);
        assertArrayEquals(Bls12381Codecs.g2ToCompressed(G2Point.INFINITY),
                SnarkjsToCardano.g2Compress(List.of(zero, one, zero)));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsToCardano.g2Compress(List.of(one, one, zero)));
    }

    @Test
    void coordinatesAtOrAboveTheModulusAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsToCardano.g1Compress(List.of(G1X.add(Fp.P), G1Y, BigInteger.ONE)));
    }
}
