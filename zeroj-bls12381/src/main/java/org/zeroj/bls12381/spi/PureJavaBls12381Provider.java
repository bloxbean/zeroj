package org.zeroj.bls12381.spi;

import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.pairing.BLS12381Pairing;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Default provider backed by ZeroJ's pure Java BLS12-381 implementation.
 *
 * <p>This provider is correctness-first and portable. Its secret-scalar methods use the
 * module's split, fixed-schedule Java ladders (ADR-0062 D1, r4): the scalar is split into two fresh
 * uniform shares, so neither the operation count nor the ladders' identity handling depends on it,
 * including for small or near-{@code r} secrets. They do not provide a JVM constant-time guarantee
 * (per-bit Java branch, {@code BigInteger}, field reductions, JIT and GC remain variable-time). No ZeroJ provider, including {@code zeroj-blst}, has an evidenced side-channel
 * contract (ADR-0062 D2), so secret-bearing generation is offline/isolated only on every
 * provider.</p>
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

    /**
     * Split, fixed-schedule ladders (ADR-0062 D1). {@link G1Point#ctScalarMul} validates the point
     * (on the curve, in the subgroup) and rejects anything else, so it is checked exactly once.
     */
    @Override
    public G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
        return Objects.requireNonNull(point, "point required")
                .ctScalarMul(reduceScalar(scalar));
    }

    /** As {@link #g1SecretScalarMul}, over G2. */
    @Override
    public G2Point g2SecretScalarMul(G2Point point, BigInteger scalar) {
        return Objects.requireNonNull(point, "point required")
                .ctScalarMul(reduceScalar(scalar));
    }

    @Override
    public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
        Bls12381Provider.requirePairingProductInput(g1Points, g2Points);
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
