package org.zeroj.bls12381.spi;

import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * ADR-0062 D9 / I8: one shared corpus that every {@link Bls12381Provider} (pure Java, blst, WASM)
 * must pass, so the providers return equal results or all reject.
 *
 * <p>Expected values never come from the provider under test: scalar multiples are computed with
 * the affine {@link G1Point#scalarMul}/{@link G2Point#scalarMul} double-and-add (independent of blst,
 * of the WASM oracle and of the pure-Java secret ladder; for the pure-Java public path it is the same
 * code, so that one leg is a self-check), and pairing products are built so that the answer is known
 * algebraically ({@code e(aP, bQ)·e(−abP, Q) = 1}, perturbed by one generator).</p>
 *
 * <p>Plain assertions ({@link AssertionError}) keep this fixture free of a test-framework
 * dependency; each provider's test module calls these from its own tests.</p>
 */
public final class Bls12381ProviderConformance {

    private Bls12381ProviderConformance() {}

    public static final BigInteger R = Bls12381Generators.SCALAR_FIELD_ORDER;
    private static final G1Point G1 = Bls12381Generators.G1;
    private static final G2Point G2 = Bls12381Generators.G2;
    private static final Fp2 B_TWIST = Fp2.of(Fp.of(4), Fp.of(4));

    /** {@code −1, 0, r−1, r, r+1, 2²⁵⁵+1, 2²⁵⁶+1, −2³⁰⁰}: every provider reduces mod r. */
    public static final List<BigInteger> EDGE_SCALARS = List.of(
            BigInteger.valueOf(-1), BigInteger.ZERO, R.subtract(BigInteger.ONE), R, R.add(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE), BigInteger.ONE.shiftLeft(256).add(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(300).negate());

    // ---- scalar multiplication ----

    /**
     * {@code count} seeded random scalar multiplications per group on the public and the secret
     * path, plus every {@link #EDGE_SCALARS} value, each compared with the affine oracle.
     */
    public static void scalarMultiplication(Bls12381Provider provider, int count, long seed) {
        Random random = new Random(seed);
        G1Point[] g1Bases = new G1Point[4];
        G2Point[] g2Bases = new G2Point[4];
        for (int i = 0; i < g1Bases.length; i++) {
            BigInteger s = new BigInteger(255, random).mod(R);
            g1Bases[i] = G1.scalarMul(s);
            g2Bases[i] = G2.scalarMul(s);
        }
        List<BigInteger> scalars = new ArrayList<>(EDGE_SCALARS);
        for (int i = 0; i < count; i++) {
            scalars.add(new BigInteger(256, random));
        }
        for (int i = 0; i < scalars.size(); i++) {
            BigInteger k = scalars.get(i);
            BigInteger reduced = k.mod(R);
            G1Point p = g1Bases[i % g1Bases.length];
            G2Point q = g2Bases[i % g2Bases.length];
            G1Point e1 = p.scalarMul(reduced);
            G2Point e2 = q.scalarMul(reduced);
            String label = provider.id() + " k=" + k.toString(16);
            check(e1.equals(provider.g1ScalarMul(p, k)), "g1ScalarMul " + label);
            check(e1.equals(provider.g1SecretScalarMul(p, k)), "g1SecretScalarMul " + label);
            check(e2.equals(provider.g2ScalarMul(q, k)), "g2ScalarMul " + label);
            check(e2.equals(provider.g2SecretScalarMul(q, k)), "g2SecretScalarMul " + label);
        }
    }

    // ---- pairing products ----

    /**
     * {@code count} seeded two-pair products: even trials are the identity
     * {@code e(aP, bQ)·e(−abP, Q)}, odd trials are perturbed to {@code e(aP, bQ)·e(−(ab+1)P, Q)}.
     * Also: identity pairs contribute 1, and empty or mismatched input is rejected.
     */
    public static void pairingProducts(Bls12381Provider provider, int count, long seed) {
        Random random = new Random(seed);
        for (int i = 0; i < count; i++) {
            BigInteger a = new BigInteger(255, random).mod(R);
            BigInteger b = new BigInteger(255, random).mod(R);
            BigInteger ab = a.multiply(b);
            boolean identity = i % 2 == 0;
            BigInteger c = identity ? ab : ab.add(BigInteger.ONE);
            G1Point[] ps = {G1.scalarMul(a), G1.scalarMul(c.mod(R)).negate()};
            G2Point[] qs = {G2.scalarMul(b), G2};
            check(provider.pairingProductIsIdentity(ps, qs) == identity,
                    provider.id() + " pairing trial " + i + " expected " + identity);
        }
        check(provider.pairingProductIsIdentity(new G1Point[]{G1Point.INFINITY}, new G2Point[]{G2}),
                provider.id() + " identity pair contributes 1");
        check(!provider.pairingProductIsIdentity(new G1Point[]{G1Point.INFINITY, G1}, new G2Point[]{G2, G2}),
                provider.id() + " identity pair does not mask the rest");
        rejects(() -> provider.pairingProductIsIdentity(new G1Point[0], new G2Point[0]), "empty pairing");
        rejects(() -> provider.pairingProductIsIdentity(new G1Point[]{G1}, new G2Point[0]), "mismatched pairing");
    }

    // ---- invalid points ----

    /** Off-curve and non-subgroup points are rejected by every point-taking method. */
    public static void invalidPointsRejected(Bls12381Provider provider) {
        List<G1Point> badG1 = List.of(new G1Point(Fp.ONE, Fp.ONE), g1OutsideSubgroup());
        List<G2Point> badG2 = List.of(new G2Point(Fp2.ONE, Fp2.ONE), g2OutsideSubgroup());
        for (G1Point p : badG1) {
            rejects(() -> provider.g1ScalarMul(p, BigInteger.TWO), "g1ScalarMul " + p);
            rejects(() -> provider.g1SecretScalarMul(p, BigInteger.TWO), "g1SecretScalarMul " + p);
            rejects(() -> provider.pairingProductIsIdentity(new G1Point[]{p}, new G2Point[]{G2}), "pairing g1 " + p);
        }
        for (G2Point q : badG2) {
            rejects(() -> provider.g2ScalarMul(q, BigInteger.TWO), "g2ScalarMul " + q);
            rejects(() -> provider.g2SecretScalarMul(q, BigInteger.TWO), "g2SecretScalarMul " + q);
            rejects(() -> provider.pairingProductIsIdentity(new G1Point[]{G1}, new G2Point[]{q}), "pairing g2 " + q);
        }
    }

    // ---- malformed-encoding corpus ----

    /** A named point encoding and whether a strict uncompressed decoder must accept it. */
    public record Encoding(String name, byte[] bytes, boolean valid) {
        public Encoding {
            Objects.requireNonNull(name);
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }

        @Override
        public String toString() {
            return name;
        }
    }

    /** Uncompressed G1 encodings (96 bytes, ZCash flags): two valid, the identity, and malformed ones. */
    public static List<Encoding> g1Encodings() {
        List<Encoding> out = new ArrayList<>();
        byte[] g = Bls12381Codecs.g1ToUncompressed(G1);
        out.add(new Encoding("generator", g, true));
        out.add(new Encoding("[7]G", Bls12381Codecs.g1ToUncompressed(G1.scalarMul(BigInteger.valueOf(7))), true));
        out.add(new Encoding("identity", Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY), true));
        out.add(new Encoding("length 95", Arrays.copyOf(g, 95), false));
        out.add(new Encoding("length 97", Arrays.copyOf(g, 97), false));
        out.add(new Encoding("compression flag", flag(g, 0x80), false));
        out.add(new Encoding("sort flag", flag(g, 0x20), false));
        out.add(new Encoding("identity flag on a point", flag(g, 0x40), false));
        byte[] infBits = Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY);
        infBits[95] = 1;
        out.add(new Encoding("identity with extra bits", infBits, false));
        out.add(new Encoding("all zero, no flag", new byte[96], false));
        out.add(new Encoding("x = p", withFp(g, 0, Fp.P), false));
        out.add(new Encoding("y = p", withFp(g, 48, Fp.P), false));
        out.add(new Encoding("x = 2^381 - 1", withFp(g, 0, BigInteger.ONE.shiftLeft(381).subtract(BigInteger.ONE)), false));
        out.add(new Encoding("off curve (y + 1)", withFp(g, 48, G1.y().value().add(BigInteger.ONE)), false));
        G1Point torsion = g1OutsideSubgroup();
        out.add(new Encoding("outside subgroup", Bls12381Codecs.g1ToUncompressed(torsion), false));
        out.add(new Encoding("outside subgroup, other y", Bls12381Codecs.g1ToUncompressed(torsion.negate()), false));
        return out;
    }

    /** Uncompressed G2 encodings (192 bytes, {@code x.c1‖x.c0‖y.c1‖y.c0}). */
    public static List<Encoding> g2Encodings() {
        List<Encoding> out = new ArrayList<>();
        byte[] g = Bls12381Codecs.g2ToUncompressed(G2);
        out.add(new Encoding("generator", g, true));
        out.add(new Encoding("[7]G", Bls12381Codecs.g2ToUncompressed(G2.scalarMul(BigInteger.valueOf(7))), true));
        out.add(new Encoding("identity", Bls12381Codecs.g2ToUncompressed(G2Point.INFINITY), true));
        out.add(new Encoding("length 191", Arrays.copyOf(g, 191), false));
        out.add(new Encoding("compression flag", flag(g, 0x80), false));
        out.add(new Encoding("sort flag", flag(g, 0x20), false));
        out.add(new Encoding("identity flag on a point", flag(g, 0x40), false));
        byte[] infBits = Bls12381Codecs.g2ToUncompressed(G2Point.INFINITY);
        infBits[191] = 1;
        out.add(new Encoding("identity with extra bits", infBits, false));
        out.add(new Encoding("all zero, no flag", new byte[192], false));
        out.add(new Encoding("x.c1 = p", withFp(g, 0, Fp.P), false));
        out.add(new Encoding("x.c0 = p", withFp(g, 48, Fp.P), false));
        out.add(new Encoding("y.c0 = p", withFp(g, 144, Fp.P), false));
        out.add(new Encoding("off curve (y.c0 + 1)", withFp(g, 144, G2.y().c0().value().add(BigInteger.ONE)), false));
        // Fp2 halves swapped (c0‖c1 instead of c1‖c0): must not decode as a valid point.
        byte[] swapped = new byte[192];
        for (int half : new int[]{0, 96}) {
            System.arraycopy(g, half, swapped, half + 48, 48);
            System.arraycopy(g, half + 48, swapped, half, 48);
        }
        G2Point swappedPoint = new G2Point(Fp2.of(G2.x().c1(), G2.x().c0()), Fp2.of(G2.y().c1(), G2.y().c0()));
        if (!onTwist(swappedPoint)) {
            out.add(new Encoding("Fp2 halves swapped", swapped, false));
        }
        G2Point torsion = g2OutsideSubgroup();
        out.add(new Encoding("outside subgroup", Bls12381Codecs.g2ToUncompressed(torsion), false));
        out.add(new Encoding("outside subgroup, other y", Bls12381Codecs.g2ToUncompressed(torsion.negate()), false));
        return out;
    }

    // ---- helpers ----

    private static byte[] flag(byte[] encoding, int bit) {
        byte[] out = encoding.clone();
        out[0] |= (byte) bit;
        return out;
    }

    private static byte[] withFp(byte[] encoding, int offset, BigInteger value) {
        byte[] out = encoding.clone();
        byte[] be = value.toByteArray();
        int n = Math.min(be.length, 48);
        Arrays.fill(out, offset, offset + 48, (byte) 0);
        System.arraycopy(be, be.length - n, out, offset + 48 - n, n);
        return out;
    }

    /** y² = x³ + 4(1 + u), written out here rather than calling the code under test. */
    private static boolean onTwist(G2Point p) {
        return p.y().square().equals(p.x().square().mul(p.x()).add(B_TWIST));
    }

    public static G1Point g1OutsideSubgroup() {
        for (int x = 1; ; x++) {
            Fp fx = Fp.of(x);
            var y = fx.square().mul(fx).add(Fp.of(4)).sqrt();
            if (y.isPresent() && !G1Point.INFINITY.equals(new G1Point(fx, y.get()).scalarMul(R))) {
                return new G1Point(fx, y.get());
            }
        }
    }

    public static G2Point g2OutsideSubgroup() {
        for (int x = 1; ; x++) {
            Fp2 fx = Fp2.of(Fp.of(x), Fp.ZERO);
            var y = fx.square().mul(fx).add(B_TWIST).sqrt();
            if (y.isPresent() && !G2Point.INFINITY.equals(new G2Point(fx, y.get()).scalarMul(R))) {
                return new G2Point(fx, y.get());
            }
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void rejects(Runnable call, String message) {
        try {
            call.run();
        } catch (IllegalArgumentException | NullPointerException expected) {
            return;
        }
        throw new AssertionError("expected a rejection: " + message);
    }
}
