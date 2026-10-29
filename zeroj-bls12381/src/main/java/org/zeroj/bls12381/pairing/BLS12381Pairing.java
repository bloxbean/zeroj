package org.zeroj.bls12381.pairing;

import org.zeroj.bls12381.ec.*;
import org.zeroj.bls12381.field.*;

import java.math.BigInteger;

/**
 * BLS12-381 optimal Ate pairing — pure Java implementation.
 *
 * <p>Computes e(P, Q) where P is a G1 point and Q is a G2 point, returning an Fp12 element.
 * The pairing is bilinear: e(aP, bQ) = e(P, Q)^{ab}.</p>
 *
 * <p>Tower: Fp2[v]/(v^3 - xi) = Fp6, Fp6[w]/(w^2 - v) = Fp12.
 * xi = 1 + u for BLS12-381.</p>
 *
 * <p>The Ate loop parameter is x = -0xd201000000010000 (negative, 64-bit).
 * This is the BLS parameter that determines the curve security.</p>
 *
 * <p><b>This class validates nothing</b> (ADR-0062 D7). {@link G1Point} and {@link G2Point} are raw
 * coordinate records, and the methods here accept any coordinates: an off-curve or
 * non-subgroup point is evaluated as if it were valid and yields a meaningless result. Callers
 * must validate untrusted points first, with {@code Bls12381Codecs.requireValid} or the checked
 * decoders, or use a {@code Bls12381Provider}, whose {@code pairingProductIsIdentity} validates
 * and rejects empty input.</p>
 */
public final class BLS12381Pairing {

    private BLS12381Pairing() {}

    /**
     * BLS12-381 parameter x (absolute value).
     * x = 0xd201000000010000 = 15132376222941642752
     */
    private static final BigInteger ATE_LOOP_COUNT = new BigInteger("d201000000010000", 16);

    /** The Ate loop is negative for BLS12-381. */
    private static final boolean ATE_LOOP_NEGATIVE = true;

    /**
     * Check if a product of pairings equals one.
     * Used for PlonK KZG verification: e(A, B) * e(C, D) == 1
     *
     * <p>Raw primitive: no point is validated (see the class Javadoc). Pairs with an identity
     * component contribute 1. An empty product is 1, so {@code pairingCheck([], [])} returns
     * {@code true}; that is mathematically correct, but a verifier that builds its arrays
     * dynamically must reject empty input itself or use the provider method, which does.</p>
     *
     * @throws IllegalArgumentException if the arrays differ in length
     */
    public static boolean pairingCheck(G1Point[] ps, G2Point[] qs) {
        if (ps.length != qs.length) throw new IllegalArgumentException("Arrays must have equal length");

        var f = Fp12.ONE;
        for (int i = 0; i < ps.length; i++) {
            if (!ps[i].isInfinity() && !qs[i].isInfinity()) {
                f = f.mul(millerLoop(ps[i], qs[i]));
            }
        }

        var result = finalExponentiation(f);
        return result.isOne();
    }

    /**
     * Miller loop for the optimal Ate pairing on BLS12-381.
     *
     * <p>Raw primitive: no point is validated (see the class Javadoc). Returns 1 if either point is
     * the identity.</p>
     *
     * @throws IllegalArgumentException if the loop reaches {@code T = ±Q}, which cannot happen for
     *         {@code Q} in the prime-order subgroup
     */
    public static Fp12 millerLoop(G1Point p, G2Point q) {
        if (p.isInfinity() || q.isInfinity()) return Fp12.ONE;

        var f = Fp12.ONE;
        var curT = q;

        int nbits = ATE_LOOP_COUNT.bitLength();
        for (int i = nbits - 2; i >= 0; i--) {
            f = f.square();

            // Doubling step
            f = f.mul(lineFuncDouble(curT, p));
            curT = curT.doublePoint();

            if (ATE_LOOP_COUNT.testBit(i)) {
                // Addition step
                f = f.mul(lineFuncAdd(curT, q, p));
                curT = curT.add(q);
            }
        }

        // For BLS12-381, the loop parameter is negative, so conjugate the result
        if (ATE_LOOP_NEGATIVE) {
            f = f.conjugate();
        }

        return f;
    }

    /**
     * Line function for point doubling at T, evaluated at P.
     *
     * <p>BLS12-381 M-twist sparse positions (matching gnark-crypto mul014):
     * <ul>
     *   <li>c0.c0 (pos 0, constant): term from T coordinates</li>
     *   <li>c0.c1 (pos 1, v): slope * P_x</li>
     *   <li>c1.c1 (pos 4, vw): tangent_y * P_y</li>
     * </ul>
     */
    private static Fp12 lineFuncDouble(G2Point t, G1Point p) {
        var tx2 = t.x().square();
        var threeTx2 = tx2.add(tx2).add(tx2);
        var twoTy = t.y().add(t.y());

        var px = Fp2.of(p.x(), Fp.ZERO);
        var py = Fp2.of(p.y(), Fp.ZERO);

        var twoTy2 = t.y().square().add(t.y().square());
        var threeTx3 = threeTx2.mul(t.x());

        // pos 0 (c0.c0) = constant from T: 3*T_x^3 - 2*T_y^2
        var c0 = threeTx3.sub(twoTy2);
        // pos 1 (c0.c1) = -3*T_x^2 * P_x (slope * P_x)
        var c1 = threeTx2.neg().mul(px);
        // pos 4 (c1.c1) = 2*T_y * P_y (tangent_y * P_y)
        var c4 = twoTy.mul(py);

        return new Fp12(
                new Fp6(c0, c1, Fp2.ZERO),
                new Fp6(Fp2.ZERO, c4, Fp2.ZERO));
    }

    /**
     * Line function for point addition of T and Q, evaluated at P.
     *
     * <p>BLS12-381 M-twist sparse positions: c0.c0 (constant), c0.c1 (P_x), c1.c1 (P_y).</p>
     */
    private static Fp12 lineFuncAdd(G2Point t, G2Point q, G1Point p) {
        // At every addition step T = [m]Q with 2 <= m < |x| < r, so T = ±Q (equal x) is impossible
        // for Q of prime order r. The former vertical-line branch here also mishandled T = Q (a
        // tangent, not a vertical line), so it is a hard failure instead (ADR-0062 D7).
        if (t.x().equals(q.x())) {
            throw new IllegalArgumentException("Miller loop reached T = ±Q: Q is not in the G2 subgroup");
        }

        var lambda = q.y().sub(t.y()).mul(q.x().sub(t.x()).inv());
        var px = Fp2.of(p.x(), Fp.ZERO);
        var py = Fp2.of(p.y(), Fp.ZERO);

        // pos 0 (c0.c0) = constant: lambda * T_x - T_y
        var c0 = lambda.mul(t.x()).sub(t.y());
        // pos 1 (c0.c1) = -lambda * P_x
        var c1 = lambda.neg().mul(px);
        // pos 4 (c1.c1) = P_y
        var c4 = py;

        return new Fp12(
                new Fp6(c0, c1, Fp2.ZERO),
                new Fp6(Fp2.ZERO, c4, Fp2.ZERO));
    }

    /**
     * Final exponentiation: f^{(p^12 - 1) / r}.
     *
     * <p>Easy part: f^{(p^6-1)(p^2+1)}. Hard part: f^{(p^4-p^2+1)/r}.</p>
     */
    public static Fp12 finalExponentiation(Fp12 f) {
        // Easy part step 1: f^{p^6 - 1} = conj(f) * f^{-1}
        var t0 = f.conjugate();
        var t1 = f.inv();
        var t2 = t0.mul(t1);

        // Easy part step 2 + hard part: compute remaining exponent
        var p = Fp.P;
        var r = G1Point.R;
        var p2 = p.multiply(p);
        var p4 = p2.multiply(p2);

        // Full remaining exponent: (p^2+1)(p^4-p^2+1)/r
        var part1 = p2.add(BigInteger.ONE);
        var part2 = p4.subtract(p2).add(BigInteger.ONE);
        var hardExp = part1.multiply(part2).divide(r);

        return t2.pow(hardExp);
    }
}
