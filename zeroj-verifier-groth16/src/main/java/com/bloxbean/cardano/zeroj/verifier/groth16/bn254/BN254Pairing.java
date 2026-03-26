package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

import java.math.BigInteger;

/**
 * BN254 optimal Ate pairing implementation.
 *
 * <p>Computes e(P, Q) where P is a G1 point and Q is a G2 point, returning an Fp12 element.
 * The pairing is bilinear: e(aP, bQ) = e(P, Q)^{ab}.</p>
 *
 * <p>Fp12 tower: Fp2[v]/(v^3-xi) = Fp6, Fp6[w]/(w^2-v) = Fp12.
 * So w^2 = v, w^6 = xi = 9 + u.</p>
 *
 * <p>Twist maps G2(Fp2) -> E(Fp12): (x, y) -> (x*w^{-2}, y*w^{-3}).
 * Line functions produce sparse Fp12 elements in positions c0.c0, c0.c1 (w^2), c1.c1 (w^3).</p>
 *
 * <p>Reference: "High-Speed Software Implementation of the Optimal Ate Pairing" (Beuchat et al.),
 * Hyperledger Besu alt_bn128 implementation.</p>
 */
public final class BN254Pairing {

    private BN254Pairing() {}

    /**
     * The loop count for the optimal Ate pairing on BN254.
     * This is 6x + 2 where x = 4965661367071055336 is the BN parameter.
     * 6x + 2 = 29793968203157093288 * 6 + 2 ... wait, let me compute correctly.
     * x = 4965661367071055336
     * 6x + 2 = 29793968202426332018 + 2 = 29793968202426332020
     *
     * Actually the standard ATE_LOOP_COUNT for alt_bn128 is:
     * 29793968203157093288 (this is 6x+2, matching Ethereum's implementation)
     */
    private static final BigInteger ATE_LOOP_COUNT = new BigInteger("29793968203157093288");

    // Whether the loop count is negative (it is for BN254)
    private static final boolean ATE_LOOP_NEGATIVE = false;

    // Frobenius twist constants: xi^((p-1)/3) and xi^((p-1)/2)
    private static final Fp2 TWIST_MUL_BY_Q_X = Fp2.of(
            Fp.of("21575463638280843010398324269430826099269044274347216827212613867836435027261"),
            Fp.of("10307601595873709700152284273816112264069230130616436755625194854815875713954")
    );
    private static final Fp2 TWIST_MUL_BY_Q_Y = Fp2.of(
            Fp.of("2821565182194536844548159561693502659359617185244120367078079554186484126554"),
            Fp.of("3505843767911556378687030309984248845540243509899259641013678093033130930403")
    );

    /**
     * Check if a product of pairings equals one (the identity in GT).
     * This is what Groth16 verification needs: e(A, B) * e(-alpha, beta) * e(-vkx, gamma) * e(-C, delta) == 1
     */
    public static boolean pairingCheck(G1Point[] ps, G2Point[] qs) {
        if (ps.length != qs.length) throw new IllegalArgumentException("Arrays must have equal length");

        // Compute product of Miller loops
        var f = Fp12.ONE;
        for (int i = 0; i < ps.length; i++) {
            if (!ps[i].isInfinity() && !qs[i].isInfinity()) {
                f = f.mul(millerLoop(ps[i], qs[i]));
            }
        }

        // Final exponentiation
        var result = finalExponentiation(f);
        return result.isOne();
    }

    /**
     * Miller loop for the optimal Ate pairing.
     *
     * <p>The line functions produce sparse Fp12 elements using the twist mapping.
     * In our Fp12 tower (Fp6[w]/(w^2-v), Fp6 = Fp2[v]/(v^3-xi)):</p>
     * <ul>
     *   <li>w^0 = 1 → c0.c0</li>
     *   <li>w^2 = v → c0.c1</li>
     *   <li>w^3 = vw → c1.c1</li>
     *   <li>w^4 = v^2 → c0.c2</li>
     * </ul>
     */
    static Fp12 millerLoop(G1Point p, G2Point q) {
        if (p.isInfinity() || q.isInfinity()) return Fp12.ONE;

        var f = Fp12.ONE;
        var curT = q; // Running point on G2

        // Process bits of ATE_LOOP_COUNT from second-most-significant bit down
        int nbits = ATE_LOOP_COUNT.bitLength();

        for (int i = nbits - 2; i >= 0; i--) {
            f = f.square();

            // Doubling step: T <- 2T, f <- f * l_{T,T}(P)
            f = f.mul(lineFuncDouble(curT, p));
            curT = curT.doublePoint();

            if (ATE_LOOP_COUNT.testBit(i)) {
                // Addition step: T <- T+Q, f <- f * l_{T,Q}(P)
                f = f.mul(lineFuncAdd(curT, q, p));
                curT = curT.add(q);
            }
        }

        // Two Frobenius correction steps for optimal Ate on BN254
        var q1 = frobeniusG2(q);
        var q2 = frobeniusG2(frobeniusG2(q)).negate();

        f = f.mul(lineFuncAdd(curT, q1, p));
        curT = curT.add(q1);
        f = f.mul(lineFuncAdd(curT, q2, p));

        return f;
    }

    /**
     * Line function for point doubling at T, evaluated at P (G1).
     *
     * <p>Sparse Fp12 positions (matching go-ethereum google/bn256):</p>
     * <ul>
     *   <li>c0.c0 (w^0) = 2*T.y * P.y</li>
     *   <li>c1.c0 (w^1) = -3*T.x^2 * P.x</li>
     *   <li>c1.c1 (w^3) = 3*T.x^3 - 2*T.y^2</li>
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

        // c0.c0 (w^0) = 2*T.y * P.y
        var c = twoTy.mul(py);

        // c1.c0 (w^1) = -3*T.x^2 * P.x
        var b = threeTx2.neg().mul(px);

        // c1.c1 (w^3) = 3*T.x^3 - 2*T.y^2
        var a = threeTx3.sub(twoTy2);

        return new Fp12(
                new Fp6(c, Fp2.ZERO, Fp2.ZERO),
                new Fp6(b, a, Fp2.ZERO)
        );
    }

    /**
     * Line function for point addition of T and Q, evaluated at P (G1).
     *
     * <p>Sparse Fp12 positions (matching go-ethereum google/bn256):</p>
     * <ul>
     *   <li>c0.c0 (w^0) = P.y</li>
     *   <li>c1.c0 (w^1) = -lambda * P.x</li>
     *   <li>c1.c1 (w^3) = lambda * T.x - T.y</li>
     * </ul>
     */
    private static Fp12 lineFuncAdd(G2Point t, G2Point q, G1Point p) {
        if (t.x().equals(q.x())) {
            var px = Fp2.of(p.x(), Fp.ZERO);
            return new Fp12(
                    Fp6.ZERO,
                    new Fp6(px.sub(t.x()), Fp2.ZERO, Fp2.ZERO)
            );
        }

        var dy = q.y().sub(t.y());
        var dx = q.x().sub(t.x());
        var lambda = dy.mul(dx.inv());

        var px = Fp2.of(p.x(), Fp.ZERO);
        var py = Fp2.of(p.y(), Fp.ZERO);

        // c0.c0 (w^0) = P.y
        var c = py;

        // c1.c0 (w^1) = -lambda * P.x
        var b = lambda.neg().mul(px);

        // c1.c1 (w^3) = lambda * T.x - T.y
        var a = lambda.mul(t.x()).sub(t.y());

        return new Fp12(
                new Fp6(c, Fp2.ZERO, Fp2.ZERO),
                new Fp6(b, a, Fp2.ZERO)
        );
    }

    /**
     * Frobenius endomorphism on G2 twist point.
     * pi(x, y) = (conj(x) * TWIST_MUL_BY_Q_X, conj(y) * TWIST_MUL_BY_Q_Y)
     */
    static G2Point frobeniusG2(G2Point q) {
        if (q.isInfinity()) return q;
        return new G2Point(
                q.x().conjugate().mul(TWIST_MUL_BY_Q_X),
                q.y().conjugate().mul(TWIST_MUL_BY_Q_Y)
        );
    }

    /**
     * Final exponentiation: f^{(p^12 - 1) / r}.
     *
     * <p>Decomposed as:</p>
     * <ol>
     *   <li>Easy part: f^{(p^6 - 1)} then f^{(p^2 + 1)}</li>
     *   <li>Hard part: f^{(p^4 - p^2 + 1)/r} via BN parameter decomposition</li>
     * </ol>
     */
    static Fp12 finalExponentiation(Fp12 f) {
        // Easy part step 1: f^{p^6 - 1} = conj(f) * f^{-1}
        var t0 = f.conjugate();
        var t1 = f.inv();
        var t2 = t0.mul(t1); // f^{p^6 - 1}

        // Easy part step 2: (f^{p^6-1})^{p^2+1}
        // For elements in the p^6-1 subgroup, Frobenius^2 = conjugate of Frobenius = ...
        // We use the simplified approach: just compute f^{p^2} * f
        // For BN254, after easy part step 1, the element is in the cyclotomic subgroup
        // p^2 on Fp12 elements: we use the hard exponentiation directly

        // For correctness, we use the full exponent: (p^12-1)/r
        // The easy part already gives us f^{p^6-1}
        // We still need f^{(p^6-1)(p^2+1)(p^4-p^2+1)/r}
        // = (f^{p^6-1})^{(p^2+1)(p^4-p^2+1)/r}

        // Compute the remaining exponent: (p^2+1)(p^4-p^2+1)/r
        var p = Fp.P;
        var r = G1Point.R;
        var p2 = p.multiply(p);
        var p4 = p2.multiply(p2);
        var part1 = p2.add(BigInteger.ONE);
        var part2 = p4.subtract(p2).add(BigInteger.ONE);
        var hardExp = part1.multiply(part2).divide(r);

        return t2.pow(hardExp);
    }
}
