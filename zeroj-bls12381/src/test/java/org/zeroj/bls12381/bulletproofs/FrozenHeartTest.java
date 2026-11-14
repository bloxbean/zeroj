package org.zeroj.bls12381.bulletproofs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 I2: the Frozen Heart forgery (Trail of Bits, 2022; CVE-2022-29566) against a weak
 * Fiat–Shamir Bulletproof, whose transcript omits {@code V}.
 *
 * <p>The forger runs the honest prover for a commitment {@code V} it can open, but publishes
 * {@code T₁' = T₁ + G}. Because {@code V} plays no part in the challenges of a weak transcript, it
 * can afterwards pick {@code V' = V − [x·z⁻²]·G}, which opens to {@code v − x·z⁻²} (out of range with
 * overwhelming probability). Check 2 does not involve {@code V} and still holds, and check 1 holds
 * for {@code V'}. Under this protocol's strong transcript the challenges for {@code V'} are different,
 * so the forged proof is rejected.
 */
class FrozenHeartTest {

    private static final byte[] CTX = "https://example.com/zeroj/frozen-heart/v1".getBytes(StandardCharsets.US_ASCII);
    private static final int N = 16;

    @Test
    @DisplayName("A forged proof that a weak verifier (V not absorbed) would accept for V' is rejected")
    void forgeryRejected() {
        BigInteger v = BigInteger.valueOf(42);
        BigInteger gamma = BigInteger.valueOf(1234567);
        G1PedersenCommitment honest = G1Pedersen.pureJava().commitScalar(v, gamma);
        G1Point vPoint = PointCodec.point(honest);

        Forgery f = forge(v, gamma, vPoint);
        G1RangeVerifier verifier = G1RangeVerifier.pureJava();

        // A weak verifier computes the challenges without V': here, from the transcript the forger used.
        G1RangeVerifier.Challenges weak = G1RangeVerifier.Challenges.derive(vPoint, f.proof, CTX);
        assertEquals(G1RangeVerifier.Layer.ACCEPT, verifier.checks(f.forgedV, f.proof, weak),
                "the recipe works against a transcript that does not bind V'");
        assertNotEquals(vPoint, f.forgedV);

        // This protocol absorbs V' itself: the challenges change and the proof fails.
        G1PedersenCommitment forged = G1PedersenCommitment.decode(PointCodec.encode(f.forgedV));
        assertFalse(verifier.verify(forged, f.proof, N, CTX));
        assertFalse(verifier.verify(forged.toPointBytes(), f.proof.toBytes(), N, CTX));
        assertTrue(verifier.evaluate(f.forgedV, f.proof, CTX).layer() != G1RangeVerifier.Layer.ACCEPT);
    }

    private record Forgery(G1RangeProof proof, G1Point forgedV) {
    }

    /**
     * A test-only prover (public arithmetic, seeded nonces): honest for {@code (v, γ)} except that it
     * publishes {@code T₁ + G}, using the transcript of the honest {@code V}.
     */
    private static Forgery forge(BigInteger v, BigInteger gamma, G1Point vPoint) {
        Random random = new Random(0xF0F0);
        BigInteger q = PointCodec.Q;
        int k = RangeTranscript.rounds(N);
        BigInteger alpha = new BigInteger(300, random).mod(q);
        BigInteger rho = new BigInteger(300, random).mod(q);
        BigInteger tau1 = new BigInteger(300, random).mod(q);
        BigInteger tau2 = new BigInteger(300, random).mod(q);
        BigInteger[] aL = new BigInteger[N], aR = new BigInteger[N], sL = new BigInteger[N], sR = new BigInteger[N];
        G1Point a = BulletproofGenerators.h().scalarMul(alpha);
        G1Point s = BulletproofGenerators.h().scalarMul(rho);
        for (int i = 0; i < N; i++) {
            aL[i] = v.testBit(i) ? BigInteger.ONE : BigInteger.ZERO;
            aR[i] = RangeMath.sub(aL[i], BigInteger.ONE);
            sL[i] = new BigInteger(300, random).mod(q);
            sR[i] = new BigInteger(300, random).mod(q);
            a = a.add(BulletproofGenerators.gVec(i).scalarMul(aL[i])).add(BulletproofGenerators.hVec(i).scalarMul(aR[i]));
            s = s.add(BulletproofGenerators.gVec(i).scalarMul(sL[i])).add(BulletproofGenerators.hVec(i).scalarMul(sR[i]));
        }
        RangeTranscript t = RangeTranscript.start(N, CTX, vPoint);
        BigInteger y = t.absorbPointsSqueeze(a, s);
        BigInteger z = t.challenge();
        BigInteger z2 = RangeMath.mul(z, z);
        BigInteger[] yPow = RangeMath.powers(y, N);
        BigInteger[] l0 = new BigInteger[N], r0 = new BigInteger[N], r1 = new BigInteger[N];
        for (int i = 0; i < N; i++) {
            l0[i] = RangeMath.sub(aL[i], z);
            r0[i] = RangeMath.add(RangeMath.mul(yPow[i], RangeMath.add(aR[i], z)), RangeMath.mul(z2, BigInteger.ONE.shiftLeft(i)));
            r1[i] = RangeMath.mul(yPow[i], sR[i]);
        }
        BigInteger t1 = RangeMath.add(RangeMath.inner(l0, r1), RangeMath.inner(sL, r0));
        BigInteger t2 = RangeMath.inner(sL, r1);
        G1Point bigT1 = BulletproofGenerators.g().scalarMul(t1).add(BulletproofGenerators.h().scalarMul(tau1))
                .add(BulletproofGenerators.g());                                   // the forgery: T₁ + G
        G1Point bigT2 = BulletproofGenerators.g().scalarMul(t2).add(BulletproofGenerators.h().scalarMul(tau2));
        BigInteger x = t.absorbPointsSqueeze(bigT1, bigT2);
        BigInteger[] l = new BigInteger[N], r = new BigInteger[N];
        for (int i = 0; i < N; i++) {
            l[i] = RangeMath.add(l0[i], RangeMath.mul(x, sL[i]));
            r[i] = RangeMath.add(r0[i], RangeMath.mul(x, r1[i]));
        }
        BigInteger tHat = RangeMath.inner(l, r);
        BigInteger tauX = RangeMath.add(RangeMath.add(RangeMath.mul(tau2, RangeMath.mul(x, x)), RangeMath.mul(tau1, x)),
                RangeMath.mul(z2, gamma));
        BigInteger mu = RangeMath.add(alpha, RangeMath.mul(rho, x));
        t.absorbScalars(tHat, tauX, mu);
        BigInteger xu = t.challenge();

        G1Point[] g = new G1Point[N], h = new G1Point[N];
        BigInteger yInv = RangeMath.inv(y);
        for (int i = 0; i < N; i++) {
            g[i] = BulletproofGenerators.gVec(i);
            h[i] = BulletproofGenerators.hVec(i).scalarMul(yInv.modPow(BigInteger.valueOf(i), q));
        }
        G1Point u = BulletproofGenerators.u().scalarMul(xu);
        G1Point[] ls = new G1Point[k], rs = new G1Point[k];
        int len = N;
        for (int j = 0; j < k; j++) {
            int half = len / 2;
            G1Point lj = u.scalarMul(RangeMath.inner(l, 0, r, half, half));
            G1Point rj = u.scalarMul(RangeMath.inner(l, half, r, 0, half));
            for (int i = 0; i < half; i++) {
                lj = lj.add(g[half + i].scalarMul(l[i])).add(h[i].scalarMul(r[half + i]));
                rj = rj.add(g[i].scalarMul(l[half + i])).add(h[half + i].scalarMul(r[i]));
            }
            BigInteger xj = t.absorbPointsSqueeze(lj, rj);
            BigInteger xjInv = RangeMath.inv(xj);
            for (int i = 0; i < half; i++) {
                g[i] = g[i].scalarMul(xjInv).add(g[half + i].scalarMul(xj));
                h[i] = h[i].scalarMul(xj).add(h[half + i].scalarMul(xjInv));
                l[i] = RangeMath.add(RangeMath.mul(xj, l[i]), RangeMath.mul(xjInv, l[half + i]));
                r[i] = RangeMath.add(RangeMath.mul(xjInv, r[i]), RangeMath.mul(xj, r[half + i]));
            }
            ls[j] = lj;
            rs[j] = rj;
            len = half;
        }
        G1RangeProof proof = G1RangeProof.of(N, a, s, bigT1, bigT2, tHat, tauX, mu, ls, rs, l[0], r[0]);
        // Check 1 with T₁ + G holds for V' = V − [x·z⁻²]·G.
        G1Point forgedV = vPoint.add(BulletproofGenerators.g().scalarMul(RangeMath.neg(RangeMath.mul(x, RangeMath.inv(z2)))));
        return new Forgery(proof, forgedV);
    }
}
