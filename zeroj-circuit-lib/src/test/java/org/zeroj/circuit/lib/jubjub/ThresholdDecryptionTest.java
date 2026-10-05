package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0053 M3: threshold decryption on ADR-0052's safe API (D5, D5a; invariants I8, I9, I15).
 * Shares are verified against {@code Y_j} taken from the context by identifier. The F7
 * fixtures, with an identity-valued share and with equal {@code Y_j}, decrypt through the safe
 * context, and every {@code (t + 1)}-subset decrypts identically.
 */
class ThresholdDecryptionTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final SecureRandom RNG = new SecureRandom();

    private static List<ThresholdKeyShare> run(DkgHarness h) {
        h.run();
        assertTrue(h.aborted.isEmpty(), "aborted: " + h.aborted);
        List<ThresholdKeyShare> out = new ArrayList<>();
        for (DkgParticipant p : h.participants) out.add(p.result());
        return out;
    }

    private static List<int[]> subsets(int n, int size) {
        List<int[]> out = new ArrayList<>();
        collect(1, n, 0, new int[size], out);
        return out;
    }

    private static void collect(int start, int n, int depth, int[] current, List<int[]> out) {
        if (depth == current.length) {
            out.add(current.clone());
            return;
        }
        for (int i = start; i <= n; i++) {
            current[depth] = i;
            collect(i + 1, n, depth + 1, current, out);
        }
    }

    /** Verifies shares against the participants' real secrets: a passing check is a true statement. */
    private static ElGamalHostApiTest.KnownSecretsDleqVerifier verifierFor(List<ThresholdKeyShare> shares) {
        ElGamalHostApiTest.KnownSecretsDleqVerifier v = new ElGamalHostApiTest.KnownSecretsDleqVerifier();
        for (ThresholdKeyShare s : shares) v.know(s.secretScalar());
        return v;
    }

    @Test
    @DisplayName("2-of-3, 3-of-5, 4-of-7: every (t + 1)-subset and the full set decrypt the same value; Σ λ_j x_j = x")
    void allSubsets() {
        for (int[] tn : new int[][]{{1, 3}, {2, 5}, {3, 7}}) {
            int t = tn[0];
            int n = tn[1];
            DkgConfig config = DkgHarness.config(t, n, "threshold", n);
            List<ThresholdKeyShare> keys = run(DkgHarness.random(config, DkgHarness.HONEST));
            ThresholdKeyContext ctx = keys.get(0).context();
            ElGamalCiphertext c = ElGamal.encrypt(ctx, 5, 3, RNG);
            List<VerifiedDecryptionShare> shares = new ArrayList<>();
            ElGamalHostApiTest.KnownSecretsDleqVerifier v = verifierFor(keys);
            for (ThresholdKeyShare k : keys) {
                VerifiedDecryptionShare own = ElGamal.decryptionShare(k, c);
                shares.add(VerifiedDecryptionShare.verify(c, k.id(), own.encode(), v));
            }
            for (int[] s : subsets(n, t + 1)) {
                List<VerifiedDecryptionShare> chosen = new ArrayList<>();
                for (int id : s) chosen.add(shares.get(id - 1));
                assertEquals(5, ElGamal.decrypt(c, chosen, 7));
                BigInteger[] lambda = ThresholdMath.lagrangeAt(s, 0);
                BigInteger x = BigInteger.ZERO;
                for (int i = 0; i < s.length; i++) x = x.add(lambda[i].multiply(keys.get(s[i] - 1).secretScalar())).mod(L);
                assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(x).projectiveEquals(ctx.jointKey().point()));
            }
            assertEquals(5, ElGamal.decrypt(c, shares, 7), "all n shares: the extra ones are checked");
        }
    }

    @Test
    @DisplayName("F7 fixtures: F(z) = 3 − 3z (Y_1 = O, D_1 = O) and F(z) = 3 (equal Y_j) decrypt from every pair")
    void f7Fixtures() {
        for (BigInteger thirdSlope : List.of(L.subtract(BigInteger.valueOf(6)), L.subtract(BigInteger.valueOf(3)))) {
            DkgConfig config = DkgHarness.config(1, 3, "f7", thirdSlope.longValue() & 0xFF);
            BigInteger[] slopes = {BigInteger.ONE, BigInteger.TWO, thirdSlope};
            List<ThresholdVss.Dealing> d = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                d.add(ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.ONE, slopes[i]},
                        new BigInteger[]{ElGamal.sample(RNG), ElGamal.sample(RNG)}));
            }
            List<ThresholdKeyShare> keys = run(DkgHarness.fixed(config, d, DkgHarness.HONEST));
            ThresholdKeyContext ctx = keys.get(0).context();
            assertTrue(ctx.jointKey().point().projectiveEquals(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(3))));
            if (thirdSlope.equals(L.subtract(BigInteger.valueOf(6)))) {
                assertTrue(ctx.verificationKey(1).isIdentity(), "Y_1 = O is valid and kept");
                assertEquals(BigInteger.ZERO, keys.get(0).secretScalar());
            } else {
                assertTrue(ctx.verificationKey(1).projectiveEquals(ctx.verificationKey(2)));
                assertTrue(ctx.verificationKey(2).projectiveEquals(ctx.verificationKey(3)));
            }
            ElGamalCiphertext c = ElGamal.encrypt(ctx, 1, 1, RNG);
            ElGamalHostApiTest.KnownSecretsDleqVerifier v = verifierFor(keys);
            List<VerifiedDecryptionShare> shares = new ArrayList<>();
            for (ThresholdKeyShare k : keys) {
                VerifiedDecryptionShare own = ElGamal.decryptionShare(k, c);
                shares.add(VerifiedDecryptionShare.verify(c, k.id(), own.share(), v));
            }
            if (thirdSlope.equals(L.subtract(BigInteger.valueOf(6)))) {
                assertTrue(shares.get(0).share().isIdentity(), "D_1 = O");
            }
            for (int[] s : subsets(3, 2)) {
                assertEquals(1, ElGamal.decrypt(c, List.of(shares.get(s[0] - 1), shares.get(s[1] - 1)), 1));
            }
        }
    }

    @Test
    @DisplayName("Negatives: too few, duplicate identifier, unqualified identifier, wrong ciphertext, invalid proof, inconsistent subset, single-key")
    void negatives() {
        DkgConfig config = DkgHarness.config(1, 3, "threshold-negatives", 1);
        // Dealer 3 is disqualified, so identifier 3 is outside QUAL.
        DkgHarness h = DkgHarness.random(config, (m, honest) ->
                m.kind() == DkgMessage.Kind.COMMITMENTS && m.sender() == 3 ? List.of() : honest).run();
        assertEquals(Set.of(3), h.aborted.keySet());
        ThresholdKeyShare k1 = h.participant(1).result();
        ThresholdKeyShare k2 = h.participant(2).result();
        ThresholdKeyContext ctx = k1.context();
        assertEquals(Set.of(1, 2), ctx.qual());
        ElGamalCiphertext c = ElGamal.encrypt(ctx, 1, 1, RNG);
        ElGamalHostApiTest.KnownSecretsDleqVerifier v = verifierFor(List.of(k1, k2));
        VerifiedDecryptionShare d1 = ElGamal.decryptionShare(k1, c);
        VerifiedDecryptionShare d2 = ElGamal.decryptionShare(k2, c);
        assertEquals(1, ElGamal.decrypt(c, List.of(d1, d2), 1));

        assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c, List.of(d1), 1), "fewer than t + 1");
        assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c, List.of(d1, d1), 1), "duplicate identifier");
        assertThrows(IllegalArgumentException.class,
                () -> VerifiedDecryptionShare.verify(c, 3, c.handle(), s -> true), "identifier outside QUAL");
        assertThrows(IllegalArgumentException.class,
                () -> VerifiedDecryptionShare.verify(c, 9, c.handle(), s -> true), "unknown identifier");
        ElGamalCiphertext other = ElGamal.encrypt(ctx, 0, 1, RNG);
        VerifiedDecryptionShare e2 = ElGamal.decryptionShare(k2, other);
        assertThrows(IllegalArgumentException.class, () -> ElGamal.decrypt(c, List.of(d1, e2), 1), "wrong ciphertext");
        assertThrows(IllegalArgumentException.class,
                () -> VerifiedDecryptionShare.verify(c, 2, d2.share().add(JubjubPoint.SUBGROUP_GENERATOR), v), "invalid proof");
        assertThrows(IllegalArgumentException.class,
                () -> ElGamal.decryptWithSecret(c, ElGamalSecretKey.of(BigInteger.ONE), 1), "no single-key path");

        // Cross-kind: n-of-n material against a threshold ciphertext, and the reverse.
        ElGamalSecretKey sk = ElGamalSecretKey.of(BigInteger.valueOf(5));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.decryptionShare(sk, c));
        assertThrows(IllegalArgumentException.class,
                () -> VerifiedDecryptionShare.verify(c, sk.publicKey(), c.handle(), s -> true));
        ElGamalCiphertext nOfN = ElGamal.encrypt(NOfNKeyContext.singleKey(sk), 1, 1, RNG);
        assertThrows(IllegalArgumentException.class, () -> ElGamal.decryptionShare(k1, nOfN));
        assertThrows(IllegalArgumentException.class, () -> VerifiedDecryptionShare.verify(nOfN, 1, nOfN.handle(), s -> true));
        assertThrows(IllegalArgumentException.class, () -> c.add(nOfN), "different contexts");
    }

    @Test
    @DisplayName("An inconsistent extra share (accepted by a lying verifier) is detected against the interpolation")
    void inconsistentSubset() {
        DkgConfig config = DkgHarness.config(1, 3, "inconsistent", 1);
        List<ThresholdKeyShare> keys = run(DkgHarness.random(config, DkgHarness.HONEST));
        ThresholdKeyContext ctx = keys.get(0).context();
        ElGamalCiphertext c = ElGamal.encrypt(ctx, 1, 1, RNG);
        VerifiedDecryptionShare d1 = ElGamal.decryptionShare(keys.get(0), c);
        VerifiedDecryptionShare d2 = ElGamal.decryptionShare(keys.get(1), c);
        VerifiedDecryptionShare lie = VerifiedDecryptionShare.verify(c, 3,
                ElGamal.decryptionShare(keys.get(2), c).share().add(JubjubPoint.SUBGROUP_GENERATOR), s -> true);
        assertThrows(IllegalStateException.class, () -> ElGamal.decrypt(c, List.of(d1, d2, lie), 1));
    }

    @Test
    @DisplayName("A share secret that does not match Y_j cannot produce a share (I15 specialised)")
    void secretMustMatch() {
        DkgConfig config = DkgHarness.config(1, 3, "secret-match", 1);
        List<ThresholdKeyShare> keys = run(DkgHarness.random(config, DkgHarness.HONEST));
        ThresholdKeyContext ctx = keys.get(0).context();
        ElGamalCiphertext c = ElGamal.encrypt(ctx, 1, 1, RNG);
        ThresholdKeyShare forged = new ThresholdKeyShare(ctx, 1, keys.get(1).secretScalar());
        assertThrows(IllegalArgumentException.class, () -> ElGamal.decryptionShare(forged, c));
    }
}
