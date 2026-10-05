package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.SortedMap;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0053 M1: the VSS primitives and Lagrange arithmetic. Property tests: any {@code t + 1}
 * shares reconstruct the same value, and {@code t} shares leave every secret equally possible
 * (the simulation check of [GJKR07] §2.2, on small parameters). Also the F7 fixtures
 * ({@code F(z) = 3 − 3z} and {@code F(z) = 3}) from every subset.
 */
class ThresholdVssTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final SecureRandom RNG = new SecureRandom();

    private static BigInteger[] randomPoly(Random rnd, int t) {
        BigInteger[] c = new BigInteger[t + 1];
        for (int k = 0; k <= t; k++) c[k] = new BigInteger(260, rnd).mod(L);
        return c;
    }

    private static List<int[]> subsets(int n, int size) {
        List<int[]> out = new ArrayList<>();
        int[] current = new int[size];
        subsets(1, n, 0, current, out);
        return out;
    }

    private static void subsets(int start, int n, int depth, int[] current, List<int[]> out) {
        if (depth == current.length) {
            out.add(current.clone());
            return;
        }
        for (int i = start; i <= n; i++) {
            current[depth] = i;
            subsets(i + 1, n, depth + 1, current, out);
        }
    }

    @Test
    @DisplayName("Interpolation inverts evaluation; Lagrange at 0 recombines from every (t + 1)-subset")
    void lagrangeProperties() {
        Random rnd = new Random(63);
        for (int[] tn : new int[][]{{1, 3}, {2, 5}, {3, 7}}) {
            int t = tn[0];
            int n = tn[1];
            BigInteger[] f = randomPoly(rnd, t);
            BigInteger[] shares = new BigInteger[n + 1];
            for (int j = 1; j <= n; j++) shares[j] = ThresholdMath.evaluate(f, j);
            for (int[] s : subsets(n, t + 1)) {
                BigInteger[] lambda = ThresholdMath.lagrangeAt(s, 0);
                BigInteger secret = BigInteger.ZERO;
                BigInteger[] ys = new BigInteger[s.length];
                for (int i = 0; i < s.length; i++) {
                    secret = secret.add(lambda[i].multiply(shares[s[i]])).mod(L);
                    ys[i] = shares[s[i]];
                }
                assertEquals(f[0], secret, "subset " + Arrays.toString(s));
                assertArrayEquals(f, ThresholdMath.interpolate(s, ys));
                // Interpolating at another identifier reproduces its share.
                for (int e = 1; e <= n; e++) {
                    BigInteger[] le = ThresholdMath.lagrangeAt(s, e);
                    BigInteger at = BigInteger.ZERO;
                    for (int i = 0; i < s.length; i++) at = at.add(le[i].multiply(shares[s[i]])).mod(L);
                    assertEquals(shares[e], at);
                }
            }
        }
        assertThrows(IllegalArgumentException.class, () -> ThresholdMath.lagrangeAt(new int[]{1, 1}, 0));
        assertThrows(IllegalArgumentException.class, () -> ThresholdMath.lagrangeAt(new int[]{0, 2}, 0));
    }

    @Test
    @DisplayName("t shares determine nothing: for every candidate secret there is exactly one consistent polynomial")
    void tSharesHideTheSecret() {
        // Small-parameter simulation (t = 2): fix t shares, then for each of several candidate
        // secrets the unique degree-t polynomial through (0, candidate) and the t shares exists
        // and reproduces those shares. A view of t shares is therefore identical for all secrets.
        Random rnd = new Random(64);
        BigInteger[] f = randomPoly(rnd, 2);
        int[] observed = {2, 5};
        BigInteger[] seen = {ThresholdMath.evaluate(f, 2), ThresholdMath.evaluate(f, 5)};
        for (BigInteger candidate : List.of(BigInteger.ZERO, BigInteger.ONE, f[0], L.subtract(BigInteger.ONE))) {
            // Interpolate through x = 7 chosen so the point (7, y) makes f(0) = candidate.
            BigInteger[] l0 = ThresholdMath.lagrangeAt(new int[]{2, 5, 7}, 0);
            BigInteger partial = l0[0].multiply(seen[0]).add(l0[1].multiply(seen[1])).mod(L);
            BigInteger y7 = candidate.subtract(partial).multiply(l0[2].modInverse(L)).mod(L);
            BigInteger[] g = ThresholdMath.interpolate(new int[]{2, 5, 7}, new BigInteger[]{seen[0], seen[1], y7});
            assertEquals(candidate, g[0]);
            for (int i = 0; i < observed.length; i++) {
                assertEquals(seen[i], ThresholdMath.evaluate(g, observed[i]));
            }
        }
    }

    @Test
    @DisplayName("Dealt shares pass (4) and (5) on both paths; a tampered share or blinding fails")
    void shareChecks() {
        ThresholdVss.Dealing d = ThresholdVss.deal(2, RNG);
        for (int j = 1; j <= 5; j++) {
            BigInteger s = d.share(j);
            BigInteger sp = d.sharePrime(j);
            assertTrue(ThresholdVss.checkPedersenPrivate(d.commitments(), j, s, sp));
            assertTrue(ThresholdVss.checkPedersenPublic(d.commitments(), j, s, sp));
            assertTrue(ThresholdVss.checkFeldmanPrivate(d.extraction(), j, s));
            assertTrue(ThresholdVss.checkFeldmanPublic(d.extraction(), j, s));
            BigInteger bad = s.add(BigInteger.ONE).mod(L);
            assertFalse(ThresholdVss.checkPedersenPrivate(d.commitments(), j, bad, sp));
            assertFalse(ThresholdVss.checkPedersenPublic(d.commitments(), j, s, sp.add(BigInteger.ONE).mod(L)));
            assertFalse(ThresholdVss.checkFeldmanPublic(d.extraction(), j, bad));
            assertFalse(ThresholdVss.checkPedersenPublic(d.commitments(), j % 5 + 1, s, sp), "another holder's index");
        }
        assertThrows(IllegalArgumentException.class,
                () -> ThresholdVss.checkPedersenPublic(d.commitments(), 1, L, BigInteger.ZERO), "non-canonical scalar");
    }

    @Test
    @DisplayName("Reconstruction: any t + 1 valid pairs recover the dealer; too few or inconsistent pairs abort")
    void reconstruction() {
        int t = 2;
        ThresholdVss.Dealing d = ThresholdVss.deal(t, RNG);
        for (int[] s : subsets(5, t + 1)) {
            SortedMap<Integer, BigInteger[]> pairs = new TreeMap<>();
            for (int j : s) pairs.put(j, new BigInteger[]{d.share(j), d.sharePrime(j)});
            ThresholdVss.Reconstructed r = ThresholdVss.reconstruct(d.commitments(), t, pairs);
            for (int k = 0; k <= t; k++) {
                assertTrue(r.extraction().get(k).projectiveEquals(d.extraction().get(k)));
            }
        }
        SortedMap<Integer, BigInteger[]> few = new TreeMap<>();
        few.put(1, new BigInteger[]{d.share(1), d.sharePrime(1)});
        few.put(2, new BigInteger[]{d.share(2), d.sharePrime(2)});
        var tooFew = assertThrows(FaultAssumptionViolatedException.class,
                () -> ThresholdVss.reconstruct(d.commitments(), t, few));
        assertEquals(FaultAssumptionViolatedException.Reason.TOO_FEW_RECONSTRUCTION_PAIRS, tooFew.reason());

        SortedMap<Integer, BigInteger[]> inconsistent = new TreeMap<>();
        for (int j = 1; j <= 4; j++) inconsistent.put(j, new BigInteger[]{d.share(j), d.sharePrime(j)});
        inconsistent.put(4, new BigInteger[]{d.share(4).add(BigInteger.ONE).mod(L), d.sharePrime(4)});
        var bad = assertThrows(FaultAssumptionViolatedException.class,
                () -> ThresholdVss.reconstruct(d.commitments(), t, inconsistent));
        assertEquals(FaultAssumptionViolatedException.Reason.INCONSISTENT_RECONSTRUCTION, bad.reason());

        // Pairs from another dealing do not reproduce these commitments.
        ThresholdVss.Dealing other = ThresholdVss.deal(t, RNG);
        SortedMap<Integer, BigInteger[]> foreign = new TreeMap<>();
        for (int j = 1; j <= 3; j++) foreign.put(j, new BigInteger[]{other.share(j), other.sharePrime(j)});
        var mismatch = assertThrows(FaultAssumptionViolatedException.class,
                () -> ThresholdVss.reconstruct(d.commitments(), t, foreign));
        assertEquals(FaultAssumptionViolatedException.Reason.INCONSISTENT_RECONSTRUCTION, mismatch.reason());
        assertTrue(mismatch.getMessage().contains("does not match its commitment"), mismatch.getMessage());
    }

    @Test
    @DisplayName("F7 fixtures: F(z) = 3 − 3z (x_1 = 0) and F(z) = 3 (equal shares) recombine from every subset")
    void f7Fixtures() {
        for (BigInteger[] slopes : List.of(
                new BigInteger[]{BigInteger.ONE, BigInteger.TWO, L.subtract(BigInteger.valueOf(6))},
                new BigInteger[]{BigInteger.ONE, BigInteger.TWO, L.subtract(BigInteger.valueOf(3))})) {
            List<ThresholdVss.Dealing> dealers = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                dealers.add(ThresholdVss.dealWithCoefficients(
                        new BigInteger[]{BigInteger.ONE, slopes[i]},
                        new BigInteger[]{ElGamal.sample(RNG), ElGamal.sample(RNG)}));
            }
            BigInteger[] x = new BigInteger[4];
            for (int j = 1; j <= 3; j++) {
                x[j] = BigInteger.ZERO;
                for (ThresholdVss.Dealing d : dealers) x[j] = x[j].add(d.share(j)).mod(L);
            }
            BigInteger slopeSum = slopes[0].add(slopes[1]).add(slopes[2]).mod(L);
            if (slopeSum.equals(L.subtract(BigInteger.valueOf(3)))) {
                assertEquals(BigInteger.ZERO, x[1], "F(1) = 3 − 3 = 0");
            } else {
                assertEquals(BigInteger.valueOf(3), x[1]);
                assertEquals(x[1], x[2]);
                assertEquals(x[2], x[3]);
            }
            for (int[] s : subsets(3, 2)) {
                BigInteger[] lambda = ThresholdMath.lagrangeAt(s, 0);
                BigInteger secret = lambda[0].multiply(x[s[0]]).add(lambda[1].multiply(x[s[1]])).mod(L);
                assertEquals(BigInteger.valueOf(3), secret);
            }
            // Zero slopes are legal: an extraction value may be the identity.
            ThresholdVss.Dealing flat = ThresholdVss.dealWithCoefficients(
                    new BigInteger[]{BigInteger.ONE, BigInteger.ZERO}, new BigInteger[]{BigInteger.TEN, BigInteger.ONE});
            assertTrue(flat.extraction().get(1).isIdentity());
            assertTrue(ThresholdVss.checkFeldmanPublic(flat.extraction(), 3, BigInteger.ONE));
        }
    }
}
