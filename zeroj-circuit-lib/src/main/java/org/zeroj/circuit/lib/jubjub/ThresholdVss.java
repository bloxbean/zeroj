package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * Pedersen-VSS and Feldman-VSS of {@code elgamal-jubjub-threshold-v1} §3 and §5 ([GJKR07]
 * Fig. 2): dealing, the share checks (4) and (5), and reconstruction from checked pairs.
 *
 * <p><b>Secret and public paths.</b> Dealing and the checks of a pair a participant received
 * privately multiply secrets, so their left-hand sides use the blinded best-effort schedule
 * (compatibility/offline class, ADR-0039 §3.1). Pairs that were broadcast (complaint answers,
 * extraction complaints, reconstruction pairs) are public and use the fast path. Right-hand
 * sides depend only on broadcast commitments and are always public.
 */
final class ThresholdVss {

    private ThresholdVss() {}

    /** A dealer's polynomials, commitments and extraction values. The coefficients are secret. */
    static final class Dealing {
        private final BigInteger[] a;
        private final BigInteger[] b;
        private final List<JubjubPoint> commitments;
        private final List<JubjubPoint> extraction;

        private Dealing(BigInteger[] a, BigInteger[] b, List<JubjubPoint> commitments, List<JubjubPoint> extraction) {
            this.a = a;
            this.b = b;
            this.commitments = commitments;
            this.extraction = extraction;
        }

        /** {@code C_ik = [a_ik]·G + [b_ik]·H}. */
        List<JubjubPoint> commitments() {
            return commitments;
        }

        /** {@code A_ik = [a_ik]·G}. */
        List<JubjubPoint> extraction() {
            return extraction;
        }

        /** {@code s_ij = f_i(j)}. */
        BigInteger share(int j) {
            return ThresholdMath.evaluate(a, j);
        }

        /** {@code s'_ij = f'_i(j)}. */
        BigInteger sharePrime(int j) {
            return ThresholdMath.evaluate(b, j);
        }

        int degree() {
            return a.length - 1;
        }
    }

    /** Samples a dealing of degree {@code t} (spec §3: 64 bytes reduced mod {@code l} per coefficient). */
    static Dealing deal(int t, SecureRandom random) {
        Objects.requireNonNull(random, "random");
        BigInteger[] a = new BigInteger[t + 1];
        BigInteger[] b = new BigInteger[t + 1];
        for (int k = 0; k <= t; k++) {
            a[k] = ElGamal.sample(random);
            b[k] = ElGamal.sample(random);
        }
        return dealWithCoefficients(a, b);
    }

    /** A dealing from fixed coefficients. Package-private: test fixtures and vectors only. */
    static Dealing dealWithCoefficients(BigInteger[] a, BigInteger[] b) {
        if (a.length == 0 || a.length != b.length) {
            throw new IllegalArgumentException("coefficient vectors must be non-empty and equal in length");
        }
        BigInteger[] ac = new BigInteger[a.length];
        BigInteger[] bc = new BigInteger[b.length];
        List<JubjubPoint> commitments = new ArrayList<>(a.length);
        List<JubjubPoint> extraction = new ArrayList<>(a.length);
        for (int k = 0; k < a.length; k++) {
            ac[k] = canonical(a[k]);
            bc[k] = canonical(b[k]);
            JubjubPoint aG = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(ac[k]).normalized();
            JubjubPoint bH = PedersenCommitment.H.scalarMulSecretBlindedBestEffort(bc[k]);
            extraction.add(aG);
            commitments.add(aG.add(bH).normalized());
        }
        return new Dealing(ac, bc, List.copyOf(commitments), List.copyOf(extraction));
    }

    /** Equation (4) for a pair received privately: secret left-hand side. */
    static boolean checkPedersenPrivate(List<JubjubPoint> commitments, int j, BigInteger s, BigInteger sp) {
        JubjubPoint left = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(canonical(s))
                .add(PedersenCommitment.H.scalarMulSecretBlindedBestEffort(canonical(sp)));
        return FastJubjubPoint.of(left).projectiveEquals(ThresholdMath.evaluateInExponentFast(commitments, j));
    }

    /** Equation (4) for a broadcast pair: public left-hand side. */
    static boolean checkPedersenPublic(List<JubjubPoint> commitments, int j, BigInteger s, BigInteger sp) {
        FastJubjubPoint left = FastJubjubPoint.GENERATOR.scalarMulPublic(canonical(s))
                .add(FastJubjubPoint.of(PedersenCommitment.H).scalarMulPublic(canonical(sp)));
        return left.projectiveEquals(ThresholdMath.evaluateInExponentFast(commitments, j));
    }

    /** Equation (5) for a pair received privately: secret left-hand side. */
    static boolean checkFeldmanPrivate(List<JubjubPoint> extraction, int j, BigInteger s) {
        JubjubPoint left = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(canonical(s));
        return FastJubjubPoint.of(left).projectiveEquals(ThresholdMath.evaluateInExponentFast(extraction, j));
    }

    /** Equation (5) for a broadcast pair: public left-hand side. */
    static boolean checkFeldmanPublic(List<JubjubPoint> extraction, int j, BigInteger s) {
        return FastJubjubPoint.GENERATOR.scalarMulPublic(canonical(s))
                .projectiveEquals(ThresholdMath.evaluateInExponentFast(extraction, j));
    }

    /** The result of reconstructing a dealer: its coefficients and recomputed extraction values. */
    record Reconstructed(BigInteger[] a, BigInteger[] b, List<JubjubPoint> extraction) {}

    /**
     * Reconstructs a marked dealer from broadcast pairs that satisfy (4) (spec §5, R6): the
     * {@code t + 1} pairs with the lowest holders define {@code f_i} and {@code f'_i}. Every other
     * valid pair must lie on them, and the interpolated coefficients must reproduce the
     * commitments.
     *
     * @param validPairs holder → {@code (s, s')}, already checked against (4)
     * @throws FaultAssumptionViolatedException on fewer than {@code t + 1} pairs (A3) or any
     *         inconsistency (A4)
     */
    static Reconstructed reconstruct(List<JubjubPoint> commitments, int t, SortedMap<Integer, BigInteger[]> validPairs) {
        if (validPairs.size() < t + 1) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.TOO_FEW_RECONSTRUCTION_PAIRS,
                    validPairs.size() + " valid pairs, " + (t + 1) + " needed");
        }
        int[] xs = new int[t + 1];
        BigInteger[] ys = new BigInteger[t + 1];
        BigInteger[] yps = new BigInteger[t + 1];
        int index = 0;
        for (Map.Entry<Integer, BigInteger[]> e : validPairs.entrySet()) {
            if (index == t + 1) break;
            xs[index] = e.getKey();
            ys[index] = e.getValue()[0];
            yps[index] = e.getValue()[1];
            index++;
        }
        BigInteger[] a = ThresholdMath.interpolate(xs, ys);
        BigInteger[] b = ThresholdMath.interpolate(xs, yps);
        for (Map.Entry<Integer, BigInteger[]> e : validPairs.entrySet()) {
            if (!ThresholdMath.evaluate(a, e.getKey()).equals(canonical(e.getValue()[0]))
                    || !ThresholdMath.evaluate(b, e.getKey()).equals(canonical(e.getValue()[1]))) {
                throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.INCONSISTENT_RECONSTRUCTION,
                        "pair of holder " + e.getKey() + " is not on the reconstructed polynomial");
            }
        }
        List<JubjubPoint> extraction = new ArrayList<>(t + 1);
        for (int k = 0; k <= t; k++) {
            FastJubjubPoint aG = FastJubjubPoint.GENERATOR.scalarMulPublic(a[k]);
            FastJubjubPoint bH = FastJubjubPoint.of(PedersenCommitment.H).scalarMulPublic(b[k]);
            if (!aG.add(bH).projectiveEquals(FastJubjubPoint.of(commitments.get(k)))) {
                throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.INCONSISTENT_RECONSTRUCTION,
                        "reconstructed coefficient " + k + " does not match its commitment");
            }
            extraction.add(aG.toJubjubPoint());
        }
        return new Reconstructed(a, b, List.copyOf(extraction));
    }

    private static BigInteger canonical(BigInteger x) {
        Objects.requireNonNull(x, "scalar");
        if (x.signum() < 0 || x.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("scalar must satisfy 0 <= x < l");
        }
        return x;
    }
}
