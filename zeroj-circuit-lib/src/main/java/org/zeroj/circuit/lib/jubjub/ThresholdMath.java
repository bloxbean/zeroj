package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * Scalar and point helpers of {@code elgamal-jubjub-threshold-v1} (spec §3, §5, §9): polynomial
 * evaluation and interpolation mod {@code l}, Lagrange coefficients, and evaluation "in the
 * exponent" of a commitment vector.
 *
 * <p>The scalar helpers run variable-time {@link BigInteger} arithmetic. When their inputs are
 * secret (dealing, a participant's own shares), they are compatibility/offline class
 * (ADR-0039 §3.1). {@link #evaluateInExponent} is for public commitment vectors only.
 */
final class ThresholdMath {

    private ThresholdMath() {}

    /** {@code Σ_k c_k·x^k mod l}, by Horner's rule. */
    static BigInteger evaluate(BigInteger[] coefficients, long x) {
        BigInteger point = BigInteger.valueOf(x);
        BigInteger acc = BigInteger.ZERO;
        for (int k = coefficients.length - 1; k >= 0; k--) {
            acc = acc.multiply(point).add(coefficients[k]).mod(SUBGROUP_ORDER);
        }
        return acc;
    }

    /**
     * {@code Σ_k [x^k]·C_k} for <b>public</b> points, by Horner's rule with the small multiplier
     * {@code x}: about {@code t} cheap multiplications instead of {@code t + 1} full ones.
     */
    static JubjubPoint evaluateInExponent(List<JubjubPoint> commitments, long x) {
        return evaluateInExponentFast(commitments, x).toJubjubPoint();
    }

    static FastJubjubPoint evaluateInExponentFast(List<JubjubPoint> commitments, long x) {
        FastJubjubPoint acc = FastJubjubPoint.IDENTITY;
        for (int k = commitments.size() - 1; k >= 0; k--) {
            acc = acc.scalarMulPublic(x).add(FastJubjubPoint.of(commitments.get(k)));
        }
        return acc;
    }

    /**
     * Lagrange coefficients at {@code e} for the identifiers {@code ids}:
     * {@code L_j(e) = Π_{m ≠ j} (e − m)·(j − m)⁻¹ mod l}. At {@code e = 0} these are the
     * coefficients {@code λ_j} that recombine a secret.
     *
     * @throws IllegalArgumentException if the identifiers are not distinct and non-zero
     */
    static BigInteger[] lagrangeAt(int[] ids, long e) {
        requireDistinctPositive(ids);
        BigInteger at = BigInteger.valueOf(e);
        BigInteger[] out = new BigInteger[ids.length];
        for (int a = 0; a < ids.length; a++) {
            BigInteger j = BigInteger.valueOf(ids[a]);
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;
            for (int b = 0; b < ids.length; b++) {
                if (a == b) continue;
                BigInteger m = BigInteger.valueOf(ids[b]);
                numerator = numerator.multiply(at.subtract(m)).mod(SUBGROUP_ORDER);
                denominator = denominator.multiply(j.subtract(m)).mod(SUBGROUP_ORDER);
            }
            out[a] = numerator.multiply(denominator.modInverse(SUBGROUP_ORDER)).mod(SUBGROUP_ORDER);
        }
        return out;
    }

    /**
     * The coefficients {@code c_0 … c_{d}} of the unique polynomial of degree at most
     * {@code d = xs.length − 1} through the points {@code (xs[i], ys[i])}, mod {@code l}.
     */
    static BigInteger[] interpolate(int[] xs, BigInteger[] ys) {
        requireDistinctPositive(xs);
        if (ys.length != xs.length) {
            throw new IllegalArgumentException("interpolation needs one value per point");
        }
        int size = xs.length;
        BigInteger[] result = new BigInteger[size];
        Arrays.fill(result, BigInteger.ZERO);
        for (int a = 0; a < size; a++) {
            // Basis polynomial Π_{b≠a} (z − x_b)/(x_a − x_b), expanded into coefficients.
            BigInteger[] basis = new BigInteger[size];
            Arrays.fill(basis, BigInteger.ZERO);
            basis[0] = BigInteger.ONE;
            int degree = 0;
            BigInteger denominator = BigInteger.ONE;
            BigInteger xa = BigInteger.valueOf(xs[a]);
            for (int b = 0; b < size; b++) {
                if (a == b) continue;
                BigInteger xb = BigInteger.valueOf(xs[b]);
                for (int k = degree + 1; k >= 1; k--) {
                    basis[k] = basis[k - 1].subtract(basis[k].multiply(xb)).mod(SUBGROUP_ORDER);
                }
                basis[0] = basis[0].multiply(xb).negate().mod(SUBGROUP_ORDER);
                degree++;
                denominator = denominator.multiply(xa.subtract(xb)).mod(SUBGROUP_ORDER);
            }
            BigInteger scale = ys[a].multiply(denominator.modInverse(SUBGROUP_ORDER)).mod(SUBGROUP_ORDER);
            for (int k = 0; k < size; k++) {
                result[k] = result[k].add(basis[k].multiply(scale)).mod(SUBGROUP_ORDER);
            }
        }
        return result;
    }

    private static void requireDistinctPositive(int[] ids) {
        Objects.requireNonNull(ids, "ids");
        int[] sorted = ids.clone();
        Arrays.sort(sorted);
        for (int i = 0; i < sorted.length; i++) {
            if (sorted[i] <= 0 || (i > 0 && sorted[i] == sorted[i - 1])) {
                throw new IllegalArgumentException("identifiers must be distinct and positive");
            }
        }
    }
}
