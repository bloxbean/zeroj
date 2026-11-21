package org.zeroj.examples.dsl.common;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <b>LEGACY TEST REGRESSION FIXTURE ONLY — INSECURE / INVERTIBLE — DO NOT USE IN REAL CIRCUITS.</b>
 *
 * <p>Host-side mirror of the deprecated {@code MiMC.hash()} / {@code SignalMiMC.hash()} gadgets,
 * retained solely so legacy BN254 regression tests can compute expected outputs for the deprecated
 * invertible keyed bijection (91 rounds of {@code (state + rc_i + key)^7}, returning
 * {@code state + key}, with SHA-256 round constants and no Miyaguchi–Preneel feed-forward).</p>
 *
 * <p>Do not copy this helper into application code; use
 * {@code PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, left, right)} instead.</p>
 */
@Deprecated(forRemoval = true)
public final class MiMCHash {

    private MiMCHash() {}

    private static final int NUM_ROUNDS = 91;

    /**
     * Compute MiMC-7 hash of two field elements.
     *
     * @param left  first input
     * @param right second input (used as key in Feistel construction)
     * @param prime the BN254 field prime when matching the in-circuit MiMC gadget
     * @return hash output in the field
     */
    public static BigInteger hash(BigInteger left, BigInteger right, BigInteger prime) {
        var state = left.mod(prime);
        var key = right.mod(prime);

        for (int i = 0; i < NUM_ROUNDS; i++) {
            var rc = roundConstant(i);
            // t = state + round_constant + key
            var t = state.add(rc).add(key).mod(prime);
            // t^7 = t * t * t * t * t * t * t (optimized)
            var t2 = t.multiply(t).mod(prime);
            var t4 = t2.multiply(t2).mod(prime);
            var t6 = t4.multiply(t2).mod(prime);
            state = t6.multiply(t).mod(prime);
        }
        return state.add(key).mod(prime);
    }

    /**
     * MiMC round constant — matches the circuit library implementation.
     * Round 0 returns 0, subsequent rounds use SHA-256("mimc_round_N").
     */
    static BigInteger roundConstant(int round) {
        if (round == 0) return BigInteger.ZERO;
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            return new BigInteger(1, digest.digest(
                    ("mimc_round_" + round).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
