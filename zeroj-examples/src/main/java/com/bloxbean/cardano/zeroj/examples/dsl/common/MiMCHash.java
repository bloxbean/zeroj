package com.bloxbean.cardano.zeroj.examples.dsl.common;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Standalone MiMC-7 hash computation (outside ZK circuits).
 *
 * <p>Produces the same output as the circuit-based {@code SignalMiMC.hash()} / {@code MiMC.hash()},
 * allowing the prover to compute hash values before constructing the witness.</p>
 *
 * <p>MiMC-7 parameters: 91 rounds, S-box x^7, round constants = SHA-256("mimc_round_N").</p>
 */
public final class MiMCHash {

    private MiMCHash() {}

    private static final int NUM_ROUNDS = 91;

    /**
     * Compute MiMC-7 hash of two field elements.
     *
     * @param left  first input
     * @param right second input (used as key in Feistel construction)
     * @param prime the field prime (curve-dependent)
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
