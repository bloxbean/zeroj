package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MiMC hash function circuit (MiMC-7 variant).
 *
 * <p>MiMC uses x^7 S-box with 91 rounds for BN254.
 * Each round: state = (state + round_constant + key)^7.
 * Approximately 273 constraints for one hash.</p>
 */
public final class MiMC {

    private MiMC() {}

    private static final int NUM_ROUNDS = 91;

    /**
     * MiMC hash of two field elements using MiMC-7 Feistel.
     *
     * @param api   circuit API
     * @param left  first input
     * @param right second input (used as key)
     * @return hash output
     */
    public static Variable hash(CircuitAPI api, Variable left, Variable right) {
        // MiMC-7 with key = right
        var state = left;
        var key = right;

        for (int i = 0; i < NUM_ROUNDS; i++) {
            // t = state + round_constant + key
            var rc = api.constant(roundConstant(i));
            var t = api.add(api.add(state, rc), key);

            // t^7 = t * t * t * t * t * t * t
            // Optimized: t^2 = t*t, t^4 = t^2*t^2, t^6 = t^4*t^2, t^7 = t^6*t
            var t2 = api.mul(t, t);      // 1 constraint
            var t4 = api.mul(t2, t2);    // 1 constraint
            var t6 = api.mul(t4, t2);    // 1 constraint
            state = api.mul(t6, t);       // 1 constraint  (4 constraints per round × 91 = 364)
        }

        // Final: hash = state + key
        return api.add(state, key);
    }

    /**
     * MiMC round constants — keccak256 hash of sequential strings.
     */
    static BigInteger roundConstant(int round) {
        if (round == 0) return BigInteger.ZERO; // first round constant is 0
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            return new BigInteger(1, digest.digest(
                    ("mimc_round_" + round).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
