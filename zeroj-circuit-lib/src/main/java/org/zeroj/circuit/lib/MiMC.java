package org.zeroj.circuit.lib;

import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <b>DEPRECATED FOR REMOVAL — INSECURE / INVERTIBLE — DO NOT USE.</b>
 *
 * <p>{@link #hash(CircuitAPI, Variable, Variable)} computes a keyed bijection {@code E_right(left)}
 * (91 rounds of {@code (state + rc_i + key)^7}, returning {@code state + key}) with <b>no
 * Miyaguchi–Preneel feed-forward</b>. Given any target output and chosen {@code right}, an attacker
 * can invert all 91 rounds in milliseconds to compute a matching {@code left}, making preimages
 * and Merkle membership proofs trivially forgeable. Round constants are derived with SHA-256
 * ({@code "mimc_round_" + round}), not Keccak-256, and this gadget is not compatible with
 * circomlib.</p>
 *
 * <p>Use {@link Poseidon#hash(CircuitAPI, PoseidonParams, Variable, Variable)} with
 * {@link PoseidonParamsBLS12_381T3#INSTANCE} on BLS12-381 instead.</p>
 *
 * @deprecated Scheduled for removal because this construction is an invertible keyed bijection
 *             rather than a one-way hash function. Use
 *             {@link Poseidon#hash(CircuitAPI, PoseidonParams, Variable, Variable)} with
 *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
 */
@Deprecated(forRemoval = true)
public final class MiMC {

    private MiMC() {}

    private static final int NUM_ROUNDS = 91;

    /**
     * <b>INSECURE:</b> Computes an invertible keyed bijection {@code E_right(left)} on BN254
     * without feed-forward. Do not use for commitments, preimage proofs, or Merkle trees.
     *
     * @param api   circuit API (BN254 only)
     * @param left  first input
     * @param right second input (used as key)
     * @return bijection output (trivially invertible in {@code left})
     * @deprecated Scheduled for removal. Use
     *             {@link Poseidon#hash(CircuitAPI, PoseidonParams, Variable, Variable)} with
     *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
     */
    @Deprecated(forRemoval = true)
    public static Variable hash(CircuitAPI api, Variable left, Variable right) {
        api.requireField(FieldConfig.BN254);

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
     * MiMC round constants — SHA-256 digest of {@code "mimc_round_" + round} (not Keccak-256, not
     * circomlib-compatible).
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
