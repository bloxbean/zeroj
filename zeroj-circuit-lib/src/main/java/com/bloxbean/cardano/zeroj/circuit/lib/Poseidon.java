package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.math.BigInteger;

/**
 * Poseidon hash function circuit — the standard ZK-friendly hash used in circom.
 *
 * <p>Parameters for BN254 (matching circomlib exactly):
 * <ul>
 *   <li>t = 3 (width: 2 inputs + 1 capacity)</li>
 *   <li>Rf = 8 full rounds (4 at start, 4 at end)</li>
 *   <li>Rp = 57 partial rounds</li>
 *   <li>S-box: x^5</li>
 *   <li>Constants from iden3/circomlibjs poseidon_constants.json</li>
 * </ul>
 *
 * <p>Approximately 330 constraints for 2 inputs.</p>
 *
 * <p>Test vectors (verified against circomlibjs):
 * <ul>
 *   <li>Poseidon(0, 0) = 14744269619966411208579211824598458697587494354926760081771325075741142829156</li>
 *   <li>Poseidon(1, 2) = 7853200120776062878684798364095072458815029376092732009249414926327459813530</li>
 *   <li>Poseidon(123, 456) = 19620391833206800292073497099357851348339828238212863168390691880932172496143</li>
 * </ul>
 */
public final class Poseidon {

    private Poseidon() {}

    private static final int T = 3;      // width
    private static final int RF = 8;     // full rounds
    private static final int RP = 57;    // partial rounds
    private static final int N_ROUNDS = RF + RP; // 65

    /**
     * Poseidon hash of two field elements (CircuitAPI style).
     */
    public static Variable hash(CircuitAPI api, Variable input0, Variable input1) {
        // Initial state: [0, input0, input1]
        Variable s0 = api.constant(0);
        Variable s1 = input0;
        Variable s2 = input1;

        for (int r = 0; r < N_ROUNDS; r++) {
            // AddRoundConstants
            s0 = api.add(s0, api.constant(PoseidonConstants.C[r * 3]));
            s1 = api.add(s1, api.constant(PoseidonConstants.C[r * 3 + 1]));
            s2 = api.add(s2, api.constant(PoseidonConstants.C[r * 3 + 2]));

            // S-box (x^5)
            if (r < RF / 2 || r >= RF / 2 + RP) {
                // Full round: apply S-box to all state elements
                s0 = sbox(api, s0);
                s1 = sbox(api, s1);
                s2 = sbox(api, s2);
            } else {
                // Partial round: apply S-box only to s0
                s0 = sbox(api, s0);
            }

            // MDS matrix multiplication
            Variable t0 = api.add(api.add(
                    api.mul(s0, api.constant(PoseidonConstants.M[0])),
                    api.mul(s1, api.constant(PoseidonConstants.M[1]))),
                    api.mul(s2, api.constant(PoseidonConstants.M[2])));
            Variable t1 = api.add(api.add(
                    api.mul(s0, api.constant(PoseidonConstants.M[3])),
                    api.mul(s1, api.constant(PoseidonConstants.M[4]))),
                    api.mul(s2, api.constant(PoseidonConstants.M[5])));
            Variable t2 = api.add(api.add(
                    api.mul(s0, api.constant(PoseidonConstants.M[6])),
                    api.mul(s1, api.constant(PoseidonConstants.M[7]))),
                    api.mul(s2, api.constant(PoseidonConstants.M[8])));
            s0 = t0;
            s1 = t1;
            s2 = t2;
        }

        return s0; // output is state[0]
    }

    /**
     * Poseidon hash using Signal API.
     */
    public static Signal hash(SignalBuilder c, Signal input0, Signal input1) {
        Variable result = hash(c.api(), input0.variable(), input1.variable());
        return c.wrap(result);
    }

    /**
     * S-box: x^5 = (x^2)^2 * x. Costs 2 multiplication constraints.
     */
    private static Variable sbox(CircuitAPI api, Variable x) {
        Variable x2 = api.mul(x, x);
        Variable x4 = api.mul(x2, x2);
        return api.mul(x4, x);
    }
}
