package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBN254T3;

/**
 * Poseidon hash function circuit — the standard ZK-friendly hash used in circom.
 *
 * <p>Structurally supports {@code t=3, α=5, RF=8, RP=57}. Round constants and
 * MDS matrix come from a {@link PoseidonParams} instance — pick the preset
 * matching the scalar field you will compile the R1CS for:
 * <ul>
 *   <li>{@link PoseidonParamsBN254T3#INSTANCE} — BN254, circomlib-compatible</li>
 *   <li>{@link com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3#INSTANCE}
 *       — BLS12-381, standards-compatible (paper spec)</li>
 * </ul>
 *
 * <p>The no-params overload defaults to {@link PoseidonParamsBN254T3#INSTANCE}
 * for back-compat with circuits that pre-date parameterization. Callers
 * targeting BLS12-381 <b>must</b> pass {@code PoseidonParamsBLS12_381T3.INSTANCE}
 * explicitly — the no-params default does not auto-select by compile curve
 * because the gadget is defined before the curve is known to the circuit.
 *
 * <p>The gadget calls {@link CircuitAPI#requireField} with the preset's field
 * during {@code define()}. If you subsequently compile or calculate a witness
 * for a curve whose field differs (e.g. {@code BLS12_381_T3} params with
 * {@code CurveId.BN254}), {@link com.bloxbean.cardano.zeroj.circuit.CircuitBuilder}
 * throws at compile/witness time — this replaces what used to be a silent
 * non-canonical output.
 *
 * <p>Approximately 330 constraints for 2 inputs.
 *
 * <p>Test vectors for the BN254 default (from circomlibjs):
 * <ul>
 *   <li>Poseidon(0, 0) = 14744269619966411208579211824598458697587494354926760081771325075741142829156</li>
 *   <li>Poseidon(1, 2) = 7853200120776062878684798364095072458815029376092732009249414926327459813530</li>
 *   <li>Poseidon(123, 456) = 19620391833206800292073497099357851348339828238212863168390691880932172496143</li>
 * </ul>
 */
public final class Poseidon {

    private Poseidon() {}

    /**
     * Poseidon hash of two field elements under the given {@link PoseidonParams}.
     * The params must have {@code t=3} and {@code alpha=5}; other shapes are
     * not yet supported by this gadget (use a different gadget for wider
     * states or different S-boxes).
     */
    public static Variable hash(CircuitAPI api, PoseidonParams params, Variable input0, Variable input1) {
        requireT3Alpha5(params);
        api.requireField(params.field());
        int t = params.t();
        int rf = params.rf();
        int rp = params.rp();
        int nRounds = rf + rp;

        Variable s0 = api.constant(0);
        Variable s1 = input0;
        Variable s2 = input1;

        for (int r = 0; r < nRounds; r++) {
            // AddRoundConstants
            s0 = api.add(s0, api.constant(params.cAt(r, 0)));
            s1 = api.add(s1, api.constant(params.cAt(r, 1)));
            s2 = api.add(s2, api.constant(params.cAt(r, 2)));

            // S-box (x^5)
            if (r < rf / 2 || r >= rf / 2 + rp) {
                s0 = sbox(api, s0);
                s1 = sbox(api, s1);
                s2 = sbox(api, s2);
            } else {
                s0 = sbox(api, s0);
            }

            // MDS matrix multiplication (3x3)
            Variable t0 = api.add(api.add(
                    api.mul(s0, api.constant(params.mAt(0, 0))),
                    api.mul(s1, api.constant(params.mAt(0, 1)))),
                    api.mul(s2, api.constant(params.mAt(0, 2))));
            Variable t1 = api.add(api.add(
                    api.mul(s0, api.constant(params.mAt(1, 0))),
                    api.mul(s1, api.constant(params.mAt(1, 1)))),
                    api.mul(s2, api.constant(params.mAt(1, 2))));
            Variable t2 = api.add(api.add(
                    api.mul(s0, api.constant(params.mAt(2, 0))),
                    api.mul(s1, api.constant(params.mAt(2, 1)))),
                    api.mul(s2, api.constant(params.mAt(2, 2))));
            s0 = t0;
            s1 = t1;
            s2 = t2;
        }

        return s0;
    }

    /** Signal-API variant of {@link #hash(CircuitAPI, PoseidonParams, Variable, Variable)}. */
    public static Signal hash(SignalBuilder c, PoseidonParams params, Signal input0, Signal input1) {
        Variable result = hash(c.api(), params, input0.variable(), input1.variable());
        return c.wrap(result);
    }

    /**
     * Poseidon hash using the back-compat default ({@link PoseidonParamsBN254T3#INSTANCE}).
     * Prefer the explicit-params overload when targeting BLS12-381 or when
     * interop with external Poseidon implementations matters.
     */
    public static Variable hash(CircuitAPI api, Variable input0, Variable input1) {
        return hash(api, PoseidonParamsBN254T3.INSTANCE, input0, input1);
    }

    /** Signal-API variant of {@link #hash(CircuitAPI, Variable, Variable)}. */
    public static Signal hash(SignalBuilder c, Signal input0, Signal input1) {
        return hash(c, PoseidonParamsBN254T3.INSTANCE, input0, input1);
    }

    /**
     * S-box: x^5 = (x^2)^2 * x. Costs 2 multiplication constraints.
     */
    private static Variable sbox(CircuitAPI api, Variable x) {
        Variable x2 = api.mul(x, x);
        Variable x4 = api.mul(x2, x2);
        return api.mul(x4, x);
    }

    private static void requireT3Alpha5(PoseidonParams params) {
        if (params.t() != 3 || params.alpha() != 5) {
            throw new IllegalArgumentException(
                    "Poseidon gadget supports only t=3, alpha=5 (got t=" + params.t()
                            + ", alpha=" + params.alpha() + ")");
        }
    }
}
