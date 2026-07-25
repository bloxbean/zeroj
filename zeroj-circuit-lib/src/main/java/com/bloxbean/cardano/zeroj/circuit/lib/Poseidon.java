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
     * Poseidon permutation over a state of arbitrary width {@code t}, with the state given
     * and returned explicitly.
     *
     * <p>This is the general form of the {@code t=3} hash above: same round structure
     * (RF/2 full rounds, RP partial rounds, RF/2 full rounds), same {@code x^alpha} S-box,
     * same MDS multiplication — just not specialised to a three-cell state. It exists so that
     * a sponge with rate {@code t-1} can absorb more than two inputs in a single permutation.
     *
     * <p>The caller owns the sponge convention: by ZeroJ's convention {@code state[0]} is the
     * capacity cell (initialised to zero, or to a domain tag) and {@code state[1..t-1]} are
     * rate cells holding the inputs; the output is {@code state[0]} after permuting.
     *
     * <p>Cost note: the MDS step is {@code t^2} constant multiplications per round, so cost
     * grows quadratically in {@code t} while capacity grows linearly. A wider permutation is
     * not automatically cheaper than folding a narrow one — measure before choosing.
     *
     * @param state input state of length {@code params.t()}; not modified
     * @return the permuted state, a fresh array
     */
    public static Variable[] permute(CircuitAPI api, PoseidonParams params, Variable[] state) {
        if (params.alpha() != 5) {
            throw new IllegalArgumentException(
                    "Poseidon gadget supports only alpha=5 (got " + params.alpha() + ")");
        }
        int t = params.t();
        if (state == null || state.length != t) {
            throw new IllegalArgumentException(
                    "state length must equal t=" + t + ", got "
                            + (state == null ? "null" : state.length));
        }
        api.requireField(params.field());

        int rf = params.rf();
        int rp = params.rp();
        int nRounds = rf + rp;

        Variable[] s = state.clone();
        for (int r = 0; r < nRounds; r++) {
            // AddRoundConstants
            for (int i = 0; i < t; i++) {
                s[i] = api.add(s[i], api.constant(params.cAt(r, i)));
            }
            // S-box: all cells in full rounds, first cell only in partial rounds
            boolean fullRound = r < rf / 2 || r >= rf / 2 + rp;
            if (fullRound) {
                for (int i = 0; i < t; i++) s[i] = sbox(api, s[i]);
            } else {
                s[0] = sbox(api, s[0]);
            }
            // MDS
            Variable[] next = new Variable[t];
            for (int i = 0; i < t; i++) {
                Variable acc = api.mul(s[0], api.constant(params.mAt(i, 0)));
                for (int j = 1; j < t; j++) {
                    acc = api.add(acc, api.mul(s[j], api.constant(params.mAt(i, j))));
                }
                next[i] = acc;
            }
            s = next;
        }
        return s;
    }

    /**
     * Sponge hash of {@code inputs} in a single permutation, with {@code capacity} seeding the
     * capacity cell — the natural place for a domain-separation tag.
     *
     * <p>Requires {@code inputs.length <= params.t() - 1}, i.e. the rate must cover the input
     * count. Returns {@code state[0]} after permuting.
     */
    public static Variable spongeHash(CircuitAPI api, PoseidonParams params,
                                      Variable capacity, Variable... inputs) {
        int t = params.t();
        if (inputs.length > t - 1) {
            throw new IllegalArgumentException(
                    "rate is " + (t - 1) + " but " + inputs.length + " inputs were supplied; "
                            + "use a wider preset or absorb in multiple permutations");
        }
        Variable[] state = new Variable[t];
        state[0] = capacity;
        for (int i = 0; i < t - 1; i++) {
            state[i + 1] = i < inputs.length ? inputs[i] : api.constant(0);
        }
        return permute(api, params, state)[0];
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
