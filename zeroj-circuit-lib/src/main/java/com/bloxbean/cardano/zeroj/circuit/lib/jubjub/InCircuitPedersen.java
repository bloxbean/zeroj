package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

/**
 * In-circuit Pedersen commitment gadgets.
 *
 * <p>{@code Commit(v, r) = [v]·G + [r]·H} where G is the Jubjub subgroup
 * generator and H is {@link PedersenCommitment#H}. Inside a SNARK, proves
 * that a committed value and blinding scalar produce a particular committed
 * point, without revealing either.
 *
 * <h2>Use cases</h2>
 * <ul>
 *   <li>Confidential amounts: commit to transaction values; prove sum
 *       preservation via commitment homomorphism.</li>
 *   <li>Private voting: commit to vote, prove it is 0 or 1, homomorphically
 *       tally.</li>
 *   <li>Range proofs: Bulletproofs-style (out of M4 scope).</li>
 * </ul>
 *
 * <h2>Performance</h2>
 * One {@link #commit} call emits two fixed-base scalar-muls (~2·5000 =
 * 10000 constraints at 252-bit scalars). This is the dominant cost in any
 * Pedersen-heavy circuit; pre-commit wherever possible.
 */
public final class InCircuitPedersen {

    private InCircuitPedersen() {}

    /**
     * Computes the Pedersen commitment {@code [v]·G + [r]·H} where G and H
     * are Jubjub subgroup bases (G = {@link JubjubPoint#SUBGROUP_GENERATOR},
     * H = {@link PedersenCommitment#H}).
     *
     * @param api         circuit API
     * @param valueBits   {@code v} as LSB-first boolean wires (each caller-
     *                    asserted-boolean); length ≤ 252
     * @param blindBits   {@code r} as LSB-first boolean wires; length ≤ 252
     * @return            the commitment point in extended coords
     */
    public static InCircuitJubjub.Point commit(CircuitAPI api,
                                               Variable[] valueBits,
                                               Variable[] blindBits) {
        InCircuitJubjub.Point vG = InCircuitJubjub.scalarMulFixedBase(
                api, JubjubPoint.SUBGROUP_GENERATOR, valueBits);
        InCircuitJubjub.Point rH = InCircuitJubjub.scalarMulFixedBase(
                api, PedersenCommitment.H, blindBits);
        return InCircuitJubjub.add(api, vG, rH);
    }

    /**
     * Scalar-input overload: bit-decomposes {@code value} and {@code blinding}
     * to {@code numBits} bits each, then commits.
     *
     * <p>{@code numBits} is shared between both scalars — for Jubjub,
     * {@code 252} is the natural choice.
     */
    public static InCircuitJubjub.Point commit(CircuitAPI api,
                                               Variable value,
                                               Variable blinding,
                                               int numBits) {
        if (numBits <= 0 || numBits > 252) {
            throw new IllegalArgumentException(
                    "numBits must be in (0, 252]; got " + numBits
                            + ". Jubjub scalars live in [0, l) where l is 252 bits.");
        }
        Variable[] valueBits = api.toBinary(value, numBits);
        Variable[] blindBits = api.toBinary(blinding, numBits);
        return commit(api, valueBits, blindBits);
    }
}
