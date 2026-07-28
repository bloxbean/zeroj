package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.BitDecomposition;
import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.util.Objects;

/**
 * In-circuit Pedersen commitment gadgets.
 *
 * <p>{@code Commit(v, r) = [v]·G + [r]·H} where G is the Jubjub subgroup
 * generator and H is {@link PedersenCommitment#H}. Inside a SNARK, proves
 * that a committed value and blinding scalar produce a particular committed
 * point, without revealing either.
 *
 * <p><b>Scalar semantics.</b> This low-level gadget proves the value represented by each
 * supplied bit vector; a width of 252 proves only {@code scalar < 2^252}, not
 * {@code scalar < l}. Protocols that require one canonical subgroup scalar must establish
 * {@code < l} separately. The symbolic {@code ZkPedersen} adapter does so before calling this
 * gadget.
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
 * One {@link #commit} call emits two windowed fixed-base scalar multiplications plus an
 * addition: 3,020 constraints at 252-bit scalars, measured. If the application's values have
 * a smaller domain bound, pass a smaller {@code numBits} — cost is close to linear in it.
 *
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
        Objects.requireNonNull(api, "api");
        // Validate both operands completely before the first scalar multiplication emits
        // anything. A malformed blinding array must not leave a partial value leg behind.
        validateScalarBits(valueBits, "valueBits");
        validateScalarBits(blindBits, "blindBits");
        InCircuitJubjub.Point vG = InCircuitJubjub.scalarMulFixedBase(
                api, JubjubPoint.SUBGROUP_GENERATOR, valueBits);
        InCircuitJubjub.Point rH = InCircuitJubjub.scalarMulFixedBase(
                api, PedersenCommitment.H, blindBits);
        return InCircuitJubjub.add(api, vG, rH);
    }

    /**
     * Overload consuming decompositions the caller already holds, so a scalar that was
     * decomposed for a range or canonicality check is not decomposed a second time here.
     *
     * <p>This is the <b>fourth ownership consumer</b> of {@link BitDecomposition}
     * (ADR-0038 Decision 1 and 5). Both operands are validated with
     * {@link CircuitAPI#requireOwned} <b>up front</b>, before either scalar multiplication
     * runs. Delegating validation to the two {@code scalarMulFixedBase} calls in sequence
     * would be wrong: a foreign {@code blinding} would then be rejected only after
     * {@code [value]·G} had already emitted its constraints into the circuit.
     *
     * <p>Each scalar is multiplied at <b>its own width</b>. A 64-bit value committed
     * alongside a 252-bit blinding pays for 64 bits on the value leg, not 252.
     *
     * @throws IllegalArgumentException if either decomposition was minted by a different
     *         circuit
     */
    public static InCircuitJubjub.Point commit(CircuitAPI api,
                                               BitDecomposition value,
                                               BitDecomposition blinding) {
        Objects.requireNonNull(api, "api");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        // Both operands authenticated before ANY constraint is emitted.
        api.requireOwned(value);
        api.requireOwned(blinding);
        validateScalarWidth(value.width());
        validateScalarWidth(blinding.width());
        InCircuitJubjub.Point vG = InCircuitJubjub.scalarMulFixedBase(
                api, JubjubPoint.SUBGROUP_GENERATOR, value.bits());
        InCircuitJubjub.Point rH = InCircuitJubjub.scalarMulFixedBase(
                api, PedersenCommitment.H, blinding.bits());
        return InCircuitJubjub.add(api, vG, rH);
    }

    private static void validateScalarBits(Variable[] bits, String name) {
        Objects.requireNonNull(bits, name);
        validateScalarWidth(bits.length);
        for (int i = 0; i < bits.length; i++) {
            Objects.requireNonNull(bits[i], name + "[" + i + "]");
        }
    }

    private static void validateScalarWidth(int numBits) {
        if (numBits <= 0 || numBits > 252) {
            throw new IllegalArgumentException(
                    "scalar bit-vector width must be in (0, 252]; got " + numBits
                            + ". This is an encoding-width cap, not a proof that the "
                            + "represented integer is < l.");
        }
    }

    /**
     * Scalar-input overload: bit-decomposes {@code value} and {@code blinding}
     * to {@code numBits} bits each, then commits.
     *
     * <p>{@code numBits} is shared between both scalars — for Jubjub,
     * {@code 252} is the natural choice. When the caller already holds decompositions, or
     * when the two scalars have different natural widths, prefer
     * {@link #commit(CircuitAPI, BitDecomposition, BitDecomposition)}.
     */
    public static InCircuitJubjub.Point commit(CircuitAPI api,
                                               Variable value,
                                               Variable blinding,
                                               int numBits) {
        Objects.requireNonNull(api, "api");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        validateScalarWidth(numBits);
        Variable[] valueBits = api.toBinary(value, numBits);
        Variable[] blindBits = api.toBinary(blinding, numBits);
        return commit(api, valueBits, blindBits);
    }
}
