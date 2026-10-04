package org.zeroj.circuit.lib.jubjub;

import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Variable;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * In-circuit Pedersen commitment gadgets ({@code pedersen-jubjub-v1}, see
 * {@code docs/specs/pedersen-jubjub-v1.md}).
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
 * <p><b>Hiding-safe blinding (ADR-0051 D2).</b> Every overload requires the blinding at full
 * width — exactly {@value #BLINDING_BITS} bits — and refuses a blinding wired directly to a
 * public input or a circuit constant. A narrower blinding cannot hide anything: a {@code k}-bit
 * blinding and a {@code j}-bit value are recovered from the public commitment by enumerating
 * {@code 2^(j+k)} candidates. The blinding wire must also not be range-confined below 252 bits
 * anywhere in the circuit ({@code CircuitAPI.requireHidingRange}, re-checked when the circuit is
 * frozen). For a raw blinding bit vector the same holds through its recorded provenance
 * ({@code CircuitAPI.requireHidingBits}): each bit's decomposition source must keep a 252-bit
 * range, and no range-confined recomposition may force one of the bits to zero; the vector may not
 * repeat a wire or share one with the value. These checks are guard rails, not a secrecy proof:
 * a secret wire the prover derived from public data still passes, and bits constrained by other
 * kinds of constraint (for example an equality with a narrow wire) are the caller's
 * responsibility. Prefer the scalar or decomposition overloads. Only the value keeps a
 * caller-chosen width, which is where the cost savings belong.
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
 * addition: 3,020 constraints at two 252-bit scalars for this gadget alone, measured. The
 * blinding leg is always 252 bits; a smaller value width makes the value leg proportionally
 * cheaper.
 */
public final class InCircuitPedersen {

    /** Required width of every blinding scalar, in bits (ADR-0051 D2). */
    public static final int BLINDING_BITS = 252;

    /** Maximum width of a value scalar, in bits. */
    public static final int MAX_VALUE_BITS = 252;

    private InCircuitPedersen() {}

    /**
     * Computes the Pedersen commitment {@code [v]·G + [r]·H} where G and H
     * are Jubjub subgroup bases (G = {@link JubjubPoint#SUBGROUP_GENERATOR},
     * H = {@link PedersenCommitment#H}).
     *
     * @param api         circuit API
     * @param valueBits   {@code v} as LSB-first boolean wires (each caller-
     *                    asserted-boolean); length 1–252
     * @param blindBits   {@code r} as LSB-first boolean wires; length exactly 252, and no bit
     *                    may be a public input or a circuit constant
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
        validateValueWidth(valueBits.length);
        validateBlindingWidth(blindBits.length);
        requireDistinctBlindingBits(valueBits, blindBits);
        for (Variable bit : blindBits) {
            api.requireNotPublicOrConstant(bit);
        }
        // Converting a decomposition to its bit array must not drop the range check: follow each
        // bit back to its decomposition source, and to any range-confined recomposition of it.
        api.requireHidingBits(blindBits, BLINDING_BITS);
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
     * alongside the 252-bit blinding pays for 64 bits on the value leg, not 252.
     *
     * @throws IllegalArgumentException if either decomposition was minted by a different
     *         circuit, if the blinding is not exactly 252 bits wide, or if the blinding's source
     *         wire is a public input or a circuit constant
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
        validateValueWidth(value.width());
        validateBlindingWidth(blinding.width());
        api.requireNotPublicOrConstant(blinding.source());
        api.requireHidingRange(blinding.source(), BLINDING_BITS);
        InCircuitJubjub.Point vG = InCircuitJubjub.scalarMulFixedBase(
                api, JubjubPoint.SUBGROUP_GENERATOR, value.bits());
        InCircuitJubjub.Point rH = InCircuitJubjub.scalarMulFixedBase(
                api, PedersenCommitment.H, blinding.bits());
        return InCircuitJubjub.add(api, vG, rH);
    }

    /**
     * Scalar-input overload: bit-decomposes {@code value} to {@code valueBits} bits and
     * {@code blinding} to the required {@value #BLINDING_BITS} bits, then commits.
     *
     * <p>Replaces the former {@code commit(api, value, blinding, numBits)} overload, whose
     * single shared width is how narrow, non-hiding blindings were declared (ADR-0051 F1).
     *
     * @throws IllegalArgumentException if {@code valueBits} is outside 1–252 or the blinding
     *         wire is a public input or a circuit constant
     */
    public static InCircuitJubjub.Point commit(CircuitAPI api,
                                               Variable value,
                                               int valueBits,
                                               Variable blinding) {
        Objects.requireNonNull(api, "api");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        validateValueWidth(valueBits);
        api.requireNotPublicOrConstant(blinding);
        api.requireHidingRange(blinding, BLINDING_BITS);
        Variable[] valueBitVector = api.toBinary(value, valueBits);
        Variable[] blindBitVector = api.toBinary(blinding, BLINDING_BITS);
        return commit(api, valueBitVector, blindBitVector);
    }

    /**
     * A raw blinding vector has no source wire whose range could be checked, so at least refuse
     * the structural ways of collapsing its entropy: the same wire at two positions, or a wire
     * shared with the value.
     */
    private static void requireDistinctBlindingBits(Variable[] valueBits, Variable[] blindBits) {
        Set<Integer> seen = new HashSet<>();
        for (Variable bit : blindBits) {
            if (!seen.add(bit.id())) {
                throw new IllegalArgumentException("blinding bit wire " + bit.id()
                        + " appears more than once; a blinding with repeated bits cannot hide (ADR-0051 D2)");
            }
        }
        for (Variable bit : valueBits) {
            if (seen.contains(bit.id())) {
                throw new IllegalArgumentException("wire " + bit.id()
                        + " is used in both the value and the blinding (ADR-0051 D2)");
            }
        }
    }

    private static void validateScalarBits(Variable[] bits, String name) {
        Objects.requireNonNull(bits, name);
        for (int i = 0; i < bits.length; i++) {
            Objects.requireNonNull(bits[i], name + "[" + i + "]");
        }
    }

    private static void validateValueWidth(int numBits) {
        if (numBits <= 0 || numBits > MAX_VALUE_BITS) {
            throw new IllegalArgumentException(
                    "value bit-vector width must be in (0, " + MAX_VALUE_BITS + "]; got "
                            + numBits + ". This is an encoding-width cap, not a proof that the "
                            + "represented integer is < l.");
        }
    }

    private static void validateBlindingWidth(int numBits) {
        if (numBits != BLINDING_BITS) {
            throw new IllegalArgumentException(
                    "blinding bit-vector width must be exactly " + BLINDING_BITS + "; got "
                            + numBits + ". A narrower blinding cannot hide the committed value: "
                            + "a k-bit blinding is recovered from the public commitment by "
                            + "enumerating 2^k candidates per value (ADR-0051 D2).");
        }
    }
}
