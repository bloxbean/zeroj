package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.annotation.ZkBits;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.InCircuitPedersen;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Symbolic Pedersen commitment adapter for annotation-based circuits
 * ({@code pedersen-jubjub-v1}, see {@code docs/specs/pedersen-jubjub-v1.md}).
 *
 * <p>Both scalars are canonical ({@code < l}): the blinding and any full-width value by an explicit
 * comparator, a value narrower than 252 bits by its own range proof ({@code 2^251 < l}). The value
 * keeps its declared width; the blinding must be declared at exactly {@value #BLINDING_BITS} bits
 * and must not be a public input or a circuit constant (ADR-0051 D2). Sample it with
 * {@link org.zeroj.circuit.lib.jubjub.PedersenCommitment#randomBlinding}.
 */
public final class ZkPedersen {
    public static final int MAX_SCALAR_BITS = 252;

    /** Required declared width of every blinding, in bits (ADR-0051 D2). */
    public static final int BLINDING_BITS = InCircuitPedersen.BLINDING_BITS;

    private ZkPedersen() {}

    /**
     * Commits to {@code value} with {@code blinding}.
     *
     * <p>The value leg is multiplied at the value's own declared width (1–252), so a 64-bit
     * amount pays for 64 bits. The blinding must be declared at {@value #BLINDING_BITS} bits:
     * a narrower blinding makes the commitment brute-forceable from public data, so it is
     * rejected at circuit-definition time, as is a blinding that is directly a public input
     * or a constant.
     *
     * <p><b>Order matters.</b> Both decompositions are obtained <em>before</em> the
     * canonicality check runs. {@code assertCanonicalScalar} compares against {@code l} at
     * {@link #MAX_SCALAR_BITS}, and its range precondition is discharged from the DSL's range
     * cache — but only if a bound is already recorded for the wire. Run it first on a derived
     * value that has no cached bound and it mints a full 252-bit decomposition that is then
     * thrown away, which is precisely the duplicate this reuse removes.
     */
    public static ZkJubjubPoint commit(ZkContext zk, ZkUInt value, ZkUInt blinding) {
        validateScalarInputs(zk, value, blinding);
        // Mint (or retrieve) both owned decompositions at their actual widths FIRST, so the
        // canonicality check below is satisfied from the range cache rather than emitting a
        // second, wider decomposition.
        BitDecomposition valueBits = value.decomposition();
        BitDecomposition blindingBits = blinding.decomposition();
        assertValueCanonical(zk, value.bits(), value.signal().variable());
        assertCanonicalScalar(zk, blinding.signal().variable());
        return ZkJubjubPoint.wrap(zk, InCircuitPedersen.commit(
                zk.builder().api(), valueBits, blindingBits));
    }

    /**
     * Commits using LSB-first scalar bit vectors. The blinding vector must be exactly
     * {@value #BLINDING_BITS} bits, none of them a public input or a constant.
     */
    public static ZkJubjubPoint commitBits(ZkContext zk, ZkBits valueBits, ZkBits blindingBits) {
        validateBitInputs(zk, valueBits, blindingBits);
        Variable[] valueVariables = variables(valueBits);
        Variable[] blindingVariables = variables(blindingBits);
        var api = zk.builder().api();
        for (Variable bit : blindingVariables) {
            api.requireNotPublicOrConstant(bit);
        }
        if (valueVariables.length == MAX_SCALAR_BITS) {
            assertCanonicalScalar(zk, api.fromBinary(valueVariables));
        }
        assertCanonicalScalar(zk, api.fromBinary(blindingVariables));
        return ZkJubjubPoint.wrap(zk, InCircuitPedersen.commit(
                api,
                valueVariables,
                blindingVariables));
    }

    /**
     * Asserts that {@code (value, blinding)} opens {@code commitment}. The same width and
     * provenance rules as {@link #commit(ZkContext, ZkUInt, ZkUInt)} apply.
     */
    public static void verifyOpening(
            ZkContext zk,
            ZkJubjubPoint commitment,
            ZkUInt value,
            ZkUInt blinding) {
        Objects.requireNonNull(commitment, "commitment");
        commitment.requireSameContext(zk);
        commit(zk, value, blinding).assertEqual(zk, commitment);
    }

    /**
     * One side-term of a balance: a non-negative integer coefficient times a range-bounded
     * amount. The amount is either the known value of a {@link ZkPedersenCommitment} computed
     * in this circuit, or an uncommitted {@link ZkUInt} such as a public fee. Its declared
     * width is the bound the wrap check uses.
     */
    public static final class Term {
        private final BigInteger coefficient;
        private final ZkUInt amount;

        private Term(BigInteger coefficient, ZkUInt amount) {
            Objects.requireNonNull(coefficient, "coefficient");
            Objects.requireNonNull(amount, "amount");
            if (coefficient.signum() <= 0) {
                throw new IllegalArgumentException(
                        "balance coefficients must be positive integers; move a negative "
                                + "coefficient to the other side (got " + coefficient + ")");
            }
            this.coefficient = coefficient;
            this.amount = amount;
        }

        /** The commitment's value, coefficient 1. */
        public static Term of(ZkPedersenCommitment commitment) {
            return of(BigInteger.ONE, commitment);
        }

        /** The commitment's value times {@code coefficient}. */
        public static Term of(BigInteger coefficient, ZkPedersenCommitment commitment) {
            Objects.requireNonNull(commitment, "commitment");
            if (!commitment.hasKnownValue()) {
                throw new IllegalArgumentException(
                        "a " + commitment.origin() + " commitment has no value known to this "
                                + "circuit, so it cannot enter a balance. Commit to its opening "
                                + "with ZkPedersenCommitment.commit and bind the published "
                                + "coordinates with assertAffineEquals (ADR-0051 D3a).");
            }
            return new Term(coefficient, commitment.knownValue());
        }

        /** An uncommitted amount (for example a public fee), coefficient 1. */
        public static Term amount(ZkUInt amount) {
            return new Term(BigInteger.ONE, amount);
        }

        /** An uncommitted amount times {@code coefficient}. */
        public static Term amount(BigInteger coefficient, ZkUInt amount) {
            return new Term(coefficient, amount);
        }

        BigInteger maximum() {
            return coefficient.multiply(BigInteger.ONE.shiftLeft(amount.bits()).subtract(BigInteger.ONE));
        }
    }

    /**
     * Asserts {@code Σ left = Σ right} as an <b>integer</b> equation over committed and
     * uncommitted amounts (ADR-0051 D3a, invariant I6).
     *
     * <p>Pedersen homomorphism only proves relations mod {@code l}: with canonical openings,
     * {@code C(l − 1, 17) + C(1, 23) = C(0, 40)}. This helper makes the integer reading sound
     * instead of hoping for it:
     * <ul>
     *   <li>every term is range-bounded by its own decomposition at its declared width —
     *       bounding only a claimed total would not prevent the wrap above;</li>
     *   <li>coefficients are positive integers fixed now, never prover-chosen;</li>
     *   <li><b>at circuit-definition time</b>, each side's maximum
     *       {@code Σ coefficient·(2^width − 1)} must be below {@code l}, or this throws. Both
     *       sides are then integers in {@code [0, l)}, and since {@code l < p} the field
     *       equation emitted below implies integer equality, with no aliasing mod {@code p}
     *       either.</li>
     * </ul>
     *
     * <p>The relation is asserted on the opened values, which is cheaper than point arithmetic
     * and binds the commitments because each committed term's value is the one its commitment
     * was computed from.
     *
     * @throws IllegalArgumentException if a side is empty, a term belongs to another circuit,
     *         or either side could reach {@code l}
     */
    public static void assertBalanced(ZkContext zk, List<Term> left, List<Term> right) {
        Objects.requireNonNull(zk, "zk");
        requireSide(zk, left, "left");
        requireSide(zk, right, "right");
        requireBelowOrder(left, "left");
        requireBelowOrder(right, "right");
        var api = zk.builder().api();
        api.assertEqual(weightedSum(zk, left), weightedSum(zk, right));
    }

    private static void requireSide(ZkContext zk, List<Term> side, String name) {
        Objects.requireNonNull(side, name);
        if (side.isEmpty()) {
            throw new IllegalArgumentException("the " + name + " side of a balance must not be empty");
        }
        for (Term term : side) {
            Objects.requireNonNull(term, name + " term");
            zk.requireSignal(term.amount.signal());
        }
    }

    private static void requireBelowOrder(List<Term> side, String name) {
        BigInteger maximum = BigInteger.ZERO;
        for (Term term : side) {
            maximum = maximum.add(term.maximum());
        }
        if (maximum.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException(
                    "the " + name + " side of this balance can reach " + maximum.toString(16)
                            + " (hex), which is not below the subgroup order l. A relation mod l "
                            + "would not imply integer conservation; narrow the declared widths or "
                            + "coefficients (ADR-0051 D3a).");
        }
    }

    private static Variable weightedSum(ZkContext zk, List<Term> side) {
        var api = zk.builder().api();
        Variable sum = null;
        for (Term term : side) {
            // Emits the range proof if this amount does not already carry one (a derived
            // ZkUInt has only a widened bound until its decomposition is minted).
            term.amount.decomposition();
            Variable weighted = term.coefficient.equals(BigInteger.ONE)
                    ? term.amount.signal().variable()
                    : api.mul(term.amount.signal().variable(), api.constant(term.coefficient));
            sum = (sum == null) ? weighted : api.add(sum, weighted);
        }
        return sum;
    }

    private static void validateScalarInputs(ZkContext zk, ZkUInt value, ZkUInt blinding) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        zk.requireSignal(value.signal());
        zk.requireSignal(blinding.signal());
        if (value.bits() <= 0 || value.bits() > MAX_SCALAR_BITS) {
            throw new IllegalArgumentException(
                    "value width must be in [1, " + MAX_SCALAR_BITS + "], got " + value.bits());
        }
        requireBlindingWidth(blinding.bits());
        zk.builder().api().requireNotPublicOrConstant(blinding.signal().variable());
        // The declared width is not enough: the same wire may carry a narrower decomposition
        // (for example a 16-bit ZkUInt re-wrapped as 252 bits).
        zk.builder().api().requireHidingRange(blinding.signal().variable(), BLINDING_BITS);
    }

    private static void validateBitInputs(ZkContext zk, ZkBits valueBits, ZkBits blindingBits) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(valueBits, "valueBits");
        Objects.requireNonNull(blindingBits, "blindingBits");
        if (valueBits.size() <= 0 || valueBits.size() > MAX_SCALAR_BITS) {
            throw new IllegalArgumentException(
                    "value width must be in [1, " + MAX_SCALAR_BITS + "], got " + valueBits.size());
        }
        requireBlindingWidth(blindingBits.size());
        for (var bit : valueBits.values()) {
            zk.requireSignal(bit.signal());
        }
        for (var bit : blindingBits.values()) {
            zk.requireSignal(bit.signal());
        }
    }

    static void requireBlindingWidth(int bits) {
        if (bits != BLINDING_BITS) {
            throw new IllegalArgumentException(
                    "blinding must be declared at exactly " + BLINDING_BITS + " bits, got " + bits
                            + ". A narrower blinding cannot hide the committed value: a k-bit "
                            + "blinding is recovered from the public commitment by enumerating "
                            + "2^k candidates per value (ADR-0051 D2).");
        }
    }

    /**
     * Makes a value canonical ({@code < l}) as cheaply as soundness allows. A value declared
     * narrower than {@value #MAX_SCALAR_BITS} bits is range-proved by its own owned decomposition
     * to be below {@code 2^251}, and {@code 2^251 < l}, so it is canonical already and the 252-bit
     * comparator would only cost rows (about 508 per commitment). Only a full-width value needs
     * the explicit check. This is the rule the vector profile uses.
     */
    private static void assertValueCanonical(ZkContext zk, int declaredBits, Variable value) {
        if (declaredBits == MAX_SCALAR_BITS) {
            assertCanonicalScalar(zk, value);
        }
    }

    static void assertCanonicalScalar(ZkContext zk, Variable scalar) {
        var api = zk.builder().api();
        api.assertEqual(
                api.lessThan(scalar, api.constant(JubjubCurve.SUBGROUP_ORDER), MAX_SCALAR_BITS),
                api.constant(1));
    }

    private static Variable[] variables(ZkBits bits) {
        Variable[] variables = new Variable[bits.size()];
        for (int i = 0; i < bits.size(); i++) {
            variables[i] = bits.get(i).signal().variable();
        }
        return variables;
    }
}
