package com.bloxbean.cardano.zeroj.circuit;

import java.util.Objects;

/**
 * A witness-checked binary decomposition of a circuit variable.
 *
 * <p>An instance is evidence that the circuit contains constraints proving
 * <em>both</em> of the following about {@link #source()}:
 * <ul>
 *   <li>every element of {@link #bits()} is boolean, and</li>
 *   <li>{@code sum(bits[i] * 2^i) == source}, hence {@code source < 2^width}.</li>
 * </ul>
 *
 * <p><b>Why this type exists.</b> Gadgets such as
 * {@link CircuitAPI#lessThan(BitDecomposition, BitDecomposition)} are only sound when
 * their operands are known to fit in a bounded number of bits. Passing a bare
 * {@code Variable[]} would carry no such proof — a caller could hand over arbitrary
 * wires and the comparison would silently produce a wrong answer. Because the
 * constructor is not public, the only way to obtain a {@code BitDecomposition} is
 * {@link CircuitAPI#decompose(Variable, int)}, which emits the constraints.
 *
 * <p>The decomposition binds the source variable, the width, and the bits together,
 * so a caller cannot pass the decomposition of {@code x} while comparing {@code y}.
 *
 * <p><b>The decomposition also binds the circuit that emitted the constraints</b>
 * (ADR-0038 P1). Every instance carries an opaque owner token, held by exactly one
 * {@code CircuitAPIImpl} and compared by reference, and every consumer validates it through
 * {@link CircuitAPI#requireOwned(BitDecomposition)} before reading the bits.
 *
 * <p>Without that binding the guarantee was forgeable, because wire ids restart at 1 in every
 * circuit, so a decomposition minted in circuit A named wires that also exist in circuit B and
 * hold entirely unrelated values. Concretely, the two consumers broke in different ways:
 * <ul>
 *   <li>{@link CircuitAPI#lessThan(BitDecomposition, BitDecomposition)} skips its range
 *       constraints entirely on the strength of the typed evidence, so a foreign operand left
 *       the comparison with no bound at all — reopening the {@code p − 1 < 1,000,000} forgery
 *       ADR-0037 closed.</li>
 *   <li>The scalar-multiplication overloads read {@code bits()} and multiply by them, but the
 *       constraint that ties those bits to {@link #source()} —
 *       {@code Σ bits[i]·2^i == source} — lives in the <em>minting</em> circuit. Consuming a
 *       foreign decomposition therefore multiplies by bits that nothing in this circuit binds
 *       to the intended scalar, leaving the prover free to choose them.</li>
 * </ul>
 *
 * <p>An earlier revision of this Javadoc claimed the guarantee "cannot be forged" while
 * checking only constructor visibility and defensive copying, which were the wrong properties.
 * A revision written during ADR-0038 P1 then justified the fix by claiming that colliding wire
 * ids let {@code CircuitAPIImpl}'s booleanity cache suppress constraints; that too was wrong,
 * and is recorded here because writing down the wrong property is the failure this type exists
 * to prevent. Those caches are keyed per circuit and every entry is written by the same
 * circuit that emitted the corresponding constraint, so a cache hit means the <em>local</em>
 * wire genuinely carries that property and skipping is correct. The missing binding above is
 * the whole defect, and it is sufficient on its own.
 *
 * <p>The token is never exposed through the public API: there is no accessor, {@link
 * #toString()} omits it, and ownership is tested through the package-private
 * {@link #isOwnedBy(Object)} predicate so the token cannot escape through a comparison either.
 * This is an API-level barrier, not a defence against code that can join this package or use
 * reflection — the circuit author already controls circuit definition, so that is not the
 * threat model.
 *
 * <p>Instances are immutable; {@link #bits()} returns a defensive copy.
 *
 * @see CircuitAPI#decompose(Variable, int)
 */
public final class BitDecomposition {

    private final Variable source;
    private final int width;
    private final Variable[] bits;

    /**
     * Identity of the circuit that emitted this decomposition's constraints, compared by
     * reference only. Deliberately an opaque token rather than the {@code CircuitAPIImpl}
     * itself: a decomposition that escapes its circuit would otherwise retain the whole
     * builder and its gate list, which on a 19M-constraint circuit is a serious leak.
     */
    private final Object owner;

    /**
     * Not public by design — see the class Javadoc. Only the DSL implementation,
     * which has just emitted the booleanity and recomposition constraints, may
     * mint an instance, and it stamps the instance with its own circuit token.
     */
    BitDecomposition(Object owner, Variable source, int width, Variable[] bits) {
        this.owner = Objects.requireNonNull(owner, "owner");
        this.source = Objects.requireNonNull(source, "source");
        if (width <= 0) throw new IllegalArgumentException("width must be positive, got " + width);
        Objects.requireNonNull(bits, "bits");
        if (bits.length != width) {
            throw new IllegalArgumentException(
                    "bits.length (" + bits.length + ") must equal width (" + width + ")");
        }
        this.width = width;
        this.bits = bits.clone();
        for (int i = 0; i < this.bits.length; i++) {
            Objects.requireNonNull(this.bits[i], "bits[" + i + "]");
        }
    }

    /**
     * Ownership predicate used by {@link CircuitAPI#requireOwned(BitDecomposition)}.
     *
     * <p>Returns a boolean rather than exposing the token, so the token cannot escape through
     * an accessor, an equality comparison, or a diagnostic message. Reference equality is the
     * whole test: a name or an id can be fabricated through the public API — {@link Variable}
     * is a public record — whereas an object identity cannot.
     */
    boolean isOwnedBy(Object candidateToken) {
        return this.owner == candidateToken;
    }

    /** The variable these bits decompose. */
    public Variable source() {
        return source;
    }

    /** Bit width; the circuit proves {@code source < 2^width}. */
    public int width() {
        return width;
    }

    /** The bits, LSB-first. Returns a defensive copy. */
    public Variable[] bits() {
        return bits.clone();
    }

    /** The bit at index {@code i}, LSB-first. */
    public Variable bit(int i) {
        if (i < 0 || i >= width) {
            throw new IndexOutOfBoundsException("bit index " + i + " out of range [0, " + width + ")");
        }
        return bits[i];
    }

    /** Internal accessor that skips the defensive copy; callers must not mutate. */
    Variable[] bitsNoCopy() {
        return bits;
    }

    @Override
    public String toString() {
        return "BitDecomposition{source=" + source + ", width=" + width + "}";
    }
}
