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
 * {@link CircuitAPI#decompose(Variable, int)}, which emits the constraints. The
 * range guarantee therefore travels with the value and cannot be forged.
 *
 * <p>The decomposition binds the source variable, the width, and the bits together,
 * so a caller cannot pass the decomposition of {@code x} while comparing {@code y}.
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
     * Not public by design — see the class Javadoc. Only the DSL implementation,
     * which has just emitted the booleanity and recomposition constraints, may
     * mint an instance.
     */
    BitDecomposition(Variable source, int width, Variable[] bits) {
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
