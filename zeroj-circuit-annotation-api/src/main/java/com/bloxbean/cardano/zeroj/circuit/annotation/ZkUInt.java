package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.circuit.BitDecomposition;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

import java.util.List;
import java.util.Objects;

/**
 * Symbolic unsigned integer backed by one field element and an explicit bit
 * width.
 */
public final class ZkUInt implements ZkValue {
    public static final int MAX_BITS = 253;

    final ZkContext context;
    final Signal signal;
    private final int bits;
    private boolean wellFormed;

    /**
     * The decomposition proving {@code signal < 2^bits}, minted lazily and cached.
     *
     * <p>Cached because the constraints it stands for are emitted exactly once. Before
     * ADR-0038 the range proof was emitted by {@code assertInRange} and the resulting
     * {@link BitDecomposition} thrown away, so a gadget that also needed the bits — Pedersen
     * commitment, for instance — decomposed the same wire a second time.
     */
    private BitDecomposition decomposition;

    private ZkUInt(ZkContext context, Signal signal, int bits, boolean wellFormed) {
        this.context = Objects.requireNonNull(context, "context");
        this.signal = Objects.requireNonNull(signal, "signal");
        context.requireSignal(signal);
        this.bits = validateBits(bits);
        this.wellFormed = wellFormed;
    }

    public static ZkUInt publicInput(SignalBuilder builder, String name, int bits) {
        return constrained(new ZkContext(builder), builder.publicInput(name), bits);
    }

    public static ZkUInt secret(SignalBuilder builder, String name, int bits) {
        return constrained(new ZkContext(builder), builder.privateInput(name), bits);
    }

    public static ZkUInt wrap(ZkContext context, Signal signal, int bits) {
        return constrained(context, signal, bits);
    }

    public static ZkUInt wrap(SignalBuilder builder, Signal signal, int bits) {
        return constrained(new ZkContext(builder), signal, bits);
    }

    static ZkUInt trusted(ZkContext context, Signal signal, int bits) {
        return new ZkUInt(context, signal, bits, true);
    }

    private static ZkUInt constrained(ZkContext context, Signal signal, int bits) {
        var value = new ZkUInt(context, signal, bits, false);
        value.assertWellFormed();
        return value;
    }

    public int bits() {
        return bits;
    }

    public ZkUInt add(ZkUInt other) {
        requireSameContext(other);
        int outputBits = checkedOutputBits("addition", Math.max(bits, other.bits) + 1);
        // Operands are already range-constrained and the widened bound stays
        // below the safe field limit, so the result cannot wrap modulo p.
        return trusted(context, signal.add(other.signal), outputBits);
    }

    public ZkUInt sub(ZkUInt other) {
        requireSameContext(other);
        return constrained(context, signal.sub(other.signal), Math.max(bits, other.bits));
    }

    public ZkUInt mul(ZkUInt other) {
        requireSameContext(other);
        int outputBits = checkedOutputBits("multiplication", bits + other.bits);
        // Operands are already range-constrained and the product bound stays
        // below the safe field limit, so no extra decomposition is needed.
        return trusted(context, signal.mul(other.signal), outputBits);
    }

    public ZkBool lt(ZkUInt other) {
        requireSameContext(other);
        int compareBits = compareBits(other);
        return ZkBool.trusted(context, signal.lessThan(other.signal, compareBits));
    }

    public ZkBool lte(ZkUInt other) {
        return gt(other).not();
    }

    public ZkBool gt(ZkUInt other) {
        return other.lt(this);
    }

    public ZkBool gte(ZkUInt other) {
        return lt(other).not();
    }

    public ZkBool isEqual(ZkUInt other) {
        requireSameContext(other);
        return ZkBool.trusted(context, signal.isEqual(other.signal));
    }

    public ZkBool inRange(ZkUInt lo, ZkUInt hi) {
        requireSameContext(lo);
        requireSameContext(hi);
        return gte(lo).and(lte(hi));
    }

    public void assertInRange() {
        assertWellFormed();
    }

    public void assertEqual(ZkUInt other) {
        requireSameContext(other);
        context.builder().assertEqual(signal, other.signal);
    }

    public ZkField asField() {
        return ZkField.wrap(context, signal);
    }

    public Signal signal() {
        return signal;
    }

    @Override
    public List<Signal> signals() {
        return List.of(signal);
    }

    @Override
    public void assertWellFormed() {
        if (!wellFormed) {
            // Route through decomposition() so the bits are retained rather than emitted and
            // discarded; the constraints are identical either way.
            decomposition();
        }
    }

    /**
     * This value's binary decomposition at its declared width, proving {@code value < 2^bits}.
     *
     * <p>Minted on first use and cached, so the range constraints are emitted once no matter
     * how many gadgets ask. A value that was already range-constrained at construction returns
     * that same decomposition; a derived value — the result of {@link #add} or {@link #mul},
     * which carry a widened bound rather than an emitted proof — mints one here at its
     * declared width.
     *
     * <p>The returned object is owned by this value's circuit and is validated by every gadget
     * that consumes it ({@link com.bloxbean.cardano.zeroj.circuit.CircuitAPI#requireOwned}).
     * Passing it to a gadget building a <em>different</em> circuit is rejected at
     * circuit-definition time, so handing it out is safe.
     *
     * @see <a href="../../../../../../../../docs/adr/0038-jubjub-dsl-remediation-plan.md">ADR-0038 Decision 5</a>
     */
    public BitDecomposition decomposition() {
        if (decomposition == null) {
            decomposition = context.builder().api().decompose(signal.variable(), bits);
            // decompose() emits exactly the booleanity + recomposition constraints that
            // assertInRange would have.
            wellFormed = true;
        }
        return decomposition;
    }

    private int compareBits(ZkUInt other) {
        int compareBits = Math.max(bits, other.bits);
        if (compareBits >= MAX_BITS) {
            throw new IllegalArgumentException(
                    "ZkUInt comparison requires bit width < " + MAX_BITS + ", got " + compareBits);
        }
        return compareBits;
    }

    private void requireSameContext(ZkUInt other) {
        if (context.builder() != other.context.builder()) {
            throw new IllegalArgumentException("Symbolic values belong to different circuit builders");
        }
    }

    private static int validateBits(int bits) {
        if (bits <= 0 || bits > MAX_BITS) {
            throw new IllegalArgumentException("bits must be in [1, " + MAX_BITS + "], got " + bits);
        }
        return bits;
    }

    private static int checkedOutputBits(String operation, int outputBits) {
        if (outputBits > MAX_BITS) {
            throw new IllegalArgumentException(
                    "ZkUInt " + operation + " output requires " + outputBits
                            + " bits, exceeding max " + MAX_BITS);
        }
        return outputBits;
    }
}
