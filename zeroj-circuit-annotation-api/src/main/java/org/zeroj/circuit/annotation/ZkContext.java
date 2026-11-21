package org.zeroj.circuit.annotation;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Minimal context wrapper around {@link SignalBuilder} for symbolic values and
 * future gadget adapters.
 */
public final class ZkContext {
    private final SignalBuilder builder;

    public ZkContext(SignalBuilder builder) {
        this.builder = Objects.requireNonNull(builder, "builder");
    }

    public SignalBuilder builder() {
        return builder;
    }

    public void requireSignal(Signal signal) {
        Objects.requireNonNull(signal, "signal");
        if (!signal.isFrom(builder)) {
            throw new IllegalArgumentException("Signal belongs to a different circuit builder");
        }
    }

    public ZkField constant(long value) {
        return ZkField.wrap(this, builder.constant(value));
    }

    public ZkField constant(BigInteger value) {
        return ZkField.wrap(this, builder.constant(value));
    }

    public ZkBool constantBool(boolean value) {
        return ZkBool.trusted(this, builder.constant(value ? 1L : 0L));
    }

    public ZkUInt constantUInt(long value, int bits) {
        if (bits <= 0 || bits > ZkUInt.MAX_BITS) {
            throw new IllegalArgumentException("bits must be in [1, " + ZkUInt.MAX_BITS + "], got " + bits);
        }
        if (value < 0 || (bits < 63 && value >= (1L << bits))) {
            throw new IllegalArgumentException("constantUInt value out of range for " + bits + " bits");
        }
        return ZkUInt.trusted(this, builder.constant(value), bits);
    }

    public ZkUInt constantUInt(BigInteger value, int bits) {
        Objects.requireNonNull(value, "value");
        if (bits <= 0 || bits > ZkUInt.MAX_BITS) {
            throw new IllegalArgumentException("bits must be in [1, " + ZkUInt.MAX_BITS + "], got " + bits);
        }
        if (value.signum() < 0 || value.bitLength() > bits) {
            throw new IllegalArgumentException("constantUInt value out of range for " + bits + " bits");
        }
        return ZkUInt.trusted(this, builder.constant(value), bits);
    }

    public ZkField field(Signal signal) {
        return ZkField.wrap(this, signal);
    }
}
