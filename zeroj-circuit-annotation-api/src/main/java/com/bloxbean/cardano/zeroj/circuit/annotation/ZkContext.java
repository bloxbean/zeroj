package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

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

    public ZkField field(Signal signal) {
        return ZkField.wrap(this, signal);
    }
}
