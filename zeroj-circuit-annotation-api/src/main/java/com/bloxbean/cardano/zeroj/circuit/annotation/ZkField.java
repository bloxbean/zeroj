package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

import java.util.List;
import java.util.Objects;

/**
 * Symbolic raw field element backed by one {@link Signal}.
 */
public final class ZkField implements ZkValue {
    final ZkContext context;
    final Signal signal;

    private ZkField(ZkContext context, Signal signal) {
        this.context = Objects.requireNonNull(context, "context");
        this.signal = Objects.requireNonNull(signal, "signal");
        context.requireSignal(signal);
    }

    public static ZkField publicInput(SignalBuilder builder, String name) {
        return wrap(new ZkContext(builder), builder.publicInput(name));
    }

    public static ZkField secret(SignalBuilder builder, String name) {
        return wrap(new ZkContext(builder), builder.privateInput(name));
    }

    public static ZkField wrap(ZkContext context, Signal signal) {
        return new ZkField(context, signal);
    }

    public static ZkField wrap(SignalBuilder builder, Signal signal) {
        return wrap(new ZkContext(builder), signal);
    }

    public ZkField add(ZkField other) {
        requireSameContext(other);
        return wrap(context, signal.add(other.signal));
    }

    public ZkField sub(ZkField other) {
        requireSameContext(other);
        return wrap(context, signal.sub(other.signal));
    }

    public ZkField mul(ZkField other) {
        requireSameContext(other);
        return wrap(context, signal.mul(other.signal));
    }

    public ZkField div(ZkField other) {
        requireSameContext(other);
        return wrap(context, signal.div(other.signal));
    }

    public ZkBool isEqual(ZkField other) {
        requireSameContext(other);
        return ZkBool.trusted(context, signal.isEqual(other.signal));
    }

    public void assertEqual(ZkField other) {
        requireSameContext(other);
        context.builder().assertEqual(signal, other.signal);
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
        // Every field element is well-formed modulo the active circuit field.
    }

    void requireSameContext(ZkField other) {
        if (context.builder() != other.context.builder()) {
            throw new IllegalArgumentException("Symbolic values belong to different circuit builders");
        }
    }
}
