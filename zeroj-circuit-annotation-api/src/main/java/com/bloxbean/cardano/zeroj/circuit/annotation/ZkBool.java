package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

import java.util.List;
import java.util.Objects;

/**
 * Symbolic boolean backed by one constrained bit signal.
 */
public final class ZkBool implements ZkValue {
    final ZkContext context;
    final Signal signal;
    private boolean wellFormed;

    private ZkBool(ZkContext context, Signal signal, boolean wellFormed) {
        this.context = Objects.requireNonNull(context, "context");
        this.signal = Objects.requireNonNull(signal, "signal");
        context.requireSignal(signal);
        this.wellFormed = wellFormed;
    }

    public static ZkBool publicInput(SignalBuilder builder, String name) {
        return constrained(new ZkContext(builder), builder.publicInput(name));
    }

    public static ZkBool secret(SignalBuilder builder, String name) {
        return constrained(new ZkContext(builder), builder.privateInput(name));
    }

    public static ZkBool wrap(ZkContext context, Signal signal) {
        return constrained(context, signal);
    }

    public static ZkBool wrap(SignalBuilder builder, Signal signal) {
        return constrained(new ZkContext(builder), signal);
    }

    static ZkBool trusted(ZkContext context, Signal signal) {
        return new ZkBool(context, signal, true);
    }

    private static ZkBool constrained(ZkContext context, Signal signal) {
        var value = new ZkBool(context, signal, false);
        value.assertWellFormed();
        return value;
    }

    public ZkBool and(ZkBool other) {
        requireSameContext(other);
        return trusted(context, signal.and(other.signal));
    }

    public ZkBool or(ZkBool other) {
        requireSameContext(other);
        return trusted(context, signal.or(other.signal));
    }

    public ZkBool xor(ZkBool other) {
        requireSameContext(other);
        return trusted(context, signal.xor(other.signal));
    }

    public ZkBool not() {
        return trusted(context, signal.not());
    }

    public ZkField select(ZkField ifTrue, ZkField ifFalse) {
        requireSameContext(ifTrue);
        requireSameContext(ifFalse);
        return ZkField.wrap(context, signal.select(ifTrue.signal, ifFalse.signal));
    }

    public ZkBool select(ZkBool ifTrue, ZkBool ifFalse) {
        requireSameContext(ifTrue);
        requireSameContext(ifFalse);
        return trusted(context, signal.select(ifTrue.signal, ifFalse.signal));
    }

    public ZkUInt select(ZkUInt ifTrue, ZkUInt ifFalse) {
        requireSameContext(ifTrue);
        requireSameContext(ifFalse);
        return ZkUInt.trusted(context, signal.select(ifTrue.signal, ifFalse.signal),
                Math.max(ifTrue.bits(), ifFalse.bits()));
    }

    public ZkBool isEqual(ZkBool other) {
        requireSameContext(other);
        return trusted(context, signal.isEqual(other.signal));
    }

    public void assertTrue() {
        context.builder().assertEqual(signal, context.builder().constant(1));
    }

    public void assertFalse() {
        context.builder().assertEqual(signal, context.builder().constant(0));
    }

    public void assertEqual(ZkBool other) {
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
            signal.assertBoolean();
            wellFormed = true;
        }
    }

    private void requireSameContext(ZkBool other) {
        if (context.builder() != other.context.builder()) {
            throw new IllegalArgumentException("Symbolic values belong to different circuit builders");
        }
    }

    private void requireSameContext(ZkField other) {
        if (context.builder() != other.context.builder()) {
            throw new IllegalArgumentException("Symbolic values belong to different circuit builders");
        }
    }

    private void requireSameContext(ZkUInt other) {
        if (context.builder() != other.context.builder()) {
            throw new IllegalArgumentException("Symbolic values belong to different circuit builders");
        }
    }
}
