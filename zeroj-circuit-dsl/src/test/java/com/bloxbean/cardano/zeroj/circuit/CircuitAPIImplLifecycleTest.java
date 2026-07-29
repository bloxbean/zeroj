package com.bloxbean.cardano.zeroj.circuit;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertThrows;

class CircuitAPIImplLifecycleTest {

    @Test
    void cachedBooleanAssertionStillFailsAfterGraphIsBuilt() {
        var escapedApi = new AtomicReference<CircuitAPI>();
        var escapedWire = new AtomicReference<Variable>();

        CircuitBuilder.create("frozen-boolean-cache")
                .secretVar("bit")
                .define(api -> {
                    Variable bit = api.var("bit");
                    api.assertBoolean(bit);
                    escapedApi.set(api);
                    escapedWire.set(bit);
                });

        assertThrows(IllegalStateException.class,
                () -> escapedApi.get().assertBoolean(escapedWire.get()),
                "the idempotency cache must not make post-build emission appear to succeed");
    }

    @Test
    void publicNameCannotAuthorizeASecretWireId() {
        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("forged-public-name")
                        .publicVar("registeredPk")
                        .secretVar("proverPk")
                        .define(api -> {
                            Variable secret = api.var("proverPk");
                            // Variable is a public record: a caller can attach a public input's
                            // name to the secret wire id. Provenance must resolve the id.
                            Variable forged = new Variable(secret.id(), "registeredPk");
                            api.requirePublicOrConstant(forged);
                        }),
                "a public-looking name must not turn a prover-controlled wire into a "
                        + "registered/public key");
    }

    @Test
    void zeroOutputHintStillFailsAfterGraphIsBuilt() {
        var escapedApi = new AtomicReference<CircuitAPI>();

        CircuitBuilder.create("frozen-zero-output-hint")
                .define(escapedApi::set);

        assertThrows(IllegalStateException.class,
                () -> escapedApi.get().hintN(
                        Gate.HintKind.MUL_MOD_REDUCE,
                        new BigInteger[0],
                        0,
                        new Variable[0]),
                "numOutputs=0 must not bypass the frozen-builder guard");
    }
}
