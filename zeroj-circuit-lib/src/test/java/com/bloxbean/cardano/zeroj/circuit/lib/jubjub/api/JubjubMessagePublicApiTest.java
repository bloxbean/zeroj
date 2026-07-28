package com.bloxbean.cardano.zeroj.circuit.lib.jubjub.api;

import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubMessage;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JubjubMessagePublicApiTest {

    @Test
    void externalCircuitCallerCanObtainCanonicalPublicFieldElement() {
        byte[] canonical = new byte[JubjubMessage.CANONICAL_BYTES];
        canonical[canonical.length - 1] = 42;
        JubjubMessage message = JubjubMessage.fromCanonicalFieldBytes(canonical);
        assertEquals(BigInteger.valueOf(42), message.toPublicFieldElement());
    }
}
