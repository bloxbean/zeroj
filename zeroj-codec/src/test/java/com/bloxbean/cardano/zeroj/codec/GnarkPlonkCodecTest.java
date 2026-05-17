package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GnarkPlonkCodecTest {

    @Test
    void toEnvelopeFromJson_usesExplicitCurve() {
        var proofJson = "{\"binary\":\"AA==\",\"protocol\":\"plonk\",\"curve\":\"bn128\"}";

        var envelope = GnarkPlonkCodec.toEnvelopeFromJson(
                proofJson, "{}", "[\"33\"]", new CircuitId("mul"));

        assertEquals(CurveId.BN254, envelope.curve());
        assertEquals("gnark-plonk-json", envelope.proofFormat().orElseThrow());
        assertEquals(1, envelope.publicInputs().size());
    }

    @Test
    void toEnvelopeFromJson_missingCurveRejected() {
        var proofJson = "{\"binary\":\"AA==\",\"protocol\":\"plonk\"}";

        assertThrows(CodecException.class, () -> GnarkPlonkCodec.toEnvelopeFromJson(
                proofJson, "{}", "[\"33\"]", new CircuitId("mul")));
    }
}
