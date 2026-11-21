package org.zeroj.codec;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Halo2CodecTest {

    @Test
    void detectCurveFailsClosedWhenMissingOrUnsupported() {
        CircuitId cid = new CircuitId("halo2-test");
        assertThrows(CodecException.class,
                () -> Halo2Codec.toEnvelopeFromJson("{\"proof\":\"AA==\",\"publicInputs\":[]}", cid));
        assertThrows(CodecException.class,
                () -> Halo2Codec.toEnvelopeFromJson("{\"proof\":\"AA==\",\"publicInputs\":[],\"curve\":\"unknown\"}", cid));
        assertThrows(CodecException.class,
                () -> Halo2Codec.toEnvelopeFromJson("{\"proof\":\"AA==\",\"curve\":\"not-a-curve\"}", "[]", cid));
    }

    @Test
    void parseAcceptsExplicitSupportedCurves() {
        CircuitId cid = new CircuitId("halo2-test");
        var pallas = Halo2Codec.toEnvelopeFromJson(
                "{\"proof\":\"AA==\",\"publicInputs\":[\"1\"],\"curve\":\"pallas\"}", cid);
        assertEquals(CurveId.PALLAS, pallas.curve());
        var bls = Halo2Codec.toEnvelopeFromJson(
                "{\"proof\":\"AA==\",\"publicInputs\":[\"2\"],\"curve\":\"" + CurveId.BLS12_381.value() + "\"}", cid);
        assertEquals(CurveId.BLS12_381, bls.curve());
    }
}
