package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M2: every case of {@code bulletproof-range-bls12-381-g1-v1.json}, written by the independent
 * Python emitter, holds through the pure-Java provider: the Java test-nonce prover reproduces every
 * positive proof byte for byte (Python → Java agreement), the Java verifier accepts them with every
 * challenge reproduced, and every negative and prover refusal gives exactly its class and layer.
 */
class BulletproofVectorsTest {

    @Test
    @DisplayName("Every case of the vector file holds through the pure-Java provider")
    void pureJava() throws IOException {
        JsonNode file = BulletproofVectorRunner.load();
        int cases = file.get("positive").size() + file.get("negative").size() + file.get("proverNegative").size();
        BulletproofVectorRunner.Report report = BulletproofVectorRunner.run(file, G1RangeProver.pureJava(),
                G1RangeVerifier.pureJava(), G1Pedersen.pureJava());
        assertEquals(List.of(), report.failures(), report.failures().size() + " failing cases");
        assertEquals(cases, report.executed());
        assertTrue(file.get("positive").size() >= 12 && file.get("negative").size() >= 100, "case counts");
    }

    @Test
    @DisplayName("An invalid fixture is rejected as a whole (a JSON number, an unknown field, a wrong generator)")
    void fixtureValidation() throws IOException {
        JsonNode good = BulletproofVectorRunner.load();
        ObjectNode number = good.deepCopy();
        ((ObjectNode) number.get("positive").get(0)).put("bits", 16);
        assertThrowsState(number);
        ObjectNode extra = good.deepCopy();
        ((ObjectNode) extra.get("negative").get(0)).put("note", "x");
        assertThrowsState(extra);
        ObjectNode gen = good.deepCopy();
        ((ObjectNode) gen.get("generators").get(5)).put("compressedHex",
                BulletproofGenerators.G_VEC_HEX.get(6));
        assertThrowsState(gen);
    }

    private static void assertThrowsState(JsonNode file) {
        assertThrows(IllegalStateException.class, () -> BulletproofVectorRunner.validate(file));
    }
}
