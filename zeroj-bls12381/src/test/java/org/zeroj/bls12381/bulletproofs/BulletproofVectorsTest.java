package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    @DisplayName("An invalid fixture is rejected as a whole (a JSON number, an unknown field, a wrong generator, a reused seed, a missing width)")
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
        // Spec §7.5: a repeated nonce seed.
        ObjectNode seed = good.deepCopy();
        ((ObjectNode) seed.get("positive").get(1)).put("nonceSeedHex", seed.get("positive").get(0).get("nonceSeedHex").asText());
        assertThrowsState(seed);
        // Spec §11: no positive case at one width.
        ObjectNode width = good.deepCopy();
        ArrayNode positives = (ArrayNode) width.get("positive");
        for (int i = positives.size() - 1; i >= 0; i--) {
            if (positives.get(i).get("bits").asText().equals("32")) positives.remove(i);
        }
        assertThrowsState(width);
    }

    @Test
    @DisplayName("The file's spec provenance hashes equal the spec files as they are now (regenerate with --out after a spec edit)")
    void specProvenanceIsCurrent() throws IOException, NoSuchAlgorithmException {
        String root = System.getProperty("zeroj.repo.root");
        assertNotNull(root, "zeroj.repo.root is not set");
        JsonNode spec = BulletproofVectorRunner.load().get("spec");
        assertEquals(3, spec.size());
        for (JsonNode entry : spec) {
            byte[] file = Files.readAllBytes(Path.of(root, entry.get("path").asText()));
            assertEquals(entry.get("sha256").asText(),
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(file)), entry.get("path").asText());
        }
    }

    private static void assertThrowsState(JsonNode file) {
        assertThrows(IllegalStateException.class, () -> BulletproofVectorRunner.validate(file));
    }
}
