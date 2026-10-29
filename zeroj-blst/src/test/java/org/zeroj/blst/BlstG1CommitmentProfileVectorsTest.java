package org.zeroj.blst;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1VectorRunner;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M3, invariant I7: every case of the two BLS12-381 G1 {@code zeroj-commitment-vectors-v1}
 * files ({@code commitment-profiles-v1} §13) holds through
 * {@code G1Pedersen.withProvider(BlstBls12381Provider.createDefault())}, with the same shared runner
 * as the pure-Java test, and every case's outcome (value or error class) is identical to the
 * pure-Java provider's.
 *
 * <p>Expected values come from the independent Python emitter; the provider comparison is
 * differential on top of that.
 */
class BlstG1CommitmentProfileVectorsTest {

    private static final BlstBls12381Provider BLST_PROVIDER = BlstBls12381Provider.createDefault();
    private static final G1Pedersen BLST = G1Pedersen.withProvider(BLST_PROVIDER);

    @Test
    @DisplayName("The blst instance under test is the blst provider and supports generation")
    void blstInstance() {
        assertSame(BLST_PROVIDER, BLST.provider());
        assertTrue(BLST.supportsGeneration(), "blst offers a secret-scalar G1 multiplication");
    }

    @ParameterizedTest
    @ValueSource(strings = {G1VectorRunner.SCALAR, G1VectorRunner.BYTES})
    @DisplayName("Every case of the G1 vector file holds through the blst provider, with outcomes identical to pure Java")
    void vectors(String profileId) throws IOException {
        JsonNode file = G1VectorRunner.load(profileId);
        assertEquals(profileId, file.path("profileId").asText());
        int cases = file.get("positive").size() + file.get("negative").size();

        G1VectorRunner.Report blst = G1VectorRunner.run(file, BLST);
        assertEquals(List.of(), blst.failures(), profileId + ": " + blst.failures().size() + " failing cases (blst)");
        assertEquals(cases, blst.executed(), "every case ran (blst)");

        G1VectorRunner.Report pure = G1VectorRunner.run(file, G1Pedersen.pureJava());
        assertEquals(List.of(), pure.failures(), profileId + " (pure Java)");
        assertEquals(cases, pure.executed(), "every case ran (pure Java)");

        assertEquals(pure.outcomes(), blst.outcomes(), profileId + ": provider outcomes differ");
    }

    @Test
    @DisplayName("Self-test: through blst, the runner reports a changed commit point and a changed verdict")
    void runnerDetectsMutationsThroughBlst() throws IOException {
        for (String profileId : G1VectorRunner.PROFILES) {
            ObjectNode commit = G1VectorRunner.load(profileId).deepCopy();
            boolean changed = false;
            for (JsonNode c : commit.get("positive")) {
                if (c.get("operation").asText().equals("commit")) {
                    String hex = c.get("expected").get("pointHex").asText();
                    char last = hex.charAt(hex.length() - 1);
                    ((ObjectNode) c.get("expected")).put("pointHex",
                            hex.substring(0, hex.length() - 1) + (last == '0' ? '1' : '0'));
                    changed = true;
                    break;
                }
            }
            assertTrue(changed, profileId + " has a commit case");
            assertFalse(G1VectorRunner.run(commit, BLST).failures().isEmpty(),
                    profileId + ": a changed commit point went unnoticed through blst");

            ObjectNode verdict = G1VectorRunner.load(profileId).deepCopy();
            changed = false;
            for (JsonNode c : verdict.get("negative")) {
                if (c.get("error").asText().equals("OPENING_MISMATCH")) {
                    ((ObjectNode) c).put("error", "MALFORMED_ENCODING");
                    changed = true;
                    break;
                }
            }
            assertTrue(changed, profileId + " has an OPENING_MISMATCH case");
            assertFalse(G1VectorRunner.run(verdict, BLST).failures().isEmpty(),
                    profileId + ": a changed verdict went unnoticed through blst");
        }
    }
}
