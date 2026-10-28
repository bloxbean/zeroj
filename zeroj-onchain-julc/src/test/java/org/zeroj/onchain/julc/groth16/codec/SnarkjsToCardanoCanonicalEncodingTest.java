package org.zeroj.onchain.julc.groth16.codec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** ADR-0062 D5: the snarkjs-to-Cardano codec accepts only affine (z = 1) points, like the verifiers. */
class SnarkjsToCardanoCanonicalEncodingTest {
    private static final BigInteger G1X = Bls12381Generators.G1.x().value();
    private static final BigInteger G1Y = Bls12381Generators.G1.y().value();

    @Test
    void g1CanonicalEncodingCompresses() {
        assertArrayEquals(Bls12381Codecs.g1ToCompressed(Bls12381Generators.G1),
                SnarkjsToCardano.g1Compress(List.of(G1X, G1Y, BigInteger.ONE)));
    }

    @Test
    void g1RescaledEncodingIsRejected() {
        BigInteger lambda = BigInteger.valueOf(7);
        var rescaled = List.of(G1X.multiply(lambda).mod(Fp.P), G1Y.multiply(lambda).mod(Fp.P), lambda);
        assertThrows(IllegalArgumentException.class, () -> SnarkjsToCardano.g1Compress(rescaled));
    }

    @Test
    void g2RescaledEncodingIsRejected() {
        var g2 = Bls12381Generators.G2;
        var x = List.of(g2.x().c0().value(), g2.x().c1().value());
        var y = List.of(g2.y().c0().value(), g2.y().c1().value());
        assertArrayEquals(Bls12381Codecs.g2ToCompressed(g2),
                SnarkjsToCardano.g2Compress(List.of(x, y, List.of(BigInteger.ONE, BigInteger.ZERO))));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsToCardano.g2Compress(
                List.of(x, y, List.of(BigInteger.TWO, BigInteger.ZERO))));
    }

    /**
     * ADR-0062 M6 review: only the canonical identity encoding is accepted for z = 0. These are the
     * point-level codecs; {@code parseProof}/{@code parseVk} add the per-field identity rules below.
     */
    @Test
    void onlyTheCanonicalIdentityIsAccepted() {
        assertArrayEquals(Bls12381Codecs.g1ToCompressed(G1Point.INFINITY),
                SnarkjsToCardano.g1Compress(List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO)));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsToCardano.g1Compress(List.of(G1X, G1Y, BigInteger.ZERO)));
        var zero = List.of(BigInteger.ZERO, BigInteger.ZERO);
        var one = List.of(BigInteger.ONE, BigInteger.ZERO);
        assertArrayEquals(Bls12381Codecs.g2ToCompressed(G2Point.INFINITY),
                SnarkjsToCardano.g2Compress(List.of(zero, one, zero)));
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsToCardano.g2Compress(List.of(one, one, zero)));
    }

    @Test
    void coordinatesAtOrAboveTheModulusAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> SnarkjsToCardano.g1Compress(List.of(G1X.add(Fp.P), G1Y, BigInteger.ONE)));
    }

    /**
     * ADR-0062 PR review item 1: on {@code main} blst-java rejected every identity point, so the
     * proof points must not become a new accept path (ADR-0025, ADR-0045 V2).
     */
    @ParameterizedTest
    @ValueSource(strings = {"pi_a", "pi_b", "pi_c"})
    void identityProofPointsAreRejected(String field) throws IOException {
        ObjectNode proof = (ObjectNode) MAPPER.readTree(fixture("proof.json"));
        assertDoesNotThrow(() -> SnarkjsToCardano.parseProof(proof.toString()));
        proof.set(field, identity(field.equals("pi_b")));
        var e = assertThrows(IllegalArgumentException.class, () -> SnarkjsToCardano.parseProof(proof.toString()));
        assertEquals(field + " must not be the point at infinity", e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"vk_alpha_1", "vk_beta_2", "vk_gamma_2", "vk_delta_2"})
    void identityVkHeaderPointsAreRejected(String field) throws IOException {
        ObjectNode vk = (ObjectNode) MAPPER.readTree(fixture("verification_key.json"));
        assertDoesNotThrow(() -> SnarkjsToCardano.parseVk(vk.toString()));
        vk.set(field, identity(field.endsWith("_2")));
        var e = assertThrows(IllegalArgumentException.class, () -> SnarkjsToCardano.parseVk(vk.toString()));
        assertEquals(field + " must not be the point at infinity", e.getMessage());
    }

    /** ADR-0045 V3: an identity {@code IC} entry is transported unchanged for the verifier to reject. */
    @Test
    void identityIcEntryIsPassedThroughForTheVerifierToReject() throws Exception {
        ObjectNode vk = (ObjectNode) MAPPER.readTree(fixture("verification_key.json"));
        ((ArrayNode) vk.get("IC")).set(1, identity(false));
        var compressed = SnarkjsToCardano.parseVk(vk.toString());
        assertArrayEquals(Bls12381Codecs.g1ToCompressed(G1Point.INFINITY), compressed.ic().get(1));
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ArrayNode identity(boolean g2) {
        ArrayNode node = MAPPER.createArrayNode();
        if (g2) {
            node.add(MAPPER.createArrayNode().add("0").add("0"));
            node.add(MAPPER.createArrayNode().add("1").add("0"));
            node.add(MAPPER.createArrayNode().add("0").add("0"));
        } else {
            node.add("0").add("1").add("0");
        }
        return node;
    }

    private static String fixture(String name) throws IOException {
        try (InputStream in = SnarkjsToCardanoCanonicalEncodingTest.class
                .getResourceAsStream("/test-circuits/sealed-bid-bls12381/" + name)) {
            assertNotNull(in, name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
