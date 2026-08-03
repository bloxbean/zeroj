package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.bloxbean.cardano.vds.jmt.JellyfishMerkleTree;
import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.JmtProfile;
import com.bloxbean.cardano.vds.jmt.store.InMemoryJmtStore;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonJmtCclVectorTest {
    private static final String RESOURCE =
            "/test-vectors/poseidon-authenticated-state-v1/vectors.json";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger DOMAIN_EMPTY = new BigInteger("5a4a4d540003", 16);
    private static final BigInteger DOMAIN_LEAF = new BigInteger("5a4a4d540004", 16);
    private static final BigInteger DOMAIN_BRANCH = new BigInteger("5a4a4d540010", 16);

    @Test
    void cclObjectsWiresAndIndependentCheckerAgreeWithLiteralFixture() throws Exception {
        JsonNode fixture = vectors().path("jmt").path("cclFixture");
        assertEquals("0.8.0-pre5-dev1", fixture.path("cclVersion").asText());
        assertEquals(Set.of(
                        "root-bit-flip", "query-key-bit-flip", "expected-value-bit-flip",
                        "wire-truncated-one-byte", "wire-appended-zero",
                        "inclusion-flag-confusion", "object-depth-gap",
                        "profile-descriptor-mismatch"),
                JSON.convertValue(fixture.path("negativeMutations"),
                        JSON.getTypeFactory().constructCollectionType(Set.class, String.class)));

        var store = new InMemoryJmtStore();
        var tree = new PoseidonJmtTree(store);
        long version = fixture.path("version").asLong();
        byte[] expectedRoot = HEX.parseHex(fixture.path("rootHex").asText());
        var commit = tree.put(version, entries(fixture.path("entries")));
        assertArrayEquals(expectedRoot, commit.rootHash());
        assertTrue(commit.nodes().size() > 1, "fixture must persist a multi-level tree");
        assertArrayEquals(expectedRoot, store.rootHash(version).orElseThrow());

        // A new tree instance over the same store proves reopen/profile replay.
        var reopened = new PoseidonJmtTree(store);
        for (JsonNode vector : fixture.path("proofs")) {
            verifyProofVector(reopened, expectedRoot, version, vector);
        }
        verifySingleNeighborFixture(fixture.path("singleNeighborFixture"));
        verifyRootLeafFixture(fixture.path("rootLeafFixture"));

        assertThrows(RuntimeException.class,
                () -> new JellyfishMerkleTree(store, JmtProfile.classicBlake2b256V1()),
                "opening the namespace under another profile must fail closed");
    }

    private static void verifySingleNeighborFixture(JsonNode fixture) {
        var tree = new PoseidonJmtTree(new InMemoryJmtStore());
        var values = new LinkedHashMap<byte[], byte[]>();
        fixture.path("entries").fields().forEachRemaining(entry -> values.put(
                bytes(entry.getKey()), bytes(entry.getValue().asText())));
        long version = fixture.path("version").asLong();
        byte[] root = HEX.parseHex(fixture.path("rootHex").asText());
        assertArrayEquals(root, tree.put(version, values).rootHash());
        JsonNode proof = fixture.path("proof");
        verifyProofVector(tree, root, version, proof);
        assertTrue(proof.path("steps").get(0).path("hasSingleNeighbor").asBoolean());
    }

    private static void verifyRootLeafFixture(JsonNode fixture) {
        var tree = new PoseidonJmtTree(new InMemoryJmtStore());
        var values = new LinkedHashMap<byte[], byte[]>();
        fixture.path("entries").fields().forEachRemaining(entry -> values.put(
                bytes(entry.getKey()), bytes(entry.getValue().asText())));
        long version = fixture.path("version").asLong();
        byte[] root = HEX.parseHex(fixture.path("rootHex").asText());
        assertArrayEquals(root, tree.put(version, values).rootHash());
        JsonNode proof = fixture.path("proof");
        verifyProofVector(tree, root, version, proof);
        assertEquals(0, proof.path("steps").size());
    }

    private static void verifyProofVector(
            PoseidonJmtTree tree, byte[] root, long version, JsonNode vector) {
        byte[] key = bytes(vector.path("keyUtf8").asText());
        byte[] value = vector.has("valueUtf8") ? bytes(vector.path("valueUtf8").asText()) : null;
        boolean including = "INCLUSION".equals(vector.path("type").asText());
        JmtProof proof = tree.getProof(key, version).orElseThrow();
        byte[] wire = tree.getProofWire(key, version).orElseThrow();

        assertEquals(vector.path("type").asText(), proof.type().name());
        assertArrayEquals(wire, tree.encodeProof(key, proof),
                "encoding an object proof must not require a second persistent-tree traversal");
        assertArrayEquals(Base64.getDecoder().decode(vector.path("wireBase64").asText()), wire);
        assertArrayEquals(wire, independentWire(vector),
                "literal object fields must independently reproduce the CCL wire grammar");
        assertEquals(vector.path("steps").size(), proof.steps().size());
        for (int index = 0; index < proof.steps().size(); index++) {
            assertStep(vector.path("steps").get(index), proof.steps().get(index));
        }
        if (including) {
            assertArrayEquals(HEX.parseHex(vector.path("leafKeyHashHex").asText()), proof.leafKeyHash());
            assertArrayEquals(HEX.parseHex(vector.path("valueHashHex").asText()), proof.valueHash());
            assertArrayEquals(value, proof.value());
            assertNotNull(proof.suffix());
            assertEquals(vector.path("leafSuffixHex").asText(), proof.suffix().toHexString());
            assertNull(proof.conflictingKeyHash());
            assertNull(proof.conflictingValueHash());
            assertNull(proof.conflictingSuffix());
            assertTrue(PoseidonJmtReference.including(root, key, value, proof));
            assertTrue(tree.verifyInclusionProof(root, key, value, proof));
            assertFalse(tree.verifyNonInclusionProof(root, key, proof));
        } else {
            assertNull(proof.value());
            assertNull(proof.valueHash());
            assertNull(proof.suffix());
            assertNull(proof.leafKeyHash());
            assertTrue(PoseidonJmtReference.excluding(root, key, proof));
            assertTrue(tree.verifyNonInclusionProof(root, key, proof));
            assertFalse(tree.verifyInclusionProof(root, key, bytes("invented"), proof));
            assertFalse(tree.verifyProof(root, key, bytes("invented"), proof));
            assertFalse(tree.verifyProofWire(root, key, bytes("invented"), false, wire));
            if (proof.type() == JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF) {
                assertArrayEquals(HEX.parseHex(vector.path("conflictingKeyHashHex").asText()),
                        proof.conflictingKeyHash());
                assertArrayEquals(HEX.parseHex(vector.path("conflictingValueHashHex").asText()),
                        proof.conflictingValueHash());
                assertNotNull(proof.conflictingSuffix());
                assertEquals(vector.path("conflictingSuffixHex").asText(),
                        proof.conflictingSuffix().toHexString());
            } else {
                assertNull(proof.conflictingKeyHash());
                assertNull(proof.conflictingValueHash());
                assertNull(proof.conflictingSuffix());
            }
        }
        assertTrue(tree.verifyProof(root, key, value, proof));
        assertTrue(tree.verifyProofWire(root, key, value, including, wire));
        assertArrayEquals(root, independentRoot(vector));

        byte[] badRoot = root.clone();
        badRoot[31] ^= 1;
        byte[] badKey = key.clone();
        badKey[0] ^= 1;
        assertFalse(tree.verifyProof(badRoot, key, value, proof));
        assertFalse(tree.verifyProofWire(badRoot, key, value, including, wire));
        boolean rootLeafDifferent = proof.type() == JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF
                && proof.steps().isEmpty();
        if (rootLeafDifferent) {
            // The same root-leaf proof validly excludes every key except the
            // conflicting leaf itself; changing one absent query to another
            // absent query must remain true.
            assertTrue(tree.verifyProof(root, badKey, null, proof));
            assertTrue(tree.verifyProofWire(root, badKey, null, false, wire));
            byte[] conflictingKey = bytes(vector.path("conflictingKeyUtf8").asText());
            assertFalse(tree.verifyProof(root, conflictingKey, null, proof));
            assertFalse(tree.verifyProofWire(root, conflictingKey, null, false, wire));
        } else {
            assertFalse(tree.verifyProof(root, badKey, value, proof));
            assertFalse(tree.verifyProofWire(root, badKey, value, including, wire));
        }
        assertFalse(tree.verifyProofWire(root, key, value, !including, wire));
        assertFalse(tree.verifyProofWire(
                root, key, value, including, Arrays.copyOf(wire, wire.length - 1)));
        assertFalse(tree.verifyProofWire(
                root, key, value, including, Arrays.copyOf(wire, wire.length + 1)));
        if (including) {
            byte[] badValue = value.clone();
            badValue[0] ^= 1;
            assertFalse(tree.verifyProof(root, key, badValue, proof));
            assertFalse(tree.verifyProofWire(root, key, badValue, true, wire));
        }
    }

    private static void assertStep(JsonNode vector, JmtProof.BranchStep step) {
        assertEquals(vector.path("prefixLength").asInt(), step.prefix().length());
        assertEquals(vector.path("prefixHex").asText(), step.prefix().toHexString());
        assertEquals(vector.path("childIndex").asInt(), step.childIndex());
        assertEquals(vector.path("hasSingleNeighbor").asBoolean(), step.hasSingleNeighbor());
        assertEquals(vector.path("neighborNibble").asInt(), step.neighborNibble());
        assertEquals(vector.path("hasForkNeighbor").asBoolean(), step.hasForkNeighbor());
        assertEquals(vector.path("hasLeafNeighbor").asBoolean(), step.hasLeafNeighbor());
        if (step.hasForkNeighbor()) {
            assertNotNull(step.forkNeighborPrefix());
            assertEquals(vector.path("forkNeighborPrefixHex").asText(),
                    step.forkNeighborPrefix().toHexString());
            assertArrayEquals(HEX.parseHex(vector.path("forkNeighborRootHex").asText()),
                    step.forkNeighborRoot());
        } else {
            assertNull(step.forkNeighborPrefix());
            assertNull(step.forkNeighborRoot());
            assertFalse(vector.has("forkNeighborPrefixHex"));
            assertFalse(vector.has("forkNeighborRootHex"));
        }
        if (step.hasLeafNeighbor()) {
            assertArrayEquals(HEX.parseHex(vector.path("leafNeighborKeyHashHex").asText()),
                    step.leafNeighborKeyHash());
            assertArrayEquals(HEX.parseHex(vector.path("leafNeighborValueHashHex").asText()),
                    step.leafNeighborValueHash());
        } else {
            assertNull(step.leafNeighborKeyHash());
            assertNull(step.leafNeighborValueHash());
            assertFalse(vector.has("leafNeighborKeyHashHex"));
            assertFalse(vector.has("leafNeighborValueHashHex"));
        }
        int bitmap = 0;
        ByteArrayOutputStream packed = new ByteArrayOutputStream();
        byte[][] children = step.childHashes();
        assertEquals(16, children.length);
        for (int index = 0; index < children.length; index++) {
            if (children[index] != null) {
                bitmap |= 1 << index;
                packed.writeBytes(children[index]);
            }
        }
        assertEquals(vector.path("childBitmapHex").asText(), String.format("%04x", bitmap));
        assertArrayEquals(Base64.getDecoder().decode(vector.path("childHashesBase64").asText()),
                packed.toByteArray());
    }

    /** Reconstructs the root using only literal JSON fields and generic Poseidon. */
    private static byte[] independentRoot(JsonNode vector) {
        byte[] current = switch (vector.path("type").asText()) {
            case "INCLUSION" -> compress(
                    DOMAIN_LEAF,
                    canonical(HEX.parseHex(vector.path("leafKeyHashHex").asText())),
                    canonical(HEX.parseHex(vector.path("valueHashHex").asText())));
            case "NON_INCLUSION_EMPTY" -> compress(DOMAIN_EMPTY, BigInteger.ZERO, BigInteger.ZERO);
            case "NON_INCLUSION_DIFFERENT_LEAF" -> compress(
                    DOMAIN_LEAF,
                    canonical(HEX.parseHex(vector.path("conflictingKeyHashHex").asText())),
                    canonical(HEX.parseHex(vector.path("conflictingValueHashHex").asText())));
            default -> throw new IllegalArgumentException("unsupported proof type");
        };
        List<JsonNode> steps = new ArrayList<>();
        vector.path("steps").forEach(steps::add);
        for (int stepIndex = steps.size() - 1; stepIndex >= 0; stepIndex--) {
            JsonNode step = steps.get(stepIndex);
            byte[][] children = unpackChildren(step);
            children[step.path("childIndex").asInt()] = current;
            current = independentBranch(children);
        }
        return current;
    }

    /** Encodes ClassicJmtProofCodec's v1 grammar without calling CCL's codec or node encoders. */
    private static byte[] independentWire(JsonNode vector) {
        try {
            Array outer = new Array();
            for (JsonNode step : vector.path("steps")) {
                int bitmap = Integer.parseInt(step.path("childBitmapHex").asText(), 16);
                byte[] packed = Base64.getDecoder().decode(step.path("childHashesBase64").asText());
                Array internalNode = new Array();
                internalNode.add(new ByteString(new byte[]{0}));
                internalNode.add(new UnsignedInteger(bitmap));
                for (int offset = 0; offset < packed.length; offset += 32) {
                    internalNode.add(new ByteString(Arrays.copyOfRange(packed, offset, offset + 32)));
                }
                outer.add(new ByteString(encodeCbor(internalNode)));
            }
            if (!"NON_INCLUSION_EMPTY".equals(vector.path("type").asText())) {
                String keyField = "INCLUSION".equals(vector.path("type").asText())
                        ? "leafKeyHashHex" : "conflictingKeyHashHex";
                String valueField = "INCLUSION".equals(vector.path("type").asText())
                        ? "valueHashHex" : "conflictingValueHashHex";
                Array leafNode = new Array();
                leafNode.add(new ByteString(new byte[]{1}));
                leafNode.add(new ByteString(HEX.parseHex(vector.path(keyField).asText())));
                leafNode.add(new ByteString(HEX.parseHex(vector.path(valueField).asText())));
                outer.add(new ByteString(encodeCbor(leafNode)));
            }
            return encodeCbor(outer);
        } catch (Exception failure) {
            throw new IllegalArgumentException("failed to independently encode vector wire", failure);
        }
    }

    private static byte[] encodeCbor(co.nstant.in.cbor.model.DataItem item) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new CborEncoder(output).encode(item);
        return output.toByteArray();
    }

    private static byte[][] unpackChildren(JsonNode step) {
        int bitmap = Integer.parseInt(step.path("childBitmapHex").asText(), 16);
        byte[] packed = Base64.getDecoder().decode(step.path("childHashesBase64").asText());
        assertEquals(Integer.bitCount(bitmap) * 32, packed.length);
        byte[][] children = new byte[16][];
        int offset = 0;
        for (int index = 0; index < 16; index++) {
            if ((bitmap & (1 << index)) != 0) {
                children[index] = Arrays.copyOfRange(packed, offset, offset + 32);
                offset += 32;
            }
        }
        return children;
    }

    private static byte[] independentBranch(byte[][] children) {
        byte[][] level = new byte[16][];
        byte[] empty = compress(DOMAIN_EMPTY, BigInteger.ZERO, BigInteger.ZERO);
        for (int index = 0; index < 16; index++) {
            level[index] = children[index] == null ? empty : children[index];
        }
        for (int depth = 0; depth < 4; depth++) {
            byte[][] next = new byte[level.length / 2][];
            for (int index = 0; index < level.length; index += 2) {
                next[index / 2] = compress(
                        DOMAIN_BRANCH.add(BigInteger.valueOf(depth)),
                        canonical(level[index]), canonical(level[index + 1]));
            }
            level = next;
        }
        return level[0];
    }

    private static byte[] compress(BigInteger domain, BigInteger left, BigInteger right) {
        return encode(PoseidonHash.spongeHash(PoseidonJmtProfile.PARAMS, domain, left, right));
    }

    private static LinkedHashMap<byte[], byte[]> entries(JsonNode definition) {
        assertEquals("0..23", definition.path("indexRange").asText());
        int count = definition.path("count").asInt();
        var entries = new LinkedHashMap<byte[], byte[]>();
        for (int index = 0; index < count; index++) {
            entries.put(bytes("jmt-key-" + index), bytes("jmt-value-" + index));
        }
        return entries;
    }

    private static BigInteger canonical(byte[] bytes) {
        if (bytes.length != 32) throw new IllegalArgumentException("field must have 32 bytes");
        BigInteger value = new BigInteger(1, bytes);
        if (value.compareTo(FieldConfig.BLS12_381.prime()) >= 0) {
            throw new IllegalArgumentException("non-canonical field");
        }
        return value;
    }

    private static byte[] encode(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] output = new byte[32];
        int source = Math.max(0, raw.length - 32);
        int count = Math.min(32, raw.length);
        System.arraycopy(raw, source, output, 32 - count, count);
        return output;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static JsonNode vectors() throws Exception {
        try (InputStream input = PoseidonJmtCclVectorTest.class.getResourceAsStream(RESOURCE)) {
            assertNotNull(input, "missing " + RESOURCE);
            return JSON.readTree(input);
        }
    }
}
