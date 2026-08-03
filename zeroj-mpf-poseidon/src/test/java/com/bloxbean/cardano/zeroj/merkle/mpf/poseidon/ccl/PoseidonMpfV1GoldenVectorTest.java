package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfProfile;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonMpfV1GoldenVectorTest {
    private static final String RESOURCE =
            "/test-vectors/poseidon-authenticated-state-v1/vectors.json";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger REF_DOMAIN_BYTES = BigInteger.valueOf(0x5a4d5046L);
    private static final BigInteger REF_DOMAIN_LEAF = BigInteger.valueOf(0x5a4d5047L);
    private static final BigInteger REF_DOMAIN_RAW_BYTES = BigInteger.valueOf(0x5a4d504aL);

    @Test
    void optimizedImplementationAndIndependentEncodingAgreeWithLiteralVectors() throws Exception {
        JsonNode root = vectors();
        JsonNode mpf = root.path("mpf");
        assertEquals(PoseidonMpfProfile.PROFILE_ID, mpf.path("profileId").asText());
        assertEquals(PoseidonMpfProfile.PARAMETER_FINGERPRINT,
                root.path("poseidonParameterFingerprint").asText());

        for (JsonNode vector : mpf.path("rawHashes")) {
            byte[] input = vectorInput(vector);
            byte[] expected = HEX.parseHex(vector.path("digestHex").asText());
            assertArrayEquals(expected, PoseidonMpfHash.digest(input), vector.path("name").asText());
            assertArrayEquals(expected, independentDigest(input), vector.path("name").asText());
        }

        byte[] valueHash = independentDigest(
                mpf.path("leafValueUtf8").asText().getBytes(StandardCharsets.UTF_8));
        assertEquals("nibble-at-index-i-is-i-mod-16", mpf.path("leafSuffixPattern").asText());
        PoseidonMpfCommitmentScheme commitments = new PoseidonMpfCommitmentScheme();
        for (JsonNode vector : mpf.path("leaves")) {
            int length = vector.path("suffixLength").asInt();
            int[] suffix = patternedNibbles(length);
            byte[] expected = HEX.parseHex(vector.path("digestHex").asText());
            assertArrayEquals(expected, commitments.commitLeaf(NibblePath.of(suffix), valueHash));
            assertArrayEquals(expected, independentLeaf(suffix, valueHash));
        }

        int[] prefix = JSON.treeToValue(mpf.path("branchPrefixNibbles"), int[].class);
        byte[] child = independentDigest(
                mpf.path("branchChildUtf8").asText().getBytes(StandardCharsets.UTF_8));
        for (int position = 0; position < 16; position++) {
            byte[][] children = new byte[16][];
            children[position] = child;
            byte[] expected = HEX.parseHex(mpf.path("branches").get(position).asText());
            assertArrayEquals(expected, commitments.commitBranch(NibblePath.of(prefix), children, null));
            assertArrayEquals(expected, independentBranch(prefix, children));
        }

        verifyCclFixture(mpf.path("fixture"));
        verifyDifferentLeafFixture(mpf.path("differentLeafFixture"));
        assertEquals(Set.of(
                        "root-bit-flip", "query-key-to-conflicting-leaf", "expected-value-bit-flip",
                        "wire-truncated-one-byte", "wire-appended-zero",
                        "inclusion-flag-confusion", "terminal-fork-rejected"),
                JSON.convertValue(mpf.path("negativeMutations"),
                        JSON.getTypeFactory().constructCollectionType(Set.class, String.class)));
        byte[] modulus = HEX.parseHex(root.path("canonicalFieldBoundaryHex").asText());
        assertEquals(FieldConfig.BLS12_381.prime(), new BigInteger(1, modulus));
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfHash.fieldFromDigestBytes(modulus));
    }

    private static void verifyCclFixture(JsonNode fixture) {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        fixture.path("entries").fields().forEachRemaining(entry -> trie.put(
                entry.getKey().getBytes(StandardCharsets.UTF_8),
                entry.getValue().asText().getBytes(StandardCharsets.UTF_8)));
        byte[] expectedRoot = HEX.parseHex(fixture.path("rootHex").asText());
        assertArrayEquals(expectedRoot, trie.getRootHash());

        byte[] inclusionKey = fixture.path("inclusionKey").asText().getBytes(StandardCharsets.UTF_8);
        assertEquals("branch-path", fixture.path("inclusionProofForm").asText());
        byte[] inclusion = Base64.getDecoder().decode(fixture.path("inclusionWireBase64").asText());
        assertArrayEquals(inclusion, trie.getProofWire(inclusionKey).orElseThrow());
        assertBranchWireFixture(inclusion, fixture.path("inclusionDecoded"));
        assertTrue(PoseidonMpfReference.including(
                expectedRoot, inclusionKey, trie.get(inclusionKey), inclusion));

        byte[] exclusionKey = fixture.path("exclusionKey").asText().getBytes(StandardCharsets.UTF_8);
        assertEquals("missing-branch", fixture.path("exclusionProofForm").asText());
        byte[] exclusion = Base64.getDecoder().decode(fixture.path("exclusionWireBase64").asText());
        assertArrayEquals(exclusion, trie.getProofWire(exclusionKey).orElseThrow());
        assertBranchWireFixture(exclusion, fixture.path("exclusionDecoded"));
        assertTrue(PoseidonMpfReference.excluding(expectedRoot, exclusionKey, exclusion));
    }

    private static void assertBranchWireFixture(byte[] wire, JsonNode decoded) {
        assertEquals("branch", decoded.path("kind").asText());
        int skip = decoded.path("skip").asInt();
        byte[][] neighbors = new byte[4][];
        for (int index = 0; index < neighbors.length; index++) {
            neighbors[index] = HEX.parseHex(decoded.path("neighborsHex").get(index).asText());
        }
        assertArrayEquals(wire, independentBranchWire(skip, neighbors));

        var steps = PoseidonMpfCodec.decode(wire);
        assertEquals(1, steps.size());
        assertEquals(PoseidonMpfCodec.KIND_BRANCH, steps.getFirst().kind());
        assertEquals(skip, steps.getFirst().skip());
        for (int index = 0; index < neighbors.length; index++) {
            assertEquals(canonical(neighbors[index]), steps.getFirst().neighbors().get(index));
        }
    }

    private static byte[] independentBranchWire(int skip, byte[][] neighbors) {
        try {
            byte[] packed = new byte[4 * PoseidonMpfHash.DIGEST_LENGTH];
            for (int index = 0; index < neighbors.length; index++) {
                if (neighbors[index].length != PoseidonMpfHash.DIGEST_LENGTH) {
                    throw new IllegalArgumentException("neighbor must be 32 bytes");
                }
                System.arraycopy(neighbors[index], 0, packed,
                        index * PoseidonMpfHash.DIGEST_LENGTH, PoseidonMpfHash.DIGEST_LENGTH);
            }
            Array step = new Array();
            step.setTag(121);
            step.add(new UnsignedInteger(skip));
            step.add(new ByteString(packed));
            Array proof = new Array();
            proof.add(step);
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
            new CborEncoder(output).encode(proof);
            return output.toByteArray();
        } catch (Exception failure) {
            throw new IllegalArgumentException("failed to encode independent branch fixture", failure);
        }
    }

    private static void verifyDifferentLeafFixture(JsonNode fixture) throws Exception {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] entryKey = fixture.path("entryKeyUtf8").asText().getBytes(StandardCharsets.UTF_8);
        byte[] entryValue = fixture.path("entryValueUtf8").asText().getBytes(StandardCharsets.UTF_8);
        byte[] queryKey = fixture.path("queryKeyUtf8").asText().getBytes(StandardCharsets.UTF_8);
        trie.put(entryKey, entryValue);

        byte[] root = HEX.parseHex(fixture.path("rootHex").asText());
        byte[] wire = Base64.getDecoder().decode(fixture.path("wireBase64").asText());
        byte[] keyHash = HEX.parseHex(fixture.path("conflictingKeyHashHex").asText());
        byte[] valueHash = HEX.parseHex(fixture.path("conflictingValueHashHex").asText());
        assertEquals("different-leaf", fixture.path("proofForm").asText());
        assertArrayEquals(root, trie.getRootHash());
        assertArrayEquals(wire, trie.getProofWire(queryKey).orElseThrow());
        assertArrayEquals(wire, independentLeafWire(fixture.path("skip").asInt(), keyHash, valueHash));
        assertTrue(PoseidonMpfReference.excluding(root, queryKey, wire));

        var steps = PoseidonMpfCodec.decode(wire);
        assertEquals(1, steps.size());
        assertEquals(PoseidonMpfCodec.KIND_LEAF, steps.getFirst().kind());
        assertEquals(fixture.path("skip").asInt(), steps.getFirst().skip());
        assertEquals(canonical(valueHash), steps.getFirst().leafValueDigest());
        int[] keyPath = PoseidonMpfHash.digestToNibbles(keyHash);
        assertArrayEquals(root, independentLeaf(keyPath, valueHash));

        byte[] badRoot = root.clone();
        badRoot[31] ^= 1;
        assertFalse(PoseidonMpfReference.excluding(badRoot, queryKey, wire));
        assertFalse(PoseidonMpfReference.excluding(root, entryKey, wire));
        assertFalse(PoseidonMpfReference.including(root, queryKey, entryValue, wire));
        assertFalse(PoseidonMpfReference.excluding(
                root, queryKey, Arrays.copyOf(wire, wire.length - 1)));
        assertFalse(PoseidonMpfReference.excluding(
                root, queryKey, Arrays.copyOf(wire, wire.length + 1)));
    }

    private static byte[] independentLeafWire(int skip, byte[] keyHash, byte[] valueHash) throws Exception {
        Array step = new Array();
        step.setTag(123);
        step.add(new UnsignedInteger(skip));
        step.add(new ByteString(keyHash));
        step.add(new ByteString(valueHash));
        Array proof = new Array();
        proof.add(step);
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        new CborEncoder(output).encode(proof);
        return output.toByteArray();
    }

    private static byte[] independentLeaf(int[] suffix, byte[] valueHash) {
        List<BigInteger> fields = new ArrayList<>();
        fields.add(REF_DOMAIN_LEAF);
        fields.add(BigInteger.valueOf(suffix.length));
        for (int offset = 0; offset < suffix.length; offset += 31) {
            int end = Math.min(suffix.length, offset + 31);
            byte[] chunk = new byte[end - offset];
            for (int i = offset; i < end; i++) chunk[i - offset] = (byte) suffix[i];
            fields.add(unsigned(chunk));
        }
        while (fields.size() < 5) fields.add(BigInteger.ZERO);
        fields.add(canonical(valueHash));
        return encode(PoseidonHash.hashN(PoseidonMpfProfile.PARAMS, fields.toArray(BigInteger[]::new)));
    }

    private static byte[] independentBranch(int[] prefix, byte[][] children) {
        byte[][] level = new byte[16][];
        for (int i = 0; i < level.length; i++) {
            level[i] = children[i] == null ? new byte[32] : children[i].clone();
        }
        while (level.length > 1) {
            byte[][] next = new byte[level.length / 2][];
            for (int i = 0; i < level.length; i += 2) {
                byte[] pair = new byte[64];
                System.arraycopy(level[i], 0, pair, 0, 32);
                System.arraycopy(level[i + 1], 0, pair, 32, 32);
                next[i / 2] = independentDigest(pair);
            }
            level = next;
        }
        byte[] prefixed = new byte[prefix.length + 32];
        for (int i = 0; i < prefix.length; i++) prefixed[i] = (byte) prefix[i];
        System.arraycopy(level[0], 0, prefixed, prefix.length, 32);
        return independentDigest(prefixed);
    }

    private static byte[] independentDigest(byte[] input) {
        List<BigInteger> fixed = fixedChunks(input);
        List<BigInteger> fields = new ArrayList<>();
        if (fixed != null) {
            fields.add(REF_DOMAIN_BYTES);
            fields.add(BigInteger.valueOf(input.length));
            fields.addAll(fixed);
            while (fields.size() < 5) fields.add(BigInteger.ZERO);
        } else {
            fields.add(REF_DOMAIN_RAW_BYTES);
            fields.add(BigInteger.valueOf(input.length));
            for (int offset = 0; offset < input.length; offset += 31) {
                fields.add(unsigned(Arrays.copyOfRange(input, offset, Math.min(input.length, offset + 31))));
            }
        }
        return encode(PoseidonHash.hashN(PoseidonMpfProfile.PARAMS, fields.toArray(BigInteger[]::new)));
    }

    private static List<BigInteger> fixedChunks(byte[] input) {
        List<BigInteger> chunks = new ArrayList<>();
        int offset = 0;
        int remainder = input.length % 32;
        if (remainder != 0) {
            chunks.add(unsigned(Arrays.copyOfRange(input, 0, remainder)));
            offset = remainder;
        }
        while (offset < input.length) {
            BigInteger chunk = unsigned(Arrays.copyOfRange(input, offset, offset + 32));
            if (chunk.compareTo(FieldConfig.BLS12_381.prime()) >= 0) return null;
            chunks.add(chunk);
            offset += 32;
        }
        return chunks.size() <= 3 ? chunks : null;
    }

    private static int[] patternedNibbles(int length) {
        int[] values = new int[length];
        for (int i = 0; i < length; i++) values[i] = i & 15;
        return values;
    }

    private static byte[] vectorInput(JsonNode vector) {
        if (vector.has("inputHex")) return HEX.parseHex(vector.path("inputHex").asText());
        if (!"sequence-mod-251".equals(vector.path("pattern").asText())) {
            throw new IllegalArgumentException("unsupported vector input pattern");
        }
        byte[] input = new byte[vector.path("length").asInt()];
        for (int i = 0; i < input.length; i++) input[i] = (byte) (i % 251);
        return input;
    }

    private static BigInteger canonical(byte[] value) {
        BigInteger field = unsigned(value);
        if (value.length != 32 || field.compareTo(FieldConfig.BLS12_381.prime()) >= 0) {
            throw new IllegalArgumentException("non-canonical field encoding");
        }
        return field;
    }

    private static BigInteger unsigned(byte[] value) {
        return value.length == 0 ? BigInteger.ZERO : new BigInteger(1, value);
    }

    private static byte[] encode(BigInteger field) {
        if (field.signum() < 0 || field.compareTo(FieldConfig.BLS12_381.prime()) >= 0) {
            throw new IllegalArgumentException("non-canonical reference field");
        }
        byte[] raw = field.toByteArray();
        byte[] output = new byte[32];
        int sourceOffset = Math.max(0, raw.length - output.length);
        int count = Math.min(raw.length, output.length);
        System.arraycopy(raw, sourceOffset, output, output.length - count, count);
        return output;
    }

    private static JsonNode vectors() throws Exception {
        try (InputStream input = PoseidonMpfV1GoldenVectorTest.class.getResourceAsStream(RESOURCE)) {
            assertNotNull(input, "missing " + RESOURCE);
            return JSON.readTree(input);
        }
    }
}
