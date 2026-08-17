package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonJmtV1GoldenVectorTest {
    private static final String RESOURCE =
            "/test-vectors/poseidon-authenticated-state-v1/vectors.json";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger REF_DOMAIN_BYTES = new BigInteger("5a4a4d540001", 16);
    private static final BigInteger REF_DOMAIN_RAW_BYTES = new BigInteger("5a4a4d540002", 16);
    private static final BigInteger REF_DOMAIN_EMPTY = new BigInteger("5a4a4d540003", 16);
    private static final BigInteger REF_DOMAIN_LEAF = new BigInteger("5a4a4d540004", 16);
    private static final BigInteger REF_BRANCH_BASE = new BigInteger("5a4a4d540010", 16);

    @Test
    void profileAndIndependentCheckerAgreeWithLiteralVectors() throws Exception {
        JsonNode root = vectors();
        JsonNode jmt = root.path("jmt");
        assertEquals(PoseidonJmtProfile.PROFILE_ID, jmt.path("profileId").asText());
        assertEquals(PoseidonJmtProfile.HASH_ALGORITHM_ID,
                jmt.path("format").path("hashAlgorithmId").asText());
        assertEquals(PoseidonJmtProfile.PROOF_CODEC_ID,
                jmt.path("format").path("proofCodecId").asText());
        assertEquals(PoseidonJmtProfile.PARAMETER_FINGERPRINT,
                root.path("poseidonParameterFingerprint").asText());

        for (JsonNode vector : jmt.path("rawHashes")) {
            byte[] input = vectorInput(vector);
            byte[] expected = HEX.parseHex(vector.path("digestHex").asText());
            assertArrayEquals(expected, PoseidonJmtHash.digest(input), vector.path("name").asText());
            assertArrayEquals(expected, independentDigest(input), vector.path("name").asText());
        }

        byte[] empty = HEX.parseHex(jmt.path("emptyHex").asText());
        assertArrayEquals(empty, PoseidonJmtCommitments.empty());
        assertArrayEquals(empty, independentCompress(REF_DOMAIN_EMPTY, BigInteger.ZERO, BigInteger.ZERO));

        byte[] keyHash = independentDigest(jmt.path("leafKeyUtf8").asText()
                .getBytes(StandardCharsets.UTF_8));
        byte[] valueHash = independentDigest(jmt.path("leafValueUtf8").asText()
                .getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(HEX.parseHex(jmt.path("keyHashHex").asText()), keyHash);
        assertArrayEquals(HEX.parseHex(jmt.path("valueHashHex").asText()), valueHash);
        byte[] leaf = independentCompress(
                REF_DOMAIN_LEAF, canonical(keyHash), canonical(valueHash));
        assertArrayEquals(HEX.parseHex(jmt.path("leafHex").asText()), leaf);
        assertArrayEquals(leaf, PoseidonJmtCommitments.leaf(keyHash, valueHash));

        for (int position = 0; position < 16; position++) {
            byte[][] children = new byte[16][];
            children[position] = leaf;
            byte[] expected = HEX.parseHex(jmt.path("branches").get(position).asText());
            assertArrayEquals(expected, PoseidonJmtCommitments.branch(children));
            assertArrayEquals(expected, independentBranch(children));
        }

        byte[] modulus = HEX.parseHex(root.path("canonicalFieldBoundaryHex").asText());
        assertEquals(FieldConfig.BLS12_381.prime(), new BigInteger(1, modulus));
        assertThrows(IllegalArgumentException.class, () -> PoseidonJmtHash.decode(modulus));
        assertThrows(IllegalArgumentException.class, () -> PoseidonJmtCommitments.branch(new byte[15][]));
        for (int length : new int[]{0, 31, 33}) {
            byte[][] malformed = new byte[16][];
            malformed[0] = new byte[length];
            assertThrows(IllegalArgumentException.class, () -> PoseidonJmtCommitments.branch(malformed));
        }
        byte[][] nonCanonical = new byte[16][];
        nonCanonical[0] = modulus;
        assertThrows(IllegalArgumentException.class, () -> PoseidonJmtCommitments.branch(nonCanonical));
    }

    private static byte[] independentBranch(byte[][] children) {
        byte[][] level = new byte[16][];
        for (int i = 0; i < level.length; i++) {
            level[i] = children[i] == null
                    ? independentCompress(REF_DOMAIN_EMPTY, BigInteger.ZERO, BigInteger.ZERO)
                    : children[i];
        }
        for (int depth = 0; depth < 4; depth++) {
            byte[][] next = new byte[level.length / 2][];
            for (int i = 0; i < level.length; i += 2) {
                next[i / 2] = independentCompress(REF_BRANCH_BASE.add(BigInteger.valueOf(depth)),
                        canonical(level[i]), canonical(level[i + 1]));
            }
            level = next;
        }
        return level[0];
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
        return independentHash(fields.toArray(BigInteger[]::new));
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

    private static byte[] independentHash(BigInteger... fields) {
        return encode(PoseidonHash.hashN(PoseidonJmtProfile.PARAMS, fields));
    }

    private static byte[] independentCompress(BigInteger domain, BigInteger left, BigInteger right) {
        return encode(PoseidonHash.spongeHash(PoseidonJmtProfile.PARAMS, domain, left, right));
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

    private static byte[] encode(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] output = new byte[32];
        int sourceOffset = Math.max(0, raw.length - output.length);
        int count = Math.min(raw.length, output.length);
        System.arraycopy(raw, sourceOffset, output, output.length - count, count);
        return output;
    }

    private static JsonNode vectors() throws Exception {
        try (InputStream input = PoseidonJmtV1GoldenVectorTest.class.getResourceAsStream(RESOURCE)) {
            assertNotNull(input, "missing " + RESOURCE);
            return JSON.readTree(input);
        }
    }
}
